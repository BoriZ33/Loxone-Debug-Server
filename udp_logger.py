#!/usr/bin/env python3
"""
Loxone Debug Server
  - UDP Port 7777: schreibt Miniserver-Debug-Streams in logs/<IP>/<datum_zeit>.log
  - HTTP Port 8080: Browse, ZIP-Download, Löschen, Benutzerverwaltung
  - Standard-Login: admin / admin  (bitte sofort ändern)
"""

import io, json, os, re, socket, sys, threading, hashlib, secrets, time, shutil, zipfile, subprocess
from datetime import datetime
from pathlib import Path
from flask import (Flask, request, send_file, redirect, url_for,
                   session, render_template_string, flash, abort,
                   get_flashed_messages, jsonify, Response)
from functools import wraps

# ── Konfiguration ──────────────────────────────────────────────────────────
UDP_PORT       = 7777
HTTP_PORT      = 8080
LOG_BASE_DIR   = Path("logs")
USERS_FILE     = Path("users.json")
AUDIT_FILE     = Path("audit.json")
SETTINGS_FILE  = Path("settings.json")
STREAM_TIMEOUT = 30   # Standardwert; wird zur Laufzeit aus settings.json gelesen

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ── Shared State ───────────────────────────────────────────────────────────
active_streams:    dict = {}
completed_streams: list = []
_lock = threading.Lock()

# ── Audit Log ──────────────────────────────────────────────────────────────
_audit_lock = threading.Lock()

def add_audit(action: str, detail: str = "", user: str = None):
    if user is None:
        try:
            user = session.get("user", "System")
        except RuntimeError:
            user = "System"
    entry = {
        "ts":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user":   user,
        "action": action,
        "detail": detail,
    }
    with _audit_lock:
        try:
            log = json.loads(AUDIT_FILE.read_text(encoding="utf-8")) if AUDIT_FILE.exists() else []
        except Exception:
            log = []
        log.insert(0, entry)
        log = log[:2000]
        AUDIT_FILE.write_text(json.dumps(log, indent=2), encoding="utf-8")

# ── Einstellungen ─────────────────────────────────────────────────────────
_SETTINGS_DEFAULTS = {"http_port": 8080, "udp_port": 7777, "stream_timeout": 30, "auto_delete_days": 0}

def load_settings() -> dict:
    if not SETTINGS_FILE.exists():
        return dict(_SETTINGS_DEFAULTS)
    try:
        saved = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        return {**_SETTINGS_DEFAULTS, **saved}
    except Exception:
        return dict(_SETTINGS_DEFAULTS)

def save_settings(s: dict):
    SETTINGS_FILE.write_text(json.dumps(s, indent=2), encoding="utf-8")

# ── Passwort ───────────────────────────────────────────────────────────────
def hash_pw(pw: str) -> str:
    salt = secrets.token_hex(16)
    return salt + ":" + hashlib.sha256((salt + pw).encode()).hexdigest()

def check_pw(stored: str, pw: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        return hashlib.sha256((salt + pw).encode()).hexdigest() == h
    except Exception:
        return False

# ── Benutzer ───────────────────────────────────────────────────────────────
def load_users() -> dict:
    if not USERS_FILE.exists():
        u = {"admin": {"password": hash_pw("admin"), "role": "admin"}}
        USERS_FILE.write_text(json.dumps(u, indent=2))
        print("[WEB] Standardbenutzer erstellt: admin / admin -- bitte aendern!")
        return u
    return json.loads(USERS_FILE.read_text(encoding="utf-8"))

def save_users(u: dict):
    USERS_FILE.write_text(json.dumps(u, indent=2), encoding="utf-8")

# ── Decorators ─────────────────────────────────────────────────────────────
def login_req(f):
    @wraps(f)
    def w(*a, **kw):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return w

def admin_req(f):
    @wraps(f)
    def w(*a, **kw):
        if "user" not in session:
            return redirect(url_for("login"))
        if load_users().get(session["user"], {}).get("role") != "admin":
            flash("Admin-Zugang erforderlich.", "error")
            return redirect(url_for("dashboard"))
        return f(*a, **kw)
    return w

# ── Hilfsfunktionen ────────────────────────────────────────────────────────
def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def safe_path(base: Path, rel: str) -> Path:
    p = (base / rel).resolve()
    if not str(p).startswith(str(base.resolve())):
        abort(400, "Ungültiger Pfad")
    return p

def stream_stats():
    with _lock:
        return list(active_streams.values()), list(completed_streams)

# ── Loxone Paket-Parser ────────────────────────────────────────────────────
def extract_message(data: bytes) -> str:
    """Extrahiert den lesbaren Text aus einem Loxone UDP-Debug-Paket.
    Das Loxone-Protokoll speichert Text zwischen 0x00 0x01 ... 0x00
    (identisch zum .LxMon Dateiformat des Loxone Monitors)."""
    # Primär: Loxone-Protokoll-Muster  \x00\x01 <TEXT> \x00
    matches = re.findall(rb'\x00\x01([\x20-\x7e]{4,})\x00', data)
    if matches:
        return "  ".join(m.decode("ascii", errors="replace") for m in matches)
    # Fallback: längste zusammenhängende lesbare Zeichenkette
    parts = re.findall(rb'[\x20-\x7e]{8,}', data)
    if parts:
        meaningful = [p.decode("ascii", errors="replace").strip()
                      for p in parts if len(p) >= 8]
        if meaningful:
            return "  ".join(meaningful)
    return f"[binary {len(data)} bytes]"

# ── UDP Listener ───────────────────────────────────────────────────────────
def udp_listener():
    LOG_BASE_DIR.mkdir(exist_ok=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", UDP_PORT))
    sock.settimeout(1.0)
    print(f"[UDP] Lausche auf Port {UDP_PORT}")

    while True:
        try:
            data, (ip, _) = sock.recvfrom(65535)
            now = time.time()
            with _lock:
                if ip not in active_streams:
                    safe_ip     = ip.replace(":", "_")
                    ts          = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                    folder_name = f"{safe_ip}_{ts}"
                    ip_dir      = LOG_BASE_DIR / folder_name
                    ip_dir.mkdir(parents=True, exist_ok=True)
                    logfile = ip_dir / f"{ts}.log"
                    active_streams[ip] = {
                        "ip":            ip,
                        "folder":        folder_name,
                        "logfile":       str(logfile),
                        "last_seen":     now,
                        "bytes_written": 0,
                        "start_time":    datetime.now().isoformat(),
                    }
                    print(f"[UDP] Neuer Stream von {ip}  >>  {logfile}")
                    add_audit("Stream gestartet", f"IP: {ip}  Ordner: {folder_name}", user="System")
                s = active_streams[ip]
                s["last_seen"]      = now
                s["bytes_written"] += len(data)
                ts  = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                msg = extract_message(data)
                with open(s["logfile"], "a", encoding="utf-8") as f:
                    f.write(f"{ts}  {msg}\n")
        except socket.timeout:
            pass
        except Exception as e:
            print(f"[UDP] Fehler: {e}")

_last_cleanup = 0.0

def _auto_cleanup():
    """Löscht Ordner älterer abgeschlossener Streams wenn auto_delete_days > 0."""
    days = load_settings().get("auto_delete_days", 0)
    if days <= 0 or not LOG_BASE_DIR.exists():
        return
    cutoff = time.time() - days * 86400
    with _lock:
        active_folders = {s.get("folder") for s in active_streams.values()}
    for d in list(LOG_BASE_DIR.iterdir()):
        if not d.is_dir() or d.name in active_folders:
            continue
        try:
            if d.stat().st_mtime < cutoff:
                shutil.rmtree(d)
                add_audit("Automatisch gelöscht", f"{d.name} (älter als {days} Tage)", user="System")
                print(f"[AUTO] Ordner gelöscht: {d.name}")
        except Exception as e:
            print(f"[AUTO] Fehler beim Löschen {d.name}: {e}")

def stream_monitor():
    global _last_cleanup
    while True:
        time.sleep(5)
        cfg     = load_settings()
        timeout = cfg["stream_timeout"]
        now     = time.time()
        with _lock:
            done = [ip for ip, s in active_streams.items()
                    if now - s["last_seen"] > timeout]
            for ip in done:
                s = active_streams.pop(ip)
                s["end_time"] = datetime.now().isoformat()
                completed_streams.insert(0, s)
                add_audit("Stream beendet",
                          f"IP: {ip}  Volumen: {fmt_bytes(s['bytes_written'])}",
                          user="System")
                print(f"[UDP] Stream von {ip} beendet")
        if now - _last_cleanup >= 300:
            _last_cleanup = now
            _auto_cleanup()

# ══════════════════════════════════════════════════════════════════════════
# Design – Loxone Corporate Style
# Primärfarbe: #69A533 (Loxone Green)
# Navigation: #1e1e1e (Charcoal)
# Hintergrund: #f4f4f4 (Light Gray)
# ══════════════════════════════════════════════════════════════════════════
CSS = """
:root {
  --green:       #69A533;
  --green-dark:  #558827;
  --green-light: #e8f4de;
  --nav-bg:      #1e1e1e;
  --nav-text:    #ffffff;
  --page-bg:     #f2f2f2;
  --card-bg:     #ffffff;
  --border:      #e0e0e0;
  --text:        #1a1a1a;
  --muted:       #6b6b6b;
  --danger:      #d0021b;
  --danger-bg:   #fff0f0;
  --danger-border:#f5c6cb;
  --success-bg:  #e8f4de;
  --success-border:#b7dfa0;
  --radius:      4px;
  --shadow:      0 1px 4px rgba(0,0,0,.10);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: "Segoe UI", Roboto, Arial, sans-serif; background: var(--page-bg);
       color: var(--text); min-height: 100vh; font-size: 14px; }

/* ── Navigation ── */
nav {
  background: var(--nav-bg); color: var(--nav-text);
  padding: 0 32px; display: flex; align-items: stretch;
  height: 56px; position: sticky; top: 0; z-index: 100;
  box-shadow: 0 2px 8px rgba(0,0,0,.35);
}
.nav-brand {
  display: flex; align-items: center; gap: 10px;
  font-size: 15px; font-weight: 700; letter-spacing: .02em;
  color: #fff; text-decoration: none; padding-right: 32px;
  border-right: 1px solid #333;
}
.nav-brand svg { flex-shrink: 0; }
.nav-links { display: flex; align-items: stretch; margin-left: 8px; }
.nav-links a {
  display: flex; align-items: center; padding: 0 18px;
  color: #ccc; text-decoration: none; font-size: 13px;
  font-weight: 500; transition: color .15s, background .15s;
  border-bottom: 3px solid transparent;
}
.nav-links a:hover { color: #fff; background: #2a2a2a; }
.nav-links a.active { color: var(--green); border-bottom-color: var(--green); }
.nav-right { margin-left: auto; display: flex; align-items: center;
             gap: 4px; font-size: 12px; color: #aaa; }
.nav-right a { color: #aaa; text-decoration: none; padding: 6px 12px;
               border-radius: var(--radius); }
.nav-right a:hover { background: #2a2a2a; color: #fff; }

/* ── Layout ── */
.container { max-width: 1240px; margin: 0 auto; padding: 28px 24px; }

/* ── Page header ── */
.page-header { margin-bottom: 24px; }
.page-header h1 { font-size: 20px; font-weight: 700; color: var(--text); }
.page-header p  { font-size: 13px; color: var(--muted); margin-top: 3px; }

/* ── Cards ── */
.card {
  background: var(--card-bg); border: 1px solid var(--border);
  border-radius: var(--radius); box-shadow: var(--shadow);
  margin-bottom: 20px; overflow: hidden;
}
.card-header {
  padding: 14px 20px; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
  background: #fafafa;
}
.card-header h2 { font-size: 13px; font-weight: 700; color: var(--text);
                  text-transform: uppercase; letter-spacing: .06em; }
.card-body { padding: 20px; }

/* ── Stats grid ── */
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
              gap: 16px; margin-bottom: 20px; }
.stat-card {
  background: var(--card-bg); border: 1px solid var(--border);
  border-radius: var(--radius); box-shadow: var(--shadow);
  padding: 18px 20px; display: flex; flex-direction: column; gap: 4px;
}
.stat-card .val { font-size: 28px; font-weight: 800; color: var(--green); line-height: 1; }
.stat-card .lbl { font-size: 11px; color: var(--muted); text-transform: uppercase;
                  letter-spacing: .05em; font-weight: 600; }
.stat-card.accent { border-left: 4px solid var(--green); }

/* ── Tables ── */
.tbl-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
thead tr { background: #fafafa; }
th { text-align: left; padding: 10px 16px; font-size: 11px; font-weight: 700;
     color: var(--muted); text-transform: uppercase; letter-spacing: .06em;
     border-bottom: 2px solid var(--border); white-space: nowrap; }
td { padding: 10px 16px; font-size: 13px; border-bottom: 1px solid #f0f0f0;
     vertical-align: middle; }
tr:last-child td { border-bottom: none; }
tbody tr:hover td { background: #f9f9f9; }

/* ── Badges ── */
.badge {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700;
  text-transform: uppercase; letter-spacing: .04em;
}
.badge-green  { background: var(--green-light); color: var(--green-dark); border: 1px solid #b7dfa0; }
.badge-gray   { background: #f0f0f0; color: #666; border: 1px solid #ddd; }
.badge-orange { background: #fff3e0; color: #e65100; border: 1px solid #ffcc80; }
.badge-blue   { background: #e3f2fd; color: #1565c0; border: 1px solid #90caf9; }
.pulse { width: 7px; height: 7px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
.pulse-green { background: var(--green); animation: pulse 1.8s ease-in-out infinite; }
.pulse-gray  { background: #aaa; }
@keyframes pulse {
  0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(105,165,51,.4); }
  50%       { opacity: .8; box-shadow: 0 0 0 5px rgba(105,165,51,0); }
}

/* ── Buttons ── */
.btn {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 7px 16px; border-radius: var(--radius); border: none;
  cursor: pointer; font-size: 13px; font-weight: 600;
  text-decoration: none; transition: background .15s, opacity .15s;
  white-space: nowrap;
}
.btn-sm { padding: 4px 12px; font-size: 12px; }
.btn-primary  { background: var(--green); color: #fff; }
.btn-primary:hover  { background: var(--green-dark); }
.btn-secondary { background: #fff; color: var(--text);
                 border: 1px solid var(--border); }
.btn-secondary:hover { background: #f5f5f5; }
.btn-danger   { background: var(--danger); color: #fff; }
.btn-danger:hover   { background: #a50016; }
.btn-outline  { background: transparent; color: var(--green);
                border: 1px solid var(--green); }
.btn-outline:hover  { background: var(--green-light); }
form.inline { display: inline; }
.actions { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }

/* ── Alerts ── */
.alert { padding: 12px 16px; border-radius: var(--radius); margin-bottom: 18px;
         font-size: 13px; border: 1px solid; display: flex; gap: 8px; align-items: flex-start; }
.alert-error   { background: var(--danger-bg);  color: #a00;  border-color: var(--danger-border); }
.alert-success { background: var(--success-bg); color: #2a6000; border-color: var(--success-border); }

/* ── Forms ── */
.form-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 14px; align-items: end; }
.form-group { display: flex; flex-direction: column; gap: 5px; }
label { font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase;
        letter-spacing: .04em; }
input, select {
  padding: 8px 10px; border: 1px solid var(--border); border-radius: var(--radius);
  font-size: 13px; color: var(--text); background: #fff;
  transition: border-color .15s;
}
input:focus, select:focus { outline: none; border-color: var(--green);
                             box-shadow: 0 0 0 3px rgba(105,165,51,.15); }

/* ── Breadcrumb ── */
.bc { font-size: 12px; color: var(--muted); margin-bottom: 16px;
      display: flex; align-items: center; gap: 6px; }
.bc a { color: var(--green); text-decoration: none; font-weight: 600; }
.bc a:hover { text-decoration: underline; }
.bc-sep { color: #ccc; }

/* ── Empty state ── */
.empty { text-align: center; padding: 56px 24px; color: #aaa; }
.empty svg { display: block; margin: 0 auto 12px; opacity: .3; }
.empty p { font-size: 14px; }

/* ── Login ── */
.login-wrap { min-height: 100vh; display: flex; align-items: center;
              justify-content: center; background: var(--nav-bg); }
.login-box {
  background: #fff; border-radius: 6px; box-shadow: 0 8px 32px rgba(0,0,0,.4);
  padding: 44px 40px; width: 100%; max-width: 400px;
}
.login-logo { display: flex; align-items: center; gap: 12px; margin-bottom: 32px; }
.login-logo .logo-mark {
  width: 42px; height: 42px; background: var(--green); border-radius: 6px;
  display: flex; align-items: center; justify-content: center;
}
.login-logo .name { font-size: 16px; font-weight: 700; color: var(--text); }
.login-logo .sub  { font-size: 11px; color: var(--muted); }
.login-box h2 { font-size: 18px; font-weight: 700; margin-bottom: 6px; }
.login-box p  { font-size: 13px; color: var(--muted); margin-bottom: 24px; }

/* ── Refresh hint ── */
.refresh-note { font-size: 11px; color: #aaa; text-align: right; margin-bottom: 10px; }

/* ── Monospace for IPs ── */
.mono { font-family: "Consolas", "Courier New", monospace; }

/* ── Role tags ── */
.role-admin { color: var(--green-dark); font-weight: 700; }
.role-user  { color: var(--muted); }

/* ── Sortable headers ── */
th.sortable { cursor: pointer; user-select: none; white-space: nowrap; }
th.sortable:hover { color: var(--text); background: #f0f0f0; }
th.sortable::after { content: " ⇅"; font-size: .7em; color: #ccc; }
th.sort-asc::after  { content: " ▲"; color: var(--green); }
th.sort-desc::after { content: " ▼"; color: var(--green); }

/* ── Live stream terminal ── */
.terminal { background: #0d1117; border-radius: var(--radius); padding: 16px;
            font-family: "Consolas","Courier New",monospace; font-size: 12.5px;
            line-height: 1.55; color: #c9d1d9; overflow-y: auto;
            height: calc(100vh - 220px); min-height: 300px; }
.terminal .ts { color: #58a6ff; margin-right: 8px; flex-shrink: 0; }
.terminal .ln { display: flex; }
.terminal .ln:hover { background: rgba(255,255,255,.04); }
.live-badge { display: inline-flex; align-items: center; gap: 6px;
              padding: 4px 12px; border-radius: 9999px; font-size: 12px;
              font-weight: 700; background: #052e16; color: #4ade80;
              border: 1px solid #166534; }
.live-badge .pulse { animation: pulse 1.2s ease-in-out infinite; }

/* ── File size cell ── */
td.size { color: var(--muted); font-variant-numeric: tabular-nums; }

/* ── Danger zone box ── */
.danger-zone { border: 1px solid var(--danger-border); border-radius: var(--radius);
               padding: 16px 20px; background: var(--danger-bg); }

/* ── Footer ── */
.site-footer { text-align: center; padding: 28px 0 18px;
               font-size: 11px; color: #aaa; letter-spacing: .03em; }
"""

# Originales Loxone Wordmark-Logo (von loxone.com extrahiert)
LOXONE_LOGO = """<svg width="90" height="20" viewBox="0 0 100 23" fill="none" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" clip-rule="evenodd" d="M91.4149 18.1044V12.2562H96.9392V8.69613H91.4149V5.93341L90.1667 4.01636H92.8082H100V0.456299H87.6289V0.471142V4.01636V18.1044V19.7067L88.9035 21.6644H100V18.1044H91.4149ZM83.4455 21.6508H83.8794V0.471191H80.4177V15.7242L72.6247 0.471191H71.489H68.8387H68.0273V21.6508H71.489V5.65867L79.6594 21.6508H80.4177H83.4455ZM63.5224 18.7948C64.4444 17.1971 64.544 15.5118 64.544 14.8618V7.21299C64.5051 3.63618 62.7241 1.86947 61.2373 1.01732C59.6341 0.0989541 57.9447 0 57.2933 0H56.0908C52.5047 0.0384399 50.7329 1.81467 49.8784 3.29784C48.958 4.89632 48.8584 6.58083 48.8584 7.23126L48.8587 14.8804C48.8973 18.4572 50.6783 20.2236 52.1651 21.0761C53.7683 21.9941 55.4573 22.093 56.1091 22.093H57.2967H57.3062C60.8942 22.0534 62.6672 20.2776 63.5224 18.7948ZM61.1099 14.8617C61.1099 16.2661 60.6111 18.6265 57.2773 18.6676H56.1095C54.6998 18.6676 52.3292 18.171 52.293 14.8617V7.23122C52.293 5.82531 52.7917 3.46069 56.1095 3.42529H57.2937C58.703 3.42529 61.0744 3.92197 61.1099 7.23122V14.8617ZM44.0577 21.6861H48.2971L42.3396 12.5366L40.2197 15.7922L44.0577 21.6861ZM42.3396 9.62064L48.2971 0.471191H44.0577L40.2197 6.36505L42.3396 9.62064ZM41.3893 11.0787L34.482 0.471191H30.2422L37.1495 11.0787L30.2422 21.6862H34.482L41.3893 11.0787ZM28.6586 18.7948C29.5806 17.1971 29.6798 15.5118 29.6798 14.8618V7.21299C29.6416 3.63618 27.8602 1.86947 26.3731 1.01732C24.7703 0.0989541 23.0809 0 22.429 0H21.227C17.6405 0.0384399 15.869 1.81467 15.0146 3.29784C14.0937 4.89632 13.9941 6.58083 13.9941 7.23126V14.8804C14.0331 18.4572 15.8141 20.2236 17.3016 21.0761C18.904 21.9941 20.5931 22.093 21.2453 22.093H22.4329H22.442C26.0308 22.0534 27.8034 20.2776 28.6586 18.7948ZM26.2443 14.8617C26.2443 16.2661 25.7462 18.6265 22.4121 18.6676H21.2443C19.8346 18.6676 17.464 18.171 17.4277 14.8617V7.23122C17.4277 5.82531 17.9261 3.46069 21.2443 3.42529H22.4281C23.8382 3.42529 26.2092 3.92197 26.2443 7.23122V14.8617ZM1.25362 21.6644H12.3717V18.1044H3.78565V0.471133H0V18.1044V19.7398L1.25362 21.6644Z" fill="currentColor"/></svg>"""

# Kleines grünes Icon für Login-Seite
LOXONE_ICON = """<svg width="36" height="36" viewBox="0 0 36 36" fill="none" xmlns="http://www.w3.org/2000/svg">
<rect width="36" height="36" rx="6" fill="#69A533"/>
<path d="M9 9h4.5v13.5H24V27H9V9z" fill="white"/>
<path d="M25 15l-5.5 5.5-3-3-2 2 5 5 7.5-7.5L25 15z" fill="white"/>
</svg>"""


def _nav(active_page=""):
    u        = session.get("user", "")
    is_admin = load_users().get(u, {}).get("role") == "admin"
    links = [("dashboard", "/", "Dashboard")]
    if is_admin:
        links += [
            ("users",       "/users",       "Benutzer"),
            ("einstellungen","/einstellungen","Einstellungen"),
            ("verlauf",     "/verlauf",     "Verlauf"),
        ]
    items = ""
    for key, href, label in links:
        cls = "active" if active_page == key else ""
        items += f'<a href="{href}" class="{cls}">{label}</a>'
    return f"""
<nav>
  <a class="nav-brand" href="/">
    {LOXONE_LOGO}
    <span style="color:#aaa;font-size:11px;font-weight:400;margin-left:8px;border-left:1px solid #444;padding-left:10px;letter-spacing:.04em">Debug Server</span>
  </a>
  <div class="nav-links">{items}</div>
  <div class="nav-right">
    <span>{u}</span>
    <a href="{url_for('logout')}">Abmelden</a>
  </div>
</nav>"""


def page(body: str, title: str = "Loxone Debug Server", active: str = "") -> str:
    msgs = get_flashed_messages(with_categories=True)
    alerts = "".join(
        f'<div class="alert alert-{cat}">{msg}</div>' for cat, msg in msgs
    )
    nav_html = _nav(active) if session.get("user") else ""
    return f"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — Loxone Debug Server</title>
<style>{CSS}</style>
</head>
<body>
{nav_html}
<div class="container">
{alerts}
{body}
</div>
<div class="site-footer">Loxone Debug Server V1.01 &mdash; von Silas Hoffmann</div>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════
# Login / Logout
# ══════════════════════════════════════════════════════════════════════════
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        users    = load_users()
        if username in users and check_pw(users[username]["password"], password):
            session["user"] = username
            add_audit("Login", f"Erfolgreich von {request.remote_addr}")
            return redirect(url_for("dashboard"))
        add_audit("Login fehlgeschlagen", f"Benutzer: {username} von {request.remote_addr}")
        flash("Falscher Benutzername oder Passwort.", "error")

    body = f"""
<div class="login-wrap">
  <div class="login-box">
    <div class="login-logo">
      <div class="logo-mark">{LOXONE_ICON}</div>
      <div>
        <div class="name">Loxone Debug Server</div>
        <div class="sub">Miniserver Log Management</div>
      </div>
    </div>
    <h2>Anmelden</h2>
    <p>Bitte melden Sie sich mit Ihren Zugangsdaten an.</p>
    {"".join(f'<div class="alert alert-{c}">{m}</div>' for c, m in get_flashed_messages(with_categories=True))}
    <form method="post">
      <div class="form-group" style="margin-bottom:14px">
        <label>Benutzername</label>
        <input name="username" autofocus autocomplete="username">
      </div>
      <div class="form-group" style="margin-bottom:22px">
        <label>Passwort</label>
        <input type="password" name="password" autocomplete="current-password">
      </div>
      <button class="btn btn-primary" style="width:100%;justify-content:center;padding:10px">
        Anmelden
      </button>
    </form>
  </div>
</div>"""
    return f"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Anmelden — Loxone Debug Server</title>
<style>{CSS}</style>
</head>
<body>{body}</body>
</html>"""


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ══════════════════════════════════════════════════════════════════════════
# Dashboard
# ══════════════════════════════════════════════════════════════════════════
@app.route("/")
@login_req
def dashboard():
    active, completed = stream_stats()
    now = time.time()

    total_bytes = sum(s["bytes_written"] for s in active + completed)
    ip_set = {s["ip"] for s in active + completed}

    # Stats
    stats = f"""
<div class="stats-grid">
  <div class="stat-card accent">
    <div class="val">{len(active)}</div>
    <div class="lbl">Aktive Streams</div>
  </div>
  <div class="stat-card">
    <div class="val">{len(completed)}</div>
    <div class="lbl">Beendete Sessions</div>
  </div>
  <div class="stat-card">
    <div class="val">{len(ip_set)}</div>
    <div class="lbl">Bekannte Miniserver</div>
  </div>
  <div class="stat-card">
    <div class="val">{fmt_bytes(int(total_bytes))}</div>
    <div class="lbl">Gesamtvolumen</div>
  </div>
</div>"""

    sort_js = """
<script>
function sortTable(th) {
  var table = th.closest('table');
  var tbody = table.querySelector('tbody');
  var idx   = Array.from(th.parentNode.children).indexOf(th);
  var asc   = th.classList.contains('sort-desc');
  table.querySelectorAll('th.sortable').forEach(function(h){ h.classList.remove('sort-asc','sort-desc'); });
  th.classList.add(asc ? 'sort-asc' : 'sort-desc');
  var rows = Array.from(tbody.querySelectorAll('tr'));
  rows.sort(function(a,b){
    var av = a.cells[idx] ? a.cells[idx].innerText.trim() : '';
    var bv = b.cells[idx] ? b.cells[idx].innerText.trim() : '';
    return asc ? av.localeCompare(bv) : bv.localeCompare(av);
  });
  rows.forEach(function(r){ tbody.appendChild(r); });
}
</script>"""

    # Active streams
    if active:
        rows = ""
        for s in sorted(active, key=lambda x: x["last_seen"], reverse=True):
            age    = int(now - s["last_seen"])
            dur    = int(now - datetime.fromisoformat(s["start_time"]).timestamp())
            folder = s.get("folder", s["ip"].replace(":", "_"))
            rows += f"""
            <tr>
              <td><span class="badge badge-green"><span class="pulse pulse-green"></span>Aktiv</span></td>
              <td class="mono"><strong>{s['ip']}</strong></td>
              <td>{s['start_time'].replace('T',' ')[:19]}</td>
              <td>{dur} s</td>
              <td>vor {age} s</td>
              <td class="size">{fmt_bytes(s['bytes_written'])}</td>
              <td>
                <div class="actions">
                  <a class="btn btn-sm btn-outline"  href="{url_for('files', folder=folder)}">Ordner</a>
                  <a class="btn btn-sm btn-primary"  href="{url_for('download_folder', folder=folder)}">ZIP</a>
                  <a class="btn btn-sm btn-success"  href="{url_for('live_stream', ip=s['ip'])}">&#9654; Live</a>
                  <form class="inline" method="post" action="{url_for('delete_folder')}"
                        onsubmit="return confirm('Ordner {folder} und alle Dateien löschen?')">
                    <input type="hidden" name="folder" value="{folder}">
                    <button class="btn btn-sm btn-danger">Löschen</button>
                  </form>
                </div>
              </td>
            </tr>"""
        active_card = f"""
        <div class="card">
          <div class="card-header">
            <h2>Aktive Datenstreams</h2>
            <span class="badge badge-green"><span class="pulse pulse-green"></span>{len(active)} aktiv</span>
          </div>
          <div class="tbl-wrap">
            <table id="tbl-active">
              <thead><tr>
                <th>Status</th>
                <th class="sortable" onclick="sortTable(this)">IP-Adresse</th>
                <th class="sortable" onclick="sortTable(this)">Start</th>
                <th>Laufzeit</th><th>Letztes Paket</th><th>Volumen</th><th>Aktionen</th>
              </tr></thead>
              <tbody>{rows}</tbody>
            </table>
          </div>
        </div>"""
    else:
        active_card = """
        <div class="card">
          <div class="card-header"><h2>Aktive Datenstreams</h2></div>
          <div class="empty">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>
            </svg>
            <p>Keine aktiven Streams — warte auf Miniserver-Verbindung auf Port 7777</p>
          </div>
        </div>"""

    # Completed streams
    if completed:
        rows = ""
        for s in completed[:100]:
            dur = ""
            try:
                start = datetime.fromisoformat(s["start_time"])
                end   = datetime.fromisoformat(s["end_time"])
                dur   = str(int((end - start).total_seconds())) + " s"
            except Exception:
                pass
            folder = s.get("folder", s["ip"].replace(":", "_"))
            rows += f"""
            <tr>
              <td><span class="badge badge-gray"><span class="pulse pulse-gray"></span>Beendet</span></td>
              <td class="mono">{s['ip']}</td>
              <td>{s['start_time'].replace('T',' ')[:19]}</td>
              <td>{s.get('end_time','—').replace('T',' ')[:19]}</td>
              <td>{dur}</td>
              <td class="size">{fmt_bytes(s['bytes_written'])}</td>
              <td>
                <div class="actions">
                  <a class="btn btn-sm btn-outline" href="{url_for('files', folder=folder)}">Ordner</a>
                  <a class="btn btn-sm btn-primary" href="{url_for('download_folder', folder=folder)}">ZIP</a>
                  <form class="inline" method="post" action="{url_for('delete_folder')}"
                        onsubmit="return confirm('Ordner {folder} und alle Dateien löschen?')">
                    <input type="hidden" name="folder" value="{folder}">
                    <button class="btn btn-sm btn-danger">Löschen</button>
                  </form>
                </div>
              </td>
            </tr>"""
        completed_card = f"""
        <div class="card">
          <div class="card-header">
            <h2>Beendete Sessions</h2>
            <span class="badge badge-gray">{len(completed)} gesamt</span>
          </div>
          <div class="tbl-wrap">
            <table id="tbl-completed">
              <thead><tr>
                <th>Status</th>
                <th class="sortable" onclick="sortTable(this)">IP-Adresse</th>
                <th class="sortable" onclick="sortTable(this)">Start</th>
                <th class="sortable" onclick="sortTable(this)">Ende</th>
                <th>Dauer</th><th>Volumen</th><th>Aktionen</th>
              </tr></thead>
              <tbody>{rows}</tbody>
            </table>
          </div>
        </div>"""
    else:
        completed_card = """
        <div class="card">
          <div class="card-header"><h2>Beendete Sessions</h2></div>
          <div class="empty"><p>Noch keine beendeten Sessions.</p></div>
        </div>"""

    header = """
    <div class="page-header">
      <h1>Dashboard</h1>
      <p>Echtzeit-Übersicht aller Miniserver Debug-Streams</p>
    </div>
    <div class="refresh-note">Seite aktualisiert automatisch alle 10 Sekunden</div>"""

    meta_refresh = '<meta http-equiv="refresh" content="10">'
    body = header + stats + active_card + completed_card + sort_js

    result = page(body, "Dashboard", "dashboard")
    return result.replace("</head>", f"{meta_refresh}</head>", 1)


# ══════════════════════════════════════════════════════════════════════════
# Datei-Browser
# ══════════════════════════════════════════════════════════════════════════
@app.route("/files/")
@app.route("/files")
@login_req
def files():
    folder = request.args.get("folder", "").strip()
    LOG_BASE_DIR.mkdir(exist_ok=True)

    _FOLDER_RE = re.compile(r'^(.+)_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})$')

    def _parse_folder(name: str):
        """Gibt (display_ip, start_dt_str) zurück. Fällt auf Rohname zurück."""
        m = _FOLDER_RE.match(name)
        if m:
            ip_part = m.group(1).replace("_", ".")
            dt_part = m.group(2).replace("_", " ").replace("-", ":", 2)
            return ip_part, dt_part
        return name.replace("_", ":"), "—"

    if not folder:
        # Ordner-Liste (sortiert nach Änderungszeit, neueste zuerst)
        entries = []
        for d in sorted(LOG_BASE_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if d.is_dir():
                logs   = list(d.glob("*.log"))
                size   = sum(f.stat().st_size for f in logs)
                disp_ip, disp_dt = _parse_folder(d.name)
                entries.append((d.name, disp_ip, disp_dt, len(logs), size))

        if entries:
            rows = ""
            for name, disp_ip, disp_dt, cnt, size in entries:
                rows += f"""
                <tr>
                  <td class="mono">
                    <a href="{url_for('files', folder=name)}" style="color:var(--green);font-weight:600">{disp_ip}</a>
                  </td>
                  <td style="color:var(--muted);font-size:12px">{disp_dt}</td>
                  <td>{cnt}</td>
                  <td class="size">{fmt_bytes(size)}</td>
                  <td>
                    <div class="actions">
                      <a class="btn btn-sm btn-outline" href="{url_for('files', folder=name)}">Öffnen</a>
                      <a class="btn btn-sm btn-primary" href="{url_for('download_folder', folder=name)}">ZIP Download</a>
                      <form class="inline" method="post" action="{url_for('delete_folder')}"
                            onsubmit="return confirm('Ordner &laquo;{name}&raquo; und alle Dateien löschen?')">
                        <input type="hidden" name="folder" value="{name}">
                        <button class="btn btn-sm btn-danger">Löschen</button>
                      </form>
                    </div>
                  </td>
                </tr>"""
            table = f"""
            <div class="tbl-wrap">
            <table>
              <thead><tr>
                <th>Miniserver IP</th><th>Startzeit</th><th>Log-Dateien</th>
                <th>Gesamtgröße</th><th>Aktionen</th>
              </tr></thead>
              <tbody>{rows}</tbody>
            </table>
            </div>"""
        else:
            table = """
            <div class="empty">
              <p>Noch keine Logs vorhanden. Warte auf eingehende UDP-Pakete auf Port 7777.</p>
            </div>"""

        header = """
        <div class="page-header">
          <h1>Dateien</h1>
          <p>Log-Archive – jede Session erhält einen eigenen Ordner (IP + Startzeit)</p>
        </div>"""
        bc   = f'<div class="bc"><span>Logs</span></div>'
        body = header + bc + f'<div class="card"><div class="card-header"><h2>Miniserver Ordner</h2></div>{table}</div>'
        return page(body, "Dateien", "files")

    # Dateien in einem IP-Ordner
    try:
        ip_dir = safe_path(LOG_BASE_DIR, folder)
    except Exception:
        abort(400)
    if not ip_dir.is_dir():
        flash(f"Ordner nicht gefunden.", "error")
        return redirect(url_for("files"))

    logs = sorted(ip_dir.glob("*.log"), key=lambda f: f.stat().st_mtime, reverse=True)
    disp_ip, disp_dt = _parse_folder(folder)
    display_ip = f"{disp_ip}" + (f" &nbsp;<span style='font-size:13px;font-weight:400;color:var(--muted)'>{disp_dt}</span>" if disp_dt != "—" else "")

    if logs:
        rows = ""
        total_size = 0
        for f in logs:
            stat   = f.stat()
            mtime  = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            total_size += stat.st_size
            rows += f"""
            <tr>
              <td class="mono">{f.name}</td>
              <td class="size">{fmt_bytes(stat.st_size)}</td>
              <td>{mtime}</td>
              <td>
                <div class="actions">
                  <a class="btn btn-sm btn-success"
                     href="{url_for('download_file_single', folder=folder, filename=f.name)}">Download</a>
                  <form class="inline" method="post" action="{url_for('delete_file')}"
                        onsubmit="return confirm('Datei &laquo;{f.name}&raquo; löschen?')">
                    <input type="hidden" name="folder"   value="{folder}">
                    <input type="hidden" name="filename" value="{f.name}">
                    <button class="btn btn-sm btn-danger">Löschen</button>
                  </form>
                </div>
              </td>
            </tr>"""
        table = f"""
        <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th>Dateiname</th><th>Größe</th><th>Erstellt</th><th>Aktionen</th>
          </tr></thead>
          <tbody>{rows}</tbody>
        </table>
        </div>
        <div style="padding:12px 16px;border-top:1px solid var(--border);background:#fafafa;
                    font-size:12px;color:var(--muted);">
          {len(logs)} Datei(en) &middot; {fmt_bytes(total_size)} gesamt
        </div>"""

        zip_btn = f'<a class="btn btn-primary" href="{url_for("download_folder", folder=folder)}">ZIP-Archiv herunterladen ({fmt_bytes(total_size)})</a>'
        del_btn = f"""
        <form class="inline" method="post" action="{url_for('delete_folder')}"
              onsubmit="return confirm('Gesamten Ordner &laquo;{folder}&raquo; löschen?')">
          <input type="hidden" name="folder" value="{folder}">
          <button class="btn btn-danger">Ordner löschen</button>
        </form>"""
        action_bar = f'<div class="actions" style="margin-bottom:16px">{zip_btn}{del_btn}</div>'
    else:
        table = '<div class="empty"><p>Keine Log-Dateien in diesem Ordner.</p></div>'
        action_bar = ""

    bc = f"""
    <div class="bc">
      <a href="{url_for('files')}">Logs</a>
      <span class="bc-sep">›</span>
      <span class="mono">{disp_ip}</span>
      {f'<span class="bc-sep">›</span><span>{disp_dt}</span>' if disp_dt != "—" else ""}
    </div>"""
    header = f"""
    <div class="page-header">
      <h1 class="mono">{display_ip}</h1>
      <p>Debug-Logs dieses Miniserver</p>
    </div>"""
    body = header + bc + action_bar + f'<div class="card"><div class="card-header"><h2>Log-Dateien</h2></div>{table}</div>'
    return page(body, disp_ip, "files")


@app.route("/download/<folder>/<filename>")
@login_req
def download_file_single(folder: str, filename: str):
    """Download einer einzelnen Log-Datei."""
    try:
        path = safe_path(LOG_BASE_DIR, folder + "/" + filename)
    except Exception:
        abort(400)
    if not path.is_file():
        abort(404)
    add_audit("Download Datei", f"{folder}/{filename}")
    return send_file(path, as_attachment=True, download_name=filename)


@app.route("/download/<folder>")
@login_req
def download_folder(folder: str):
    """Packt den gesamten IP-Ordner als ZIP und sendet ihn."""
    try:
        ip_dir = safe_path(LOG_BASE_DIR, folder)
    except Exception:
        abort(400)
    if not ip_dir.is_dir():
        abort(404)

    logs = list(ip_dir.glob("*.log"))
    if not logs:
        flash("Keine Dateien zum Herunterladen.", "error")
        return redirect(url_for("files", folder=folder))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(logs):
            zf.write(f, arcname=f.name)
    buf.seek(0)

    display_ip = folder.replace("_", "-")
    zip_name   = f"loxone-debug-{display_ip}.zip"
    add_audit("Download ZIP", f"{folder} ({len(logs)} Dateien)")
    return send_file(buf, as_attachment=True, download_name=zip_name,
                     mimetype="application/zip")


@app.route("/delete_file", methods=["POST"])
@login_req
def delete_file():
    folder   = request.form.get("folder",   "").strip()
    filename = request.form.get("filename", "").strip()
    try:
        path = safe_path(LOG_BASE_DIR, folder + "/" + filename)
    except Exception:
        flash("Ungültiger Pfad.", "error")
        return redirect(url_for("files"))
    if path.is_file():
        path.unlink()
        add_audit("Datei gelöscht", f"{folder}/{filename}")
        flash(f"Datei gelöscht.", "success")
    else:
        flash("Datei nicht gefunden.", "error")
    return redirect(url_for("files", folder=folder))


@app.route("/delete_folder", methods=["POST"])
@login_req
def delete_folder():
    folder = request.form.get("folder", "").strip()
    try:
        path = safe_path(LOG_BASE_DIR, folder)
    except Exception:
        flash("Ungültiger Pfad.", "error")
        return redirect(url_for("files"))
    if path.is_dir():
        shutil.rmtree(path)
        add_audit("Ordner gelöscht", folder)
        flash(f"Ordner gelöscht.", "success")
    else:
        flash("Ordner nicht gefunden.", "error")
    return redirect(url_for("files"))


# ══════════════════════════════════════════════════════════════════════════
# Live Stream
# ══════════════════════════════════════════════════════════════════════════
@app.route("/live/<path:ip>")
@login_req
def live_stream(ip: str):
    with _lock:
        is_active = ip in active_streams
        if is_active:
            logfile = active_streams[ip]["logfile"]
            folder  = active_streams[ip].get("folder", ip.replace(":", "_"))
        else:
            match   = next((s for s in completed_streams if s["ip"] == ip), None)
            logfile = match["logfile"] if match else None
            folder  = match.get("folder", ip.replace(":", "_")) if match else ip.replace(":", "_")

    if not logfile:
        flash("Kein Log für diese IP gefunden.", "error")
        return redirect(url_for("dashboard"))
    status_badge = (
        '<span class="live-badge"><span class="pulse pulse-green"></span>LIVE</span>'
        if is_active else
        '<span class="badge badge-gray">Beendet</span>'
    )

    body = f"""
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:10px">
      <div>
        <div class="page-header" style="margin-bottom:0">
          <h1 class="mono" style="display:inline">{ip}</h1>
          &nbsp;&nbsp;{status_badge}
        </div>
        <p style="font-size:13px;color:var(--muted);margin-top:4px">Debug-Stream Liveansicht</p>
      </div>
      <div class="actions">
        <a class="btn btn-secondary" href="{url_for('files', folder=folder)}">Ordner</a>
        <a class="btn btn-primary"   href="{url_for('download_folder', folder=folder)}">ZIP Download</a>
        <a class="btn btn-secondary" href="{url_for('dashboard')}">&#8592; Dashboard</a>
      </div>
    </div>
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
      <span style="font-size:12px;color:var(--muted)">Letzte <strong id="line-count">—</strong> Zeilen</span>
      <label style="font-size:12px;color:var(--muted);display:flex;align-items:center;gap:6px;cursor:pointer">
        <input type="checkbox" id="autoscroll" checked> Auto-Scroll
      </label>
    </div>
    <div class="terminal" id="terminal">
      <div style="color:#58a6ff;padding:8px 0">Verbinde...</div>
    </div>
    <script>
    var lastCount = 0;
    var ip = {json.dumps(ip)};
    var active = {'true' if is_active else 'false'};

    function fetchLines() {{
      fetch('/api/tail/' + encodeURIComponent(ip) + '?after=' + lastCount)
        .then(function(r){{ return r.json(); }})
        .then(function(d){{
          var term = document.getElementById('terminal');
          if (d.lines && d.lines.length > 0) {{
            if (lastCount === 0) term.innerHTML = '';
            d.lines.forEach(function(l) {{
              var div = document.createElement('div');
              div.className = 'ln';
              div.textContent = l;
              term.appendChild(div);
            }});
            lastCount = d.total;
            document.getElementById('line-count').textContent = d.total;
            if (document.getElementById('autoscroll').checked)
              term.scrollTop = term.scrollHeight;
          }}
          if (!d.active && lastCount > 0) {{
            var div = document.createElement('div');
            div.style.color='#f0883e'; div.style.padding='8px 0';
            div.textContent = '— Stream beendet —';
            term.appendChild(div);
            return;
          }}
          if (active || d.active) setTimeout(fetchLines, 2000);
        }})
        .catch(function(){{ setTimeout(fetchLines, 3000); }});
    }}
    fetchLines();
    </script>"""

    return page(body, f"Live: {ip}", "dashboard")


@app.route("/api/tail/<path:ip>")
@login_req
def api_tail(ip: str):
    """Gibt neue Zeilen des aktiven Log-Streams zurück."""
    after = int(request.args.get("after", 0))
    with _lock:
        is_active = ip in active_streams
        logfile   = active_streams[ip]["logfile"] if is_active else None
        if not is_active:
            match = next((s for s in completed_streams if s["ip"] == ip), None)
            logfile = match["logfile"] if match else None

    if not logfile or not Path(logfile).is_file():
        return jsonify({"lines": [], "total": 0, "active": False})

    try:
        with open(logfile, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
        total = len(all_lines)
        # Beim ersten Aufruf nur letzte 200 Zeilen liefern
        if after == 0:
            lines = [l.rstrip() for l in all_lines[-200:]]
            return jsonify({"lines": lines, "total": total, "active": is_active})
        # Sonst nur neue Zeilen ab `after`
        new_lines = [l.rstrip() for l in all_lines[after:]]
        return jsonify({"lines": new_lines, "total": total, "active": is_active})
    except Exception as e:
        return jsonify({"lines": [], "total": 0, "active": False, "error": str(e)})


# ══════════════════════════════════════════════════════════════════════════
# Benutzerverwaltung
# ══════════════════════════════════════════════════════════════════════════
@app.route("/users")
@admin_req
def users():
    all_users = load_users()

    rows = ""
    for uname, info in sorted(all_users.items()):
        is_self  = uname == session["user"]
        role_cls = "role-admin" if info.get("role") == "admin" else "role-user"
        role_lbl = "Administrator" if info.get("role") == "admin" else "Benutzer"
        you      = ' <span style="font-size:11px;color:var(--muted)">(Sie)</span>' if is_self else ""
        del_btn  = "" if is_self else f"""
            <form class="inline" method="post" action="{url_for('user_delete')}"
                  onsubmit="return confirm('Benutzer &laquo;{uname}&raquo; wirklich löschen?')">
              <input type="hidden" name="username" value="{uname}">
              <button class="btn btn-sm btn-danger">Löschen</button>
            </form>"""
        rows += f"""
        <tr>
          <td><strong>{uname}</strong>{you}</td>
          <td><span class="{role_cls}">{role_lbl}</span></td>
          <td>
            <div class="actions">
              <a class="btn btn-sm btn-secondary"
                 href="{url_for('user_edit', username=uname)}">Bearbeiten</a>
              {del_btn}
            </div>
          </td>
        </tr>"""

    user_table = f"""
    <div class="card">
      <div class="card-header">
        <h2>Benutzer</h2>
        <span class="badge badge-gray">{len(all_users)} Benutzer</span>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>Benutzername</th><th>Rolle</th><th>Aktionen</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>"""

    add_form = f"""
    <div class="card">
      <div class="card-header"><h2>Neuen Benutzer anlegen</h2></div>
      <div class="card-body">
        <form method="post" action="{url_for('user_add')}">
          <div class="form-row">
            <div class="form-group">
              <label>Benutzername</label>
              <input name="username" required autocomplete="off">
            </div>
            <div class="form-group">
              <label>Passwort</label>
              <input type="password" name="password" required autocomplete="new-password">
            </div>
            <div class="form-group">
              <label>Rolle</label>
              <select name="role">
                <option value="user">Benutzer</option>
                <option value="admin">Administrator</option>
              </select>
            </div>
            <div class="form-group" style="justify-content:flex-end">
              <button class="btn btn-primary">Anlegen</button>
            </div>
          </div>
        </form>
      </div>
    </div>"""

    header = """
    <div class="page-header">
      <h1>Benutzerverwaltung</h1>
      <p>Zugangsdaten und Berechtigungen verwalten</p>
    </div>"""
    return page(header + user_table + add_form, "Benutzer", "users")


@app.route("/users/add", methods=["POST"])
@admin_req
def user_add():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role     = request.form.get("role", "user")
    users    = load_users()
    if not username or not password:
        flash("Benutzername und Passwort dürfen nicht leer sein.", "error")
    elif username in users:
        flash(f"Benutzer bereits vorhanden.", "error")
    elif role not in ("admin", "user"):
        flash("Ungültige Rolle.", "error")
    else:
        users[username] = {"password": hash_pw(password), "role": role}
        save_users(users)
        role_lbl = "Administrator" if role == "admin" else "Benutzer"
        add_audit("Benutzer angelegt", f"{username} (Rolle: {role_lbl})")
        flash(f"Benutzer '{username}' wurde angelegt.", "success")
    return redirect(url_for("users"))


@app.route("/users/edit/<username>", methods=["GET", "POST"])
@admin_req
def user_edit(username: str):
    all_users = load_users()
    if username not in all_users:
        flash("Benutzer nicht gefunden.", "error")
        return redirect(url_for("users"))

    if request.method == "POST":
        new_pw   = request.form.get("password", "").strip()
        new_role = request.form.get("role", "")
        if new_pw:
            all_users[username]["password"] = hash_pw(new_pw)
        if new_role in ("admin", "user"):
            if username == session["user"] and new_role != "admin":
                admins = [u for u, v in all_users.items() if v.get("role") == "admin"]
                if len(admins) <= 1:
                    flash("Letzten Administrator nicht degradierbar.", "error")
                    return redirect(url_for("user_edit", username=username))
            all_users[username]["role"] = new_role
        save_users(all_users)
        changes = []
        if new_pw: changes.append("Passwort geändert")
        if new_role in ("admin", "user"): changes.append(f"Rolle: {new_role}")
        add_audit("Benutzer bearbeitet", f"{username} – {', '.join(changes) if changes else 'keine Änderung'}")
        flash(f"Benutzer '{username}' aktualisiert.", "success")
        return redirect(url_for("users"))

    info       = all_users[username]
    is_self    = username == session["user"]
    role_opts  = "".join(
        f'<option value="{r}" {"selected" if info["role"]==r else ""}>'
        f'{"Administrator" if r=="admin" else "Benutzer"}</option>'
        for r in ("user", "admin")
    )
    dis_role = 'disabled title="Eigene Rolle kann nicht geändert werden"' if is_self else ""

    bc = f"""
    <div class="bc">
      <a href="{url_for('users')}">Benutzer</a>
      <span class="bc-sep">›</span>
      <span>{username}</span>
    </div>"""
    form = f"""
    <div class="card" style="max-width:480px">
      <div class="card-header"><h2>Benutzer bearbeiten: {username}</h2></div>
      <div class="card-body">
        <form method="post">
          <div class="form-group" style="margin-bottom:16px">
            <label>Neues Passwort <span style="font-weight:400;text-transform:none;color:#aaa">(leer = nicht ändern)</span></label>
            <input type="password" name="password" autocomplete="new-password">
          </div>
          <div class="form-group" style="margin-bottom:24px">
            <label>Rolle</label>
            <select name="role" {dis_role}>{role_opts}</select>
          </div>
          <div class="actions">
            <button class="btn btn-primary">Speichern</button>
            <a class="btn btn-secondary" href="{url_for('users')}">Abbrechen</a>
          </div>
        </form>
      </div>
    </div>"""
    header = f"""
    <div class="page-header">
      <h1>Benutzer: {username}</h1>
    </div>"""
    return page(header + bc + form, f"Benutzer: {username}", "users")


@app.route("/users/delete", methods=["POST"])
@admin_req
def user_delete():
    username  = request.form.get("username", "").strip()
    all_users = load_users()
    if username == session["user"]:
        flash("Eigenen Account nicht löschbar.", "error")
    elif username not in all_users:
        flash("Benutzer nicht gefunden.", "error")
    else:
        admins = [u for u, v in all_users.items() if v.get("role") == "admin"]
        if all_users[username].get("role") == "admin" and len(admins) <= 1:
            flash("Letzten Administrator nicht löschbar.", "error")
        else:
            del all_users[username]
            save_users(all_users)
            add_audit("Benutzer gelöscht", username)
            flash(f"Benutzer '{username}' gelöscht.", "success")
    return redirect(url_for("users"))


# ══════════════════════════════════════════════════════════════════════════
# Einstellungen
# ══════════════════════════════════════════════════════════════════════════
@app.route("/einstellungen", methods=["GET", "POST"])
@admin_req
def einstellungen():
    cfg = load_settings()
    port_changed = False

    if request.method == "POST":
        old_cfg = dict(cfg)
        try:
            http_port   = int(request.form.get("http_port",        cfg["http_port"]))
            udp_port    = int(request.form.get("udp_port",         cfg["udp_port"]))
            timeout     = int(request.form.get("stream_timeout",   cfg["stream_timeout"]))
            auto_delete = int(request.form.get("auto_delete_days", cfg["auto_delete_days"]))
            if not (1 <= http_port <= 65535 and 1 <= udp_port <= 65535):
                raise ValueError
            if not (1 <= timeout <= 3600):
                raise ValueError
            if auto_delete < 0:
                raise ValueError
        except (ValueError, TypeError):
            flash("Ungültige Eingabe. Ports: 1–65535, Timeout: 1–3600 s, Auto-Löschen: ≥ 0.", "error")
            return redirect(url_for("einstellungen"))

        cfg = {"http_port": http_port, "udp_port": udp_port,
               "stream_timeout": timeout, "auto_delete_days": auto_delete}
        save_settings(cfg)

        changes = []
        if old_cfg["http_port"]        != http_port:   changes.append(f"HTTP Port {old_cfg['http_port']} → {http_port}");     port_changed = True
        if old_cfg["udp_port"]         != udp_port:    changes.append(f"UDP Port {old_cfg['udp_port']} → {udp_port}");        port_changed = True
        if old_cfg["stream_timeout"]   != timeout:     changes.append(f"Timeout {old_cfg['stream_timeout']} → {timeout} s")
        if old_cfg["auto_delete_days"] != auto_delete: changes.append(f"Auto-Löschen {old_cfg['auto_delete_days']} → {auto_delete} Tage")

        if changes:
            add_audit("Einstellungen geändert", "; ".join(changes))
            if port_changed:
                flash("Einstellungen gespeichert. Port-Änderungen werden erst nach Neustart des Servers wirksam.", "success")
            else:
                flash("Einstellungen gespeichert.", "success")
        else:
            flash("Keine Änderungen.", "success")
        return redirect(url_for("einstellungen"))

    auto_del_val = cfg.get("auto_delete_days", 0)
    body = f"""
    <div class="page-header">
      <h1>Einstellungen</h1>
      <p>Server-Konfiguration – Port-Änderungen erfordern einen Neustart</p>
    </div>
    <div class="card" style="max-width:560px">
      <div class="card-header"><h2>Server-Parameter</h2></div>
      <div class="card-body">
        <form method="post">
          <div class="form-group" style="margin-bottom:18px">
            <label>HTTP Port <span style="font-weight:400;text-transform:none;color:#aaa">(Web-Interface, Neustart erforderlich)</span></label>
            <input type="number" name="http_port" value="{cfg['http_port']}" min="1" max="65535" required>
          </div>
          <div class="form-group" style="margin-bottom:18px">
            <label>UDP Port <span style="font-weight:400;text-transform:none;color:#aaa">(Miniserver Debug-Stream, Neustart erforderlich)</span></label>
            <input type="number" name="udp_port" value="{cfg['udp_port']}" min="1" max="65535" required>
          </div>
          <div class="form-group" style="margin-bottom:18px">
            <label>Stream Timeout <span style="font-weight:400;text-transform:none;color:#aaa">(Sekunden ohne Daten → Stream gilt als beendet, sofort aktiv)</span></label>
            <input type="number" name="stream_timeout" value="{cfg['stream_timeout']}" min="1" max="3600" required>
          </div>
          <div class="form-group" style="margin-bottom:24px">
            <label>Automatisch löschen nach <span style="font-weight:400;text-transform:none;color:#aaa">(Tage nach Stream-Ende, 0 = deaktiviert, sofort aktiv)</span></label>
            <input type="number" name="auto_delete_days" value="{auto_del_val}" min="0" max="3650" required>
          </div>
          <div class="actions">
            <button class="btn btn-primary">Speichern</button>
          </div>
        </form>
      </div>
    </div>
    <div class="card" style="max-width:560px;margin-top:16px">
      <div class="card-header"><h2>Aktuelle Werte</h2></div>
      <div class="card-body" style="display:grid;grid-template-columns:repeat(4,1fr);gap:14px">
        <div class="stat-card accent"><div class="val">{cfg['http_port']}</div><div class="lbl">HTTP Port</div></div>
        <div class="stat-card accent"><div class="val">{cfg['udp_port']}</div><div class="lbl">UDP Port</div></div>
        <div class="stat-card accent"><div class="val">{cfg['stream_timeout']} s</div><div class="lbl">Timeout</div></div>
        <div class="stat-card {'accent' if auto_del_val > 0 else ''}">
          <div class="val" style="font-size:20px">{f'{auto_del_val} d' if auto_del_val > 0 else 'Aus'}</div>
          <div class="lbl">Auto-Löschen</div>
        </div>
      </div>
    </div>
    <div class="card" style="max-width:560px;margin-top:16px">
      <div class="card-header"><h2>Server-Neustart</h2></div>
      <div class="card-body">
        <p style="font-size:13px;color:var(--muted);margin-bottom:16px">
          Startet den Server-Prozess neu. Alle aktiven Streams werden kurz unterbrochen.
          Port-Änderungen werden erst nach einem Neustart wirksam.
        </p>
        <form method="post" action="{url_for('restart_server')}"
              onsubmit="return confirm('Server wirklich neu starten?')">
          <button class="btn btn-danger">Server neu starten</button>
        </form>
      </div>
    </div>"""
    return page(body, "Einstellungen", "einstellungen")


# ══════════════════════════════════════════════════════════════════════════
# Server-Neustart
# ══════════════════════════════════════════════════════════════════════════
@app.route("/restart", methods=["POST"])
@admin_req
def restart_server():
    add_audit("Server-Neustart", f"Ausgelöst von {session.get('user','?')} ({request.remote_addr})")

    def do_restart():
        time.sleep(1.5)
        try:
            subprocess.Popen([sys.executable] + sys.argv,
                             close_fds=True,
                             creationflags=0)
        except TypeError:
            subprocess.Popen([sys.executable] + sys.argv, close_fds=True)
        os._exit(0)

    threading.Thread(target=do_restart, daemon=False).start()

    body = """
    <div class="page-header" style="text-align:center;padding-top:60px">
      <h1>Server wird neu gestartet&hellip;</h1>
      <p style="margin-top:8px">Bitte warten &mdash; die Seite lädt automatisch neu sobald der Server bereit ist.</p>
    </div>
    <div class="card" style="max-width:400px;margin:24px auto">
      <div class="card-body" style="text-align:center;padding:40px">
        <div style="font-size:40px;margin-bottom:16px;animation:spin 1s linear infinite;display:inline-block">&#8635;</div>
        <p style="color:var(--muted);font-size:13px">Verbinde neu&hellip;</p>
      </div>
    </div>
    <style>@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}</style>
    <script>
    setTimeout(function(){
      var t = setInterval(function(){
        fetch('/login').then(function(r){ if(r.ok){ clearInterval(t); location.href='/'; } }).catch(function(){});
      }, 1000);
    }, 2500);
    </script>"""
    return page(body, "Neustart", "einstellungen")


# ══════════════════════════════════════════════════════════════════════════
# Verlauf (Audit Log)
# ══════════════════════════════════════════════════════════════════════════
@app.route("/verlauf")
@admin_req
def verlauf():
    with _audit_lock:
        try:
            log = json.loads(AUDIT_FILE.read_text(encoding="utf-8")) if AUDIT_FILE.exists() else []
        except Exception:
            log = []

    if log:
        rows = ""
        for e in log:
            action_lower = e["action"].lower()
            action_cls = ""
            if "gelöscht" in action_lower:
                action_cls = 'style="color:var(--danger);font-weight:600"'
            elif "download" in action_lower:
                action_cls = 'style="color:var(--green-dark);font-weight:600"'
            elif "login fehlgeschlagen" in action_lower or "neustart" in action_lower:
                action_cls = 'style="color:#e65100;font-weight:600"'
            elif "stream gestartet" in action_lower:
                action_cls = 'style="color:var(--green);font-weight:600"'
            elif "stream beendet" in action_lower:
                action_cls = 'style="color:var(--muted);font-weight:600"'
            rows += f"""
            <tr>
              <td class="mono" style="white-space:nowrap;font-size:12px">{e['ts']}</td>
              <td><strong>{e['user']}</strong></td>
              <td {action_cls}>{e['action']}</td>
              <td style="color:var(--muted);font-size:12px">{e.get('detail','')}</td>
            </tr>"""
        table = f"""
        <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th>Zeitstempel</th><th>Benutzer</th><th>Aktion</th><th>Detail</th>
          </tr></thead>
          <tbody>{rows}</tbody>
        </table>
        </div>"""
    else:
        table = '<div class="empty"><p>Noch keine Einträge vorhanden.</p></div>'

    header = """
    <div class="page-header">
      <h1>Verlauf</h1>
      <p>Protokoll aller Aktionen: Benutzer, Downloads, Löschungen, Streams, Neustart</p>
    </div>"""
    body = header + f'<div class="card"><div class="card-header"><h2>Aktivitätsprotokoll</h2><span class="badge badge-gray">{len(log)} Einträge</span></div>{table}</div>'
    return page(body, "Verlauf", "verlauf")


# ══════════════════════════════════════════════════════════════════════════
# Start
# ══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    LOG_BASE_DIR.mkdir(exist_ok=True)
    load_users()

    for target in (udp_listener, stream_monitor):
        threading.Thread(target=target, daemon=True).start()

    print(f"[WEB] Webinterface auf http://0.0.0.0:{HTTP_PORT}")
    print(f"[WEB] Login: admin / admin  -- nach erstem Login bitte aendern!")
    app.run(host="0.0.0.0", port=HTTP_PORT, debug=False, use_reloader=False)
