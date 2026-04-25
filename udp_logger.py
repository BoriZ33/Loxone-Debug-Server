#!/usr/bin/env python3
"""
Loxone Debug Server V1.02
  - UDP Port 7777: schreibt Miniserver-Debug-Streams in logs/<IP_DATUM_UHRZEIT>/
  - HTTP Port 8080: Browse, ZIP-Download, Loeschen, Benutzerverwaltung
  - Standard-Login: admin / admin  (bitte sofort aendern)
"""

import io, json, os, re, socket, sys, threading, hashlib, secrets, time, shutil, zipfile, subprocess
from datetime import datetime
from pathlib import Path
from flask import (Flask, request, send_file, redirect, url_for,
                   session, flash, abort, get_flashed_messages, jsonify)
from functools import wraps

# ── Konfiguration ──────────────────────────────────────────────────────────
UDP_PORT       = 7777
HTTP_PORT      = 8080
LOG_BASE_DIR   = Path("logs")
USERS_FILE     = Path("users.json")
AUDIT_FILE     = Path("audit.json")
SETTINGS_FILE  = Path("settings.json")
STREAM_TIMEOUT = 30
VERSION        = "V1.02"

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
_SETTINGS_DEFAULTS = {"http_port": 8080, "udp_port": 7777, "stream_timeout": 30, "auto_delete_days": 0, "max_storage_mb": 0}

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

# ── Übersetzungen ──────────────────────────────────────────────────────────
TRANSLATIONS = {
    "de": {
        "nav_dashboard": "Dashboard", "nav_users": "Benutzer",
        "nav_settings": "Einstellungen", "nav_history": "Verlauf", "nav_logout": "Abmelden",
        "login_title": "Anmelden", "login_subtitle": "Bitte melden Sie sich mit Ihren Zugangsdaten an.",
        "login_user": "Benutzername", "login_pw": "Passwort", "login_btn": "Anmelden",
        "login_error": "Falscher Benutzername oder Passwort.",
        "dash_title": "Dashboard", "dash_subtitle": "Echtzeit-Übersicht aller Miniserver Debug-Streams",
        "dash_active_streams": "Aktive Datenstreams", "dash_completed": "Beendete Sessions",
        "dash_stat_active": "Aktive Streams", "dash_stat_completed": "Beendete Sessions",
        "dash_stat_servers": "Bekannte Miniserver", "dash_stat_volume": "Gesamtvolumen",
        "dash_no_active": "Keine aktiven Streams — warte auf Miniserver-Verbindung auf Port {port}",
        "dash_no_completed": "Noch keine beendeten Sessions.",
        "dash_refresh": "Seite aktualisiert automatisch alle 10 Sekunden",
        "tbl_status": "Status", "tbl_ip": "IP-Adresse", "tbl_start": "Start",
        "tbl_runtime": "Laufzeit", "tbl_last_pkt": "Letztes Paket", "tbl_volume": "Volumen",
        "tbl_actions": "Aktionen", "tbl_end": "Ende", "tbl_duration": "Dauer",
        "badge_active": "Aktiv", "badge_ended": "Beendet",
        "badge_active_count": "{n} aktiv", "badge_total": "{n} gesamt",
        "btn_folder": "Ordner", "btn_zip": "ZIP", "btn_live": "&#9654; Live",
        "btn_delete": "Löschen", "btn_open": "Öffnen", "btn_zip_dl": "ZIP Download",
        "btn_download": "Download", "btn_save": "Speichern", "btn_cancel": "Abbrechen",
        "btn_create": "Anlegen", "btn_edit": "Bearbeiten", "btn_restart": "Server neu starten",
        "confirm_delete_folder": "Ordner {name} und alle Dateien löschen?",
        "confirm_delete_file": "Datei «{name}» löschen?",
        "confirm_restart": "Server wirklich neu starten?",
        "confirm_delete_user": "Benutzer «{name}» wirklich löschen?",
        "files_title": "Dateien", "files_subtitle": "Log-Archive – jede Session erhält einen eigenen Ordner (IP + Startzeit)",
        "files_col_ip": "Miniserver IP", "files_col_start": "Startzeit",
        "files_col_logs": "Log-Dateien", "files_col_size": "Gesamtgröße", "files_col_action": "Aktionen",
        "files_no_logs": "Noch keine Logs vorhanden. Warte auf eingehende UDP-Pakete auf Port {port}.",
        "files_no_logs_folder": "Keine Log-Dateien in diesem Ordner.",
        "files_miniserver_logs": "Debug-Logs dieses Miniserver",
        "files_log_files": "Log-Dateien", "files_folders": "Miniserver Ordner",
        "files_col_filename": "Dateiname", "files_col_created": "Erstellt",
        "files_zip_download": "ZIP-Archiv herunterladen ({size})",
        "files_delete_folder": "Ordner löschen",
        "files_confirm_folder": "Gesamten Ordner «{name}» löschen?",
        "files_count": "{n} Datei(en) · {size} gesamt",
        "files_not_found": "Ordner nicht gefunden.",
        "files_no_dl": "Keine Dateien zum Herunterladen.",
        "files_invalid_path": "Ungültiger Pfad.",
        "files_deleted": "Datei gelöscht.", "files_not_found_file": "Datei nicht gefunden.",
        "folder_deleted": "Ordner gelöscht.", "folder_not_found": "Ordner nicht gefunden.",
        "users_title": "Benutzerverwaltung", "users_subtitle": "Zugangsdaten und Berechtigungen verwalten",
        "users_col_name": "Benutzername", "users_col_role": "Rolle", "users_you": "(Sie)",
        "users_admin": "Administrator", "users_user": "Benutzer",
        "users_new": "Neuen Benutzer anlegen",
        "users_edit_title": "Benutzer bearbeiten: {name}",
        "users_edit_pw": "Neues Passwort", "users_edit_pw_hint": "(leer = nicht ändern)",
        "users_edit_role": "Rolle", "users_edit_role_disabled": "Eigene Rolle kann nicht geändert werden",
        "users_err_empty": "Benutzername und Passwort dürfen nicht leer sein.",
        "users_err_exists": "Benutzer bereits vorhanden.",
        "users_err_role": "Ungültige Rolle.",
        "users_created": "Benutzer '{name}' wurde angelegt.",
        "users_updated": "Benutzer '{name}' aktualisiert.",
        "users_deleted": "Benutzer '{name}' gelöscht.",
        "users_err_self": "Eigenen Account nicht löschbar.",
        "users_err_not_found": "Benutzer nicht gefunden.",
        "users_err_last_admin_del": "Letzten Administrator nicht löschbar.",
        "users_err_last_admin_role": "Letzten Administrator nicht degradierbar.",
        "users_page": "Benutzer: {name}",
        "settings_title": "Einstellungen", "settings_subtitle": "Server-Konfiguration – Port-Änderungen erfordern einen Neustart",
        "settings_params": "Server-Parameter",
        "settings_http_port": "HTTP Port", "settings_http_port_hint": "(Web-Interface, Neustart erforderlich)",
        "settings_udp_port": "UDP Port", "settings_udp_port_hint": "(Miniserver Debug-Stream, Neustart erforderlich)",
        "settings_timeout": "Stream Timeout", "settings_timeout_hint": "(Sekunden ohne Daten → Stream gilt als beendet, sofort aktiv)",
        "settings_auto_delete": "Automatisch löschen nach", "settings_auto_delete_hint": "(Tage nach Stream-Ende, 0 = deaktiviert, sofort aktiv)",
        "settings_max_storage": "Maximaler Speicherbedarf", "settings_max_storage_hint": "(MB, 0 = deaktiviert — älteste Ordner werden automatisch gelöscht, sofort aktiv)",
        "settings_current": "Aktuelle Werte", "settings_timeout_lbl": "Timeout",
        "settings_auto_delete_lbl": "Auto-Löschen", "settings_auto_delete_off": "Aus",
        "settings_max_storage_lbl": "Max. Speicher", "settings_max_storage_off": "Aus",
        "settings_restart_title": "Server-Neustart",
        "settings_restart_desc": "Startet den Server-Prozess neu. Alle aktiven Streams werden kurz unterbrochen. Port-Änderungen werden erst nach einem Neustart wirksam.",
        "settings_err": "Ungültige Eingabe. Ports: 1–65535, Timeout: 1–3600 s, Auto-Löschen: ≥ 0, Max. Speicher: ≥ 0.",
        "settings_saved": "Einstellungen gespeichert.",
        "settings_saved_restart": "Einstellungen gespeichert. Port-Änderungen werden erst nach Neustart des Servers wirksam.",
        "settings_no_change": "Keine Änderungen.",
        "history_title": "Verlauf", "history_subtitle": "Protokoll aller Aktionen: Benutzer, Downloads, Löschungen, Streams, Neustart",
        "history_log": "Aktivitätsprotokoll", "history_entries": "{n} Einträge",
        "history_empty": "Noch keine Einträge vorhanden.",
        "history_col_ts": "Zeitstempel", "history_col_user": "Benutzer",
        "history_col_action": "Aktion", "history_col_detail": "Detail",
        "restart_title": "Server wird neu gestartet…",
        "restart_subtitle": "Bitte warten — die Seite lädt automatisch neu sobald der Server bereit ist.",
        "restart_connecting": "Verbinde neu…",
        "live_subtitle": "Debug-Stream Liveansicht", "live_lines": "Letzte", "live_lines2": "Zeilen",
        "live_autoscroll": "Auto-Scroll", "live_connecting": "Verbinde...",
        "live_ended": "— Stream beendet —",
        "live_no_log": "Kein Log für diese IP gefunden.",
        "logs_bc": "Logs", "before_n_s": "vor {n} s", "lang_label": "Sprache",
        "audit_login_ok": "Login", "audit_login_fail": "Login fehlgeschlagen",
        "audit_stream_start": "Stream gestartet", "audit_stream_end": "Stream beendet",
        "audit_dl_file": "Download Datei", "audit_dl_zip": "Download ZIP",
        "audit_del_file": "Datei gelöscht", "audit_del_folder": "Ordner gelöscht",
        "audit_auto_del": "Automatisch gelöscht", "audit_storage_del": "Speicherlimit: gelöscht", "audit_user_add": "Benutzer angelegt",
        "audit_user_edit": "Benutzer bearbeitet", "audit_user_del": "Benutzer gelöscht",
        "audit_settings": "Einstellungen geändert", "audit_restart": "Server-Neustart",
        "audit_pw_changed": "Passwort geändert", "audit_role": "Rolle",
        "audit_no_change": "keine Änderung",
        "footer": f"Loxone Debug Server {VERSION} &mdash; von Silas Hoffmann",
    },
    "en": {
        "nav_dashboard": "Dashboard", "nav_users": "Users",
        "nav_settings": "Settings", "nav_history": "History", "nav_logout": "Sign out",
        "login_title": "Sign in", "login_subtitle": "Please sign in with your credentials.",
        "login_user": "Username", "login_pw": "Password", "login_btn": "Sign in",
        "login_error": "Invalid username or password.",
        "dash_title": "Dashboard", "dash_subtitle": "Real-time overview of all Miniserver debug streams",
        "dash_active_streams": "Active Data Streams", "dash_completed": "Ended Sessions",
        "dash_stat_active": "Active Streams", "dash_stat_completed": "Ended Sessions",
        "dash_stat_servers": "Known Miniservers", "dash_stat_volume": "Total Volume",
        "dash_no_active": "No active streams — waiting for Miniserver connection on port {port}",
        "dash_no_completed": "No ended sessions yet.",
        "dash_refresh": "Page refreshes automatically every 10 seconds",
        "tbl_status": "Status", "tbl_ip": "IP Address", "tbl_start": "Start",
        "tbl_runtime": "Runtime", "tbl_last_pkt": "Last Packet", "tbl_volume": "Volume",
        "tbl_actions": "Actions", "tbl_end": "End", "tbl_duration": "Duration",
        "badge_active": "Active", "badge_ended": "Ended",
        "badge_active_count": "{n} active", "badge_total": "{n} total",
        "btn_folder": "Folder", "btn_zip": "ZIP", "btn_live": "&#9654; Live",
        "btn_delete": "Delete", "btn_open": "Open", "btn_zip_dl": "ZIP Download",
        "btn_download": "Download", "btn_save": "Save", "btn_cancel": "Cancel",
        "btn_create": "Create", "btn_edit": "Edit", "btn_restart": "Restart server",
        "confirm_delete_folder": "Delete folder {name} and all files?",
        "confirm_delete_file": "Delete file «{name}»?",
        "confirm_restart": "Really restart the server?",
        "confirm_delete_user": "Really delete user «{name}»?",
        "files_title": "Files", "files_subtitle": "Log archives — each session gets its own folder (IP + start time)",
        "files_col_ip": "Miniserver IP", "files_col_start": "Start Time",
        "files_col_logs": "Log Files", "files_col_size": "Total Size", "files_col_action": "Actions",
        "files_no_logs": "No logs yet. Waiting for incoming UDP packets on port {port}.",
        "files_no_logs_folder": "No log files in this folder.",
        "files_miniserver_logs": "Debug logs for this Miniserver",
        "files_log_files": "Log Files", "files_folders": "Miniserver Folders",
        "files_col_filename": "Filename", "files_col_created": "Created",
        "files_zip_download": "Download ZIP archive ({size})",
        "files_delete_folder": "Delete folder",
        "files_confirm_folder": "Delete entire folder «{name}»?",
        "files_count": "{n} file(s) · {size} total",
        "files_not_found": "Folder not found.",
        "files_no_dl": "No files to download.",
        "files_invalid_path": "Invalid path.",
        "files_deleted": "File deleted.", "files_not_found_file": "File not found.",
        "folder_deleted": "Folder deleted.", "folder_not_found": "Folder not found.",
        "users_title": "User Management", "users_subtitle": "Manage credentials and permissions",
        "users_col_name": "Username", "users_col_role": "Role", "users_you": "(You)",
        "users_admin": "Administrator", "users_user": "User",
        "users_new": "Create new user",
        "users_edit_title": "Edit user: {name}",
        "users_edit_pw": "New password", "users_edit_pw_hint": "(leave empty to keep current)",
        "users_edit_role": "Role", "users_edit_role_disabled": "Cannot change own role",
        "users_err_empty": "Username and password must not be empty.",
        "users_err_exists": "User already exists.",
        "users_err_role": "Invalid role.",
        "users_created": "User '{name}' has been created.",
        "users_updated": "User '{name}' updated.",
        "users_deleted": "User '{name}' deleted.",
        "users_err_self": "Cannot delete own account.",
        "users_err_not_found": "User not found.",
        "users_err_last_admin_del": "Cannot delete the last administrator.",
        "users_err_last_admin_role": "Cannot demote the last administrator.",
        "users_page": "User: {name}",
        "settings_title": "Settings", "settings_subtitle": "Server configuration — port changes require a restart",
        "settings_params": "Server Parameters",
        "settings_http_port": "HTTP Port", "settings_http_port_hint": "(Web interface, restart required)",
        "settings_udp_port": "UDP Port", "settings_udp_port_hint": "(Miniserver debug stream, restart required)",
        "settings_timeout": "Stream Timeout", "settings_timeout_hint": "(seconds without data → stream considered ended, effective immediately)",
        "settings_auto_delete": "Auto-delete after", "settings_auto_delete_hint": "(days after stream end, 0 = disabled, effective immediately)",
        "settings_max_storage": "Maximum storage", "settings_max_storage_hint": "(MB, 0 = disabled — oldest folders are deleted automatically, effective immediately)",
        "settings_current": "Current Values", "settings_timeout_lbl": "Timeout",
        "settings_auto_delete_lbl": "Auto-Delete", "settings_auto_delete_off": "Off",
        "settings_max_storage_lbl": "Max. Storage", "settings_max_storage_off": "Off",
        "settings_restart_title": "Server Restart",
        "settings_restart_desc": "Restarts the server process. Active streams will be briefly interrupted. Port changes only take effect after a restart.",
        "settings_err": "Invalid input. Ports: 1–65535, Timeout: 1–3600 s, Auto-delete: ≥ 0, Max. storage: ≥ 0.",
        "settings_saved": "Settings saved.",
        "settings_saved_restart": "Settings saved. Port changes will take effect after a server restart.",
        "settings_no_change": "No changes.",
        "history_title": "History", "history_subtitle": "Log of all actions: users, downloads, deletions, streams, restart",
        "history_log": "Activity Log", "history_entries": "{n} entries",
        "history_empty": "No entries yet.",
        "history_col_ts": "Timestamp", "history_col_user": "User",
        "history_col_action": "Action", "history_col_detail": "Detail",
        "restart_title": "Restarting server…",
        "restart_subtitle": "Please wait — the page will reload automatically once the server is ready.",
        "restart_connecting": "Reconnecting…",
        "live_subtitle": "Debug stream live view", "live_lines": "Last", "live_lines2": "lines",
        "live_autoscroll": "Auto-scroll", "live_connecting": "Connecting...",
        "live_ended": "— Stream ended —",
        "live_no_log": "No log found for this IP.",
        "logs_bc": "Logs", "before_n_s": "{n} s ago", "lang_label": "Language",
        "audit_login_ok": "Login", "audit_login_fail": "Login failed",
        "audit_stream_start": "Stream started", "audit_stream_end": "Stream ended",
        "audit_dl_file": "Download file", "audit_dl_zip": "Download ZIP",
        "audit_del_file": "File deleted", "audit_del_folder": "Folder deleted",
        "audit_auto_del": "Auto-deleted", "audit_storage_del": "Storage limit: deleted", "audit_user_add": "User created",
        "audit_user_edit": "User edited", "audit_user_del": "User deleted",
        "audit_settings": "Settings changed", "audit_restart": "Server restart",
        "audit_pw_changed": "Password changed", "audit_role": "Role",
        "audit_no_change": "no change",
        "footer": f"Loxone Debug Server {VERSION} &mdash; by Silas Hoffmann",
    },
}

def t(key: str, **kwargs) -> str:
    lang = "de"
    try:
        lang = session.get("lang", "de")
    except RuntimeError:
        pass
    text = TRANSLATIONS.get(lang, TRANSLATIONS["de"]).get(key) \
        or TRANSLATIONS["de"].get(key, key)
    if kwargs:
        try:
            text = text.format(**kwargs)
        except Exception:
            pass
    return text

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
            flash(t("users_err_role"), "error")
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
    matches = re.findall(rb'\x00\x01([\x20-\x7e]{4,})\x00', data)
    if matches:
        return "  ".join(m.decode("ascii", errors="replace") for m in matches)
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
_last_storage_check = 0.0

def _folder_size(path: Path) -> int:
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())

def _total_log_size() -> int:
    if not LOG_BASE_DIR.exists():
        return 0
    return sum(_folder_size(d) for d in LOG_BASE_DIR.iterdir() if d.is_dir())

def _auto_cleanup():
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

def _storage_cleanup():
    limit_mb = load_settings().get("max_storage_mb", 0)
    if limit_mb <= 0 or not LOG_BASE_DIR.exists():
        return
    limit_bytes = limit_mb * 1024 * 1024
    with _lock:
        active_folders = {s.get("folder") for s in active_streams.values()}
    while True:
        total = _total_log_size()
        if total <= limit_bytes:
            break
        candidates = sorted(
            [d for d in LOG_BASE_DIR.iterdir() if d.is_dir() and d.name not in active_folders],
            key=lambda d: d.stat().st_mtime
        )
        if not candidates:
            break
        oldest = candidates[0]
        try:
            shutil.rmtree(oldest)
            add_audit("Speicherlimit: gelöscht",
                      f"{oldest.name} ({fmt_bytes(total)} > {limit_mb} MB)",
                      user="System")
            print(f"[STORAGE] Ordner gelöscht: {oldest.name} (Limit: {limit_mb} MB)")
        except Exception as e:
            print(f"[STORAGE] Fehler beim Löschen {oldest.name}: {e}")
            break

def stream_monitor():
    global _last_cleanup, _last_storage_check
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
        if now - _last_storage_check >= 60:
            _last_storage_check = now
            _storage_cleanup()

# ══════════════════════════════════════════════════════════════════════════
# Design – Loxone Corporate Style
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
.nav-right a { color: #aaa; text-decoration: none; padding: 6px 10px;
               border-radius: var(--radius); }
.nav-right a:hover { background: #2a2a2a; color: #fff; }
.lang-switcher { display: flex; align-items: center; gap: 2px;
                 border: 1px solid #444; border-radius: var(--radius);
                 overflow: hidden; margin-right: 4px; }
.lang-switcher a {
  padding: 4px 8px; font-size: 11px; font-weight: 700;
  color: #888; text-decoration: none; letter-spacing: .04em;
  transition: background .15s, color .15s;
}
.lang-switcher a:hover { background: #2a2a2a; color: #fff; }
.lang-switcher a.lang-active { background: var(--green); color: #fff; }
.login-lang { position: absolute; top: 18px; right: 24px;
              display: flex; gap: 2px; border: 1px solid #444;
              border-radius: var(--radius); overflow: hidden; }
.login-lang a { padding: 4px 10px; font-size: 11px; font-weight: 700;
                color: #666; text-decoration: none; background: #fff; }
.login-lang a:hover { background: #f0f0f0; }
.login-lang a.lang-active { background: var(--green); color: #fff; }
.container { max-width: 1240px; margin: 0 auto; padding: 28px 24px; }
.page-header { margin-bottom: 24px; }
.page-header h1 { font-size: 20px; font-weight: 700; color: var(--text); }
.page-header p  { font-size: 13px; color: var(--muted); margin-top: 3px; }
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
.badge {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700;
  text-transform: uppercase; letter-spacing: .04em;
}
.badge-green  { background: var(--green-light); color: var(--green-dark); border: 1px solid #b7dfa0; }
.badge-gray   { background: #f0f0f0; color: #666; border: 1px solid #ddd; }
.badge-orange { background: #fff3e0; color: #e65100; border: 1px solid #ffcc80; }
.pulse { width: 7px; height: 7px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
.pulse-green { background: var(--green); animation: pulse 1.8s ease-in-out infinite; }
.pulse-gray  { background: #aaa; }
@keyframes pulse {
  0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(105,165,51,.4); }
  50%       { opacity: .8; box-shadow: 0 0 0 5px rgba(105,165,51,0); }
}
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
.btn-secondary { background: #fff; color: var(--text); border: 1px solid var(--border); }
.btn-secondary:hover { background: #f5f5f5; }
.btn-success  { background: #1565c0; color: #fff; }
.btn-success:hover  { background: #0d47a1; }
.btn-danger   { background: var(--danger); color: #fff; }
.btn-danger:hover   { background: #a50016; }
.btn-outline  { background: transparent; color: var(--green); border: 1px solid var(--green); }
.btn-outline:hover  { background: var(--green-light); }
form.inline { display: inline; }
.actions { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
.alert { padding: 12px 16px; border-radius: var(--radius); margin-bottom: 18px;
         font-size: 13px; border: 1px solid; display: flex; gap: 8px; align-items: flex-start; }
.alert-error   { background: var(--danger-bg);  color: #a00;  border-color: var(--danger-border); }
.alert-success { background: var(--success-bg); color: #2a6000; border-color: var(--success-border); }
.form-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 14px; align-items: end; }
.form-group { display: flex; flex-direction: column; gap: 5px; }
label { font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase;
        letter-spacing: .04em; }
input, select {
  padding: 8px 10px; border: 1px solid var(--border); border-radius: var(--radius);
  font-size: 13px; color: var(--text); background: #fff; transition: border-color .15s;
}
input:focus, select:focus { outline: none; border-color: var(--green);
                             box-shadow: 0 0 0 3px rgba(105,165,51,.15); }
.bc { font-size: 12px; color: var(--muted); margin-bottom: 16px;
      display: flex; align-items: center; gap: 6px; }
.bc a { color: var(--green); text-decoration: none; font-weight: 600; }
.bc a:hover { text-decoration: underline; }
.bc-sep { color: #ccc; }
.empty { text-align: center; padding: 56px 24px; color: #aaa; }
.empty svg { display: block; margin: 0 auto 12px; opacity: .3; }
.empty p { font-size: 14px; }
.login-wrap { min-height: 100vh; display: flex; align-items: center;
              justify-content: center; background: var(--nav-bg); position: relative; }
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
.refresh-note { font-size: 11px; color: #aaa; text-align: right; margin-bottom: 10px; }
.mono { font-family: "Consolas", "Courier New", monospace; }
.role-admin { color: var(--green-dark); font-weight: 700; }
.role-user  { color: var(--muted); }
th.sortable { cursor: pointer; user-select: none; white-space: nowrap; }
th.sortable:hover { color: var(--text); background: #f0f0f0; }
th.sortable::after { content: " ⇅"; font-size: .7em; color: #ccc; }
th.sort-asc::after  { content: " ▲"; color: var(--green); }
th.sort-desc::after { content: " ▼"; color: var(--green); }
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
td.size { color: var(--muted); font-variant-numeric: tabular-nums; }
.site-footer { text-align: center; padding: 28px 0 18px;
               font-size: 11px; color: #aaa; letter-spacing: .03em; }
"""

LOXONE_LOGO = """<svg width="90" height="20" viewBox="0 0 100 23" fill="none" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" clip-rule="evenodd" d="M91.4149 18.1044V12.2562H96.9392V8.69613H91.4149V5.93341L90.1667 4.01636H92.8082H100V0.456299H87.6289V0.471142V4.01636V18.1044V19.7067L88.9035 21.6644H100V18.1044H91.4149ZM83.4455 21.6508H83.8794V0.471191H80.4177V15.7242L72.6247 0.471191H71.489H68.8387H68.0273V21.6508H71.489V5.65867L79.6594 21.6508H80.4177H83.4455ZM63.5224 18.7948C64.4444 17.1971 64.544 15.5118 64.544 14.8618V7.21299C64.5051 3.63618 62.7241 1.86947 61.2373 1.01732C59.6341 0.0989541 57.9447 0 57.2933 0H56.0908C52.5047 0.0384399 50.7329 1.81467 49.8784 3.29784C48.958 4.89632 48.8584 6.58083 48.8584 7.23126L48.8587 14.8804C48.8973 18.4572 50.6783 20.2236 52.1651 21.0761C53.7683 21.9941 55.4573 22.093 56.1091 22.093H57.2967H57.3062C60.8942 22.0534 62.6672 20.2776 63.5224 18.7948ZM61.1099 14.8617C61.1099 16.2661 60.6111 18.6265 57.2773 18.6676H56.1095C54.6998 18.6676 52.3292 18.171 52.293 14.8617V7.23122C52.293 5.82531 52.7917 3.46069 56.1095 3.42529H57.2937C58.703 3.42529 61.0744 3.92197 61.1099 7.23122V14.8617ZM44.0577 21.6861H48.2971L42.3396 12.5366L40.2197 15.7922L44.0577 21.6861ZM42.3396 9.62064L48.2971 0.471191H44.0577L40.2197 6.36505L42.3396 9.62064ZM41.3893 11.0787L34.482 0.471191H30.2422L37.1495 11.0787L30.2422 21.6862H34.482L41.3893 11.0787ZM28.6586 18.7948C29.5806 17.1971 29.6798 15.5118 29.6798 14.8618V7.21299C29.6416 3.63618 27.8602 1.86947 26.3731 1.01732C24.7703 0.0989541 23.0809 0 22.429 0H21.227C17.6405 0.0384399 15.869 1.81467 15.0146 3.29784C14.0937 4.89632 13.9941 6.58083 13.9941 7.23126V14.8804C14.0331 18.4572 15.8141 20.2236 17.3016 21.0761C18.904 21.9941 20.5931 22.093 21.2453 22.093H22.4329H22.442C26.0308 22.0534 27.8034 20.2776 28.6586 18.7948ZM26.2443 14.8617C26.2443 16.2661 25.7462 18.6265 22.4121 18.6676H21.2443C19.8346 18.6676 17.464 18.171 17.4277 14.8617V7.23122C17.4277 5.82531 17.9261 3.46069 21.2443 3.42529H22.4281C23.8382 3.42529 26.2092 3.92197 26.2443 7.23122V14.8617ZM1.25362 21.6644H12.3717V18.1044H3.78565V0.471133H0V18.1044V19.7398L1.25362 21.6644Z" fill="currentColor"/></svg>"""

LOXONE_ICON = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" width="36" height="36">
<rect width="48" height="48" rx="10" fill="#69A533"/>
<text x="5" y="38" font-family="Arial Black, Arial" font-weight="900" font-size="34" fill="white">L</text>
<text x="26" y="20" font-family="Arial, sans-serif" font-weight="700" font-size="12" fill="rgba(255,255,255,0.85)">DS</text>
</svg>"""

FAVICON = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'%3E%3Crect width='48' height='48' rx='10' fill='%2369A533'/%3E%3Ctext x='5' y='38' font-family='Arial Black,Arial' font-weight='900' font-size='34' fill='white'%3EL%3C/text%3E%3Ctext x='26' y='20' font-family='Arial,sans-serif' font-weight='700' font-size='12' fill='rgba(255,255,255,.85)'%3EDS%3C/text%3E%3C/svg%3E"

_FOLDER_RE = re.compile(r'^(.+)_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})$')

def _parse_folder(name: str):
    m = _FOLDER_RE.match(name)
    if m:
        ip_part = m.group(1).replace("_", ".")
        dt_part = m.group(2).replace("_", " ").replace("-", ":", 2)
        return ip_part, dt_part
    return name.replace("_", ":"), "—"

def _lang_switcher(current: str, login_page: bool = False) -> str:
    de_cls = "lang-active" if current == "de" else ""
    en_cls = "lang-active" if current == "en" else ""
    cls    = "login-lang" if login_page else "lang-switcher"
    return (f'<div class="{cls}">'
            f'<a href="{url_for("set_lang", lang="de")}" class="{de_cls}">DE</a>'
            f'<a href="{url_for("set_lang", lang="en")}" class="{en_cls}">EN</a>'
            f'</div>')

def _nav(active_page=""):
    u        = session.get("user", "")
    lang     = session.get("lang", "de")
    is_admin = load_users().get(u, {}).get("role") == "admin"
    links    = [("dashboard", "/", t("nav_dashboard"))]
    if is_admin:
        links += [
            ("users",        "/users",        t("nav_users")),
            ("einstellungen","/einstellungen", t("nav_settings")),
            ("verlauf",      "/verlauf",       t("nav_history")),
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
    {_lang_switcher(lang)}
    <span>{u}</span>
    <a href="{url_for('logout')}">{t('nav_logout')}</a>
  </div>
</nav>"""

def page(body: str, title: str = "Loxone Debug Server", active: str = "") -> str:
    lang  = session.get("lang", "de") if session else "de"
    msgs  = get_flashed_messages(with_categories=True)
    alerts = "".join(f'<div class="alert alert-{cat}">{msg}</div>' for cat, msg in msgs)
    nav_html = _nav(active) if session.get("user") else ""
    return f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — Loxone Debug Server</title>
<link rel="icon" type="image/svg+xml" href="{FAVICON}">
<style>{CSS}</style>
</head>
<body>
{nav_html}
<div class="container">
{alerts}
{body}
</div>
<div class="site-footer">{t('footer')}</div>
</body>
</html>"""

# ══════════════════════════════════════════════════════════════════════════
# Sprache wechseln
# ══════════════════════════════════════════════════════════════════════════
@app.route("/lang/<lang>")
def set_lang(lang: str):
    if lang in ("de", "en"):
        session["lang"] = lang
    return redirect(request.referrer or url_for("dashboard"))

# ══════════════════════════════════════════════════════════════════════════
# Login / Logout
# ══════════════════════════════════════════════════════════════════════════
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("dashboard"))
    lang = session.get("lang", "de")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        users    = load_users()
        if username in users and check_pw(users[username]["password"], password):
            session["user"] = username
            add_audit(t("audit_login_ok"), f"von {request.remote_addr}")
            return redirect(url_for("dashboard"))
        add_audit(t("audit_login_fail"), f"{t('login_user')}: {username} von {request.remote_addr}")
        flash(t("login_error"), "error")

    alerts = "".join(f'<div class="alert alert-{c}">{m}</div>'
                     for c, m in get_flashed_messages(with_categories=True))
    body = f"""
<div class="login-wrap">
  {_lang_switcher(lang, login_page=True)}
  <div class="login-box">
    <div class="login-logo">
      <div class="logo-mark">{LOXONE_ICON}</div>
      <div>
        <div class="name">Loxone Debug Server</div>
        <div class="sub">Miniserver Log Management</div>
      </div>
    </div>
    <h2>{t('login_title')}</h2>
    <p>{t('login_subtitle')}</p>
    {alerts}
    <form method="post">
      <div class="form-group" style="margin-bottom:14px">
        <label>{t('login_user')}</label>
        <input name="username" autofocus autocomplete="username">
      </div>
      <div class="form-group" style="margin-bottom:22px">
        <label>{t('login_pw')}</label>
        <input type="password" name="password" autocomplete="current-password">
      </div>
      <button class="btn btn-primary" style="width:100%;justify-content:center;padding:10px">
        {t('login_btn')}
      </button>
    </form>
  </div>
</div>"""
    return f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{t('login_title')} — Loxone Debug Server</title>
<link rel="icon" type="image/svg+xml" href="{FAVICON}">
<style>{CSS}</style>
</head>
<body>{body}</body>
</html>"""


@app.route("/logout")
def logout():
    lang = session.get("lang", "de")
    session.clear()
    session["lang"] = lang
    return redirect(url_for("login"))

# ══════════════════════════════════════════════════════════════════════════
# Dashboard
# ══════════════════════════════════════════════════════════════════════════
@app.route("/")
@login_req
def dashboard():
    active, completed = stream_stats()
    now = time.time()
    cfg = load_settings()

    total_bytes = sum(s["bytes_written"] for s in active + completed)
    ip_set = {s["ip"] for s in active + completed}

    stats = f"""
<div class="stats-grid">
  <div class="stat-card accent">
    <div class="val">{len(active)}</div>
    <div class="lbl">{t('dash_stat_active')}</div>
  </div>
  <div class="stat-card">
    <div class="val">{len(completed)}</div>
    <div class="lbl">{t('dash_stat_completed')}</div>
  </div>
  <div class="stat-card">
    <div class="val">{len(ip_set)}</div>
    <div class="lbl">{t('dash_stat_servers')}</div>
  </div>
  <div class="stat-card">
    <div class="val">{fmt_bytes(int(total_bytes))}</div>
    <div class="lbl">{t('dash_stat_volume')}</div>
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

    if active:
        rows = ""
        for s in sorted(active, key=lambda x: x["last_seen"], reverse=True):
            age    = int(now - s["last_seen"])
            dur    = int(now - datetime.fromisoformat(s["start_time"]).timestamp())
            folder = s.get("folder", s["ip"].replace(":", "_"))
            rows += f"""
            <tr>
              <td><span class="badge badge-green"><span class="pulse pulse-green"></span>{t('badge_active')}</span></td>
              <td class="mono"><strong>{s['ip']}</strong></td>
              <td>{s['start_time'].replace('T',' ')[:19]}</td>
              <td>{dur} s</td>
              <td>{t('before_n_s', n=age)}</td>
              <td class="size">{fmt_bytes(s['bytes_written'])}</td>
              <td>
                <div class="actions">
                  <a class="btn btn-sm btn-outline" href="{url_for('files', folder=folder)}">{t('btn_folder')}</a>
                  <a class="btn btn-sm btn-primary" href="{url_for('download_folder', folder=folder)}">{t('btn_zip')}</a>
                  <a class="btn btn-sm btn-success" href="{url_for('live_stream', ip=s['ip'])}">{t('btn_live')}</a>
                  <form class="inline" method="post" action="{url_for('delete_folder')}"
                        onsubmit="return confirm({json.dumps(t('confirm_delete_folder', name=folder))})">
                    <input type="hidden" name="folder" value="{folder}">
                    <button class="btn btn-sm btn-danger">{t('btn_delete')}</button>
                  </form>
                </div>
              </td>
            </tr>"""
        active_card = f"""
        <div class="card">
          <div class="card-header">
            <h2>{t('dash_active_streams')}</h2>
            <span class="badge badge-green"><span class="pulse pulse-green"></span>{t('badge_active_count', n=len(active))}</span>
          </div>
          <div class="tbl-wrap">
            <table id="tbl-active">
              <thead><tr>
                <th>{t('tbl_status')}</th>
                <th class="sortable" onclick="sortTable(this)">{t('tbl_ip')}</th>
                <th class="sortable" onclick="sortTable(this)">{t('tbl_start')}</th>
                <th>{t('tbl_runtime')}</th><th>{t('tbl_last_pkt')}</th>
                <th>{t('tbl_volume')}</th><th>{t('tbl_actions')}</th>
              </tr></thead>
              <tbody>{rows}</tbody>
            </table>
          </div>
        </div>"""
    else:
        active_card = f"""
        <div class="card">
          <div class="card-header"><h2>{t('dash_active_streams')}</h2></div>
          <div class="empty">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>
            </svg>
            <p>{t('dash_no_active', port=cfg['udp_port'])}</p>
          </div>
        </div>"""

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
              <td><span class="badge badge-gray"><span class="pulse pulse-gray"></span>{t('badge_ended')}</span></td>
              <td class="mono">{s['ip']}</td>
              <td>{s['start_time'].replace('T',' ')[:19]}</td>
              <td>{s.get('end_time','—').replace('T',' ')[:19]}</td>
              <td>{dur}</td>
              <td class="size">{fmt_bytes(s['bytes_written'])}</td>
              <td>
                <div class="actions">
                  <a class="btn btn-sm btn-outline" href="{url_for('files', folder=folder)}">{t('btn_folder')}</a>
                  <a class="btn btn-sm btn-primary" href="{url_for('download_folder', folder=folder)}">{t('btn_zip')}</a>
                  <form class="inline" method="post" action="{url_for('delete_folder')}"
                        onsubmit="return confirm({json.dumps(t('confirm_delete_folder', name=folder))})">
                    <input type="hidden" name="folder" value="{folder}">
                    <button class="btn btn-sm btn-danger">{t('btn_delete')}</button>
                  </form>
                </div>
              </td>
            </tr>"""
        completed_card = f"""
        <div class="card">
          <div class="card-header">
            <h2>{t('dash_completed')}</h2>
            <span class="badge badge-gray">{t('badge_total', n=len(completed))}</span>
          </div>
          <div class="tbl-wrap">
            <table id="tbl-completed">
              <thead><tr>
                <th>{t('tbl_status')}</th>
                <th class="sortable" onclick="sortTable(this)">{t('tbl_ip')}</th>
                <th class="sortable" onclick="sortTable(this)">{t('tbl_start')}</th>
                <th class="sortable" onclick="sortTable(this)">{t('tbl_end')}</th>
                <th>{t('tbl_duration')}</th><th>{t('tbl_volume')}</th><th>{t('tbl_actions')}</th>
              </tr></thead>
              <tbody>{rows}</tbody>
            </table>
          </div>
        </div>"""
    else:
        completed_card = f"""
        <div class="card">
          <div class="card-header"><h2>{t('dash_completed')}</h2></div>
          <div class="empty"><p>{t('dash_no_completed')}</p></div>
        </div>"""

    header = f"""
    <div class="page-header">
      <h1>{t('dash_title')}</h1>
      <p>{t('dash_subtitle')}</p>
    </div>
    <div class="refresh-note">{t('dash_refresh')}</div>"""

    meta_refresh = '<meta http-equiv="refresh" content="10">'
    result = page(header + stats + active_card + completed_card + sort_js, t("dash_title"), "dashboard")
    return result.replace("</head>", f"{meta_refresh}</head>", 1)

# ══════════════════════════════════════════════════════════════════════════
# Datei-Browser
# ══════════════════════════════════════════════════════════════════════════
@app.route("/files/")
@app.route("/files")
@login_req
def files():
    folder = request.args.get("folder", "").strip()
    cfg    = load_settings()
    LOG_BASE_DIR.mkdir(exist_ok=True)

    if not folder:
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
                      <a class="btn btn-sm btn-outline" href="{url_for('files', folder=name)}">{t('btn_open')}</a>
                      <a class="btn btn-sm btn-primary" href="{url_for('download_folder', folder=name)}">{t('btn_zip_dl')}</a>
                      <form class="inline" method="post" action="{url_for('delete_folder')}"
                            onsubmit="return confirm({json.dumps(t('confirm_delete_folder', name=name))})">
                        <input type="hidden" name="folder" value="{name}">
                        <button class="btn btn-sm btn-danger">{t('btn_delete')}</button>
                      </form>
                    </div>
                  </td>
                </tr>"""
            table = f"""
            <div class="tbl-wrap">
            <table>
              <thead><tr>
                <th>{t('files_col_ip')}</th><th>{t('files_col_start')}</th>
                <th>{t('files_col_logs')}</th><th>{t('files_col_size')}</th>
                <th>{t('files_col_action')}</th>
              </tr></thead>
              <tbody>{rows}</tbody>
            </table>
            </div>"""
        else:
            table = f'<div class="empty"><p>{t("files_no_logs", port=cfg["udp_port"])}</p></div>'

        bc   = f'<div class="bc"><span>{t("logs_bc")}</span></div>'
        body = (f'<div class="page-header"><h1>{t("files_title")}</h1>'
                f'<p>{t("files_subtitle")}</p></div>'
                + bc
                + f'<div class="card"><div class="card-header"><h2>{t("files_folders")}</h2></div>{table}</div>')
        return page(body, t("files_title"), "files")

    try:
        ip_dir = safe_path(LOG_BASE_DIR, folder)
    except Exception:
        abort(400)
    if not ip_dir.is_dir():
        flash(t("files_not_found"), "error")
        return redirect(url_for("files"))

    logs = sorted(ip_dir.glob("*.log"), key=lambda f: f.stat().st_mtime, reverse=True)
    disp_ip, disp_dt = _parse_folder(folder)
    display_ip = (f"{disp_ip}"
                  + (f" &nbsp;<span style='font-size:13px;font-weight:400;color:var(--muted)'>{disp_dt}</span>"
                     if disp_dt != "—" else ""))

    if logs:
        rows = ""
        total_size = 0
        for f in logs:
            stat  = f.stat()
            mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            total_size += stat.st_size
            rows += f"""
            <tr>
              <td class="mono">{f.name}</td>
              <td class="size">{fmt_bytes(stat.st_size)}</td>
              <td>{mtime}</td>
              <td>
                <div class="actions">
                  <a class="btn btn-sm btn-success"
                     href="{url_for('download_file_single', folder=folder, filename=f.name)}">{t('btn_download')}</a>
                  <form class="inline" method="post" action="{url_for('delete_file')}"
                        onsubmit="return confirm({json.dumps(t('confirm_delete_file', name=f.name))})">
                    <input type="hidden" name="folder"   value="{folder}">
                    <input type="hidden" name="filename" value="{f.name}">
                    <button class="btn btn-sm btn-danger">{t('btn_delete')}</button>
                  </form>
                </div>
              </td>
            </tr>"""
        table = f"""
        <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th>{t('files_col_filename')}</th><th>{t('files_col_size')}</th>
            <th>{t('files_col_created')}</th><th>{t('tbl_actions')}</th>
          </tr></thead>
          <tbody>{rows}</tbody>
        </table>
        </div>
        <div style="padding:12px 16px;border-top:1px solid var(--border);background:#fafafa;font-size:12px;color:var(--muted);">
          {t('files_count', n=len(logs), size=fmt_bytes(total_size))}
        </div>"""

        zip_btn = (f'<a class="btn btn-primary" href="{url_for("download_folder", folder=folder)}">'
                   f'{t("files_zip_download", size=fmt_bytes(total_size))}</a>')
        del_btn = f"""
        <form class="inline" method="post" action="{url_for('delete_folder')}"
              onsubmit="return confirm({json.dumps(t('files_confirm_folder', name=folder))})">
          <input type="hidden" name="folder" value="{folder}">
          <button class="btn btn-danger">{t('files_delete_folder')}</button>
        </form>"""
        action_bar = f'<div class="actions" style="margin-bottom:16px">{zip_btn}{del_btn}</div>'
    else:
        table = f'<div class="empty"><p>{t("files_no_logs_folder")}</p></div>'
        action_bar = ""

    bc = f"""
    <div class="bc">
      <a href="{url_for('files')}">{t('logs_bc')}</a>
      <span class="bc-sep">›</span>
      <span class="mono">{disp_ip}</span>
      {f'<span class="bc-sep">›</span><span>{disp_dt}</span>' if disp_dt != "—" else ""}
    </div>"""
    header = f"""
    <div class="page-header">
      <h1 class="mono">{display_ip}</h1>
      <p>{t('files_miniserver_logs')}</p>
    </div>"""
    body = (header + bc + action_bar
            + f'<div class="card"><div class="card-header"><h2>{t("files_log_files")}</h2></div>{table}</div>')
    return page(body, disp_ip, "files")


@app.route("/download/<folder>/<filename>")
@login_req
def download_file_single(folder: str, filename: str):
    try:
        path = safe_path(LOG_BASE_DIR, folder + "/" + filename)
    except Exception:
        abort(400)
    if not path.is_file():
        abort(404)
    add_audit(t("audit_dl_file"), f"{folder}/{filename}")
    return send_file(path, as_attachment=True, download_name=filename)


@app.route("/download/<folder>")
@login_req
def download_folder(folder: str):
    try:
        ip_dir = safe_path(LOG_BASE_DIR, folder)
    except Exception:
        abort(400)
    if not ip_dir.is_dir():
        abort(404)

    logs = list(ip_dir.glob("*.log"))
    if not logs:
        flash(t("files_no_dl"), "error")
        return redirect(url_for("files", folder=folder))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(logs):
            zf.write(f, arcname=f.name)
    buf.seek(0)

    display_ip = folder.replace("_", "-")
    zip_name   = f"loxone-debug-{display_ip}.zip"
    add_audit(t("audit_dl_zip"), f"{folder} ({len(logs)} files)")
    return send_file(buf, as_attachment=True, download_name=zip_name, mimetype="application/zip")


@app.route("/delete_file", methods=["POST"])
@login_req
def delete_file():
    folder   = request.form.get("folder",   "").strip()
    filename = request.form.get("filename", "").strip()
    try:
        path = safe_path(LOG_BASE_DIR, folder + "/" + filename)
    except Exception:
        flash(t("files_invalid_path"), "error")
        return redirect(url_for("files"))
    if path.is_file():
        path.unlink()
        add_audit(t("audit_del_file"), f"{folder}/{filename}")
        flash(t("files_deleted"), "success")
    else:
        flash(t("files_not_found_file"), "error")
    return redirect(url_for("files", folder=folder))


@app.route("/delete_folder", methods=["POST"])
@login_req
def delete_folder():
    folder = request.form.get("folder", "").strip()
    try:
        path = safe_path(LOG_BASE_DIR, folder)
    except Exception:
        flash(t("files_invalid_path"), "error")
        return redirect(url_for("files"))
    if path.is_dir():
        shutil.rmtree(path)
        add_audit(t("audit_del_folder"), folder)
        flash(t("folder_deleted"), "success")
    else:
        flash(t("folder_not_found"), "error")
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
        flash(t("live_no_log"), "error")
        return redirect(url_for("dashboard"))

    status_badge = (
        '<span class="live-badge"><span class="pulse pulse-green"></span>LIVE</span>'
        if is_active else
        f'<span class="badge badge-gray">{t("badge_ended")}</span>'
    )
    ended_msg = json.dumps(t("live_ended"))

    body = f"""
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:10px">
      <div>
        <div class="page-header" style="margin-bottom:0">
          <h1 class="mono" style="display:inline">{ip}</h1>
          &nbsp;&nbsp;{status_badge}
        </div>
        <p style="font-size:13px;color:var(--muted);margin-top:4px">{t('live_subtitle')}</p>
      </div>
      <div class="actions">
        <a class="btn btn-secondary" href="{url_for('files', folder=folder)}">{t('btn_folder')}</a>
        <a class="btn btn-primary"   href="{url_for('download_folder', folder=folder)}">{t('btn_zip_dl')}</a>
        <a class="btn btn-secondary" href="{url_for('dashboard')}">&#8592; {t('nav_dashboard')}</a>
      </div>
    </div>
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
      <span style="font-size:12px;color:var(--muted)">{t('live_lines')} <strong id="line-count">—</strong> {t('live_lines2')}</span>
      <label style="font-size:12px;color:var(--muted);display:flex;align-items:center;gap:6px;cursor:pointer">
        <input type="checkbox" id="autoscroll" checked> {t('live_autoscroll')}
      </label>
    </div>
    <div class="terminal" id="terminal">
      <div style="color:#58a6ff;padding:8px 0">{t('live_connecting')}</div>
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
            div.textContent = {ended_msg};
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
        if after == 0:
            lines = [l.rstrip() for l in all_lines[-200:]]
            return jsonify({"lines": lines, "total": total, "active": is_active})
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
        role_lbl = t("users_admin") if info.get("role") == "admin" else t("users_user")
        you      = f' <span style="font-size:11px;color:var(--muted)">{t("users_you")}</span>' if is_self else ""
        del_btn  = "" if is_self else f"""
            <form class="inline" method="post" action="{url_for('user_delete')}"
                  onsubmit="return confirm({json.dumps(t('confirm_delete_user', name=uname))})">
              <input type="hidden" name="username" value="{uname}">
              <button class="btn btn-sm btn-danger">{t('btn_delete')}</button>
            </form>"""
        rows += f"""
        <tr>
          <td><strong>{uname}</strong>{you}</td>
          <td><span class="{role_cls}">{role_lbl}</span></td>
          <td>
            <div class="actions">
              <a class="btn btn-sm btn-secondary" href="{url_for('user_edit', username=uname)}">{t('btn_edit')}</a>
              {del_btn}
            </div>
          </td>
        </tr>"""

    user_table = f"""
    <div class="card">
      <div class="card-header">
        <h2>{t('users_col_name')}</h2>
        <span class="badge badge-gray">{t('badge_total', n=len(all_users))}</span>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>{t('users_col_name')}</th><th>{t('users_col_role')}</th><th>{t('tbl_actions')}</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>"""

    add_form = f"""
    <div class="card">
      <div class="card-header"><h2>{t('users_new')}</h2></div>
      <div class="card-body">
        <form method="post" action="{url_for('user_add')}">
          <div class="form-row">
            <div class="form-group">
              <label>{t('users_col_name')}</label>
              <input name="username" required autocomplete="off">
            </div>
            <div class="form-group">
              <label>{t('users_edit_pw')}</label>
              <input type="password" name="password" required autocomplete="new-password">
            </div>
            <div class="form-group">
              <label>{t('users_col_role')}</label>
              <select name="role">
                <option value="user">{t('users_user')}</option>
                <option value="admin">{t('users_admin')}</option>
              </select>
            </div>
            <div class="form-group" style="justify-content:flex-end">
              <button class="btn btn-primary">{t('btn_create')}</button>
            </div>
          </div>
        </form>
      </div>
    </div>"""

    header = f"""
    <div class="page-header">
      <h1>{t('users_title')}</h1>
      <p>{t('users_subtitle')}</p>
    </div>"""
    return page(header + user_table + add_form, t("users_title"), "users")


@app.route("/users/add", methods=["POST"])
@admin_req
def user_add():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role     = request.form.get("role", "user")
    users    = load_users()
    if not username or not password:
        flash(t("users_err_empty"), "error")
    elif username in users:
        flash(t("users_err_exists"), "error")
    elif role not in ("admin", "user"):
        flash(t("users_err_role"), "error")
    else:
        users[username] = {"password": hash_pw(password), "role": role}
        save_users(users)
        role_lbl = t("users_admin") if role == "admin" else t("users_user")
        add_audit(t("audit_user_add"), f"{username} ({t('users_col_role')}: {role_lbl})")
        flash(t("users_created", name=username), "success")
    return redirect(url_for("users"))


@app.route("/users/edit/<username>", methods=["GET", "POST"])
@admin_req
def user_edit(username: str):
    all_users = load_users()
    if username not in all_users:
        flash(t("users_err_not_found"), "error")
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
                    flash(t("users_err_last_admin_role"), "error")
                    return redirect(url_for("user_edit", username=username))
            all_users[username]["role"] = new_role
        save_users(all_users)
        changes = []
        if new_pw:                       changes.append(t("audit_pw_changed"))
        if new_role in ("admin", "user"): changes.append(f"{t('audit_role')}: {new_role}")
        add_audit(t("audit_user_edit"),
                  f"{username} – {', '.join(changes) if changes else t('audit_no_change')}")
        flash(t("users_updated", name=username), "success")
        return redirect(url_for("users"))

    info      = all_users[username]
    is_self   = username == session["user"]
    role_opts = "".join(
        f'<option value="{r}" {"selected" if info["role"]==r else ""}>'
        f'{t("users_admin") if r=="admin" else t("users_user")}</option>'
        for r in ("user", "admin")
    )
    dis_role = f'disabled title="{t("users_edit_role_disabled")}"' if is_self else ""

    bc = f"""
    <div class="bc">
      <a href="{url_for('users')}">{t('nav_users')}</a>
      <span class="bc-sep">›</span>
      <span>{username}</span>
    </div>"""
    form = f"""
    <div class="card" style="max-width:480px">
      <div class="card-header"><h2>{t('users_edit_title', name=username)}</h2></div>
      <div class="card-body">
        <form method="post">
          <div class="form-group" style="margin-bottom:16px">
            <label>{t('users_edit_pw')} <span style="font-weight:400;text-transform:none;color:#aaa">{t('users_edit_pw_hint')}</span></label>
            <input type="password" name="password" autocomplete="new-password">
          </div>
          <div class="form-group" style="margin-bottom:24px">
            <label>{t('users_edit_role')}</label>
            <select name="role" {dis_role}>{role_opts}</select>
          </div>
          <div class="actions">
            <button class="btn btn-primary">{t('btn_save')}</button>
            <a class="btn btn-secondary" href="{url_for('users')}">{t('btn_cancel')}</a>
          </div>
        </form>
      </div>
    </div>"""
    header = f'<div class="page-header"><h1>{t("users_page", name=username)}</h1></div>'
    return page(header + bc + form, t("users_page", name=username), "users")


@app.route("/users/delete", methods=["POST"])
@admin_req
def user_delete():
    username  = request.form.get("username", "").strip()
    all_users = load_users()
    if username == session["user"]:
        flash(t("users_err_self"), "error")
    elif username not in all_users:
        flash(t("users_err_not_found"), "error")
    else:
        admins = [u for u, v in all_users.items() if v.get("role") == "admin"]
        if all_users[username].get("role") == "admin" and len(admins) <= 1:
            flash(t("users_err_last_admin_del"), "error")
        else:
            del all_users[username]
            save_users(all_users)
            add_audit(t("audit_user_del"), username)
            flash(t("users_deleted", name=username), "success")
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
            max_storage = int(request.form.get("max_storage_mb",   cfg.get("max_storage_mb", 0)))
            if not (1 <= http_port <= 65535 and 1 <= udp_port <= 65535):
                raise ValueError
            if not (1 <= timeout <= 3600) or auto_delete < 0 or max_storage < 0:
                raise ValueError
        except (ValueError, TypeError):
            flash(t("settings_err"), "error")
            return redirect(url_for("einstellungen"))

        cfg = {"http_port": http_port, "udp_port": udp_port,
               "stream_timeout": timeout, "auto_delete_days": auto_delete,
               "max_storage_mb": max_storage}
        save_settings(cfg)

        changes = []
        if old_cfg["http_port"]                    != http_port:   changes.append(f"HTTP Port {old_cfg['http_port']} → {http_port}");                    port_changed = True
        if old_cfg["udp_port"]                     != udp_port:    changes.append(f"UDP Port {old_cfg['udp_port']} → {udp_port}");                       port_changed = True
        if old_cfg["stream_timeout"]               != timeout:     changes.append(f"Timeout {old_cfg['stream_timeout']} → {timeout} s")
        if old_cfg["auto_delete_days"]             != auto_delete: changes.append(f"Auto-Delete {old_cfg['auto_delete_days']} → {auto_delete} d")
        if old_cfg.get("max_storage_mb", 0)        != max_storage: changes.append(f"Max. Speicher {old_cfg.get('max_storage_mb', 0)} → {max_storage} MB")

        if changes:
            add_audit(t("audit_settings"), "; ".join(changes))
            flash(t("settings_saved_restart") if port_changed else t("settings_saved"), "success")
        else:
            flash(t("settings_no_change"), "success")
        return redirect(url_for("einstellungen"))

    auto_del_val  = cfg.get("auto_delete_days", 0)
    max_store_val = cfg.get("max_storage_mb", 0)
    body = f"""
    <div class="page-header">
      <h1>{t('settings_title')}</h1>
      <p>{t('settings_subtitle')}</p>
    </div>
    <div class="card" style="max-width:560px">
      <div class="card-header"><h2>{t('settings_params')}</h2></div>
      <div class="card-body">
        <form method="post">
          <div class="form-group" style="margin-bottom:18px">
            <label>{t('settings_http_port')} <span style="font-weight:400;text-transform:none;color:#aaa">{t('settings_http_port_hint')}</span></label>
            <input type="number" name="http_port" value="{cfg['http_port']}" min="1" max="65535" required>
          </div>
          <div class="form-group" style="margin-bottom:18px">
            <label>{t('settings_udp_port')} <span style="font-weight:400;text-transform:none;color:#aaa">{t('settings_udp_port_hint')}</span></label>
            <input type="number" name="udp_port" value="{cfg['udp_port']}" min="1" max="65535" required>
          </div>
          <div class="form-group" style="margin-bottom:18px">
            <label>{t('settings_timeout')} <span style="font-weight:400;text-transform:none;color:#aaa">{t('settings_timeout_hint')}</span></label>
            <input type="number" name="stream_timeout" value="{cfg['stream_timeout']}" min="1" max="3600" required>
          </div>
          <div class="form-group" style="margin-bottom:18px">
            <label>{t('settings_auto_delete')} <span style="font-weight:400;text-transform:none;color:#aaa">{t('settings_auto_delete_hint')}</span></label>
            <input type="number" name="auto_delete_days" value="{auto_del_val}" min="0" max="3650" required>
          </div>
          <div class="form-group" style="margin-bottom:24px">
            <label>{t('settings_max_storage')} <span style="font-weight:400;text-transform:none;color:#aaa">{t('settings_max_storage_hint')}</span></label>
            <input type="number" name="max_storage_mb" value="{max_store_val}" min="0" max="1000000" required>
          </div>
          <div class="actions">
            <button class="btn btn-primary">{t('btn_save')}</button>
          </div>
        </form>
      </div>
    </div>
    <div class="card" style="max-width:560px;margin-top:16px">
      <div class="card-header"><h2>{t('settings_current')}</h2></div>
      <div class="card-body" style="display:grid;grid-template-columns:repeat(5,1fr);gap:14px">
        <div class="stat-card accent"><div class="val">{cfg['http_port']}</div><div class="lbl">HTTP Port</div></div>
        <div class="stat-card accent"><div class="val">{cfg['udp_port']}</div><div class="lbl">UDP Port</div></div>
        <div class="stat-card accent"><div class="val">{cfg['stream_timeout']} s</div><div class="lbl">{t('settings_timeout_lbl')}</div></div>
        <div class="stat-card {'accent' if auto_del_val > 0 else ''}">
          <div class="val" style="font-size:20px">{f'{auto_del_val} d' if auto_del_val > 0 else t('settings_auto_delete_off')}</div>
          <div class="lbl">{t('settings_auto_delete_lbl')}</div>
        </div>
        <div class="stat-card {'accent' if max_store_val > 0 else ''}">
          <div class="val" style="font-size:20px">{f'{max_store_val} MB' if max_store_val > 0 else t('settings_max_storage_off')}</div>
          <div class="lbl">{t('settings_max_storage_lbl')}</div>
        </div>
      </div>
    </div>
    <div class="card" style="max-width:560px;margin-top:16px">
      <div class="card-header"><h2>{t('settings_restart_title')}</h2></div>
      <div class="card-body">
        <p style="font-size:13px;color:var(--muted);margin-bottom:16px">{t('settings_restart_desc')}</p>
        <form method="post" action="{url_for('restart_server')}"
              onsubmit="return confirm({json.dumps(t('confirm_restart'))})">
          <button class="btn btn-danger">{t('btn_restart')}</button>
        </form>
      </div>
    </div>"""
    return page(body, t("settings_title"), "einstellungen")

# ══════════════════════════════════════════════════════════════════════════
# Server-Neustart
# ══════════════════════════════════════════════════════════════════════════
@app.route("/restart", methods=["POST"])
@admin_req
def restart_server():
    add_audit(t("audit_restart"), f"{session.get('user','?')} ({request.remote_addr})")

    def do_restart():
        time.sleep(1.5)
        try:
            subprocess.Popen([sys.executable] + sys.argv, close_fds=True, creationflags=0)
        except TypeError:
            subprocess.Popen([sys.executable] + sys.argv, close_fds=True)
        os._exit(0)

    threading.Thread(target=do_restart, daemon=False).start()

    body = f"""
    <div class="page-header" style="text-align:center;padding-top:60px">
      <h1>{t('restart_title')}</h1>
      <p style="margin-top:8px">{t('restart_subtitle')}</p>
    </div>
    <div class="card" style="max-width:400px;margin:24px auto">
      <div class="card-body" style="text-align:center;padding:40px">
        <div style="font-size:40px;margin-bottom:16px;animation:spin 1s linear infinite;display:inline-block">&#8635;</div>
        <p style="color:var(--muted);font-size:13px">{t('restart_connecting')}</p>
      </div>
    </div>
    <style>@keyframes spin{{from{{transform:rotate(0deg)}}to{{transform:rotate(360deg)}}}}</style>
    <script>
    setTimeout(function(){{
      var i = setInterval(function(){{
        fetch('/login').then(function(r){{ if(r.ok){{ clearInterval(i); location.href='/'; }} }}).catch(function(){{}});
      }}, 1000);
    }}, 2500);
    </script>"""
    return page(body, t("restart_title"), "einstellungen")

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
            if any(w in action_lower for w in ["gelöscht", "deleted", "auto-del"]):
                action_cls = 'style="color:var(--danger);font-weight:600"'
            elif any(w in action_lower for w in ["download"]):
                action_cls = 'style="color:var(--green-dark);font-weight:600"'
            elif any(w in action_lower for w in ["fehlgeschlagen", "failed", "neustart", "restart"]):
                action_cls = 'style="color:#e65100;font-weight:600"'
            elif any(w in action_lower for w in ["gestartet", "started"]):
                action_cls = 'style="color:var(--green);font-weight:600"'
            elif any(w in action_lower for w in ["beendet", "ended"]):
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
            <th>{t('history_col_ts')}</th><th>{t('history_col_user')}</th>
            <th>{t('history_col_action')}</th><th>{t('history_col_detail')}</th>
          </tr></thead>
          <tbody>{rows}</tbody>
        </table>
        </div>"""
    else:
        table = f'<div class="empty"><p>{t("history_empty")}</p></div>'

    header = f"""
    <div class="page-header">
      <h1>{t('history_title')}</h1>
      <p>{t('history_subtitle')}</p>
    </div>"""
    body = (header
            + f'<div class="card"><div class="card-header">'
            + f'<h2>{t("history_log")}</h2>'
            + f'<span class="badge badge-gray">{t("history_entries", n=len(log))}</span>'
            + f'</div>{table}</div>')
    return page(body, t("history_title"), "verlauf")

# ══════════════════════════════════════════════════════════════════════════
# Start
# ══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    LOG_BASE_DIR.mkdir(exist_ok=True)
    load_users()

    for target in (udp_listener, stream_monitor):
        threading.Thread(target=target, daemon=True).start()

    cfg = load_settings()
    print(f"[WEB] Webinterface auf http://0.0.0.0:{cfg['http_port']}")
    print(f"[WEB] Login: admin / admin  -- nach erstem Login bitte aendern!")
    app.run(host="0.0.0.0", port=cfg["http_port"], debug=False, use_reloader=False)
