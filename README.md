# Loxone Debug Server

A local server for receiving, storing, and displaying debug streams from the Loxone Miniserver.  
Data is received via UDP and managed through a web interface in the browser.

![Loxone Debug Server](https://img.shields.io/badge/Version-1.06-69A533?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0+-000000?style=flat-square&logo=flask)

---

## Requirements

- Python 3.10 or newer
- Windows (tested) or Linux

---

## Installation & Start

### Windows

```bat
start.bat
```

The script automatically installs all dependencies and starts the server.

### Linux / macOS

```bash
pip install flask
python udp_logger.py
```

### First Login

| Field    | Value   |
|----------|---------|
| Username | `admin` |
| Password | `admin` |

> **Please change the password after the first login under *Users → Edit*.**

---

## Features

### Language Selection

The user interface is fully available in **German** and **English**.

- Language switcher **DE / EN** directly on the login page (top right)
- Language switcher **DE / EN** in the navigation (top right, next to the username)
- The selected language is retained even after logging out and back in
- Default: German

---

### UDP Reception

The server listens on **UDP port 7777** for incoming debug packets from the Loxone Miniserver.

- Loxone binary protocol is decoded by its fixed header (`1f fa` Miniserver / `18 f9` Linux subsystem)
- The **sender IP** is read from the packet header (offset 16) — correct behind NAT/VPN
- Gateway and client Miniservers get **separate streams**, even when they arrive from the same public IP
- The **serial number (MAC)** of each sender is determined from the packet header (last MAC bytes) and confirmed via log messages (e.g. `192-168-178-210.504F94D019C2.dyndns…`)
- Every session is written twice: a readable `.log` and a **`.LxMon` file in the exact Loxone Config format** (open it in Loxone Config → Monitor)
- Each session gets its own folder in the format `IP_DATE_TIME`  
  (e.g. `192.168.1.100_2026-04-25_14-30-00`)
- Streams that have not sent data for more than X seconds are considered ended (configurable)

---

### Dashboard

Real-time overview of all active and ended debug streams.

| Column | Description |
|--------|-------------|
| Status | Active (green dot) or Ended |
| IP Address | Source IP of the Miniserver |
| Start | Time of the first packet |
| Runtime / Duration | How long the stream has been / was running (auto-formatted: s / min s / h min s) |
| Last Packet | How many seconds ago data was last received |
| Volume | Amount of data received |
| Serial Number | Serial number (= MAC) of the sending Miniserver. Shown as `504F94··19C2` until the full number has been seen in a log message |
| Assigned To | User responsible for this session — select from dropdown, saved instantly |

**Actions per stream:**

- **Folder** — opens the file browser for this stream
- **ZIP** — downloads all log files as a ZIP archive
- **Live** — opens the live stream terminal *(active streams only)*
- **Delete** — deletes the entire folder including all log files and removes it from the dashboard immediately

The page refreshes automatically every 10 seconds.

---

### Live Stream Terminal

Displays the current debug output of an active stream in real time.

- Updates every 2 seconds via polling
- Shows the last 200 lines on first load
- **Auto-scroll** (toggleable)
- Timestamp per line
- Remains visible after stream ends

---

### File Browser

Overview of all stored log sessions, sorted by date (newest first).

- Displays Miniserver IP and start time per folder
- Download individual log files
- ZIP download of all files in a folder
- Delete individual files or entire folders

---

### User Management *(admins only)*

Manage all user accounts for the web interface.

- Create new users with username, password, and role
- Change password and role of existing users
- Delete users *(own account cannot be deleted)*
- Two roles: **Administrator** (full access) and **User** (no access to Users, Settings, and History)
- Passwords are stored with SHA-256 + random salt

---

### Settings *(admins only)*

Configure the server via the web interface.

| Setting | Description | Restart required |
|---|---|:---:|
| HTTP Port | Port of the web interface (default: 8080) | ✅ |
| UDP Port | Port for incoming Miniserver packets (default: 7777) | ✅ |
| Stream Timeout | Seconds without data until a stream is considered ended (default: 30) | ❌ |
| Auto-Delete | Automatically delete folders after X days (0 = disabled) | ❌ |
| Maximum Storage | Limit total log folder size in GB — oldest folders are deleted automatically when exceeded (0 = disabled) | ❌ |
| Max. Log File Size | Maximum size per log file in MB — a new file is created automatically when reached (default: 10 MB) | ❌ |

All changes are recorded in the history.

#### Server Restart

The server can be restarted directly from the settings page.  
A waiting page automatically detects when the server is ready again and redirects.

---

### History / Audit Log *(admins only)*

Complete log of all actions on the server.

| Action | Color | Triggered by |
|--------|-------|--------------|
| Login (success / failure) | — / Orange | User |
| Stream started | Green | System |
| Stream ended | Gray | System |
| Download (file / ZIP) | Green | User |
| File / folder deleted | Red | User |
| Auto-deleted (auto-delete) | Red | System |
| Storage limit exceeded: deleted | Red | System |
| User created / edited / deleted | — | Admin |
| Settings changed | — | Admin |
| Server restart | Orange | Admin |

The history stores the last 2,000 entries in `audit.json`.

---

## File Structure

```
UDP/
├── udp_logger.py       # Main script (server + web interface)
├── start.bat           # Windows launcher
├── requirements.txt    # Python dependencies
├── users.json          # User data (auto-created)
├── settings.json       # Configuration (auto-created)
├── audit.json          # History / audit log (auto-created)
├── assignments.json    # Session user assignments (auto-created)
└── logs/
    └── 192.168.1.100_2026-04-25_14-30-00/
        ├── 2026-04-25_14-30-00.log     # readable text log
        ├── 2026-04-25_14-30-00.LxMon   # Loxone Config monitor file (byte-identical format)
        └── stream.json                 # sender IP, external IP, serial number
```

> `users.json`, `settings.json`, `audit.json`, `assignments.json` and the `logs/` folder are listed in `.gitignore` and are not uploaded to the repository.

---

## Loxone Miniserver Configuration

In Loxone Config under **Miniserver → Settings → Logging & Monitoring**:

- **Enable debug output via UDP**
- Target IP: IP address of the machine running the debug server
- Target port: `7777`

---

## Technical Details

- **Backend:** Python 3, Flask
- **Frontend:** Vanilla HTML/CSS/JS, Loxone corporate design (`#69A533`)
- **Protocol:** Loxone UDP debug binary format — fixed 28-byte header (sender IP at offset 16, MAC tail at 24–25), text from offset 29; `.LxMon` = MFC CArchive of `CCommonLogDataLine` objects incl. Loxone Config's row colours (verified byte-identical against ~827,000 lines from real Loxone Config files)
- **Authentication:** Session-based, passwords hashed with SHA-256 + random salt
- **Threading:** UDP listener and stream monitor run as daemon threads
- **Path safety:** All file accesses are checked against path traversal attacks

---

## Changelog

### V1.08
- **Software update without Git:** If `git` is not installed (or the program folder is not a Git clone), *Check for update* / *Install update* now download the current version directly from GitHub over HTTPS (standard library only). Runtime data (`logs/`, `users.json`, `settings.json`, `audit.json`, `assignments.json`) is never overwritten; the installed commit is stored in `.installed_commit`
- Git is also found in its default Windows install folders when it is missing from `PATH`

### V1.07
- **LxMon export:** Each stream is additionally written as a `.LxMon` file in exactly the format Loxone Config uses (header, CArchive records, timestamps, row colours, original packets) — can be opened directly in Loxone Config
- **Correct sender IP:** IP is read from the fixed header position instead of scanning for RFC1918-like bytes (which produced bogus IPs such as `10.241.58.1`)
- **Gateway / client separation:** Streams are keyed by external IP + sender IP, so every Miniserver gets its own folder
- **Correct serial number:** The serial (MAC) of the sending Miniserver is derived from the packet header and confirmed in the log text, instead of listing the first serial numbers found in any message
- Multiple Loxone packets in one UDP datagram are split correctly; texts are decoded as UTF-8 with cp1252 fallback (umlauts)

### V1.06
- **Runtime formatting:** Durations are now human-readable — under 60 s shown as `45 s`, under 1 h as `2 min 30 s`, above 1 h as `1h 30min 45s`
- **Serial number detection:** The dashboard scans each log file for Loxone device serial numbers (`504F94...`) and shows up to 3 per session; air devices (`504F94FFFE...`) are automatically excluded
- **User assignment:** Each session in the dashboard can be assigned to a responsible user via a dropdown — the selection is saved instantly without page reload (`assignments.json`)

### V1.05
- New setting: Auto-Update — checks GitHub periodically for new versions and automatically runs `git pull` + restarts when an update is found
- New setting: Check interval in minutes (default: 60)
- Manual "Check now" button in Settings with live status display (current commit, remote commit, last check time)
- "Update & Restart" button appears automatically when an update is available
- All automatic and manual updates are recorded in the history

### V1.04
- Internal Miniserver IP extracted from UDP packet header — works correctly behind NAT (external router IP no longer shown)
- Each log line is tagged with the IP of the Miniserver that sent it — multiple Miniservers per UDP stream supported
- Log file rotation: new files now use the current timestamp as filename instead of `_2_2_2...` chains
- Volume display: dashboard and folder view now show consistent values (actual bytes written to disk)
- Delete button on dashboard: now deletes the folder directly and returns to dashboard (previously opened file browser)
- Deleted streams are removed from the dashboard immediately without waiting for the next reload

### V1.03
- New login and browser tab icon (L/DS monogram)
- New setting: Maximum storage in GB — oldest folders are deleted automatically when the limit is exceeded
- Storage deletions are recorded in the history
- Settings page: layout revised (full width, fields stacked vertically)

### V1.02
- User interface fully translated to German and English
- Language switcher DE / EN on the login page and in the navigation
- Language selection is retained after logout

### V1.01
- Initial release
- UDP reception with automatic decoding of the Loxone binary protocol
- Dashboard with real-time overview of all active and ended streams
- Live stream terminal with auto-scroll
- File browser with ZIP download
- User management with two roles (Administrator / User)
- Settings page (HTTP port, UDP port, stream timeout, auto-delete)
- Server restart via web interface
- History / audit log for all actions

---

## Developed by

**Silas Hoffmann** — with support from [Claude Code](https://claude.ai/code)
