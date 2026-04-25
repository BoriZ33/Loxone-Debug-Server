# Loxone Debug Server

Ein lokaler Server zum Empfangen, Speichern und Anzeigen von Debug-Streams des Loxone Miniserver.  
Daten werden per UDP empfangen und über ein Web-Interface im Browser verwaltet.

![Loxone Debug Server](https://img.shields.io/badge/Version-1.02-69A533?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0+-000000?style=flat-square&logo=flask)

---

## Voraussetzungen

- Python 3.10 oder neuer
- Windows (getestet) oder Linux

---

## Installation & Start

### Windows

```bat
start.bat
```

Das Skript installiert automatisch alle Abhängigkeiten und startet den Server.

### Linux / macOS

```bash
pip install flask
python udp_logger.py
```

### Erster Login

| Feld       | Wert    |
|------------|---------|
| Benutzer   | `admin` |
| Passwort   | `admin` |

> **Bitte das Passwort nach dem ersten Login unter *Benutzer → Bearbeiten* ändern.**

---

## Funktionen

### Sprachauswahl

Die Benutzeroberfläche ist vollständig auf **Deutsch** und **Englisch** verfügbar.

- Sprachumschalter **DE / EN** direkt auf der Login-Seite (oben rechts)
- Sprachumschalter **DE / EN** in der Navigation (oben rechts neben dem Benutzernamen)
- Die gewählte Sprache bleibt auch nach dem Aus- und Einloggen erhalten
- Standard: Deutsch

---

### UDP-Empfang

Der Server lauscht auf **UDP Port 7777** auf eingehende Debug-Pakete des Loxone Miniserver.

- Loxone-Binärprotokoll wird automatisch dekodiert (`\x00\x01...\x00` Muster)
- Jede Session erhält einen eigenen Ordner im Format `IP_DATUM_UHRZEIT`  
  (z. B. `192.168.1.100_2026-04-25_14-30-00`)
- Mehrere Miniserver mit gleicher IP werden sauber getrennt
- Streams die seit mehr als X Sekunden keine Daten senden gelten als beendet (konfigurierbar)

---

### Dashboard

Echtzeit-Übersicht aller aktiven und beendeten Debug-Streams.

| Spalte | Beschreibung |
|--------|-------------|
| Status | Aktiv (grüner Punkt) oder Beendet |
| IP-Adresse | Quell-IP des Miniserver |
| Start | Zeitpunkt des ersten Pakets |
| Laufzeit / Dauer | Wie lange der Stream läuft / gelaufen ist |
| Letztes Paket | Vor wie vielen Sekunden zuletzt Daten empfangen wurden |
| Volumen | Empfangene Datenmenge |

**Aktionen pro Stream:**

- **Ordner** — öffnet den Datei-Browser für diesen Stream
- **ZIP** — lädt alle Log-Dateien als ZIP-Archiv herunter
- **Live** — öffnet das Live-Stream Terminal *(nur bei aktiven Streams)*
- **Löschen** — löscht den gesamten Ordner inkl. aller Log-Dateien

Die Seite aktualisiert sich automatisch alle 10 Sekunden.

---

### Live-Stream Terminal

Zeigt den aktuellen Debug-Output eines aktiven Streams in Echtzeit an.

- Aktualisierung alle 2 Sekunden per Polling
- Zeigt die letzten 200 Zeilen beim ersten Aufruf
- **Auto-Scroll** (ein-/ausschaltbar)
- Zeitstempel pro Zeile
- Nach Stream-Ende bleibt der letzte Stand sichtbar

---

### Datei-Browser

Übersicht aller gespeicherten Log-Sessions, sortiert nach Datum (neueste zuerst).

- Anzeige von Miniserver-IP und Startzeit pro Ordner
- Einzelne Log-Dateien herunterladen
- ZIP-Download aller Dateien eines Ordners
- Einzelne Dateien oder gesamte Ordner löschen

---

### Benutzerverwaltung *(nur Admins)*

Verwaltung aller Benutzerkonten des Web-Interface.

- Neue Benutzer anlegen mit Benutzername, Passwort und Rolle
- Passwort und Rolle bestehender Benutzer ändern
- Benutzer löschen *(eigener Account nicht löschbar)*
- Zwei Rollen: **Administrator** (voller Zugriff) und **Benutzer** (kein Zugriff auf Benutzer, Einstellungen und Verlauf)
- Passwörter werden mit SHA-256 + Salt gespeichert

---

### Einstellungen *(nur Admins)*

Konfiguration des Servers über das Web-Interface.

| Einstellung | Beschreibung | Neustart erforderlich |
|---|---|:---:|
| HTTP Port | Port des Web-Interface (Standard: 8080) | ✅ |
| UDP Port | Port für eingehende Miniserver-Pakete (Standard: 7777) | ✅ |
| Stream Timeout | Sekunden ohne Daten bis ein Stream als beendet gilt (Standard: 30) | ❌ |
| Auto-Löschen | Ordner automatisch nach X Tagen löschen (0 = deaktiviert) | ❌ |

Alle Änderungen werden im Verlauf protokolliert.

#### Server-Neustart

Der Server kann direkt über die Einstellungsseite neu gestartet werden.  
Eine Warte-Seite erkennt automatisch wenn der Server wieder bereit ist und leitet weiter.

---

### Verlauf / Audit-Log *(nur Admins)*

Vollständiges Protokoll aller Aktionen auf dem Server.

| Aktion | Farbe | Ausgelöst durch |
|--------|-------|-----------------|
| Login (Erfolg / Fehlschlag) | — / Orange | Benutzer |
| Stream gestartet | Grün | System |
| Stream beendet | Grau | System |
| Download (Datei / ZIP) | Grün | Benutzer |
| Datei / Ordner gelöscht | Rot | Benutzer |
| Automatisch gelöscht | Rot | System |
| Benutzer angelegt / bearbeitet / gelöscht | — | Admin |
| Einstellungen geändert | — | Admin |
| Server-Neustart | Orange | Admin |

Der Verlauf speichert die letzten 2.000 Einträge in `audit.json`.

---

## Dateistruktur

```
UDP/
├── udp_logger.py       # Hauptskript (Server + Web-Interface)
├── start.bat           # Windows-Starter
├── requirements.txt    # Python-Abhängigkeiten
├── users.json          # Benutzerdaten (automatisch erstellt)
├── settings.json       # Konfiguration (automatisch erstellt)
├── audit.json          # Verlauf / Audit-Log (automatisch erstellt)
└── logs/
    └── 192.168.1.100_2026-04-25_14-30-00/
        └── 2026-04-25_14-30-00.log
```

> `users.json`, `settings.json`, `audit.json` und der `logs/`-Ordner sind in `.gitignore` eingetragen und werden nicht ins Repository hochgeladen.

---

## Loxone Miniserver konfigurieren

Im Loxone Config unter **Miniserver → Einstellungen → Logging & Monitoring**:

- **Debug-Ausgabe per UDP aktivieren**
- Ziel-IP: IP-Adresse des Rechners auf dem der Debug Server läuft
- Ziel-Port: `7777`

---

## Technische Details

- **Backend:** Python 3, Flask
- **Frontend:** Vanilla HTML/CSS/JS, Loxone Corporate Design (`#69A533`)
- **Protokoll:** Loxone UDP-Debug-Binärformat — Text wird zwischen `\x00\x01` und `\x00` extrahiert
- **Authentifizierung:** Session-basiert, Passwörter mit SHA-256 + zufälligem Salt gehasht
- **Threading:** UDP-Listener und Stream-Monitor laufen als Daemon-Threads
- **Pfadsicherheit:** Alle Dateizugriffe werden gegen Path-Traversal-Angriffe geprüft

---

## Changelog

### V1.02
- Benutzeroberfläche vollständig auf Deutsch und Englisch übersetzt
- Sprachumschalter DE / EN auf der Login-Seite und in der Navigation
- Sprachauswahl bleibt nach dem Logout erhalten

### V1.01
- Erstveröffentlichung
- UDP-Empfang mit automatischer Dekodierung des Loxone-Binärprotokolls
- Dashboard mit Echtzeit-Übersicht aller aktiven und beendeten Streams
- Live-Stream Terminal mit Auto-Scroll
- Datei-Browser mit ZIP-Download
- Benutzerverwaltung mit zwei Rollen (Administrator / Benutzer)
- Einstellungsseite (HTTP-Port, UDP-Port, Stream-Timeout, Auto-Löschen)
- Server-Neustart über das Web-Interface
- Verlauf / Audit-Log für alle Aktionen

---

## Entwickelt von

**Silas Hoffmann** — mit Unterstützung von [Claude Code](https://claude.ai/code)
