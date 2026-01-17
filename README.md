# 🦌 DeerSecure 

Status: Development (MVP - Laufstark)

DeerSecure ist eine hybride Sicherheitslösung für Windows, die Echtzeit-Dateisystemüberwachung mit Cloud-Analysen (VirusTotal) und nativer Integration von Windows Defender kombiniert.

## 🚀 Aktuelle Features

Echtzeit-Monitoring: 
- Überwachung von C:/Users/Public und Downloads mittels Watchdog.

Modernes Dashboard: 
- KivyMD-UI mit weißem Design, interaktivem Logo-Button (Scan-Trigger) und Hamburger-Menü.

Integrierter Logger:
- Alle Aktivitäten werden präzise in deersecure_internal.log protokolliert.

Smart Caching:
- SQLite-Datenbank zur Vermeidung redundanter API-Abfragen.

UI-Animation:
- Fortschrittsbalken und visuelles Feedback während manueller Scans.

## 🛠 Installation & Start
Repository klonen

Umgebung einrichten:

'''bash
python -m venv .venv
source .venv/Scripts/activate  # Windows
pip install -r requirements.txt'''

VirusTotal API-Key: 
- Setze deinen Key in der Datei deer_hunter.py oder als Umgebungsvariable VIRUSTOTAL_API_KEY.

Start:

'''bash
python DeerSecure/deer_hunter.py'''
