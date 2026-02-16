# 🦌 DeerSecure - README

**Status:** Development (MVP - Laufstark)
DeerSecure ist eine hybride Sicherheitslösung für Windows, die Echtzeit-Dateisystemüberwachung mit Cloud-Analysen (VirusTotal) und nativer Integration von Windows Defender kombiniert.

## 🚀 Aktuelle Features

**Echtzeit-Monitoring:** Überwachung von C:/Users/Public und Downloads mittels Watchdog.

**Modernes Dashboard:** KivyMD-UI mit weißem Design, interaktivem Logo-Button (Scan-Trigger) und Hamburger-Menü.

**Integrierter Logger:** Alle Aktivitäten werden präzise in deersecure_internal.log protokolliert.

**Smart Caching:** SQLite-Datenbank zur Vermeidung redundanter API-Abfragen.

**UI-Animation:** Fortschrittsbalken und visuelles Feedback während manueller Scans.

## 🛠 Installation & Start

### Repository klonen

**Umgebung einrichten:**

```bash
python -m venv .venv
source .venv/Scripts/activate  # Windows
pip install -r requirements.txt 
```

**VirusTotal API-Key:**

Setze deinen Key in der Datei deer_hunter.py oder als Umgebungsvariable VIRUSTOTAL_API_KEY.

**Start:**

```bash
python DeerSecure/deer_hunter.py
```

## 🗺️ Roadmap: Der Weg zur Version 1.0

Um die App produktionsreif zu machen, muss ich noch folgende Phasen durchlaufen:

**Phase 1: Stabilität & Sicherheit (Kurzfristig)**
[ ] Berechtigungs-Eskalation: Automatischer UAC-Prompt beim Start, um Defender-Scans ohne manuelle Admin-Rechte auszuführen.

[ ] Quarantäne-Verwaltung: Implementierung von „Wiederherstellen“ und „Endgültig löschen“ im UI-Screen.

[ ] Exception-Handling: Besseres Abfangen von Netzwerkfehlern (Timeout bei VT API).

**Phase 2: Analyse-Tiefe (Mittelfristig)**
[ ] Defender History Viewer: Einlesen der Get-MpThreatDetection Logs direkt in das Dashboard-Fenster.

[ ] Heuristik-Check: Einfache lokale Prüfung auf verdächtige Dateiendungen oder doppelte Endungen (z.B. foto.jpg.exe).

[ ] Statistik-Modul: Visualisierung der Scans pro Tag (Bar-Charts).

**Phase 3: System-Integration (Langfristig)**
[ ] System Tray: Minimierung der App in den Infobereich (Tray) neben der Uhr.

[ ] Auto-Update: Mechanismus zum Aktualisieren der lokalen Scan-Logik.

## 🧪 Testing-Konzept

Da Sicherheitssoftware keine Fehler erlauben darf, brauchen wir ein zweistufiges Test-System.

1. Unit Tests (Einzelne Funktionen)
Wir testen die Logik isoliert (ohne UI). Dazu nutzen wir pytest.

**Hashing:** Prüfen, ob get_file_hash für bekannte Dateien den richtigen SHA256 liefert.

**Cache:** Prüfen, ob die SQL-Einträge korrekt gelesen und geschrieben werden.

**Rechte-Check:** Simulieren von Admin- und Nicht-Admin-Umgebungen.

1. Integration Tests (Zusammenspiel)
File-to-Log-Flow: Eine Testdatei in den Download-Ordner legen und prüfen, ob nach X Sekunden ein Log-Eintrag in der UI-Liste erscheint.

VT-Mocking: Die VirusTotal API simulieren, um keine echten Credits zu verbrauchen und "Malicious"-Funde zu testen.

Beispiel für einen ersten Test (tests/test_logic.py):
´´´python
    import pytest
    from DeerSecure.deer_hunter import DeerHunterApp
    def test_hash_calculation():
        # Teste mit einer temporären Datei
        with open("test.txt", "w") as f:
            f.write("DeerSecure Test")
    app = DeerHunterApp()
    file_hash = app.get_file_hash_with_retry("test.txt")
    assert file_hash is not None
    assert len(file_hash) == 64  # SHA256 Länge
