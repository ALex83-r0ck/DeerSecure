import os
import asyncio
import hashlib
import shutil
import subprocess
import sqlite3
import threading
import logging
import json
from datetime import datetime, timedelta

# Kivy & KivyMD Imports
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from kivy.clock import Clock #type: ignore
from kivy.lang import Builder #type: ignore
from kivymd.app import MDApp #type: ignore
from kivymd.uix.screen import MDScreen #type: ignore
from kivymd.uix.screenmanager import ScreenManager #type: ignore
from kivymd.uix.button import MDRaisedButton, MDFlatButton #type: ignore
from kivymd.uix.label import MDLabel #type: ignore
from kivymd.uix.snackbar import MDSnackbar #type: ignore
from kivymd.uix.dialog import MDDialog #type: ignore
from kivymd.uix.list import OneLineListItem, TwoLineListItem #type: ignore
from kivymd.uix.boxlayout import MDBoxLayout #type: ignore
from kivymd.uix.scrollview import MDScrollView #type: ignore
import vt #type: ignore

# ---------------------------------------------------------
# LOGGER SETUP
# ---------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("deersecure_internal.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("DeerSecure")

# ---------------------------------------------------------
# KV-LAYOUT (GUI-Struktur)
# ---------------------------------------------------------
KV = '''
MDBoxLayout:
    orientation: "vertical"

    MDTopAppBar:
        title: "DeerSecure Monitor"
        elevation: 4
        left_action_items: [["menu", lambda x: nav_drawer.set_state("open")]]
        right_action_items: [["shield-check", lambda x: app.run_defender_scan()]]

    MDNavigationLayout:
        ScreenManager:
            id: screen_manager
            
            MDScreen:
                name: "dashboard"
                MDBoxLayout:
                    orientation: "vertical"
                    padding: "10dp"
                    spacing: "10dp"
                    
                    MDLabel:
                        text: "System-Status: Geschützt"
                        halign: "center"
                        font_style: "H5"
                        size_hint_y: None
                        height: "50dp"

                    MDScrollView:
                        MDList:
                            id: log_list  # Hier landen die Echtzeit-Logs

            MDScreen:
                name: "quarantine"
                MDBoxLayout:
                    orientation: "vertical"
                    padding: "10dp"
                    MDLabel:
                        text: "Quarantäne-Bereich"
                        halign: "center"
                        size_hint_y: None
                        height: "40dp"
                    MDScrollView:
                        MDList:
                            id: quarantine_list

        MDNavigationDrawer:
            id: nav_drawer
            MDBoxLayout:
                orientation: "vertical"
                padding: "8dp"
                spacing: "8dp"
                
                MDLabel:
                    text: "DeerSecure Menü"
                    font_style: "Button"
                    size_hint_y: None
                    height: "50dp"
                
                MDRaisedButton:
                    text: "Dashboard"
                    size_hint_x: 1
                    on_release: 
                        screen_manager.current = "dashboard"
                        nav_drawer.set_state("close")
                
                MDRaisedButton:
                    text: "Quarantäne"
                    size_hint_x: 1
                    on_release: 
                        app.show_quarantine()
                        nav_drawer.set_state("close")
                
                MDRaisedButton:
                    text: "Defender Historie"
                    size_hint_x: 1
                    on_release: 
                        app.check_defender_history()
                        nav_drawer.set_state("close")
'''

# ---------------------------------------------------------
# LOGIK-KLASSEN
# ---------------------------------------------------------

class FileWatcher(FileSystemEventHandler):
    """Überwacht Dateisystem-Events und meldet sie an die App."""
    def __init__(self, app):
        self.app = app

    def on_created(self, event):
        if not event.is_directory:
            logger.info(f"Neue Datei erkannt: {event.src_path}")
            # Übergabe an Kivy-Thread
            Clock.schedule_once(lambda dt: self.app.process_new_file(event.src_path), 0)

class DeerHunterApp(MDApp):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY", "DEIN_API_KEY")
        self.quarantine_dir = "C:/DeerSecure/Quarantine"
        self.watch_dirs = ["C:/Users/Public", os.path.join(os.path.expanduser("~"), "Downloads")]
        self.cache_db = "deersecure_cache.db"
        self.observers = []

    def build(self):
        self.theme_cls.primary_palette = "Blue"
        self.init_database()
        return Builder.load_string(KV)

    def init_database(self):
        """Erstellt die Cache-DB für Scan-Ergebnisse."""
        conn = sqlite3.connect(self.cache_db)
        conn.execute("""CREATE TABLE IF NOT EXISTS cache 
                        (hash TEXT PRIMARY KEY, result TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
        conn.close()

    def add_log_to_ui(self, message):
        """Fügt eine Nachricht direkt in die Liste im Dashboard ein."""
        if self.root is None:
            return
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.root.ids.log_list.add_widget(
            OneLineListItem(text=f"[{timestamp}] {message}")
        )

    # --- DATEIÜBERWACHUNG ---
    def on_start(self):
        """Wird beim Start der App ausgeführt."""
        for path in self.watch_dirs:
            if os.path.exists(path):
                obs = Observer()
                obs.schedule(FileWatcher(self), path, recursive=True)
                obs.start()
                self.observers.append(obs)
                logger.info(f"Überwachung aktiv: {path}")
                self.add_log_to_ui(f"Überwachung gestartet: {path}")

    def process_new_file(self, file_path):
        """Startet die Prüfung in einem Thread, um UI-Freeze zu verhindern."""
        threading.Thread(target=self.run_security_checks, args=(file_path,), daemon=True).start()

    def run_security_checks(self, file_path):
        """Kombinierte Prüfung: Cache -> VirusTotal."""
        file_hash = self.get_file_hash(file_path)
        if not file_hash: return

        # 1. Cache Check
        cached = self.check_cache(file_hash)
        if cached:
            self.handle_scan_result(file_path, json.loads(cached), from_cache=True)
            return

        # 2. VirusTotal Check (Async-Wrapper für Thread)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(self.vt_scan(file_hash))
        self.handle_scan_result(file_path, result)

    async def vt_scan(self, file_hash):
        """Abfrage der VirusTotal API."""
        try:
            async with vt.Client(self.api_key) as client:
                file_obj = await client.get_object_async(f"/files/{file_hash}")
                stats = file_obj.last_analysis_stats
                res = {"malicious": stats.get("malicious", 0)}
                self.save_to_cache(file_hash, res)
                return res
        except Exception as e:
            logger.error(f"VT Fehler: {e}")
            return {"error": str(e)}

    def handle_scan_result(self, file_path, result, from_cache=False):
        """Entscheidet, ob eine Datei in Quarantäne muss."""
        name = os.path.basename(file_path)
        malicious_count = result.get("malicious", 0)

        if malicious_count > 0:
            Clock.schedule_once(lambda dt: self.add_log_to_ui(f"WARNUNG: {name} ist bösartig!"), 0)
            self.move_to_quarantine(file_path)
        else:
            msg = f"Datei sicher: {name}" + (" (Cache)" if from_cache else "")
            Clock.schedule_once(lambda dt: self.add_log_to_ui(msg), 0)

    # --- DEFENDER INTEGRATION ---
    def run_defender_scan(self):
        """Startet Defender QuickScan ohne die UI einzufrieren."""
        self.add_log_to_ui("Defender Scan gestartet...")
        
        def scan():
            try:
                # Nutze PowerShell für den Scan
                subprocess.run(["powershell", "-Command", "Start-MpScan -ScanType QuickScan"], capture_output=True)
                Clock.schedule_once(lambda dt: self.add_log_to_ui("Defender Scan beendet."), 0)
            except Exception as e:
                logger.error(f"Defender Fehler: {e}")

        threading.Thread(target=scan, daemon=True).start()

    def check_defender_history(self):
        """Liest die letzten Funde von Windows Defender aus."""
        try:
            cmd = "Get-MpThreatDetection | Select-Object -First 5 | ConvertTo-Json"
            res = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
            if res.stdout:
                # Hier könnte man ein Dialogfenster mit den Funden öffnen
                self.add_log_to_ui("Defender Historie abgerufen (siehe Logfile)")
                logger.info(f"Defender History: {res.stdout}")
            else:
                self.add_log_to_ui("Keine Defender-Funde in der Historie.")
        except Exception as e:
            logger.error(f"Fehler beim Auslesen der Historie: {e}")

    # --- HILFSFUNKTIONEN ---
    def get_file_hash(self, path):
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""): h.update(chunk)
            return h.hexdigest()
        except: return None

    def save_to_cache(self, f_hash, data):
        conn = sqlite3.connect(self.cache_db)
        conn.execute("INSERT OR REPLACE INTO cache (hash, result) VALUES (?, ?)", (f_hash, json.dumps(data)))
        conn.commit()
        conn.close()

    def check_cache(self, f_hash):
        conn = sqlite3.connect(self.cache_db)
        res = conn.execute("SELECT result FROM cache WHERE hash=?", (f_hash,)).fetchone()
        conn.close()
        return res[0] if res else None

    def move_to_quarantine(self, path):
        """Verschiebt Datei und entzieht Rechte."""
        if not os.path.exists(self.quarantine_dir): os.makedirs(self.quarantine_dir)
        try:
            dest = os.path.join(self.quarantine_dir, os.path.basename(path))
            shutil.move(path, dest)
            # Simpler Schutz: Dateiendung ändern
            os.rename(dest, dest + ".locked")
            logger.warning(f"Datei in Quarantäne: {dest}")
        except Exception as e:
            logger.error(f"Quarantäne Fehler: {e}")

    def show_quarantine(self):
        """Zeigt Dateien im Quarantäne-Ordner an."""
        if self.root is None:
            return
        self.root.ids.screen_manager.current = "quarantine"
        list_widget = self.root.ids.quarantine_list
        list_widget.clear_widgets()
        if os.path.exists(self.quarantine_dir):
            for f in os.listdir(self.quarantine_dir):
                list_widget.add_widget(OneLineListItem(text=f))

    def on_stop(self):
        for obs in self.observers:
            obs.stop()
            obs.join()

if __name__ == "__main__":
    DeerHunterApp().run()