import asyncio
import hashlib
import os
import shutil
import subprocess
import sqlite3
from datetime import datetime, timedelta
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from kivy.app import App
from kivy.clock import Clock
from kivy.uix.filechooser import FileChooserListView
from kivymd.app import MDApp
from kivymd.uix.screen import MDScreen
from kivymd.uix.screenmanager import ScreenManager
from kivymd.uix.button import MDRaisedButton, MDFlatButton
from kivymd.uix.label import MDLabel
from kivymd.uix.snackbar import MDSnackbar
from kivymd.uix.dialog import MDDialog
from kivymd.uix.list import OneLineListItem
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.scrollview import MDScrollView
import vt

class FileWatcher(FileSystemEventHandler):
    def __init__(self, app):
        self.app = app

    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            # Verwende Kivy's Clock für Thread-sichere GUI-Updates
            Clock.schedule_once(lambda dt: self.app.schedule_file_check(file_path), 0)

class DeerHunterApp(MDApp):  # MDApp statt App verwenden
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # WICHTIG: API-Key sollte aus Umgebungsvariable oder Config-Datei geladen werden
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY", "DEIN_API_KEY_HIER")
        self.quarantine_dir = "C:/DeerSecure/Quarantine"
        # Korrektur: watch_dir als Liste definieren
        self.watch_dirs = ["C:/Users/Public", "C:/Users/Student/Downloads"]
        self.observers = []  # Liste für mehrere Observer
        self.cache_db = "deersecure_cache.db"
        self.init_database()

    def init_database(self):
        """Initialisiert die Cache-Datenbank"""
        try:
            conn = sqlite3.connect(self.cache_db)
            c = conn.cursor()
            c.execute("""CREATE TABLE IF NOT EXISTS cache 
                        (hash TEXT PRIMARY KEY, 
                         result TEXT, 
                         timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Fehler beim Initialisieren der Datenbank: {e}")

    def build(self):
        self.sm = ScreenManager()
        
        # Hauptbildschirm
        main_screen = MDScreen(name="main")
        main_layout = MDBoxLayout(orientation="vertical", spacing="20dp", padding="20dp")
        
        main_layout.add_widget(MDLabel(
            text="DeerSecure: Schutz vor Schadsoftware",
            halign="center",
            theme_text_color="Primary",
            size_hint_y=None,
            height="40dp"
        ))
        
        main_layout.add_widget(MDRaisedButton(
            text="Datei scannen",
            size_hint=(None, None),
            size=("200dp", "40dp"),
            pos_hint={"center_x": 0.5},
            on_press=self.show_file_chooser
        ))
        
        main_layout.add_widget(MDRaisedButton(
            text="Quarantäne anzeigen",
            size_hint=(None, None),
            size=("200dp", "40dp"),
            pos_hint={"center_x": 0.5},
            on_press=lambda x: self.show_quarantine()
        ))
        
        main_layout.add_widget(MDRaisedButton(
            text="Defender-Scan jetzt",
            size_hint=(None, None),
            size=("200dp", "40dp"),
            pos_hint={"center_x": 0.5},
            on_press=self.run_defender_scan
        ))
        
        main_screen.add_widget(main_layout)
        
        # Dateiauswahl-Bildschirm
        file_screen = MDScreen(name="file_chooser")
        file_layout = MDBoxLayout(orientation="vertical", spacing="10dp", padding="10dp")
        
        # Verwende den ersten verfügbaren Pfad
        initial_path = next((path for path in self.watch_dirs if os.path.exists(path)), os.path.expanduser("~"))
        self.file_chooser = FileChooserListView(path=initial_path)
        file_layout.add_widget(self.file_chooser)
        
        button_layout = MDBoxLayout(orientation="horizontal", size_hint_y=None, height="40dp", spacing="10dp")
        button_layout.add_widget(MDRaisedButton(
            text="Auswählen",
            on_press=self.scan_selected_file
        ))
        button_layout.add_widget(MDRaisedButton(
            text="Zurück",
            on_press=lambda x: setattr(self.sm, 'current', 'main')
        ))
        file_layout.add_widget(button_layout)
        file_screen.add_widget(file_layout)
        
        # Quarantäne-Bildschirm
        quarantine_screen = MDScreen(name="quarantine")
        quarantine_layout = MDBoxLayout(orientation="vertical", spacing="10dp", padding="10dp")
        
        quarantine_layout.add_widget(MDLabel(
            text="Quarantäne-Dateien",
            halign="center",
            size_hint_y=None,
            height="40dp"
        ))
        
        # Scrollbare Liste für Quarantäne-Dateien
        scroll = MDScrollView()
        self.quarantine_list = MDBoxLayout(orientation="vertical", adaptive_height=True)
        scroll.add_widget(self.quarantine_list)
        quarantine_layout.add_widget(scroll)
        
        quarantine_layout.add_widget(MDRaisedButton(
            text="Zurück",
            size_hint_y=None,
            height="40dp",
            on_press=lambda x: setattr(self.sm, 'current', 'main')
        ))
        
        quarantine_screen.add_widget(quarantine_layout)
        
        self.sm.add_widget(main_screen)
        self.sm.add_widget(file_screen)
        self.sm.add_widget(quarantine_screen)
        
        # Starte Dateiüberwachung
        self.start_watching()
        
        # Plane Defender-Scan
        self.schedule_defender_scan()
        
        return self.sm

    def start_watching(self):
        """Startet die Dateiüberwachung für alle konfigurierten Verzeichnisse"""
        for watch_dir in self.watch_dirs:
            if os.path.exists(watch_dir):
                observer = Observer()
                event_handler = FileWatcher(self)
                observer.schedule(event_handler, watch_dir, recursive=True)
                observer.start()
                self.observers.append(observer)
                print(f"Überwachung gestartet für: {watch_dir}")

    def show_file_chooser(self, instance):
        self.sm.current = "file_chooser"

    def show_quarantine(self):
        self.update_quarantine_list()
        self.sm.current = "quarantine"

    def scan_selected_file(self, instance):
        selected = self.file_chooser.selection
        if selected:
            file_path = selected[0]
            self.schedule_file_check(file_path)
            self.sm.current = "main"
        else:
            self.show_snackbar("Keine Datei ausgewählt")

    def schedule_file_check(self, file_path):
        """Plant eine asynchrone Dateiprüfung"""
        asyncio.create_task(self.check_file(file_path))

    def get_file_hash(self, file_path):
        """Berechnet SHA256-Hash einer Datei"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            print(f"Fehler beim Berechnen des Hash: {e}")
            return None

    def cache_result(self, file_hash, result):
        """Speichert Scan-Ergebnis im Cache"""
        try:
            conn = sqlite3.connect(self.cache_db)
            c = conn.cursor()
            c.execute("INSERT OR REPLACE INTO cache (hash, result) VALUES (?, ?)", 
                     (file_hash, str(result)))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Fehler beim Cachen: {e}")

    def check_cached_result(self, file_hash):
        """Prüft, ob ein Ergebnis im Cache vorhanden ist"""
        try:
            conn = sqlite3.connect(self.cache_db)
            c = conn.cursor()
            c.execute("SELECT result, timestamp FROM cache WHERE hash = ?", (file_hash,))
            result = c.fetchone()
            conn.close()
            
            if result:
                # Cache ist 24 Stunden gültig
                cache_time = datetime.fromisoformat(result[1])
                if datetime.now() - cache_time < timedelta(hours=24):
                    return result[0]
            return None
        except Exception as e:
            print(f"Fehler beim Cache-Check: {e}")
            return None

    async def check_file(self, file_path):
        """Prüft eine Datei mit VirusTotal API"""
        if not os.path.exists(file_path):
            self.show_snackbar("Datei nicht gefunden")
            return

        file_hash = self.get_file_hash(file_path)
        if not file_hash:
            return

        filename = os.path.basename(file_path)

        # Prüfe Cache
        cached_result = self.check_cached_result(file_hash)
        if cached_result:
            try:
                result_dict = eval(cached_result)  # Vorsicht: eval verwenden
                if isinstance(result_dict, dict) and result_dict.get("malicious", 0) > 0:
                    self.quarantine_file(file_path)
                    self.show_snackbar(f"Datei {filename} ist verdächtig (aus Cache)!")
                else:
                    self.show_snackbar(f"Datei {filename} ist sicher (aus Cache)")
            except:
                pass
            return

        # VirusTotal API-Abfrage
        if self.api_key == "6fbbd41a847b24b741a5140b8019ef84cd100c7a949ef81908d178d1506aed53":
            self.show_snackbar("Bitte VirusTotal API-Key konfigurieren")
            return

        try:
            async with vt.Client(self.api_key) as client:
                try:
                    # Korrekte Verwendung der VirusTotal API
                    file_report = client.get_object(f"/files/{file_hash}")
                    stats = file_report.last_analysis_stats
                    positives = getattr(stats, "malicious", 0)
                    
                    # Cache das Ergebnis
                    cache_data = {
                        "malicious": positives,
                        "suspicious": getattr(stats, "suspicious", 0),
                        "harmless": getattr(stats, "harmless", 0),
                        "undetected": getattr(stats, "undetected", 0)
                    }
                    self.cache_result(file_hash, str(cache_data))
                    
                    if positives > 0:
                        self.quarantine_file(file_path)
                        self.show_snackbar(f"Bedrohung erkannt in {filename}! Positives: {positives}")
                    else:
                        self.show_snackbar(f"Keine Bedrohung in {filename} gefunden")
                        
                except vt.error.APIError as e:
                    if e.code == "NotFoundError":
                        self.show_snackbar(f"Datei {filename} nicht in VirusTotal-Datenbank")
                        # Optional: Datei hochladen (nur kleine Dateien)
                        if os.path.getsize(file_path) < 32 * 1024 * 1024:  # 32MB Limit
                            await self.upload_file(file_path)
                    else:
                        self.show_snackbar(f"VirusTotal-Fehler: {str(e)}")
        except Exception as e:
            self.show_snackbar(f"Fehler bei der Dateiprüfung: {str(e)}")

    async def upload_file(self, file_path):
        """Lädt eine Datei zur Analyse zu VirusTotal hoch"""
        try:
            async with vt.Client(self.api_key) as client:
                with open(file_path, "rb") as f:
                    analysis = client.scan_file(f)
                
                # Warte auf Analyse-Ergebnis (mit Timeout)
                filename = os.path.basename(file_path)
                self.show_snackbar(f"Datei {filename} wurde zur Analyse hochgeladen")
                
                # Einfache Behandlung - keine Warte-Schleife da die API async ist
                try:
                    # Versuche nach kurzer Zeit das Ergebnis abzurufen
                    await asyncio.sleep(5)  # Kurz warten
                    analysis_obj = client.get_object(f"/analyses/{analysis.id}")
                    
                    if hasattr(analysis_obj, 'stats'):
                        stats = analysis_obj.stats
                        positives = getattr(stats, "malicious", 0)
                        
                        cache_data = {
                            "malicious": positives,
                            "suspicious": getattr(stats, "suspicious", 0),
                            "harmless": getattr(stats, "harmless", 0),
                            "undetected": getattr(stats, "undetected", 0)
                        }
                        self.cache_result(self.get_file_hash(file_path), str(cache_data))
                        
                        if positives > 0:
                            self.quarantine_file(file_path)
                            self.show_snackbar(f"Upload-Scan: Bedrohung erkannt in {filename}!")
                        else:
                            self.show_snackbar(f"Upload-Scan: Keine Bedrohung in {filename}")
                    else:
                        self.show_snackbar(f"Upload-Analyse für {filename} läuft noch")
                        
                except Exception as inner_e:
                    self.show_snackbar(f"Upload-Analyse noch nicht verfügbar: {str(inner_e)}")
                    
        except Exception as e:
            self.show_snackbar(f"Upload fehlgeschlagen: {str(e)}")

    def quarantine_file(self, file_path):
        """Verschiebt eine Datei in die Quarantäne"""
        try:
            os.makedirs(self.quarantine_dir, exist_ok=True)
            filename = os.path.basename(file_path)
            dest_path = os.path.join(self.quarantine_dir, filename)
            
            # Verhindere Überschreibung durch Zeitstempel
            if os.path.exists(dest_path):
                name, ext = os.path.splitext(filename)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                dest_path = os.path.join(self.quarantine_dir, f"{name}_{timestamp}{ext}")
            
            shutil.move(file_path, dest_path)
            self.update_quarantine_list()
            return True
        except Exception as e:
            self.show_snackbar(f"Quarantäne fehlgeschlagen: {str(e)}")
            return False

    def update_quarantine_list(self):
        """Aktualisiert die Quarantäne-Liste"""
        self.quarantine_list.clear_widgets()
        if os.path.exists(self.quarantine_dir):
            for file in os.listdir(self.quarantine_dir):
                item = OneLineListItem(
                    text=file,
                    on_press=lambda x, f=file: self.restore_file(f)
                )
                self.quarantine_list.add_widget(item)

    def restore_file(self, filename):
        """Stellt eine Datei aus der Quarantäne wieder her"""
        def confirm_restore(dialog_instance):
            try:
                src_path = os.path.join(self.quarantine_dir, filename)
                # Verwende Desktop als Wiederherstellungsort
                dest_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Restored")
                os.makedirs(dest_dir, exist_ok=True)
                dest_path = os.path.join(dest_dir, filename)
                
                shutil.move(src_path, dest_path)
                self.update_quarantine_list()
                self.show_snackbar(f"Datei {filename} auf Desktop wiederhergestellt")
            except Exception as e:
                self.show_snackbar(f"Wiederherstellung fehlgeschlagen: {str(e)}")
            dialog_instance.dismiss()

        dialog = MDDialog(
            title="Datei wiederherstellen",
            text=f"Möchtest du {filename} aus der Quarantäne wiederherstellen?",
            buttons=[
                MDFlatButton(text="Abbrechen", on_release=lambda x: dialog.dismiss()),
                MDFlatButton(text="Wiederherstellen", on_release=confirm_restore)
            ]
        )
        dialog.open()

    def run_defender_scan(self, instance=None):
        """Führt einen Windows Defender Scan aus"""
        try:
            # Prüfe, ob Windows Defender verfügbar ist
            result = subprocess.run(
                ["powershell", "Get-Command Start-MpScan"], 
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                self.show_snackbar("Windows Defender nicht verfügbar")
                return

            subprocess.run(
                ["powershell", "Start-MpScan -ScanType QuickScan"], 
                check=True, timeout=300
            )
            
            # Prüfe Bedrohungen
            result = subprocess.run(
                ["powershell", "Get-MpThreat"], 
                capture_output=True, text=True, timeout=30
            )
            
            if not result.stdout.strip() or "No threats" in result.stdout:
                self.show_snackbar("Defender-Scan: Keine Bedrohungen gefunden")
            else:
                self.show_snackbar("Defender-Scan: Bedrohung erkannt!")
                
        except subprocess.TimeoutExpired:
            self.show_snackbar("Defender-Scan Timeout")
        except Exception as e:
            self.show_snackbar(f"Defender-Scan fehlgeschlagen: {str(e)}")

    def schedule_defender_scan(self):
        """Plant den täglichen Defender-Scan um 22:00 Uhr"""
        now = datetime.now()
        target_time = now.replace(hour=22, minute=0, second=0, microsecond=0)
        
        # Wenn es bereits nach 22:00 ist, plane für den nächsten Tag
        if now >= target_time:
            target_time += timedelta(days=1)
        
        seconds_until = (target_time - now).total_seconds()
        Clock.schedule_once(lambda dt: self.run_defender_scan(), seconds_until)
        
        # Nach dem Scan, plane den nächsten
        Clock.schedule_once(lambda dt: self.schedule_defender_scan(), seconds_until + 1)

    def show_snackbar(self, text):
        """Zeigt eine Snackbar-Nachricht an"""
        try:
            snackbar = MDSnackbar(
                MDLabel(text=text, theme_text_color="Custom"),
                snackbar_x="10dp",
                snackbar_y="10dp"
            )
            snackbar.open()
        except:
            # Fallback für ältere KivyMD Versionen
            MDSnackbar(text=text).open()

    def on_stop(self):
        """Wird beim Beenden der App aufgerufen"""
        for observer in self.observers:
            observer.stop()
            observer.join()

if __name__ == "__main__":
    # Erstelle Event Loop für asyncio
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    app = DeerHunterApp()
    app.run()