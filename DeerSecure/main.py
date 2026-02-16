import os
import threading
from typing import Optional, Any
from datetime import datetime
from kivy.lang import Builder #type: ignore
from kivy.clock import Clock #type: ignore
from kivymd.app import MDApp #type: ignore
from kivymd.uix.list import MDListItem, MDListItemHeadlineText #type: ignore

# Eigene Module importieren
from data.database import DatabaseHandler
from core.scanner import SecurityScanner
from core.watcher import start_monitoring

class DeerSecureApp(MDApp): #type: ignore
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.db = DatabaseHandler("deersecure_cache.db")
        potential_dirs = [
            os.path.join(os.environ.get('PUBLIC', 'C:/Users/Public')),
            os.path.expanduser("~/Downloads")
        ]
        self.watch_dirs = [dir for dir in potential_dirs if os.path.exists(dir)]
        self.observer = None

    def build(self):
        # UI aus dem ui-ordner laden
        return Builder.load_file("ui/deer_hunter.kv")

    def get_ui_id(self, widget_id: str) -> Optional[Any]:
        """Sicherer Zugriff auf UI-Elemente zur Vermeidung von NoneType-Fehlern."""
        if self.root and hasattr(self.root, 'ids') and widget_id in self.root.ids:
            return self.root.ids[widget_id]
        return None

    def on_start(self):
        if not self.watch_dirs:
            self.add_log("Keine potenziellen Verzeichnisse gefunden. Monitoring wird nicht gestartet.")
            return
        
        # Starte Monitoring im Hintergrund
        self.observer = start_monitoring(self.watch_dirs, self.process_file)
        Clock.schedule_once(lambda dt: self.add_log("Monitoring aktiv..."), 0.2)

    def process_file(self, file_path: str) -> None:
        filename = os.path.basename(file_path)
        Clock.schedule_once(lambda dt: self.add_log(f"Neue Datei erkannt: {filename}"), 0.2)

        # 1. Hash berechnen
        scanner = SecurityScanner()
        f_hash = scanner.get_file_hash(file_path)
        
        # 2. In DB prüfen
        cached_result = self.db.get_cache(f_hash) if f_hash else None
        
        # 3. UI benachrichtigen
        msg = f"Scan: {os.path.basename(file_path)} - {'Gefunden im Cache' if cached_result else 'Neu'}"
        Clock.schedule_once(lambda dt: self.add_log(msg))

    def add_log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_list = self.get_ui_id('log_list')

        if log_list:
            item = MDListItem(
                MDListItemHeadlineText(text=f"{timestamp} | {message}"),
            )
            log_list.add_widget(item)

    def on_stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()

if __name__ == "__main__":
    DeerSecureApp().run()