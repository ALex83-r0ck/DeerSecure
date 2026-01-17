import os
import asyncio
import hashlib
import shutil
import subprocess
import sqlite3
import threading
import logging
import json
import time
from datetime import datetime
from typing import Any, List, Optional, Union #type: ignore

# Kivy / KivyMD Imports
from watchdog.observers import Observer #type: ignore
from watchdog.events import FileSystemEventHandler #type: ignore
from kivy.clock import Clock #type: ignore
from kivy.lang import Builder #type: ignore
from kivymd.app import MDApp #type: ignore
from kivymd.uix.list import OneLineListItem #type: ignore

# ---------------------------------------------------------
# LOGGING SETUP
# ---------------------------------------------------------
logger = logging.getLogger("DeerSecure")
logger.setLevel(logging.INFO)
logger.propagate = False 

if not logger.handlers:
    fh = logging.FileHandler("deersecure_internal.log", encoding="utf-8")
    fh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
    logger.addHandler(fh)

# ---------------------------------------------------------
# KV-LAYOUT
# ---------------------------------------------------------
KV = '''
MDBoxLayout:
    orientation: "vertical"
    md_bg_color: 1, 1, 1, 1

    MDTopAppBar:
        id: toolbar
        title: "DeerSecure"
        elevation: 2
        md_bg_color: 1, 1, 1, 1
        specific_text_color: 0, 0, 0, 1
        right_action_items: [["menu", lambda x: nav_drawer.set_state("open")]]
        
        MDBoxLayout:
            adaptive_width: True
            padding: ["4dp", "0dp", "0dp", "0dp"]
            MDIconButton:
                icon: "/assets/images/deer-icon-png-0.jpg"
                user_font_size: "32sp"
                on_release: app.run_manual_full_scan()

    MDProgressBar:
        id: progress_bar
        value: 0
        max: 100
        type: "determinate"
        size_hint_y: None
        height: "4dp"
        opacity: 0

    MDNavigationLayout:
        ScreenManager:
            id: screen_manager
            MDScreen:
                name: "dashboard"
                MDBoxLayout:
                    orientation: "vertical"
                    padding: "15dp"
                    MDLabel:
                        text: "System-Aktivität"
                        font_style: "H6"
                        size_hint_y: None
                        height: "40dp"
                    MDScrollView:
                        MDList:
                            id: log_list

        MDNavigationDrawer:
            id: nav_drawer
            anchor: "right"
            md_bg_color: 0.98, 0.98, 0.98, 1
            MDBoxLayout:
                orientation: "vertical"
                padding: "16dp"
                spacing: "10dp"
                MDRaisedButton:
                    text: "Dashboard"
                    size_hint_x: 1
                    on_release: screen_manager.current = "dashboard"; nav_drawer.set_state("close")
'''

class FileWatcher(FileSystemEventHandler): #type: ignore
    def __init__(self, app: Any): #type: ignore
        self.app = app
    def on_created(self, event: Any): #type: ignore
        if not event.is_directory:
            Clock.schedule_once(lambda dt: self.app.process_new_file(event.src_path), 0.5)

class DeerHunterApp(MDApp): #type: ignore
    def __init__(self, **kwargs: Any): #type: ignore
        super().__init__(**kwargs)
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY", "DEIN_KEY")
        self.cache_db = "deersecure_cache.db"
        # Typsichere Liste für Observer (Any verhindert Mypy .stop() Fehler)
        self.observers: List[Any] = [] #type: ignore

    def build(self) -> Any: #type: ignore
        self.init_database()
        return Builder.load_string(KV)

    def init_database(self) -> None: #type: ignore
        try:
            conn = sqlite3.connect(self.cache_db)
            conn.execute("CREATE TABLE IF NOT EXISTS cache (hash TEXT PRIMARY KEY, result TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
            conn.close()
        except Exception as e:
            logger.error(f"Datenbankfehler: {e}")

    def get_ui_id(self, widget_id: str) -> Optional[Any]: #type: ignore
        """Verhindert Pylance 'NoneType' Fehler bei IDs."""
        if self.root and hasattr(self.root, 'ids') and widget_id in self.root.ids:
            return self.root.ids[widget_id]
        return None

    def add_log_to_ui(self, message: str) -> None: #type: ignore
        def update(dt: float) -> None: #type: ignore
            log_list = self.get_ui_id('log_list')
            if log_list:
                log_list.add_widget(OneLineListItem(text=f"{datetime.now().strftime('%H:%M:%S')} | {message}"))
        Clock.schedule_once(update)
        logger.info(message)

    def run_manual_full_scan(self) -> None: #type: ignore
        pb = self.get_ui_id('progress_bar')
        if pb:
            pb.opacity = 1
            pb.value = 0
        self.add_log_to_ui("Manueller System-Scan gestartet...")
        threading.Thread(target=self._scan_task, daemon=True).start()

    def _scan_task(self) -> None: #type: ignore
        # Hier Logik für Scan...
        time.sleep(1)
        Clock.schedule_once(lambda dt: self._finish_scan())

    def _finish_scan(self) -> None: #type: ignore
        pb = self.get_ui_id('progress_bar')
        if pb: pb.opacity = 0
        self.add_log_to_ui("Scan abgeschlossen.")

    def on_start(self) -> None: #type: ignore
        # Überwachte Ordner (Beispiel)
        path = os.path.expanduser("~/Downloads")
        if os.path.exists(path):
            try:
                obs = Observer() #type: ignore
                obs.schedule(FileWatcher(self), path, recursive=True)
                obs.start()
                self.observers.append(obs)
                self.add_log_to_ui(f"Überwachung aktiv: {path}")
            except Exception as e:
                logger.error(f"Watchdog Start Fehler: {e}")

    def on_stop(self) -> None: #type: ignore
        """Sicheres Beenden der Observer-Threads."""
        for obs in self.observers:
            try:
                # Mypy ignoriert jetzt diese Zeilen durch List[Any]
                obs.stop() 
                obs.join()
            except Exception as e:
                logger.error(f"Fehler beim Stoppen des Observers: {e}")
        logger.info("DeerSecure wurde beendet.")

if __name__ == "__main__":
    DeerHunterApp().run()