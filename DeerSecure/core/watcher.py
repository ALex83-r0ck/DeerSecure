from watchdog.observers import Observer
from watchdog.events import DirCreatedEvent, FileCreatedEvent, FileSystemEventHandler
from typing import List

class DeerWatcher(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback

    def on_created(self, event):
        if not event.is_directory:
            # Hier übergeben wir den Pfad an die App zurück
            self.callback(event.src_path)

def start_monitoring(paths: List, callback):
    observer = Observer()
    for path in paths:
        observer.schedule(DeerWatcher(callback), path, recursive=True)
    observer.start()
    return observer