import sqlite3
import json
import logging
from typing import Optional

class DatabaseHandler:
    def __init__(self, db_name: str) -> None:
        self.db_name = db_name
        self.__init__db()

    def __init__db(self):
        # Verbindung zur Datenbank herstellen und Tabellen erstellen
        with sqlite3.connect(self.db_name) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache 
                (hash TEXT PRIMARY KEY, result TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)
            """)
    
    def get_cache(self, file_hash: str) -> Optional[str]:
        with sqlite3.connect(self.db_name) as conn:
            res = conn.execute("SELECT result FROM cache WHERE hash = ?", (file_hash,)).fetchone()
            return json.loads(res[0]) if res else None
        
    def save_cache(self, file_hash: str, result: dict):
        with sqlite3.connect(self.db_name) as conn:
            conn.execute("INSERT OR REPLACE INTO cache (hash, result) VALUES (?, ?)",
                         (file_hash, json.dumps(result)))