import hashlib
import os
from typing import Optional

class SecurityScanner:
    def __init__(self):
        pass

    def get_file_hash(self, path: str) -> Optional[str]:
        """Berechnet den SHA256 Hash einer Datei."""
        if not os.path.exists(path):
            return None
            
        sha256_hash = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                # Lesen in 4KB Blöcken für Effizienz
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except IOError:
            # Datei könnte gesperrt sein
            return None