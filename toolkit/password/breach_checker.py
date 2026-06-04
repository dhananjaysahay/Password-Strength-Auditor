"""Check passwords against a local SQLite database of known-compromised hashes."""

import hashlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path

DB_PATH = Path(__file__).parent.parent.parent / "data" / "breached.db"


@dataclass
class BreachResult:
    is_breached: bool
    message: str = ""


class BreachChecker:
    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or DB_PATH
        self._ensure_db()

    def _ensure_db(self):
        if self.db_path.exists():
            return
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("CREATE TABLE IF NOT EXISTS breached_hashes (sha256 TEXT PRIMARY KEY)")
        common_file = self.db_path.parent / "common_passwords.txt"
        if common_file.exists():
            with open(common_file) as f:
                hashes = [(hashlib.sha256(l.strip().encode()).hexdigest(),) for l in f if l.strip()]
            conn.executemany("INSERT OR IGNORE INTO breached_hashes (sha256) VALUES (?)", hashes)
        conn.commit()
        conn.close()

    def check(self, password: str) -> BreachResult:
        h = hashlib.sha256(password.encode()).hexdigest()
        try:
            conn = sqlite3.connect(str(self.db_path))
            found = conn.execute("SELECT 1 FROM breached_hashes WHERE sha256=?", (h,)).fetchone()
            conn.close()
        except sqlite3.Error:
            return BreachResult(False, "Could not check breach database")
        if found:
            return BreachResult(True, "This password appears in known data breaches")
        return BreachResult(False, "Not found in breach database")

    @property
    def count(self) -> int:
        try:
            conn = sqlite3.connect(str(self.db_path))
            n = conn.execute("SELECT COUNT(*) FROM breached_hashes").fetchone()[0]
            conn.close()
            return n
        except sqlite3.Error:
            return 0
