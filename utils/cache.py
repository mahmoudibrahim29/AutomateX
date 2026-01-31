import sqlite3
import json
import time
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
  ioc TEXT NOT NULL,
  provider TEXT NOT NULL,
  fetched_at INTEGER NOT NULL,
  data TEXT NOT NULL,
  PRIMARY KEY (ioc, provider)
);
"""

class Cache:
    def __init__(self, path: str = "ioc_cache.db"):
        self.path = path
        self._init()

    def _init(self):
        with sqlite3.connect(self.path) as con:
            con.execute(SCHEMA)
            con.commit()

    def get(self, ioc: str, provider: str, ttl_seconds: int = 86400) -> Optional[dict]:
        now = int(time.time())
        with sqlite3.connect(self.path) as con:
            row = con.execute(
                "SELECT fetched_at, data FROM cache WHERE ioc=? AND provider=?",
                (ioc, provider),
            ).fetchone()

        if not row:
            return None

        fetched_at, data = row
        if now - fetched_at > ttl_seconds:
            return None

        return json.loads(data)

    def set(self, ioc: str, provider: str, data: dict):
        now = int(time.time())
        with sqlite3.connect(self.path) as con:
            con.execute(
                "INSERT OR REPLACE INTO cache (ioc, provider, fetched_at, data) VALUES (?, ?, ?, ?)",
                (ioc, provider, now, json.dumps(data)),
            )
            con.commit()
