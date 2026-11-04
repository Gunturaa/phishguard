import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List


class ScanStorage:
    def __init__(self) -> None:
        default_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "phishguard.db")
        configured_path = os.getenv("SCAN_DATABASE_PATH", "").strip()
        self.path = configured_path or default_path
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT,
                    risk_score INTEGER,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

    def save(self, scan_type: str, target: str, status: str, result: Dict[str, Any], risk_score: int | None = None) -> int:
        created_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scan_history (scan_type, target, status, risk_score, result_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (scan_type, target, status, risk_score, json.dumps(result), created_at),
            )
            return int(cursor.lastrowid)

    def list_recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        safe_limit = max(1, min(limit, 100))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id, scan_type, target, status, risk_score, created_at FROM scan_history ORDER BY id DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get(self, record_id: int) -> Dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM scan_history WHERE id = ?",
                (record_id,),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["result"] = json.loads(result.pop("result_json"))
        return result


scan_storage = ScanStorage()
