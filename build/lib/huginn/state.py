from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS releases (
    registry TEXT NOT NULL,
    package_name TEXT NOT NULL,
    version TEXT NOT NULL,
    event_type TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'discovered',
    artifact_sha256 TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    completed_at TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (registry, package_name, version)
);

CREATE TABLE IF NOT EXISTS registry_cursors (
    cursor_key TEXT PRIMARY KEY,
    cursor_value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class StateDB:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def has_release(self, registry: str, package_name: str, version: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM releases WHERE registry=? AND package_name=? AND version=?",
            (registry, package_name, version),
        ).fetchone()
        return bool(row)

    def is_completed(self, registry: str, package_name: str, version: str) -> bool:
        row = self.conn.execute(
            "SELECT status FROM releases WHERE registry=? AND package_name=? AND version=?",
            (registry, package_name, version),
        ).fetchone()
        return bool(row and row[0] == "completed")

    def package_seen(self, registry: str, package_name: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM releases WHERE registry=? AND package_name=? LIMIT 1",
            (registry, package_name),
        ).fetchone()
        return bool(row)

    def record_discovered(self, registry: str, package_name: str, version: str, event_type: str, first_seen_at: str) -> None:
        self.conn.execute(
            """
            INSERT INTO releases(registry, package_name, version, event_type, first_seen_at)
            VALUES(?,?,?,?,?)
            ON CONFLICT(registry, package_name, version) DO NOTHING
            """,
            (registry, package_name, version, event_type, first_seen_at),
        )
        self.conn.commit()

    def mark_completed(self, registry: str, package_name: str, version: str, sha256: str, completed_at: str) -> None:
        self.conn.execute(
            """
            UPDATE releases SET status='completed', artifact_sha256=?, last_error='', completed_at=?
            WHERE registry=? AND package_name=? AND version=?
            """,
            (sha256, completed_at, registry, package_name, version),
        )
        self.conn.commit()

    def mark_failed(self, registry: str, package_name: str, version: str, error: str) -> None:
        self.conn.execute(
            """UPDATE releases SET status='failed', last_error=? WHERE registry=? AND package_name=? AND version=?""",
            (error[:4000], registry, package_name, version),
        )
        self.conn.commit()

    def get_cursor(self, key: str) -> str | None:
        row = self.conn.execute(
            "SELECT cursor_value FROM registry_cursors WHERE cursor_key=?",
            (key,),
        ).fetchone()
        return str(row[0]) if row else None

    def set_cursor(self, key: str, value: str) -> None:
        self.conn.execute(
            """
            INSERT INTO registry_cursors(cursor_key, cursor_value, updated_at)
            VALUES(?,?,?)
            ON CONFLICT(cursor_key) DO UPDATE SET
                cursor_value=excluded.cursor_value,
                updated_at=excluded.updated_at
            """,
            (key, value, _utc_now()),
        )
        self.conn.commit()

    def set_cursors(self, values: dict[str, str]) -> None:
        if not values:
            return
        now = _utc_now()
        with self.conn:
            for key, value in values.items():
                self.conn.execute(
                    """
                    INSERT INTO registry_cursors(cursor_key, cursor_value, updated_at)
                    VALUES(?,?,?)
                    ON CONFLICT(cursor_key) DO UPDATE SET
                        cursor_value=excluded.cursor_value,
                        updated_at=excluded.updated_at
                    """,
                    (key, value, now),
                )
