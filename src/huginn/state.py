from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .models import ReleaseCandidate


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
CREATE TABLE IF NOT EXISTS cursors (
    source TEXT PRIMARY KEY,
    cursor_value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    registry TEXT NOT NULL,
    package_name TEXT NOT NULL,
    package_version TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 50,
    state TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    not_before TEXT NOT NULL,
    lease_owner TEXT NOT NULL DEFAULT '',
    lease_expires_at TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(registry, package_name, package_version)
);
CREATE INDEX IF NOT EXISTS jobs_ready_idx
ON jobs(state, not_before, priority, created_at);
"""


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


class StateDB:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def is_completed(self, registry: str, package_name: str, version: str) -> bool:
        row = self.conn.execute(
            "SELECT status FROM releases WHERE registry=? AND package_name=? AND version=?",
            (registry, package_name, version),
        ).fetchone()
        return bool(row and row["status"] == "completed")

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
            "UPDATE releases SET status='failed', last_error=? WHERE registry=? AND package_name=? AND version=?",
            (error[:4000], registry, package_name, version),
        )
        self.conn.commit()

    def get_cursor(self, source: str) -> tuple[str, str] | None:
        row = self.conn.execute(
            "SELECT cursor_value, updated_at FROM cursors WHERE source=?", (source,)
        ).fetchone()
        return (str(row["cursor_value"]), str(row["updated_at"])) if row else None

    def set_cursor(self, source: str, value: str, updated_at: str) -> None:
        self.conn.execute(
            """
            INSERT INTO cursors(source, cursor_value, updated_at) VALUES(?,?,?)
            ON CONFLICT(source) DO UPDATE SET cursor_value=excluded.cursor_value, updated_at=excluded.updated_at
            """,
            (source, value, updated_at),
        )
        self.conn.commit()

    def enqueue(self, candidate: ReleaseCandidate, now: str, *, priority: int = 50, force: bool = False) -> None:
        if not force and self.is_completed(candidate.registry, candidate.name, candidate.version):
            return
        payload = json.dumps({
            "registry": candidate.registry,
            "name": candidate.name,
            "version": candidate.version,
            "event_type": candidate.event_type,
            "published_at": candidate.published_at,
            "source_url": candidate.source_url,
        }, sort_keys=True)
        if force:
            self.conn.execute(
                """
                INSERT INTO jobs(
                    registry, package_name, package_version, event_type, payload_json,
                    priority, state, attempts, not_before, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,'pending',0,?,?,?)
                ON CONFLICT(registry, package_name, package_version) DO UPDATE SET
                    event_type=excluded.event_type,
                    payload_json=excluded.payload_json,
                    priority=excluded.priority,
                    state='pending',
                    attempts=0,
                    not_before=excluded.not_before,
                    lease_owner='',
                    lease_expires_at='',
                    last_error='',
                    updated_at=excluded.updated_at
                """,
                (candidate.registry, candidate.name, candidate.version, candidate.event_type,
                 payload, priority, now, now, now),
            )
        else:
            self.conn.execute(
                """
                INSERT INTO jobs(
                    registry, package_name, package_version, event_type, payload_json,
                    priority, state, attempts, not_before, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,'pending',0,?,?,?)
                ON CONFLICT(registry, package_name, package_version) DO NOTHING
                """,
                (candidate.registry, candidate.name, candidate.version, candidate.event_type,
                 payload, priority, now, now, now),
            )
        self.conn.commit()

    def lease(self, owner: str, now: str, *, limit: int = 25, lease_minutes: int = 30) -> list[tuple[int, ReleaseCandidate]]:
        now_dt = datetime.fromisoformat(now.replace("Z", "+00:00"))
        expires = _iso(now_dt + timedelta(minutes=lease_minutes))
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            rows = self.conn.execute(
                """
                SELECT * FROM jobs
                WHERE (
                    (state IN ('pending','retry') AND not_before <= ?)
                    OR (state='leased' AND lease_expires_at != '' AND lease_expires_at <= ?)
                )
                ORDER BY priority ASC, created_at ASC
                LIMIT ?
                """,
                (now, now, limit),
            ).fetchall()
            leased: list[tuple[int, ReleaseCandidate]] = []
            for row in rows:
                self.conn.execute(
                    """
                    UPDATE jobs SET state='leased', attempts=attempts+1, lease_owner=?,
                        lease_expires_at=?, updated_at=?
                    WHERE id=?
                    """,
                    (owner, expires, now, row["id"]),
                )
                payload = json.loads(row["payload_json"])
                leased.append((int(row["id"]), ReleaseCandidate(**payload)))
            self.conn.commit()
            return leased
        except Exception:
            self.conn.rollback()
            raise

    def complete_job(self, job_id: int, now: str) -> None:
        self.conn.execute(
            "UPDATE jobs SET state='complete', lease_owner='', lease_expires_at='', updated_at=? WHERE id=?",
            (now, job_id),
        )
        self.conn.commit()

    def retry_job(self, job_id: int, error: str, now: str) -> None:
        row = self.conn.execute("SELECT attempts FROM jobs WHERE id=?", (job_id,)).fetchone()
        attempts = int(row["attempts"]) if row else 1
        delay = min(3600, 60 * (2 ** max(0, attempts - 1)))
        now_dt = datetime.fromisoformat(now.replace("Z", "+00:00"))
        not_before = _iso(now_dt + timedelta(seconds=delay))
        self.conn.execute(
            """
            UPDATE jobs SET state='retry', not_before=?, lease_owner='', lease_expires_at='',
                last_error=?, updated_at=? WHERE id=?
            """,
            (not_before, error[:4000], now, job_id),
        )
        self.conn.commit()

    def queue_stats(self) -> dict[str, int]:
        rows = self.conn.execute("SELECT state, COUNT(*) AS n FROM jobs GROUP BY state").fetchall()
        return {str(row["state"]): int(row["n"]) for row in rows}
