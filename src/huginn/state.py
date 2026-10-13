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

-- Every release the fresh malware hunt discovered, scanned or not, so recall can
-- tell a ranking gap (seen, not scanned) from a discovery gap (never seen).
CREATE TABLE IF NOT EXISTS fresh_seen (
    registry TEXT NOT NULL,
    package_name TEXT NOT NULL,
    version TEXT NOT NULL,
    seen_at TEXT NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,
    reasons TEXT NOT NULL DEFAULT '',
    scanned INTEGER NOT NULL DEFAULT 0,
    scan_status TEXT NOT NULL DEFAULT '',
    verdict TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (registry, package_name, version)
);

-- OSV MAL- advisories already fetched (recall), keyed by advisory id.
CREATE TABLE IF NOT EXISTS mal_advisories (
    advisory_id TEXT PRIMARY KEY,
    registry TEXT NOT NULL,
    package_name TEXT NOT NULL,
    published TEXT NOT NULL DEFAULT ''
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

    # --- fresh malware hunt ---------------------------------------------------------

    def record_fresh(self, registry: str, package_name: str, version: str, seen_at: str,
                     score: int, reasons: str) -> None:
        self.conn.execute(
            """
            INSERT INTO fresh_seen(registry, package_name, version, seen_at, score, reasons)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(registry, package_name, version) DO NOTHING
            """,
            (registry, package_name, version, seen_at, score, reasons[:500]),
        )
        self.conn.commit()

    def fresh_known(self, registry: str, package_name: str, version: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM fresh_seen WHERE registry=? AND package_name=? AND version=?",
            (registry, package_name, version),
        ).fetchone()
        return bool(row)

    def record_fresh_scan(self, registry: str, package_name: str, version: str,
                          scan_status: str, verdict: str) -> None:
        self.conn.execute(
            """UPDATE fresh_seen SET scanned=1, scan_status=?, verdict=?
               WHERE registry=? AND package_name=? AND version=?""",
            (scan_status, verdict, registry, package_name, version),
        )
        self.conn.commit()

    def fresh_seen_since(self, registry: str, since: str) -> dict[str, dict]:
        """Lower-case package name -> its most telling record since `since`."""
        def weight(record: dict) -> int:
            # A flagged version says more than a scanned one, which says more than unscanned.
            return 2 if record["verdict"] else 1 if record["scanned"] else 0

        out: dict[str, dict] = {}
        for name, score, reasons, scanned, status, verdict in self.conn.execute(
                """SELECT package_name, score, reasons, scanned, scan_status, verdict
                   FROM fresh_seen WHERE registry=? AND seen_at>=?""", (registry, since)):
            record = {"score": score, "reasons": reasons, "scanned": bool(scanned),
                      "scan_status": status, "verdict": verdict}
            prior = out.get(name.lower())
            if prior is None or weight(record) > weight(prior):
                out[name.lower()] = record
        return out

    def cached_advisory(self, advisory_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT advisory_id, package_name, published FROM mal_advisories WHERE advisory_id=?",
            (advisory_id,),
        ).fetchone()
        return {"id": row[0], "name": row[1], "published": row[2]} if row else None

    def cache_advisory(self, registry: str, adv: dict) -> None:
        self.conn.execute(
            """INSERT INTO mal_advisories(advisory_id, registry, package_name, published)
               VALUES(?,?,?,?) ON CONFLICT(advisory_id) DO NOTHING""",
            (adv["id"], registry, adv["name"], adv.get("published", "")),
        )
        self.conn.commit()
