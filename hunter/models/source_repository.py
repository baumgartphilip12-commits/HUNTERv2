"""Source and sync-event persistence helpers for the SQLite knowledge store."""

from __future__ import annotations

import sqlite3
from typing import Any, TYPE_CHECKING

from hunter.models.common import utc_now

if TYPE_CHECKING:
    from hunter.models.knowledge_store import KnowledgeStore


class SourceRepository:
    """Encapsulates sync source and sync event persistence."""

    def __init__(self, store: "KnowledgeStore"):
        self.store = store

    def list_sources(self) -> list[dict]:
        with self.store._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM sync_sources ORDER BY name COLLATE NOCASE"
            ).fetchall()
        return [self._row_to_source(row) for row in rows]

    def get_source(self, source_id: int) -> dict | None:
        with self.store._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sync_sources WHERE id = ?",
                (source_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_source(row)

    def get_source_by_name(self, source_name: str) -> dict | None:
        with self.store._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sync_sources WHERE name = ?",
                (source_name,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_source(row)

    def create_source(
        self,
        *,
        name: str,
        connector: str,
        config: dict | None = None,
        enabled: bool = True,
        approved: bool = True,
    ) -> int:
        try:
            with self.store._connect() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO sync_sources (name, connector, config_json, enabled, approved)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        name,
                        connector,
                        self.store._json_dump(config or {}),
                        int(enabled),
                        int(approved),
                    ),
                )
                return int(cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"Sync source already exists: {name}") from exc

    def update_source(
        self,
        source_id: int,
        *,
        name: str | None = None,
        connector: str | None = None,
        config: dict | None = None,
        enabled: bool | None = None,
        approved: bool | None = None,
        health: str | None = None,
        last_sync_at: str | None = None,
        last_status: str | None = None,
        last_error: str | None = None,
    ) -> None:
        assignments: list[str] = []
        params: list[Any] = []
        if name is not None:
            assignments.append("name = ?")
            params.append(name)
        if connector is not None:
            assignments.append("connector = ?")
            params.append(connector)
        if config is not None:
            assignments.append("config_json = ?")
            params.append(self.store._json_dump(config))
        if enabled is not None:
            assignments.append("enabled = ?")
            params.append(int(enabled))
        if approved is not None:
            assignments.append("approved = ?")
            params.append(int(approved))
        if health is not None:
            assignments.append("health = ?")
            params.append(health)
        if last_sync_at is not None:
            assignments.append("last_sync_at = ?")
            params.append(last_sync_at)
        if last_status is not None:
            assignments.append("last_status = ?")
            params.append(last_status)
        if last_error is not None:
            assignments.append("last_error = ?")
            params.append(last_error)
        if not assignments:
            return
        params.append(source_id)
        with self.store._connect() as conn:
            conn.execute(
                f"UPDATE sync_sources SET {', '.join(assignments)} WHERE id = ?",
                params,
            )

    def create_sync_event(
        self,
        source_id: int,
        connector: str,
        mode: str,
        *,
        summary: dict | None = None,
        diff: dict | None = None,
        snapshot_path: str = "",
        rollback_snapshot_path: str = "",
        status: str = "running",
        error: str = "",
    ) -> int:
        with self.store._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO sync_events (
                    source_id, connector, started_at, mode, status,
                    summary_json, diff_json, snapshot_path,
                    rollback_snapshot_path, error
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_id,
                    connector,
                    utc_now(),
                    mode,
                    status,
                    self.store._json_dump(summary or {}),
                    self.store._json_dump(diff or {}),
                    snapshot_path,
                    rollback_snapshot_path,
                    error,
                ),
            )
            return int(cursor.lastrowid)

    def finish_sync_event(
        self,
        event_id: int,
        *,
        status: str,
        summary: dict | None = None,
        diff: dict | None = None,
        snapshot_path: str | None = None,
        rollback_snapshot_path: str | None = None,
        error: str = "",
    ) -> None:
        assignments = [
            "finished_at = ?",
            "status = ?",
            "summary_json = ?",
            "diff_json = ?",
            "error = ?",
        ]
        params: list[Any] = [
            utc_now(),
            status,
            self.store._json_dump(summary or {}),
            self.store._json_dump(diff or {}),
            error,
        ]
        if snapshot_path is not None:
            assignments.append("snapshot_path = ?")
            params.append(snapshot_path)
        if rollback_snapshot_path is not None:
            assignments.append("rollback_snapshot_path = ?")
            params.append(rollback_snapshot_path)
        params.append(event_id)
        with self.store._connect() as conn:
            conn.execute(
                f"UPDATE sync_events SET {', '.join(assignments)} WHERE id = ?",
                params,
            )

    def list_sync_events(self, source_id: int | None = None) -> list[dict]:
        query = "SELECT * FROM sync_events"
        params: tuple[Any, ...] = ()
        if source_id is not None:
            query += " WHERE source_id = ?"
            params = (source_id,)
        query += " ORDER BY id DESC LIMIT 50"
        with self.store._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                **dict(row),
                "summary": self.store._json_load(row["summary_json"], {}),
                "diff": self.store._json_load(row["diff_json"], {}),
            }
            for row in rows
        ]

    def _row_to_source(self, row) -> dict:
        return {
            **dict(row),
            "config": self.store._json_load(row["config_json"], {}),
            "enabled": bool(row["enabled"]),
            "approved": bool(row["approved"]),
        }
