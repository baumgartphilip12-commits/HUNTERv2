"""Hunt pack persistence helpers for the SQLite knowledge store."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hunter.models.common import utc_now

if TYPE_CHECKING:
    from hunter.models.knowledge_store import KnowledgeStore


class HuntPackRepository:
    """Encapsulates save/update/list operations for hunt packs."""

    def __init__(self, store: "KnowledgeStore"):
        self.store = store

    def save_hunt_pack(
        self,
        *,
        name: str,
        status: str,
        summary: dict,
        payload: dict,
        entity_ids: list[int],
        created_at: str | None = None,
        updated_at: str | None = None,
    ) -> int:
        now = utc_now()
        created = created_at or now
        updated = updated_at or now
        with self.store._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO hunt_packs (name, status, summary_json, payload_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    status,
                    self.store._json_dump(summary),
                    self.store._json_dump(payload),
                    created,
                    updated,
                ),
            )
            hunt_pack_id = int(cursor.lastrowid)
            for entity_id in entity_ids:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO hunt_pack_entities (hunt_pack_id, entity_id, role)
                    VALUES (?, ?, 'selected')
                    """,
                    (hunt_pack_id, entity_id),
                )
            return hunt_pack_id

    def update_hunt_pack(
        self,
        hunt_pack_id: int,
        *,
        name: str | None = None,
        status: str | None = None,
        summary: dict | None = None,
        payload: dict | None = None,
    ) -> None:
        now = utc_now()
        with self.store._connect() as conn:
            row = conn.execute(
                "SELECT * FROM hunt_packs WHERE id = ?",
                (hunt_pack_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"Hunt pack {hunt_pack_id} was not found.")
            conn.execute(
                """
                UPDATE hunt_packs
                SET name = ?,
                    status = ?,
                    summary_json = ?,
                    payload_json = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    name if name is not None else row["name"],
                    status if status is not None else row["status"],
                    self.store._json_dump(
                        summary if summary is not None else self.store._json_load(row["summary_json"], {})
                    ),
                    self.store._json_dump(
                        payload if payload is not None else self.store._json_load(row["payload_json"], {})
                    ),
                    now,
                    hunt_pack_id,
                ),
            )

    def list_hunt_packs(self) -> list[dict]:
        with self.store._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM hunt_packs ORDER BY id DESC"
            ).fetchall()
        return [
            {
                **dict(row),
                "summary": self.store._json_load(row["summary_json"], {}),
                "payload": self.store._json_load(row["payload_json"], {}),
            }
            for row in rows
        ]

    def get_hunt_pack(self, hunt_pack_id: int) -> dict | None:
        with self.store._connect() as conn:
            row = conn.execute(
                "SELECT * FROM hunt_packs WHERE id = ?",
                (hunt_pack_id,),
            ).fetchone()
            entity_rows = conn.execute(
                """
                SELECT e.*
                FROM hunt_pack_entities hpe
                JOIN entities e ON e.id = hpe.entity_id
                WHERE hpe.hunt_pack_id = ?
                ORDER BY e.type, e.name COLLATE NOCASE
                """,
                (hunt_pack_id,),
            ).fetchall()
        if row is None:
            return None
        return {
            **dict(row),
            "summary": self.store._json_load(row["summary_json"], {}),
            "payload": self.store._json_load(row["payload_json"], {}),
            "entities": [self.store._entity_repo.row_to_entity(entity_row) for entity_row in entity_rows],
        }

    def delete_hunt_pack(self, hunt_pack_id: int) -> bool:
        with self.store._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM hunt_packs WHERE id = ?",
                (hunt_pack_id,),
            )
            return cursor.rowcount > 0
