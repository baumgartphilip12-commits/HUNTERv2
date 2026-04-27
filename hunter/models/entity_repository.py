"""Entity persistence helpers for the SQLite knowledge store."""

from __future__ import annotations

import sqlite3
from typing import Any, TYPE_CHECKING

from hunter.models.common import ENTITY_TYPES, utc_now
from hunter.search_documents import entity_search_document
from hunter.search_query import matches_search_query

if TYPE_CHECKING:
    from hunter.models.knowledge_store import KnowledgeStore


class EntityRepository:
    """Encapsulates CRUD operations for knowledge entities."""

    def __init__(self, store: "KnowledgeStore"):
        self.store = store

    def upsert_entity(
        self,
        *,
        entity_type: str,
        external_id: str,
        name: str,
        short_description: str = "",
        status: str = "active",
        confidence: float = 0.5,
        priority: str = "",
        source_name: str = "local",
        source_ref: str = "",
        source_url: str = "",
        retrieved_at: str = "",
        last_seen: str = "",
        valid_until: str = "",
        tags: list[str] | None = None,
        payload: dict | None = None,
    ) -> int:
        if entity_type not in ENTITY_TYPES:
            raise ValueError(f"Unsupported entity type: {entity_type}")
        now = utc_now()
        with self.store._connect() as conn:
            conn.execute(
                """
                INSERT INTO entities (
                    type, external_id, name, short_description, status,
                    confidence, priority, source_name, source_ref, source_url,
                    retrieved_at, last_seen, valid_until, tags_json, payload_json,
                    created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(type, external_id) DO UPDATE SET
                    name = excluded.name,
                    short_description = excluded.short_description,
                    status = excluded.status,
                    confidence = excluded.confidence,
                    priority = excluded.priority,
                    source_name = excluded.source_name,
                    source_ref = excluded.source_ref,
                    source_url = excluded.source_url,
                    retrieved_at = excluded.retrieved_at,
                    last_seen = excluded.last_seen,
                    valid_until = excluded.valid_until,
                    tags_json = excluded.tags_json,
                    payload_json = excluded.payload_json,
                    updated_at = excluded.updated_at
                """,
                (
                    entity_type,
                    external_id,
                    name,
                    short_description,
                    status,
                    confidence,
                    priority,
                    source_name,
                    source_ref,
                    source_url,
                    retrieved_at,
                    last_seen,
                    valid_until,
                    self.store._json_dump(tags or []),
                    self.store._json_dump(payload or {}),
                    now,
                    now,
                ),
            )
            row = conn.execute(
                """
                SELECT id FROM entities
                WHERE type = ? AND external_id = ?
                """,
                (entity_type, external_id),
            ).fetchone()
            return int(row["id"])

    def get_entity(self, entity_id: int) -> dict | None:
        with self.store._connect() as conn:
            row = conn.execute(
                "SELECT * FROM entities WHERE id = ?",
                (entity_id,),
            ).fetchone()
        if row is None:
            return None
        return self.row_to_entity(row)

    def get_entity_by_external_id(self, entity_type: str, external_id: str) -> dict | None:
        with self.store._connect() as conn:
            row = conn.execute(
                "SELECT * FROM entities WHERE type = ? AND external_id = ?",
                (entity_type, external_id),
            ).fetchone()
        if row is None:
            return None
        return self.row_to_entity(row)

    def list_entities(self, entity_type: str, search: str = "") -> list[dict]:
        search = search.strip()
        query = (
            "SELECT * FROM entities WHERE type = ?"
            " AND payload_json NOT LIKE '%\"removed_from_source\": true%'"
        )
        query += " ORDER BY name COLLATE NOCASE"
        with self.store._connect() as conn:
            rows = conn.execute(query, [entity_type]).fetchall()
        entities = [self.row_to_entity(row) for row in rows]
        if search:
            entities = [
                entity
                for entity in entities
                if matches_search_query(search, entity_search_document(entity))
            ]
        return entities

    def count_entities(self, entity_type: str, search: str = "") -> int:
        return len(self.list_entities(entity_type, search))

    def delete_entity(self, entity_id: int) -> None:
        with self.store._connect() as conn:
            conn.execute("DELETE FROM entities WHERE id = ?", (entity_id,))

    def mark_entity_removed(self, entity_id: int, *, status: str = "deprecated") -> None:
        with self.store._connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM entities WHERE id = ?",
                (entity_id,),
            ).fetchone()
            if row is None:
                return
            payload = self.store._json_load(row["payload_json"], {})
            payload["removed_from_source"] = True
            conn.execute(
                """
                UPDATE entities
                SET status = ?, payload_json = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    status,
                    self.store._json_dump(payload),
                    utc_now(),
                    entity_id,
                ),
            )

    def row_to_entity(self, row: sqlite3.Row) -> dict:
        return {
            **dict(row),
            "tags": self.store._json_load(row["tags_json"], []),
            "payload": self.store._json_load(row["payload_json"], {}),
        }
