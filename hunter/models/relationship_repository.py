"""Relationship persistence helpers for the SQLite knowledge store."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from hunter.models.knowledge_store import KnowledgeStore


class RelationshipRepository:
    """Encapsulates CRUD operations for graph relationships."""

    def __init__(self, store: "KnowledgeStore"):
        self.store = store

    def upsert_relationship(
        self,
        *,
        src_entity_id: int,
        dst_entity_id: int,
        rel_type: str,
        weight: float = 1.0,
        confidence: float = 0.5,
        status: str = "confirmed",
        source_name: str = "local",
        source_ref: str = "",
        context: dict | None = None,
        first_seen: str = "",
        last_seen: str = "",
        valid_until: str = "",
    ) -> int:
        with self.store._connect() as conn:
            conn.execute(
                """
                INSERT INTO relationships (
                    src_entity_id, dst_entity_id, rel_type, weight, confidence,
                    status, source_name, source_ref, context_json,
                    first_seen, last_seen, valid_until
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(src_entity_id, dst_entity_id, rel_type, source_name, source_ref)
                DO UPDATE SET
                    weight = excluded.weight,
                    confidence = excluded.confidence,
                    status = excluded.status,
                    context_json = excluded.context_json,
                    first_seen = excluded.first_seen,
                    last_seen = excluded.last_seen,
                    valid_until = excluded.valid_until
                """,
                (
                    src_entity_id,
                    dst_entity_id,
                    rel_type,
                    weight,
                    confidence,
                    status,
                    source_name,
                    source_ref,
                    self.store._json_dump(context or {}),
                    first_seen,
                    last_seen,
                    valid_until,
                ),
            )
            row = conn.execute(
                """
                SELECT id FROM relationships
                WHERE src_entity_id = ? AND dst_entity_id = ? AND rel_type = ?
                  AND source_name = ? AND source_ref = ?
                """,
                (src_entity_id, dst_entity_id, rel_type, source_name, source_ref),
            ).fetchone()
            return int(row["id"])

    def list_relationships(
        self,
        *,
        entity_id: int | None = None,
        rel_type: str | None = None,
        direction: str = "any",
    ) -> list[dict]:
        clauses: list[str] = []
        params: list[Any] = []
        if entity_id is not None:
            if direction == "out":
                clauses.append("r.src_entity_id = ?")
                params.append(entity_id)
            elif direction == "in":
                clauses.append("r.dst_entity_id = ?")
                params.append(entity_id)
            else:
                clauses.append("(r.src_entity_id = ? OR r.dst_entity_id = ?)")
                params.extend([entity_id, entity_id])
        if rel_type is not None:
            clauses.append("r.rel_type = ?")
            params.append(rel_type)

        query = """
            SELECT
                r.*,
                src.type AS src_type,
                src.external_id AS src_external_id,
                src.name AS src_name,
                dst.type AS dst_type,
                dst.external_id AS dst_external_id,
                dst.name AS dst_name
            FROM relationships r
            JOIN entities src ON src.id = r.src_entity_id
            JOIN entities dst ON dst.id = r.dst_entity_id
        """
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY dst.name COLLATE NOCASE, src.name COLLATE NOCASE"

        with self.store._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                **dict(row),
                "context": self.store._json_load(row["context_json"], {}),
            }
            for row in rows
        ]

    def delete_relationships_for_entity(
        self,
        entity_id: int,
        *,
        rel_type: str | None = None,
        source_name: str | None = None,
        direction: str = "out",
    ) -> None:
        clauses: list[str] = []
        params: list[Any] = []
        if direction == "out":
            clauses.append("src_entity_id = ?")
            params.append(entity_id)
        elif direction == "in":
            clauses.append("dst_entity_id = ?")
            params.append(entity_id)
        else:
            clauses.append("(src_entity_id = ? OR dst_entity_id = ?)")
            params.extend([entity_id, entity_id])
        if rel_type is not None:
            clauses.append("rel_type = ?")
            params.append(rel_type)
        if source_name is not None:
            clauses.append("source_name = ?")
            params.append(source_name)
        with self.store._connect() as conn:
            conn.execute(
                f"DELETE FROM relationships WHERE {' AND '.join(clauses)}",
                params,
            )

    def get_related_entities(self, entity_id: int) -> dict[str, list[dict]]:
        relationships = self.list_relationships(entity_id=entity_id)
        buckets: dict[str, list[dict]] = {}
        for rel in relationships:
            if rel["src_entity_id"] == entity_id:
                related_type = rel["dst_type"]
                related = {
                    "relationship": rel["rel_type"],
                    "weight": rel["weight"],
                    "confidence": rel["confidence"],
                    "status": rel["status"],
                    "entity_id": rel["dst_entity_id"],
                    "type": rel["dst_type"],
                    "external_id": rel["dst_external_id"],
                    "name": rel["dst_name"],
                    "context": rel["context"],
                }
            else:
                related_type = rel["src_type"]
                related = {
                    "relationship": rel["rel_type"],
                    "weight": rel["weight"],
                    "confidence": rel["confidence"],
                    "status": rel["status"],
                    "entity_id": rel["src_entity_id"],
                    "type": rel["src_type"],
                    "external_id": rel["src_external_id"],
                    "name": rel["src_name"],
                    "context": rel["context"],
                }
            buckets.setdefault(related_type, []).append(related)
        return buckets
