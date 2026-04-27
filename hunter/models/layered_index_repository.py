"""Layered module index helpers for incremental local-content sync."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hunter.models.knowledge_store import KnowledgeStore


class LayeredIndexRepository:
    """Encapsulates layered-module index reads and writes."""

    def __init__(self, store: "KnowledgeStore"):
        self.store = store

    def list_layered_module_index(self, source_id: int) -> list[dict]:
        with self.store._connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM layered_module_index
                WHERE source_id = ?
                ORDER BY layer, relative_path
                """,
                (source_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_layered_module_index_map(self, source_id: int) -> dict[str, dict]:
        return {
            row["relative_path"]: row
            for row in self.list_layered_module_index(source_id)
        }

    def replace_layered_module_index(self, source_id: int, rows: list[dict]) -> None:
        with self.store._connect() as conn:
            conn.execute("DELETE FROM layered_module_index WHERE source_id = ?", (source_id,))
            for row in rows:
                self._upsert_index_row(conn, source_id, row)

    def upsert_layered_module_index_row(self, source_id: int, row: dict) -> None:
        with self.store._connect() as conn:
            self._upsert_index_row(conn, source_id, row)

    def delete_layered_module_index_row(self, source_id: int, relative_path: str) -> None:
        with self.store._connect() as conn:
            conn.execute(
                """
                DELETE FROM layered_module_index
                WHERE source_id = ? AND relative_path = ?
                """,
                (source_id, relative_path),
            )

    def get_layered_module_index_stats(self, source_id: int) -> dict:
        rows = self.list_layered_module_index(source_id)
        layer_counts: dict[str, int] = {"threats": 0, "tools": 0, "mitre": 0}
        layer_active_counts: dict[str, int] = {"threats": 0, "tools": 0, "mitre": 0}
        warning_count = 0
        deleted_count = 0
        last_indexed_at = ""
        for row in rows:
            layer = row.get("layer", "")
            if layer in layer_counts:
                layer_counts[layer] += 1
                if row.get("status") != "deleted":
                    layer_active_counts[layer] += 1
            if row.get("status") == "warning":
                warning_count += 1
            if row.get("status") == "deleted":
                deleted_count += 1
            last_indexed_at = max(last_indexed_at, row.get("last_indexed_at", ""))
        return {
            "row_count": len(rows),
            "active_count": sum(layer_active_counts.values()),
            "deleted_count": deleted_count,
            "warning_count": warning_count,
            "layer_counts": layer_counts,
            "layer_active_counts": layer_active_counts,
            "last_indexed_at": last_indexed_at,
        }

    def get_source_entities_by_refs(self, source_name: str, source_refs: list[str]) -> list[dict]:
        if not source_refs:
            return []
        placeholders = ", ".join("?" for _ in source_refs)
        with self.store._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT *
                FROM entities
                WHERE source_name = ? AND source_ref IN ({placeholders})
                ORDER BY type, external_id
                """,
                [source_name, *source_refs],
            ).fetchall()
        return [self.store._entity_repo.row_to_entity(row) for row in rows]

    def get_source_relationships_by_refs(self, source_name: str, source_refs: list[str]) -> list[dict]:
        if not source_refs:
            return []
        placeholders = ", ".join("?" for _ in source_refs)
        with self.store._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    r.*,
                    src.type AS src_type,
                    src.external_id AS src_external_id,
                    dst.type AS dst_type,
                    dst.external_id AS dst_external_id
                FROM relationships r
                JOIN entities src ON src.id = r.src_entity_id
                JOIN entities dst ON dst.id = r.dst_entity_id
                WHERE r.source_name = ? AND r.source_ref IN ({placeholders})
                ORDER BY r.rel_type
                """,
                [source_name, *source_refs],
            ).fetchall()
        return [
            {
                **dict(row),
                "context": self.store._json_load(row["context_json"], {}),
            }
            for row in rows
        ]

    def _upsert_index_row(self, conn, source_id: int, row: dict) -> None:
        conn.execute(
            """
            INSERT INTO layered_module_index (
                source_id, layer, relative_path, absolute_path, entity_type,
                external_id, mtime_ns, size_bytes, content_hash, status,
                warning_text, last_seen_at, last_indexed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_id, relative_path) DO UPDATE SET
                layer = excluded.layer,
                absolute_path = excluded.absolute_path,
                entity_type = excluded.entity_type,
                external_id = excluded.external_id,
                mtime_ns = excluded.mtime_ns,
                size_bytes = excluded.size_bytes,
                content_hash = excluded.content_hash,
                status = excluded.status,
                warning_text = excluded.warning_text,
                last_seen_at = excluded.last_seen_at,
                last_indexed_at = excluded.last_indexed_at
            """,
            (
                source_id,
                row.get("layer", ""),
                row.get("relative_path", ""),
                row.get("absolute_path", ""),
                row.get("entity_type", ""),
                row.get("external_id", ""),
                int(row.get("mtime_ns", 0) or 0),
                int(row.get("size_bytes", 0) or 0),
                row.get("content_hash", ""),
                row.get("status", "indexed"),
                row.get("warning_text", ""),
                row.get("last_seen_at", ""),
                row.get("last_indexed_at", ""),
            ),
        )
