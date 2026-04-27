"""SQLite-backed knowledge store for HUNTER v2."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, time
from pathlib import Path
from typing import Any

from hunter.models.common import ENTITY_TYPES, utc_now
from hunter.models.entity_repository import EntityRepository
from hunter.models.hunt_pack_repository import HuntPackRepository
from hunter.models.layered_index_repository import LayeredIndexRepository
from hunter.models.module_store import ensure_layered_module_dirs
from hunter.models.relationship_repository import RelationshipRepository
from hunter.models.source_repository import SourceRepository
from hunter.models.store_bootstrap import KnowledgeRuntimeBootstrap, bootstrap_runtime_store
from hunter.runtime_paths import (
    bootstrap_bundle_path,
    bootstrap_dir,
    infer_layered_ref,
    layered_module_path,
    layered_source_config,
    offline_mode,
    project_root,
)


class KnowledgeStore:
    """Persistence layer for the layered hunting knowledge graph."""

    def __init__(self, project_dir: str, *, bootstrap: bool = False):
        self.project_dir = project_root(project_dir)
        self.data_dir = self.project_dir / "data"
        self.snapshot_dir = self.data_dir / "snapshots"
        self.export_dir = self.data_dir / "exports"
        self.import_dir = self.data_dir / "imports"
        self.data_dir.mkdir(exist_ok=True)
        bootstrap_dir(self.project_dir).mkdir(parents=True, exist_ok=True)
        self.snapshot_dir.mkdir(exist_ok=True)
        self.export_dir.mkdir(exist_ok=True)
        self.import_dir.mkdir(exist_ok=True)
        ensure_layered_module_dirs(self.project_dir)
        self.db_path = self.data_dir / "hunter_v2.sqlite3"
        self._source_repo = SourceRepository(self)
        self._entity_repo = EntityRepository(self)
        self._relationship_repo = RelationshipRepository(self)
        self._hunt_pack_repo = HuntPackRepository(self)
        self._layered_index_repo = LayeredIndexRepository(self)
        self._initialize()
        if bootstrap:
            self.bootstrap_runtime()

    @classmethod
    def open_bootstrapped(cls, project_dir: str) -> "KnowledgeStore":
        return cls(project_dir, bootstrap=True)

    @classmethod
    def open_unbootstrapped(cls, project_dir: str) -> "KnowledgeStore":
        return cls(project_dir, bootstrap=False)

    def bootstrap_runtime(self) -> None:
        bootstrap_runtime_store(self)

    def import_seed_bundle_if_empty(self) -> bool:
        """Import the offline seed bundle on first startup when no runtime DB exists."""

        if self.get_stats().get("entities", 0) or self.list_hunt_packs():
            return False
        seed_path = bootstrap_bundle_path(self.project_dir)
        if not seed_path.exists():
            return False
        self.import_knowledge_bundle(str(seed_path))
        return True

    def close(self) -> None:
        """Compatibility no-op for callers that expect explicit cleanup."""
        return None

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @classmethod
    def json_safe(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                str(key): cls.json_safe(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls.json_safe(item) for item in value]
        if isinstance(value, tuple):
            return [cls.json_safe(item) for item in value]
        if isinstance(value, set):
            normalized = [cls.json_safe(item) for item in value]
            return sorted(
                normalized,
                key=lambda item: json.dumps(item, sort_keys=True),
            )
        if isinstance(value, (datetime, date, time)):
            return value.isoformat()
        if isinstance(value, Path):
            return str(value)
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        return str(value)

    @classmethod
    def _json_dump(cls, value: Any) -> str:
        return json.dumps(
            cls.json_safe({} if value is None else value),
            indent=2,
            sort_keys=True,
        )

    @staticmethod
    def _json_load(value: str | None, default: Any) -> Any:
        if not value:
            return default
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS entities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    external_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    short_description TEXT DEFAULT '',
                    status TEXT DEFAULT 'active',
                    confidence REAL DEFAULT 0.5,
                    priority TEXT DEFAULT '',
                    source_name TEXT DEFAULT 'local',
                    source_ref TEXT DEFAULT '',
                    source_url TEXT DEFAULT '',
                    retrieved_at TEXT DEFAULT '',
                    last_seen TEXT DEFAULT '',
                    valid_until TEXT DEFAULT '',
                    tags_json TEXT DEFAULT '[]',
                    payload_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(type, external_id)
                );

                CREATE TABLE IF NOT EXISTS relationships (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_entity_id INTEGER NOT NULL,
                    dst_entity_id INTEGER NOT NULL,
                    rel_type TEXT NOT NULL,
                    weight REAL DEFAULT 1.0,
                    confidence REAL DEFAULT 0.5,
                    status TEXT DEFAULT 'confirmed',
                    source_name TEXT DEFAULT 'local',
                    source_ref TEXT DEFAULT '',
                    context_json TEXT DEFAULT '{}',
                    first_seen TEXT DEFAULT '',
                    last_seen TEXT DEFAULT '',
                    valid_until TEXT DEFAULT '',
                    UNIQUE(src_entity_id, dst_entity_id, rel_type, source_name, source_ref),
                    FOREIGN KEY(src_entity_id) REFERENCES entities(id) ON DELETE CASCADE,
                    FOREIGN KEY(dst_entity_id) REFERENCES entities(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS sync_sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    connector TEXT NOT NULL,
                    config_json TEXT DEFAULT '{}',
                    enabled INTEGER DEFAULT 1,
                    approved INTEGER DEFAULT 1,
                    health TEXT DEFAULT 'unknown',
                    last_sync_at TEXT DEFAULT '',
                    last_status TEXT DEFAULT 'never',
                    last_error TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS sync_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id INTEGER NOT NULL,
                    connector TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT DEFAULT '',
                    mode TEXT DEFAULT 'preview',
                    status TEXT DEFAULT 'running',
                    summary_json TEXT DEFAULT '{}',
                    diff_json TEXT DEFAULT '{}',
                    snapshot_path TEXT DEFAULT '',
                    rollback_snapshot_path TEXT DEFAULT '',
                    error TEXT DEFAULT '',
                    FOREIGN KEY(source_id) REFERENCES sync_sources(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS layered_module_index (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id INTEGER NOT NULL,
                    layer TEXT NOT NULL,
                    relative_path TEXT NOT NULL,
                    absolute_path TEXT DEFAULT '',
                    entity_type TEXT DEFAULT '',
                    external_id TEXT DEFAULT '',
                    mtime_ns INTEGER DEFAULT 0,
                    size_bytes INTEGER DEFAULT 0,
                    content_hash TEXT DEFAULT '',
                    status TEXT DEFAULT 'indexed',
                    warning_text TEXT DEFAULT '',
                    last_seen_at TEXT DEFAULT '',
                    last_indexed_at TEXT DEFAULT '',
                    UNIQUE(source_id, relative_path),
                    FOREIGN KEY(source_id) REFERENCES sync_sources(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS hunt_packs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    status TEXT DEFAULT 'draft',
                    summary_json TEXT DEFAULT '{}',
                    payload_json TEXT DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS hunt_pack_entities (
                    hunt_pack_id INTEGER NOT NULL,
                    entity_id INTEGER NOT NULL,
                    role TEXT DEFAULT 'selected',
                    PRIMARY KEY(hunt_pack_id, entity_id, role),
                    FOREIGN KEY(hunt_pack_id) REFERENCES hunt_packs(id) ON DELETE CASCADE,
                    FOREIGN KEY(entity_id) REFERENCES entities(id) ON DELETE CASCADE
                );
                """
            )

    def seed_default_sources(self) -> None:
        defaults = [
            {
                "name": "MITRE ATT&CK Enterprise",
                "connector": "mitre_attack",
                "config": {
                    "bundle_url": (
                        "https://raw.githubusercontent.com/mitre-attack/"
                        "attack-stix-data/master/enterprise-attack/enterprise-attack.json"
                    ),
                },
            },
            {
                "name": "Layered Local Modules",
                "connector": "layered_modules",
                "config": layered_source_config(self.project_dir),
            },
            {
                "name": "SigmaHQ Rules",
                "connector": "sigmahq_rules",
                "config": {
                    "repo_url": "https://github.com/SigmaHQ/sigma",
                    "archive_url": "https://codeload.github.com/SigmaHQ/sigma/zip/refs/heads/master",
                    "raw_base_url": "https://raw.githubusercontent.com/SigmaHQ/sigma/master",
                },
            },
        ]
        with self._connect() as conn:
            for source in defaults:
                conn.execute(
                    """
                    INSERT INTO sync_sources (name, connector, config_json)
                    VALUES (?, ?, ?)
                    ON CONFLICT(name) DO UPDATE SET
                        connector = excluded.connector,
                        config_json = CASE
                            WHEN sync_sources.last_status = 'never'
                            THEN excluded.config_json
                            ELSE sync_sources.config_json
                        END
                    """,
                    (
                        source["name"],
                        source["connector"],
                        self._json_dump(source["config"]),
                    ),
                )

    def enforce_authored_catalog_mode(self) -> None:
        """Keep only the authored threat/tool catalog sources active in the runtime store."""
        retired_sources = (
            "Local Vendor Intel Feed",
            "Local IOC Feed",
        )
        for source_name in retired_sources:
            self.delete_source(source_name)

        self.purge_source_entity_types(
            "MITRE ATT&CK Enterprise",
            ["ThreatProfile", "ToolPack", "IndicatorSet"],
        )

        mitre_source = self.get_source_by_name("MITRE ATT&CK Enterprise")
        if mitre_source is not None:
            if offline_mode():
                self.update_source(
                    mitre_source["id"],
                    connector="mitre_attack",
                    enabled=bool(
                        mitre_source.get("config", {}).get("bundle_file")
                        or mitre_source.get("config", {}).get("bundle_path")
                    ),
                    approved=True,
                )
            else:
                self.update_source(
                    mitre_source["id"],
                    connector="mitre_attack",
                    config={
                        "bundle_url": (
                            "https://raw.githubusercontent.com/mitre-attack/"
                            "attack-stix-data/master/enterprise-attack/enterprise-attack.json"
                        ),
                    },
                    enabled=True,
                    approved=True,
                )

        layered_source = self.get_source_by_name("Layered Local Modules")
        if layered_source is not None:
            self.update_source(
                layered_source["id"],
                connector="layered_modules",
                config=layered_source_config(self.project_dir),
                enabled=True,
                approved=True,
            )

        sigma_source = self.get_source_by_name("SigmaHQ Rules")
        if sigma_source is not None:
            update: dict[str, Any] = {"connector": "sigmahq_rules"}
            if not sigma_source.get("config"):
                update["config"] = {
                    "repo_url": "https://github.com/SigmaHQ/sigma",
                    "archive_url": "https://codeload.github.com/SigmaHQ/sigma/zip/refs/heads/master",
                    "raw_base_url": "https://raw.githubusercontent.com/SigmaHQ/sigma/master",
                }
            if offline_mode() and not any(
                sigma_source.get("config", {}).get(key)
                for key in ("archive_path", "rules_dir", "rules_file")
            ):
                update["enabled"] = False
            self.update_source(sigma_source["id"], **update)

    def reconcile_portable_runtime_paths(self) -> None:
        """Reconcile layered local records against the current project root.

        Older databases stored absolute local paths directly in source config,
        entities, and the layered index.  When the repository moves to a new
        machine or folder those paths become stale.  The layered source now uses
        repo-relative refs as the durable identity, so startup reconciles any
        legacy absolute paths back to the current project root.
        """

        layered_source = self.get_source_by_name("Layered Local Modules")
        if layered_source is None:
            return

        portable_config = layered_source_config(self.project_dir)
        current_config = dict(layered_source.get("config", {}))
        if any(current_config.get(key) != value for key, value in portable_config.items()):
            current_config.update(portable_config)
            self.update_source(layered_source["id"], config=current_config)

        self._reconcile_layered_entities()
        self._reconcile_layered_relationships()
        self._reconcile_layered_index_rows(layered_source["id"])

    def _reconcile_layered_entities(self) -> None:
        """Convert local layered entities to portable ``source_ref`` values."""

        now = utc_now()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, type, external_id, source_ref, source_url
                FROM entities
                WHERE source_name = 'Layered Local Modules'
                """
            ).fetchall()
            for row in rows:
                portable_ref = infer_layered_ref(
                    entity_type=row["type"],
                    external_id=row["external_id"],
                    source_ref=row["source_ref"],
                    source_url=row["source_url"],
                    project_dir=self.project_dir,
                )
                if not portable_ref:
                    continue
                if portable_ref != row["source_ref"] or row["source_url"]:
                    conn.execute(
                        """
                        UPDATE entities
                        SET source_ref = ?, source_url = '', updated_at = ?
                        WHERE id = ?
                        """,
                        (portable_ref, now, row["id"]),
                    )

    def _reconcile_layered_relationships(self) -> None:
        """Normalize layered relationship refs to match portable module refs."""

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, source_ref
                FROM relationships
                WHERE source_name = 'Layered Local Modules'
                """
            ).fetchall()
            for row in rows:
                portable_ref = infer_layered_ref(
                    source_ref=row["source_ref"],
                    project_dir=self.project_dir,
                )
                if portable_ref and portable_ref != row["source_ref"]:
                    conn.execute(
                        "UPDATE relationships SET source_ref = ? WHERE id = ?",
                        (portable_ref, row["id"]),
                    )

    def _reconcile_layered_index_rows(self, source_id: int) -> None:
        """Refresh index rows so relative refs stay authoritative."""

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, layer, relative_path, absolute_path, external_id
                FROM layered_module_index
                WHERE source_id = ?
                """,
                (source_id,),
            ).fetchall()
            for row in rows:
                portable_ref = infer_layered_ref(
                    layer=row["layer"],
                    external_id=row["external_id"],
                    source_ref=row["relative_path"],
                    source_url=row["absolute_path"],
                    project_dir=self.project_dir,
                )
                if not portable_ref:
                    continue
                absolute_path = str(layered_module_path(portable_ref, self.project_dir))
                if portable_ref != row["relative_path"] or absolute_path != (row["absolute_path"] or ""):
                    conn.execute(
                        """
                        UPDATE layered_module_index
                        SET relative_path = ?, absolute_path = ?
                        WHERE id = ?
                        """,
                        (portable_ref, absolute_path, row["id"]),
                    )

    def list_sources(self) -> list[dict]:
        return self._source_repo.list_sources()

    def get_source(self, source_id: int) -> dict | None:
        return self._source_repo.get_source(source_id)

    def get_source_by_name(self, source_name: str) -> dict | None:
        return self._source_repo.get_source_by_name(source_name)

    def create_source(
        self,
        *,
        name: str,
        connector: str,
        config: dict | None = None,
        enabled: bool = True,
        approved: bool = True,
    ) -> int:
        return self._source_repo.create_source(
            name=name,
            connector=connector,
            config=config or {},
            enabled=enabled,
            approved=approved,
        )

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
        self._source_repo.update_source(
            source_id,
            name=name,
            connector=connector,
            config=config,
            enabled=enabled,
            approved=approved,
            health=health,
            last_sync_at=last_sync_at,
            last_status=last_status,
            last_error=last_error,
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
        return self._source_repo.create_sync_event(
            source_id,
            connector,
            mode,
            summary=summary,
            diff=diff,
            snapshot_path=snapshot_path,
            rollback_snapshot_path=rollback_snapshot_path,
            status=status,
            error=error,
        )

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
        self._source_repo.finish_sync_event(
            event_id,
            status=status,
            summary=summary,
            diff=diff,
            snapshot_path=snapshot_path,
            rollback_snapshot_path=rollback_snapshot_path,
            error=error,
        )

    def list_sync_events(self, source_id: int | None = None) -> list[dict]:
        return self._source_repo.list_sync_events(source_id)

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
        return self._entity_repo.upsert_entity(
            entity_type=entity_type,
            external_id=external_id,
            name=name,
            short_description=short_description,
            status=status,
            confidence=confidence,
            priority=priority,
            source_name=source_name,
            source_ref=source_ref,
            source_url=source_url,
            retrieved_at=retrieved_at,
            last_seen=last_seen,
            valid_until=valid_until,
            tags=tags,
            payload=payload,
        )

    def get_entity(self, entity_id: int) -> dict | None:
        return self._entity_repo.get_entity(entity_id)

    def get_entity_by_external_id(
        self, entity_type: str, external_id: str
    ) -> dict | None:
        return self._entity_repo.get_entity_by_external_id(entity_type, external_id)

    def list_entities(self, entity_type: str, search: str = "") -> list[dict]:
        return self._entity_repo.list_entities(entity_type, search)

    def count_entities(self, entity_type: str, search: str = "") -> int:
        return self._entity_repo.count_entities(entity_type, search)

    def delete_entity(self, entity_id: int) -> None:
        self._entity_repo.delete_entity(entity_id)

    def mark_entity_removed(self, entity_id: int, *, status: str = "deprecated") -> None:
        self._entity_repo.mark_entity_removed(entity_id, status=status)

    def _row_to_entity(self, row: sqlite3.Row) -> dict:
        return self._entity_repo.row_to_entity(row)

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
        return self._relationship_repo.upsert_relationship(
            src_entity_id=src_entity_id,
            dst_entity_id=dst_entity_id,
            rel_type=rel_type,
            weight=weight,
            confidence=confidence,
            status=status,
            source_name=source_name,
            source_ref=source_ref,
            context=context,
            first_seen=first_seen,
            last_seen=last_seen,
            valid_until=valid_until,
        )

    def list_relationships(
        self,
        *,
        entity_id: int | None = None,
        rel_type: str | None = None,
        direction: str = "any",
    ) -> list[dict]:
        return self._relationship_repo.list_relationships(
            entity_id=entity_id,
            rel_type=rel_type,
            direction=direction,
        )

    def delete_relationships_for_entity(
        self,
        entity_id: int,
        *,
        rel_type: str | None = None,
        source_name: str | None = None,
        direction: str = "out",
    ) -> None:
        self._relationship_repo.delete_relationships_for_entity(
            entity_id,
            rel_type=rel_type,
            source_name=source_name,
            direction=direction,
        )

    def get_related_entities(self, entity_id: int) -> dict[str, list[dict]]:
        return self._relationship_repo.get_related_entities(entity_id)

    def get_stats(self) -> dict[str, int]:
        stats = {entity_type: 0 for entity_type in ENTITY_TYPES}
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT type, COUNT(*) AS count
                FROM entities
                WHERE payload_json NOT LIKE '%"removed_from_source": true%'
                GROUP BY type
                """
            ).fetchall()
            relationship_count = conn.execute(
                "SELECT COUNT(*) AS count FROM relationships"
            ).fetchone()["count"]
            hunt_pack_count = conn.execute(
                "SELECT COUNT(*) AS count FROM hunt_packs"
            ).fetchone()["count"]
        for row in rows:
            stats[row["type"]] = row["count"]
        stats["relationships"] = relationship_count
        stats["hunt_packs"] = hunt_pack_count
        return stats

    def get_source_snapshot(self, source_name: str) -> dict:
        source = self.get_source_by_name(source_name)
        with self._connect() as conn:
            entity_rows = conn.execute(
                """
                SELECT * FROM entities
                WHERE source_name = ?
                ORDER BY type, external_id
                """,
                (source_name,),
            ).fetchall()
            rel_rows = conn.execute(
                """
                SELECT r.*, src.type AS src_type, src.external_id AS src_external_id,
                       dst.type AS dst_type, dst.external_id AS dst_external_id
                FROM relationships r
                JOIN entities src ON src.id = r.src_entity_id
                JOIN entities dst ON dst.id = r.dst_entity_id
                WHERE r.source_name = ?
                ORDER BY r.rel_type
                """,
                (source_name,),
            ).fetchall()
            index_rows = []
            if source is not None and source["connector"] == "layered_modules":
                index_rows = conn.execute(
                    """
                    SELECT *
                    FROM layered_module_index
                    WHERE source_id = ?
                    ORDER BY layer, relative_path
                    """,
                    (source["id"],),
                ).fetchall()
        return {
            "source_name": source_name,
            "captured_at": utc_now(),
            "entities": [
                {
                    **self._row_to_entity(row),
                    "tags_json": None,
                    "payload_json": None,
                }
                for row in entity_rows
            ],
            "relationships": [
                {
                    **dict(row),
                    "context": self._json_load(row["context_json"], {}),
                }
                for row in rel_rows
            ],
            "layered_module_index": [dict(row) for row in index_rows],
        }

    def write_snapshot(self, source_name: str, snapshot: dict, suffix: str) -> str:
        safe_name = source_name.lower().replace(" ", "_").replace("/", "_")
        path = self.snapshot_dir / f"{safe_name}_{suffix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path.write_text(
            json.dumps(self.json_safe(snapshot), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return str(path)

    def restore_source_snapshot(self, source_name: str, snapshot: dict) -> dict:
        source = self.get_source_by_name(source_name)
        restored_entities = 0
        restored_relationships = 0
        entity_ids: dict[tuple[str, str], int] = {}
        incoming_keys = {
            (entity["type"], entity["external_id"])
            for entity in snapshot.get("entities", [])
        }

        with self._connect() as conn:
            stale_rows = conn.execute(
                """
                SELECT id, payload_json
                FROM entities
                WHERE source_name = ?
                """,
                (source_name,),
            ).fetchall()
            conn.execute(
                "DELETE FROM relationships WHERE source_name = ?",
                (source_name,),
            )
            for row in stale_rows:
                entity = conn.execute(
                    "SELECT type, external_id FROM entities WHERE id = ?",
                    (row["id"],),
                ).fetchone()
                if entity is None:
                    continue
                key = (entity["type"], entity["external_id"])
                if key in incoming_keys:
                    continue
                payload = self._json_load(row["payload_json"], {})
                payload["removed_from_source"] = True
                conn.execute(
                    """
                    UPDATE entities
                    SET status = ?, payload_json = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        "deprecated",
                        self._json_dump(payload),
                        utc_now(),
                        row["id"],
                    ),
                )

        for entity in snapshot.get("entities", []):
            payload = dict(entity.get("payload", {}))
            payload.pop("removed_from_source", None)
            entity_id = self.upsert_entity(
                entity_type=entity["type"],
                external_id=entity["external_id"],
                name=entity["name"],
                short_description=entity.get("short_description", ""),
                status=entity.get("status", "active"),
                confidence=entity.get("confidence", 0.5),
                priority=entity.get("priority", ""),
                source_name=entity.get("source_name", source_name),
                source_ref=entity.get("source_ref", ""),
                source_url=entity.get("source_url", ""),
                retrieved_at=entity.get("retrieved_at", ""),
                last_seen=entity.get("last_seen", ""),
                valid_until=entity.get("valid_until", ""),
                tags=entity.get("tags", []),
                payload=payload,
            )
            entity_ids[(entity["type"], entity["external_id"])] = entity_id
            restored_entities += 1

        for rel in snapshot.get("relationships", []):
            src_key = (rel["src_type"], rel["src_external_id"])
            dst_key = (rel["dst_type"], rel["dst_external_id"])
            src_id = entity_ids.get(src_key) or self.get_entity_by_external_id(*src_key)
            dst_id = entity_ids.get(dst_key) or self.get_entity_by_external_id(*dst_key)
            if isinstance(src_id, dict):
                src_id = src_id["id"]
            if isinstance(dst_id, dict):
                dst_id = dst_id["id"]
            if src_id is None or dst_id is None:
                continue
            self.upsert_relationship(
                src_entity_id=int(src_id),
                dst_entity_id=int(dst_id),
                rel_type=rel["rel_type"],
                weight=rel.get("weight", 1.0),
                confidence=rel.get("confidence", 0.5),
                status=rel.get("status", "confirmed"),
                source_name=rel.get("source_name", source_name),
                source_ref=rel.get("source_ref", ""),
                context=rel.get("context", {}),
                first_seen=rel.get("first_seen", ""),
                last_seen=rel.get("last_seen", ""),
                valid_until=rel.get("valid_until", ""),
            )
            restored_relationships += 1

        if source is not None and source["connector"] == "layered_modules":
            self.replace_layered_module_index(
                source["id"],
                snapshot.get("layered_module_index", []),
            )

        return {
            "restored_entities": restored_entities,
            "restored_relationships": restored_relationships,
        }

    def delete_source_owned_data(self, source_name: str) -> None:
        source = self.get_source_by_name(source_name)
        with self._connect() as conn:
            conn.execute("DELETE FROM relationships WHERE source_name = ?", (source_name,))
            conn.execute("DELETE FROM entities WHERE source_name = ?", (source_name,))
            if source is not None:
                conn.execute("DELETE FROM layered_module_index WHERE source_id = ?", (source["id"],))

    def delete_source(self, source_name: str) -> None:
        source = self.get_source_by_name(source_name)
        self.delete_source_owned_data(source_name)
        if source is None:
            return
        with self._connect() as conn:
            conn.execute("DELETE FROM sync_sources WHERE id = ?", (source["id"],))

    def purge_source_entity_types(self, source_name: str, entity_types: list[str]) -> None:
        if not entity_types:
            return
        placeholders = ", ".join("?" for _ in entity_types)
        with self._connect() as conn:
            conn.execute(
                f"""
                DELETE FROM entities
                WHERE source_name = ? AND type IN ({placeholders})
                """,
                [source_name, *entity_types],
            )

    def list_layered_module_index(self, source_id: int) -> list[dict]:
        return self._layered_index_repo.list_layered_module_index(source_id)

    def get_layered_module_index_map(self, source_id: int) -> dict[str, dict]:
        return self._layered_index_repo.get_layered_module_index_map(source_id)

    def replace_layered_module_index(self, source_id: int, rows: list[dict]) -> None:
        self._layered_index_repo.replace_layered_module_index(source_id, rows)

    def upsert_layered_module_index_row(self, source_id: int, row: dict) -> None:
        self._layered_index_repo.upsert_layered_module_index_row(source_id, row)

    def delete_layered_module_index_row(self, source_id: int, relative_path: str) -> None:
        self._layered_index_repo.delete_layered_module_index_row(source_id, relative_path)

    def get_layered_module_index_stats(self, source_id: int) -> dict:
        return self._layered_index_repo.get_layered_module_index_stats(source_id)

    def get_source_entities_by_refs(self, source_name: str, source_refs: list[str]) -> list[dict]:
        return self._layered_index_repo.get_source_entities_by_refs(source_name, source_refs)

    def get_source_relationships_by_refs(self, source_name: str, source_refs: list[str]) -> list[dict]:
        return self._layered_index_repo.get_source_relationships_by_refs(source_name, source_refs)

    def export_knowledge_bundle(self, path: str) -> dict:
        bundle = {
            "metadata": {
                "generated_at": utc_now(),
                "project": "HUNTER v2",
                "stats": self.get_stats(),
            },
            "sources": self.list_sources(),
            "entities": [
                entity
                for entity_type in ENTITY_TYPES
                for entity in self.list_entities(entity_type)
            ],
            "relationships": self.list_relationships(),
            "hunt_packs": [
                self.get_hunt_pack(hunt_pack["id"])
                for hunt_pack in self.list_hunt_packs()
            ],
        }
        Path(path).write_text(
            json.dumps(self.json_safe(bundle), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return bundle["metadata"]["stats"]

    def import_knowledge_bundle(self, path: str) -> dict:
        bundle = json.loads(Path(path).read_text(encoding="utf-8"))
        imported_entities = 0
        imported_relationships = 0
        imported_hunt_packs = 0
        id_map: dict[tuple[str, str], int] = {}

        for source in bundle.get("sources", []):
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO sync_sources (name, connector, config_json, enabled, approved, health)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(name) DO UPDATE SET
                        connector = excluded.connector,
                        config_json = excluded.config_json,
                        enabled = excluded.enabled,
                        approved = excluded.approved,
                        health = excluded.health
                    """,
                    (
                        source["name"],
                        source["connector"],
                        self._json_dump(source.get("config", {})),
                        int(source.get("enabled", True)),
                        int(source.get("approved", True)),
                        source.get("health", "unknown"),
                    ),
                )

        for entity in bundle.get("entities", []):
            entity_id = self.upsert_entity(
                entity_type=entity["type"],
                external_id=entity["external_id"],
                name=entity["name"],
                short_description=entity.get("short_description", ""),
                status=entity.get("status", "active"),
                confidence=entity.get("confidence", 0.5),
                priority=entity.get("priority", ""),
                source_name=entity.get("source_name", "bundle_import"),
                source_ref=entity.get("source_ref", ""),
                source_url=entity.get("source_url", ""),
                retrieved_at=entity.get("retrieved_at", ""),
                last_seen=entity.get("last_seen", ""),
                valid_until=entity.get("valid_until", ""),
                tags=entity.get("tags", []),
                payload=entity.get("payload", {}),
            )
            id_map[(entity["type"], entity["external_id"])] = entity_id
            imported_entities += 1

        for rel in bundle.get("relationships", []):
            src_id = id_map.get((rel["src_type"], rel["src_external_id"]))
            dst_id = id_map.get((rel["dst_type"], rel["dst_external_id"]))
            if src_id is None or dst_id is None:
                continue
            self.upsert_relationship(
                src_entity_id=src_id,
                dst_entity_id=dst_id,
                rel_type=rel["rel_type"],
                weight=rel.get("weight", 1.0),
                confidence=rel.get("confidence", 0.5),
                status=rel.get("status", "confirmed"),
                source_name=rel.get("source_name", "bundle_import"),
                source_ref=rel.get("source_ref", ""),
                context=rel.get("context", {}),
                first_seen=rel.get("first_seen", ""),
                last_seen=rel.get("last_seen", ""),
                valid_until=rel.get("valid_until", ""),
            )
            imported_relationships += 1

        for hunt_pack in bundle.get("hunt_packs", []):
            entity_ids: list[int] = []
            for entity in hunt_pack.get("entities", []):
                entity_id = id_map.get((entity["type"], entity["external_id"]))
                if entity_id is not None:
                    entity_ids.append(entity_id)
            self.save_hunt_pack(
                name=hunt_pack.get("name", "Imported Hunt Pack"),
                status=hunt_pack.get("status", "draft"),
                summary=hunt_pack.get("summary", {}),
                payload=hunt_pack.get("payload", {}),
                entity_ids=entity_ids,
                created_at=hunt_pack.get("created_at"),
                updated_at=hunt_pack.get("updated_at"),
            )
            imported_hunt_packs += 1

        return {
            "imported_entities": imported_entities,
            "imported_relationships": imported_relationships,
            "imported_hunt_packs": imported_hunt_packs,
        }

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
        return self._hunt_pack_repo.save_hunt_pack(
            name=name,
            status=status,
            summary=summary,
            payload=payload,
            entity_ids=entity_ids,
            created_at=created_at,
            updated_at=updated_at,
        )

    def update_hunt_pack(
        self,
        hunt_pack_id: int,
        *,
        name: str | None = None,
        status: str | None = None,
        summary: dict | None = None,
        payload: dict | None = None,
    ) -> None:
        self._hunt_pack_repo.update_hunt_pack(
            hunt_pack_id,
            name=name,
            status=status,
            summary=summary,
            payload=payload,
        )

    def list_hunt_packs(self) -> list[dict]:
        return self._hunt_pack_repo.list_hunt_packs()

    def get_hunt_pack(self, hunt_pack_id: int) -> dict | None:
        return self._hunt_pack_repo.get_hunt_pack(hunt_pack_id)

    def delete_hunt_pack(self, hunt_pack_id: int) -> bool:
        return self._hunt_pack_repo.delete_hunt_pack(hunt_pack_id)
