"""Sync orchestration, diffing, and rollback services for HUNTER v2."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hunter.models.knowledge_store import KnowledgeStore, utc_now
from hunter.services.connectors import (
    BaseConnector,
    JsonFeedConnector,
    LayeredModuleConnector,
    MitreAttackConnector,
    SigmaHQRulesConnector,
    SyncResult,
)


class SyncService:
    """Coordinates connectors, previews, applies, and rollback."""

    def __init__(self, store: KnowledgeStore):
        self.store = store
        self.connectors: dict[str, BaseConnector] = {
            MitreAttackConnector.name: MitreAttackConnector(),
            JsonFeedConnector.name: JsonFeedConnector(store),
            SigmaHQRulesConnector.name: SigmaHQRulesConnector(store),
            LayeredModuleConnector.name: LayeredModuleConnector(store),
        }

    def preview_source(self, source_id: int) -> SyncResult:
        source = self.store.get_source(source_id)
        if source is None:
            raise ValueError("Unknown source")
        self._ensure_source_allowed(source, require_approval=True)
        connector = self._get_connector(source["connector"])
        dataset = connector.build_dataset(source)
        current = self.store.get_source_snapshot(source["name"])
        diff = self._diff_dataset(current, dataset)
        summary = {
            "entity_count": len(dataset.get("entities", [])),
            "relationship_count": len(dataset.get("relationships", [])),
            "new_entities": diff["new_entities"],
            "updated_entities": diff["updated_entities"],
            "new_relationships": diff["new_relationships"],
            "updated_relationships": diff["updated_relationships"],
            "warning_count": len(dataset.get("metadata", {}).get("warnings", [])),
        }
        sync_stats = dataset.get("metadata", {}).get("sync_stats", {})
        if sync_stats:
            summary.update(sync_stats)
        event_id = self.store.create_sync_event(
            source_id=source_id,
            connector=connector.name,
            mode="preview",
            summary=summary,
            diff=diff,
            status="completed",
        )
        return SyncResult(
            source_id=source_id,
            source_name=source["name"],
            connector=connector.name,
            summary=summary,
            diff=diff,
            dataset=dataset,
            event_id=event_id,
        )

    def apply_source(self, source_id: int) -> SyncResult:
        source = self.store.get_source(source_id)
        if source is None:
            raise ValueError("Unknown source")
        self._ensure_source_allowed(source, require_approval=True)
        preview = self.preview_source(source_id)

        rollback_snapshot = self.store.get_source_snapshot(source["name"])
        rollback_path = self.store.write_snapshot(
            source["name"], rollback_snapshot, "rollback"
        )
        incoming_path = self.store.write_snapshot(
            source["name"], preview.dataset, "incoming"
        )

        apply_event_id = self.store.create_sync_event(
            source_id=source_id,
            connector=preview.connector,
            mode="apply",
            summary=preview.summary,
            diff=preview.diff,
            snapshot_path=incoming_path,
            rollback_snapshot_path=rollback_path,
            status="running",
        )

        try:
            self.store.restore_source_snapshot(source["name"], preview.dataset)
            self.store.finish_sync_event(
                apply_event_id,
                status="completed",
                summary=preview.summary,
                diff=preview.diff,
                snapshot_path=incoming_path,
                rollback_snapshot_path=rollback_path,
            )
            self.store.update_source(
                source_id,
                last_sync_at=utc_now(),
                last_status="completed",
                last_error="",
                health="healthy",
            )
        except Exception as exc:
            self.store.finish_sync_event(
                apply_event_id,
                status="failed",
                summary=preview.summary,
                diff=preview.diff,
                snapshot_path=incoming_path,
                rollback_snapshot_path=rollback_path,
                error=str(exc),
            )
            self.store.update_source(
                source_id,
                last_sync_at=utc_now(),
                last_status="failed",
                last_error=str(exc),
                health="degraded",
            )
            raise

        preview.event_id = apply_event_id
        return preview

    def validate_layered_threat_module(
        self, item: dict[str, Any], file_path: str | Path
    ) -> None:
        connector = self._get_connector(LayeredModuleConnector.name)
        if not isinstance(connector, LayeredModuleConnector):
            raise RuntimeError("Layered module connector is not available.")
        connector.validate_threat_module(item, Path(file_path))

    def validate_layered_tool_module(
        self, item: dict[str, Any], file_path: str | Path
    ) -> None:
        connector = self._get_connector(LayeredModuleConnector.name)
        if not isinstance(connector, LayeredModuleConnector):
            raise RuntimeError("Layered module connector is not available.")
        connector.validate_tool_module(item, Path(file_path))

    def rollback_latest(self, source_id: int) -> dict:
        source = self.store.get_source(source_id)
        if source is None:
            raise ValueError("Unknown source")
        events = self.store.list_sync_events(source_id)
        apply_event = next(
            (
                event
                for event in events
                if event["mode"] == "apply"
                and event["status"] == "completed"
                and event["rollback_snapshot_path"]
            ),
            None,
        )
        if apply_event is None:
            raise RuntimeError("No completed apply event is available to roll back.")

        snapshot = json.loads(
            Path(apply_event["rollback_snapshot_path"]).read_text(encoding="utf-8")
        )
        summary = self.store.restore_source_snapshot(source["name"], snapshot)
        self.store.update_source(
            source_id,
            last_sync_at=utc_now(),
            last_status="rolled_back",
            last_error="",
            health="healthy",
        )
        self.store.create_sync_event(
            source_id=source_id,
            connector=source["connector"],
            mode="rollback",
            summary=summary,
            diff={"rolled_back_from_event": apply_event["id"]},
            snapshot_path=apply_event["rollback_snapshot_path"],
            status="completed",
        )
        return summary

    def repair_mitre_linkage(self) -> dict[str, Any]:
        summary: dict[str, Any] = {"mitre_refreshed": False, "layered_refreshed": False}
        mitre_source = self.store.get_source_by_name("MITRE ATT&CK Enterprise")
        if mitre_source and mitre_source.get("enabled", True):
            self.apply_source(mitre_source["id"])
            summary["mitre_refreshed"] = True
        layered_source = self.store.get_source_by_name("Layered Local Modules")
        if layered_source and layered_source.get("enabled", True):
            self.apply_source(layered_source["id"])
            summary["layered_refreshed"] = True
        return summary

    def export_offline_bundle(self, path: str) -> dict:
        return self.store.export_knowledge_bundle(path)

    def import_offline_bundle(self, path: str) -> dict:
        return self.store.import_knowledge_bundle(path)

    def refresh_startup_sources(self, *, connector_names: set[str] | None = None) -> None:
        """Apply approved local sources during app startup without interrupting launch."""
        for source in self.store.list_sources():
            if connector_names and source["connector"] not in connector_names:
                continue
            try:
                self.apply_source(source["id"])
            except Exception as exc:
                print(f"[WARN] Startup sync failed for {source['name']}: {exc}")

    def _get_connector(self, connector_name: str) -> BaseConnector:
        connector = self.connectors.get(connector_name)
        if connector is None:
            raise ValueError(f"Unsupported connector: {connector_name}")
        return connector

    @staticmethod
    def _ensure_source_allowed(source: dict, *, require_approval: bool) -> None:
        if not source.get("enabled", True):
            raise RuntimeError(
                f"Sync source '{source['name']}' is disabled. Enable it before running sync."
            )
        if require_approval and not source.get("approved", True):
            raise RuntimeError(
                f"Sync source '{source['name']}' is not approved. Approve it before running sync."
            )

    def _diff_dataset(self, current: dict, incoming: dict) -> dict:
        current_entities = {
            (entity["type"], entity["external_id"]): self._entity_signature(entity)
            for entity in current.get("entities", [])
        }
        incoming_entities = {
            (entity["type"], entity["external_id"]): self._entity_signature(entity)
            for entity in incoming.get("entities", [])
        }
        current_relationships = {
            (
                rel["src_type"],
                rel["src_external_id"],
                rel["dst_type"],
                rel["dst_external_id"],
                rel["rel_type"],
                rel.get("source_ref", ""),
            ): self._relationship_signature(rel)
            for rel in current.get("relationships", [])
        }
        incoming_relationships = {
            (
                rel["src_type"],
                rel["src_external_id"],
                rel["dst_type"],
                rel["dst_external_id"],
                rel["rel_type"],
                rel.get("source_ref", ""),
            ): self._relationship_signature(rel)
            for rel in incoming.get("relationships", [])
        }

        new_entities = [
            key for key in incoming_entities.keys() if key not in current_entities
        ]
        updated_entities = [
            key
            for key, signature in incoming_entities.items()
            if key in current_entities and current_entities[key] != signature
        ]
        new_relationships = [
            key
            for key in incoming_relationships.keys()
            if key not in current_relationships
        ]
        updated_relationships = [
            key
            for key, signature in incoming_relationships.items()
            if key in current_relationships and current_relationships[key] != signature
        ]

        return {
            "new_entities": len(new_entities),
            "updated_entities": len(updated_entities),
            "new_relationships": len(new_relationships),
            "updated_relationships": len(updated_relationships),
            "entity_examples": [f"{kind}:{external_id}" for kind, external_id in new_entities[:10]],
            "updated_entity_examples": [
                f"{kind}:{external_id}" for kind, external_id in updated_entities[:10]
            ],
            "relationship_examples": [
                f"{src_type}:{src_external}->{rel_type}->{dst_type}:{dst_external}"
                for src_type, src_external, dst_type, dst_external, rel_type, _ in new_relationships[:10]
            ],
            "new_files": incoming.get("metadata", {}).get("sync_stats", {}).get("new_files", 0),
            "changed_files": incoming.get("metadata", {}).get("sync_stats", {}).get("changed_files", 0),
            "unchanged_files": incoming.get("metadata", {}).get("sync_stats", {}).get("unchanged_files", 0),
            "deleted_files": incoming.get("metadata", {}).get("sync_stats", {}).get("deleted_files", 0),
            "warning_count": incoming.get("metadata", {}).get("sync_stats", {}).get("warning_count", 0),
        }

    @staticmethod
    def _entity_signature(entity: dict) -> str:
        normalized = {
            "name": entity.get("name", ""),
            "short_description": entity.get("short_description", ""),
            "status": entity.get("status", ""),
            "confidence": entity.get("confidence", 0.0),
            "priority": entity.get("priority", ""),
            "tags": entity.get("tags", []),
            "payload": entity.get("payload", {}),
            "source_ref": entity.get("source_ref", ""),
            "source_url": entity.get("source_url", ""),
        }
        return json.dumps(KnowledgeStore.json_safe(normalized), sort_keys=True)

    @staticmethod
    def _relationship_signature(rel: dict) -> str:
        normalized = {
            "weight": rel.get("weight", 1.0),
            "confidence": rel.get("confidence", 0.0),
            "status": rel.get("status", ""),
            "context": rel.get("context", {}),
            "source_ref": rel.get("source_ref", ""),
        }
        return json.dumps(KnowledgeStore.json_safe(normalized), sort_keys=True)


__all__ = [
    "BaseConnector",
    "JsonFeedConnector",
    "LayeredModuleConnector",
    "MitreAttackConnector",
    "SigmaHQRulesConnector",
    "SyncResult",
    "SyncService",
]
