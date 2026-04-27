"""Unified authoring persistence helpers for local and layered entities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunter.services.layered_entity_service import LayeredEntitySaveResult, LayeredEntityService


@dataclass
class AuthoringResult:
    """Persistence result for an authored save or delete action."""

    persistence: str
    entity: dict[str, Any] | None = None
    layered_source: dict[str, Any] | None = None


class AuthoringService:
    """Persist authored entities without letting the UI own storage policy."""

    def __init__(self, store, layered_entity_service: LayeredEntityService):
        self.store = store
        self.layered_entity_service = layered_entity_service

    def save_entity(
        self,
        entity_type: str,
        entity: dict[str, Any],
        *,
        branch_source: dict[str, Any] | None = None,
        previous_entity: dict[str, Any] | None = None,
    ) -> AuthoringResult:
        existing = self.store.get_entity(entity["id"]) if entity.get("id") else None
        collision = self.store.get_entity_by_external_id(entity_type, entity["external_id"])
        if collision is not None and (existing is None or collision["id"] != existing["id"]):
            raise ValueError("Choose a unique external ID for the new record.")

        if entity_type == "ThreatProfile":
            result = self.layered_entity_service.save_threat(
                entity,
                previous_entity=previous_entity or existing,
            )
            return self._layered_result(result)
        if entity_type == "ToolPack":
            result = self.layered_entity_service.save_tool(
                entity,
                branch_source=branch_source,
                previous_entity=previous_entity or existing,
            )
            return self._layered_result(result)

        entity_id = self.store.upsert_entity(
            entity_type=entity_type,
            external_id=entity["external_id"],
            name=entity["name"],
            short_description=entity.get("short_description", ""),
            status=entity.get("status", "active"),
            confidence=entity.get(
                "confidence",
                existing.get("confidence", 0.7) if existing is not None else 0.7,
            ),
            priority=entity.get("priority", ""),
            source_name="local",
            source_ref=entity["external_id"],
            tags=entity.get("tags", []),
            payload=entity.get("payload", {}),
        )
        self._sync_local_relationships(entity_type, entity_id, entity)
        saved = self.store.get_entity(entity_id)
        return AuthoringResult(persistence="local", entity=saved)

    def delete_entity(self, entity_type: str, entity: dict[str, Any]) -> AuthoringResult:
        if entity_type == "ThreatProfile" and self._is_layered_threat(entity):
            self.layered_entity_service.delete_layered_entity(entity)
            return AuthoringResult(
                persistence="layered",
                layered_source=self.layered_entity_service.layered_source(),
            )
        if entity_type == "ToolPack" and self._is_layered_tool(entity):
            self.layered_entity_service.delete_layered_entity(entity)
            return AuthoringResult(
                persistence="layered",
                layered_source=self.layered_entity_service.layered_source(),
            )
        if entity.get("source_name") != "local":
            raise PermissionError("Synced source-owned records cannot be deleted from the browser.")
        self.store.delete_entity(entity["id"])
        return AuthoringResult(persistence="local")

    def save_tool_sigma_scope(
        self,
        tool: dict[str, Any],
        families: list[str] | tuple[str, ...] | set[str],
    ) -> AuthoringResult:
        """Persist only ToolPack Sigma generation scope without rewriting hunt methods."""

        if tool.get("type") != "ToolPack":
            raise ValueError("Sigma scope can only be edited for ToolPack records.")
        normalized_families = LayeredEntityService.normalize_sigma_scope_families(families)
        if tool.get("source_name") == "Layered Local Modules":
            result = self.layered_entity_service.save_tool_sigma_scope(tool, normalized_families)
            return self._layered_result(result)
        if tool.get("source_name") not in {"local", "", None}:
            raise PermissionError("Only local or layered ToolPacks can persist Sigma generation scope.")
        payload = {
            **tool.get("payload", {}),
            "sigma_scope": {"default_families": normalized_families},
        }
        entity_id = self.store.upsert_entity(
            entity_type="ToolPack",
            external_id=tool["external_id"],
            name=tool["name"],
            short_description=tool.get("short_description", ""),
            status=tool.get("status", "active"),
            confidence=tool.get("confidence", 0.7),
            priority=tool.get("priority", ""),
            source_name=tool.get("source_name") or "local",
            source_ref=tool.get("source_ref") or tool["external_id"],
            source_url=tool.get("source_url", ""),
            retrieved_at=tool.get("retrieved_at", ""),
            last_seen=tool.get("last_seen", ""),
            valid_until=tool.get("valid_until", ""),
            tags=tool.get("tags", []),
            payload=payload,
        )
        saved = self.store.get_entity(entity_id)
        return AuthoringResult(persistence="local", entity=saved)

    def layered_entity_ref(self, entity: dict[str, Any]) -> str:
        return self.layered_entity_service.layered_entity_ref(entity)

    def resolved_layered_entity_path(self, entity: dict[str, Any]):
        return self.layered_entity_service.resolved_layered_entity_path(entity)

    def _layered_result(self, result: LayeredEntitySaveResult) -> AuthoringResult:
        return AuthoringResult(
            persistence="layered",
            entity=result.entity,
            layered_source=result.layered_source,
        )

    def _is_layered_threat(self, entity: dict[str, Any]) -> bool:
        return (
            entity.get("source_name") == "Layered Local Modules"
            and bool(self.layered_entity_ref(entity))
        )

    def _is_layered_tool(self, entity: dict[str, Any]) -> bool:
        payload = entity.get("payload", {})
        return (
            entity.get("source_name") == "Layered Local Modules"
            and bool(self.layered_entity_ref(entity))
            and (
                payload.get("variant_of_tool_external_id")
                or not payload.get("generation")
            )
        )

    def _sync_local_relationships(self, entity_type: str, entity_id: int, entity: dict[str, Any]) -> None:
        payload = entity.get("payload", {})
        if entity_type == "ThreatProfile":
            self.store.delete_relationships_for_entity(entity_id, rel_type="USES", source_name="local", direction="out")
            self.store.delete_relationships_for_entity(
                entity_id,
                rel_type="USES_INDICATOR_SET",
                source_name="local",
                direction="out",
            )
            for technique_id in payload.get("mitre_techniques", []):
                technique_entity_id = self._ensure_entity_reference("MitreTechnique", technique_id)
                self.store.upsert_relationship(
                    src_entity_id=entity_id,
                    dst_entity_id=technique_entity_id,
                    rel_type="USES",
                    weight=1.0,
                    confidence=entity.get("confidence", 0.7),
                    status=entity.get("status", "active"),
                    source_name="local",
                    source_ref=entity["external_id"],
                    context={"origin": "local_authoring"},
                    first_seen=entity.get("retrieved_at", ""),
                    last_seen=entity.get("last_seen", ""),
                )
            for indicator_external_id in payload.get("indicator_set_ids", []):
                indicator_entity = self.store.get_entity_by_external_id("IndicatorSet", indicator_external_id)
                if indicator_entity is None:
                    continue
                self.store.upsert_relationship(
                    src_entity_id=entity_id,
                    dst_entity_id=indicator_entity["id"],
                    rel_type="USES_INDICATOR_SET",
                    weight=1.0,
                    confidence=entity.get("confidence", 0.7),
                    status=entity.get("status", "active"),
                    source_name="local",
                    source_ref=entity["external_id"],
                    context={"origin": "local_authoring"},
                )
            return

        if entity_type == "ToolPack":
            self.store.delete_relationships_for_entity(
                entity_id,
                rel_type="COVERS",
                source_name="local",
                direction="out",
            )
            technique_ids = sorted(
                {
                    technique_id
                    for method in payload.get("hunt_methods", [])
                    for technique_id in method.get("techniques", [])
                }
            )
            for technique_id in technique_ids:
                technique_entity_id = self._ensure_entity_reference("MitreTechnique", technique_id)
                self.store.upsert_relationship(
                    src_entity_id=entity_id,
                    dst_entity_id=technique_entity_id,
                    rel_type="COVERS",
                    weight=1.0,
                    confidence=entity.get("confidence", 0.7),
                    status=entity.get("status", "active"),
                    source_name="local",
                    source_ref=entity["external_id"],
                    context={"origin": "local_authoring"},
                )
            return

        if entity_type == "AddonPack":
            self.store.delete_relationships_for_entity(
                entity_id,
                rel_type="EXTENDS",
                source_name="local",
                direction="out",
            )
            for target_external_id in payload.get("target_tool_ids", []):
                target = self.store.get_entity_by_external_id("ToolPack", target_external_id)
                if target is None:
                    continue
                self.store.upsert_relationship(
                    src_entity_id=entity_id,
                    dst_entity_id=target["id"],
                    rel_type="EXTENDS",
                    weight=1.0,
                    confidence=entity.get("confidence", 0.7),
                    status=entity.get("status", "active"),
                    source_name="local",
                    source_ref=entity["external_id"],
                    context={"origin": "addon_target", "target_type": "ToolPack"},
                )
            for target_external_id in payload.get("target_threat_ids", []):
                target = self.store.get_entity_by_external_id("ThreatProfile", target_external_id)
                if target is None:
                    continue
                self.store.upsert_relationship(
                    src_entity_id=entity_id,
                    dst_entity_id=target["id"],
                    rel_type="EXTENDS",
                    weight=1.0,
                    confidence=entity.get("confidence", 0.7),
                    status=entity.get("status", "active"),
                    source_name="local",
                    source_ref=entity["external_id"],
                    context={"origin": "addon_target", "target_type": "ThreatProfile"},
                )

    def _ensure_entity_reference(self, entity_type: str, external_id: str) -> int:
        existing = self.store.get_entity_by_external_id(entity_type, external_id)
        if existing is not None:
            return existing["id"]
        return self.store.upsert_entity(
            entity_type=entity_type,
            external_id=external_id,
            name=external_id,
            short_description="Local placeholder entity created during authoring.",
            status="placeholder",
            confidence=0.3,
            source_name="local",
            source_ref=external_id,
            payload={
                "technique_id": external_id,
                "parent_technique_id": external_id.split(".", 1)[0],
                "is_subtechnique": "." in external_id,
            }
            if entity_type == "MitreTechnique"
            else {},
        )
