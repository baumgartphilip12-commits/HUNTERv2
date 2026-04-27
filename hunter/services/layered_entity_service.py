"""Shared authored layered-entity persistence helpers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hunter.models.common import utc_now
from hunter.models.module_store import save_layered_module_json
from hunter.runtime_paths import (
    infer_layered_ref,
    layered_module_path,
    layered_module_target_path,
    relative_module_ref,
)
from hunter.services.sync_service import SyncService
from hunter.services.tool_catalog_compiler import ToolCatalogCompiler


@dataclass
class LayeredEntitySaveResult:
    entity: dict[str, Any]
    layered_source: dict[str, Any]
    saved_path: str


class LayeredEntityService:
    """Persist authored threat and tool modules without a full layered re-sync."""

    def __init__(self, store, sync_service: SyncService, project_dir: str):
        self.store = store
        self.sync_service = sync_service
        self.project_dir = str(project_dir)

    @staticmethod
    def normalize_sigma_scope_families(families: list[str] | tuple[str, ...] | set[str]) -> list[str]:
        return sorted(
            {
                str(family).strip().lower()
                for family in families
                if str(family).strip()
            }
        )

    def save_threat(
        self,
        entity: dict[str, Any],
        *,
        previous_entity: dict[str, Any] | None = None,
    ) -> LayeredEntitySaveResult:
        payload = json.loads(json.dumps(entity.get("payload", {})))
        file_payload = {
            "external_id": entity["external_id"],
            "name": entity["name"],
            "summary": payload.get("summary", entity.get("short_description", "")),
            "aliases": payload.get("aliases", []),
            "techniques": payload.get("mitre_techniques", []),
            "indicators": payload.get("indicators", []),
            "references": payload.get("references", []),
            "extra_hunts": payload.get("extra_hunts", []),
            "status": entity.get("status", "active"),
            "tags": entity.get("tags", []),
        }
        target_path = self.layered_module_target_path("threats", entity["external_id"])
        self.sync_service.validate_layered_threat_module(file_payload, target_path)
        saved_path = save_layered_module_json(
            "threats",
            entity["external_id"],
            file_payload,
            self.project_dir,
        )
        self._remove_previous_file(previous_entity, saved_path)

        layered_source = self.layered_source()
        if layered_source is None:
            raise RuntimeError("Layered Local Modules source is not available.")
        saved_entity = self._persist_threat_runtime(
            entity,
            payload=payload,
            saved_path=saved_path,
            layered_source=layered_source,
            previous_entity=previous_entity,
        )
        return LayeredEntitySaveResult(
            entity=saved_entity,
            layered_source=layered_source,
            saved_path=saved_path,
        )

    def save_tool(
        self,
        entity: dict[str, Any],
        *,
        branch_source: dict[str, Any] | None = None,
        previous_entity: dict[str, Any] | None = None,
    ) -> LayeredEntitySaveResult:
        payload = json.loads(json.dumps(entity.get("payload", {})))
        payload.setdefault("summary", entity.get("short_description", ""))
        payload.setdefault("references", payload.get("references", []))
        payload.setdefault("environment_defaults", {})
        payload.setdefault("template_values", {})
        payload.setdefault("execution_surface", payload.get("execution_surface", ""))
        payload.setdefault("surface_details", payload.get("surface_details", ""))
        payload.setdefault("service_examples", payload.get("service_examples", []))
        payload["hunt_methods"] = [
            ToolCatalogCompiler.ensure_method_metadata(method)
            for method in payload.get("hunt_methods", [])
        ]
        payload.pop("generation", None)
        if branch_source is not None:
            source_payload = branch_source.get("payload", {})
            payload["variant_of_tool_external_id"] = (
                payload.get("variant_of_tool_external_id")
                or source_payload.get("variant_of_tool_external_id")
                or branch_source["external_id"]
            )
            payload["variant_origin"] = "branched_from_generated"
        elif payload.get("variant_of_tool_external_id"):
            payload["variant_origin"] = payload.get("variant_origin") or "local_variant"

        file_payload = {
            "external_id": entity["external_id"],
            "name": entity["name"],
            "summary": payload.get("summary", entity.get("short_description", "")),
            "status": entity.get("status", "active"),
            "tags": entity.get("tags", []),
            "platform": payload.get("platform", ""),
            "execution_surface": payload.get("execution_surface", ""),
            "surface_details": payload.get("surface_details", ""),
            "service_examples": payload.get("service_examples", []),
            "references": payload.get("references", []),
            "variant_of_tool_external_id": payload.get("variant_of_tool_external_id", ""),
            "variant_origin": payload.get("variant_origin", "local_variant"),
            "environment_defaults": payload.get("environment_defaults", {}),
            "template_values": payload.get("template_values", {}),
            "hunt_methods": payload.get("hunt_methods", []),
        }
        if isinstance(payload.get("sigma_translation"), dict):
            file_payload["sigma_translation"] = payload.get("sigma_translation")
        if isinstance(payload.get("sigma_scope"), dict):
            file_payload["sigma_scope"] = payload.get("sigma_scope")
        target_path = self.layered_module_target_path("tools", entity["external_id"])
        self.sync_service.validate_layered_tool_module(file_payload, target_path)
        saved_path = save_layered_module_json(
            "tools",
            entity["external_id"],
            file_payload,
            self.project_dir,
        )
        self._remove_previous_file(previous_entity, saved_path)

        layered_source = self.layered_source()
        if layered_source is None:
            raise RuntimeError("Layered Local Modules source is not available.")
        saved_entity = self._persist_tool_runtime(
            entity,
            payload=payload,
            saved_path=saved_path,
            layered_source=layered_source,
            previous_entity=previous_entity,
        )
        return LayeredEntitySaveResult(
            entity=saved_entity,
            layered_source=layered_source,
            saved_path=saved_path,
        )

    def save_tool_sigma_scope(
        self,
        entity: dict[str, Any],
        families: list[str] | tuple[str, ...] | set[str],
    ) -> LayeredEntitySaveResult:
        """Update only a layered ToolPack's trusted Sigma generation scope."""

        normalized_families = self.normalize_sigma_scope_families(families)
        payload = json.loads(json.dumps(entity.get("payload", {})))
        payload["sigma_scope"] = {"default_families": normalized_families}

        layered_source = self.layered_source()
        if layered_source is None:
            raise RuntimeError("Layered Local Modules source is not available.")
        module_path = self.resolved_layered_entity_path(entity)
        if module_path is None or not module_path.exists():
            raise RuntimeError("The ToolPack module file could not be resolved for Sigma scope editing.")
        file_payload = json.loads(module_path.read_text(encoding="utf-8"))
        file_payload["sigma_scope"] = {"default_families": normalized_families}
        self.sync_service.validate_layered_tool_module(file_payload, module_path)
        saved_path = save_layered_module_json(
            "tools",
            entity["external_id"],
            file_payload,
            self.project_dir,
        )
        saved_entity = self._persist_tool_runtime(
            entity,
            payload=payload,
            saved_path=saved_path,
            layered_source=layered_source,
            previous_entity=entity,
        )
        return LayeredEntitySaveResult(
            entity=saved_entity,
            layered_source=layered_source,
            saved_path=saved_path,
        )

    def delete_layered_entity(self, entity: dict[str, Any]) -> None:
        layered_source = self.layered_source()
        if layered_source is None:
            raise RuntimeError("Layered Local Modules source is not available.")
        entity_path = self.resolved_layered_entity_path(entity)
        if entity_path is not None and entity_path.exists():
            entity_path.unlink()
        self._retire_previous_layered_entity(entity, layered_source=layered_source)

    def layered_source(self) -> dict[str, Any] | None:
        return self.store.get_source_by_name("Layered Local Modules")

    def layered_module_target_path(self, layer: str, external_id: str) -> Path:
        return layered_module_target_path(layer, external_id, self.project_dir)

    def layered_entity_ref(self, entity: dict[str, Any]) -> str:
        if entity.get("source_name") != "Layered Local Modules":
            return ""
        return infer_layered_ref(
            entity_type=entity.get("type", ""),
            external_id=entity.get("external_id", ""),
            source_ref=entity.get("source_ref", ""),
            source_url=entity.get("source_url", ""),
            project_dir=self.project_dir,
        )

    def resolved_layered_entity_path(self, entity: dict[str, Any]) -> Path | None:
        relative_ref = self.layered_entity_ref(entity)
        if not relative_ref:
            return None
        return layered_module_path(relative_ref, self.project_dir)

    def _layered_relative_ref(self, path: str | Path) -> str:
        return relative_module_ref(path, self.project_dir)

    def _remove_previous_file(self, previous_entity: dict[str, Any] | None, saved_path: str) -> None:
        if (
            previous_entity is None
            or not self.layered_entity_ref(previous_entity)
            or previous_entity.get("external_id") == Path(saved_path).stem
        ):
            return
        try:
            previous_path = self.resolved_layered_entity_path(previous_entity)
            current_path = Path(saved_path).resolve()
            if previous_path is not None and previous_path != current_path and previous_path.exists():
                previous_path.unlink()
        except OSError as exc:
            raise RuntimeError(
                f"Saved the updated module but could not remove the old file: {exc}"
            ) from exc

    def _build_layered_index_row(
        self,
        *,
        layer: str,
        entity_type: str,
        external_id: str,
        path: str | Path,
    ) -> dict[str, Any]:
        resolved = Path(path).resolve()
        stat = resolved.stat()
        return {
            "layer": layer,
            "relative_path": self._layered_relative_ref(resolved),
            "absolute_path": str(resolved),
            "entity_type": entity_type,
            "external_id": external_id,
            "mtime_ns": int(stat.st_mtime_ns),
            "size_bytes": int(stat.st_size),
            "content_hash": hashlib.sha256(
                resolved.read_text(encoding="utf-8").encode("utf-8")
            ).hexdigest(),
            "status": "indexed",
            "warning_text": "",
            "last_seen_at": utc_now(),
            "last_indexed_at": utc_now(),
        }

    def _retire_previous_layered_entity(
        self,
        previous_entity: dict[str, Any] | None,
        *,
        layered_source: dict[str, Any],
    ) -> None:
        if previous_entity is None:
            return
        if previous_entity.get("source_name") != layered_source["name"]:
            return
        self.store.delete_relationships_for_entity(
            previous_entity["id"],
            source_name=layered_source["name"],
            direction="any",
        )
        self.store.mark_entity_removed(previous_entity["id"])
        previous_ref = previous_entity.get("source_ref", "")
        if previous_ref:
            self.store.delete_layered_module_index_row(layered_source["id"], previous_ref)

    def _replace_threat_relationships(
        self,
        entity_id: int,
        *,
        technique_ids: list[str],
        source_name: str,
        source_ref: str,
        status: str,
    ) -> None:
        self.store.delete_relationships_for_entity(
            entity_id,
            rel_type="USES",
            source_name=source_name,
            direction="out",
        )
        timestamp = utc_now()
        for technique_id in technique_ids:
            technique = self.store.get_entity_by_external_id("MitreTechnique", technique_id)
            if technique is None:
                raise RuntimeError(
                    f"ATT&CK technique {technique_id} is missing from the runtime store. Run the MITRE sync first."
                )
            self.store.upsert_relationship(
                src_entity_id=entity_id,
                dst_entity_id=technique["id"],
                rel_type="USES",
                weight=1.0,
                confidence=0.75,
                status=status,
                source_name=source_name,
                source_ref=source_ref,
                context={"origin": "layered_local_editor"},
                first_seen=timestamp,
                last_seen=timestamp,
            )

    def _replace_tool_relationships(
        self,
        entity_id: int,
        *,
        technique_ids: list[str],
        source_name: str,
        source_ref: str,
        status: str,
    ) -> None:
        self.store.delete_relationships_for_entity(
            entity_id,
            rel_type="COVERS",
            source_name=source_name,
            direction="out",
        )
        timestamp = utc_now()
        for technique_id in sorted(set(technique_ids)):
            technique = self.store.get_entity_by_external_id("MitreTechnique", technique_id)
            if technique is None:
                raise RuntimeError(
                    f"ATT&CK technique {technique_id} is missing from the runtime store. Run the MITRE sync first."
                )
            self.store.upsert_relationship(
                src_entity_id=entity_id,
                dst_entity_id=technique["id"],
                rel_type="COVERS",
                weight=1.0,
                confidence=0.75,
                status=status,
                source_name=source_name,
                source_ref=source_ref,
                context={"origin": "layered_local_editor"},
                first_seen=timestamp,
                last_seen=timestamp,
            )

    def _persist_threat_runtime(
        self,
        entity: dict[str, Any],
        *,
        payload: dict[str, Any],
        saved_path: str,
        layered_source: dict[str, Any],
        previous_entity: dict[str, Any] | None,
    ) -> dict[str, Any]:
        resolved = Path(saved_path).resolve()
        source_ref = self._layered_relative_ref(resolved)
        if previous_entity is not None and previous_entity.get("external_id") != entity["external_id"]:
            self._retire_previous_layered_entity(previous_entity, layered_source=layered_source)
        entity_id = self.store.upsert_entity(
            entity_type="ThreatProfile",
            external_id=entity["external_id"],
            name=entity["name"],
            short_description=payload.get("summary", entity.get("short_description", "")),
            status=entity.get("status", "active"),
            confidence=0.75,
            priority=entity.get("priority", ""),
            source_name=layered_source["name"],
            source_ref=source_ref,
            source_url="",
            retrieved_at=previous_entity.get("retrieved_at", utc_now()) if previous_entity else utc_now(),
            last_seen=utc_now(),
            tags=entity.get("tags", []),
            payload={
                "summary": payload.get("summary", entity.get("short_description", "")),
                "aliases": payload.get("aliases", []),
                "mitre_techniques": payload.get("mitre_techniques", []),
                "indicators": payload.get("indicators", []),
                "references": payload.get("references", []),
                "extra_hunts": payload.get("extra_hunts", []),
            },
        )
        self._replace_threat_relationships(
            entity_id,
            technique_ids=payload.get("mitre_techniques", []),
            source_name=layered_source["name"],
            source_ref=source_ref,
            status=entity.get("status", "active"),
        )
        self.store.upsert_layered_module_index_row(
            layered_source["id"],
            self._build_layered_index_row(
                layer="threats",
                entity_type="ThreatProfile",
                external_id=entity["external_id"],
                path=resolved,
            ),
        )
        synced = self.store.get_entity_by_external_id("ThreatProfile", entity["external_id"])
        if synced is None:
            raise RuntimeError("Threat save completed, but the updated runtime record could not be loaded.")
        return synced

    def _persist_tool_runtime(
        self,
        entity: dict[str, Any],
        *,
        payload: dict[str, Any],
        saved_path: str,
        layered_source: dict[str, Any],
        previous_entity: dict[str, Any] | None,
    ) -> dict[str, Any]:
        resolved = Path(saved_path).resolve()
        source_ref = self._layered_relative_ref(resolved)
        if previous_entity is not None and previous_entity.get("external_id") != entity["external_id"]:
            self._retire_previous_layered_entity(previous_entity, layered_source=layered_source)
        entity_id = self.store.upsert_entity(
            entity_type="ToolPack",
            external_id=entity["external_id"],
            name=entity["name"],
            short_description=payload.get("summary", entity.get("short_description", "")),
            status=entity.get("status", "active"),
            confidence=0.75,
            priority=entity.get("priority", ""),
            source_name=layered_source["name"],
            source_ref=source_ref,
            source_url="",
            retrieved_at=previous_entity.get("retrieved_at", utc_now()) if previous_entity else utc_now(),
            last_seen=utc_now(),
            tags=entity.get("tags", []),
            payload=payload,
        )
        technique_ids = [
            technique_id
            for method in payload.get("hunt_methods", [])
            for technique_id in method.get("techniques", [])
        ]
        self._replace_tool_relationships(
            entity_id,
            technique_ids=technique_ids,
            source_name=layered_source["name"],
            source_ref=source_ref,
            status=entity.get("status", "active"),
        )
        self.store.upsert_layered_module_index_row(
            layered_source["id"],
            self._build_layered_index_row(
                layer="tools",
                entity_type="ToolPack",
                external_id=entity["external_id"],
                path=resolved,
            ),
        )
        synced = self.store.get_entity_by_external_id("ToolPack", entity["external_id"])
        if synced is None:
            raise RuntimeError("Tool save completed, but the updated runtime record could not be loaded.")
        return synced
