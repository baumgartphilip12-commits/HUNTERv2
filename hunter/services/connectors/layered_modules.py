"""Layered local module sync connector."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from hunter.models.module_store import ensure_layered_module_dirs
from hunter.runtime_paths import layered_source_config, relative_module_ref, resolve_layered_source_paths
from hunter.services.connectors.base import JsonFeedConnector
from hunter.services.sigma_service import SIGMA_TRANSLATION_REQUIRED_FIELDS
from hunter.models.knowledge_store import utc_now


class LayeredModuleConnector(JsonFeedConnector):
    """Connector for v2 layered local JSON modules on disk."""

    name = "layered_modules"

    def __init__(self, store):
        super().__init__(store, create_mitre_placeholders=True)

    def build_dataset(self, source: dict) -> dict:
        config = source.get("config", {})
        ensure_layered_module_dirs(self.store.project_dir)
        resolved_paths = resolve_layered_source_paths(config, self.store.project_dir)
        portable_config = layered_source_config(self.store.project_dir)
        layered_dirs = {
            "threats": str(resolved_paths["threats"]),
            "tools": str(resolved_paths["tools"]),
            "mitre": str(resolved_paths["mitre"]),
        }

        payload = {
            "threat_profiles": [],
            "tool_packs": [],
            "indicator_sets": [],
            "addon_packs": [],
        }
        current_snapshot = self.store.get_source_snapshot(source["name"])
        current_entities = current_snapshot.get("entities", [])
        current_relationships = current_snapshot.get("relationships", [])
        current_index = self.store.get_layered_module_index_map(source["id"])
        warnings: list[str] = []
        file_counts = {key: 0 for key in layered_dirs}
        sync_stats = {
            "new_files": 0,
            "changed_files": 0,
            "unchanged_files": 0,
            "deleted_files": 0,
            "warning_count": 0,
        }
        changed_refs: set[str] = set()
        seen_refs: set[str] = set()
        index_rows: list[dict] = []
        now = utc_now()

        for layer_name in ("threats", "tools", "mitre"):
            directory = Path(layered_dirs[layer_name]).resolve()
            if not directory.exists():
                continue
            for file_path in sorted(directory.glob("*.json")):
                file_counts[layer_name] += 1
                resolved_path = file_path.resolve()
                relative_ref = relative_module_ref(resolved_path, self.store.project_dir)
                seen_refs.add(relative_ref)
                stat = resolved_path.stat()
                previous = current_index.get(relative_ref)
                if (
                    previous is not None
                    and previous.get("status") != "warning"
                    and int(previous.get("mtime_ns", 0) or 0) == int(stat.st_mtime_ns)
                    and int(previous.get("size_bytes", 0) or 0) == int(stat.st_size)
                ):
                    sync_stats["unchanged_files"] += 1
                    index_rows.append(
                        {
                            **previous,
                            "layer": layer_name,
                            "relative_path": relative_ref,
                            "absolute_path": str(resolved_path),
                            "mtime_ns": int(stat.st_mtime_ns),
                            "size_bytes": int(stat.st_size),
                            "status": "indexed",
                            "warning_text": "",
                            "last_seen_at": now,
                            "last_indexed_at": now,
                        }
                    )
                    continue
                try:
                    raw_text = file_path.read_text(encoding="utf-8")
                    content_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
                    if previous is not None and content_hash == previous.get("content_hash", ""):
                        sync_stats["unchanged_files"] += 1
                        index_rows.append(
                            {
                                **previous,
                                "layer": layer_name,
                                "relative_path": relative_ref,
                                "absolute_path": str(resolved_path),
                                "mtime_ns": int(stat.st_mtime_ns),
                                "size_bytes": int(stat.st_size),
                                "content_hash": content_hash,
                                "status": "indexed",
                                "warning_text": "",
                                "last_seen_at": now,
                                "last_indexed_at": now,
                            }
                        )
                        continue

                    item = json.loads(raw_text)
                    if not isinstance(item, dict):
                        raise ValueError("module file must contain a JSON object")
                    if not item.get("external_id") or not item.get("name"):
                        raise ValueError("module file requires external_id and name")
                    item = dict(item)
                    item["source_ref"] = relative_ref
                    item["source_url"] = ""
                    item.setdefault("status", "active")
                    item.setdefault("confidence", 0.75)
                    item.setdefault("tags", [])
                    if layer_name == "threats":
                        self._validate_threat_module(item, resolved_path)
                        item.setdefault("indicator_set_ids", [])
                        payload["threat_profiles"].append(item)
                        entity_type = "ThreatProfile"
                    elif layer_name == "tools":
                        self._validate_tool_module(item, resolved_path)
                        payload["tool_packs"].append(item)
                        entity_type = "ToolPack"
                    else:
                        entity_type = "MitreTechnique"

                    if previous is None:
                        sync_stats["new_files"] += 1
                    else:
                        sync_stats["changed_files"] += 1
                        changed_refs.add(relative_ref)

                    if layer_name != "mitre":
                        index_rows.append(
                            {
                                "layer": layer_name,
                                "relative_path": relative_ref,
                                "absolute_path": str(resolved_path),
                                "entity_type": entity_type,
                                "external_id": item.get("external_id", ""),
                                "mtime_ns": int(stat.st_mtime_ns),
                                "size_bytes": int(stat.st_size),
                                "content_hash": content_hash,
                                "status": "indexed",
                                "warning_text": "",
                                "last_seen_at": now,
                                "last_indexed_at": now,
                            }
                        )
                except Exception as exc:
                    warnings.append(f"{file_path.name}: {exc}")
                    print(f"[WARN] Could not load layered module {file_path}: {exc}")
                    sync_stats["warning_count"] += 1
                    index_rows.append(
                        {
                            "layer": layer_name,
                            "relative_path": relative_ref,
                            "absolute_path": str(resolved_path),
                            "entity_type": previous.get("entity_type", "") if previous else "",
                            "external_id": previous.get("external_id", "") if previous else "",
                            "mtime_ns": int(stat.st_mtime_ns),
                            "size_bytes": int(stat.st_size),
                            "content_hash": previous.get("content_hash", "") if previous else "",
                            "status": "warning",
                            "warning_text": str(exc),
                            "last_seen_at": now,
                            "last_indexed_at": now,
                        }
                    )

        for relative_ref, previous in current_index.items():
            if previous.get("layer") not in {"threats", "tools", "mitre"}:
                continue
            if relative_ref in seen_refs:
                continue
            sync_stats["deleted_files"] += 1
            changed_refs.add(relative_ref)
            index_rows.append(
                {
                    **previous,
                    "status": "deleted",
                    "warning_text": "",
                    "last_indexed_at": now,
                }
            )

        retained_entities = [
            entity
            for entity in current_entities
            if entity.get("source_ref", "") not in changed_refs
            and not self._is_layered_placeholder(entity, source["name"])
        ]
        retained_relationships = [
            rel
            for rel in current_relationships
            if rel.get("source_ref", "") not in changed_refs
        ]

        partial_dataset = self._normalize_payload(source, payload)
        dataset = {
            "source_name": source["name"],
            "connector": self.name,
            "fetched_at": now,
            "entities": retained_entities + partial_dataset.get("entities", []),
            "relationships": retained_relationships + partial_dataset.get("relationships", []),
        }
        dataset["entities"] = self._dedupe_entities(dataset["entities"])
        dataset["relationships"] = self._dedupe_relationships(dataset["relationships"])

        referenced_techniques = {
            rel["dst_external_id"]
            for rel in dataset.get("relationships", [])
            if rel.get("dst_type") == "MitreTechnique"
        }
        dataset["entities"] = [
            entity
            for entity in dataset.get("entities", [])
            if not self._is_orphan_placeholder(entity, source["name"], referenced_techniques)
        ]
        dataset["metadata"] = {
            "root": portable_config["root"],
            "directories": {
                "threats": portable_config["threats_dir"],
                "tools": portable_config["tools_dir"],
                "mitre": portable_config["mitre_dir"],
            },
            "file_counts": file_counts,
            "warnings": warnings,
            "loaded_at": now,
            "sync_stats": sync_stats,
        }
        dataset["layered_module_index"] = index_rows
        return dataset

    def validate_threat_module(self, item: dict[str, Any], file_path: Path) -> None:
        self._validate_threat_module(item, file_path)

    def validate_tool_module(self, item: dict[str, Any], file_path: Path) -> None:
        self._validate_tool_module(item, file_path)

    def _validate_threat_module(self, item: dict[str, Any], file_path: Path) -> None:
        required_fields = (
            "external_id",
            "name",
            "summary",
            "aliases",
            "techniques",
            "indicators",
            "references",
            "extra_hunts",
            "status",
            "tags",
        )
        missing = [field for field in required_fields if field not in item]
        if missing:
            raise ValueError(
                f"{file_path.name} is missing required threat fields: {', '.join(missing)}"
            )
        if not isinstance(item.get("aliases"), list):
            raise ValueError(f"{file_path.name} aliases must be a list.")
        if not isinstance(item.get("techniques"), list) or not item.get("techniques"):
            raise ValueError(f"{file_path.name} must define at least one ATT&CK technique.")
        if not isinstance(item.get("indicators"), list):
            raise ValueError(f"{file_path.name} indicators must be a list.")
        if not isinstance(item.get("references"), list):
            raise ValueError(f"{file_path.name} references must be a list.")
        if not isinstance(item.get("extra_hunts"), list):
            raise ValueError(f"{file_path.name} extra_hunts must be a list.")
        for indicator in item.get("indicators", []):
            if not isinstance(indicator, dict):
                raise ValueError(f"{file_path.name} indicators must contain objects with type/value.")
            if not indicator.get("type") or not indicator.get("value"):
                raise ValueError(f"{file_path.name} indicator entries require both type and value.")

    def _validate_tool_module(self, item: dict[str, Any], file_path: Path) -> None:
        required_fields = (
            "external_id",
            "name",
            "summary",
            "status",
            "tags",
            "platform",
            "hunt_methods",
        )
        missing = [field for field in required_fields if field not in item]
        if missing:
            raise ValueError(
                f"{file_path.name} is missing required tool fields: {', '.join(missing)}"
            )
        hunt_methods = item.get("hunt_methods", [])
        if not isinstance(hunt_methods, list) or not hunt_methods:
            raise ValueError(f"{file_path.name} must define at least one hunt method.")
        if "environment_defaults" in item and not isinstance(item.get("environment_defaults"), dict):
            raise ValueError(f"{file_path.name} environment_defaults must be a JSON object.")
        if "template_values" in item and not isinstance(item.get("template_values"), dict):
            raise ValueError(f"{file_path.name} template_values must be a JSON object.")
        if "sigma_translation" in item:
            sigma_translation = item.get("sigma_translation")
            if not isinstance(sigma_translation, dict):
                raise ValueError(f"{file_path.name} sigma_translation must be a JSON object.")
            missing_fields = [
                field
                for field in SIGMA_TRANSLATION_REQUIRED_FIELDS
                if field not in sigma_translation
            ]
            if missing_fields:
                raise ValueError(
                    f"{file_path.name} sigma_translation is missing fields: {', '.join(missing_fields)}"
                )
            if not isinstance(sigma_translation.get("enabled"), bool):
                raise ValueError(f"{file_path.name} sigma_translation.enabled must be true or false.")
            if not str(sigma_translation.get("backend", "")).strip():
                raise ValueError(f"{file_path.name} sigma_translation.backend is required.")
            if not isinstance(sigma_translation.get("pipelines"), list):
                raise ValueError(f"{file_path.name} sigma_translation.pipelines must be a JSON array.")
            if not str(sigma_translation.get("output_format", "")).strip():
                raise ValueError(f"{file_path.name} sigma_translation.output_format is required.")
        required_method_fields = (
            "title",
            "techniques",
            "template",
            "supported_ioc_types",
            "required_placeholders",
            "output_format",
            "execution_surface",
            "surface_details",
            "service_examples",
            "prerequisites",
            "noise_level",
            "privilege_required",
            "time_cost",
            "data_sources",
            "expectation",
            "method_strength",
            "method_kind",
            "strength_reason",
            "behavior_focus",
        )
        for method in hunt_methods:
            missing_fields = [field for field in required_method_fields if field not in method]
            if missing_fields:
                raise ValueError(
                    f"{file_path.name} contains a method missing fields: {', '.join(missing_fields)}"
                )
            if method.get("method_strength") not in {"primary_hunt", "supporting_pivot"}:
                raise ValueError(
                    f"{file_path.name} has an invalid method_strength on {method.get('title', 'Untitled method')}."
                )
            if not str(method.get("method_kind", "")).strip():
                raise ValueError(
                    f"{file_path.name} has a method missing method_kind."
                )
            if not str(method.get("strength_reason", "")).strip():
                raise ValueError(
                    f"{file_path.name} has a method missing strength_reason."
                )
            if not str(method.get("behavior_focus", "")).strip():
                raise ValueError(
                    f"{file_path.name} has a method missing behavior_focus."
                )

    @staticmethod
    def _is_orphan_placeholder(entity: dict, source_name: str, referenced_techniques: set[str]) -> bool:
        payload = entity.get("payload", {})
        if entity.get("source_name") != source_name:
            return False
        if entity.get("type") != "MitreTechnique":
            return False
        if entity.get("external_id") in referenced_techniques:
            return False
        return payload.get("technique_id") == entity.get("external_id") and "placeholder" in entity.get("tags", [])

    @staticmethod
    def _is_layered_placeholder(entity: dict, source_name: str) -> bool:
        if entity.get("source_name") != source_name:
            return False
        if entity.get("type") != "MitreTechnique":
            return False
        return entity.get("status") == "placeholder" or "placeholder" in entity.get("tags", [])

    @staticmethod
    def _dedupe_entities(entities: list[dict]) -> list[dict]:
        deduped: dict[tuple[str, str], dict] = {}
        for entity in entities:
            deduped[(entity["type"], entity["external_id"])] = entity
        return list(deduped.values())

    @staticmethod
    def _dedupe_relationships(relationships: list[dict]) -> list[dict]:
        deduped: dict[tuple[str, str, str, str, str, str], dict] = {}
        for rel in relationships:
            key = (
                rel["src_type"],
                rel["src_external_id"],
                rel["dst_type"],
                rel["dst_external_id"],
                rel["rel_type"],
                rel.get("source_ref", ""),
            )
            deduped[key] = rel
        return list(deduped.values())
