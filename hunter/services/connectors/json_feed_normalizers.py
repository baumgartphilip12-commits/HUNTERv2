"""Entity normalizers for curated JSON feed datasets."""

from __future__ import annotations

from typing import Any

from hunter.models.knowledge_store import utc_now


def _external_id(item: dict[str, Any]) -> str:
    return item.get("external_id") or item["name"].lower().replace(" ", "_")


def _source_ref(item: dict[str, Any], fallback: str) -> str:
    return item.get("source_ref", item.get("external_id", fallback))


def normalize_threat_profile(
    source: dict[str, Any],
    threat: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Normalize one threat profile plus its owned relationships."""
    threat_external_id = _external_id(threat)
    source_ref = _source_ref(threat, threat["name"])
    entity = {
        "type": "ThreatProfile",
        "external_id": threat_external_id,
        "name": threat["name"],
        "short_description": threat.get("summary", ""),
        "status": threat.get("status", "active"),
        "confidence": float(threat.get("confidence", 0.7)),
        "priority": threat.get("priority", ""),
        "source_name": source["name"],
        "source_ref": source_ref,
        "source_url": threat.get("source_url", ""),
        "retrieved_at": utc_now(),
        "last_seen": threat.get("last_seen", utc_now()),
        "valid_until": threat.get("valid_until", ""),
        "tags": threat.get("tags", []),
        "payload": {
            "aliases": threat.get("aliases", []),
            "summary": threat.get("summary", ""),
            "mitre_techniques": threat.get("techniques", []),
            "indicator_set_ids": threat.get("indicator_set_ids", []),
            "references": threat.get("references", []),
            "indicators": threat.get("indicators", []),
            "extra_hunts": threat.get("extra_hunts", []),
        },
    }
    relationships = [
        {
            "src_type": "ThreatProfile",
            "src_external_id": threat_external_id,
            "dst_type": "MitreTechnique",
            "dst_external_id": technique_id,
            "rel_type": "USES",
            "weight": float(threat.get("weight", 1.0)),
            "confidence": float(threat.get("confidence", 0.7)),
            "status": threat.get("status", "active"),
            "source_name": source["name"],
            "source_ref": source_ref,
            "context": {"origin": "json_feed"},
            "first_seen": utc_now(),
            "last_seen": threat.get("last_seen", utc_now()),
            "valid_until": threat.get("valid_until", ""),
        }
        for technique_id in threat.get("techniques", [])
    ]
    relationships.extend(
        {
            "src_type": "ThreatProfile",
            "src_external_id": threat_external_id,
            "dst_type": "IndicatorSet",
            "dst_external_id": indicator_set_id,
            "rel_type": "USES_INDICATOR_SET",
            "weight": float(threat.get("weight", 1.0)),
            "confidence": float(threat.get("confidence", 0.7)),
            "status": threat.get("status", "active"),
            "source_name": source["name"],
            "source_ref": source_ref,
            "context": {"origin": "json_feed"},
            "first_seen": utc_now(),
            "last_seen": threat.get("last_seen", utc_now()),
            "valid_until": threat.get("valid_until", ""),
        }
        for indicator_set_id in threat.get("indicator_set_ids", [])
    )
    return [entity], relationships


def normalize_indicator_set(
    source: dict[str, Any],
    indicator_set: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Normalize one indicator set."""
    entity = {
        "type": "IndicatorSet",
        "external_id": _external_id(indicator_set),
        "name": indicator_set["name"],
        "short_description": indicator_set.get("summary", ""),
        "status": indicator_set.get("status", "active"),
        "confidence": float(indicator_set.get("confidence", 0.7)),
        "priority": "",
        "source_name": source["name"],
        "source_ref": _source_ref(indicator_set, indicator_set["name"]),
        "source_url": indicator_set.get("source_url", ""),
        "retrieved_at": utc_now(),
        "last_seen": indicator_set.get("last_seen", utc_now()),
        "valid_until": indicator_set.get("valid_until", ""),
        "tags": indicator_set.get("tags", []),
        "payload": {
            "summary": indicator_set.get("summary", ""),
            "indicators": indicator_set.get("indicators", []),
            "lifecycle": indicator_set.get("lifecycle", {}),
        },
    }
    return [entity], []


def normalize_tool_pack(
    source: dict[str, Any],
    tool: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Normalize one tool pack plus ATT&CK coverage relationships."""
    tool_external_id = _external_id(tool)
    source_ref = tool.get("source_ref", tool_external_id)
    technique_ids = set(tool.get("techniques", []))
    for method in tool.get("hunt_methods", []):
        technique_ids.update(method.get("techniques", []))
    entity = {
        "type": "ToolPack",
        "external_id": tool_external_id,
        "name": tool["name"],
        "short_description": tool.get("summary", ""),
        "status": tool.get("status", "active"),
        "confidence": float(tool.get("confidence", 0.7)),
        "priority": "",
        "source_name": source["name"],
        "source_ref": source_ref,
        "source_url": tool.get("source_url", ""),
        "retrieved_at": utc_now(),
        "last_seen": tool.get("last_seen", utc_now()),
        "valid_until": tool.get("valid_until", ""),
        "tags": tool.get("tags", []),
        "payload": {
            "platform": tool.get("platform", ""),
            "summary": tool.get("summary", ""),
            "execution_surface": tool.get("execution_surface", ""),
            "surface_details": tool.get("surface_details", ""),
            "service_examples": tool.get("service_examples", []),
            "references": tool.get("references", []),
            "generation": tool.get("generation", {}),
            "hunt_methods": tool.get("hunt_methods", []),
            "environment_defaults": tool.get("environment_defaults", {}),
            "template_values": tool.get("template_values", {}),
            "sigma_translation": tool.get("sigma_translation"),
            "sigma_scope": tool.get("sigma_scope"),
            "variant_of_tool_external_id": tool.get("variant_of_tool_external_id", ""),
            "variant_origin": tool.get("variant_origin", ""),
        },
    }
    relationships = [
        {
            "src_type": "ToolPack",
            "src_external_id": tool_external_id,
            "dst_type": "MitreTechnique",
            "dst_external_id": technique_id,
            "rel_type": "COVERS",
            "weight": 1.0,
            "confidence": float(tool.get("confidence", 0.7)),
            "status": tool.get("status", "active"),
            "source_name": source["name"],
            "source_ref": source_ref,
            "context": {"origin": "json_feed"},
            "first_seen": utc_now(),
            "last_seen": tool.get("last_seen", utc_now()),
            "valid_until": tool.get("valid_until", ""),
        }
        for technique_id in sorted(technique_ids)
    ]
    return [entity], relationships


def normalize_addon_pack(
    source: dict[str, Any],
    addon: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Normalize one addon pack plus target extension relationships."""
    addon_external_id = _external_id(addon)
    source_ref = addon.get("source_ref", addon_external_id)
    entity = {
        "type": "AddonPack",
        "external_id": addon_external_id,
        "name": addon["name"],
        "short_description": addon.get("summary", ""),
        "status": addon.get("status", "active"),
        "confidence": float(addon.get("confidence", 0.7)),
        "priority": addon.get("priority", ""),
        "source_name": source["name"],
        "source_ref": source_ref,
        "source_url": addon.get("source_url", ""),
        "retrieved_at": utc_now(),
        "last_seen": addon.get("last_seen", utc_now()),
        "valid_until": addon.get("valid_until", ""),
        "tags": addon.get("tags", []),
        "payload": {
            "environment_scope": addon.get("environment_scope", ""),
            "precedence": addon.get("precedence", "source_update"),
            "merge_mode": addon.get("merge_mode", "extend"),
            "target_tool_ids": addon.get("target_tool_ids", []),
            "target_threat_ids": addon.get("target_threat_ids", []),
            "environment_defaults": addon.get("environment_defaults", {}),
            "template_values": addon.get("template_values", {}),
            "additional_methods": addon.get("additional_methods", []),
        },
    }
    relationships = [
        {
            "src_type": "AddonPack",
            "src_external_id": addon_external_id,
            "dst_type": "ToolPack",
            "dst_external_id": target_tool_id,
            "rel_type": "EXTENDS",
            "weight": 1.0,
            "confidence": float(addon.get("confidence", 0.7)),
            "status": addon.get("status", "active"),
            "source_name": source["name"],
            "source_ref": source_ref,
            "context": {"origin": "json_feed", "target_type": "ToolPack"},
            "first_seen": utc_now(),
            "last_seen": addon.get("last_seen", utc_now()),
            "valid_until": addon.get("valid_until", ""),
        }
        for target_tool_id in addon.get("target_tool_ids", [])
    ]
    relationships.extend(
        {
            "src_type": "AddonPack",
            "src_external_id": addon_external_id,
            "dst_type": "ThreatProfile",
            "dst_external_id": target_threat_id,
            "rel_type": "EXTENDS",
            "weight": 1.0,
            "confidence": float(addon.get("confidence", 0.7)),
            "status": addon.get("status", "active"),
            "source_name": source["name"],
            "source_ref": source_ref,
            "context": {"origin": "json_feed", "target_type": "ThreatProfile"},
            "first_seen": utc_now(),
            "last_seen": addon.get("last_seen", utc_now()),
            "valid_until": addon.get("valid_until", ""),
        }
        for target_threat_id in addon.get("target_threat_ids", [])
    )
    return [entity], relationships


def normalize_placeholder_techniques(
    source: dict[str, Any],
    *,
    existing_entities: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    store: Any = None,
    create_mitre_placeholders: bool = True,
) -> list[dict[str, Any]]:
    """Create placeholder MITRE entities for referenced-but-missing techniques."""
    if not create_mitre_placeholders:
        return []
    referenced_techniques = {
        rel["dst_external_id"]
        for rel in relationships
        if rel["dst_type"] == "MitreTechnique"
    }
    existing_techniques = {
        entity["external_id"]
        for entity in existing_entities
        if entity["type"] == "MitreTechnique"
    }
    placeholders: list[dict[str, Any]] = []
    for technique_id in sorted(referenced_techniques - existing_techniques):
        existing = store.get_entity_by_external_id("MitreTechnique", technique_id) if store else None
        if (
            existing is not None
            and existing.get("status") != "placeholder"
            and "placeholder" not in existing.get("tags", [])
        ):
            continue
        placeholders.append(
            {
                "type": "MitreTechnique",
                "external_id": technique_id,
                "name": technique_id,
                "short_description": "Placeholder technique created from local threat/tool module references.",
                "status": "placeholder",
                "confidence": 0.35,
                "priority": "",
                "source_name": source["name"],
                "source_ref": technique_id,
                "source_url": "",
                "retrieved_at": utc_now(),
                "last_seen": utc_now(),
                "valid_until": "",
                "tags": ["placeholder", "mitre"],
                "payload": {
                    "technique_id": technique_id,
                    "parent_technique_id": technique_id.split(".", 1)[0],
                    "is_subtechnique": "." in technique_id,
                },
            }
        )
    return placeholders
