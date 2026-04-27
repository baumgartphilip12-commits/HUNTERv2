"""Shared searchable document builders for knowledge entities.

Repository searches and Qt visible filters both feed these documents into the
mini-query matcher.  Keeping the mapping centralized prevents UI search from
drifting away from backend search semantics when new entity fields are added.
"""

from __future__ import annotations

from typing import Any


def entity_search_document(entity: dict[str, Any]) -> dict[str, Any]:
    """Build fielded mini-query data for one entity.

    Values may be nested lists/dicts; ``matches_search_query`` flattens them.
    The field names here are the public search grammar exposed in README
    examples, such as ``alias:``, ``indicator:``, ``platform:``, and
    ``technique:``.
    """

    payload = entity.get("payload", {}) if isinstance(entity.get("payload"), dict) else {}
    document: dict[str, Any] = {
        "id": [entity.get("id"), entity.get("external_id"), payload.get("technique_id")],
        "external_id": [entity.get("external_id"), payload.get("technique_id")],
        "name": entity.get("name"),
        "title": [entity.get("name"), payload.get("title")],
        "description": [
            entity.get("short_description"),
            payload.get("description"),
            payload.get("detection"),
        ],
        "summary": [entity.get("short_description"), payload.get("summary")],
        "tag": entity.get("tags", []),
        "status": entity.get("status"),
        "source": [entity.get("source_name"), entity.get("source_ref"), entity.get("source_url")],
    }
    entity_type = entity.get("type")
    if entity_type == "MitreTechnique":
        document.update(
            {
                "technique": [
                    entity.get("external_id"),
                    payload.get("technique_id"),
                    payload.get("parent_technique_id"),
                ],
                "attack": [entity.get("external_id"), payload.get("technique_id")],
                "mitre": [entity.get("external_id"), payload.get("technique_id")],
                "datasource": payload.get("data_sources", []),
                "platform": payload.get("platforms", []),
                "hunt": [payload.get("detection"), payload.get("detection_blocks", [])],
            }
        )
    elif entity_type == "ThreatProfile":
        document.update(
            {
                "alias": payload.get("aliases", []),
                "indicator": payload.get("indicators", []),
                "technique": payload.get("mitre_techniques", []),
                "attack": payload.get("mitre_techniques", []),
                "mitre": payload.get("mitre_techniques", []),
                "hunt": payload.get("extra_hunts", []),
                "source": [document["source"], payload.get("references", [])],
            }
        )
    elif entity_type == "ToolPack":
        methods = payload.get("hunt_methods", [])
        methods = methods if isinstance(methods, list) else []
        document.update(
            {
                "platform": payload.get("platform"),
                "surface": [payload.get("execution_surface"), payload.get("surface_details")],
                "service": payload.get("service_examples", []),
                "method": methods,
                "template": [method.get("template") for method in methods if isinstance(method, dict)],
                "ioc": [
                    value
                    for method in methods
                    if isinstance(method, dict)
                    for value in (
                        method.get("supported_ioc_types", []),
                        method.get("required_placeholders", []),
                    )
                ],
                "technique": [
                    technique
                    for method in methods
                    if isinstance(method, dict)
                    for technique in method.get("techniques", [])
                ],
                "attack": [
                    technique
                    for method in methods
                    if isinstance(method, dict)
                    for technique in method.get("techniques", [])
                ],
                "mitre": [
                    technique
                    for method in methods
                    if isinstance(method, dict)
                    for technique in method.get("techniques", [])
                ],
                "kind": [method.get("method_kind") for method in methods if isinstance(method, dict)],
                "strength": [method.get("method_strength") for method in methods if isinstance(method, dict)],
            }
        )
    elif entity_type == "SigmaRule":
        document.update(
            {
                "title": [entity.get("name"), payload.get("title")],
                "technique": payload.get("attack_techniques", []),
                "attack": payload.get("attack_tags", []),
                "mitre": payload.get("attack_techniques", []),
                "source": [document["source"], payload.get("repo_path"), payload.get("raw_rule_url")],
            }
        )
    return document
