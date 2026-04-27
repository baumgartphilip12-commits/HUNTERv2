"""Readable HTML entity detail renderers for the PySide6 shell.

QTextBrowser supports a constrained HTML/CSS subset, so these helpers generate
simple table-backed sections and chunked chips instead of relying on modern web
layout features.  All entity/module data is escaped before insertion.
"""

from __future__ import annotations

import html
from typing import Any

from hunter.qt.formatting import json_preview


PAYLOAD_PREVIEW_LIMIT = 5000


def _escape(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _normalize_payload(entity: dict[str, Any]) -> dict[str, Any]:
    payload = entity.get("payload", {})
    return payload if isinstance(payload, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _label(value: str) -> str:
    return str(value or "").replace("_", " ")


def _html_document(body: list[str]) -> str:
    return (
        "<html><head><style>"
        "body{background:#101721;color:#f0f6ff;font-family:'Segoe UI',sans-serif;font-size:11pt;}"
        "h1{color:#fff;font-size:23px;margin:0 0 8px 0;}"
        "h2{color:#8ee8f7;font-size:17px;margin:0 0 10px 0;}"
        "p{line-height:1.55;margin:8px 0 10px 0;}"
        ".muted{color:#b8c8dc;}"
        ".card{background:#151d29;border:1px solid #3c4d64;border-radius:6px;margin:0 0 14px 0;padding:14px;}"
        ".chips{margin:8px 0 10px 0;}"
        ".chip{background:#243246;color:#f0f6ff;border:1px solid #5a6f8c;border-radius:8px;"
        "padding:5px 10px;font-size:10pt;font-weight:600;}"
        ".chip.mitre{background:#0d4f70;color:#e6fbff;border-color:#24c7e5;}"
        ".chip.success{background:#1d4a32;color:#c7ffd8;border-color:#4da76d;}"
        ".chip.warning{background:#4a321c;color:#ffe0a8;border-color:#b57a31;}"
        "table{border-collapse:collapse;width:100%;margin-top:6px;font-size:10.5pt;}"
        "td{border-bottom:1px solid #34445a;padding:7px 8px;vertical-align:top;}"
        "td.key{color:#c5d9f2;width:32%;font-weight:700;}"
        "ul{margin:8px 0 10px 22px;padding:0;line-height:1.45;}"
        "pre{white-space:pre-wrap;background:#0f1620;border:1px solid #29374a;border-radius:4px;"
        "padding:10px;color:#f0f6ff;font-family:Consolas,monospace;font-size:9.5pt;}"
        "a{color:#8ee8f7;}"
        "</style></head><body>"
        + "\n".join(body)
        + "</body></html>"
    )


def _section(title: str, description: str = "", *parts: str) -> str:
    content = [f"<h2>{_escape(title)}</h2>"]
    if description:
        content.append(f"<p class=\"muted\">{_escape(description)}</p>")
    content.extend(part for part in parts if part)
    return "<div class=\"card\">" + "\n".join(content) + "</div>"


def _chunked(values: list[str], size: int) -> list[list[str]]:
    return [values[index : index + size] for index in range(0, len(values), size)]


def _chips(values: list[Any], *, tone: str = "") -> str:
    """Render bounded chip tables that wrap long labels inside each cell."""

    cleaned = [str(value).strip() for value in values if str(value).strip()]
    if not cleaned:
        return ""
    klass = f"chip {tone}".strip()
    per_row = 4 if tone == "mitre" else 6
    width = max(1, 100 // per_row)
    rows = []
    for row_values in _chunked(cleaned, per_row):
        cells = "".join(
            f"<td class=\"{klass}\" width=\"{width}%\">{_escape(value)}</td>"
            for value in row_values
        )
        rows.append(f"<tr>{cells}</tr>")
    return (
        "<table class=\"chips\" width=\"100%\" cellspacing=\"6\" cellpadding=\"0\">"
        + "".join(rows)
        + "</table>"
    )


def _table(rows: list[tuple[str, Any]]) -> str:
    visible = [(key, value) for key, value in rows if str(value if value is not None else "").strip()]
    if not visible:
        return ""
    cells = [
        f"<tr><td class=\"key\">{_escape(key)}</td><td>{_format_value(value)}</td></tr>"
        for key, value in visible
    ]
    return "<table>" + "".join(cells) + "</table>"


def _format_value(value: Any) -> str:
    text = str(value if value is not None else "")
    if text.startswith(("https://", "http://")):
        escaped = _escape(text)
        return f"<a href=\"{escaped}\">{escaped}</a>"
    return _escape(value)


def _bullets(values: list[Any]) -> str:
    cleaned = [str(value).strip() for value in values if str(value).strip()]
    if not cleaned:
        return ""
    return "<ul>" + "".join(f"<li>{_format_value(value)}</li>" for value in cleaned) + "</ul>"


def _paragraph(value: Any, *, muted: bool = False) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    klass = " class=\"muted\"" if muted else ""
    return f"<p{klass}>{_escape(text)}</p>"


def _code(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return f"<pre>{_escape(text)}</pre>"


def _rich_blocks(blocks: list[Any], fallback: Any = "") -> str:
    rendered: list[str] = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        block_type = str(block.get("type", "paragraph"))
        text = block.get("text", "")
        if block_type in {"bullet", "list_item"}:
            rendered.append(_bullets([text]))
        elif block_type == "code":
            rendered.append(_code(text))
        else:
            rendered.append(_paragraph(text))
    if rendered:
        return "\n".join(rendered)
    return _paragraph(fallback)


def _technique_label(store: Any, technique_id: str) -> str:
    technique = store.get_entity_by_external_id("MitreTechnique", technique_id)
    if technique:
        return f"{technique_id} - {technique.get('name', 'Untitled')}"
    return technique_id


def _related(entity: dict[str, Any], store: Any) -> dict[str, list[dict[str, Any]]]:
    entity_id = entity.get("id")
    if entity_id is None:
        return {}
    try:
        return store.get_related_entities(int(entity_id))
    except Exception:
        return {}


def _sigma_rule_refs(sigma_rule_service: Any, techniques: list[str]) -> list[dict[str, Any]]:
    if sigma_rule_service is None or not techniques:
        return []
    try:
        return list(sigma_rule_service.matching_rule_refs(techniques))
    except Exception:
        return []


def _tool_sigma_summary(
    sigma_rule_service: Any,
    tool: dict[str, Any],
    techniques: list[str],
) -> dict[str, Any]:
    if sigma_rule_service is None:
        return {}
    try:
        return dict(sigma_rule_service.summarize_tool_coverage(tool, techniques))
    except Exception:
        return {}


class EntityDetailRenderer:
    """Build readable, escaped HTML for entity detail panes."""

    @staticmethod
    def render(entity: dict[str, Any], store: Any, sigma_rule_service: Any = None) -> str:
        payload = _normalize_payload(entity)
        body = [
            _section(
                entity.get("name") or entity.get("external_id") or "Untitled",
                entity.get("type", ""),
                _paragraph(payload.get("description") or payload.get("summary") or entity.get("short_description")),
                _chips(
                    [
                        entity.get("external_id", ""),
                        entity.get("status", "active"),
                        entity.get("source_name", "local"),
                    ]
                ),
                _chips(_as_list(entity.get("tags"))),
                _table(
                    [
                        ("Source Ref", entity.get("source_ref", "") or "N/A"),
                        ("Source URL", entity.get("source_url", "") or "N/A"),
                    ]
                ),
            )
        ]
        entity_type = entity.get("type", "")
        if entity_type == "MitreTechnique":
            body.extend(EntityDetailRenderer._render_mitre(entity, payload, store))
        elif entity_type == "ThreatProfile":
            body.extend(EntityDetailRenderer._render_threat(entity, payload, store, sigma_rule_service))
        elif entity_type == "ToolPack":
            body.extend(EntityDetailRenderer._render_tool(entity, payload, store, sigma_rule_service))
        body.append(
            _section(
                "Structured Payload Preview",
                "Raw payload is capped to keep large records responsive.",
                _code(json_preview(payload, limit=PAYLOAD_PREVIEW_LIMIT)),
            )
        )
        return _html_document(body)

    @staticmethod
    def _render_mitre(entity: dict[str, Any], payload: dict[str, Any], store: Any) -> list[str]:
        sections = [
            _section(
                "ATT&CK Metadata",
                "Core ATT&CK fields used for analyst orientation.",
                _table(
                    [
                        ("ATT&CK ID", payload.get("technique_id") or entity.get("external_id")),
                        ("ATT&CK URL", entity.get("source_url", "")),
                        ("Parent Technique", payload.get("parent_technique_id") or "N/A"),
                        ("Created", payload.get("created") or "Unknown"),
                        ("Modified", payload.get("modified") or "Unknown"),
                        ("Sub-technique", "Yes" if payload.get("is_subtechnique") else "No"),
                    ]
                ),
            ),
            _section(
                "Technique Description",
                "Narrative ATT&CK guidance with preserved paragraph text.",
                _rich_blocks(_as_list(payload.get("description_blocks")), payload.get("description") or entity.get("short_description")),
            ),
            _section(
                "Detection Notes",
                "ATT&CK detection guidance and validation notes.",
                _rich_blocks(_as_list(payload.get("detection_blocks")), payload.get("detection")),
            ),
        ]
        for title, key, tone in (
            ("Tactics", "tactics", "mitre"),
            ("Platforms", "platforms", "mitre"),
            ("Data Sources", "data_sources", ""),
            ("Permissions Required", "permissions_required", "warning"),
            ("Defenses Bypassed", "defenses_bypassed", "warning"),
        ):
            values = _as_list(payload.get(key))
            if values:
                sections.append(_section(title, "", _chips(values, tone=tone)))
        if payload.get("references"):
            sections.append(_section("ATT&CK References", "", _bullets(_as_list(payload.get("references")))))
        sigma_related = _related(entity, store).get("SigmaRule", [])
        if sigma_related:
            sections.append(
                _section(
                    "Linked Sigma Rules",
                    "Official SigmaHQ rules mapped to this ATT&CK technique.",
                    _table([("Matching Sigma Rules", len(sigma_related))]),
                    _bullets([f"{item.get('name')} ({item.get('external_id')})" for item in sigma_related[:12]]),
                )
            )
        return sections

    @staticmethod
    def _render_threat(
        entity: dict[str, Any],
        payload: dict[str, Any],
        store: Any,
        sigma_rule_service: Any,
    ) -> list[str]:
        sections: list[str] = []
        aliases = _as_list(payload.get("aliases"))
        if aliases:
            sections.append(_section("Aliases", "Known alternate names and cluster labels.", _chips(aliases)))
        techniques = [str(value) for value in _as_list(payload.get("mitre_techniques") or payload.get("techniques"))]
        if techniques:
            unresolved = [
                technique_id
                for technique_id in techniques
                if store.get_entity_by_external_id("MitreTechnique", technique_id) is None
            ]
            sections.append(
                _section(
                    "Mapped ATT&CK Techniques",
                    "Techniques this threat contributes to hunt generation.",
                    _table(
                        [
                            ("Technique Count", len(techniques)),
                            ("Resolved", max(len(techniques) - len(unresolved), 0)),
                            ("Unresolved", len(unresolved)),
                        ]
                    ),
                    _chips([_technique_label(store, technique_id) for technique_id in techniques], tone="mitre"),
                )
            )
            if unresolved:
                sections.append(_section("Unresolved ATT&CK Links", "", _chips(unresolved, tone="warning")))
        indicators = [
            f"{item.get('type', 'unknown')}: {item.get('value', '')}"
            for item in _as_list(payload.get("indicators"))
            if isinstance(item, dict)
        ]
        if indicators:
            sections.append(_section("Threat Indicators", "Indicators stored on this threat module.", _bullets(indicators)))
        if payload.get("extra_hunts"):
            sections.append(_section("Analyst Hunt Prompts", "", _bullets(_as_list(payload.get("extra_hunts")))))
        if payload.get("references"):
            sections.append(_section("References", "", _bullets(_as_list(payload.get("references")))))
        sigma_refs = _sigma_rule_refs(sigma_rule_service, techniques)
        if sigma_refs:
            mapped = sorted({tech for ref in sigma_refs for tech in ref.get("techniques", [])})
            sections.append(
                _section(
                    "Sigma Coverage",
                    "SigmaHQ rules overlapping this threat through ATT&CK mappings.",
                    _table([("Matching Sigma Rules", len(sigma_refs)), ("Mapped Techniques", len(mapped))]),
                    _bullets([f"{rule.get('name')} ({rule.get('external_id')})" for rule in sigma_refs[:10]]),
                )
            )
        return sections

    @staticmethod
    def _render_tool(
        entity: dict[str, Any],
        payload: dict[str, Any],
        store: Any,
        sigma_rule_service: Any,
    ) -> list[str]:
        sections: list[str] = []
        variant_of = payload.get("variant_of_tool_external_id", "")
        variant_origin = payload.get("variant_origin", "")
        if variant_of or variant_origin:
            sections.append(
                _section(
                    "Variant Status",
                    "Modified variants branch from a base tool.",
                    _table([("Variant Of", variant_of or "N/A"), ("Origin", variant_origin or "local_variant")]),
                )
            )
        generation = payload.get("generation", {}) if isinstance(payload.get("generation"), dict) else {}
        sections.append(
            _section(
                "Execution Surface",
                "The exact interface or hunting surface the operator will use.",
                _table(
                    [
                        ("Platform", payload.get("platform") or "Unknown"),
                        ("Execution Surface", payload.get("execution_surface") or entity.get("name")),
                        ("Surface Details", payload.get("surface_details") or "No extra surface notes recorded."),
                        ("Coverage Model", _label(generation.get("coverage_mode") or "custom / local")),
                    ]
                ),
                _chips(_as_list(payload.get("service_examples")), tone="success"),
                _paragraph(generation.get("coverage_summary")),
            )
        )
        if payload.get("environment_defaults") or payload.get("template_values"):
            default_rows = []
            for key, value in dict(payload.get("environment_defaults") or {}).items():
                default_rows.append((str(key), value))
            for key, value in dict(payload.get("template_values") or {}).items():
                default_rows.append((str(key), value))
            sections.append(_section("Tool-Level Defaults", "Values that can resolve hunt placeholders.", _table(default_rows)))
        methods = [method for method in _as_list(payload.get("hunt_methods")) if isinstance(method, dict)]
        technique_ids = sorted({tech for method in methods for tech in _as_list(method.get("techniques"))})
        sigma_summary = _tool_sigma_summary(sigma_rule_service, entity, technique_ids)
        translation = sigma_summary.get("translation", {}) if isinstance(sigma_summary.get("translation"), dict) else {}
        mode = "Translation Enabled" if sigma_summary.get("mode") == "translation_enabled" else "Reference Only"
        sections.append(
            _section(
                "Sigma Translation",
                "SigmaHQ coverage can supplement authored hunts when configured.",
                _table(
                    [
                        ("Mode", mode),
                        ("Backend", translation.get("backend") or "Not configured"),
                        ("Matching Sigma Rules", sigma_summary.get("rule_count", 0)),
                        ("Matched Techniques", len(_as_list(sigma_summary.get("matched_techniques")))),
                    ]
                ),
                _chips(
                    [_technique_label(store, str(technique_id)) for technique_id in _as_list(sigma_summary.get("matched_techniques"))[:12]],
                    tone="mitre",
                ),
                _bullets([f"{rule.get('name')} ({rule.get('external_id')})" for rule in _as_list(sigma_summary.get("rule_preview"))[:8]]),
            )
        )
        if methods:
            primary_count = len([method for method in methods if method.get("method_strength") == "primary_hunt"])
            supporting_count = len([method for method in methods if method.get("method_strength") == "supporting_pivot"])
            sections.append(
                _section(
                    "Hunt Methods",
                    "Product-specific hunt methods aligned to ATT&CK techniques.",
                    _chips(
                        [
                            f"Methods: {len(methods)}",
                            f"Technique Coverage: {len(technique_ids)}",
                            f"Primary Hunts: {primary_count}",
                            f"Supporting Pivots: {supporting_count}",
                        ],
                        tone="success",
                    ),
                    _bullets(
                        [
                            " - ".join(
                                part
                                for part in (
                                    method.get("title", "Untitled"),
                                    ", ".join(str(value) for value in _as_list(method.get("techniques"))),
                                    _label(method.get("method_strength", "")),
                                    _label(method.get("method_kind", "")),
                                )
                                if part
                            )
                            for method in methods[:12]
                        ]
                    ),
                )
            )
        else:
            sections.append(_section("Hunt Methods", "", _paragraph("No hunt methods are defined yet.", muted=True)))
        return sections
