"""Shared helpers for HUNTER unittest coverage."""

from __future__ import annotations

import json
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from hunter.models.knowledge_store import KnowledgeStore


def create_temp_project() -> tempfile.TemporaryDirectory[str]:
    tempdir = tempfile.TemporaryDirectory()
    root = Path(tempdir.name)
    (root / "modules" / "threats").mkdir(parents=True, exist_ok=True)
    (root / "modules" / "tools").mkdir(parents=True, exist_ok=True)
    (root / "modules" / "mitre").mkdir(parents=True, exist_ok=True)
    return tempdir


def make_store(project_root: str | Path) -> KnowledgeStore:
    return KnowledgeStore.open_bootstrapped(str(project_root))


def seed_technique(
    store: KnowledgeStore,
    *,
    external_id: str = "T1001",
    name: str = "Data Obfuscation",
    description: str = "Example ATT&CK technique.",
) -> int:
    return store.upsert_entity(
        entity_type="MitreTechnique",
        external_id=external_id,
        name=name,
        short_description=description,
        source_name="MITRE ATT&CK Enterprise",
        source_ref=external_id,
        source_url=f"https://attack.mitre.org/techniques/{external_id}/",
        payload={
            "technique_id": external_id,
            "description": description,
            "description_blocks": [{"type": "paragraph", "text": description}],
            "detection": "Example detection guidance.",
            "detection_blocks": [{"type": "paragraph", "text": "Example detection guidance."}],
            "platforms": ["Windows"],
            "tactics": ["Execution"],
            "data_sources": ["Process monitoring"],
        },
    )


def seed_threat(store: KnowledgeStore, *, technique_id: str = "T1001") -> int:
    threat_id = store.upsert_entity(
        entity_type="ThreatProfile",
        external_id="apt_test",
        name="APT Test",
        short_description="Synthetic threat for unit tests.",
        payload={
            "summary": "Synthetic threat for unit tests.",
            "aliases": ["APT Unit"],
            "mitre_techniques": [technique_id],
            "indicators": [{"type": "domain", "value": "evil.example"}],
            "extra_hunts": ["Pivot on outbound traffic."],
            "references": ["https://example.test/report"],
        },
    )
    technique = store.get_entity_by_external_id("MitreTechnique", technique_id)
    assert technique is not None
    store.upsert_relationship(
        src_entity_id=threat_id,
        dst_entity_id=technique["id"],
        rel_type="USES",
        source_name="Layered Local Modules",
        source_ref=f"threats/apt_test.json::{technique_id}",
        weight=1.0,
        confidence=0.9,
        context={"origin": "test"},
    )
    return threat_id


def seed_tool(
    store: KnowledgeStore,
    *,
    external_id: str = "aws_hunting",
    name: str = "AWS Hunting",
    technique_ids: list[str] | None = None,
    sigma_translation: dict[str, Any] | None = None,
    sigma_scope: dict[str, Any] | None = None,
) -> int:
    technique_ids = technique_ids or ["T1001"]
    hunt_methods: list[dict[str, Any]] = []
    for technique_id in technique_ids:
        hunt_methods.append(
            {
                "title": f"{technique_id} Hunt",
                "techniques": [technique_id],
                "template": "fields @timestamp, eventName | filter destination.domain = '<DOMAIN_IOC>'",
                "supported_ioc_types": ["domain"],
                "required_placeholders": ["<DOMAIN_IOC>"],
                "output_format": "query",
                "execution_surface": "CloudWatch Logs Insights",
                "surface_details": "CloudTrail-backed log hunting",
                "service_examples": ["CloudTrail"],
                "prerequisites": ["CloudTrail enabled"],
                "noise_level": "medium",
                "privilege_required": "user",
                "time_cost": 2,
                "data_sources": ["CloudTrail"],
                "expectation": f"Surface {technique_id} evidence in AWS telemetry.",
                "method_strength": "primary_hunt",
                "method_kind": "behavior_hunt",
                "strength_reason": "Primary hunt because it directly validates the behavior in AWS telemetry.",
                "behavior_focus": f"Validate ATT&CK behavior for {technique_id} in AWS control-plane or log telemetry.",
            }
        )
    return store.upsert_entity(
        entity_type="ToolPack",
        external_id=external_id,
        name=name,
        short_description="Synthetic tool pack for unit tests.",
        payload={
            "summary": "Synthetic tool pack for unit tests.",
            "platform": "AWS",
            "execution_surface": "CloudWatch Logs Insights",
            "surface_details": "CloudTrail-backed log hunting",
            "service_examples": ["CloudTrail"],
            "environment_defaults": {"AWS_LOG_SOURCE": "CloudTrail"},
            "template_values": {},
            "sigma_translation": sigma_translation,
            "sigma_scope": sigma_scope,
            "hunt_methods": hunt_methods,
            "references": ["https://example.test/tool"],
        },
    )


def seed_sigma_rule(
    store: KnowledgeStore,
    *,
    external_id: str = "11111111-1111-1111-1111-111111111111",
    title: str = "Suspicious PowerShell Download",
    technique_ids: list[str] | None = None,
    rule_path: str = "rules/windows/process_creation/test_sigma_rule.yml",
    status: str = "stable",
    level: str = "medium",
    raw_yaml: str | None = None,
    references: list[str] | None = None,
    logsource: dict[str, Any] | None = None,
    fields: list[str] | None = None,
) -> int:
    technique_ids = technique_ids or ["T1001"]
    attack_tags = [f"attack.{technique_id.lower()}" for technique_id in technique_ids]
    references = references or ["https://example.test/sigma"]
    logsource = logsource or {"product": "windows", "category": "process_creation"}
    raw_yaml = raw_yaml or (
        f"title: {title}\n"
        f"id: {external_id}\n"
        f"status: {status}\n"
        f"level: {level}\n"
        "tags:\n"
        + "".join(f"  - attack.{technique_id.lower()}\n" for technique_id in technique_ids)
        + "logsource:\n"
        + "".join(f"  {key}: {value}\n" for key, value in logsource.items())
        + "detection:\n"
        + "  selection:\n"
        + "    Image|endswith: '\\\\powershell.exe'\n"
        + "    CommandLine|contains:\n"
        + "      - DownloadString\n"
        + "      - http\n"
        + "  condition: selection\n"
    )

    entity_id = store.upsert_entity(
        entity_type="SigmaRule",
        external_id=external_id,
        name=title,
        short_description=title,
        source_name="SigmaHQ Rules",
        source_ref=rule_path,
        source_url=f"https://raw.githubusercontent.com/SigmaHQ/sigma/master/{rule_path}",
        payload={
            "rule_uuid": external_id,
            "title": title,
            "status": status,
            "level": level,
            "summary": title,
            "description": "",
            "references": references,
            "tags": attack_tags,
            "attack_tags": attack_tags,
            "attack_techniques": technique_ids,
            "fields": fields or [],
            "logsource": logsource,
            "source_family": str(
                (logsource or {}).get("product")
                or (logsource or {}).get("service")
                or (logsource or {}).get("category")
                or ""
            ).strip().lower(),
            "repo_path": rule_path,
            "repo_url": "https://github.com/SigmaHQ/sigma",
            "raw_rule_url": f"https://raw.githubusercontent.com/SigmaHQ/sigma/master/{rule_path}",
            "raw_yaml": raw_yaml,
            "last_modified": "2026-01-01T00:00:00Z",
        },
    )

    for technique_id in technique_ids:
        technique = store.get_entity_by_external_id("MitreTechnique", technique_id)
        assert technique is not None
        store.upsert_relationship(
            src_entity_id=entity_id,
            dst_entity_id=technique["id"],
            rel_type="DETECTS",
            source_name="SigmaHQ Rules",
            source_ref=f"{rule_path}::{technique_id}",
            weight=1.0,
            confidence=0.9,
            context={"origin": "test"},
        )
    return entity_id


def write_sigma_archive(
    root: Path,
    *,
    files: dict[str, str],
    filename: str = "sigmahq_rules.zip",
) -> Path:
    archive_path = root / filename
    with zipfile.ZipFile(archive_path, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative_path, content in files.items():
            archive.writestr(relative_path, content)
    return archive_path


def write_threat_module(root: Path, *, technique_ids: list[str] | None = None) -> Path:
    technique_ids = technique_ids or ["T1001"]
    payload = {
        "external_id": "apt_test",
        "name": "APT Test",
        "summary": "Synthetic threat for layered sync tests.",
        "aliases": ["APT Unit"],
        "techniques": technique_ids,
        "indicators": [{"type": "domain", "value": "evil.example"}],
        "references": ["https://example.test/report"],
        "extra_hunts": ["Pivot on outbound traffic."],
        "status": "active",
        "tags": ["test"],
    }
    path = root / "modules" / "threats" / "apt_test.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_tool_module(
    root: Path,
    *,
    external_id: str = "aws_hunting",
    name: str = "AWS Hunting",
    platform: str = "AWS",
    technique_ids: list[str] | None = None,
    coverage_mode: str = "full_matrix",
) -> Path:
    technique_ids = technique_ids or ["T1001"]
    hunt_methods: list[dict[str, Any]] = []
    for technique_id in technique_ids:
        hunt_methods.append(
            {
                "title": f"{technique_id} Behavior Hunt",
                "techniques": [technique_id],
                "template": "fields @timestamp, eventName | filter destination.domain = '<DOMAIN_IOC>'",
                "supported_ioc_types": ["domain"],
                "required_placeholders": ["<DOMAIN_IOC>"],
                "output_format": "query",
                "execution_surface": "CloudWatch Logs Insights",
                "surface_details": "CloudTrail-backed log hunting",
                "service_examples": ["CloudTrail"],
                "prerequisites": ["CloudTrail enabled"],
                "noise_level": "medium",
                "privilege_required": "user",
                "time_cost": 2,
                "data_sources": ["CloudTrail"],
                "expectation": f"Surface {technique_id} evidence in AWS telemetry.",
                "method_strength": "primary_hunt",
                "method_kind": "behavior_hunt",
                "strength_reason": "Primary hunt because it isolates tool-native behavior in AWS telemetry.",
                "behavior_focus": f"Validate {technique_id} through AWS log evidence and operator pivots.",
            }
        )
        hunt_methods.append(
            {
                "title": f"{technique_id} IOC Pivot",
                "techniques": [technique_id],
                "template": "fields @timestamp, eventName | filter destination.domain = '<DOMAIN_IOC>'",
                "supported_ioc_types": ["domain"],
                "required_placeholders": ["<DOMAIN_IOC>"],
                "output_format": "query",
                "execution_surface": "CloudWatch Logs Insights",
                "surface_details": "CloudTrail-backed log hunting",
                "service_examples": ["CloudTrail"],
                "prerequisites": ["CloudTrail enabled"],
                "noise_level": "medium",
                "privilege_required": "user",
                "time_cost": 2,
                "data_sources": ["CloudTrail"],
                "expectation": f"Pivot from known indicators into {technique_id} activity.",
                "method_strength": "supporting_pivot",
                "method_kind": "ioc_pivot",
                "strength_reason": "Supporting pivot because it helps scope known indicators but should trail stronger behavior hunts.",
                "behavior_focus": f"Use indicator hits to pivot into surrounding evidence for {technique_id}.",
            }
        )
    payload = {
        "external_id": external_id,
        "name": name,
        "summary": "Synthetic tool module for layered sync tests.",
        "status": "active",
        "tags": ["test", "authored"],
        "platform": platform,
        "execution_surface": "CloudWatch Logs Insights",
        "surface_details": "CloudTrail-backed log hunting",
        "service_examples": ["CloudTrail"],
        "references": ["https://example.test/tool"],
        "generation": {
            "compiler": "modules_tools_authored_v1",
            "coverage_mode": coverage_mode,
            "coverage_policy": "quality_first_full" if coverage_mode == "full_matrix" else "quality_first_partial",
            "coverage_scope": (
                "enterprise_attack_full_matrix"
                if coverage_mode == "full_matrix"
                else "enterprise_attack_partial_specialist"
            ),
            "coverage_summary": "Synthetic authored tool coverage for unit tests.",
            "applicability": {},
            "strength_counts": {
                "primary_hunt": len(
                    [method for method in hunt_methods if method["method_strength"] == "primary_hunt"]
                ),
                "supporting_pivot": len(
                    [method for method in hunt_methods if method["method_strength"] == "supporting_pivot"]
                ),
            },
            "technique_count": len(technique_ids),
            "catalog_technique_count": len(technique_ids),
        },
        "environment_defaults": {"AWS_LOG_SOURCE": "CloudTrail"},
        "template_values": {},
        "hunt_methods": hunt_methods,
    }
    path = root / "modules" / "tools" / f"{external_id}.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path
