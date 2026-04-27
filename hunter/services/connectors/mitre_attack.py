"""MITRE ATT&CK sync connector."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone

from hunter.models.knowledge_store import utc_now
from hunter.runtime_paths import repo_relative_path, resolve_repo_path
from hunter.services.connectors.base import BaseConnector
from hunter.services.connectors.common import (
    attack_text_blocks,
    attack_text_html,
    clean_attack_markup,
    short_attack_summary,
)


class MitreAttackConnector(BaseConnector):
    """Connector for ATT&CK enterprise technique taxonomy."""

    name = "mitre_attack"

    def build_dataset(self, source: dict) -> dict:
        config = source.get("config", {})
        raw, bundle_label, last_modified = self._load_bundle(config)

        bundle = json.loads(raw)
        objects = bundle.get("objects", [])

        entities: list[dict] = []
        relationships: list[dict] = []

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            ext_id = self._external_attack_id(obj)
            if not ext_id:
                continue
            is_sub = bool(obj.get("x_mitre_is_subtechnique")) or "." in ext_id
            parent_ext = ext_id.split(".", 1)[0] if is_sub else ext_id
            source_url = self._technique_url(ext_id)
            raw_description = obj.get("description", "")
            raw_detection = obj.get("x_mitre_detection", "")
            description_blocks = attack_text_blocks(raw_description)
            detection_blocks = attack_text_blocks(raw_detection)
            entities.append(
                {
                    "type": "MitreTechnique",
                    "external_id": ext_id,
                    "name": obj.get("name", ext_id),
                    "short_description": short_attack_summary(raw_description),
                    "status": self._status(obj),
                    "confidence": 0.95,
                    "priority": "",
                    "source_name": source["name"],
                    "source_ref": obj.get("id", ext_id),
                    "source_url": source_url,
                    "retrieved_at": utc_now(),
                    "last_seen": obj.get("modified", last_modified),
                    "valid_until": "",
                    "tags": obj.get("x_mitre_domains", []),
                    "payload": {
                        "technique_id": ext_id,
                        "stix_id": obj.get("id", ""),
                        "description": clean_attack_markup(raw_description),
                        "description_html": attack_text_html(description_blocks),
                        "description_blocks": description_blocks,
                        "is_subtechnique": is_sub,
                        "parent_technique_id": parent_ext,
                        "tactics": [
                            phase.get("phase_name", "").replace("-", " ").title()
                            for phase in obj.get("kill_chain_phases", [])
                            if phase.get("phase_name")
                        ],
                        "platforms": obj.get("x_mitre_platforms", []),
                        "data_sources": obj.get("x_mitre_data_sources", []),
                        "detection": clean_attack_markup(raw_detection),
                        "detection_html": attack_text_html(detection_blocks),
                        "detection_blocks": detection_blocks,
                        "permissions_required": obj.get("x_mitre_permissions_required", []),
                        "defenses_bypassed": obj.get("x_mitre_defense_bypassed", []),
                        "system_requirements": obj.get("x_mitre_system_requirements", []),
                        "effective_permissions": obj.get("x_mitre_effective_permissions", []),
                        "impact_type": obj.get("x_mitre_impact_type", []),
                        "remote_support": obj.get("x_mitre_remote_support", False),
                        "modified": obj.get("modified", ""),
                        "created": obj.get("created", ""),
                        "kill_chain_phases": obj.get("kill_chain_phases", []),
                        "references": obj.get("external_references", []),
                    },
                }
            )

        for entity in entities:
            if entity["type"] != "MitreTechnique":
                continue
            ext_id = entity["external_id"]
            if "." not in ext_id:
                continue
            parent_ext = ext_id.split(".", 1)[0]
            relationships.append(
                {
                    "src_type": "MitreTechnique",
                    "src_external_id": ext_id,
                    "dst_type": "MitreTechnique",
                    "dst_external_id": parent_ext,
                    "rel_type": "CHILD_OF",
                    "weight": 1.0,
                    "confidence": 0.95,
                    "status": "confirmed",
                    "source_name": source["name"],
                    "source_ref": f"{ext_id}->{parent_ext}",
                    "context": {"origin": "mitre_hierarchy"},
                    "first_seen": utc_now(),
                    "last_seen": utc_now(),
                    "valid_until": "",
                }
            )

        return {
            "source_name": source["name"],
            "connector": self.name,
            "fetched_at": utc_now(),
            "metadata": {
                "bundle_url": config.get("bundle_url", ""),
                "bundle": bundle_label,
                "bundle_id": bundle.get("id", ""),
                "bundle_modified": last_modified,
                "object_count": len(objects),
            },
            "entities": entities,
            "relationships": relationships,
        }

    @staticmethod
    def _load_bundle(config: dict) -> tuple[str, str, str]:
        bundle_file = str(config.get("bundle_file") or config.get("bundle_path") or "").strip()
        if bundle_file:
            path = resolve_repo_path(bundle_file)
            if not path.exists():
                raise FileNotFoundError(f"MITRE ATT&CK bundle file not found: {path}")
            return (
                path.read_text(encoding="utf-8"),
                repo_relative_path(path),
                MitreAttackConnector._file_mtime(path),
            )

        bundle_url = config.get("bundle_url")
        if not bundle_url:
            raise ValueError("MITRE source config is missing bundle_url or bundle_file")

        request = urllib.request.Request(
            bundle_url,
            headers={
                "User-Agent": "HUNTER-v2-sync",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read().decode("utf-8")
                last_modified = response.headers.get("Last-Modified", "")
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Unable to fetch MITRE ATT&CK bundle: {exc}") from exc
        return raw, str(bundle_url), last_modified

    @staticmethod
    def _file_mtime(path) -> str:
        return (
            datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            .replace(microsecond=0)
            .isoformat()
        )

    @staticmethod
    def _status(obj: dict) -> str:
        if obj.get("revoked"):
            return "revoked"
        if obj.get("x_mitre_deprecated"):
            return "deprecated"
        return "active"

    @staticmethod
    def _external_attack_id(obj: dict) -> str:
        for ref in obj.get("external_references", []):
            ext_id = ref.get("external_id", "")
            if ext_id.startswith("T"):
                return ext_id
        return ""

    @staticmethod
    def _technique_url(external_id: str) -> str:
        if "." in external_id:
            parent, child = external_id.split(".", 1)
            return f"https://attack.mitre.org/techniques/{parent}/{child}/"
        return f"https://attack.mitre.org/techniques/{external_id}/"
