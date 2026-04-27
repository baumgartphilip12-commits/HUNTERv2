"""Tests for the unified authoring persistence service."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from hunter.services.authoring_service import AuthoringService
from hunter.services.layered_entity_service import LayeredEntityService
from hunter.services.sync_service import SyncService
from tests.support import create_temp_project, make_store, seed_technique, seed_threat, seed_tool


class AuthoringServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_project = create_temp_project()
        self.addCleanup(self.temp_project.cleanup)
        self.root = Path(self.temp_project.name)
        self.store = make_store(self.root)
        self.sync = SyncService(self.store)
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        seed_technique(self.store, external_id="T1041", name="Exfiltration Over C2 Channel")
        self.layered_service = LayeredEntityService(self.store, self.sync, str(self.root))
        self.service = AuthoringService(self.store, self.layered_service)
        self.layered_source = self.store.get_source_by_name("Layered Local Modules")
        assert self.layered_source is not None

    def _layered_dirs(self) -> dict[str, str]:
        modules_root = self.root / "modules"
        return {
            "root": str(modules_root),
            "mitre": str(modules_root / "mitre"),
            "threats": str(modules_root / "threats"),
            "tools": str(modules_root / "tools"),
        }

    def _save_module_json(
        self,
        layer: str,
        external_id: str,
        payload: dict,
        project_dir: str | None = None,
    ) -> str:
        path = Path(self._layered_dirs()[layer]) / f"{external_id}.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return str(path)

    def test_save_entity_routes_local_addon_pack_through_service_boundary(self) -> None:
        tool_id = seed_tool(self.store, external_id="aws_hunting", technique_ids=["T1001"])
        threat_id = seed_threat(self.store, technique_id="T1041")
        tool = self.store.get_entity(tool_id)
        threat = self.store.get_entity(threat_id)
        assert tool is not None
        assert threat is not None

        entity = {
            "id": None,
            "type": "AddonPack",
            "name": "Analyst Addon",
            "external_id": "analyst_addon",
            "status": "active",
            "priority": "",
            "tags": ["local"],
            "payload": {
                "environment_scope": "aws",
                "precedence": "source_update",
                "merge_mode": "extend",
                "target_tool_ids": [tool["external_id"]],
                "target_threat_ids": [threat["external_id"]],
                "environment_defaults": {"AWS_REGION": "us-east-1"},
                "template_values": {"DOMAIN": "example.test"},
                "additional_methods": [],
            },
        }

        result = self.service.save_entity("AddonPack", entity)

        self.assertEqual(result.persistence, "local")
        self.assertIsNone(result.layered_source)
        saved = self.store.get_entity_by_external_id("AddonPack", "analyst_addon")
        self.assertIsNotNone(saved)
        relationships = self.store.list_relationships(entity_id=saved["id"], direction="out", rel_type="EXTENDS")
        self.assertEqual(
            {(rel["dst_type"], rel["dst_external_id"]) for rel in relationships},
            {("ToolPack", tool["external_id"]), ("ThreatProfile", threat["external_id"])},
        )

    def test_delete_entity_routes_layered_tool_cleanup_without_full_sync(self) -> None:
        entity = {
            "id": None,
            "type": "ToolPack",
            "name": "AWS Hunting Variant",
            "external_id": "aws_hunting__modified",
            "status": "active",
            "priority": "",
            "tags": ["aws", "variant"],
            "short_description": "Updated tool summary.",
            "payload": {
                "summary": "Updated tool summary.",
                "platform": "AWS",
                "execution_surface": "CloudWatch Logs Insights",
                "surface_details": "CloudTrail-backed log hunting",
                "service_examples": ["CloudTrail"],
                "references": ["https://example.test/tool"],
                "variant_of_tool_external_id": "aws_hunting",
                "variant_origin": "local_variant",
                "environment_defaults": {"AWS_LOG_SOURCE": "CloudTrail"},
                "template_values": {"AWS_REGION": "us-east-1"},
                "hunt_methods": [
                    {
                        "title": "New Hunt",
                        "techniques": ["T1041"],
                        "template": "fields @timestamp | filter destination.domain = '<DOMAIN_IOC>'",
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
                        "expectation": "Find suspicious exfiltration telemetry.",
                    }
                ],
            },
        }
        self.sync.apply_source = Mock(side_effect=AssertionError("apply_source should not be called"))

        with patch("hunter.services.layered_entity_service.save_layered_module_json", new=self._save_module_json):
            save_result = self.service.save_entity("ToolPack", entity)

        saved = save_result.entity
        path = self.root / "modules" / "tools" / "aws_hunting__modified.json"
        self.assertTrue(path.exists())

        delete_result = self.service.delete_entity("ToolPack", saved)

        self.assertEqual(delete_result.persistence, "layered")
        self.assertFalse(path.exists())
        retired = self.store.get_entity(saved["id"])
        self.assertEqual(retired["status"], "deprecated")
        self.assertTrue(retired["payload"]["removed_from_source"])
        self.sync.apply_source.assert_not_called()

    def test_legacy_module_records_are_not_treated_as_local_authoring(self) -> None:
        entity_id = self.store.upsert_entity(
            entity_type="AddonPack",
            external_id="legacy_addon",
            name="Legacy Addon",
            short_description="Legacy flat-module record.",
            source_name="legacy_modules",
            source_ref="legacy_addon",
            payload={"target_tool_ids": [], "target_threat_ids": []},
        )
        entity = self.store.get_entity(entity_id)
        assert entity is not None

        with self.assertRaises(PermissionError):
            self.service.delete_entity("AddonPack", entity)

    def test_legacy_module_tool_sigma_scope_is_not_editable_as_local(self) -> None:
        tool_id = self.store.upsert_entity(
            entity_type="ToolPack",
            external_id="legacy_tool",
            name="Legacy Tool",
            short_description="Legacy flat-module tool.",
            source_name="legacy_modules",
            source_ref="legacy_tool",
            payload={"summary": "Legacy flat-module tool."},
        )
        tool = self.store.get_entity(tool_id)
        assert tool is not None

        with self.assertRaises(PermissionError):
            self.service.save_tool_sigma_scope(tool, ["windows"])


if __name__ == "__main__":
    unittest.main()
