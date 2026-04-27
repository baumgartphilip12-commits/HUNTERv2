"""Tests for the extracted layered entity persistence service."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from hunter.services.layered_entity_service import LayeredEntityService
from hunter.services.sync_service import SyncService
from tests.support import create_temp_project, make_store, seed_technique


class LayeredEntityServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_project = create_temp_project()
        self.addCleanup(self.temp_project.cleanup)
        self.root = Path(self.temp_project.name)
        self.store = make_store(self.root)
        self.sync = SyncService(self.store)
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        seed_technique(self.store, external_id="T1041", name="Exfiltration Over C2 Channel")
        self.layered_source = self.store.get_source_by_name("Layered Local Modules")
        assert self.layered_source is not None
        self.service = LayeredEntityService(
            self.store,
            self.sync,
            str(self.root),
        )

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

    def test_save_threat_updates_runtime_without_full_layered_sync(self) -> None:
        entity = {
            "id": None,
            "type": "ThreatProfile",
            "name": "APT Save Test",
            "external_id": "apt_save_test",
            "status": "active",
            "priority": "",
            "tags": ["iran", "test"],
            "short_description": "Threat save test summary.",
            "payload": {
                "summary": "Threat save test summary.",
                "aliases": ["Save Unit"],
                "mitre_techniques": ["T1001", "T1041"],
                "indicators": [{"type": "domain", "value": "evil.example"}],
                "references": ["https://example.test/threat"],
                "extra_hunts": ["Pivot outbound connections."],
            },
        }
        self.sync.apply_source = Mock(side_effect=AssertionError("apply_source should not be called"))

        with patch("hunter.services.layered_entity_service.save_layered_module_json", new=self._save_module_json):
            result = self.service.save_threat(entity)
        saved = result.entity

        self.assertEqual(saved["source_name"], "Layered Local Modules")
        self.assertEqual(saved["payload"]["mitre_techniques"], ["T1001", "T1041"])
        self.assertEqual(saved["source_ref"], "threats/apt_save_test.json")

        relationships = self.store.list_relationships(entity_id=saved["id"], direction="out", rel_type="USES")
        self.assertEqual({rel["dst_external_id"] for rel in relationships}, {"T1001", "T1041"})

        index_map = self.store.get_layered_module_index_map(self.layered_source["id"])
        self.assertIn("threats/apt_save_test.json", index_map)
        self.assertEqual(index_map["threats/apt_save_test.json"]["external_id"], "apt_save_test")
        self.sync.apply_source.assert_not_called()

    def test_save_tool_rename_retires_old_runtime_row_and_updates_index_without_sync(self) -> None:
        old_path = Path(self._layered_dirs()["tools"]) / "aws_hunting__modified.json"
        old_path.write_text("{}", encoding="utf-8")
        old_ref = "tools/aws_hunting__modified.json"
        old_entity_id = self.store.upsert_entity(
            entity_type="ToolPack",
            external_id="aws_hunting__modified",
            name="AWS Hunting (Modified)",
            short_description="Old modified tool.",
            status="active",
            source_name="Layered Local Modules",
            source_ref=old_ref,
            source_url=str(old_path.resolve()),
            tags=["aws"],
            payload={
                "summary": "Old modified tool.",
                "platform": "AWS",
                "execution_surface": "CloudWatch Logs Insights",
                "surface_details": "Old details",
                "service_examples": ["CloudTrail"],
                "references": [],
                "environment_defaults": {},
                "template_values": {},
                "sigma_translation": {
                    "enabled": True,
                    "backend": "elasticsearch",
                    "pipelines": [],
                    "output_format": "lucene",
                },
                "variant_of_tool_external_id": "aws_hunting",
                "variant_origin": "local_variant",
                "hunt_methods": [
                    {
                        "title": "Old Hunt",
                        "techniques": ["T1001"],
                        "template": "old template",
                        "supported_ioc_types": ["domain"],
                        "required_placeholders": ["<DOMAIN_IOC>"],
                        "output_format": "query",
                        "execution_surface": "CloudWatch Logs Insights",
                        "surface_details": "Old details",
                        "service_examples": ["CloudTrail"],
                        "prerequisites": ["CloudTrail enabled"],
                        "noise_level": "medium",
                        "privilege_required": "user",
                        "time_cost": 2,
                        "data_sources": ["CloudTrail"],
                        "expectation": "Old expectation",
                    }
                ],
            },
        )
        technique = self.store.get_entity_by_external_id("MitreTechnique", "T1001")
        assert technique is not None
        self.store.upsert_relationship(
            src_entity_id=old_entity_id,
            dst_entity_id=technique["id"],
            rel_type="COVERS",
            source_name="Layered Local Modules",
            source_ref=old_ref,
            context={"origin": "test"},
        )
        self.store.upsert_layered_module_index_row(
            self.layered_source["id"],
            {
                "layer": "tools",
                "relative_path": old_ref,
                "absolute_path": str(old_path.resolve()),
                "entity_type": "ToolPack",
                "external_id": "aws_hunting__modified",
                "mtime_ns": 1,
                "size_bytes": 2,
                "content_hash": "old",
                "status": "indexed",
                "warning_text": "",
                "last_seen_at": "2026-01-01T00:00:00Z",
                "last_indexed_at": "2026-01-01T00:00:00Z",
            },
        )

        entity = {
            "id": old_entity_id,
            "type": "ToolPack",
            "name": "AWS Hunting (Modified v2)",
            "external_id": "aws_hunting__modified_v2",
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
                "sigma_translation": {
                    "enabled": True,
                    "backend": "elasticsearch",
                    "pipelines": [],
                    "output_format": "lucene",
                },
                "generation": {"compiler": "should_be_removed"},
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
        previous_entity = self.store.get_entity(old_entity_id)
        assert previous_entity is not None
        self.sync.apply_source = Mock(side_effect=AssertionError("apply_source should not be called"))

        with patch("hunter.services.layered_entity_service.save_layered_module_json", new=self._save_module_json):
            result = self.service.save_tool(entity, previous_entity=previous_entity)
        saved = result.entity

        self.assertEqual(saved["source_ref"], "tools/aws_hunting__modified_v2.json")
        self.assertNotIn("generation", saved["payload"])
        self.assertEqual(
            saved["payload"]["sigma_translation"],
            {
                "enabled": True,
                "backend": "elasticsearch",
                "pipelines": [],
                "output_format": "lucene",
            },
        )

        retired = self.store.get_entity(old_entity_id)
        self.assertEqual(retired["status"], "deprecated")
        self.assertTrue(retired["payload"]["removed_from_source"])

        old_relationships = self.store.list_relationships(entity_id=old_entity_id, direction="any")
        self.assertEqual(old_relationships, [])
        new_relationships = self.store.list_relationships(entity_id=saved["id"], direction="out", rel_type="COVERS")
        self.assertEqual([rel["dst_external_id"] for rel in new_relationships], ["T1041"])

        index_map = self.store.get_layered_module_index_map(self.layered_source["id"])
        self.assertNotIn(old_ref, index_map)
        self.assertIn("tools/aws_hunting__modified_v2.json", index_map)
        self.sync.apply_source.assert_not_called()

    def test_save_tool_sigma_scope_preserves_generated_tool_payload_and_module_file(self) -> None:
        module_payload = {
            "external_id": "kibana",
            "name": "Kibana",
            "summary": "Generated full-matrix tool.",
            "status": "active",
            "tags": ["elastic"],
            "platform": "Elastic",
            "execution_surface": "Kibana Discover",
            "surface_details": "Elastic hunting.",
            "service_examples": ["Elastic Defend"],
            "references": ["https://example.test/kibana"],
            "generation": {"coverage_mode": "full_matrix"},
            "sigma_translation": {
                "enabled": True,
                "backend": "elasticsearch",
                "pipelines": [],
                "output_format": "lucene",
            },
            "sigma_scope": {"default_families": ["windows"]},
            "environment_defaults": {},
            "template_values": {},
            "hunt_methods": [
                {
                    "title": "Kibana T1001 Hunt",
                    "techniques": ["T1001"],
                    "template": "process.name:powershell",
                    "supported_ioc_types": ["domain"],
                    "required_placeholders": [],
                    "output_format": "query",
                    "execution_surface": "Kibana Discover",
                    "surface_details": "Elastic hunting.",
                    "service_examples": ["Elastic Defend"],
                    "prerequisites": ["Elastic data available"],
                    "noise_level": "medium",
                    "privilege_required": "user",
                    "time_cost": 2,
                    "data_sources": ["Process monitoring"],
                    "expectation": "Find process behavior.",
                    "method_strength": "primary_hunt",
                    "method_kind": "behavior_hunt",
                    "strength_reason": "Direct behavior hunt.",
                    "behavior_focus": "Process execution behavior.",
                }
            ],
        }
        module_path = Path(self._layered_dirs()["tools"]) / "kibana.json"
        module_path.write_text(json.dumps(module_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        entity_id = self.store.upsert_entity(
            entity_type="ToolPack",
            external_id="kibana",
            name="Kibana",
            short_description="Generated full-matrix tool.",
            status="active",
            source_name="Layered Local Modules",
            source_ref="tools/kibana.json",
            source_url="",
            tags=["elastic"],
            payload={
                "summary": module_payload["summary"],
                "platform": module_payload["platform"],
                "execution_surface": module_payload["execution_surface"],
                "surface_details": module_payload["surface_details"],
                "service_examples": module_payload["service_examples"],
                "references": module_payload["references"],
                "generation": module_payload["generation"],
                "sigma_translation": module_payload["sigma_translation"],
                "sigma_scope": module_payload["sigma_scope"],
                "environment_defaults": {},
                "template_values": {},
                "hunt_methods": module_payload["hunt_methods"],
            },
        )
        entity = self.store.get_entity(entity_id)
        assert entity is not None
        self.sync.apply_source = Mock(side_effect=AssertionError("apply_source should not be called"))

        with patch("hunter.services.layered_entity_service.save_layered_module_json", new=self._save_module_json):
            result = self.service.save_tool_sigma_scope(entity, ["azure", "windows"])

        saved_file = json.loads(module_path.read_text(encoding="utf-8"))
        self.assertEqual(saved_file["sigma_scope"], {"default_families": ["azure", "windows"]})
        self.assertEqual(saved_file["generation"], {"coverage_mode": "full_matrix"})
        self.assertEqual(result.entity["payload"]["sigma_scope"], {"default_families": ["azure", "windows"]})
        self.assertEqual(result.entity["payload"]["generation"], {"coverage_mode": "full_matrix"})
        self.sync.apply_source.assert_not_called()


if __name__ == "__main__":
    unittest.main()
