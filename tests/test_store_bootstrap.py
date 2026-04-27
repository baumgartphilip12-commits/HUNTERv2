"""Compatibility tests for knowledge-store runtime bootstrap."""

from __future__ import annotations

import unittest
import json
from pathlib import Path

from hunter.models.knowledge_store import KnowledgeStore
from hunter.models.store_bootstrap import KnowledgeRuntimeBootstrap
from tests.support import create_temp_project, make_store, write_tool_module


class StoreBootstrapTests(unittest.TestCase):
    def test_direct_knowledge_store_starts_unbootstrapped(self) -> None:
        tempdir = create_temp_project()
        self.addCleanup(tempdir.cleanup)
        root = Path(tempdir.name)

        store = KnowledgeStore(str(root))
        self.addCleanup(store.close)

        self.assertEqual(store.list_sources(), [])

    def test_open_bootstrapped_seeds_default_sources(self) -> None:
        tempdir = create_temp_project()
        self.addCleanup(tempdir.cleanup)
        root = Path(tempdir.name)

        store = make_store(root)
        self.addCleanup(store.close)

        names = {source["name"] for source in store.list_sources()}
        self.assertIn("MITRE ATT&CK Enterprise", names)
        self.assertIn("Layered Local Modules", names)
        self.assertIn("SigmaHQ Rules", names)
        self.assertTrue((root / "modules" / "SIGMA").is_dir())

    def test_create_source_persists_config_flags_and_rejects_duplicate_names(self) -> None:
        tempdir = create_temp_project()
        self.addCleanup(tempdir.cleanup)
        root = Path(tempdir.name)

        store = make_store(root)
        self.addCleanup(store.close)

        source_id = store.create_source(
            name="Local Sigma Lab",
            connector="sigmahq_rules",
            config={"rules_dir": "modules/SIGMA/lab"},
            enabled=False,
            approved=False,
        )
        source = store.get_source(source_id)

        self.assertEqual(source["name"], "Local Sigma Lab")
        self.assertEqual(source["connector"], "sigmahq_rules")
        self.assertEqual(source["config"], {"rules_dir": "modules/SIGMA/lab"})
        self.assertFalse(source["enabled"])
        self.assertFalse(source["approved"])
        with self.assertRaises(ValueError):
            store.create_source(
                name="Local Sigma Lab",
                connector="sigmahq_rules",
                config={"rules_dir": "modules/SIGMA/other"},
            )

    def test_bootstrap_preserves_customized_default_sigma_source_config(self) -> None:
        tempdir = create_temp_project()
        self.addCleanup(tempdir.cleanup)
        root = Path(tempdir.name)

        store = make_store(root)
        self.addCleanup(store.close)
        source = store.get_source_by_name("SigmaHQ Rules")
        store.update_source(
            source["id"],
            config={"rules_dir": "modules/SIGMA/local"},
            last_status="completed",
        )

        KnowledgeRuntimeBootstrap.ensure(store)

        refreshed = store.get_source_by_name("SigmaHQ Rules")
        self.assertEqual(refreshed["config"], {"rules_dir": "modules/SIGMA/local"})

    def test_explicit_bootstrap_api_can_leave_store_unbootstrapped_until_requested(self) -> None:
        tempdir = create_temp_project()
        self.addCleanup(tempdir.cleanup)
        root = Path(tempdir.name)

        store = KnowledgeStore.open_unbootstrapped(str(root))
        self.addCleanup(store.close)

        self.assertEqual(store.list_sources(), [])

        KnowledgeRuntimeBootstrap.ensure(store)

        names = {source["name"] for source in store.list_sources()}
        self.assertIn("MITRE ATT&CK Enterprise", names)
        self.assertIn("Layered Local Modules", names)
        self.assertIn("SigmaHQ Rules", names)

    def test_normal_bootstrap_does_not_import_legacy_flat_modules(self) -> None:
        tempdir = create_temp_project()
        self.addCleanup(tempdir.cleanup)
        root = Path(tempdir.name)
        legacy_module = {
            "id": "legacy_flat_threat",
            "name": "Legacy Flat Threat",
            "category": "APT",
            "mitre_techniques": ["T1001"],
            "hunt_actions": [{"title": "Legacy Hunt", "actions": ["Do legacy thing"]}],
        }
        (root / "modules" / "legacy_flat_threat.json").write_text(
            json.dumps(legacy_module),
            encoding="utf-8",
        )

        store = KnowledgeStore.open_bootstrapped(str(root))
        self.addCleanup(store.close)

        self.assertIsNone(
            store.get_entity_by_external_id("ThreatProfile", "legacy_flat_threat")
        )

    def test_bootstrap_repairs_stale_layered_tool_sigma_scope_from_module_file(self) -> None:
        tempdir = create_temp_project()
        self.addCleanup(tempdir.cleanup)
        root = Path(tempdir.name)
        module_path = write_tool_module(
            root,
            external_id="kibana",
            name="Kibana",
            platform="Elastic",
            technique_ids=["T1001"],
        )
        module_payload = json.loads(module_path.read_text(encoding="utf-8"))
        module_payload["sigma_translation"] = {
            "enabled": True,
            "backend": "elasticsearch",
            "pipelines": [],
            "output_format": "lucene",
        }
        module_payload["sigma_scope"] = {"default_families": ["windows", "linux"]}
        module_path.write_text(json.dumps(module_payload, indent=2), encoding="utf-8")

        store = KnowledgeStore.open_unbootstrapped(str(root))
        self.addCleanup(store.close)
        store.upsert_entity(
            entity_type="ToolPack",
            external_id="kibana",
            name="Kibana",
            short_description="Stale runtime tool.",
            source_name="Layered Local Modules",
            source_ref="tools/kibana.json",
            payload={
                "summary": "Stale runtime tool.",
                "sigma_translation": module_payload["sigma_translation"],
                "hunt_methods": [],
            },
        )

        KnowledgeRuntimeBootstrap.ensure(store)

        repaired = store.get_entity_by_external_id("ToolPack", "kibana")
        self.assertIsNotNone(repaired)
        self.assertEqual(
            repaired["payload"]["sigma_scope"],
            {"default_families": ["windows", "linux"]},
        )

    def test_bootstrap_does_not_repair_non_layered_tool_even_when_source_ref_matches(self) -> None:
        tempdir = create_temp_project()
        self.addCleanup(tempdir.cleanup)
        root = Path(tempdir.name)
        module_path = write_tool_module(
            root,
            external_id="kibana",
            name="Kibana",
            platform="Elastic",
            technique_ids=["T1001"],
        )
        module_payload = json.loads(module_path.read_text(encoding="utf-8"))
        module_payload["sigma_scope"] = {"default_families": ["windows"]}
        module_path.write_text(json.dumps(module_payload, indent=2), encoding="utf-8")

        store = KnowledgeStore.open_unbootstrapped(str(root))
        self.addCleanup(store.close)
        store.upsert_entity(
            entity_type="ToolPack",
            external_id="kibana",
            name="Local Kibana",
            short_description="Local runtime tool should not be layered-repaired.",
            source_name="local",
            source_ref="tools/kibana.json",
            payload={"summary": "Local runtime tool should not be layered-repaired."},
        )

        KnowledgeRuntimeBootstrap.ensure(store)

        tool = store.get_entity_by_external_id("ToolPack", "kibana")
        self.assertEqual(tool["source_name"], "local")
        self.assertNotIn("sigma_scope", tool["payload"])


if __name__ == "__main__":
    unittest.main()
