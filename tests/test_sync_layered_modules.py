"""Regression tests for layered local sync and portability reconciliation."""

from __future__ import annotations

import json
import time
import unittest
from pathlib import Path

from hunter.services.sync_service import SyncService
from tests.support import (
    create_temp_project,
    make_store,
    seed_technique,
    write_threat_module,
    write_tool_module,
)


class SyncLayeredModulesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = create_temp_project()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.store = make_store(self.root)
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        self.store.upsert_entity(
            entity_type="MitreTechnique",
            external_id="T1098",
            name="Account Manipulation",
            short_description="Cloud identity manipulation test technique.",
            source_name="MITRE ATT&CK Enterprise",
            source_ref="T1098",
            source_url="https://attack.mitre.org/techniques/T1098/",
            payload={
                "technique_id": "T1098",
                "description": "Cloud identity manipulation test technique.",
                "description_blocks": [{"type": "paragraph", "text": "Cloud identity manipulation test technique."}],
                "detection": "Cloud identity detection guidance.",
                "detection_blocks": [{"type": "paragraph", "text": "Cloud identity detection guidance."}],
                "platforms": ["IaaS", "Identity Provider"],
                "tactics": ["Persistence"],
                "data_sources": ["Cloud control-plane telemetry"],
            },
        )
        self.store.upsert_entity(
            entity_type="MitreTechnique",
            external_id="T1610",
            name="Deploy Container",
            short_description="Container runtime test technique.",
            source_name="MITRE ATT&CK Enterprise",
            source_ref="T1610",
            source_url="https://attack.mitre.org/techniques/T1610/",
            payload={
                "technique_id": "T1610",
                "description": "Container runtime test technique.",
                "description_blocks": [{"type": "paragraph", "text": "Container runtime test technique."}],
                "detection": "Container runtime detection guidance.",
                "detection_blocks": [{"type": "paragraph", "text": "Container runtime detection guidance."}],
                "platforms": ["Containers", "Linux"],
                "tactics": ["Execution"],
                "data_sources": ["Container telemetry"],
            },
        )
        self.store.upsert_entity(
            entity_type="MitreTechnique",
            external_id="T1595",
            name="Active Scanning",
            short_description="External reconnaissance test technique.",
            source_name="MITRE ATT&CK Enterprise",
            source_ref="T1595",
            source_url="https://attack.mitre.org/techniques/T1595/",
            payload={
                "technique_id": "T1595",
                "description": "External reconnaissance test technique.",
                "description_blocks": [{"type": "paragraph", "text": "External reconnaissance test technique."}],
                "detection": "Recon detection guidance.",
                "detection_blocks": [{"type": "paragraph", "text": "Recon detection guidance."}],
                "platforms": ["Network Devices"],
                "tactics": ["Reconnaissance"],
                "data_sources": ["Internet-facing service telemetry"],
            },
        )
        write_threat_module(self.root, technique_ids=["T1001"])
        write_tool_module(
            self.root,
            external_id="aws_hunting",
            name="AWS Hunting",
            platform="AWS",
            technique_ids=["T1001", "T1098", "T1610", "T1595"],
            coverage_mode="full_matrix",
        )
        self.sync = SyncService(self.store)
        self.layered_source = self.store.get_source_by_name("Layered Local Modules")
        assert self.layered_source is not None

    def test_layered_source_config_uses_portable_relative_paths(self) -> None:
        self.assertEqual(
            self.layered_source["config"],
            {
                "root": "modules",
                "threats_dir": "modules/threats",
                "tools_dir": "modules/tools",
                "mitre_dir": "modules/mitre",
            },
        )

    def test_reconcile_stale_layered_paths_recovers_portable_refs(self) -> None:
        stale_path = r"C:\StaleRoot\modules\threats\portable_test.json"
        entity_id = self.store.upsert_entity(
            entity_type="ThreatProfile",
            external_id="portable_test",
            name="Portable Test",
            short_description="Portable threat.",
            source_name="Layered Local Modules",
            source_ref="",
            source_url=stale_path,
            payload={"summary": "Portable threat."},
        )
        self.store.upsert_layered_module_index_row(
            self.layered_source["id"],
            {
                "layer": "threats",
                "relative_path": "",
                "absolute_path": stale_path,
                "entity_type": "ThreatProfile",
                "external_id": "portable_test",
                "mtime_ns": 0,
                "size_bytes": 0,
                "content_hash": "",
                "status": "indexed",
                "warning_text": "",
                "last_seen_at": "",
                "last_indexed_at": "",
            },
        )

        self.store.reconcile_portable_runtime_paths()

        entity = self.store.get_entity(entity_id)
        self.assertEqual(entity["source_ref"], "threats/portable_test.json")
        self.assertEqual(entity["source_url"], "")
        index_map = self.store.get_layered_module_index_map(self.layered_source["id"])
        self.assertIn("threats/portable_test.json", index_map)
        self.assertEqual(
            index_map["threats/portable_test.json"]["absolute_path"],
            str((self.root / "modules" / "threats" / "portable_test.json").resolve()),
        )

    def test_layered_sync_tracks_new_unchanged_changed_and_deleted_files(self) -> None:
        first = self.sync.apply_source(self.layered_source["id"])
        self.assertGreater(first.summary["entity_count"], 0)
        self.assertGreater(first.summary["new_files"], 0)
        self.assertNotIn("tool_compiler", first.dataset.get("metadata", {}))

        second = self.sync.preview_source(self.layered_source["id"])
        self.assertEqual(second.summary["changed_files"], 0)
        self.assertEqual(second.summary["deleted_files"], 0)
        self.assertGreater(second.summary["unchanged_files"], 0)

        threat_path = self.root / "modules" / "threats" / "apt_test.json"
        payload = json.loads(threat_path.read_text(encoding="utf-8"))
        payload["summary"] = "Updated summary for incremental sync."
        time.sleep(0.02)
        threat_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        changed = self.sync.preview_source(self.layered_source["id"])
        self.assertGreaterEqual(changed.summary["changed_files"], 1)

        self.sync.apply_source(self.layered_source["id"])
        threat_path.unlink()
        deleted = self.sync.preview_source(self.layered_source["id"])
        self.assertGreaterEqual(deleted.summary["deleted_files"], 1)

    def test_layered_sync_records_warnings_for_malformed_files(self) -> None:
        bad_path = self.root / "modules" / "threats" / "bad.json"
        bad_path.write_text(
            json.dumps({"external_id": "bad", "name": "Bad Threat"}),
            encoding="utf-8",
        )

        preview = self.sync.preview_source(self.layered_source["id"])
        self.assertGreaterEqual(preview.summary["warning_count"], 1)
        warnings = preview.dataset.get("metadata", {}).get("warnings", [])
        self.assertTrue(any("bad.json" in warning for warning in warnings))

    def test_layered_sync_imports_tool_sigma_scope(self) -> None:
        tool_path = self.root / "modules" / "tools" / "aws_hunting.json"
        payload = json.loads(tool_path.read_text(encoding="utf-8"))
        payload["sigma_translation"] = {
            "enabled": True,
            "backend": "elasticsearch",
            "pipelines": [],
            "output_format": "lucene",
        }
        payload["sigma_scope"] = {"default_families": ["windows", "linux"]}
        tool_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        self.sync.apply_source(self.layered_source["id"])

        tool = self.store.get_entity_by_external_id("ToolPack", "aws_hunting")
        self.assertIsNotNone(tool)
        self.assertEqual(
            tool["payload"]["sigma_scope"],
            {"default_families": ["windows", "linux"]},
        )

    def test_layered_sync_creates_mitre_placeholders_when_mitre_source_is_empty(self) -> None:
        tempdir = create_temp_project()
        self.addCleanup(tempdir.cleanup)
        root = Path(tempdir.name)
        write_threat_module(root, technique_ids=["T9999"])
        write_tool_module(
            root,
            external_id="offline_tool",
            name="Offline Tool",
            technique_ids=["T9999"],
        )
        store = make_store(root)
        self.addCleanup(store.close)
        sync = SyncService(store)
        layered_source = store.get_source_by_name("Layered Local Modules")
        assert layered_source is not None

        preview = sync.preview_source(layered_source["id"])

        self.assertEqual(preview.summary["warning_count"], 0)
        self.assertGreaterEqual(preview.summary["relationship_count"], 2)

        sync.apply_source(layered_source["id"])

        placeholder = store.get_entity_by_external_id("MitreTechnique", "T9999")
        self.assertIsNotNone(placeholder)
        self.assertEqual(placeholder["status"], "placeholder")
        self.assertIn("placeholder", placeholder["tags"])
        threat = store.get_entity_by_external_id("ThreatProfile", "apt_test")
        tool = store.get_entity_by_external_id("ToolPack", "offline_tool")
        assert threat is not None
        assert tool is not None
        threat_links = store.list_relationships(
            entity_id=threat["id"],
            direction="out",
            rel_type="USES",
        )
        tool_links = store.list_relationships(
            entity_id=tool["id"],
            direction="out",
            rel_type="COVERS",
        )
        self.assertEqual([rel["dst_external_id"] for rel in threat_links], ["T9999"])
        self.assertEqual([rel["dst_external_id"] for rel in tool_links], ["T9999"])


if __name__ == "__main__":
    unittest.main()
