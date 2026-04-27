"""Offline portability coverage for Windows release bundles."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from hunter.models.knowledge_store import KnowledgeStore
from hunter.runtime_paths import bootstrap_bundle_path, bundled_node_path, project_root
from hunter.services.connectors.mitre_attack import MitreAttackConnector
from tests.support import create_temp_project, seed_technique


class OfflinePortabilityTests(unittest.TestCase):
    def test_portable_root_environment_overrides_source_derived_root(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            portable = Path(tempdir)
            with mock.patch.dict(os.environ, {"HUNTER_PORTABLE_ROOT": str(portable)}):
                self.assertEqual(project_root(), portable.resolve())
                self.assertEqual(bootstrap_bundle_path(), portable.resolve() / "data" / "bootstrap" / "seed_knowledge_bundle.json")
                self.assertEqual(bundled_node_path(), portable.resolve() / "runtime" / "node" / "node.exe")

    def test_mitre_connector_imports_local_bundle_file(self) -> None:
        tempdir = create_temp_project()
        self.addCleanup(tempdir.cleanup)
        root = Path(tempdir.name)
        bundle = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--unit",
                    "name": "Unit Technique",
                    "description": "Local ATT&CK technique.",
                    "external_references": [{"source_name": "mitre-attack", "external_id": "T1234"}],
                    "kill_chain_phases": [{"phase_name": "execution"}],
                    "x_mitre_platforms": ["Windows"],
                    "x_mitre_data_sources": ["Process"],
                }
            ]
        }
        bundle_path = root / "modules" / "mitre" / "enterprise-attack.json"
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

        with mock.patch.dict(os.environ, {"HUNTER_PORTABLE_ROOT": str(root)}):
            dataset = MitreAttackConnector().build_dataset(
                {
                    "name": "MITRE ATT&CK Enterprise",
                    "config": {"bundle_file": "modules/mitre/enterprise-attack.json"},
                }
            )

        self.assertEqual(dataset["entities"][0]["external_id"], "T1234")
        self.assertEqual(dataset["metadata"]["bundle"], "modules/mitre/enterprise-attack.json")

    def test_bootstrap_imports_seed_bundle_when_database_is_empty(self) -> None:
        tempdir = create_temp_project()
        self.addCleanup(tempdir.cleanup)
        root = Path(tempdir.name)
        seed_store = KnowledgeStore.open_bootstrapped(str(root))
        self.addCleanup(seed_store.close)
        seed_technique(seed_store, external_id="T9999", name="Seed Technique")
        seed_path = root / "data" / "bootstrap" / "seed_knowledge_bundle.json"
        seed_path.parent.mkdir(parents=True, exist_ok=True)
        seed_store.export_knowledge_bundle(str(seed_path))
        seed_store.db_path.unlink()

        with mock.patch.dict(os.environ, {"HUNTER_OFFLINE": "1", "HUNTER_PORTABLE_ROOT": str(root)}):
            store = KnowledgeStore.open_bootstrapped(str(root))
        self.addCleanup(store.close)

        self.assertIsNotNone(store.get_entity_by_external_id("MitreTechnique", "T9999"))
        mitre = store.get_source_by_name("MITRE ATT&CK Enterprise")
        self.assertFalse(mitre["enabled"])

    def test_bundle_builder_creates_manifest_launcher_seed_and_zip(self) -> None:
        from tools.build_offline_bundle import build_offline_bundle

        tempdir = create_temp_project()
        self.addCleanup(tempdir.cleanup)
        root = Path(tempdir.name)
        for relative, text in {
            "main.py": "print('hunter')\n",
            "README.md": "# HUNTER\n",
            "export_docx.js": "console.log('docx')\n",
            "package.json": "{}\n",
            "package-lock.json": "{}\n",
            "hunter/__init__.py": "",
            "vendor/requirements.txt": "PySide6>=6.8,<7\n",
            ".gitignore": "data/hunter_v2.sqlite3\n",
        }.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        (root / "node_modules" / "docx").mkdir(parents=True)
        (root / "vendor" / "python" / "PySide6").mkdir(parents=True)
        store = KnowledgeStore.open_bootstrapped(str(root))
        self.addCleanup(store.close)
        seed_technique(store)

        output = root / "dist" / "HUNTER-v2.1-offline-win64"
        manifest = build_offline_bundle(
            project_root_path=root,
            output_path=output,
            include_current_knowledge=True,
        )

        self.assertTrue((output / "run_hunter.bat").exists())
        self.assertTrue((output / "data" / "bootstrap" / "seed_knowledge_bundle.json").exists())
        self.assertTrue((output / "offline_bundle_manifest.json").exists())
        self.assertTrue(Path(manifest["zip_path"]).exists())
        self.assertFalse((output / "data" / "hunter_v2.sqlite3").exists())
        seed = json.loads((output / "data" / "bootstrap" / "seed_knowledge_bundle.json").read_text(encoding="utf-8"))
        mitre = next(source for source in seed["sources"] if source["name"] == "MITRE ATT&CK Enterprise")
        self.assertFalse(mitre["enabled"])
        with zipfile.ZipFile(manifest["zip_path"]) as archive:
            names = set(archive.namelist())
        self.assertIn("HUNTER-v2.1-offline-win64/run_hunter.bat", names)
        self.assertNotIn("HUNTER-v2.1-offline-win64/data/hunter_v2.sqlite3", names)


if __name__ == "__main__":
    unittest.main()
