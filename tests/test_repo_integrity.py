"""Repository-level integrity checks for committed module content."""

from __future__ import annotations

import json
import unittest
import inspect
import subprocess
from pathlib import Path

from hunter.models import module_store
from hunter.models.knowledge_store import KnowledgeStore


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class RepositoryIntegrityTests(unittest.TestCase):
    def test_layered_module_filenames_match_external_ids(self) -> None:
        for folder_name in ("threats", "tools"):
            folder = PROJECT_ROOT / "modules" / folder_name
            self.assertTrue(folder.exists(), msg=f"Missing modules folder: {folder}")
            for path in sorted(folder.glob("*.json")):
                payload = json.loads(path.read_text(encoding="utf-8"))
                external_id = str(payload.get("external_id", "")).strip()
                self.assertTrue(external_id, msg=f"{path} is missing external_id")
                self.assertEqual(
                    path.name,
                    f"{external_id}.json",
                    msg=f"{path} should use the canonical external_id.json filename",
                )

    def test_legacy_flat_module_migration_surface_is_removed(self) -> None:
        self.assertFalse(hasattr(KnowledgeStore, "seed_from_legacy_modules"))
        self.assertFalse(hasattr(KnowledgeStore, "prune_legacy_seed_if_layered"))
        self.assertFalse(hasattr(module_store, "load_modules_from_disk"))
        self.assertFalse(hasattr(module_store, "list_flat_module_files"))

        bootstrap_source = (
            PROJECT_ROOT / "hunter" / "models" / "store_bootstrap.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("seed_from_legacy_modules", bootstrap_source)
        self.assertNotIn("prune_legacy_seed_if_layered", bootstrap_source)

        knowledge_store_source = inspect.getsource(KnowledgeStore)
        self.assertNotIn("legacy_modules", knowledge_store_source)

    def test_visible_python_ui_strings_do_not_contain_mojibake(self) -> None:
        ui_paths = [
            *(PROJECT_ROOT / "hunter" / "qt").rglob("*.py"),
        ]
        forbidden_fragments = {
            "\u00e2\u20ac\u00a2": "mojibake bullet separator",
            "\ufffd": "replacement character",
            "Ã": "UTF-8 decoded as Latin-1 marker",
            "Â": "stray Latin-1 continuation marker",
        }
        findings: list[str] = []
        for path in sorted(ui_paths):
            text = path.read_text(encoding="utf-8")
            for lineno, line in enumerate(text.splitlines(), 1):
                for fragment, label in forbidden_fragments.items():
                    if fragment in line:
                        findings.append(f"{path.relative_to(PROJECT_ROOT)}:{lineno}: {label}")
        self.assertEqual(findings, [])

    def test_shipped_runtime_no_longer_imports_tk(self) -> None:
        runtime_paths = [
            path
            for path in (PROJECT_ROOT / "hunter").rglob("*.py")
            if "__pycache__" not in path.parts
        ]
        forbidden = ("import tkinter", "from tkinter", "tkinter.")
        findings: list[str] = []
        for path in sorted(runtime_paths):
            text = path.read_text(encoding="utf-8").lower()
            for fragment in forbidden:
                if fragment in text:
                    findings.append(f"{path.relative_to(PROJECT_ROOT)} contains {fragment!r}")
                    break
        self.assertEqual(findings, [])

    def test_qt_startup_owns_windows_dpi_awareness(self) -> None:
        main_source = (PROJECT_ROOT / "main.py").read_text(encoding="utf-8")

        self.assertNotIn("SetProcessDpiAwareness", main_source)
        self.assertNotIn("SetProcessDPIAware", main_source)

    def test_legacy_ui_packages_are_removed_from_current_runtime(self) -> None:
        removed_paths = [
            PROJECT_ROOT / "hunter" / "app.py",
            PROJECT_ROOT / "hunter" / "theme.py",
            PROJECT_ROOT / "hunter" / "ui",
            PROJECT_ROOT / "hunter" / "views",
        ]

        self.assertEqual([str(path.relative_to(PROJECT_ROOT)) for path in removed_paths if path.exists()], [])

    def test_current_docs_do_not_reference_removed_ui_paths(self) -> None:
        forbidden = (
            "hunter/" + "app.py",
            "hunter/" + "ui",
            "hunter/" + "views",
            "Hunter" + "App",
            "test_app" + "_smoke",
            "test_editor" + "_local_save",
            "test_tool" + "_and_threat_forms",
        )
        findings: list[str] = []
        for path in (PROJECT_ROOT / "README.md", PROJECT_ROOT / "HUNTER_Documentation.md"):
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8")
            for fragment in forbidden:
                if fragment in text:
                    findings.append(f"{path.name} contains {fragment!r}")
        self.assertEqual(findings, [])

    def test_readme_does_not_reference_removed_docs_or_tests(self) -> None:
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

        self.assertNotIn("HUNTER_Documentation.md", readme)
        self.assertNotIn("test_generate_flow.py", readme)

    def test_readme_documents_current_qt_split_and_local_artifacts(self) -> None:
        readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

        required_fragments = {
            "hunter/qt/entity_browser.py",
            "hunter/qt/entity_dialogs.py",
            "hunter/qt/generate_page.py",
            "hunter/qt/review_page.py",
            "hunter/qt/settings_sync.py",
            "hunter/qt/formatting.py",
            "tests/test_qt_shell_smoke.py",
            "tests/test_qt_generate_page.py",
            "tests/test_qt_review_page.py",
            "tests/test_qt_settings_dialog.py",
            "requirements-dev.txt",
            "npm ci",
            "node_modules/",
            "generated_hunt_pack_report.docx",
            "Offline Windows Bundle",
            "tools/build_offline_bundle.py",
            "HUNTER_PORTABLE_ROOT",
            "HUNTER_OFFLINE",
            "bundle_file=modules/mitre/enterprise-attack.json",
        }
        missing = sorted(fragment for fragment in required_fragments if fragment not in readme)

        self.assertEqual(missing, [])
        self.assertNotIn("tests/test_qt_shell.py tests/test_qt_models.py", readme)

    def test_required_qt_and_docx_runtime_files_are_tracked(self) -> None:
        required = {
            "hunter/qt_app.py",
            "hunter/qt/main_window.py",
            "hunter/qt/entity_browser.py",
            "hunter/qt/entity_dialogs.py",
            "hunter/qt/entity_editors.py",
            "hunter/qt/formatting.py",
            "hunter/qt/generate_page.py",
            "hunter/qt/review_page.py",
            "hunter/qt/settings_sync.py",
            "hunter/controllers/docx_runtime.py",
            "hunter/controllers/export_preparation.py",
            "hunter/search_documents.py",
            "hunter/services/connectors/sigmahq_rules.py",
            "tests/test_qt_shell.py",
            "tests/qt_shell_support.py",
            "tests/test_qt_shell_smoke.py",
            "tests/test_qt_generate_page.py",
            "tests/test_qt_review_page.py",
            "tests/test_qt_settings_dialog.py",
            "tests/test_docx_export_script.py",
            "tools/build_offline_bundle.py",
            ".gitignore",
        }
        result = subprocess.run(
            ["git", "ls-files", *sorted(required)],
            cwd=PROJECT_ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )
        tracked = {line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()}

        self.assertEqual(required - tracked, set())

    def test_package_declares_direct_docx_script_dependencies(self) -> None:
        package = json.loads((PROJECT_ROOT / "package.json").read_text(encoding="utf-8"))
        dependencies = package.get("dependencies", {})

        self.assertIn("docx", dependencies)
        self.assertIn("jszip", dependencies)

    def test_package_lock_root_dependencies_match_package_manifest(self) -> None:
        package = json.loads((PROJECT_ROOT / "package.json").read_text(encoding="utf-8"))
        lockfile = json.loads((PROJECT_ROOT / "package-lock.json").read_text(encoding="utf-8"))

        self.assertEqual(
            package.get("dependencies", {}),
            lockfile.get("packages", {}).get("", {}).get("dependencies", {}),
        )

    def test_dev_requirements_declares_pytest(self) -> None:
        dev_requirements = PROJECT_ROOT / "requirements-dev.txt"

        self.assertTrue(dev_requirements.exists())
        self.assertIn("pytest", dev_requirements.read_text(encoding="utf-8").lower())

    def test_no_tracked_python_bytecode_artifacts_remain(self) -> None:
        result = subprocess.run(
            ["git", "ls-files", "*.pyc", "*/__pycache__/*"],
            cwd=PROJECT_ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )

        tracked = [line for line in result.stdout.splitlines() if line.strip()]
        self.assertEqual(tracked, [])

    def test_no_tracked_ignored_artifacts_remain(self) -> None:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--ignored", "--exclude-standard"],
            cwd=PROJECT_ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )

        tracked = [line for line in result.stdout.splitlines() if line.strip()]
        self.assertEqual(tracked, [])

    def test_gitignore_protects_offline_generated_artifacts(self) -> None:
        gitignore = PROJECT_ROOT / ".gitignore"
        self.assertTrue(gitignore.exists())
        text = gitignore.read_text(encoding="utf-8")
        for fragment in (
            "node_modules/",
            "vendor/python/",
            "data/hunter_v2.sqlite3",
            "data/snapshots/",
            "data/exports/",
            "data/imports/",
            "dist/",
            "generated_hunt_pack_report.docx",
        ):
            self.assertIn(fragment, text)


if __name__ == "__main__":
    unittest.main()
