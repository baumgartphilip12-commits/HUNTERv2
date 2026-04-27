"""Regression coverage for repo-local Python vendor bootstrap behavior."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from hunter.vendor_runtime import bootstrap_vendor_path, duplicate_vendor_distributions, ensure_vendor_packages
from hunter.controllers.docx_runtime import DocxRuntimeHelper


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class VendorRuntimeTests(unittest.TestCase):
    @staticmethod
    def _write_vendor_package(root: Path, relative_path: str, content: str = "") -> None:
        target = root / "vendor" / "python" / Path(relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def test_bootstrap_vendor_path_adds_repo_local_vendor_python(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            vendor_python = root / "vendor" / "python"
            vendor_python.mkdir(parents=True, exist_ok=True)

            original_sys_path = list(sys.path)
            try:
                bootstrap_vendor_path(project_dir=root)
                self.assertIn(str(vendor_python.resolve()), sys.path)
            finally:
                sys.path[:] = original_sys_path

    def test_ensure_vendor_packages_reports_missing_manifest_dependency_when_noninteractive(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            requirements = root / "vendor" / "requirements.txt"
            requirements.parent.mkdir(parents=True, exist_ok=True)
            requirements.write_text("PyYAML>=6.0,<7\n", encoding="utf-8")

            status = ensure_vendor_packages(project_dir=root, interactive=False)

            self.assertFalse(status["ready"])
            self.assertIn("PyYAML", status["missing_packages"])
            self.assertIn("yaml", status["missing_modules"])

    def test_ensure_vendor_packages_reports_missing_manifest_when_noninteractive(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            (root / "vendor").mkdir(parents=True, exist_ok=True)

            status = ensure_vendor_packages(project_dir=root, interactive=False)

            self.assertFalse(status["ready"])
            self.assertEqual(status["required_specs"], [])
            self.assertIn("vendor/requirements.txt", status["error"])

    def test_ensure_vendor_packages_tracks_official_sigma_runtime_modules(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            requirements = root / "vendor" / "requirements.txt"
            requirements.parent.mkdir(parents=True, exist_ok=True)
            requirements.write_text(
                "\n".join(
                    [
                        "PyYAML>=6.0,<7",
                        "pySigma>=1.3,<2",
                        "pySigma-backend-elasticsearch>=2.0,<3",
                        "PySide6>=6.8,<7",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            status = ensure_vendor_packages(project_dir=root, interactive=False)

            self.assertFalse(status["ready"])
            self.assertIn("PyYAML", status["missing_packages"])
            self.assertIn("pySigma", status["missing_packages"])
            self.assertIn("pySigma-backend-elasticsearch", status["missing_packages"])
            self.assertIn("PySide6", status["missing_packages"])
            self.assertIn("yaml", status["missing_modules"])
            self.assertIn("sigma", status["missing_modules"])
            self.assertIn("sigma.backends.elasticsearch", status["missing_modules"])
            self.assertIn("PySide6", status["missing_modules"])

    def test_ensure_vendor_packages_accepts_vendored_namespace_package_backend(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            requirements = root / "vendor" / "requirements.txt"
            requirements.parent.mkdir(parents=True, exist_ok=True)
            requirements.write_text(
                "\n".join(
                    [
                        "PyYAML>=6.0,<7",
                        "pySigma>=1.3,<2",
                        "pySigma-backend-elasticsearch>=2.0,<3",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            self._write_vendor_package(root, "yaml/__init__.py", "__all__ = []\n")
            self._write_vendor_package(
                root,
                "sigma/backends/elasticsearch/__init__.py",
                "__all__ = []\n",
            )

            status = ensure_vendor_packages(project_dir=root, interactive=False)

            self.assertTrue(status["ready"])
            self.assertEqual(status["missing_packages"], [])
            self.assertEqual(status["missing_modules"], [])
            self.assertEqual(status["error"], "")

    def test_ensure_vendor_packages_handles_missing_namespace_backend_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            requirements = root / "vendor" / "requirements.txt"
            requirements.parent.mkdir(parents=True, exist_ok=True)
            requirements.write_text(
                "\n".join(
                    [
                        "PyYAML>=6.0,<7",
                        "pySigma>=1.3,<2",
                        "pySigma-backend-elasticsearch>=2.0,<3",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            self._write_vendor_package(root, "yaml/__init__.py", "__all__ = []\n")
            (root / "vendor" / "python" / "sigma" / "backends").mkdir(parents=True, exist_ok=True)

            status = ensure_vendor_packages(project_dir=root, interactive=False)

            self.assertFalse(status["ready"])
            self.assertIn("pySigma-backend-elasticsearch", status["missing_packages"])
            self.assertIn("sigma.backends.elasticsearch", status["missing_modules"])

    def test_repo_vendor_manifest_includes_official_sigma_runtime(self) -> None:
        manifest = (PROJECT_ROOT / "vendor" / "requirements.txt").read_text(
            encoding="utf-8"
        ).lower()

        self.assertIn("pyyaml", manifest)
        self.assertIn("pysigma", manifest)
        self.assertIn("pysigma-backend-elasticsearch", manifest)
        self.assertIn("pyside6", manifest)

    def test_vendor_runtime_startup_prompt_path_does_not_import_tkinter(self) -> None:
        source = (PROJECT_ROOT / "hunter" / "vendor_runtime.py").read_text(encoding="utf-8")

        self.assertNotIn("tkinter", source.lower())

    def test_import_qt_app_survives_when_yaml_is_missing(self) -> None:
        script = textwrap.dedent(
            """
            import builtins
            import sys

            real_import = builtins.__import__

            def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
                if name == "yaml" or name.startswith("yaml."):
                    raise ModuleNotFoundError("No module named 'yaml'")
                return real_import(name, globals, locals, fromlist, level)

            builtins.__import__ = fake_import
            try:
                import hunter.qt_app  # noqa: F401
                print("startup-import-ok")
            finally:
                builtins.__import__ = real_import
            """
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=(result.stdout + "\n" + result.stderr).strip(),
        )
        self.assertIn("startup-import-ok", result.stdout)

    def test_repo_noninteractive_vendor_status_smoke_exits_cleanly(self) -> None:
        script = textwrap.dedent(
            f"""
            from hunter.vendor_runtime import ensure_vendor_packages

            status = ensure_vendor_packages(project_dir=r"{PROJECT_ROOT}", interactive=False)
            print("status-ok", status.get("ready"), status.get("error", ""))
            """
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=(result.stdout + "\n" + result.stderr).strip(),
        )
        self.assertIn("status-ok", result.stdout)

    def test_duplicate_vendor_distribution_names_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            vendor_python = root / "vendor" / "python"
            (vendor_python / "packaging-26.1.dist-info").mkdir(parents=True)
            (vendor_python / "packaging-26.2.dist-info").mkdir(parents=True)
            (vendor_python / "PyYAML-6.0.dist-info").mkdir(parents=True)

            duplicates = duplicate_vendor_distributions(project_dir=root)

            self.assertEqual(duplicates, {"packaging": ["packaging-26.1.dist-info", "packaging-26.2.dist-info"]})

    def test_repo_vendor_python_has_no_duplicate_distribution_names(self) -> None:
        self.assertEqual(duplicate_vendor_distributions(project_dir=PROJECT_ROOT), {})

    def test_interactive_decline_uses_non_tk_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            requirements = root / "vendor" / "requirements.txt"
            requirements.parent.mkdir(parents=True, exist_ok=True)
            requirements.write_text("PyYAML>=6.0,<7\n", encoding="utf-8")

            with (
                patch("hunter.vendor_runtime._ask_yes_no", return_value=False) as ask_mock,
                patch("hunter.vendor_runtime._notify_user") as notify_mock,
            ):
                status = ensure_vendor_packages(project_dir=root, interactive=True)

            ask_mock.assert_called_once()
            notify_mock.assert_called_once()
            self.assertTrue(status["declined"])

    def test_offline_mode_does_not_attempt_pip_install(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            requirements = root / "vendor" / "requirements.txt"
            requirements.parent.mkdir(parents=True, exist_ok=True)
            requirements.write_text("PyYAML>=6.0,<7\n", encoding="utf-8")

            with (
                patch.dict("os.environ", {"HUNTER_OFFLINE": "1", "HUNTER_PORTABLE_ROOT": str(root)}),
                patch("hunter.vendor_runtime._run_pip_install") as install_mock,
                patch("hunter.vendor_runtime._notify_user") as notify_mock,
            ):
                status = ensure_vendor_packages(project_dir=root, interactive=True)

            install_mock.assert_not_called()
            notify_mock.assert_called_once()
            self.assertTrue(status["offline"])
            self.assertFalse(status["install_attempted"])
            self.assertIn("offline bundle", status["error"].lower())

    def test_docx_runtime_finds_bundled_node_before_path(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            bundled = root / "runtime" / "node" / "node.exe"
            bundled.parent.mkdir(parents=True, exist_ok=True)
            bundled.write_text("", encoding="utf-8")

            with patch.dict("os.environ", {"HUNTER_PORTABLE_ROOT": str(root)}):
                self.assertEqual(DocxRuntimeHelper.find_node(str(root)), str(bundled))

    def test_docx_runtime_offline_missing_packages_does_not_run_npm(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            (root / "export_docx.js").write_text("console.log('docx')\n", encoding="utf-8")
            bundled = root / "runtime" / "node" / "node.exe"
            bundled.parent.mkdir(parents=True, exist_ok=True)
            bundled.write_text("", encoding="utf-8")

            with (
                patch.dict("os.environ", {"HUNTER_OFFLINE": "1", "HUNTER_PORTABLE_ROOT": str(root)}),
                patch.object(DocxRuntimeHelper, "run_npm_install") as npm_mock,
                patch("hunter.controllers.docx_runtime.QtWidgets.QMessageBox.warning") as warning_mock,
            ):
                DocxRuntimeHelper.export_word(None, {"payload": {"steps": []}}, str(root))

            npm_mock.assert_not_called()
            warning_mock.assert_called()


if __name__ == "__main__":
    unittest.main()
