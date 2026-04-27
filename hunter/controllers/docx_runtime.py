"""DOCX export runtime helpers for Node/npm-backed report generation.

The Python UI owns prompts, file selection, and dependency checks.  Actual DOCX
composition stays in ``export_docx.js`` so the report can use the JavaScript
``docx`` package and JSZip post-processing for collapsed outline sections.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
from datetime import datetime

from PySide6 import QtWidgets

from hunter.runtime_paths import bundled_node_path, export_docx_script_path, offline_mode, project_root


class DocxRuntimeHelper:
    """Runtime helpers for the DOCX export pipeline."""

    @staticmethod
    def find_node(script_dir: str | None = None) -> str | None:
        """Find Node.js across PATH and common Windows/nvm install locations."""

        bundled = bundled_node_path(script_dir)
        if bundled.exists():
            return str(bundled)

        found = shutil.which("node") or shutil.which("node.exe")
        if found:
            return found

        candidate_paths = [
            os.path.join(os.environ.get("PROGRAMFILES", ""), "nodejs", "node.exe"),
            os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "nodejs", "node.exe"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "nodejs", "node.exe"),
        ]
        nvm_symlink = os.environ.get("NVM_SYMLINK", "")
        if nvm_symlink:
            candidate_paths.append(os.path.join(nvm_symlink, "node.exe"))
        nvm_home = os.environ.get("NVM_HOME", "") or os.path.join(os.environ.get("APPDATA", ""), "nvm")
        if nvm_home:
            candidate_paths.append(os.path.join(nvm_home, "node.exe"))
            candidate_paths.extend(
                sorted(glob.glob(os.path.join(nvm_home, "v*", "node.exe")), reverse=True)
            )
        for candidate in candidate_paths:
            if candidate and os.path.exists(candidate):
                return candidate
        return None

    @staticmethod
    def find_npm(node_cmd: str, script_dir: str | None = None) -> dict:
        """Build an npm command that respects the committed lockfile.

        ``npm ci`` is preferred when ``package-lock.json`` is present so DOCX
        export repairs are reproducible.  The return shape is passed directly to
        ``subprocess.run`` and records whether shell execution is needed.
        """

        node_dir = os.path.dirname(os.path.abspath(node_cmd))
        npm_args = ["ci"] if os.path.exists(os.path.join(str(project_root(script_dir)), "package-lock.json")) else ["install"]
        for name in ("npm.cmd", "npm"):
            candidate = os.path.join(node_dir, name)
            if os.path.exists(candidate):
                return {"cmd": [candidate, *npm_args], "shell": False}
        npm_cli = os.path.join(node_dir, "node_modules", "npm", "bin", "npm-cli.js")
        if os.path.exists(npm_cli):
            return {"cmd": [node_cmd, npm_cli, *npm_args], "shell": False}
        for name in ("npm.cmd", "npm"):
            found = shutil.which(name)
            if found:
                return {"cmd": [found, *npm_args], "shell": False}
        return {"cmd": "npm ci" if npm_args == ["ci"] else "npm install", "shell": True}

    @classmethod
    def run_npm_install(
        cls,
        parent_window: QtWidgets.QWidget | None,
        script_dir: str,
        node_cmd: str,
    ) -> bool:
        """Install/repair DOCX npm dependencies after user confirmation."""

        npm_spec = cls.find_npm(node_cmd, script_dir)
        try:
            result = subprocess.run(
                npm_spec["cmd"],
                capture_output=True,
                text=True,
                cwd=script_dir,
                shell=npm_spec["shell"],
                timeout=240,
                check=False,
            )
        except subprocess.TimeoutExpired:
            QtWidgets.QMessageBox.warning(parent_window, "npm Install Timeout", "npm install timed out after 240 seconds.")
            return False
        except Exception as exc:
            QtWidgets.QMessageBox.warning(parent_window, "npm Install Failed", str(exc))
            return False
        if result.returncode == 0:
            QtWidgets.QMessageBox.information(parent_window, "Package Installed", "DOCX packages installed successfully. Proceeding with export.")
            return True
        err = result.stderr or result.stdout or "npm install failed."
        QtWidgets.QMessageBox.warning(
            parent_window,
            "npm Install Failed",
            "Could not install the DOCX packages automatically.\n\n"
            f"Open a terminal in:\n  {script_dir}\n\n"
            f"and run: npm ci\n\nError:\n{err[:500]}",
        )
        return False

    @classmethod
    def export_word(
        cls,
        parent_window: QtWidgets.QWidget | None,
        plan_dict: dict,
        script_dir: str,
        initial_filename: str | None = None,
    ) -> None:
        """Write temp JSON, invoke export_docx.js, and surface UI errors."""

        project_dir = str(project_root(script_dir))
        docx_script = str(export_docx_script_path(project_dir))
        if not os.path.exists(docx_script):
            QtWidgets.QMessageBox.warning(
                parent_window,
                "Missing File",
                f"export_docx.js not found in:\n{project_dir}\n\n"
                "Make sure the repository still contains export_docx.js at the project root.",
            )
            return

        node_cmd = cls.find_node(project_dir)
        if node_cmd is None:
            QtWidgets.QMessageBox.warning(
                parent_window,
                "Node.js Not Found",
                "Node.js is required for Word export.\n"
                "Download and install from https://nodejs.org, then restart HUNTER.",
            )
            return

        missing_node_modules = [
            name
            for name in ("docx", "jszip")
            if not os.path.isdir(os.path.join(project_dir, "node_modules", name))
        ]
        if missing_node_modules:
            if offline_mode():
                QtWidgets.QMessageBox.warning(
                    parent_window,
                    "DOCX Packages Missing",
                    "This offline HUNTER bundle is missing the DOCX npm packages:\n\n"
                    f"{', '.join(missing_node_modules)}\n\n"
                    "Rebuild the offline bundle with node_modules included, then copy the rebuilt bundle to this system.",
                )
                return
            answer = QtWidgets.QMessageBox.question(
                parent_window,
                "Install Required Package",
                "The DOCX npm packages are not installed yet.\n\n"
                f"Missing: {', '.join(missing_node_modules)}\n\n"
                f"HUNTER will run: npm ci\nin: {project_dir}\n\n"
                "This is a one-time setup. Proceed?",
            )
            if answer != QtWidgets.QMessageBox.Yes:
                return
            if not cls.run_npm_install(parent_window, project_dir, node_cmd):
                return

        path, _selected_filter = QtWidgets.QFileDialog.getSaveFileName(
            parent_window,
            "Export Word Report",
            initial_filename
            or f"HUNTER_Hunt_Plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx",
            "Word Documents (*.docx)",
        )
        if not path:
            return

        tmp_json = os.path.join(project_dir, "_tmp_hunt_plan.json")
        with open(tmp_json, "w", encoding="utf-8") as handle:
            json.dump(plan_dict, handle, indent=2)

        try:
            result = subprocess.run(
                [node_cmd, docx_script, tmp_json, path],
                capture_output=True,
                text=True,
                cwd=project_dir,
                timeout=60,
                check=False,
            )
            if result.returncode == 0:
                QtWidgets.QMessageBox.information(parent_window, "Export Complete", f"Word document exported to:\n{path}")
            else:
                QtWidgets.QMessageBox.warning(
                    parent_window,
                    "Export Failed",
                    f"export_docx.js returned an error:\n\n{result.stderr[:1200]}",
                )
        except subprocess.TimeoutExpired:
            QtWidgets.QMessageBox.warning(parent_window, "Export Timeout", "The Node.js export script timed out after 60 seconds.")
        except Exception as exc:
            QtWidgets.QMessageBox.warning(parent_window, "Export Error", str(exc))
        finally:
            try:
                os.remove(tmp_json)
            except Exception:
                pass
