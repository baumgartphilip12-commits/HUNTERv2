"""Settings and sync dialogs for the PySide6 shell.

This module owns user-facing source management.  It deliberately keeps source
CRUD and sync execution separate from connector internals, so the dialog can
display status/details while SyncService remains the only sync engine.
"""

from __future__ import annotations

import sys
from typing import Any

from PySide6 import QtCore, QtWidgets

from hunter.models.knowledge_store import utc_now
from hunter.qt.formatting import json_preview as _json_preview
from hunter.qt.models import EntityListModel
from hunter.runtime_paths import offline_mode, repo_relative_path, resolve_repo_path, sigma_modules_dir
from hunter.vendor_runtime import ensure_vendor_packages


def _sigma_source_dialog_class():
    """Return the patchable compatibility dialog class exposed by main_window."""

    main_window = sys.modules.get("hunter.qt.main_window")
    if main_window is not None:
        return getattr(main_window, "SigmaSourceDialog", SigmaSourceDialog)
    return SigmaSourceDialog


class SigmaSourceDialog(QtWidgets.QDialog):
    """Structured editor for configurable Sigma sync sources.

    Local paths are stored repo-relative whenever possible so source records can
    survive project folder moves and be shared across machines.
    """

    KIND_CONFIG = {
        "Remote ZIP URL": "archive_url",
        "Local ZIP Archive": "archive_path",
        "Local YAML Folder": "rules_dir",
        "Local YAML File": "rules_file",
    }

    def __init__(self, *, project_dir: str, source: dict[str, Any] | None = None, parent=None) -> None:
        super().__init__(parent)
        self.project_dir = project_dir
        self.source = source or {}
        self.setWindowTitle("Sigma Source")
        self.resize(640, 320)
        layout = QtWidgets.QVBoxLayout(self)
        form = QtWidgets.QFormLayout()
        self.name_edit = QtWidgets.QLineEdit(str(self.source.get("name") or ""))
        self.kind_combo = QtWidgets.QComboBox()
        self.kind_combo.addItems(list(self.KIND_CONFIG))
        self.location_edit = QtWidgets.QLineEdit()
        self.repo_url_edit = QtWidgets.QLineEdit()
        self.raw_base_url_edit = QtWidgets.QLineEdit()
        self.enabled_check = QtWidgets.QCheckBox("Enabled")
        self.approved_check = QtWidgets.QCheckBox("Approved")
        self.enabled_check.setChecked(bool(self.source.get("enabled", True)))
        self.approved_check.setChecked(bool(self.source.get("approved", True)))
        location_row = QtWidgets.QHBoxLayout()
        location_row.addWidget(self.location_edit, 1)
        self.browse_button = QtWidgets.QPushButton("Browse")
        location_row.addWidget(self.browse_button)
        form.addRow("Name", self.name_edit)
        form.addRow("Kind", self.kind_combo)
        form.addRow("Location", location_row)
        form.addRow("Repo URL", self.repo_url_edit)
        form.addRow("Raw Base URL", self.raw_base_url_edit)
        checks = QtWidgets.QHBoxLayout()
        checks.addWidget(self.enabled_check)
        checks.addWidget(self.approved_check)
        checks.addStretch(1)
        form.addRow("Status", checks)
        layout.addLayout(form)
        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.browse_button.clicked.connect(self.browse_location)
        self.kind_combo.currentTextChanged.connect(self._update_browse_enabled)
        self._populate_from_source()

    def _populate_from_source(self) -> None:
        config = self.source.get("config", {}) if isinstance(self.source.get("config"), dict) else {}
        for label, key in self.KIND_CONFIG.items():
            if config.get(key):
                self.kind_combo.setCurrentText(label)
                self.location_edit.setText(str(config.get(key)))
                break
        self.repo_url_edit.setText(str(config.get("repo_url", "")))
        self.raw_base_url_edit.setText(str(config.get("raw_base_url", "")))
        if not self.name_edit.text():
            self.name_edit.setText("Local Sigma Source")
        self._update_browse_enabled()

    def _update_browse_enabled(self) -> None:
        self.browse_button.setEnabled(self.kind_combo.currentText() != "Remote ZIP URL")

    def browse_location(self) -> None:
        start = str(sigma_modules_dir(self.project_dir))
        kind = self.kind_combo.currentText()
        if kind == "Local YAML Folder":
            path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select Sigma Folder", start)
        elif kind == "Local ZIP Archive":
            path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Sigma ZIP", start, "ZIP Archives (*.zip)")
        else:
            path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Sigma YAML", start, "Sigma YAML (*.yml *.yaml)")
        if path:
            self.location_edit.setText(self._portable_path(path))

    def _portable_path(self, path: str) -> str:
        """Convert local picker output to a repo-relative ref when possible."""

        try:
            return repo_relative_path(path, self.project_dir)
        except Exception:
            return path

    def _location_value(self) -> str:
        text = self.location_edit.text().strip()
        if not text or self.kind_combo.currentText() == "Remote ZIP URL":
            return text
        return self._portable_path(str(resolve_repo_path(text, self.project_dir)))

    def value(self) -> dict[str, Any]:
        """Return the create/update payload consumed by KnowledgeStore source APIs."""

        name = self.name_edit.text().strip()
        if not name:
            raise ValueError("Sigma source name is required.")
        location = self._location_value()
        if not location:
            raise ValueError("Sigma source location is required.")
        config = {self.KIND_CONFIG[self.kind_combo.currentText()]: location}
        repo_url = self.repo_url_edit.text().strip()
        raw_base_url = self.raw_base_url_edit.text().strip()
        if repo_url:
            config["repo_url"] = repo_url
        if raw_base_url:
            config["raw_base_url"] = raw_base_url
        return {
            "name": name,
            "connector": "sigmahq_rules",
            "config": config,
            "enabled": self.enabled_check.isChecked(),
            "approved": self.approved_check.isChecked(),
        }

    def accept(self) -> None:
        try:
            self.value()
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Invalid Sigma Source", str(exc))
            return
        super().accept()


class SettingsSyncDialog(QtWidgets.QDialog):
    """Qt Settings / Sync dialog for source operations and vendor repair."""

    PROTECTED_SOURCE_NAMES = {"MITRE ATT&CK Enterprise", "Layered Local Modules", "SigmaHQ Rules"}

    def __init__(self, *, store, sync_service, project_dir: str | None = None, parent=None) -> None:
        super().__init__(parent)
        self.store = store
        self.sync_service = sync_service
        self.project_dir = project_dir or str(getattr(store, "project_dir", ""))
        self.setWindowTitle("Settings / Sync")
        self.resize(980, 680)
        self.model = EntityListModel()
        layout = QtWidgets.QVBoxLayout(self)
        mode_text = "Portable Offline Mode" if offline_mode() else "Online-Capable Mode"
        self.mode_label = QtWidgets.QLabel(mode_text)
        layout.addWidget(self.mode_label)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        layout.addWidget(splitter, 1)
        left = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left)
        self.source_list = QtWidgets.QListView()
        self.source_list.setModel(self.model)
        left_layout.addWidget(self.source_list, 1)
        button_row = QtWidgets.QVBoxLayout()
        self.preview_button = QtWidgets.QPushButton("Preview")
        self.apply_button = QtWidgets.QPushButton("Sync")
        self.rollback_button = QtWidgets.QPushButton("Rollback")
        self.add_sigma_button = QtWidgets.QPushButton("Add Sigma Source")
        self.edit_source_button = QtWidgets.QPushButton("Edit Source")
        self.remove_source_button = QtWidgets.QPushButton("Remove Source")
        self.import_bundle_button = QtWidgets.QPushButton("Import Offline Bundle")
        self.export_bundle_button = QtWidgets.QPushButton("Export Offline Bundle")
        self.vendor_button = QtWidgets.QPushButton("Install/Repair Python Vendor Packages")
        for button in (
            self.preview_button,
            self.apply_button,
            self.rollback_button,
            self.add_sigma_button,
            self.edit_source_button,
            self.remove_source_button,
            self.import_bundle_button,
            self.export_bundle_button,
            self.vendor_button,
        ):
            button_row.addWidget(button)
        left_layout.addLayout(button_row)
        self.detail = QtWidgets.QTextBrowser()
        splitter.addWidget(left)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(1, 3)
        self.source_list.selectionModel().selectionChanged.connect(self.render_source)
        self.preview_button.clicked.connect(lambda: self.run_sync_action("preview"))
        self.apply_button.clicked.connect(lambda: self.run_sync_action("apply"))
        self.rollback_button.clicked.connect(lambda: self.run_sync_action("rollback"))
        self.add_sigma_button.clicked.connect(self.add_sigma_source)
        self.edit_source_button.clicked.connect(self.edit_source)
        self.remove_source_button.clicked.connect(self.remove_source)
        self.import_bundle_button.clicked.connect(self.import_offline_bundle)
        self.export_bundle_button.clicked.connect(self.export_offline_bundle)
        self.vendor_button.clicked.connect(self.install_vendor)
        self.refresh()

    def refresh(self, *, select_id: int | None = None, render: bool = True) -> None:
        """Refresh the source list while preserving selection and optional detail text."""

        current_id = select_id
        if current_id is None:
            current = self.selected_source()
            current_id = current.get("id") if current else None
        blocker = QtCore.QSignalBlocker(self.source_list.selectionModel())
        self.model.set_entities(self.store.list_sources())
        selected = False
        if current_id is not None:
            row = self.model.row_for_id(current_id)
            if row >= 0:
                self.source_list.setCurrentIndex(self.model.index(row, 0))
                selected = True
        if self.model.rowCount():
            if not selected:
                self.source_list.setCurrentIndex(self.model.index(0, 0))
                selected = True
        del blocker
        if render:
            self.render_source()

    def selected_source(self) -> dict[str, Any] | None:
        index = self.source_list.currentIndex()
        if not index.isValid():
            return None
        return self.model.entity_at(index.row())

    def render_source(self) -> None:
        """Render a readable source summary, with structured Sigma config details."""

        source = self.selected_source()
        if not source:
            self.detail.setPlainText("Select a source.")
            return
        if source.get("connector") == "sigmahq_rules":
            config = source.get("config", {}) if isinstance(source.get("config"), dict) else {}
            location_mode = self._source_location_mode(config)
            lines = [
                f"Name: {source.get('name', '')}",
                "Type: Sigma Rules",
                f"Location Mode: {location_mode}",
                f"Enabled: {source.get('enabled', False)}",
                f"Approved: {source.get('approved', False)}",
                f"Health: {source.get('health', '')}",
                f"Last Status: {source.get('last_status', '')}",
                f"Last Sync: {source.get('last_sync_at', '') or 'Never'}",
                "",
                "Config:",
            ]
            for key in ("archive_url", "archive_path", "rules_dir", "rules_file", "repo_url", "raw_base_url"):
                if config.get(key):
                    lines.append(f"- {key}: {config[key]}")
            self.detail.setPlainText("\n".join(lines))
            return
        config = source.get("config", {}) if isinstance(source.get("config"), dict) else {}
        location_mode = self._source_location_mode(config)
        self.detail.setPlainText(f"Location Mode: {location_mode}\n\n" + _json_preview(source, limit=30000))

    @staticmethod
    def _source_location_mode(config: dict[str, Any]) -> str:
        if any(config.get(key) for key in ("bundle_file", "bundle_path", "archive_path", "rules_dir", "rules_file")):
            return "Local"
        if any(config.get(key) for key in ("bundle_url", "archive_url", "repo_url", "raw_base_url")):
            return "Online"
        return "Local"

    def run_sync_action(self, action: str) -> None:
        """Run preview/sync/rollback and keep the action result visible after refresh."""

        source = self.selected_source()
        if not source:
            return
        try:
            if action == "preview":
                result = self.sync_service.preview_source(source["id"])
                self.detail.setPlainText(_json_preview({"summary": result.summary, "diff": result.diff}, limit=60000))
            elif action == "apply":
                result = self.sync_service.apply_source(source["id"])
                self.detail.setPlainText(_json_preview({"applied": result.summary}, limit=60000))
            else:
                result = self.sync_service.rollback_latest(source["id"])
                self.detail.setPlainText(_json_preview({"rolled_back": result}, limit=60000))
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Sync Failed", str(exc))
            self.refresh(select_id=source["id"])
            return
        self.refresh(select_id=source["id"], render=False)

    def install_vendor(self) -> None:
        status = ensure_vendor_packages(interactive=True, parent=self)
        self.detail.setPlainText(_json_preview(status))

    def export_offline_bundle(self) -> None:
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Export Offline Knowledge Bundle",
            "hunter_knowledge_bundle.json",
            "JSON Files (*.json)",
        )
        if not path:
            return
        try:
            summary = self.sync_service.export_offline_bundle(path)
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Export Failed", str(exc))
            return
        self.detail.setPlainText(_json_preview({"exported": summary, "path": path}, limit=60000))

    def import_offline_bundle(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Import Offline Knowledge Bundle",
            "",
            "JSON Files (*.json)",
        )
        if not path:
            return
        try:
            summary = self.sync_service.import_offline_bundle(path)
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Import Failed", str(exc))
            return
        self.refresh(render=False)
        self.detail.setPlainText(_json_preview({"imported": summary, "path": path}, limit=60000))

    def add_sigma_source(self) -> None:
        dialog = _sigma_source_dialog_class()(project_dir=self.project_dir, parent=self)
        if dialog.exec() != QtWidgets.QDialog.Accepted:
            return
        try:
            value = dialog.value()
            source_id = self.store.create_source(**value)
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Source Save Failed", str(exc))
            return
        self.refresh()
        self._select_source_id(source_id)

    def edit_source(self) -> None:
        source = self.selected_source()
        if not source or source.get("connector") != "sigmahq_rules":
            QtWidgets.QMessageBox.information(self, "Edit Source", "Select a Sigma source to edit.")
            return
        dialog = _sigma_source_dialog_class()(project_dir=self.project_dir, source=source, parent=self)
        if dialog.exec() != QtWidgets.QDialog.Accepted:
            return
        try:
            value = dialog.value()
            self.store.update_source(
                source["id"],
                name=value["name"],
                connector=value["connector"],
                config=value["config"],
                enabled=value["enabled"],
                approved=value["approved"],
            )
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Source Save Failed", str(exc))
            return
        self.refresh()
        self._select_source_id(source["id"])

    def remove_source(self) -> None:
        source = self.selected_source()
        if not source or source.get("name") in self.PROTECTED_SOURCE_NAMES or source.get("connector") != "sigmahq_rules":
            return
        if (
            QtWidgets.QMessageBox.question(
                self,
                "Remove Sigma Source",
                f"Remove '{source['name']}' and its imported Sigma records?",
            )
            != QtWidgets.QMessageBox.Yes
        ):
            return
        self.store.delete_source(source["name"])
        self.refresh()

    def _select_source_id(self, source_id: int) -> None:
        row = self.model.row_for_id(source_id)
        if row >= 0:
            self.source_list.setCurrentIndex(self.model.index(row, 0))


