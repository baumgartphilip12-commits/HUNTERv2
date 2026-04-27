"""Structured entity dialogs for the PySide6 shell.

Threat and Tool entities get domain-specific editors, while other entity types
fall back to JSON editing.  The public constructor/value API is kept stable so
older tests and callers can still import dialog classes from main_window.
"""

from __future__ import annotations

import json
from typing import Any

from PySide6 import QtCore, QtWidgets

from hunter.qt.entity_editors import ThreatPayloadEditor, ToolPayloadEditor
from hunter.qt.formatting import json_preview as _json_preview
from hunter.qt.theme import QT_STYLE


class EntityEditorDialog(QtWidgets.QDialog):
    """Authoring dialog that preserves entity shape expected by AuthoringService."""

    def __init__(
        self,
        entity_type: str,
        entity: dict[str, Any],
        parent=None,
        *,
        techniques: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(parent)
        self.entity_type = entity_type
        self.entity = dict(entity)
        self.setWindowTitle(f"Edit {entity_type}")
        self.setStyleSheet(QT_STYLE)
        self.resize(900, 720)
        layout = QtWidgets.QVBoxLayout(self)
        form = QtWidgets.QFormLayout()
        self.external_id = QtWidgets.QLineEdit(str(entity.get("external_id", "")))
        self.name = QtWidgets.QLineEdit(str(entity.get("name", "")))
        self.description = QtWidgets.QLineEdit(str(entity.get("short_description", "")))
        self.status = QtWidgets.QLineEdit(str(entity.get("status", "active")))
        self.tags = QtWidgets.QLineEdit(", ".join(entity.get("tags", []) or []))
        form.addRow("External ID", self.external_id)
        form.addRow("Name", self.name)
        form.addRow("Description", self.description)
        form.addRow("Status", self.status)
        form.addRow("Tags", self.tags)
        layout.addLayout(form)
        self.payload_editor = QtWidgets.QPlainTextEdit()
        self.payload_editor.setPlainText(_json_preview(entity.get("payload", {}), limit=200000))
        self.structured_editor: ThreatPayloadEditor | ToolPayloadEditor | None = None
        self.tabs: QtWidgets.QTabWidget | None = None
        technique_catalog = techniques
        if technique_catalog is None and parent is not None and hasattr(parent, "store"):
            technique_catalog = parent.store.list_entities("MitreTechnique")
        technique_catalog = technique_catalog or []
        available_sigma_families: dict[str, int] | list[str] = []
        if parent is not None and hasattr(parent, "sigma_rule_service") and parent.sigma_rule_service is not None:
            available_sigma_families = parent.sigma_rule_service.available_source_families()
        payload = entity.get("payload", {}) if isinstance(entity.get("payload"), dict) else {}
        if entity_type == "ThreatProfile":
            self.structured_editor = ThreatPayloadEditor(techniques=technique_catalog, payload=payload)
            self.tabs = self.structured_editor.tabs
            layout.addWidget(self.structured_editor, 1)
        elif entity_type == "ToolPack":
            self.structured_editor = ToolPayloadEditor(
                techniques=technique_catalog,
                payload=payload,
                available_sigma_families=available_sigma_families,
            )
            self.tabs = self.structured_editor.tabs
            layout.addWidget(self.structured_editor, 1)
        else:
            layout.addWidget(QtWidgets.QLabel("Structured payload JSON"))
            layout.addWidget(self.payload_editor, 1)
        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Save | QtWidgets.QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self._accept_if_valid)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _accept_if_valid(self) -> None:
        """Keep the dialog open when raw JSON or required top-level fields are invalid."""

        if self.structured_editor is None:
            try:
                json.loads(self.payload_editor.toPlainText() or "{}")
            except json.JSONDecodeError as exc:
                QtWidgets.QMessageBox.warning(self, "Invalid JSON", str(exc))
                return
        if not self.external_id.text().strip() or not self.name.text().strip():
            QtWidgets.QMessageBox.warning(self, "Missing Fields", "External ID and name are required.")
            return
        self.accept()

    def value(self) -> dict[str, Any]:
        """Return the edited entity dictionary in AuthoringService-compatible shape."""

        entity = dict(self.entity)
        entity.update(
            {
                "type": self.entity_type,
                "external_id": self.external_id.text().strip(),
                "name": self.name.text().strip(),
                "short_description": self.description.text().strip(),
                "status": self.status.text().strip() or "active",
                "tags": [value.strip() for value in self.tags.text().split(",") if value.strip()],
            }
        )
        if isinstance(self.structured_editor, ThreatPayloadEditor):
            entity["payload"] = self.structured_editor.payload(summary=entity["short_description"])
        elif isinstance(self.structured_editor, ToolPayloadEditor):
            entity["payload"] = self.structured_editor.payload(summary=entity["short_description"])
        else:
            entity["payload"] = json.loads(self.payload_editor.toPlainText() or "{}")
        return entity


class SigmaScopeEditorDialog(QtWidgets.QDialog):
    """Selector for a ToolPack's Sigma source-family scope.

    Imported families are checkable rows with counts; custom families are kept
    separately so analysts can configure source scopes before rules are synced.
    """

    def __init__(
        self,
        *,
        available_families: dict[str, int] | list[str] | tuple[str, ...],
        current_families: list[str] | tuple[str, ...] | set[str],
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit Tool Sigma Scope")
        self.resize(560, 520)

        layout = QtWidgets.QVBoxLayout(self)
        intro = QtWidgets.QLabel("Choose known Sigma source families, or add specific family names in Other.")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        known_group = QtWidgets.QGroupBox("Known Sigma Families")
        known_layout = QtWidgets.QVBoxLayout(known_group)
        self.search = QtWidgets.QLineEdit()
        self.search.setPlaceholderText("Filter families")
        known_layout.addWidget(self.search)
        self.known_list = QtWidgets.QListWidget()
        self.known_list.setMinimumHeight(180)
        known_layout.addWidget(self.known_list)
        layout.addWidget(known_group, 1)

        other_group = QtWidgets.QGroupBox("Other")
        other_layout = QtWidgets.QVBoxLayout(other_group)
        entry_row = QtWidgets.QHBoxLayout()
        self.custom_input = QtWidgets.QLineEdit()
        self.custom_input.setPlaceholderText("Add a custom source family")
        self.add_custom_button = QtWidgets.QPushButton("Add")
        entry_row.addWidget(self.custom_input, 1)
        entry_row.addWidget(self.add_custom_button)
        other_layout.addLayout(entry_row)
        self.custom_list = QtWidgets.QListWidget()
        self.custom_list.setMinimumHeight(90)
        other_layout.addWidget(self.custom_list)
        remove_row = QtWidgets.QHBoxLayout()
        remove_row.addStretch(1)
        self.remove_custom_button = QtWidgets.QPushButton("Remove Selected")
        remove_row.addWidget(self.remove_custom_button)
        other_layout.addLayout(remove_row)
        layout.addWidget(other_group)

        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._populate(available_families, current_families)
        self.search.textChanged.connect(self._apply_filter)
        self.add_custom_button.clicked.connect(self._add_custom_family)
        self.custom_input.returnPressed.connect(self._add_custom_family)
        self.remove_custom_button.clicked.connect(self._remove_selected_custom_families)

    @staticmethod
    def _normalize_family(value: Any) -> str:
        return str(value).strip().lower()

    def _available_counts(self, available_families: dict[str, int] | list[str] | tuple[str, ...]) -> dict[str, int]:
        if isinstance(available_families, dict):
            return {
                self._normalize_family(family): int(count or 0)
                for family, count in available_families.items()
                if self._normalize_family(family)
            }
        return {self._normalize_family(family): 0 for family in available_families if self._normalize_family(family)}

    def _populate(
        self,
        available_families: dict[str, int] | list[str] | tuple[str, ...],
        current_families: list[str] | tuple[str, ...] | set[str],
    ) -> None:
        counts = self._available_counts(available_families)
        current = [self._normalize_family(family) for family in current_families if self._normalize_family(family)]
        current_set = set(current)
        for family in sorted(counts):
            suffix = f" ({counts[family]})" if counts[family] else ""
            item = QtWidgets.QListWidgetItem(f"{family}{suffix}")
            item.setData(QtCore.Qt.UserRole, family)
            item.setFlags(item.flags() | QtCore.Qt.ItemIsUserCheckable)
            item.setCheckState(QtCore.Qt.Checked if family in current_set else QtCore.Qt.Unchecked)
            self.known_list.addItem(item)
        for family in current:
            if family not in counts:
                self._append_custom_family(family)

    def _apply_filter(self, text: str) -> None:
        query = text.strip().lower()
        for row in range(self.known_list.count()):
            item = self.known_list.item(row)
            family = str(item.data(QtCore.Qt.UserRole) or "")
            item.setHidden(bool(query and query not in family))

    def _append_custom_family(self, family: str) -> None:
        if not family or family in self._current_custom_families():
            return
        item = QtWidgets.QListWidgetItem(family)
        self.custom_list.addItem(item)

    def _current_custom_families(self) -> set[str]:
        return {self.custom_list.item(row).text() for row in range(self.custom_list.count())}

    def _add_custom_family(self) -> None:
        family = self._normalize_family(self.custom_input.text())
        if not family:
            return
        for row in range(self.known_list.count()):
            item = self.known_list.item(row)
            if item.data(QtCore.Qt.UserRole) == family:
                item.setCheckState(QtCore.Qt.Checked)
                self.custom_input.clear()
                return
        self._append_custom_family(family)
        self.custom_input.clear()

    def _remove_selected_custom_families(self) -> None:
        for item in self.custom_list.selectedItems():
            self.custom_list.takeItem(self.custom_list.row(item))

    def families(self) -> list[str]:
        """Return checked known families plus custom families, normalized and deduped."""

        selected: list[str] = []
        seen: set[str] = set()
        for row in range(self.known_list.count()):
            item = self.known_list.item(row)
            family = str(item.data(QtCore.Qt.UserRole) or "")
            if item.checkState() == QtCore.Qt.Checked and family and family not in seen:
                selected.append(family)
                seen.add(family)
        for row in range(self.custom_list.count()):
            family = self._normalize_family(self.custom_list.item(row).text())
            if family and family not in seen:
                selected.append(family)
                seen.add(family)
        return selected


