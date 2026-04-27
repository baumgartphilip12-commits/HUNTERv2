"""Generate workflow page for the PySide6 shell.

Generate is the canonical owner of hunt-scope selection.  Browse tabs can ask
the main window to toggle rows here, but this page owns selected threat/tool/
manual-MITRE IDs, Sigma family checkboxes, and draft invalidation.
"""

from __future__ import annotations

import sys
from typing import Any

from PySide6 import QtCore, QtWidgets

from hunter.qt.entity_dialogs import SigmaScopeEditorDialog
from hunter.qt.models import EntityListModel, EntitySearchProxy, GenerateSelectedItemDelegate


def _sigma_scope_dialog_class():
    """Return the patchable compatibility dialog class exposed by main_window."""

    main_window = sys.modules.get("hunter.qt.main_window")
    if main_window is not None:
        return getattr(main_window, "SigmaScopeEditorDialog", SigmaScopeEditorDialog)
    return SigmaScopeEditorDialog


class GeneratePage(QtWidgets.QWidget):
    """Build and persist hunt-pack drafts from selected entities."""

    huntPackGenerated = QtCore.Signal(int)

    def __init__(self, *, store, hunt_generator, sigma_rule_service, parent=None) -> None:
        super().__init__(parent)
        self.store = store
        self.hunt_generator = hunt_generator
        self.sigma_rule_service = sigma_rule_service
        self._last_draft = None
        self._family_checks: dict[str, QtWidgets.QCheckBox] = {}
        self._sigma_family_selection: set[str] | None = None

        layout = QtWidgets.QVBoxLayout(self)
        title = QtWidgets.QLabel("Generate")
        title.setObjectName("SectionTitle")
        layout.addWidget(title)

        self.mission_name = QtWidgets.QLineEdit("Generated Hunt Pack")
        layout.addWidget(self.mission_name)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        layout.addWidget(splitter, 1)

        self.threats = self._selection_panel("Threats", "ThreatProfile")
        self.tools = self._selection_panel("Tools", "ToolPack")
        self.mitre = self._selection_panel("Manual MITRE", "MitreTechnique")
        splitter.addWidget(self.threats["widget"])
        splitter.addWidget(self.tools["widget"])
        splitter.addWidget(self.mitre["widget"])

        self.sigma_group = QtWidgets.QGroupBox("Sigma Families")
        sigma_layout = QtWidgets.QVBoxLayout(self.sigma_group)
        self.sigma_help = QtWidgets.QLabel("Sigma families are limited by selected tools; Azure requires an Azure-scoped ToolPack.")
        self.sigma_help.setWordWrap(True)
        sigma_layout.addWidget(self.sigma_help)
        self.sigma_checks = QtWidgets.QWidget()
        self.sigma_checks_layout = QtWidgets.QVBoxLayout(self.sigma_checks)
        sigma_layout.addWidget(self.sigma_checks)
        self.reset_sigma_button = QtWidgets.QPushButton("Reset To Tool Defaults")
        self.edit_sigma_button = QtWidgets.QPushButton("Edit Tool Sigma Scope")
        sigma_buttons = QtWidgets.QHBoxLayout()
        sigma_buttons.addWidget(self.reset_sigma_button)
        sigma_buttons.addWidget(self.edit_sigma_button)
        sigma_layout.addLayout(sigma_buttons)
        layout.addWidget(self.sigma_group)

        action_row = QtWidgets.QHBoxLayout()
        self.preview_button = QtWidgets.QPushButton("Build Preview")
        self.generate_button = QtWidgets.QPushButton("Generate Hunt Pack")
        self.generate_button.setObjectName("Primary")
        action_row.addWidget(self.preview_button)
        action_row.addWidget(self.generate_button)
        layout.addLayout(action_row)

        self.preview = QtWidgets.QTextBrowser()
        layout.addWidget(self.preview, 1)

        self.preview_button.clicked.connect(self.build_preview)
        self.generate_button.clicked.connect(self.generate)
        self.reset_sigma_button.clicked.connect(self.reset_sigma_defaults)
        self.edit_sigma_button.clicked.connect(self.edit_tool_sigma_scope)
        self.mission_name.textChanged.connect(self.invalidate_draft)
        for panel in (self.threats, self.tools, self.mitre):
            panel["view"].selectionModel().selectionChanged.connect(
                lambda _selected, _deselected, current_panel=panel: self._sync_panel_selected_ids(current_panel)
            )
            panel["view"].selectionModel().selectionChanged.connect(self.invalidate_draft)
            panel["view"].selectionModel().selectionChanged.connect(self.refresh_sigma_families)

        self.refresh()

    def _selection_panel(self, label: str, entity_type: str) -> dict[str, Any]:
        widget = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(widget)
        layout.addWidget(QtWidgets.QLabel(label))
        search = QtWidgets.QLineEdit()
        search.setPlaceholderText("Search")
        layout.addWidget(search)
        model = EntityListModel()
        proxy = EntitySearchProxy(widget)
        proxy.setSourceModel(model)
        view = QtWidgets.QListView()
        view.setSelectionMode(QtWidgets.QAbstractItemView.MultiSelection)
        view.setModel(proxy)
        view.setItemDelegate(GenerateSelectedItemDelegate(view))
        layout.addWidget(view, 1)
        search.textChanged.connect(proxy.set_search_text)
        return {"widget": widget, "model": model, "proxy": proxy, "view": view, "type": entity_type}

    def refresh(self) -> None:
        """Reload selectable entities while preserving current Generate selections."""

        selected_by_type = {
            panel["type"]: self.selected_ids_for_type(panel["type"])
            for panel in (self.threats, self.tools, self.mitre)
        }
        for panel in (self.threats, self.tools, self.mitre):
            panel["model"].set_entities(self.store.list_entities(panel["type"]))
            self._restore_panel_selection(panel, selected_by_type.get(panel["type"], set()))
            self._sync_panel_selected_ids(panel)
        self.refresh_sigma_families()

    def _selected_entities(self, panel: dict[str, Any]) -> list[dict[str, Any]]:
        selected: list[dict[str, Any]] = []
        for proxy_index in panel["view"].selectionModel().selectedRows():
            source_index = panel["proxy"].mapToSource(proxy_index)
            entity = panel["model"].entity_at(source_index.row())
            if entity:
                selected.append(entity)
        return selected

    def _selected_ids(self, panel: dict[str, Any]) -> list[int]:
        return [entity["id"] for entity in self._selected_entities(panel)]

    def _panel_for_type(self, entity_type: str) -> dict[str, Any] | None:
        for panel in (self.threats, self.tools, self.mitre):
            if panel["type"] == entity_type:
                return panel
        return None

    def selected_ids_for_type(self, entity_type: str) -> set[int]:
        panel = self._panel_for_type(entity_type)
        if panel is None:
            return set()
        return {int(entity_id) for entity_id in self._selected_ids(panel)}

    def has_entity(self, entity_type: str, entity_id: int) -> bool:
        panel = self._panel_for_type(entity_type)
        return bool(panel is not None and panel["model"].row_for_id(entity_id) >= 0)

    def toggle_entity_selection(self, entity_type: str, entity_id: int, *, notify: bool = True) -> bool:
        """Toggle a row by entity ID and return True when the row becomes selected."""

        panel = self._panel_for_type(entity_type)
        if panel is None:
            return False
        source_row = panel["model"].row_for_id(entity_id)
        if source_row < 0:
            return False
        proxy_index = panel["proxy"].mapFromSource(panel["model"].index(source_row, 0))
        if not proxy_index.isValid():
            return False
        selection_model = panel["view"].selectionModel()
        is_selected = selection_model.isSelected(proxy_index)
        command = QtCore.QItemSelectionModel.Deselect if is_selected else QtCore.QItemSelectionModel.Select
        if notify:
            selection_model.select(proxy_index, command | QtCore.QItemSelectionModel.Rows)
        else:
            blocker = QtCore.QSignalBlocker(selection_model)
            selection_model.select(proxy_index, command | QtCore.QItemSelectionModel.Rows)
            del blocker
        self._sync_panel_selected_ids(panel)
        return not is_selected

    def _restore_panel_selection(self, panel: dict[str, Any], entity_ids: set[int]) -> None:
        selection_model = panel["view"].selectionModel()
        selection_model.clearSelection()
        for entity_id in entity_ids:
            source_row = panel["model"].row_for_id(entity_id)
            if source_row < 0:
                continue
            proxy_index = panel["proxy"].mapFromSource(panel["model"].index(source_row, 0))
            if proxy_index.isValid():
                selection_model.select(proxy_index, QtCore.QItemSelectionModel.Select | QtCore.QItemSelectionModel.Rows)
        self._sync_panel_selected_ids(panel)

    def _sync_panel_selected_ids(self, panel: dict[str, Any]) -> None:
        panel["model"].set_selected_ids(self._selected_ids(panel))

    def invalidate_draft(self) -> None:
        """Drop cached preview so Generate never persists stale scope."""

        self._last_draft = None

    def _tool_default_families(self) -> set[str]:
        families: set[str] = set()
        for tool in self._selected_entities(self.tools):
            scope = tool.get("payload", {}).get("sigma_scope", {}) or {}
            families.update(str(value).lower() for value in scope.get("default_families", []) if str(value).strip())
        return families

    def refresh_sigma_families(self) -> None:
        """Rebuild Sigma family checkboxes from selected tool scope and inventory.

        A ``None`` selection means "use current tool defaults"; an empty set is
        a deliberate user choice to include no Sigma families.
        """

        allowed = self._tool_default_families()
        inventory = self.sigma_rule_service.available_source_families()
        families = [family for family in inventory if family in allowed]
        selected_tools = self._selected_entities(self.tools)
        selected = self._sigma_family_selection
        while self.sigma_checks_layout.count():
            item = self.sigma_checks_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._family_checks = {}
        for family in families:
            checkbox = QtWidgets.QCheckBox(f"{family} ({inventory.get(family, 0)})")
            checkbox.setChecked(True if selected is None else family in selected)
            self._family_checks[family] = checkbox
            self.sigma_checks_layout.addWidget(checkbox)
            checkbox.stateChanged.connect(self._sigma_family_changed)
        if not families and len(selected_tools) == 1:
            empty = QtWidgets.QLabel("No matching Sigma families are currently available. Edit the tool scope to choose known or custom families.")
            empty.setWordWrap(True)
            self.sigma_checks_layout.addWidget(empty)
        self.sigma_group.setVisible(bool(families) or len(selected_tools) == 1)
        self.reset_sigma_button.setEnabled(bool(families))
        self.edit_sigma_button.setEnabled(len(selected_tools) == 1)

    def selected_sigma_families(self) -> list[str]:
        return sorted(
            family
            for family, checkbox in self._family_checks.items()
            if checkbox.isChecked()
        )

    def _sigma_family_changed(self) -> None:
        self._sigma_family_selection = {
            family for family, checkbox in self._family_checks.items() if checkbox.isChecked()
        }
        self.invalidate_draft()

    def reset_sigma_defaults(self) -> None:
        self._sigma_family_selection = None
        for checkbox in self._family_checks.values():
            checkbox.setChecked(True)
        self._sigma_family_selection = None
        self.invalidate_draft()

    def edit_tool_sigma_scope(self) -> None:
        tools = self._selected_entities(self.tools)
        if len(tools) != 1:
            QtWidgets.QMessageBox.information(self, "Select One Tool", "Select exactly one ToolPack to edit Sigma scope.")
            return
        tool = tools[0]
        payload = tool.get("payload", {}) if isinstance(tool.get("payload"), dict) else {}
        scope = payload.get("sigma_scope", {}) if isinstance(payload.get("sigma_scope"), dict) else {}
        current = scope.get("default_families", []) or []
        dialog_class = _sigma_scope_dialog_class()
        dialog = dialog_class(
            available_families=self.sigma_rule_service.available_source_families(),
            current_families=current,
            parent=self,
        )
        if dialog.exec() != QtWidgets.QDialog.Accepted:
            return
        families = dialog.families()
        parent = self.window()
        try:
            parent.authoring_service.save_tool_sigma_scope(tool, families)
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Sigma Scope Save Failed", str(exc))
            return
        self.refresh()
        self.invalidate_draft()

    def build_preview(self) -> None:
        try:
            self._last_draft = self.hunt_generator.generate(
                mission_name=self.mission_name.text().strip() or "Generated Hunt Pack",
                threat_ids=self._selected_ids(self.threats),
                tool_ids=self._selected_ids(self.tools),
                manual_technique_ids=self._selected_ids(self.mitre),
                selected_sigma_families=self.selected_sigma_families(),
            )
        except Exception as exc:
            self.preview.setPlainText(f"Preview failed: {exc}")
            return
        summary = self._last_draft.summary
        sigma_ids = self._last_draft.payload.get("audit", {}).get("sigma_rule_ids", [])
        sigma_lines = self._sigma_rule_preview_lines(self._last_draft)
        visible_sigma_lines = sigma_lines[:80]
        if len(sigma_lines) > 80:
            visible_sigma_lines.append(f"... and {len(sigma_lines) - 80} more Sigma rules")
        self.preview.setPlainText(
            "\n".join(
                [
                    summary.get("mission_name", self._last_draft.name),
                    "",
                    f"Steps: {summary.get('candidate_steps', 0)}",
                    f"Enabled: {summary.get('enabled_steps', 0)}",
                    f"Sigma rules: {len(sigma_ids)}",
                    "",
                    "Sigma Rules:",
                    "\n".join(visible_sigma_lines) or "None",
                ]
            )
        )

    def _sigma_rule_preview_lines(self, draft: Any) -> list[str]:
        """Format Sigma preview rows with titles first and IDs only as fallback."""

        payload = draft.payload if isinstance(getattr(draft, "payload", None), dict) else {}
        steps = payload.get("steps", [])
        audit = payload.get("audit", {}) if isinstance(payload.get("audit"), dict) else {}
        sigma_ids = [str(value) for value in audit.get("sigma_rule_ids", []) if str(value).strip()]
        lines: list[str] = []
        seen: set[str] = set()

        if isinstance(steps, list):
            for step in steps:
                if not isinstance(step, dict):
                    continue
                sigma_id = str(step.get("sigma_rule_id", "")).strip()
                if not sigma_id or sigma_id in seen:
                    continue
                seen.add(sigma_id)
                lines.append(self._sigma_step_preview_label(step, sigma_id))

        for sigma_id in sigma_ids:
            if sigma_id in seen:
                continue
            seen.add(sigma_id)
            lines.append(self._sigma_entity_preview_label(sigma_id))
        return lines

    def _sigma_step_preview_label(self, step: dict[str, Any], sigma_id: str) -> str:
        title = str(step.get("sigma_title") or step.get("title") or "").strip()
        if title.endswith(" (Sigma)"):
            title = title[:-8].strip()
        if not title:
            title = self._sigma_entity_preview_label(sigma_id)
        details = self._sigma_preview_details(
            techniques=step.get("techniques", []),
            source_family=step.get("sigma_source_family", ""),
        )
        return f"{title} ({details})" if details and title != sigma_id else title

    def _sigma_entity_preview_label(self, sigma_id: str) -> str:
        rule = self.store.get_entity_by_external_id("SigmaRule", sigma_id)
        if rule is None:
            return sigma_id
        payload = rule.get("payload", {}) if isinstance(rule.get("payload"), dict) else {}
        title = str(rule.get("name") or payload.get("title") or sigma_id).strip() or sigma_id
        details = self._sigma_preview_details(
            techniques=payload.get("attack_techniques", []),
            source_family=payload.get("source_family", ""),
        )
        return f"{title} ({details})" if details else title

    def _sigma_preview_details(self, *, techniques: Any, source_family: Any) -> str:
        detail_parts: list[str] = []
        family = str(source_family).strip()
        if family:
            detail_parts.append(family)
        if isinstance(techniques, (list, tuple, set)):
            technique_values = [str(value).strip() for value in techniques if str(value).strip()]
        else:
            technique_values = [str(techniques).strip()] if str(techniques).strip() else []
        if technique_values:
            detail_parts.append(", ".join(technique_values[:6]))
        return "; ".join(detail_parts)

    def generate(self) -> None:
        """Persist the current draft, rebuilding first when inputs invalidated it."""

        if self._last_draft is None:
            self.build_preview()
        if self._last_draft is None:
            return
        hunt_pack_id = self.hunt_generator.persist(self._last_draft)
        self.huntPackGenerated.emit(hunt_pack_id)


