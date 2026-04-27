"""Entity browse rail for the PySide6 shell.

The browse pages are intentionally light wrappers around shared Qt models: the
Generate page owns selection state, while each browser mirrors that state for
green-row/blue-marker feedback and keeps single-click detail rendering local.
"""

from __future__ import annotations

from typing import Any

from PySide6 import QtCore, QtGui, QtWidgets

from hunter.qt.detail_renderers import EntityDetailRenderer
from hunter.qt.entity_dialogs import EntityEditorDialog
from hunter.qt.models import EntityListModel, EntitySearchProxy, GenerateSelectedItemDelegate


def _entity_title(entity: dict[str, Any] | None) -> str:
    """Return the human label used in dialogs and status messages."""

    if not entity:
        return "No selection"
    return str(entity.get("name") or entity.get("external_id") or "Untitled")


def _attack_url_for_entity(entity: dict[str, Any]) -> str:
    """Resolve an ATT&CK URL from source metadata or technique ID fallback."""

    if entity.get("source_url"):
        return str(entity["source_url"])
    payload = entity.get("payload", {}) if isinstance(entity.get("payload"), dict) else {}
    technique_id = str(payload.get("technique_id") or entity.get("external_id") or "").strip()
    if not technique_id:
        return ""
    if "." in technique_id:
        parent, child = technique_id.split(".", 1)
        return f"https://attack.mitre.org/techniques/{parent}/{child}/"
    return f"https://attack.mitre.org/techniques/{technique_id}/"


class EntityBrowserPage(QtWidgets.QWidget):
    """Shared MITRE/Threat/Tool browser with optional authoring controls."""

    def __init__(
        self,
        *,
        store,
        authoring_service,
        entity_type: str,
        title: str,
        sigma_rule_service=None,
        send_to_generate=None,
        generate_selected_ids=None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.store = store
        self.authoring_service = authoring_service
        self.sigma_rule_service = sigma_rule_service
        self.send_to_generate = send_to_generate
        self.generate_selected_ids = generate_selected_ids
        self.entity_type = entity_type
        self.title = title
        self.model = EntityListModel()
        self.proxy = EntitySearchProxy(self)
        self.proxy.setSourceModel(self.model)

        layout = QtWidgets.QVBoxLayout(self)
        header = QtWidgets.QLabel(title)
        header.setObjectName("SectionTitle")
        layout.addWidget(header)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        layout.addWidget(splitter, 1)

        rail = QtWidgets.QWidget()
        rail_layout = QtWidgets.QVBoxLayout(rail)
        self.search = QtWidgets.QLineEdit()
        self.search.setPlaceholderText('Search, e.g. id:T1001 "domain pivot" -deprecated')
        rail_layout.addWidget(self.search)
        self.list_view = QtWidgets.QListView()
        self.list_view.setModel(self.proxy)
        self.list_view.setItemDelegate(GenerateSelectedItemDelegate(self.list_view))
        self.list_view.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.list_view.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        rail_layout.addWidget(self.list_view, 1)
        if entity_type in {"ThreatProfile", "ToolPack"}:
            label = "Threat" if entity_type == "ThreatProfile" else "Tool"
            button_row = QtWidgets.QHBoxLayout()
            self.add_button = QtWidgets.QPushButton(f"Add {label}")
            self.remove_button = QtWidgets.QPushButton(f"Remove {label}")
            self.edit_button = QtWidgets.QPushButton(f"Edit {label}")
            for button in (self.add_button, self.remove_button, self.edit_button):
                button_row.addWidget(button)
            rail_layout.addLayout(button_row)

        self.detail = QtWidgets.QTextBrowser()
        self.detail.setOpenExternalLinks(True)
        splitter.addWidget(rail)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)

        self.search.textChanged.connect(self.proxy.set_search_text)
        self.list_view.selectionModel().selectionChanged.connect(self._selection_changed)
        self.list_view.doubleClicked.connect(self._row_double_clicked)
        self.list_view.customContextMenuRequested.connect(self._show_context_menu)
        if entity_type in {"ThreatProfile", "ToolPack"}:
            self.add_button.clicked.connect(self.new_entity)
            self.remove_button.clicked.connect(self.delete_selected)
            self.edit_button.clicked.connect(self.edit_selected)

        self.refresh()

    def refresh(self, *, preserve_id: int | None = None) -> None:
        """Reload entities and preserve the current row when the backing store changes."""

        current = preserve_id if preserve_id is not None else self.selected_entity_id()
        self.model.set_entities(self.store.list_entities(self.entity_type))
        self.sync_generate_selection_state()
        if current is not None:
            self.select_entity_id(current)
        elif self.proxy.rowCount() and not self.list_view.selectionModel().hasSelection():
            self.select_first()

    def select_first(self) -> None:
        if self.proxy.rowCount() <= 0:
            self.detail.setPlainText("No records are available.")
            return
        self.list_view.setCurrentIndex(self.proxy.index(0, 0))

    def select_entity_id(self, entity_id: int) -> None:
        source_row = self.model.row_for_id(entity_id)
        if source_row < 0:
            return
        proxy_index = self.proxy.mapFromSource(self.model.index(source_row, 0))
        if proxy_index.isValid():
            self.list_view.setCurrentIndex(proxy_index)

    def selected_entity_id(self) -> int | None:
        entity = self.selected_entity()
        return entity.get("id") if entity else None

    def selected_entity(self) -> dict[str, Any] | None:
        index = self.list_view.currentIndex()
        if not index.isValid():
            return None
        source_index = self.proxy.mapToSource(index)
        return self.model.entity_at(source_index.row())

    def selected_entities(self) -> list[dict[str, Any]]:
        return [entity for entity in (self.selected_entity(),) if entity]

    def detail_text(self) -> str:
        return self.detail.toPlainText()

    def _selection_changed(self) -> None:
        self.render_detail(self.selected_entity())

    def render_detail(self, entity: dict[str, Any] | None) -> None:
        if entity is None:
            self.detail.setPlainText("Select a record to inspect details.")
            return
        self.detail.setHtml(EntityDetailRenderer.render(entity, self.store, self.sigma_rule_service))

    def _editable_payload(self, entity: dict[str, Any] | None = None) -> dict[str, Any]:
        if entity:
            return dict(entity)
        return {
            "type": self.entity_type,
            "external_id": "",
            "name": "",
            "short_description": "",
            "status": "active",
            "confidence": 0.7,
            "priority": "",
            "tags": [],
            "payload": {},
        }

    def _open_editor(self, *, entity: dict[str, Any] | None, branch: bool = False) -> None:
        """Open the structured editor and route saves through AuthoringService."""

        dialog = EntityEditorDialog(self.entity_type, self._editable_payload(entity), self)
        if dialog.exec() != QtWidgets.QDialog.Accepted:
            return
        edited = dialog.value()
        previous = entity if not branch else None
        branch_source = entity if branch else None
        try:
            result = self.authoring_service.save_entity(
                self.entity_type,
                edited,
                branch_source=branch_source,
                previous_entity=previous,
            )
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Save Failed", str(exc))
            return
        saved_id = result.entity.get("id") if result.entity else None
        self.refresh(preserve_id=saved_id)

    def new_entity(self) -> None:
        self._open_editor(entity=None)

    def edit_selected(self) -> None:
        entity = self.selected_entity()
        if not entity:
            return
        self._open_editor(entity=entity)

    def branch_selected(self) -> None:
        entity = self.selected_entity()
        if not entity:
            return
        self._open_editor(entity=entity, branch=True)

    def delete_selected(self) -> None:
        entity = self.selected_entity()
        if not entity:
            return
        if QtWidgets.QMessageBox.question(
            self,
            "Delete Record",
            f"Delete {_entity_title(entity)}?",
        ) != QtWidgets.QMessageBox.Yes:
            return
        try:
            self.authoring_service.delete_entity(self.entity_type, entity)
        except Exception as exc:
            QtWidgets.QMessageBox.warning(self, "Delete Failed", str(exc))
            return
        self.refresh()

    def sync_generate_selection_state(self) -> None:
        """Mirror Generate selections into row roles without owning the selection."""

        if self.generate_selected_ids is None:
            self.model.set_selected_ids(set())
            return
        self.model.set_selected_ids(self.generate_selected_ids(self.entity_type))

    def toggle_generate_selected(self) -> None:
        """Delegate browse-tab double-click selection to HunterMainWindow/GeneratePage."""

        entity = self.selected_entity()
        if not entity or self.send_to_generate is None:
            return
        self.send_to_generate(self.entity_type, entity)
        self.sync_generate_selection_state()

    def _row_double_clicked(self, index: QtCore.QModelIndex) -> None:
        if not index.isValid() or self.send_to_generate is None:
            return
        self.list_view.setCurrentIndex(index)
        self.toggle_generate_selected()

    def _show_context_menu(self, position: QtCore.QPoint) -> None:
        if self.entity_type != "MitreTechnique":
            return
        index = self.list_view.indexAt(position)
        if index.isValid():
            self.list_view.setCurrentIndex(index)
        entity = self.selected_entity()
        if not entity:
            return
        menu = QtWidgets.QMenu(self)
        open_action = menu.addAction("Open ATT&CK Page")
        action = menu.exec(self.list_view.viewport().mapToGlobal(position))
        if action == open_action:
            self.open_attack_page(entity)

    def open_attack_page(self, entity: dict[str, Any] | None = None) -> None:
        entity = entity or self.selected_entity()
        if not entity:
            return
        url = _attack_url_for_entity(entity)
        if url:
            QtGui.QDesktopServices.openUrl(QtCore.QUrl(url))


