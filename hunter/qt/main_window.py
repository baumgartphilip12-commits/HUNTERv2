"""PySide6 main window for the HUNTER desktop shell.

The workflow pages live in focused modules; this file is intentionally the
composition root plus compatibility exports used by tests and older callers.
"""

from __future__ import annotations

from typing import Any

from PySide6 import QtCore, QtWidgets

from hunter.qt.entity_browser import EntityBrowserPage, _attack_url_for_entity, _entity_title
from hunter.qt.entity_dialogs import EntityEditorDialog, SigmaScopeEditorDialog
from hunter.qt.generate_page import GeneratePage
from hunter.qt.models import EntitySearchProxy, GenerateSelectedItemDelegate
from hunter.qt.review_page import ReviewPage
from hunter.qt.settings_sync import SettingsSyncDialog, SigmaSourceDialog
from hunter.qt.theme import QT_STYLE


WORKFLOW_STEPS = ("MITRE", "Threats", "Tools", "Generate", "Review")


class HunterMainWindow(QtWidgets.QMainWindow):
    """Compose the five-step Qt workflow and cross-page selection bridge."""

    def __init__(
        self,
        *,
        store,
        sync_service,
        hunt_generator,
        sigma_rule_service,
        authoring_service,
        project_dir: str,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.store = store
        self.sync_service = sync_service
        self.hunt_generator = hunt_generator
        self.sigma_rule_service = sigma_rule_service
        self.authoring_service = authoring_service
        self.project_dir = project_dir
        self.setWindowTitle("HUNTER v2 - Layered Threat-Hunting Knowledge Graph")
        self.resize(1480, 920)
        self.setStyleSheet(QT_STYLE)
        self.entity_pages: dict[str, EntityBrowserPage] = {}

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        root = QtWidgets.QVBoxLayout(central)

        header = QtWidgets.QFrame()
        header.setObjectName("Header")
        header_layout = QtWidgets.QHBoxLayout(header)
        title = QtWidgets.QLabel("HUNTER v2")
        title.setObjectName("Title")
        header_layout.addWidget(title)
        header_layout.addStretch(1)
        self.stats_label = QtWidgets.QLabel()
        header_layout.addWidget(self.stats_label)
        self.settings_button = QtWidgets.QPushButton("Settings")
        header_layout.addWidget(self.settings_button)
        root.addWidget(header)

        self.step_buttons: list[QtWidgets.QPushButton] = []
        step_row = QtWidgets.QHBoxLayout()
        for index, name in enumerate(WORKFLOW_STEPS):
            button = QtWidgets.QPushButton(f"{index + 1:02d} {name}")
            button.setCheckable(True)
            button.clicked.connect(lambda _checked=False, idx=index: self.select_workflow_step(idx))
            self.step_buttons.append(button)
            step_row.addWidget(button)
        root.addLayout(step_row)

        self.stack = QtWidgets.QStackedWidget()
        root.addWidget(self.stack, 1)

        self.generate_page = GeneratePage(
            store=store,
            hunt_generator=hunt_generator,
            sigma_rule_service=sigma_rule_service,
        )
        self.entity_pages["MitreTechnique"] = EntityBrowserPage(
            store=store,
            authoring_service=authoring_service,
            entity_type="MitreTechnique",
            title="MITRE",
            sigma_rule_service=sigma_rule_service,
            send_to_generate=self.send_entity_to_generate,
            generate_selected_ids=self.generate_page.selected_ids_for_type,
        )
        self.entity_pages["ThreatProfile"] = EntityBrowserPage(
            store=store,
            authoring_service=authoring_service,
            entity_type="ThreatProfile",
            title="Threats",
            sigma_rule_service=sigma_rule_service,
            send_to_generate=self.send_entity_to_generate,
            generate_selected_ids=self.generate_page.selected_ids_for_type,
        )
        self.entity_pages["ToolPack"] = EntityBrowserPage(
            store=store,
            authoring_service=authoring_service,
            entity_type="ToolPack",
            title="Tools",
            sigma_rule_service=sigma_rule_service,
            send_to_generate=self.send_entity_to_generate,
            generate_selected_ids=self.generate_page.selected_ids_for_type,
        )
        self.review_page = ReviewPage(store=store, project_dir=project_dir)
        for page in (
            self.entity_pages["MitreTechnique"],
            self.entity_pages["ThreatProfile"],
            self.entity_pages["ToolPack"],
            self.generate_page,
            self.review_page,
        ):
            self.stack.addWidget(page)

        self.settings_button.clicked.connect(self.open_settings)
        self.generate_page.huntPackGenerated.connect(self._hunt_pack_generated)
        self.select_workflow_step(0)
        self.refresh_counts()

    def workflow_step_names(self) -> list[str]:
        return list(WORKFLOW_STEPS)

    def current_workflow_step(self) -> str:
        return WORKFLOW_STEPS[self.stack.currentIndex()]

    def select_workflow_step(self, index: int) -> None:
        if not 0 <= index < len(WORKFLOW_STEPS):
            return
        self.stack.setCurrentIndex(index)
        for button_index, button in enumerate(self.step_buttons):
            button.setChecked(button_index == index)
        if WORKFLOW_STEPS[index] == "Generate":
            self.generate_page.refresh()
        elif WORKFLOW_STEPS[index] == "Review":
            self.review_page.refresh()
        else:
            page = self.stack.widget(index)
            if isinstance(page, EntityBrowserPage):
                page.refresh()
        self.refresh_counts()

    def refresh_counts(self) -> None:
        mitre = len(self.store.list_entities("MitreTechnique"))
        threats = len(self.store.list_entities("ThreatProfile"))
        tools = len(self.store.list_entities("ToolPack"))
        sigma = len(self.store.list_entities("SigmaRule"))
        packs = len(self.store.list_hunt_packs())
        self.stats_label.setText(
            f"MITRE {mitre} - Threats {threats} - Tools {tools} - Sigma {sigma} - Hunt Packs {packs}"
        )

    def send_entity_to_generate(self, entity_type: str, entity: dict[str, Any]) -> bool:
        """Toggle a browse-row entity into Generate with immediate visual feedback."""

        entity_id = int(entity["id"])
        if not self.generate_page.has_entity(entity_type, entity_id):
            self.generate_page.refresh()
        added = self.generate_page.toggle_entity_selection(entity_type, entity_id, notify=False)
        page = self.entity_pages.get(entity_type)
        if page is not None:
            page.sync_generate_selection_state()
            page.list_view.viewport().update()
            QtWidgets.QApplication.processEvents(QtCore.QEventLoop.ExcludeUserInputEvents)
        for other_type, other_page in self.entity_pages.items():
            if other_type != entity_type:
                other_page.sync_generate_selection_state()
        self.generate_page.refresh_sigma_families()
        self.generate_page._last_draft = None
        action = "Added" if added else "Removed"
        direction = "to" if added else "from"
        self.statusBar().showMessage(
            f"{action} {_entity_title(entity)} {direction} Generate.",
            5000,
        )
        return added

    def open_settings(self) -> SettingsSyncDialog:
        dialog = SettingsSyncDialog(
            store=self.store,
            sync_service=self.sync_service,
            project_dir=self.project_dir,
            parent=self,
        )
        dialog.show()
        self._settings_dialog = dialog
        return dialog

    def _hunt_pack_generated(self, hunt_pack_id: int) -> None:
        self.review_page.refresh(select_id=hunt_pack_id)
        self.select_workflow_step(WORKFLOW_STEPS.index("Review"))


def open_window(**kwargs) -> HunterMainWindow:
    """Small factory used by tests and the app entrypoint."""

    return HunterMainWindow(**kwargs)
