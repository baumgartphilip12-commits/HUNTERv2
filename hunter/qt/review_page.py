"""Review workflow page for the PySide6 shell.

Review presents persisted hunt packs using virtualized models so large plans do
not create one widget per step.  Export actions sanitize through controller
helpers rather than reading directly from visible table state.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from PySide6 import QtCore, QtWidgets

from hunter.controllers.export_controller import ExportController
from hunter.controllers.export_preparation import HuntPackExportPreparation
from hunter.qt.models import HuntPackListModel, ReviewPlanModel
from hunter.services.hunt_pack_summary_service import HuntPackSummaryService


class ReviewPage(QtWidgets.QWidget):
    """Virtualized Review workflow with JSON/DOCX export actions."""

    def __init__(self, *, store, project_dir: str, parent=None) -> None:
        super().__init__(parent)
        self.store = store
        self.project_dir = project_dir
        self.pack_model = HuntPackListModel()
        self.plan_model = ReviewPlanModel()
        self._active_pack_id: int | None = None

        layout = QtWidgets.QVBoxLayout(self)
        title = QtWidgets.QLabel("Review")
        title.setObjectName("SectionTitle")
        layout.addWidget(title)
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        layout.addWidget(splitter, 1)

        left = QtWidgets.QWidget()
        left_layout = QtWidgets.QVBoxLayout(left)
        left_layout.addWidget(QtWidgets.QLabel("Generated Hunt Packs"))
        self.pack_list = QtWidgets.QListView()
        self.pack_list.setModel(self.pack_model)
        left_layout.addWidget(self.pack_list, 1)
        self.refresh_button = QtWidgets.QPushButton("Refresh")
        self.export_json_button = QtWidgets.QPushButton("Export JSON")
        self.export_docx_button = QtWidgets.QPushButton("Export DOCX")
        self.delete_button = QtWidgets.QPushButton("Delete")
        left_layout.addWidget(self.refresh_button)
        left_layout.addWidget(self.export_json_button)
        left_layout.addWidget(self.export_docx_button)
        left_layout.addWidget(self.delete_button)

        right = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right)
        self.summary = QtWidgets.QTextBrowser()
        self.summary.setMaximumHeight(180)
        right_layout.addWidget(self.summary)
        self.plan_view = QtWidgets.QTableView()
        self.plan_view.setModel(self.plan_model)
        self.plan_view.setAlternatingRowColors(True)
        self.plan_view.verticalHeader().setDefaultSectionSize(28)
        self.plan_view.horizontalHeader().setStretchLastSection(True)
        self.plan_view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        right_layout.addWidget(self.plan_view, 1)
        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 4)

        self.pack_list.selectionModel().selectionChanged.connect(self._pack_selected)
        self.refresh_button.clicked.connect(self.refresh)
        self.export_json_button.clicked.connect(self.export_json)
        self.export_docx_button.clicked.connect(self.export_docx)
        self.delete_button.clicked.connect(self.delete_selected)
        self.plan_model.payloadChanged.connect(self.persist_plan_changes)
        self.refresh()

    def refresh(self, *, select_id: int | None = None) -> None:
        """Reload hunt packs while keeping the active pack selected when possible."""

        current = select_id if select_id is not None else self._active_pack_id
        packs = self.store.list_hunt_packs()
        self.pack_model.set_hunt_packs(packs)
        if current:
            row = self.pack_model.row_for_id(current)
            if row >= 0:
                self.pack_list.setCurrentIndex(self.pack_model.index(row, 0))
                return
        if packs:
            self.pack_list.setCurrentIndex(self.pack_model.index(0, 0))
        else:
            self.plan_model.set_hunt_pack(None)
            self.summary.setPlainText("No generated hunt packs yet.")

    def _pack_selected(self) -> None:
        index = self.pack_list.currentIndex()
        if not index.isValid():
            return
        pack = self.pack_model.hunt_pack_at(index.row())
        self.set_hunt_pack(pack)

    def set_hunt_pack(self, pack: dict[str, Any] | None) -> None:
        """Load a hunt pack into the summary pane and review table model."""

        self._active_pack_id = pack.get("id") if pack else None
        self.plan_model.set_hunt_pack(pack)
        if not pack:
            self.summary.setPlainText("No generated hunt pack selected.")
            return
        summary = pack.get("summary", {})
        self.summary.setPlainText(
            "\n".join(
                [
                    pack.get("name", "Generated Hunt Pack"),
                    f"Enabled: {summary.get('enabled_steps', 0)} of {summary.get('candidate_steps', 0)}",
                    f"Covered techniques: {summary.get('covered_techniques', 0)}",
                    f"Gaps: {summary.get('missing_techniques', 0)}",
                ]
            )
        )
        self.plan_view.resizeColumnsToContents()

    def persist_plan_changes(self) -> None:
        """Persist enabled/disabled review edits back into the stored hunt pack."""

        if not self._active_pack_id:
            return
        pack = self.plan_model.hunt_pack
        steps = pack.get("payload", {}).get("steps", [])
        summary = HuntPackSummaryService.summarize(pack.get("summary", {}), steps)
        pack["summary"] = summary
        pack["payload"]["summary"] = summary
        self.store.update_hunt_pack(
            self._active_pack_id,
            summary=summary,
            payload=pack.get("payload", {}),
        )
        self.set_hunt_pack(pack)

    def export_json(self) -> None:
        """Export the active hunt pack as sanitized enabled-step JSON."""

        if not self._active_pack_id:
            return
        pack = self.store.get_hunt_pack(self._active_pack_id)
        if not pack:
            return
        initial = HuntPackExportPreparation.initial_hunt_pack_name(pack).lower().replace(" ", "_")
        path, _filter = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Export Hunt Pack JSON",
            f"{initial}.json",
            "JSON files (*.json)",
        )
        if not path:
            return
        sanitized = HuntPackExportPreparation.sanitize_hunt_pack(pack)
        Path(path).write_text(json.dumps(sanitized, indent=2), encoding="utf-8")

    def export_docx(self) -> None:
        """Export the active hunt pack through the Node-backed DOCX runtime."""

        if not self._active_pack_id:
            return
        pack = self.store.get_hunt_pack(self._active_pack_id)
        if not pack:
            return
        ExportController.export_hunt_pack_docx(
            parent_window=self,
            hunt_pack=pack,
            script_dir=self.project_dir,
            store=self.store,
        )

    def delete_selected(self) -> None:
        if not self._active_pack_id:
            return
        if QtWidgets.QMessageBox.question(self, "Delete Hunt Pack", "Delete this hunt pack?") != QtWidgets.QMessageBox.Yes:
            return
        self.store.delete_hunt_pack(self._active_pack_id)
        self._active_pack_id = None
        self.refresh()


