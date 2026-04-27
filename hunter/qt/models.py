"""Qt item models used by the PySide6 shell.

These models keep presentation roles close to the data they decorate.  They do
not own persistence; callers reload entities from KnowledgeStore and use roles
to keep selection, search, and review tables consistent across pages.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from PySide6 import QtCore, QtGui, QtWidgets

from hunter.search_documents import entity_search_document
from hunter.search_query import matches_search_query


ID_ROLE = QtCore.Qt.UserRole + 1
ENTITY_ROLE = QtCore.Qt.UserRole + 2
TYPE_ROLE = QtCore.Qt.UserRole + 3
GENERATE_SELECTED_ROLE = QtCore.Qt.UserRole + 4
GENERATE_SELECTED_BACKGROUND = QtGui.QColor("#123d2c")


class GenerateSelectedItemDelegate(QtWidgets.QStyledItemDelegate):
    """Paint the shared green/blue Generate-selected row treatment."""

    def paint(
        self,
        painter: QtGui.QPainter,
        option: QtWidgets.QStyleOptionViewItem,
        index: QtCore.QModelIndex,
    ) -> None:
        if not index.data(GENERATE_SELECTED_ROLE):
            super().paint(painter, option, index)
            return
        selected_option = QtWidgets.QStyleOptionViewItem(option)
        selected_option.state &= ~QtWidgets.QStyle.State_Selected
        super().paint(painter, selected_option, index)
        painter.save()
        painter.setPen(QtCore.Qt.NoPen)
        painter.setBrush(QtGui.QColor("#14b8d4"))
        marker = QtCore.QRect(option.rect.left(), option.rect.top(), 4, option.rect.height())
        painter.drawRect(marker)
        painter.restore()


class EntityListModel(QtCore.QAbstractListModel):
    """List model for knowledge entities and mirrored Generate selection roles."""

    def __init__(self, entities: list[dict[str, Any]] | None = None, parent=None) -> None:
        super().__init__(parent)
        self._entities: list[dict[str, Any]] = list(entities or [])
        self._selected_ids: set[int] = set()

    def rowCount(self, parent: QtCore.QModelIndex = QtCore.QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._entities)

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self._entities):
            return None
        entity = self._entities[index.row()]
        if role == QtCore.Qt.DisplayRole:
            name = entity.get("name") or entity.get("external_id") or "Untitled"
            external_id = entity.get("external_id", "")
            status = entity.get("status", "")
            return " - ".join(str(part) for part in (name, external_id, status) if part)
        if role == QtCore.Qt.BackgroundRole and entity.get("id") in self._selected_ids:
            return QtGui.QBrush(GENERATE_SELECTED_BACKGROUND)
        if role == GENERATE_SELECTED_ROLE:
            return entity.get("id") in self._selected_ids
        if role == ID_ROLE:
            return entity.get("id")
        if role == ENTITY_ROLE:
            return entity
        if role == TYPE_ROLE:
            return entity.get("type")
        return None

    def set_entities(self, entities: list[dict[str, Any]]) -> None:
        self.beginResetModel()
        self._entities = list(entities or [])
        self.endResetModel()

    def set_selected_ids(self, entity_ids: set[int] | list[int] | tuple[int, ...]) -> None:
        """Expose Generate-selected IDs through roles without changing row text."""

        self._selected_ids = {int(entity_id) for entity_id in entity_ids}
        if self._entities:
            top_left = self.index(0, 0)
            bottom_right = self.index(len(self._entities) - 1, 0)
            self.dataChanged.emit(
                top_left,
                bottom_right,
                [QtCore.Qt.DisplayRole, QtCore.Qt.BackgroundRole, GENERATE_SELECTED_ROLE],
            )

    def entity_at(self, row: int) -> dict[str, Any] | None:
        if 0 <= row < len(self._entities):
            return self._entities[row]
        return None

    def entities(self) -> list[dict[str, Any]]:
        return list(self._entities)

    def row_for_id(self, entity_id: int | None) -> int:
        for row, entity in enumerate(self._entities):
            if entity.get("id") == entity_id:
                return row
        return -1


class EntitySearchProxy(QtCore.QSortFilterProxyModel):
    """Mini-query-aware search proxy shared by browse rails and Generate panels."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._query = ""
        self.setFilterCaseSensitivity(QtCore.Qt.CaseInsensitive)

    def set_search_text(self, text: str) -> None:
        self.beginFilterChange()
        self._query = text.strip()
        self.endFilterChange()

    def filterAcceptsRow(self, source_row: int, source_parent: QtCore.QModelIndex) -> bool:
        if not self._query:
            return True
        index = self.sourceModel().index(source_row, 0, source_parent)
        entity = self.sourceModel().data(index, ENTITY_ROLE) or {}
        return matches_search_query(self._query, entity_search_document(entity))


class HuntPackListModel(QtCore.QAbstractListModel):
    """List model for generated hunt packs."""

    def __init__(self, hunt_packs: list[dict[str, Any]] | None = None, parent=None) -> None:
        super().__init__(parent)
        self._hunt_packs = list(hunt_packs or [])

    def rowCount(self, parent: QtCore.QModelIndex = QtCore.QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._hunt_packs)

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self._hunt_packs):
            return None
        pack = self._hunt_packs[index.row()]
        if role == QtCore.Qt.DisplayRole:
            summary = pack.get("summary", {})
            enabled = summary.get("enabled_steps", 0)
            total = summary.get("candidate_steps", 0)
            return f"{pack.get('name', 'Generated Hunt Pack')} - {enabled}/{total} enabled"
        if role == ID_ROLE:
            return pack.get("id")
        if role == ENTITY_ROLE:
            return pack
        return None

    def set_hunt_packs(self, hunt_packs: list[dict[str, Any]]) -> None:
        self.beginResetModel()
        self._hunt_packs = list(hunt_packs or [])
        self.endResetModel()

    def hunt_pack_at(self, row: int) -> dict[str, Any] | None:
        if 0 <= row < len(self._hunt_packs):
            return self._hunt_packs[row]
        return None

    def row_for_id(self, hunt_pack_id: int | None) -> int:
        for row, pack in enumerate(self._hunt_packs):
            if pack.get("id") == hunt_pack_id:
                return row
        return -1


@dataclass(frozen=True)
class ReviewRow:
    kind: str
    technique_id: str
    step_index: int | None = None


class ReviewPlanModel(QtCore.QAbstractTableModel):
    """Virtualized Review model grouped by ATT&CK technique."""

    payloadChanged = QtCore.Signal()

    HEADERS = ("Enabled", "Technique / Step", "Tool", "Kind", "Origin")

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.hunt_pack: dict[str, Any] = {}
        self._rows: list[ReviewRow] = []
        self._group_order: list[str] = []
        self._groups: dict[str, list[int]] = {}

    @property
    def step_count(self) -> int:
        return len(self._steps())

    @property
    def group_count(self) -> int:
        return len(self._group_order)

    def _steps(self) -> list[dict[str, Any]]:
        payload = self.hunt_pack.get("payload", {}) if self.hunt_pack else {}
        steps = payload.get("steps", [])
        return steps if isinstance(steps, list) else []

    def set_hunt_pack(self, hunt_pack: dict[str, Any] | None) -> None:
        self.beginResetModel()
        self.hunt_pack = dict(hunt_pack or {})
        payload = dict(self.hunt_pack.get("payload", {}) or {})
        payload["steps"] = [dict(step) for step in payload.get("steps", []) if isinstance(step, dict)]
        self.hunt_pack["payload"] = payload
        self._rebuild_rows()
        self.endResetModel()

    def _rebuild_rows(self) -> None:
        self._rows = []
        self._groups = {}
        for index, step in enumerate(self._steps()):
            technique_id = str((step.get("techniques") or ["Unmapped"])[0] or "Unmapped")
            self._groups.setdefault(technique_id, []).append(index)
        self._group_order = sorted(self._groups)
        for technique_id in self._group_order:
            self._rows.append(ReviewRow("group", technique_id))
            for step_index in self._groups[technique_id]:
                self._rows.append(ReviewRow("step", technique_id, step_index))

    def rowCount(self, parent: QtCore.QModelIndex = QtCore.QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QtCore.QModelIndex = QtCore.QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section: int, orientation: QtCore.Qt.Orientation, role: int = QtCore.Qt.DisplayRole):
        if role == QtCore.Qt.DisplayRole and orientation == QtCore.Qt.Horizontal:
            if 0 <= section < len(self.HEADERS):
                return self.HEADERS[section]
        return None

    def flags(self, index: QtCore.QModelIndex) -> QtCore.Qt.ItemFlag:
        if not index.isValid():
            return QtCore.Qt.NoItemFlags
        flags = QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable
        if index.column() == 0:
            flags |= QtCore.Qt.ItemIsUserCheckable
        return flags

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self._rows):
            return None
        row = self._rows[index.row()]
        if role == QtCore.Qt.CheckStateRole and index.column() == 0:
            return self._check_state(row)
        if role not in {QtCore.Qt.DisplayRole, QtCore.Qt.ToolTipRole}:
            return None
        if row.kind == "group":
            return self._group_display(row, index.column())
        return self._step_display(row, index.column())

    def _check_state(self, row: ReviewRow):
        steps = self._steps()
        if row.kind == "step" and row.step_index is not None:
            return QtCore.Qt.Checked if steps[row.step_index].get("enabled", True) else QtCore.Qt.Unchecked
        group_steps = [steps[index] for index in self._groups.get(row.technique_id, [])]
        enabled_count = len([step for step in group_steps if step.get("enabled", True)])
        if enabled_count == len(group_steps):
            return QtCore.Qt.Checked
        if enabled_count == 0:
            return QtCore.Qt.Unchecked
        return QtCore.Qt.PartiallyChecked

    def _group_display(self, row: ReviewRow, column: int) -> str:
        group_steps = self._groups.get(row.technique_id, [])
        if column == 1:
            enabled = len([step for step in self._steps_for_group(row.technique_id) if step.get("enabled", True)])
            return f"{row.technique_id} - {enabled}/{len(group_steps)} enabled"
        if column == 2:
            tools = sorted({step.get("tool_pack", "Unknown") for step in self._steps_for_group(row.technique_id)})
            return ", ".join(tools)
        return ""

    def _step_display(self, row: ReviewRow, column: int) -> str:
        if row.step_index is None:
            return ""
        step = self._steps()[row.step_index]
        if column == 1:
            return step.get("title", "Untitled step")
        if column == 2:
            surface = step.get("execution_surface") or step.get("tool_pack", "")
            return " - ".join(part for part in (step.get("tool_pack", ""), surface) if part)
        if column == 3:
            return str(step.get("method_kind", "behavior_hunt")).replace("_", " ")
        if column == 4:
            return str(step.get("content_origin", "authored_tool_hunt")).replace("_", " ")
        return ""

    def setData(self, index: QtCore.QModelIndex, value, role: int = QtCore.Qt.EditRole) -> bool:
        if role != QtCore.Qt.CheckStateRole or index.column() != 0 or not index.isValid():
            return False
        row = self._rows[index.row()]
        enabled = self._is_checked_state(value)
        if row.kind == "group":
            self.set_group_enabled(row.technique_id, enabled)
            return True
        if row.kind == "step" and row.step_index is not None:
            self._steps()[row.step_index]["enabled"] = enabled
            self.dataChanged.emit(index, index.siblingAtColumn(self.columnCount() - 1))
            self.payloadChanged.emit()
            return True
        return False

    @staticmethod
    def _is_checked_state(value) -> bool:
        """Normalize Qt delegate check-state values across enum and raw-int paths."""
        normalized = getattr(value, "value", value)
        try:
            return int(normalized) == int(QtCore.Qt.Checked.value)
        except (TypeError, ValueError, AttributeError):
            return value == QtCore.Qt.Checked

    def _steps_for_group(self, technique_id: str) -> list[dict[str, Any]]:
        steps = self._steps()
        return [steps[index] for index in self._groups.get(technique_id, [])]

    def set_group_enabled(self, technique_id: str, enabled: bool) -> None:
        steps = self._steps()
        changed_rows: list[int] = []
        for row_index, row in enumerate(self._rows):
            if row.technique_id != technique_id:
                continue
            if row.kind == "step" and row.step_index is not None:
                steps[row.step_index]["enabled"] = enabled
            changed_rows.append(row_index)
        if changed_rows:
            first = self.index(min(changed_rows), 0)
            last = self.index(max(changed_rows), self.columnCount() - 1)
            self.dataChanged.emit(first, last)
            self.payloadChanged.emit()

    def index_for_step_id(self, step_id: str) -> QtCore.QModelIndex:
        for row_index, row in enumerate(self._rows):
            if row.kind != "step" or row.step_index is None:
                continue
            if self._steps()[row.step_index].get("step_id") == step_id:
                return self.index(row_index, 0)
        return QtCore.QModelIndex()
