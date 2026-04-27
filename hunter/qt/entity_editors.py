"""Structured Qt editors for ThreatProfile and ToolPack payloads.

The editors expose form/table controls for common fields while preserving the
original payload dictionaries.  That preservation is important because layered
module JSON may contain fields the current UI does not understand yet.
"""

from __future__ import annotations

import copy
from typing import Any

from PySide6 import QtCore, QtWidgets

from hunter.qt.formatting import json_preview


PLATFORM_OPTIONS = (
    "Splunk",
    "Elastic",
    "Elastic Endgame",
    "General Host Hunt",
    "Microsoft 365",
    "Microsoft Defender",
    "Microsoft Sentinel",
    "PowerShell",
    "Arkime",
    "AWS",
    "AWS Athena",
    "Azure",
    "Falco",
    "General Network Hunt",
    "Wireshark",
    "Velociraptor",
    "Shodan",
    "Other",
)
OUTPUT_OPTIONS = (
    "query",
    "workflow",
    "checklist",
    "spl",
    "esql",
    "kql",
    "powershell",
    "cloudwatch_insights",
    "arkime_query",
    "sql",
    "eql",
    "wireshark_filter",
    "yaml",
    "vql",
    "shodan_query",
)
SIGMA_OUTPUT_FORMAT_OPTIONS = (
    "lucene",
    "kql",
    "eql",
    "spl",
    "sigma",
    "yaml",
    "query",
    "Other",
)
METHOD_STRENGTH_OPTIONS = ("primary_hunt", "supporting_pivot")
METHOD_KIND_OPTIONS = (
    "behavior_hunt",
    "ioc_pivot",
    "metadata_pivot",
    "corroboration",
    "visibility_gap",
    "stream_validation",
    "workflow",
    "scope_reduction",
    "correlation",
)
NOISE_OPTIONS = ("low", "medium", "high")
PRIVILEGE_OPTIONS = ("none", "user", "elevated", "admin", "unknown")
IOC_TYPES = ("ip", "domain", "url", "sha256", "md5", "hostname", "email", "Custom")
IOC_DEFAULTS = ("domain", "ip", "url", "hostname", "email", "sha256", "md5")
METHOD_STRING_DEFAULTS = {
    "title": "Untitled method",
    "template": "",
    "output_format": "query",
    "execution_surface": "",
    "surface_details": "",
    "expectation": "",
    "strength_reason": "",
    "behavior_focus": "",
}
METHOD_LIST_FIELDS = (
    "techniques",
    "supported_ioc_types",
    "required_placeholders",
    "service_examples",
    "prerequisites",
    "data_sources",
)
TIME_COST_TEXT_DEFAULTS = {"low": 1, "medium": 2, "high": 3}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _text_lines(text: str) -> list[str]:
    return [line.strip() for line in str(text or "").splitlines() if line.strip()]


def _set_combo(combo: QtWidgets.QComboBox, value: Any, fallback: str = "") -> None:
    text = str(value or fallback)
    if combo.findText(text) < 0 and text:
        combo.addItem(text)
    if text:
        combo.setCurrentText(text)


def _coerce_time_cost(value: Any) -> int:
    """Normalize historical numeric/text time-cost values into editor integers."""

    if isinstance(value, bool):
        return 1
    if isinstance(value, (int, float)):
        return max(1, int(value))
    text = str(value or "").strip().lower()
    if text in TIME_COST_TEXT_DEFAULTS:
        return TIME_COST_TEXT_DEFAULTS[text]
    try:
        return max(1, int(float(text)))
    except ValueError:
        return 1


def _normalize_method(method: Any) -> dict[str, Any]:
    """Return a saveable hunt-method dict without discarding unknown keys.

    Local modules can contain partial or historical hunt-method records.  The
    editor normalizes required fields before display so malformed methods remain
    editable and can be saved back in a healthier shape.
    """

    normalized = dict(method) if isinstance(method, dict) else {}
    for key, fallback in METHOD_STRING_DEFAULTS.items():
        value = normalized.get(key, fallback)
        text = str(value or "").strip()
        normalized[key] = text or fallback
    for key in METHOD_LIST_FIELDS:
        normalized[key] = [str(value) for value in _as_list(normalized.get(key))]
    if normalized.get("method_strength") not in METHOD_STRENGTH_OPTIONS:
        normalized["method_strength"] = "primary_hunt"
    if normalized.get("method_kind") not in METHOD_KIND_OPTIONS:
        normalized["method_kind"] = "behavior_hunt"
    if normalized.get("noise_level") not in NOISE_OPTIONS:
        normalized["noise_level"] = "medium"
    if normalized.get("privilege_required") not in PRIVILEGE_OPTIONS:
        normalized["privilege_required"] = "unknown"
    normalized["time_cost"] = _coerce_time_cost(normalized.get("time_cost", 1))
    return normalized


def _configure_editor_table(table: QtWidgets.QTableWidget) -> None:
    """Apply readable defaults shared by structured editor tables."""

    table.verticalHeader().setVisible(False)
    table.verticalHeader().setDefaultSectionSize(36)
    table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    table.setAlternatingRowColors(True)
    table.setShowGrid(True)
    table.setWordWrap(True)
    table.horizontalHeader().setMinimumSectionSize(140)


def _scroll_area(widget: QtWidgets.QWidget) -> QtWidgets.QScrollArea:
    """Wrap dense tab bodies so small dialogs scroll instead of crushing fields."""

    area = QtWidgets.QScrollArea()
    area.setWidgetResizable(True)
    area.setFrameShape(QtWidgets.QFrame.NoFrame)
    area.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
    area.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
    area.setWidget(widget)
    return area


class StringListEditor(QtWidgets.QWidget):
    """Table-backed editor for repeated strings such as aliases and references."""

    def __init__(self, title: str = "", values: list[str] | None = None, parent=None) -> None:
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        if title:
            layout.addWidget(QtWidgets.QLabel(title))
        self.table = QtWidgets.QTableWidget(0, 1)
        self.table.setHorizontalHeaderLabels(["Value"])
        self.table.horizontalHeader().setStretchLastSection(True)
        _configure_editor_table(self.table)
        self.table.setMinimumHeight(220)
        layout.addWidget(self.table, 1)
        buttons = QtWidgets.QHBoxLayout()
        self.add_button = QtWidgets.QPushButton("Add")
        self.remove_button = QtWidgets.QPushButton("Remove")
        buttons.addWidget(self.add_button)
        buttons.addWidget(self.remove_button)
        layout.addLayout(buttons)
        self.add_button.clicked.connect(lambda: self.add_value(""))
        self.remove_button.clicked.connect(self.remove_selected)
        self.set_values(values or [])

    def set_values(self, values: list[str]) -> None:
        self.table.setRowCount(0)
        for value in values:
            self.add_value(str(value))

    def add_value(self, value: str) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(str(value)))

    def remove_selected(self) -> None:
        rows = sorted({index.row() for index in self.table.selectedIndexes()}, reverse=True)
        if not rows and self.table.currentRow() >= 0:
            rows = [self.table.currentRow()]
        for row in rows:
            self.table.removeRow(row)

    def values(self) -> list[str]:
        result: list[str] = []
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            text = item.text().strip() if item else ""
            if text:
                result.append(text)
        return result


class KeyValueTableEditor(QtWidgets.QWidget):
    """Editor for payload dictionaries that must round-trip string keys/values."""

    """Table editor for simple string key/value mappings."""

    def __init__(self, title: str = "", values: dict[str, Any] | None = None, parent=None) -> None:
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        if title:
            layout.addWidget(QtWidgets.QLabel(title))
        self.table = QtWidgets.QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Key", "Value"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        _configure_editor_table(self.table)
        self.table.setMinimumHeight(220)
        layout.addWidget(self.table, 1)
        buttons = QtWidgets.QHBoxLayout()
        self.add_button = QtWidgets.QPushButton("Add")
        self.remove_button = QtWidgets.QPushButton("Remove")
        buttons.addWidget(self.add_button)
        buttons.addWidget(self.remove_button)
        layout.addLayout(buttons)
        self.add_button.clicked.connect(lambda: self.add_pair("", ""))
        self.remove_button.clicked.connect(self.remove_selected)
        for key, value in (values or {}).items():
            self.add_pair(str(key), str(value))

    def add_pair(self, key: str, value: str) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(str(key)))
        self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(str(value)))

    def remove_selected(self) -> None:
        rows = sorted({index.row() for index in self.table.selectedIndexes()}, reverse=True)
        if not rows and self.table.currentRow() >= 0:
            rows = [self.table.currentRow()]
        for row in rows:
            self.table.removeRow(row)

    def values(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for row in range(self.table.rowCount()):
            key_item = self.table.item(row, 0)
            value_item = self.table.item(row, 1)
            key = key_item.text().strip() if key_item else ""
            value = value_item.text().strip() if value_item else ""
            if key:
                result[key] = value
        return result


class IocTableEditor(QtWidgets.QWidget):
    """Threat indicator table with readable type/custom/value columns."""

    """Table editor for threat indicator type/value pairs."""

    def __init__(self, indicators: list[dict[str, str]] | None = None, parent=None) -> None:
        super().__init__(parent)
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(QtWidgets.QLabel("Threat Indicators"))
        self.table = QtWidgets.QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Type", "Custom Type", "Value"])
        _configure_editor_table(self.table)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.Interactive)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.Interactive)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(1, 180)
        self.table.setMinimumHeight(220)
        layout.addWidget(self.table, 1)
        buttons = QtWidgets.QHBoxLayout()
        self.add_button = QtWidgets.QPushButton("Add IOC")
        self.remove_button = QtWidgets.QPushButton("Remove")
        buttons.addWidget(self.add_button)
        buttons.addWidget(self.remove_button)
        layout.addLayout(buttons)
        self.add_button.clicked.connect(lambda: self.add_indicator("ip", "", ""))
        self.remove_button.clicked.connect(self.remove_selected)
        for indicator in indicators or []:
            kind = str(indicator.get("type", "ip"))
            self.add_indicator(kind if kind in IOC_DEFAULTS else "Custom", "" if kind in IOC_DEFAULTS else kind, str(indicator.get("value", "")))

    def add_indicator(self, kind: str, custom_type: str, value: str) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        combo = QtWidgets.QComboBox()
        combo.addItems(IOC_TYPES)
        combo.setMinimumWidth(140)
        combo.setMinimumHeight(30)
        _set_combo(combo, kind, "ip")
        self.table.setCellWidget(row, 0, combo)
        self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(str(custom_type)))
        self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(str(value)))

    def remove_selected(self) -> None:
        rows = sorted({index.row() for index in self.table.selectedIndexes()}, reverse=True)
        if not rows and self.table.currentRow() >= 0:
            rows = [self.table.currentRow()]
        for row in rows:
            self.table.removeRow(row)

    def values(self) -> list[dict[str, str]]:
        result: list[dict[str, str]] = []
        for row in range(self.table.rowCount()):
            combo = self.table.cellWidget(row, 0)
            selected = combo.currentText().strip() if isinstance(combo, QtWidgets.QComboBox) else "ip"
            custom_item = self.table.item(row, 1)
            value_item = self.table.item(row, 2)
            custom = custom_item.text().strip() if custom_item else ""
            value = value_item.text().strip() if value_item else ""
            kind = custom if selected == "Custom" else selected
            if kind and value:
                result.append({"type": kind, "value": value})
        return result


class MultiCheckEditor(QtWidgets.QWidget):
    """Checkbox group with stable value ordering."""

    def __init__(self, title: str, options: list[str], values: list[str] | None = None, parent=None) -> None:
        super().__init__(parent)
        self._checks: dict[str, QtWidgets.QCheckBox] = {}
        layout = QtWidgets.QVBoxLayout(self)
        if title:
            layout.addWidget(QtWidgets.QLabel(title))
        grid = QtWidgets.QGridLayout()
        layout.addLayout(grid)
        selected = set(values or [])
        for index, option in enumerate(options):
            check = QtWidgets.QCheckBox(option)
            check.setChecked(option in selected)
            self._checks[option] = check
            grid.addWidget(check, index // 4, index % 4)

    def set_values(self, values: list[str]) -> None:
        selected = set(values)
        for option, check in self._checks.items():
            check.setChecked(option in selected)

    def values(self) -> list[str]:
        return [option for option, check in self._checks.items() if check.isChecked()]


class TechniqueSelector(QtWidgets.QWidget):
    """Two-list ATT&CK selector that edits selected technique IDs only."""

    """Searchable available/selected ATT&CK selector."""

    def __init__(self, techniques: list[dict[str, Any]], values: list[str] | None = None, parent=None) -> None:
        super().__init__(parent)
        self._catalog = sorted(techniques, key=lambda item: (item.get("external_id", ""), item.get("name", "")))
        self._by_id = {str(item.get("external_id")): item for item in self._catalog}
        layout = QtWidgets.QVBoxLayout(self)
        self.search = QtWidgets.QLineEdit()
        self.search.setPlaceholderText('Search ATT&CK, e.g. T1041 or "C2 Channel"')
        layout.addWidget(self.search)
        body = QtWidgets.QHBoxLayout()
        layout.addLayout(body, 1)
        self.available = QtWidgets.QListWidget()
        self.selected = QtWidgets.QListWidget()
        for list_widget in (self.available, self.selected):
            list_widget.setMinimumWidth(240)
            list_widget.setMinimumHeight(220)
            list_widget.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
            list_widget.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
            list_widget.setTextElideMode(QtCore.Qt.ElideNone)
        buttons = QtWidgets.QVBoxLayout()
        self.add_button = QtWidgets.QPushButton("Add ->")
        self.remove_button = QtWidgets.QPushButton("<- Remove")
        buttons.addStretch(1)
        buttons.addWidget(self.add_button)
        buttons.addWidget(self.remove_button)
        buttons.addStretch(1)
        body.addWidget(self.available, 1)
        body.addLayout(buttons)
        body.addWidget(self.selected, 1)
        self.search.textChanged.connect(self._refresh_available)
        self.add_button.clicked.connect(self.add_selected_available)
        self.remove_button.clicked.connect(self.remove_selected)
        self.available.itemDoubleClicked.connect(lambda _item: self.add_selected_available())
        self.selected.itemDoubleClicked.connect(lambda _item: self.remove_selected())
        self._selected_ids: list[str] = []
        self.set_values(values or [])

    def _label(self, technique_id: str) -> str:
        technique = self._by_id.get(technique_id)
        if not technique:
            return technique_id
        return f"{technique_id} - {technique.get('name', '')}".strip(" -")

    def _refresh_available(self) -> None:
        query = self.search.text().strip().lower()
        self.available.clear()
        for technique in self._catalog:
            technique_id = str(technique.get("external_id", ""))
            label = self._label(technique_id)
            if technique_id in self._selected_ids:
                continue
            if query and query not in label.lower() and query not in str(technique.get("short_description", "")).lower():
                continue
            item = QtWidgets.QListWidgetItem(label)
            item.setData(QtCore.Qt.UserRole, technique_id)
            self.available.addItem(item)

    def _refresh_selected(self) -> None:
        self.selected.clear()
        for technique_id in self._selected_ids:
            item = QtWidgets.QListWidgetItem(self._label(technique_id))
            item.setData(QtCore.Qt.UserRole, technique_id)
            self.selected.addItem(item)

    def set_values(self, values: list[str]) -> None:
        self._selected_ids = []
        for value in values:
            self.add_value(str(value), refresh=False)
        self._refresh_selected()
        self._refresh_available()

    def add_value(self, technique_id: str, *, refresh: bool = True) -> None:
        if technique_id and technique_id not in self._selected_ids:
            self._selected_ids.append(technique_id)
        if refresh:
            self._refresh_selected()
            self._refresh_available()

    def add_selected_available(self) -> None:
        item = self.available.currentItem()
        if item:
            self.add_value(str(item.data(QtCore.Qt.UserRole)))

    def remove_selected(self) -> None:
        item = self.selected.currentItem()
        if item:
            technique_id = str(item.data(QtCore.Qt.UserRole))
            self._selected_ids = [value for value in self._selected_ids if value != technique_id]
            self._refresh_selected()
            self._refresh_available()

    def selected_values(self) -> list[str]:
        return list(self._selected_ids)


class MethodListModel(QtCore.QAbstractListModel):
    def __init__(self, methods: list[dict[str, Any]], parent=None) -> None:
        super().__init__(parent)
        self.methods = methods

    def rowCount(self, parent: QtCore.QModelIndex = QtCore.QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.methods)

    def data(self, index: QtCore.QModelIndex, role: int = QtCore.Qt.DisplayRole):
        if not index.isValid() or not 0 <= index.row() < len(self.methods):
            return None
        method = self.methods[index.row()]
        if role == QtCore.Qt.DisplayRole:
            return method.get("title") or "Untitled method"
        if role == QtCore.Qt.UserRole:
            return index.row()
        return None

    def reset(self) -> None:
        self.beginResetModel()
        self.endResetModel()


class MethodFilterProxy(QtCore.QSortFilterProxyModel):
    def __init__(self, owner: "HuntMethodCatalogEditor", parent=None) -> None:
        super().__init__(parent)
        self.owner = owner

    def rowCount(self, parent: QtCore.QModelIndex = QtCore.QModelIndex()) -> int:
        return max(0, super().rowCount(parent))

    def filterAcceptsRow(self, source_row: int, source_parent: QtCore.QModelIndex) -> bool:
        method = self.sourceModel().methods[source_row]
        query = self.owner.search.text().strip().lower()
        technique = self.owner.filter_technique.currentText()
        kind = self.owner.filter_kind.currentText()
        strength = self.owner.filter_strength.currentText()
        ioc_filter = self.owner.filter_ioc.currentText()
        haystack = " ".join(
            str(value)
            for value in (
                method.get("title", ""),
                method.get("template", ""),
                method.get("method_kind", ""),
                method.get("method_strength", ""),
                " ".join(method.get("techniques", []) or []),
                " ".join(method.get("supported_ioc_types", []) or []),
            )
        ).lower()
        if query and query not in haystack:
            return False
        if technique != "All" and technique not in (method.get("techniques", []) or []):
            return False
        if kind != "All" and kind != method.get("method_kind"):
            return False
        if strength != "All" and strength != method.get("method_strength"):
            return False
        has_ioc = bool(method.get("supported_ioc_types"))
        if ioc_filter == "Supports IOC" and not has_ioc:
            return False
        if ioc_filter == "No IOC" and has_ioc:
            return False
        return True


class HuntMethodCatalogEditor(QtWidgets.QWidget):
    """Structured split-pane editor for ToolPack hunt methods.

    Filtering operates on proxy rows, but edits always write back to the
    original method list index so hidden methods are not lost or reordered.
    """

    def __init__(self, techniques: list[dict[str, Any]], methods: list[dict[str, Any]] | None = None, parent=None) -> None:
        super().__init__(parent)
        self.setMinimumSize(620, 460)
        self._techniques = techniques
        self._methods = [_normalize_method(method) for method in methods or []]
        self._current_source_row: int | None = None
        self._loading = False
        self._persisting = False
        layout = QtWidgets.QVBoxLayout(self)

        self.splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.splitter.setChildrenCollapsible(False)
        layout.addWidget(self.splitter, 1)

        self.method_rail = QtWidgets.QWidget()
        self.method_rail.setMinimumWidth(280)
        rail_layout = QtWidgets.QVBoxLayout(self.method_rail)
        self.search = QtWidgets.QLineEdit()
        self.search.setPlaceholderText("Search methods")
        rail_layout.addWidget(self.search)
        filters = QtWidgets.QGridLayout()
        self.filter_technique = QtWidgets.QComboBox()
        self.filter_technique.addItems(["All", *sorted({technique.get("external_id", "") for technique in techniques if technique.get("external_id")})])
        self.filter_kind = QtWidgets.QComboBox()
        self.filter_kind.addItems(["All", *METHOD_KIND_OPTIONS])
        self.filter_strength = QtWidgets.QComboBox()
        self.filter_strength.addItems(["All", *METHOD_STRENGTH_OPTIONS])
        self.filter_ioc = QtWidgets.QComboBox()
        self.filter_ioc.addItems(["Any", "Supports IOC", "No IOC"])
        for column, (label, combo) in enumerate(
            (
                ("Technique", self.filter_technique),
                ("Kind", self.filter_kind),
                ("Strength", self.filter_strength),
                ("IOC", self.filter_ioc),
            )
        ):
            filters.addWidget(QtWidgets.QLabel(label), column, 0)
            filters.addWidget(combo, column, 1)
        rail_layout.addLayout(filters)
        self.count_label = QtWidgets.QLabel()
        rail_layout.addWidget(self.count_label)
        self.model = MethodListModel(self._methods)
        self.proxy = MethodFilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self.list_view = QtWidgets.QListView()
        self.list_view.setModel(self.proxy)
        rail_layout.addWidget(self.list_view, 1)
        actions = QtWidgets.QHBoxLayout()
        self.add_button = QtWidgets.QPushButton("Add Method")
        self.remove_button = QtWidgets.QPushButton("Remove")
        actions.addWidget(self.add_button)
        actions.addWidget(self.remove_button)
        rail_layout.addLayout(actions)

        self.detail_pane = QtWidgets.QWidget()
        detail_layout = QtWidgets.QVBoxLayout(self.detail_pane)
        self.empty_state = QtWidgets.QLabel("No hunt methods match the current filters.")
        self.empty_state.setAlignment(QtCore.Qt.AlignCenter)
        self.empty_state.setWordWrap(True)
        detail_layout.addWidget(self.empty_state)
        self.detail_tabs = QtWidgets.QTabWidget()
        self.detail_tabs.setMinimumWidth(360)
        detail_layout.addWidget(self.detail_tabs, 1)
        self.splitter.addWidget(self.method_rail)
        self.splitter.addWidget(self.detail_pane)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setStretchFactor(1, 3)
        self.splitter.setSizes([260, 620])
        self._build_detail_tabs()

        self.search.textChanged.connect(self._filter_changed)
        for combo in (self.filter_technique, self.filter_kind, self.filter_strength, self.filter_ioc):
            combo.currentTextChanged.connect(self._filter_changed)
        self.list_view.selectionModel().selectionChanged.connect(self._selection_changed)
        self.add_button.clicked.connect(self.add_method)
        self.remove_button.clicked.connect(self.remove_selected)
        for widget in (
            self.title,
            self.execution_surface,
            self.surface_details,
        ):
            widget.textChanged.connect(self._editor_changed)
        for combo in (self.output_format, self.method_strength, self.method_kind, self.noise_level, self.privilege_required):
            combo.currentTextChanged.connect(self._editor_changed)
        self.time_cost.valueChanged.connect(self._editor_changed)
        for text in (self.template, self.expectation, self.behavior_focus, self.strength_reason):
            text.textChanged.connect(self._editor_changed)
        self._filter_changed()
        if self.proxy.rowCount():
            self.list_view.setCurrentIndex(self.proxy.index(0, 0))
        self._update_empty_state()

    def _build_detail_tabs(self) -> None:
        overview = QtWidgets.QWidget()
        form = QtWidgets.QFormLayout(overview)
        self.title = QtWidgets.QLineEdit()
        self.output_format = QtWidgets.QComboBox()
        self.output_format.addItems(OUTPUT_OPTIONS)
        self.method_strength = QtWidgets.QComboBox()
        self.method_strength.addItems(METHOD_STRENGTH_OPTIONS)
        self.method_kind = QtWidgets.QComboBox()
        self.method_kind.addItems(METHOD_KIND_OPTIONS)
        self.noise_level = QtWidgets.QComboBox()
        self.noise_level.addItems(NOISE_OPTIONS)
        self.privilege_required = QtWidgets.QComboBox()
        self.privilege_required.addItems(PRIVILEGE_OPTIONS)
        self.time_cost = QtWidgets.QSpinBox()
        self.time_cost.setRange(1, 99)
        self.execution_surface = QtWidgets.QLineEdit()
        self.surface_details = QtWidgets.QLineEdit()
        for label, widget in (
            ("Title", self.title),
            ("Output Format", self.output_format),
            ("Strength", self.method_strength),
            ("Kind", self.method_kind),
            ("Noise", self.noise_level),
            ("Privilege", self.privilege_required),
            ("Time Cost", self.time_cost),
            ("Execution Surface", self.execution_surface),
            ("Surface Details", self.surface_details),
        ):
            form.addRow(label, widget)
        self.detail_tabs.addTab(overview, "Overview")

        template_tab = QtWidgets.QWidget()
        template_layout = QtWidgets.QVBoxLayout(template_tab)
        self.template = QtWidgets.QPlainTextEdit()
        self.template.setMinimumHeight(260)
        template_layout.addWidget(self.template)
        self.detail_tabs.addTab(template_tab, "Template")

        mapping = QtWidgets.QWidget()
        mapping_layout = QtWidgets.QVBoxLayout(mapping)
        self.techniques = TechniqueSelector(self._techniques)
        self.supported_iocs = MultiCheckEditor("Supported IOC Types", list(IOC_DEFAULTS))
        self.placeholders = StringListEditor("Required Placeholders")
        self.data_sources = StringListEditor("Data Sources")
        mapping_layout.addWidget(self.techniques, 2)
        mapping_layout.addWidget(self.supported_iocs)
        mapping_layout.addWidget(self.placeholders)
        mapping_layout.addWidget(self.data_sources)
        self.detail_tabs.addTab(_scroll_area(mapping), "Mapping")

        guidance = QtWidgets.QWidget()
        guidance_layout = QtWidgets.QVBoxLayout(guidance)
        self.expectation = QtWidgets.QPlainTextEdit()
        self.behavior_focus = QtWidgets.QPlainTextEdit()
        self.strength_reason = QtWidgets.QPlainTextEdit()
        self.service_examples = StringListEditor("Service Examples")
        self.prerequisites = StringListEditor("Prerequisites")
        for label, widget in (
            ("Expectation", self.expectation),
            ("Behavior Focus", self.behavior_focus),
            ("Strength Reason", self.strength_reason),
        ):
            guidance_layout.addWidget(QtWidgets.QLabel(label))
            widget.setMinimumHeight(80)
            guidance_layout.addWidget(widget)
        guidance_layout.addWidget(self.service_examples)
        guidance_layout.addWidget(self.prerequisites)
        self.detail_tabs.addTab(_scroll_area(guidance), "Guidance")

    def _blank_method(self) -> dict[str, Any]:
        return _normalize_method({
            "title": "New Hunt Method",
            "techniques": [],
            "template": "",
            "supported_ioc_types": [],
            "required_placeholders": [],
            "output_format": "query",
            "execution_surface": "",
            "surface_details": "",
            "service_examples": [],
            "prerequisites": [],
            "noise_level": "medium",
            "privilege_required": "unknown",
            "time_cost": 2,
            "data_sources": [],
            "expectation": "",
            "method_strength": "primary_hunt",
            "method_kind": "behavior_hunt",
            "strength_reason": "",
            "behavior_focus": "",
        })

    def _filter_changed(self) -> None:
        self._persist_current()
        self._invalidate_filter()
        shown = self.proxy.rowCount()
        total = len(self._methods)
        self.count_label.setText(f"{shown} of {total} methods" if shown != total else f"{total} methods")
        if shown and not self.list_view.currentIndex().isValid():
            self.list_view.setCurrentIndex(self.proxy.index(0, 0))
        self._update_empty_state()

    def _selection_changed(self) -> None:
        self._persist_current()
        index = self.list_view.currentIndex()
        if not index.isValid():
            self._current_source_row = None
            self._update_empty_state()
            return
        source = self.proxy.mapToSource(index)
        self._current_source_row = source.row()
        self._load_method(self._methods[source.row()])
        self._update_empty_state()

    def _load_method(self, method: dict[str, Any]) -> None:
        method = _normalize_method(method)
        self._loading = True
        try:
            self.title.setText(str(method.get("title", "")))
            _set_combo(self.output_format, method.get("output_format"), "query")
            _set_combo(self.method_strength, method.get("method_strength"), "primary_hunt")
            _set_combo(self.method_kind, method.get("method_kind"), "behavior_hunt")
            _set_combo(self.noise_level, method.get("noise_level"), "medium")
            _set_combo(self.privilege_required, method.get("privilege_required"), "unknown")
            self.time_cost.setValue(_coerce_time_cost(method.get("time_cost")))
            self.execution_surface.setText(str(method.get("execution_surface", "")))
            self.surface_details.setText(str(method.get("surface_details", "")))
            self.template.setPlainText(str(method.get("template", "")))
            self.techniques.set_values([str(value) for value in _as_list(method.get("techniques"))])
            self.supported_iocs.set_values([str(value) for value in _as_list(method.get("supported_ioc_types"))])
            self.placeholders.set_values([str(value) for value in _as_list(method.get("required_placeholders"))])
            self.data_sources.set_values([str(value) for value in _as_list(method.get("data_sources"))])
            self.expectation.setPlainText(str(method.get("expectation", "")))
            self.behavior_focus.setPlainText(str(method.get("behavior_focus", "")))
            self.strength_reason.setPlainText(str(method.get("strength_reason", "")))
            self.service_examples.set_values([str(value) for value in _as_list(method.get("service_examples"))])
            self.prerequisites.set_values([str(value) for value in _as_list(method.get("prerequisites"))])
        finally:
            self._loading = False

    def _current_payload(self) -> dict[str, Any]:
        try:
            time_cost = int(self.time_cost.value())
        except ValueError:
            time_cost = 1
        return {
            "title": self.title.text().strip() or "Untitled method",
            "techniques": self.techniques.selected_values(),
            "template": self.template.toPlainText().strip(),
            "supported_ioc_types": self.supported_iocs.values(),
            "required_placeholders": self.placeholders.values(),
            "output_format": self.output_format.currentText(),
            "method_strength": self.method_strength.currentText(),
            "method_kind": self.method_kind.currentText(),
            "noise_level": self.noise_level.currentText(),
            "privilege_required": self.privilege_required.currentText(),
            "time_cost": max(1, time_cost),
            "execution_surface": self.execution_surface.text().strip(),
            "surface_details": self.surface_details.text().strip(),
            "data_sources": self.data_sources.values(),
            "expectation": self.expectation.toPlainText().strip(),
            "behavior_focus": self.behavior_focus.toPlainText().strip(),
            "strength_reason": self.strength_reason.toPlainText().strip(),
            "service_examples": self.service_examples.values(),
            "prerequisites": self.prerequisites.values(),
        }

    def _editor_changed(self) -> None:
        if not self._loading:
            self._persist_current()

    def _persist_current(self) -> None:
        if self._loading or self._persisting or self._current_source_row is None or not 0 <= self._current_source_row < len(self._methods):
            return
        self._persisting = True
        try:
            original = dict(self._methods[self._current_source_row])
            original.update(self._current_payload())
            self._methods[self._current_source_row] = original
            self.model.dataChanged.emit(self.model.index(self._current_source_row, 0), self.model.index(self._current_source_row, 0))
        finally:
            self._persisting = False

    def add_method(self) -> None:
        self._persist_current()
        self.search.clear()
        self.filter_technique.setCurrentText("All")
        self.filter_kind.setCurrentText("All")
        self.filter_strength.setCurrentText("All")
        self.filter_ioc.setCurrentText("Any")
        row = len(self._methods)
        self.model.beginInsertRows(QtCore.QModelIndex(), row, row)
        self._methods.append(self._blank_method())
        self.model.endInsertRows()
        self._invalidate_filter()
        index = self.proxy.mapFromSource(self.model.index(row, 0))
        if index.isValid():
            self.list_view.setCurrentIndex(index)

    def remove_selected(self) -> None:
        index = self.list_view.currentIndex()
        if not index.isValid():
            return
        source = self.proxy.mapToSource(index)
        row = source.row()
        self.model.beginRemoveRows(QtCore.QModelIndex(), row, row)
        self._methods.pop(row)
        self.model.endRemoveRows()
        self._current_source_row = None
        self._invalidate_filter()
        if self.proxy.rowCount():
            self.list_view.setCurrentIndex(self.proxy.index(min(row, self.proxy.rowCount() - 1), 0))

    def methods(self) -> list[dict[str, Any]]:
        """Return normalized hunt methods after persisting the visible detail form."""

        self._persist_current()
        return [_normalize_method(method) for method in self._methods]

    def _invalidate_filter(self) -> None:
        if hasattr(self.proxy, "beginFilterChange") and hasattr(self.proxy, "endFilterChange"):
            self.proxy.beginFilterChange()
            self.proxy.endFilterChange()
        else:
            self.proxy.invalidateFilter()

    def _update_empty_state(self) -> None:
        has_visible_method = self.proxy.rowCount() > 0 and self.list_view.currentIndex().isValid()
        self.empty_state.setVisible(not has_visible_method)
        self.detail_tabs.setEnabled(has_visible_method)
        if has_visible_method:
            return
        self._current_source_row = None
        self._loading = True
        try:
            self.title.clear()
            self.execution_surface.clear()
            self.surface_details.clear()
            self.template.clear()
            self.techniques.set_values([])
            self.supported_iocs.set_values([])
            self.placeholders.set_values([])
            self.data_sources.set_values([])
            self.expectation.clear()
            self.behavior_focus.clear()
            self.strength_reason.clear()
            self.service_examples.set_values([])
            self.prerequisites.set_values([])
        finally:
            self._loading = False


class ThreatPayloadEditor(QtWidgets.QWidget):
    """Structured ThreatProfile payload editor that preserves unknown keys."""

    def __init__(self, *, techniques: list[dict[str, Any]], payload: dict[str, Any], parent=None) -> None:
        super().__init__(parent)
        self.setMinimumWidth(500)
        self._original = copy.deepcopy(payload or {})
        layout = QtWidgets.QVBoxLayout(self)
        self.tabs = QtWidgets.QTabWidget()
        layout.addWidget(self.tabs, 1)
        scope = QtWidgets.QWidget()
        scope_layout = QtWidgets.QVBoxLayout(scope)
        self.techniques = TechniqueSelector(techniques, [str(value) for value in _as_list(payload.get("mitre_techniques") or payload.get("techniques"))])
        scope_layout.addWidget(self.techniques)
        self.tabs.addTab(_scroll_area(scope), "ATT&CK Scope")
        intel = QtWidgets.QWidget()
        intel_layout = QtWidgets.QVBoxLayout(intel)
        self.aliases = StringListEditor("Aliases", [str(value) for value in _as_list(payload.get("aliases"))])
        self.indicators = IocTableEditor(_as_list(payload.get("indicators")))
        intel_layout.addWidget(self.aliases)
        intel_layout.addWidget(self.indicators)
        self.tabs.addTab(_scroll_area(intel), "Intel")
        notes = QtWidgets.QWidget()
        notes_layout = QtWidgets.QVBoxLayout(notes)
        self.extra_hunts = StringListEditor("Extra Hunts", [str(value) for value in _as_list(payload.get("extra_hunts"))])
        self.references = StringListEditor("References", [str(value) for value in _as_list(payload.get("references"))])
        notes_layout.addWidget(self.extra_hunts)
        notes_layout.addWidget(self.references)
        self.tabs.addTab(_scroll_area(notes), "Notes")
        self.preview = QtWidgets.QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setPlainText(json_preview(payload or {}, limit=12000))
        self.tabs.addTab(self.preview, "Payload Preview")

    def payload(self, *, summary: str) -> dict[str, Any]:
        """Merge structured threat edits back into the original payload."""

        payload = copy.deepcopy(self._original)
        payload.update(
            {
                "summary": summary,
                "aliases": self.aliases.values(),
                "mitre_techniques": self.techniques.selected_values(),
                "indicators": self.indicators.values(),
                "extra_hunts": self.extra_hunts.values(),
                "references": self.references.values(),
            }
        )
        return payload


class ToolPayloadEditor(QtWidgets.QWidget):
    """Structured ToolPack payload editor with defaults, Sigma, and methods tabs."""

    def __init__(
        self,
        *,
        techniques: list[dict[str, Any]],
        payload: dict[str, Any],
        available_sigma_families: dict[str, int] | list[str] | tuple[str, ...] | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setMinimumWidth(620)
        self._original = copy.deepcopy(payload or {})
        if isinstance(available_sigma_families, dict):
            self.available_sigma_families = sorted(
                str(value).strip().lower()
                for value in available_sigma_families
                if str(value).strip()
            )
        else:
            self.available_sigma_families = sorted(
                str(value).strip().lower()
                for value in (available_sigma_families or [])
                if str(value).strip()
            )
        layout = QtWidgets.QVBoxLayout(self)
        self.tabs = QtWidgets.QTabWidget()
        layout.addWidget(self.tabs, 1)
        self._build_profile_tab(payload)
        self._build_defaults_tab(payload)
        self.methods_editor = HuntMethodCatalogEditor(techniques, _as_list(payload.get("hunt_methods")))
        self.tabs.addTab(self.methods_editor, "Hunt Methods")
        self._build_sigma_tab(payload)
        self.preview = QtWidgets.QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setPlainText(json_preview(payload or {}, limit=12000))
        self.tabs.addTab(self.preview, "Payload Preview")

    def _build_profile_tab(self, payload: dict[str, Any]) -> None:
        tab = QtWidgets.QWidget()
        form = QtWidgets.QFormLayout(tab)
        self.platform = QtWidgets.QComboBox()
        self.platform.addItems(PLATFORM_OPTIONS)
        _set_combo(self.platform, payload.get("platform"), "Other")
        self.execution_surface = QtWidgets.QLineEdit(str(payload.get("execution_surface", "")))
        self.surface_details = QtWidgets.QLineEdit(str(payload.get("surface_details", "")))
        self.variant_of = QtWidgets.QLineEdit(str(payload.get("variant_of_tool_external_id", "")))
        self.variant_origin = QtWidgets.QLineEdit(str(payload.get("variant_origin", "")))
        self.service_examples = StringListEditor("Service Examples", [str(value) for value in _as_list(payload.get("service_examples"))])
        self.references = StringListEditor("References", [str(value) for value in _as_list(payload.get("references"))])
        for label, widget in (
            ("Platform", self.platform),
            ("Execution Surface", self.execution_surface),
            ("Surface Details", self.surface_details),
            ("Variant Of", self.variant_of),
            ("Variant Origin", self.variant_origin),
        ):
            form.addRow(label, widget)
        form.addRow(self.service_examples)
        form.addRow(self.references)
        self.tabs.addTab(_scroll_area(tab), "Profile")

    def _build_defaults_tab(self, payload: dict[str, Any]) -> None:
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(tab)
        self.environment_defaults = KeyValueTableEditor("Environment Defaults", payload.get("environment_defaults", {}) if isinstance(payload.get("environment_defaults"), dict) else {})
        self.template_values = KeyValueTableEditor("Template Values", payload.get("template_values", {}) if isinstance(payload.get("template_values"), dict) else {})
        layout.addWidget(self.environment_defaults)
        layout.addWidget(self.template_values)
        self.tabs.addTab(_scroll_area(tab), "Defaults")

    def _build_sigma_tab(self, payload: dict[str, Any]) -> None:
        tab = QtWidgets.QWidget()
        form = QtWidgets.QFormLayout(tab)
        sigma_translation = payload.get("sigma_translation", {}) if isinstance(payload.get("sigma_translation"), dict) else {}
        sigma_scope = payload.get("sigma_scope", {}) if isinstance(payload.get("sigma_scope"), dict) else {}
        self.sigma_enabled = QtWidgets.QCheckBox("Enabled")
        self.sigma_enabled.setChecked(bool(sigma_translation.get("enabled")))
        self.sigma_backend = QtWidgets.QLineEdit(str(sigma_translation.get("backend", "")))
        self.sigma_output_format = QtWidgets.QComboBox()
        self.sigma_output_format.addItems(SIGMA_OUTPUT_FORMAT_OPTIONS)
        self.sigma_output_format_other = QtWidgets.QLineEdit()
        self.sigma_output_format_other.setPlaceholderText("Custom output format")
        output_format = str(sigma_translation.get("output_format", "")).strip()
        if output_format and output_format not in SIGMA_OUTPUT_FORMAT_OPTIONS:
            self.sigma_output_format.setCurrentText("Other")
            self.sigma_output_format_other.setText(output_format)
        else:
            _set_combo(self.sigma_output_format, output_format, "lucene")
        self.sigma_output_format.currentTextChanged.connect(self._update_sigma_output_format_other)
        self._update_sigma_output_format_other()
        self.sigma_families = StringListEditor("Default Families", [str(value) for value in _as_list(sigma_scope.get("default_families"))])
        self.sigma_autofill_button = QtWidgets.QPushButton("Autofill From Imported Sigma")
        self.sigma_autofill_button.setEnabled(bool(self.available_sigma_families))
        self.sigma_autofill_button.clicked.connect(self.autofill_sigma_families)
        form.addRow("Sigma Translation", self.sigma_enabled)
        form.addRow("Backend", self.sigma_backend)
        form.addRow("Output Format", self.sigma_output_format)
        form.addRow("Other Format", self.sigma_output_format_other)
        form.addRow(self.sigma_families)
        form.addRow(self.sigma_autofill_button)
        self.tabs.addTab(_scroll_area(tab), "Sigma")

    def _update_sigma_output_format_other(self) -> None:
        self.sigma_output_format_other.setVisible(self.sigma_output_format.currentText() == "Other")

    def _sigma_output_format_value(self) -> str:
        if self.sigma_output_format.currentText() == "Other":
            return self.sigma_output_format_other.text().strip()
        return self.sigma_output_format.currentText().strip()

    def autofill_sigma_families(self) -> None:
        existing = self.sigma_families.values()
        merged: list[str] = []
        for value in [*existing, *self.available_sigma_families]:
            normalized = str(value).strip().lower()
            if normalized and normalized not in merged:
                merged.append(normalized)
        self.sigma_families.set_values(merged)

    def payload(self, *, summary: str) -> dict[str, Any]:
        payload = copy.deepcopy(self._original)
        sigma_translation = copy.deepcopy(payload.get("sigma_translation", {}) if isinstance(payload.get("sigma_translation"), dict) else {})
        sigma_translation.update(
            {
                "enabled": self.sigma_enabled.isChecked(),
                "backend": self.sigma_backend.text().strip(),
                "output_format": self._sigma_output_format_value(),
            }
        )
        sigma_scope = copy.deepcopy(payload.get("sigma_scope", {}) if isinstance(payload.get("sigma_scope"), dict) else {})
        sigma_scope["default_families"] = self.sigma_families.values()
        payload.update(
            {
                "summary": summary,
                "platform": self.platform.currentText(),
                "execution_surface": self.execution_surface.text().strip(),
                "surface_details": self.surface_details.text().strip(),
                "variant_of_tool_external_id": self.variant_of.text().strip(),
                "variant_origin": self.variant_origin.text().strip(),
                "service_examples": self.service_examples.values(),
                "references": self.references.values(),
                "environment_defaults": self.environment_defaults.values(),
                "template_values": self.template_values.values(),
                "sigma_translation": sigma_translation,
                "sigma_scope": sigma_scope,
                "hunt_methods": self.methods_editor.methods(),
            }
        )
        return payload
