"""Qt stylesheet and palette constants for the HUNTER shell."""

from __future__ import annotations


QT_STYLE = """
QMainWindow, QWidget {
    background: #101721;
    color: #d8e2f0;
    font-family: "Segoe UI";
    font-size: 10pt;
}
QFrame#Header {
    background: #151d29;
    border-bottom: 1px solid #283445;
}
QLabel#Title {
    color: #ff2457;
    font-size: 22px;
    font-weight: 800;
}
QLabel#SectionTitle {
    color: #ffffff;
    font-size: 15px;
    font-weight: 700;
}
QPushButton {
    background: #1d2838;
    border: 1px solid #2d3b4e;
    border-radius: 4px;
    padding: 7px 12px;
    color: #d8e2f0;
}
QPushButton:hover {
    background: #26354a;
    border-color: #12b5cb;
}
QPushButton:checked {
    background: #0d4560;
    border-color: #16c4df;
    color: #ffffff;
}
QPushButton#Primary {
    background: #11b5cf;
    color: #061018;
    font-weight: 700;
    border-color: #11b5cf;
}
QLineEdit, QTextEdit, QPlainTextEdit {
    background: #0f1620;
    border: 1px solid #29374a;
    border-radius: 4px;
    color: #ffffff;
    padding: 7px;
}
QTabWidget::pane {
    border: 1px solid #3f5672;
    top: -1px;
}
QTabBar::tab {
    background: #162131;
    border: 1px solid #3f5672;
    border-bottom-color: #49627f;
    color: #ffffff;
    padding: 8px 16px;
    margin-right: 2px;
}
QTabBar::tab:hover {
    background: #203047;
    border-color: #5d7da2;
}
QTabBar::tab:selected {
    background: #243247;
    border-color: #7fa4cb;
    border-bottom-color: #243247;
    color: #ffffff;
}
QListView, QTableView, QTableWidget, QTreeView {
    background: #0f1620;
    alternate-background-color: #151f2c;
    border: 1px solid #3f5672;
    color: #ffffff;
    gridline-color: #49627f;
    selection-background-color: #0d4560;
    selection-color: #ffffff;
}
QTableWidget::item, QListView::item, QTreeView::item {
    color: #ffffff;
    border-bottom: 1px solid #1b2839;
    padding: 4px;
}
QTableWidget::item:selected, QListView::item:selected, QTreeView::item:selected {
    background: #0d4560;
    color: #ffffff;
}
QHeaderView::section {
    background: #1a2636;
    color: #d8e2f0;
    padding: 7px;
    border: 0;
    border-right: 1px solid #49627f;
    border-bottom: 1px solid #49627f;
}
QComboBox {
    background: #0f1620;
    border: 1px solid #3f5672;
    border-radius: 4px;
    color: #ffffff;
    padding: 5px 8px;
}
QComboBox:hover {
    border-color: #5d7da2;
}
QComboBox QAbstractItemView {
    background: #0f1620;
    border: 1px solid #49627f;
    color: #ffffff;
    selection-background-color: #0d4560;
    selection-color: #ffffff;
}
QCheckBox {
    color: #ffffff;
}
QGroupBox {
    border: 1px solid #3f5672;
    border-radius: 5px;
    margin-top: 12px;
    padding: 12px;
}
QGroupBox::title {
    color: #8ee8f7;
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
}
QSplitter::handle {
    background: #263142;
}
"""
