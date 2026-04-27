"""Qt model regressions for the PySide6 shell."""

from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6 import QtCore, QtGui, QtWidgets, QtTest
from PySide6.QtWidgets import QApplication

from hunter.qt.models import EntityListModel


def qt_app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


class QtReviewPlanModelTests(unittest.TestCase):
    def setUp(self) -> None:
        qt_app()

    def _steps(self, count: int = 1000) -> list[dict]:
        return [
            {
                "step_id": f"step_{index:04d}",
                "title": f"Review Step {index}",
                "tool_pack": "Kibana" if index % 2 else "Arkime",
                "techniques": [f"T{1000 + (index % 20)}"],
                "enabled": True,
                "content_origin": "authored_tool_hunt",
                "method_kind": "behavior_hunt",
                "method_strength": "primary_hunt",
                "why_selected": "Model virtualization fixture.",
            }
            for index in range(count)
        ]

    def test_review_plan_model_groups_large_packs_without_step_widgets(self) -> None:
        from hunter.qt.models import ReviewPlanModel

        model = ReviewPlanModel()
        model.set_hunt_pack(
            {
                "id": 42,
                "name": "Large Qt Review Pack",
                "payload": {"steps": self._steps(1000)},
                "summary": {},
            }
        )

        self.assertEqual(model.step_count, 1000)
        self.assertEqual(model.group_count, 20)
        self.assertEqual(model.rowCount(), 1020)
        self.assertEqual(model.columnCount(), 5)

    def test_review_plan_model_updates_hidden_group_steps(self) -> None:
        from hunter.qt.models import ReviewPlanModel

        model = ReviewPlanModel()
        model.set_hunt_pack(
            {
                "id": 43,
                "name": "Editable Qt Review Pack",
                "payload": {"steps": self._steps(60)},
                "summary": {},
            }
        )
        model.set_group_enabled("T1001", False)

        disabled = [
            step
            for step in model.hunt_pack["payload"]["steps"]
            if (step.get("techniques") or [""])[0] == "T1001"
        ]
        self.assertGreater(len(disabled), 0)
        self.assertTrue(all(not step.get("enabled", True) for step in disabled))

        step_index = model.index_for_step_id(disabled[0]["step_id"])
        self.assertTrue(step_index.isValid())
        self.assertEqual(model.data(step_index.siblingAtColumn(0), QtCore.Qt.CheckStateRole), QtCore.Qt.Unchecked)

    def test_review_plan_model_accepts_raw_qt_checkstate_ints(self) -> None:
        from hunter.qt.models import ReviewPlanModel

        model = ReviewPlanModel()
        model.set_hunt_pack(
            {
                "id": 44,
                "name": "Raw Qt CheckState Pack",
                "payload": {"steps": self._steps(2)},
                "summary": {},
            }
        )
        step_index = model.index_for_step_id("step_0000").siblingAtColumn(0)

        self.assertTrue(model.setData(step_index, 0, QtCore.Qt.CheckStateRole))
        self.assertFalse(model.hunt_pack["payload"]["steps"][0]["enabled"])
        self.assertEqual(model.data(step_index, QtCore.Qt.CheckStateRole), QtCore.Qt.Unchecked)

        self.assertTrue(model.setData(step_index, 2, QtCore.Qt.CheckStateRole))
        self.assertTrue(model.hunt_pack["payload"]["steps"][0]["enabled"])
        self.assertEqual(model.data(step_index, QtCore.Qt.CheckStateRole), QtCore.Qt.Checked)

    def test_review_plan_model_group_accepts_raw_qt_checkstate_ints(self) -> None:
        from hunter.qt.models import ReviewPlanModel

        model = ReviewPlanModel()
        model.set_hunt_pack(
            {
                "id": 45,
                "name": "Raw Group CheckState Pack",
                "payload": {"steps": self._steps(40)},
                "summary": {},
            }
        )
        group_index = next(
            model.index(row, 0)
            for row in range(model.rowCount())
            if model.data(model.index(row, 1), QtCore.Qt.DisplayRole).startswith("T1001 -")
        )

        self.assertTrue(model.setData(group_index, 0, QtCore.Qt.CheckStateRole))
        self.assertTrue(
            all(
                not step.get("enabled", True)
                for step in model.hunt_pack["payload"]["steps"]
                if (step.get("techniques") or [""])[0] == "T1001"
            )
        )

        self.assertTrue(model.setData(group_index, 2, QtCore.Qt.CheckStateRole))
        self.assertTrue(
            all(
                step.get("enabled", True)
                for step in model.hunt_pack["payload"]["steps"]
                if (step.get("techniques") or [""])[0] == "T1001"
            )
        )

    def test_review_plan_table_keyboard_toggle_reenables_step(self) -> None:
        from hunter.qt.models import ReviewPlanModel

        model = ReviewPlanModel()
        model.set_hunt_pack(
            {
                "id": 46,
                "name": "Keyboard CheckState Pack",
                "payload": {"steps": self._steps(1)},
                "summary": {},
            }
        )
        view = QtWidgets.QTableView()
        self.addCleanup(view.close)
        view.setModel(model)
        view.show()
        QApplication.processEvents()
        step_index = model.index_for_step_id("step_0000").siblingAtColumn(0)
        view.setCurrentIndex(step_index)
        QApplication.processEvents()

        QtTest.QTest.keyClick(view, QtCore.Qt.Key_Space)
        QApplication.processEvents()
        self.assertEqual(model.data(step_index, QtCore.Qt.CheckStateRole), QtCore.Qt.Unchecked)

        QtTest.QTest.keyClick(view, QtCore.Qt.Key_Space)
        QApplication.processEvents()
        self.assertEqual(model.data(step_index, QtCore.Qt.CheckStateRole), QtCore.Qt.Checked)

    def test_review_plan_table_mouse_toggle_reenables_step(self) -> None:
        from hunter.qt.models import ReviewPlanModel

        model = ReviewPlanModel()
        model.set_hunt_pack(
            {
                "id": 47,
                "name": "Mouse CheckState Pack",
                "payload": {"steps": self._steps(1)},
                "summary": {},
            }
        )
        view = QtWidgets.QTableView()
        self.addCleanup(view.close)
        view.setModel(model)
        view.show()
        QApplication.processEvents()

        step_index = model.index_for_step_id("step_0000").siblingAtColumn(0)
        rect = view.visualRect(step_index)
        checkbox_pos = QtCore.QPoint(rect.left() + 10, rect.center().y())
        QtTest.QTest.mouseClick(view.viewport(), QtCore.Qt.LeftButton, QtCore.Qt.NoModifier, checkbox_pos)
        QApplication.processEvents()
        self.assertEqual(model.data(step_index, QtCore.Qt.CheckStateRole), QtCore.Qt.Unchecked)

        rect = view.visualRect(step_index)
        checkbox_pos = QtCore.QPoint(rect.left() + 10, rect.center().y())
        QtTest.QTest.mouseClick(view.viewport(), QtCore.Qt.LeftButton, QtCore.Qt.NoModifier, checkbox_pos)
        QApplication.processEvents()
        self.assertEqual(model.data(step_index, QtCore.Qt.CheckStateRole), QtCore.Qt.Checked)


class QtEntitySearchProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        qt_app()
        self.model = EntityListModel(
            [
                {
                    "type": "MitreTechnique",
                    "external_id": "T1001",
                    "name": "Data Obfuscation",
                    "short_description": "Adversaries may use encoded command lines.",
                    "status": "active",
                    "tags": [],
                    "payload": {
                        "technique_id": "T1001",
                        "description": "Adversaries may use encoded command lines.",
                    },
                },
                {
                    "type": "MitreTechnique",
                    "external_id": "T1041",
                    "name": "Exfiltration Over C2 Channel",
                    "short_description": "Steal data over command and control channels.",
                    "status": "active",
                    "tags": [],
                    "payload": {"technique_id": "T1041"},
                },
                {
                    "type": "ThreatProfile",
                    "external_id": "apt_search",
                    "name": "APT Search",
                    "short_description": "Threat known for outbound pivots.",
                    "status": "active",
                    "tags": [],
                    "payload": {
                        "summary": "Threat known for outbound pivots.",
                        "aliases": ["Search Unit"],
                        "mitre_techniques": ["T1041"],
                        "indicators": [{"type": "domain", "value": "evil.example"}],
                        "extra_hunts": ["Review outbound traffic."],
                    },
                },
                {
                    "type": "ToolPack",
                    "external_id": "elastic_search_tool",
                    "name": "Elastic Search Tool",
                    "short_description": "AWS hunting via Elastic.",
                    "status": "active",
                    "tags": [],
                    "payload": {
                        "summary": "AWS hunting via Elastic.",
                        "platform": "AWS",
                        "hunt_methods": [
                            {
                                "title": "T1041 Hunt",
                                "techniques": ["T1041"],
                                "template": "dns.question.name: <DOMAIN_IOC>",
                                "supported_ioc_types": ["domain"],
                                "execution_surface": "Kibana",
                            }
                        ],
                    },
                },
                {
                    "type": "ToolPack",
                    "external_id": "deprecated_tool",
                    "name": "Deprecated Tool",
                    "short_description": "Old Elastic tool variant.",
                    "status": "deprecated",
                    "tags": [],
                    "payload": {
                        "summary": "Old Elastic tool variant.",
                        "platform": "Elastic",
                        "hunt_methods": [
                            {
                                "title": "Domain IOC pivot",
                                "techniques": ["T1041"],
                                "template": "dns.question.name: <DOMAIN_IOC>",
                                "supported_ioc_types": ["domain"],
                                "execution_surface": "Kibana",
                            }
                        ],
                    },
                },
                {
                    "type": "ToolPack",
                    "external_id": "elastic_active_tool",
                    "name": "Elastic Active Tool",
                    "short_description": "Active Elastic tool variant.",
                    "status": "active",
                    "tags": [],
                    "payload": {
                        "summary": "Active Elastic tool variant.",
                        "platform": "Elastic",
                        "hunt_methods": [
                            {
                                "title": "Domain IOC pivot",
                                "techniques": ["T1041"],
                                "template": "dns.question.name: <DOMAIN_IOC>",
                                "supported_ioc_types": ["domain"],
                                "execution_surface": "Kibana",
                            }
                        ],
                    },
                },
            ]
        )

    def _matches(self, query: str) -> list[str]:
        from hunter.qt.models import EntitySearchProxy
        from hunter.qt.models import ENTITY_ROLE

        proxy = EntitySearchProxy()
        proxy.setSourceModel(self.model)
        proxy.set_search_text(query)
        return [
            proxy.data(proxy.index(row, 0), ENTITY_ROLE)["external_id"]
            for row in range(proxy.rowCount())
        ]

    def test_visible_search_supports_id_and_quoted_phrases(self) -> None:
        self.assertEqual(self._matches("id:T1001"), ["T1001"])
        self.assertEqual(self._matches('"Exfiltration Over C2 Channel"'), ["T1041"])

    def test_visible_search_supports_threat_fields(self) -> None:
        self.assertEqual(self._matches('alias:"Search Unit"'), ["apt_search"])
        self.assertEqual(self._matches("indicator:evil.example"), ["apt_search"])
        self.assertEqual(self._matches("technique:T1041"), ["T1041", "apt_search", "elastic_search_tool", "deprecated_tool", "elastic_active_tool"])

    def test_visible_search_supports_tool_fields_and_exclusions(self) -> None:
        self.assertEqual(self._matches('platform:AWS method:"T1041 Hunt"'), ["elastic_search_tool"])
        self.assertEqual(self._matches("platform:Elastic -deprecated"), ["elastic_active_tool"])


class QtEntityListModelSelectionStateTests(unittest.TestCase):
    def setUp(self) -> None:
        qt_app()

    def test_generate_selected_rows_use_green_background_without_text_suffix(self) -> None:
        from hunter.qt.models import GENERATE_SELECTED_ROLE

        model = EntityListModel(
            [
                {
                    "id": 7,
                    "type": "MitreTechnique",
                    "external_id": "T1041",
                    "name": "Exfiltration Over C2 Channel",
                    "status": "active",
                    "payload": {"technique_id": "T1041"},
                }
            ]
        )

        model.set_selected_ids({7})
        index = model.index(0, 0)

        self.assertNotIn("Selected", model.data(index, QtCore.Qt.DisplayRole))
        self.assertIsInstance(model.data(index, QtCore.Qt.BackgroundRole), QtGui.QBrush)
        self.assertTrue(model.data(index, GENERATE_SELECTED_ROLE))


if __name__ == "__main__":
    unittest.main()
