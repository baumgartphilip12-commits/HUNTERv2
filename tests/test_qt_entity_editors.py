"""Structured Qt editor regressions for ThreatProfile and ToolPack payloads."""

from __future__ import annotations

import json
import os
from pathlib import Path
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6 import QtCore, QtWidgets
from PySide6.QtWidgets import QApplication, QAbstractItemView, QScrollArea, QSplitter


TECHNIQUES = [
    {"external_id": "T1001", "name": "Data Obfuscation", "short_description": "Test technique one"},
    {"external_id": "T1041", "name": "Exfiltration Over C2 Channel", "short_description": "Test technique two"},
]


def qt_app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def sample_methods() -> list[dict]:
    return [
        {
            "title": "Encoded command behavior",
            "techniques": ["T1001"],
            "template": "process.command_line contains '-enc'",
            "supported_ioc_types": [],
            "required_placeholders": [],
            "output_format": "query",
            "execution_surface": "Kibana",
            "surface_details": "Elastic endpoint index",
            "service_examples": ["Elastic Defend"],
            "prerequisites": ["Endpoint events"],
            "noise_level": "medium",
            "privilege_required": "user",
            "time_cost": 2,
            "data_sources": ["Endpoint process telemetry"],
            "expectation": "Find suspicious encoded process execution.",
            "method_strength": "primary_hunt",
            "method_kind": "behavior_hunt",
            "strength_reason": "Primary hunt for command-line behavior.",
            "behavior_focus": "Encoded command execution.",
        },
        {
            "title": "Domain IOC pivot",
            "techniques": ["T1041"],
            "template": "dns.question.name: <DOMAIN_IOC>",
            "supported_ioc_types": ["domain"],
            "required_placeholders": ["<DOMAIN_IOC>"],
            "output_format": "query",
            "execution_surface": "Kibana",
            "surface_details": "Elastic DNS index",
            "service_examples": ["Zeek dns"],
            "prerequisites": ["DNS events"],
            "noise_level": "low",
            "privilege_required": "user",
            "time_cost": 1,
            "data_sources": ["DNS logs"],
            "expectation": "Find outbound traffic to known domains.",
            "method_strength": "supporting_pivot",
            "method_kind": "ioc_pivot",
            "strength_reason": "Supporting pivot for known domains.",
            "behavior_focus": "Domain resolution for selected IOCs.",
        },
    ]


class QtThreatEditorTests(unittest.TestCase):
    def setUp(self) -> None:
        qt_app()

    def test_threat_form_populates_edits_and_preserves_unknown_payload(self) -> None:
        from hunter.qt.entity_editors import ThreatPayloadEditor

        editor = ThreatPayloadEditor(
            techniques=TECHNIQUES,
            payload={
                "summary": "Threat summary",
                "aliases": ["APT Unit"],
                "mitre_techniques": ["T1001"],
                "indicators": [{"type": "domain", "value": "evil.example"}],
                "extra_hunts": ["Review outbound traffic"],
                "references": ["https://example.test"],
                "unknown_key": {"keep": True},
            },
        )

        self.assertEqual(editor.tabs.count(), 4)
        self.assertEqual(editor.aliases.values(), ["APT Unit"])
        self.assertEqual(editor.techniques.selected_values(), ["T1001"])
        self.assertEqual(editor.indicators.values(), [{"type": "domain", "value": "evil.example"}])

        editor.aliases.add_value("Peach Sandstorm")
        editor.techniques.add_value("T1041")
        editor.indicators.add_indicator("Custom", "registry", "HKCU\\Software\\Bad")
        editor.extra_hunts.add_value("Check lateral movement")
        editor.references.add_value("https://example.test/two")

        payload = editor.payload(summary="Updated summary")

        self.assertEqual(payload["summary"], "Updated summary")
        self.assertEqual(payload["aliases"], ["APT Unit", "Peach Sandstorm"])
        self.assertEqual(payload["mitre_techniques"], ["T1001", "T1041"])
        self.assertIn({"type": "registry", "value": "HKCU\\Software\\Bad"}, payload["indicators"])
        self.assertIn("Check lateral movement", payload["extra_hunts"])
        self.assertIn("https://example.test/two", payload["references"])
        self.assertEqual(payload["unknown_key"], {"keep": True})

    def test_ioc_table_add_remove_supports_standard_and_custom_types(self) -> None:
        from hunter.qt.entity_editors import IocTableEditor

        editor = IocTableEditor([{"type": "ip", "value": "10.0.0.1"}])
        editor.add_indicator("Custom", "mutex", "Global\\Bad")
        editor.table.selectRow(0)
        editor.remove_selected()

        self.assertEqual(editor.values(), [{"type": "mutex", "value": "Global\\Bad"}])

    def test_structured_tables_keep_readable_grid_defaults(self) -> None:
        from hunter.qt.entity_editors import IocTableEditor, StringListEditor

        aliases = StringListEditor("Aliases", ["APT Unit"])
        indicators = IocTableEditor([{"type": "domain", "value": "evil.example"}])

        for table in (aliases.table, indicators.table):
            self.assertTrue(table.showGrid())
            self.assertTrue(table.alternatingRowColors())
            self.assertFalse(table.verticalHeader().isVisible())
            self.assertEqual(table.selectionBehavior(), QAbstractItemView.SelectRows)

    def test_ioc_table_uses_readable_columns_and_combo_size(self) -> None:
        from hunter.qt.entity_editors import IocTableEditor

        editor = IocTableEditor([{"type": "domain", "value": "evil.example"}])
        combo = editor.table.cellWidget(0, 0)

        self.assertGreaterEqual(editor.table.minimumHeight(), 220)
        self.assertGreaterEqual(editor.table.verticalHeader().defaultSectionSize(), 34)
        self.assertGreaterEqual(editor.table.horizontalHeader().minimumSectionSize(), 140)
        self.assertGreaterEqual(editor.table.columnWidth(0), 150)
        self.assertGreaterEqual(editor.table.columnWidth(1), 180)
        self.assertIsInstance(combo, QtWidgets.QComboBox)
        self.assertGreaterEqual(combo.minimumWidth(), 140)
        self.assertGreaterEqual(combo.minimumHeight(), 30)

    def test_threat_tabs_are_scroll_wrapped_for_small_dialogs(self) -> None:
        from hunter.qt.entity_editors import ThreatPayloadEditor

        editor = ThreatPayloadEditor(
            techniques=TECHNIQUES,
            payload={
                "aliases": ["APT Unit"],
                "mitre_techniques": ["T1001"],
                "indicators": [{"type": "domain", "value": "evil.example"}],
            },
        )

        self.assertLessEqual(editor.minimumWidth(), 520)
        for index in range(3):
            tab = editor.tabs.widget(index)
            self.assertIsInstance(tab, QScrollArea)
            self.assertTrue(tab.widgetResizable())


class QtToolEditorTests(unittest.TestCase):
    def setUp(self) -> None:
        qt_app()

    def test_tool_form_profile_defaults_sigma_round_trip(self) -> None:
        from hunter.qt.entity_editors import ToolPayloadEditor

        editor = ToolPayloadEditor(
            techniques=TECHNIQUES,
            available_sigma_families={"windows": 12, "azure": 4},
            payload={
                "summary": "Tool summary",
                "platform": "AWS",
                "execution_surface": "CloudWatch Logs Insights",
                "surface_details": "CloudTrail-backed hunting",
                "service_examples": ["CloudTrail"],
                "references": ["https://example.test/tool"],
                "environment_defaults": {"AWS_LOG_SOURCE": "CloudTrail"},
                "template_values": {"AWS_REGION": "us-east-1"},
                "variant_of_tool_external_id": "aws_hunting",
                "variant_origin": "branched_from_generated",
                "sigma_translation": {"enabled": True, "backend": "elasticsearch", "output_format": "lucene"},
                "sigma_scope": {"default_families": ["windows"]},
                "hunt_methods": sample_methods(),
                "unknown_key": "keep-me",
            },
        )

        self.assertEqual(editor.tabs.count(), 5)
        editor.platform.setCurrentText("Elastic")
        editor.environment_defaults.add_pair("INDEX", "logs-*")
        editor.template_values.add_pair("TENANT", "prod")
        editor.sigma_families.add_value("azure")

        payload = editor.payload(summary="Updated tool")

        self.assertEqual(payload["summary"], "Updated tool")
        self.assertEqual(payload["platform"], "Elastic")
        self.assertEqual(payload["environment_defaults"]["AWS_LOG_SOURCE"], "CloudTrail")
        self.assertEqual(payload["environment_defaults"]["INDEX"], "logs-*")
        self.assertEqual(payload["template_values"]["TENANT"], "prod")
        self.assertEqual(payload["sigma_translation"]["backend"], "elasticsearch")
        self.assertEqual(payload["sigma_scope"]["default_families"], ["windows", "azure"])
        self.assertEqual(payload["unknown_key"], "keep-me")

    def test_tool_sigma_editor_autofills_available_families_and_preserves_custom(self) -> None:
        from hunter.qt.entity_editors import ToolPayloadEditor

        editor = ToolPayloadEditor(
            techniques=TECHNIQUES,
            available_sigma_families={"windows": 12, "azure": 4, "linux": 2},
            payload={
                "sigma_scope": {"default_families": ["custom-feed"]},
                "hunt_methods": sample_methods(),
            },
        )

        self.assertGreaterEqual(editor.sigma_families.table.minimumHeight(), 220)
        editor.autofill_sigma_families()
        payload = editor.payload(summary="Tool")

        self.assertEqual(
            payload["sigma_scope"]["default_families"],
            ["custom-feed", "azure", "linux", "windows"],
        )

    def test_tool_sigma_output_format_uses_dropdown_with_other_manual_input(self) -> None:
        from hunter.qt.entity_editors import ToolPayloadEditor

        editor = ToolPayloadEditor(
            techniques=TECHNIQUES,
            payload={
                "sigma_translation": {"enabled": True, "backend": "elasticsearch", "output_format": "lucene"},
                "hunt_methods": sample_methods(),
            },
        )

        self.assertEqual(editor.sigma_output_format.currentText(), "lucene")
        self.assertTrue(editor.sigma_output_format_other.isHidden())

        editor.sigma_output_format.setCurrentText("Other")
        editor.sigma_output_format_other.setText("custom-format")
        payload = editor.payload(summary="Tool")

        self.assertFalse(editor.sigma_output_format_other.isHidden())
        self.assertEqual(payload["sigma_translation"]["output_format"], "custom-format")

        editor = ToolPayloadEditor(
            techniques=TECHNIQUES,
            payload={
                "sigma_translation": {"enabled": True, "backend": "custom-backend", "output_format": "vendor_query"},
                "hunt_methods": sample_methods(),
            },
        )

        self.assertEqual(editor.sigma_output_format.currentText(), "Other")
        self.assertEqual(editor.sigma_output_format_other.text(), "vendor_query")

    def test_method_catalog_loads_first_method_and_has_empty_state(self) -> None:
        from hunter.qt.entity_editors import HuntMethodCatalogEditor

        editor = HuntMethodCatalogEditor(techniques=TECHNIQUES, methods=sample_methods())

        self.assertEqual(editor.title.text(), "Encoded command behavior")
        self.assertTrue(editor.detail_tabs.isEnabled())

        editor.search.setText("no-such-method")

        self.assertEqual(editor.proxy.rowCount(), 0)
        self.assertFalse(editor.detail_tabs.isEnabled())
        self.assertIn("No hunt methods match", editor.empty_state.text())

        editor.search.clear()

        self.assertEqual(editor.title.text(), "Encoded command behavior")
        self.assertTrue(editor.detail_tabs.isEnabled())

    def test_method_catalog_persists_nested_control_edits_across_selection_changes(self) -> None:
        from hunter.qt.entity_editors import HuntMethodCatalogEditor

        editor = HuntMethodCatalogEditor(techniques=TECHNIQUES, methods=sample_methods())
        editor.techniques.add_value("T1041")
        editor.supported_iocs.set_values(["domain"])
        editor.placeholders.add_value("<DOMAIN_IOC>")
        editor.data_sources.add_value("DNS logs")
        editor.service_examples.add_value("Zeek dns")
        editor.prerequisites.add_value("DNS telemetry")
        editor.list_view.setCurrentIndex(editor.proxy.index(1, 0))
        exported = editor.methods()

        self.assertEqual(exported[0]["techniques"], ["T1001", "T1041"])
        self.assertEqual(exported[0]["supported_ioc_types"], ["domain"])
        self.assertIn("<DOMAIN_IOC>", exported[0]["required_placeholders"])
        self.assertIn("DNS logs", exported[0]["data_sources"])
        self.assertIn("Zeek dns", exported[0]["service_examples"])
        self.assertIn("DNS telemetry", exported[0]["prerequisites"])

    def test_method_catalog_defaults_malformed_methods_for_save(self) -> None:
        from hunter.qt.entity_editors import HuntMethodCatalogEditor

        editor = HuntMethodCatalogEditor(
            techniques=TECHNIQUES,
            methods=[
                {
                    "title": "",
                    "time_cost": "medium",
                    "method_strength": "bad-strength",
                    "unknown_extra": {"keep": True},
                }
            ],
        )
        editor.method_strength.setCurrentText("primary_hunt")
        payload = editor.methods()[0]

        self.assertEqual(payload["title"], "Untitled method")
        self.assertEqual(payload["time_cost"], 2)
        self.assertEqual(payload["method_strength"], "primary_hunt")
        self.assertEqual(payload["method_kind"], "behavior_hunt")
        self.assertEqual(payload["noise_level"], "medium")
        self.assertEqual(payload["privilege_required"], "unknown")
        self.assertEqual(payload["techniques"], [])
        self.assertEqual(payload["supported_ioc_types"], [])
        self.assertEqual(payload["required_placeholders"], [])
        self.assertEqual(payload["service_examples"], [])
        self.assertEqual(payload["prerequisites"], [])
        self.assertEqual(payload["data_sources"], [])
        self.assertEqual(payload["unknown_extra"], {"keep": True})

    def test_tool_editor_autodefaults_malformed_hunt_methods(self) -> None:
        from hunter.qt.entity_editors import ToolPayloadEditor

        editor = ToolPayloadEditor(
            techniques=TECHNIQUES,
            payload={"hunt_methods": [{"time_cost": "high", "method_strength": "unknown"}]},
        )

        payload = editor.payload(summary="Tool")
        method = payload["hunt_methods"][0]

        self.assertEqual(method["title"], "Untitled method")
        self.assertEqual(method["time_cost"], 3)
        self.assertEqual(method["method_strength"], "primary_hunt")
        self.assertEqual(method["output_format"], "query")

    def test_kibana_string_time_cost_methods_can_change_strength_and_export(self) -> None:
        from hunter.qt.entity_editors import ToolPayloadEditor

        payload = json.loads(Path("modules/tools/kibana.json").read_text(encoding="utf-8"))
        editor = ToolPayloadEditor(techniques=TECHNIQUES, payload=payload)
        editor.methods_editor.method_strength.setCurrentText("primary_hunt")
        exported = editor.payload(summary="Kibana")

        self.assertEqual(exported["hunt_methods"][0]["method_strength"], "primary_hunt")
        self.assertIsInstance(exported["hunt_methods"][0]["time_cost"], int)

    def test_method_filters_edit_original_method_and_add_clears_filters(self) -> None:
        from hunter.qt.entity_editors import HuntMethodCatalogEditor

        editor = HuntMethodCatalogEditor(techniques=TECHNIQUES, methods=sample_methods())
        editor.search.setText("domain")
        self.assertEqual(editor.proxy.rowCount(), 1)
        editor.list_view.setCurrentIndex(editor.proxy.index(0, 0))

        editor.title.setText("Renamed domain pivot")
        exported = editor.methods()

        self.assertEqual(exported[0]["title"], "Encoded command behavior")
        self.assertEqual(exported[1]["title"], "Renamed domain pivot")

        editor.search.setText("no-such-method")
        self.assertEqual(editor.proxy.rowCount(), 0)
        editor.add_method()

        self.assertEqual(editor.search.text(), "")
        self.assertEqual(editor.proxy.rowCount(), 3)
        self.assertEqual(editor.list_view.currentIndex().data(QtCore.Qt.DisplayRole), "New Hunt Method")

    def test_method_catalog_uses_non_collapsible_resizable_splitter(self) -> None:
        from hunter.qt.entity_editors import HuntMethodCatalogEditor

        editor = HuntMethodCatalogEditor(techniques=TECHNIQUES, methods=sample_methods())

        self.assertLessEqual(editor.minimumWidth(), 640)
        self.assertIsInstance(editor.splitter, QSplitter)
        self.assertFalse(editor.splitter.childrenCollapsible())
        self.assertGreaterEqual(editor.method_rail.minimumWidth(), 280)
        self.assertGreater(editor.detail_tabs.minimumWidth(), editor.method_rail.minimumWidth())

    def test_technique_selector_uses_flexible_list_widths(self) -> None:
        from hunter.qt.entity_editors import TechniqueSelector

        selector = TechniqueSelector(TECHNIQUES, ["T1001"])

        self.assertGreaterEqual(selector.available.minimumWidth(), 240)
        self.assertGreaterEqual(selector.selected.minimumWidth(), 240)
        self.assertEqual(selector.available.horizontalScrollBarPolicy(), QtCore.Qt.ScrollBarAsNeeded)
        self.assertEqual(selector.selected.horizontalScrollBarPolicy(), QtCore.Qt.ScrollBarAsNeeded)

    def test_method_detail_tabs_write_structured_fields_and_remove_cleanly(self) -> None:
        from hunter.qt.entity_editors import HuntMethodCatalogEditor

        editor = HuntMethodCatalogEditor(techniques=TECHNIQUES, methods=sample_methods())
        editor.list_view.setCurrentIndex(editor.proxy.index(0, 0))
        editor.title.setText("Updated behavior hunt")
        editor.output_format.setCurrentText("kql")
        editor.method_strength.setCurrentText("supporting_pivot")
        editor.method_kind.setCurrentText("ioc_pivot")
        editor.noise_level.setCurrentText("high")
        editor.privilege_required.setCurrentText("admin")
        editor.time_cost.setValue(5)
        editor.template.setPlainText("event.dataset:process")
        editor.techniques.add_value("T1041")
        editor.supported_iocs.set_values(["domain", "ip"])
        editor.placeholders.add_value("<IP_IOC>")
        editor.data_sources.add_value("Process telemetry")
        editor.expectation.setPlainText("Updated expectation")
        editor.behavior_focus.setPlainText("Updated behavior focus")
        editor.strength_reason.setPlainText("Updated strength reason")
        editor.service_examples.add_value("Sysmon")
        editor.prerequisites.add_value("EDR enabled")

        payload = editor.methods()[0]

        self.assertEqual(payload["title"], "Updated behavior hunt")
        self.assertEqual(payload["output_format"], "kql")
        self.assertEqual(payload["method_strength"], "supporting_pivot")
        self.assertEqual(payload["method_kind"], "ioc_pivot")
        self.assertEqual(payload["noise_level"], "high")
        self.assertEqual(payload["privilege_required"], "admin")
        self.assertEqual(payload["time_cost"], 5)
        self.assertEqual(payload["template"], "event.dataset:process")
        self.assertEqual(payload["techniques"], ["T1001", "T1041"])
        self.assertEqual(payload["supported_ioc_types"], ["domain", "ip"])
        self.assertIn("<IP_IOC>", payload["required_placeholders"])
        self.assertIn("Process telemetry", payload["data_sources"])
        self.assertEqual(payload["expectation"], "Updated expectation")
        self.assertEqual(payload["behavior_focus"], "Updated behavior focus")
        self.assertEqual(payload["strength_reason"], "Updated strength reason")
        self.assertIn("Sysmon", payload["service_examples"])
        self.assertIn("EDR enabled", payload["prerequisites"])

        editor.remove_selected()

        self.assertEqual(len(editor.methods()), 1)

    def test_editor_theme_defines_high_contrast_tabs_tables_and_combos(self) -> None:
        from hunter.qt.theme import QT_STYLE

        self.assertIn("QTabBar::tab", QT_STYLE)
        self.assertIn("color: #ffffff", QT_STYLE)
        self.assertIn("gridline-color: #49627f", QT_STYLE)
        self.assertIn("QTableWidget::item", QT_STYLE)
        self.assertIn("QComboBox", QT_STYLE)

    def test_tool_tabs_are_scroll_wrapped_for_small_dialogs(self) -> None:
        from hunter.qt.entity_editors import ToolPayloadEditor

        editor = ToolPayloadEditor(
            techniques=TECHNIQUES,
            payload={
                "platform": "AWS",
                "environment_defaults": {"AWS_LOG_SOURCE": "CloudTrail"},
                "template_values": {"AWS_REGION": "us-east-1"},
                "hunt_methods": sample_methods(),
            },
        )

        self.assertLessEqual(editor.minimumWidth(), 640)
        for index in (0, 1, 3):
            tab = editor.tabs.widget(index)
            self.assertIsInstance(tab, QScrollArea)
            self.assertTrue(tab.widgetResizable())


if __name__ == "__main__":
    unittest.main()
