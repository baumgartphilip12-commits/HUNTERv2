from __future__ import annotations

from tests.qt_shell_support import *


class QtShellSmokeTests(QtShellTestCase):
    def test_attack_url_derivation_handles_parent_and_subtechnique_ids(self) -> None:
        from hunter.qt.main_window import _attack_url_for_entity

        self.assertEqual(
            _attack_url_for_entity({"external_id": "T1001", "payload": {"technique_id": "T1001"}}),
            "https://attack.mitre.org/techniques/T1001/",
        )
        self.assertEqual(
            _attack_url_for_entity({"external_id": "T1001.001", "payload": {"technique_id": "T1001.001"}}),
            "https://attack.mitre.org/techniques/T1001/001/",
        )
    def test_qt_shell_launches_and_switches_workflow_steps(self) -> None:
        from hunter.qt.main_window import HunterMainWindow

        qt_app()
        store, root, _tempdir = self._build_store()
        sync_service = SyncService(store)
        layered_service = LayeredEntityService(store, sync_service, root)
        window = HunterMainWindow(
            store=store,
            sync_service=sync_service,
            hunt_generator=HuntGenerator(store),
            sigma_rule_service=SigmaRuleService(store),
            authoring_service=AuthoringService(store, layered_service),
            project_dir=str(root),
        )
        self.addCleanup(window.close)

        self.assertEqual(window.workflow_step_names(), ["MITRE", "Threats", "Tools", "Generate", "Review"])
        for index, name in enumerate(window.workflow_step_names()):
            window.select_workflow_step(index)
            QApplication.processEvents()
            self.assertEqual(window.current_workflow_step(), name)
    def test_qt_shell_entity_selection_updates_detail_immediately(self) -> None:
        from hunter.qt.main_window import HunterMainWindow

        qt_app()
        store, root, _tempdir = self._build_store()
        sync_service = SyncService(store)
        layered_service = LayeredEntityService(store, sync_service, root)
        window = HunterMainWindow(
            store=store,
            sync_service=sync_service,
            hunt_generator=HuntGenerator(store),
            sigma_rule_service=SigmaRuleService(store),
            authoring_service=AuthoringService(store, layered_service),
            project_dir=str(root),
        )
        self.addCleanup(window.close)

        window.select_workflow_step(window.workflow_step_names().index("Tools"))
        tool_page = window.entity_pages["ToolPack"]
        tool_page.select_first()
        QApplication.processEvents()

        self.assertIn("AWS Hunting", tool_page.detail_text())
        self.assertIn("Execution Surface", tool_page.detail_text())
        self.assertIn("Hunt Methods", tool_page.detail_text())
        self.assertIn("Structured Payload Preview", tool_page.detail_text())
    def test_qt_shell_threat_detail_is_readable(self) -> None:
        from hunter.qt.main_window import HunterMainWindow

        qt_app()
        store, root, _tempdir = self._build_store()
        sync_service = SyncService(store)
        layered_service = LayeredEntityService(store, sync_service, root)
        window = HunterMainWindow(
            store=store,
            sync_service=sync_service,
            hunt_generator=HuntGenerator(store),
            sigma_rule_service=SigmaRuleService(store),
            authoring_service=AuthoringService(store, layered_service),
            project_dir=str(root),
        )
        self.addCleanup(window.close)

        window.select_workflow_step(window.workflow_step_names().index("Threats"))
        threat_page = window.entity_pages["ThreatProfile"]
        threat_page.select_first()
        QApplication.processEvents()

        detail = threat_page.detail_text()
        self.assertIn("Mapped ATT&CK Techniques", detail)
        self.assertIn("domain: evil.example", detail)
        self.assertIn("Sigma Coverage", detail)
    def test_threat_and_tool_editors_show_structured_tabs(self) -> None:
        from hunter.qt.main_window import EntityEditorDialog

        qt_app()
        threat = {
            "type": "ThreatProfile",
            "external_id": "apt_test",
            "name": "APT Test",
            "short_description": "Threat summary",
            "status": "active",
            "tags": [],
            "payload": {
                "summary": "Threat summary",
                "aliases": ["APT Unit"],
                "mitre_techniques": ["T1001"],
                "indicators": [{"type": "domain", "value": "evil.example"}],
                "extra_hunts": ["Review outbound traffic"],
                "references": ["https://example.test"],
            },
        }
        tool = {
            "type": "ToolPack",
            "external_id": "aws_hunting",
            "name": "AWS Hunting",
            "short_description": "Tool summary",
            "status": "active",
            "tags": [],
            "payload": {
                "summary": "Tool summary",
                "platform": "AWS",
                "environment_defaults": {"AWS_LOG_SOURCE": "CloudTrail"},
                "template_values": {"AWS_REGION": "us-east-1"},
                "hunt_methods": [{"title": "T1001 Hunt", "techniques": ["T1001"], "template": "filter *"}],
            },
        }
        techniques = [{"external_id": "T1001", "name": "Data Obfuscation"}]

        threat_dialog = EntityEditorDialog("ThreatProfile", threat, techniques=techniques)
        tool_dialog = EntityEditorDialog("ToolPack", tool, techniques=techniques)
        self.addCleanup(threat_dialog.close)
        self.addCleanup(tool_dialog.close)

        self.assertEqual(
            [threat_dialog.tabs.tabText(index) for index in range(threat_dialog.tabs.count())],
            ["ATT&CK Scope", "Intel", "Notes", "Payload Preview"],
        )
        self.assertEqual(
            [tool_dialog.tabs.tabText(index) for index in range(tool_dialog.tabs.count())],
            ["Profile", "Defaults", "Hunt Methods", "Sigma", "Payload Preview"],
        )
        self.assertLessEqual(threat_dialog.structured_editor.minimumWidth(), 520)
        self.assertLessEqual(tool_dialog.structured_editor.minimumWidth(), 640)
        self.assertGreaterEqual(threat_dialog.structured_editor.indicators.table.minimumHeight(), 220)
        self.assertGreaterEqual(tool_dialog.structured_editor.methods_editor.method_rail.minimumWidth(), 280)
        threat_dialog.resize(640, 520)
        tool_dialog.resize(700, 560)
        self.assertIn("QTabBar::tab", threat_dialog.styleSheet())
        self.assertIn("gridline-color: #49627f", tool_dialog.styleSheet())
    def test_threat_and_tool_rails_show_record_buttons_but_mitre_does_not(self) -> None:
        from hunter.qt.main_window import HunterMainWindow

        qt_app()
        store, root, _tempdir = self._build_store()
        sync_service = SyncService(store)
        layered_service = LayeredEntityService(store, sync_service, root)
        window = HunterMainWindow(
            store=store,
            sync_service=sync_service,
            hunt_generator=HuntGenerator(store),
            sigma_rule_service=SigmaRuleService(store),
            authoring_service=AuthoringService(store, layered_service),
            project_dir=str(root),
        )
        self.addCleanup(window.close)

        for entity_type in ("ThreatProfile", "ToolPack"):
            page = window.entity_pages[entity_type]
            self.assertEqual(page.add_button.text(), "Add Threat" if entity_type == "ThreatProfile" else "Add Tool")
            self.assertEqual(page.remove_button.text(), "Remove Threat" if entity_type == "ThreatProfile" else "Remove Tool")
            self.assertEqual(page.edit_button.text(), "Edit Threat" if entity_type == "ThreatProfile" else "Edit Tool")
            self.assertTrue(page.add_button.isVisible() or not window.isVisible())

        mitre_page = window.entity_pages["MitreTechnique"]
        for attr in ("add_button", "remove_button", "edit_button", "branch_button", "delete_button", "generate_button"):
            self.assertFalse(hasattr(mitre_page, attr))
    def test_threat_and_tool_record_buttons_dispatch_existing_actions(self) -> None:
        from hunter.qt.main_window import EntityBrowserPage, HunterMainWindow

        qt_app()
        calls: list[str] = []

        with (
            patch.object(EntityBrowserPage, "new_entity", autospec=True, side_effect=lambda self: calls.append(f"{self.entity_type}:new")),
            patch.object(EntityBrowserPage, "edit_selected", autospec=True, side_effect=lambda self: calls.append(f"{self.entity_type}:edit")),
            patch.object(EntityBrowserPage, "delete_selected", autospec=True, side_effect=lambda self: calls.append(f"{self.entity_type}:delete")),
        ):
            store, root, _tempdir = self._build_store()
            sync_service = SyncService(store)
            layered_service = LayeredEntityService(store, sync_service, root)
            window = HunterMainWindow(
                store=store,
                sync_service=sync_service,
                hunt_generator=HuntGenerator(store),
                sigma_rule_service=SigmaRuleService(store),
                authoring_service=AuthoringService(store, layered_service),
                project_dir=str(root),
            )
            self.addCleanup(window.close)

            for entity_type in ("ThreatProfile", "ToolPack"):
                page = window.entity_pages[entity_type]
                page.add_button.click()
                page.edit_button.click()
                page.remove_button.click()

        self.assertEqual(
            calls,
            [
                "ThreatProfile:new",
                "ThreatProfile:edit",
                "ThreatProfile:delete",
                "ToolPack:new",
                "ToolPack:edit",
                "ToolPack:delete",
            ],
        )
    def test_tool_editor_receives_available_sigma_families_from_parent_page(self) -> None:
        from hunter.qt.main_window import EntityEditorDialog, HunterMainWindow

        qt_app()
        store, root, _tempdir = self._build_store()
        seed_sigma_rule(
            store,
            external_id="77777777-7777-7777-7777-777777777777",
            title="Azure Sigma Rule",
            technique_ids=["T1001"],
            logsource={"product": "azure", "service": "signinlogs"},
        )
        sync_service = SyncService(store)
        layered_service = LayeredEntityService(store, sync_service, root)
        window = HunterMainWindow(
            store=store,
            sync_service=sync_service,
            hunt_generator=HuntGenerator(store),
            sigma_rule_service=SigmaRuleService(store),
            authoring_service=AuthoringService(store, layered_service),
            project_dir=str(root),
        )
        self.addCleanup(window.close)
        tool = store.get_entity_by_external_id("ToolPack", "aws_hunting")
        dialog = EntityEditorDialog("ToolPack", tool, window.entity_pages["ToolPack"])
        self.addCleanup(dialog.close)

        dialog.structured_editor.autofill_sigma_families()
        payload = dialog.value()["payload"]

        self.assertIn("azure", payload["sigma_scope"]["default_families"])
        self.assertIn("windows", payload["sigma_scope"]["default_families"])


if __name__ == "__main__":
    unittest.main()
