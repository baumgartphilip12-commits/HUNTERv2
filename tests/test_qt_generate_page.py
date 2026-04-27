from __future__ import annotations

from tests.qt_shell_support import *


class QtGeneratePageTests(QtShellTestCase):
    def test_browse_tab_selection_updates_visuals_before_expensive_generate_refresh(self) -> None:
        from hunter.qt.main_window import HunterMainWindow
        from hunter.qt.models import GENERATE_SELECTED_ROLE

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
        page = window.entity_pages["ToolPack"]
        page.select_first()
        entity = page.selected_entity()
        self.assertIsNotNone(entity)
        index = page.list_view.currentIndex()
        events: list[str] = []

        original_refresh = window.generate_page.refresh
        original_sigma = window.generate_page.refresh_sigma_families
        original_sync = page.sync_generate_selection_state

        def tracked_refresh() -> None:
            events.append("refresh")
            original_refresh()

        def tracked_sync() -> None:
            original_sync()
            events.append(f"sync:{bool(index.data(GENERATE_SELECTED_ROLE))}")

        def tracked_sigma() -> None:
            events.append("sigma")
            original_sigma()

        window.generate_page.refresh = tracked_refresh
        window.generate_page.refresh_sigma_families = tracked_sigma
        page.sync_generate_selection_state = tracked_sync

        page.list_view.doubleClicked.emit(index)
        QApplication.processEvents()

        self.assertNotIn("refresh", events)
        self.assertLess(events.index("sync:True"), events.index("sigma"))
    def test_browse_tabs_double_click_toggle_generate_selection_for_all_entity_types(self) -> None:
        from hunter.qt.main_window import HunterMainWindow
        from hunter.qt.models import GENERATE_SELECTED_ROLE

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

        for entity_type in ("ThreatProfile", "ToolPack", "MitreTechnique"):
            page = window.entity_pages[entity_type]
            page.select_first()
            entity = page.selected_entity()
            self.assertIsNotNone(entity)
            entity_id = int(entity["id"])
            index = page.list_view.currentIndex()

            page.list_view.doubleClicked.emit(index)
            QApplication.processEvents()

            self.assertIn(entity_id, window.generate_page.selected_ids_for_type(entity_type))
            self.assertTrue(index.data(GENERATE_SELECTED_ROLE))
            self.assertIsNotNone(index.data(QtCore.Qt.BackgroundRole))

            page.list_view.doubleClicked.emit(index)
            QApplication.processEvents()

            self.assertNotIn(entity_id, window.generate_page.selected_ids_for_type(entity_type))
    def test_edit_tool_sigma_scope_uses_selector_dialog_and_saves_scope(self) -> None:
        from hunter.qt import main_window
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
        panel = window.generate_page.tools
        index = panel["proxy"].index(0, 0)
        panel["view"].selectionModel().select(
            index,
            QtCore.QItemSelectionModel.Select | QtCore.QItemSelectionModel.Rows,
        )
        tool = window.generate_page._selected_entities(panel)[0]

        class FakeSigmaScopeDialog:
            def __init__(self, *, available_families, current_families, parent=None) -> None:
                self.available_families = available_families
                self.current_families = current_families
                self.parent = parent

            def exec(self) -> int:
                return QtWidgets.QDialog.Accepted

            def families(self) -> list[str]:
                return ["windows", "custom-feed"]

        with (
            patch.object(main_window, "SigmaScopeEditorDialog", FakeSigmaScopeDialog),
            patch.object(window.authoring_service, "save_tool_sigma_scope") as save_scope,
        ):
            window.generate_page.edit_tool_sigma_scope()

        save_scope.assert_called_once_with(tool, ["windows", "custom-feed"])
    def test_empty_sigma_family_selection_survives_refresh(self) -> None:
        from hunter.qt.main_window import HunterMainWindow

        qt_app()
        store, root, _tempdir = self._build_store()
        tool = store.list_entities("ToolPack")[0]
        payload = dict(tool["payload"])
        payload["sigma_scope"] = {"default_families": ["windows"]}
        store.upsert_entity(
            entity_type="ToolPack",
            external_id=tool["external_id"],
            name=tool["name"],
            short_description=tool["short_description"],
            source_name=tool["source_name"],
            source_ref=tool["source_ref"],
            payload=payload,
            tags=tool["tags"],
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
        panel = window.generate_page.tools
        panel["view"].selectionModel().select(
            panel["proxy"].index(0, 0),
            QtCore.QItemSelectionModel.Select | QtCore.QItemSelectionModel.Rows,
        )
        QApplication.processEvents()
        self.assertIn("windows", window.generate_page._family_checks)

        window.generate_page._family_checks["windows"].setChecked(False)
        window.generate_page.refresh_sigma_families()

        self.assertFalse(window.generate_page._family_checks["windows"].isChecked())
    def test_generate_panels_use_same_selection_visual_roles(self) -> None:
        from hunter.qt.main_window import GenerateSelectedItemDelegate, HunterMainWindow
        from hunter.qt.models import GENERATE_SELECTED_ROLE

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

        for panel in (window.generate_page.threats, window.generate_page.tools, window.generate_page.mitre):
            index = panel["proxy"].index(0, 0)
            self.assertIsInstance(panel["view"].itemDelegate(), GenerateSelectedItemDelegate)

            panel["view"].selectionModel().select(
                index,
                QtCore.QItemSelectionModel.Select | QtCore.QItemSelectionModel.Rows,
            )
            QApplication.processEvents()

            self.assertTrue(index.data(GENERATE_SELECTED_ROLE))
            self.assertIsNotNone(index.data(QtCore.Qt.BackgroundRole))

            panel["view"].selectionModel().select(
                index,
                QtCore.QItemSelectionModel.Deselect | QtCore.QItemSelectionModel.Rows,
            )
            QApplication.processEvents()

            self.assertFalse(index.data(GENERATE_SELECTED_ROLE))
            self.assertIsNone(index.data(QtCore.Qt.BackgroundRole))
    def test_generate_rebuilds_preview_after_inputs_change(self) -> None:
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
        page = window.generate_page
        page.mission_name.setText("First Mission")
        page.build_preview()
        self.assertIsNotNone(page._last_draft)

        page.mission_name.setText("Second Mission")
        QApplication.processEvents()
        page.generate()
        QApplication.processEvents()

        packs = store.list_hunt_packs()
        self.assertEqual(packs[0]["name"], "Second Mission")
    def test_generate_selection_visual_state_survives_refresh(self) -> None:
        from hunter.qt.main_window import HunterMainWindow
        from hunter.qt.models import GENERATE_SELECTED_ROLE

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
        panel = window.generate_page.tools
        index = panel["proxy"].index(0, 0)
        entity_id = index.data(QtCore.Qt.UserRole + 1)
        panel["view"].selectionModel().select(
            index,
            QtCore.QItemSelectionModel.Select | QtCore.QItemSelectionModel.Rows,
        )

        window.generate_page.refresh()
        QApplication.processEvents()
        refreshed_row = panel["model"].row_for_id(entity_id)
        refreshed_index = panel["proxy"].mapFromSource(panel["model"].index(refreshed_row, 0))

        self.assertTrue(refreshed_index.data(GENERATE_SELECTED_ROLE))
        self.assertIsNotNone(refreshed_index.data(QtCore.Qt.BackgroundRole))
    def test_mitre_generate_selection_state_survives_refreshes(self) -> None:
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
        mitre_page = window.entity_pages["MitreTechnique"]
        mitre_page.select_first()
        entity = mitre_page.selected_entity()
        self.assertIsNotNone(entity)
        entity_id = int(entity["id"])

        window.send_entity_to_generate("MitreTechnique", entity)
        window.generate_page.refresh()
        mitre_page.refresh(preserve_id=entity_id)
        QApplication.processEvents()

        self.assertIn(entity_id, window.generate_page.selected_ids_for_type("MitreTechnique"))
        self.assertNotIn("Selected", mitre_page.list_view.currentIndex().data())
        self.assertIsNotNone(mitre_page.list_view.currentIndex().data(QtCore.Qt.BackgroundRole))
    def test_mitre_tab_double_click_preview_includes_manual_scope(self) -> None:
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
        mitre_page = window.entity_pages["MitreTechnique"]
        mitre_page.select_first()
        entity = mitre_page.selected_entity()
        self.assertIsNotNone(entity)
        entity_id = int(entity["id"])
        index = mitre_page.list_view.currentIndex()

        mitre_page.list_view.doubleClicked.emit(index)
        QApplication.processEvents()

        self.assertIn(entity_id, window.generate_page.selected_ids_for_type("MitreTechnique"))
        self.assertNotIn("Selected", mitre_page.list_view.currentIndex().data())
        self.assertIsNotNone(mitre_page.list_view.currentIndex().data(QtCore.Qt.BackgroundRole))

        window.generate_page.build_preview()
        QApplication.processEvents()
        self.assertIn(entity["external_id"], window.generate_page._last_draft.summary["selected_manual_mitre"])
    def test_mitre_tab_double_click_toggles_manual_generate_selection(self) -> None:
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
        mitre_page = window.entity_pages["MitreTechnique"]
        mitre_page.select_first()
        entity = mitre_page.selected_entity()
        self.assertIsNotNone(entity)
        entity_id = int(entity["id"])
        index = mitre_page.list_view.currentIndex()

        mitre_page.list_view.doubleClicked.emit(index)
        QApplication.processEvents()
        self.assertIn(entity_id, window.generate_page.selected_ids_for_type("MitreTechnique"))

        mitre_page.list_view.doubleClicked.emit(index)
        QApplication.processEvents()
        self.assertNotIn(entity_id, window.generate_page.selected_ids_for_type("MitreTechnique"))
    def test_preview_includes_browse_tab_threat_tool_and_mitre_selections(self) -> None:
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

        selected: dict[str, dict] = {}
        for entity_type in ("ThreatProfile", "ToolPack", "MitreTechnique"):
            page = window.entity_pages[entity_type]
            page.select_first()
            entity = page.selected_entity()
            self.assertIsNotNone(entity)
            selected[entity_type] = entity
            page.list_view.doubleClicked.emit(page.list_view.currentIndex())

        window.generate_page.build_preview()
        QApplication.processEvents()
        summary = window.generate_page._last_draft.summary

        self.assertIn(selected["ThreatProfile"]["name"], summary["selected_threats"])
        self.assertIn(selected["ToolPack"]["name"], summary["selected_tools"])
        self.assertIn(selected["MitreTechnique"]["external_id"], summary["selected_manual_mitre"])
    def test_qt_generate_preview_and_persist_flow(self) -> None:
        from hunter.qt.main_window import HunterMainWindow

        qt_app()
        store, root, _tempdir = self._build_store()
        self._enable_default_tool_sigma_translation(store)
        seed_sigma_rule(
            store,
            external_id="33333333-3333-3333-3333-333333333333",
            title="APT Unit Suspicious PowerShell Download",
            technique_ids=["T1001"],
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
        page = window.generate_page
        for panel in (page.threats, page.tools):
            self.assertGreater(panel["proxy"].rowCount(), 0)
            index = panel["proxy"].index(0, 0)
            panel["view"].selectionModel().select(
                index,
                QtCore.QItemSelectionModel.Select | QtCore.QItemSelectionModel.Rows,
            )

        page.build_preview()
        QApplication.processEvents()
        self.assertIsNotNone(page._last_draft)
        preview_text = page.preview.toPlainText()
        self.assertIn("Steps:", preview_text)
        self.assertIn("Sigma Rules:", preview_text)
        self.assertIn("APT Unit Suspicious PowerShell Download", preview_text)
        self.assertNotIn("Sigma IDs:", preview_text)
        self.assertNotIn("33333333-3333-3333-3333-333333333333", preview_text)

        page.generate()
        QApplication.processEvents()
        self.assertGreater(len(store.list_hunt_packs()), 0)
    def test_qt_generate_preview_falls_back_to_unresolved_sigma_id(self) -> None:
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
        page = window.generate_page
        draft = SimpleNamespace(
            payload={
                "steps": [],
                "audit": {"sigma_rule_ids": ["missing-sigma-rule"]},
            }
        )

        self.assertEqual(page._sigma_rule_preview_lines(draft), ["missing-sigma-rule"])
    def test_sigma_scope_editor_selects_known_and_custom_families(self) -> None:
        from hunter.qt.main_window import SigmaScopeEditorDialog

        qt_app()
        dialog = SigmaScopeEditorDialog(
            available_families={"windows": 12, "azure": 4},
            current_families=["windows", "custom-feed"],
        )
        self.addCleanup(dialog.close)

        self.assertEqual(dialog.known_list.count(), 2)
        self.assertEqual(dialog.known_list.item(0).data(QtCore.Qt.UserRole), "azure")
        self.assertEqual(dialog.known_list.item(1).data(QtCore.Qt.UserRole), "windows")
        self.assertEqual(dialog.known_list.item(1).checkState(), QtCore.Qt.Checked)
        self.assertEqual(dialog.custom_list.item(0).text(), "custom-feed")

        dialog.custom_input.setText(" Other Family ")
        dialog.add_custom_button.click()
        dialog.known_list.item(0).setCheckState(QtCore.Qt.Checked)

        self.assertEqual(dialog.families(), ["azure", "windows", "custom-feed", "other family"])


if __name__ == "__main__":
    unittest.main()
