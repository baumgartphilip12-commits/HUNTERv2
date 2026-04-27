from __future__ import annotations

from tests.qt_shell_support import *


class QtSettingsDialogTests(QtShellTestCase):
    def test_default_sources_are_not_removed_from_settings_dialog(self) -> None:
        from hunter.qt.main_window import SettingsSyncDialog

        qt_app()
        store, root, _tempdir = self._build_store()
        dialog = SettingsSyncDialog(store=store, sync_service=SyncService(store), project_dir=str(root))
        self.addCleanup(dialog.close)
        default_source = store.get_source_by_name("MITRE ATT&CK Enterprise")
        row = dialog.model.row_for_id(default_source["id"])
        dialog.source_list.setCurrentIndex(dialog.model.index(row, 0))

        with patch.object(QtWidgets.QMessageBox, "question") as question:
            dialog.remove_source()

        question.assert_not_called()
        self.assertIsNotNone(store.get_source_by_name("MITRE ATT&CK Enterprise"))

    def test_qt_shell_settings_dialog_opens(self) -> None:
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

        dialog = window.open_settings()
        self.addCleanup(dialog.close)
        QApplication.processEvents()

        self.assertTrue(dialog.isVisible())
        self.assertGreater(dialog.model.rowCount(), 0)
    def test_settings_sync_action_result_remains_visible_after_refresh(self) -> None:
        from hunter.qt.main_window import SettingsSyncDialog

        qt_app()
        store, root, _tempdir = self._build_store()
        sync_service = SyncService(store)
        dialog = SettingsSyncDialog(store=store, sync_service=sync_service, project_dir=str(root))
        self.addCleanup(dialog.close)
        source = dialog.selected_source()
        self.assertIsNotNone(source)

        with patch.object(
            sync_service,
            "preview_source",
            return_value=SimpleNamespace(summary={"entity_count": 7}, diff={"new_entities": [("SigmaRule", "x")]}),
        ):
            dialog.run_sync_action("preview")

        self.assertEqual(dialog.selected_source()["id"], source["id"])
        detail = dialog.detail.toPlainText()
        self.assertIn("entity_count", detail)
        self.assertIn("new_entities", detail)
    def test_settings_sync_dialog_add_edit_remove_sigma_source_actions(self) -> None:
        from hunter.qt import main_window
        from hunter.qt.main_window import SettingsSyncDialog

        qt_app()
        store, root, _tempdir = self._build_store()
        sync_service = SyncService(store)
        dialog = SettingsSyncDialog(store=store, sync_service=sync_service, project_dir=str(root))
        self.addCleanup(dialog.close)

        self.assertEqual(dialog.apply_button.text(), "Sync")
        self.assertEqual(dialog.add_sigma_button.text(), "Add Sigma Source")
        self.assertEqual(dialog.edit_source_button.text(), "Edit Source")
        self.assertEqual(dialog.remove_source_button.text(), "Remove Source")

        class FakeAddDialog:
            def __init__(self, *, project_dir, source=None, parent=None) -> None:
                self.project_dir = project_dir
                self.source = source

            def exec(self) -> int:
                return QtWidgets.QDialog.Accepted

            def value(self) -> dict:
                return {
                    "name": "Local Sigma Lab",
                    "connector": "sigmahq_rules",
                    "config": {"rules_dir": "modules/SIGMA/lab"},
                    "enabled": True,
                    "approved": True,
                }

        with patch.object(main_window, "SigmaSourceDialog", FakeAddDialog):
            dialog.add_sigma_source()
        source = store.get_source_by_name("Local Sigma Lab")
        self.assertIsNotNone(source)
        self.assertEqual(source["config"]["rules_dir"], "modules/SIGMA/lab")

        class FakeEditDialog(FakeAddDialog):
            def value(self) -> dict:
                return {
                    "name": "Local Sigma Lab Edited",
                    "connector": "sigmahq_rules",
                    "config": {"rules_file": "modules/SIGMA/lab/rule.yml"},
                    "enabled": False,
                    "approved": False,
                }

        dialog.refresh()
        row = dialog.model.row_for_id(source["id"])
        dialog.source_list.setCurrentIndex(dialog.model.index(row, 0))
        with patch.object(main_window, "SigmaSourceDialog", FakeEditDialog):
            dialog.edit_source()
        edited = store.get_source_by_name("Local Sigma Lab Edited")
        self.assertIsNotNone(edited)
        self.assertEqual(edited["config"]["rules_file"], "modules/SIGMA/lab/rule.yml")
        self.assertFalse(edited["enabled"])
        self.assertFalse(edited["approved"])

        dialog.refresh()
        row = dialog.model.row_for_id(edited["id"])
        dialog.source_list.setCurrentIndex(dialog.model.index(row, 0))
        with patch.object(QtWidgets.QMessageBox, "question", return_value=QtWidgets.QMessageBox.Yes):
            dialog.remove_source()
        self.assertIsNone(store.get_source_by_name("Local Sigma Lab Edited"))

    def test_settings_dialog_marks_offline_mode_and_import_export_bundle_actions(self) -> None:
        from hunter.qt.main_window import SettingsSyncDialog

        qt_app()
        store, root, _tempdir = self._build_store()
        sync_service = SyncService(store)
        with patch.dict("os.environ", {"HUNTER_OFFLINE": "1"}):
            dialog = SettingsSyncDialog(store=store, sync_service=sync_service, project_dir=str(root))
        self.addCleanup(dialog.close)

        self.assertIn("Offline", dialog.mode_label.text())
        self.assertEqual(dialog.import_bundle_button.text(), "Import Offline Bundle")
        self.assertEqual(dialog.export_bundle_button.text(), "Export Offline Bundle")

        export_path = str(root / "data" / "exports" / "portable.json")
        with (
            patch.object(QtWidgets.QFileDialog, "getSaveFileName", return_value=(export_path, "JSON Files (*.json)")),
            patch.object(sync_service, "export_offline_bundle", return_value={"entities": 3}) as export_mock,
        ):
            dialog.export_offline_bundle()
        export_mock.assert_called_once_with(export_path)
        self.assertIn("entities", dialog.detail.toPlainText())

        import_path = str(root / "data" / "imports" / "portable.json")
        with (
            patch.object(QtWidgets.QFileDialog, "getOpenFileName", return_value=(import_path, "JSON Files (*.json)")),
            patch.object(sync_service, "import_offline_bundle", return_value={"imported_entities": 3}) as import_mock,
        ):
            dialog.import_offline_bundle()
        import_mock.assert_called_once_with(import_path)
        self.assertIn("imported_entities", dialog.detail.toPlainText())

    def test_sigma_source_dialog_builds_url_and_local_configs(self) -> None:
        from hunter.qt.main_window import SigmaSourceDialog

        qt_app()
        tempdir = create_temp_project()
        self.addCleanup(tempdir.cleanup)
        root = Path(tempdir.name)
        dialog = SigmaSourceDialog(project_dir=str(root))
        self.addCleanup(dialog.close)

        dialog.name_edit.setText("Sigma Fork")
        dialog.kind_combo.setCurrentText("Remote ZIP URL")
        dialog.location_edit.setText("https://example.test/sigma.zip")
        value = dialog.value()
        self.assertEqual(value["name"], "Sigma Fork")
        self.assertEqual(value["connector"], "sigmahq_rules")
        self.assertEqual(value["config"]["archive_url"], "https://example.test/sigma.zip")
        self.assertTrue(value["enabled"])
        self.assertTrue(value["approved"])

        local_file = root / "modules" / "SIGMA" / "local.yml"
        local_file.parent.mkdir(parents=True, exist_ok=True)
        local_file.write_text("title: Local", encoding="utf-8")
        dialog.kind_combo.setCurrentText("Local YAML File")
        dialog.location_edit.setText(str(local_file))
        value = dialog.value()
        self.assertEqual(value["config"]["rules_file"], "modules/SIGMA/local.yml")
    def test_sigma_source_dialog_keeps_invalid_form_open(self) -> None:
        from hunter.qt.main_window import SigmaSourceDialog

        qt_app()
        tempdir = create_temp_project()
        self.addCleanup(tempdir.cleanup)
        dialog = SigmaSourceDialog(project_dir=tempdir.name)
        self.addCleanup(dialog.close)
        dialog.name_edit.clear()
        dialog.location_edit.clear()

        with patch.object(QtWidgets.QMessageBox, "warning") as warning:
            dialog.accept()

        warning.assert_called_once()
        self.assertNotEqual(dialog.result(), QtWidgets.QDialog.Accepted)


if __name__ == "__main__":
    unittest.main()
