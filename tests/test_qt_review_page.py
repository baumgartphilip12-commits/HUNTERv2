from __future__ import annotations

from PySide6 import QtTest

from tests.qt_shell_support import *


class QtReviewPageTests(QtShellTestCase):
    def test_review_docx_export_without_active_pack_is_noop(self) -> None:
        from hunter.controllers.export_controller import ExportController
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
        window.review_page._active_pack_id = None

        with patch.object(ExportController, "export_hunt_pack_docx") as export_docx:
            window.review_page.export_docx()

        export_docx.assert_not_called()
    def test_review_page_exposes_and_dispatches_docx_export(self) -> None:
        from hunter.controllers.export_controller import ExportController
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
        for panel in (page.threats, page.tools):
            index = panel["proxy"].index(0, 0)
            panel["view"].selectionModel().select(
                index,
                QtCore.QItemSelectionModel.Select | QtCore.QItemSelectionModel.Rows,
            )
        page.build_preview()
        page.generate()
        QApplication.processEvents()

        with patch.object(ExportController, "export_hunt_pack_docx") as export_docx:
            window.review_page.export_docx_button.click()

        export_docx.assert_called_once()
        _, kwargs = export_docx.call_args
        self.assertIs(kwargs["parent_window"], window.review_page)
        self.assertEqual(kwargs["script_dir"], str(root))
        self.assertIs(kwargs["store"], store)
        self.assertEqual(kwargs["hunt_pack"]["id"], window.review_page._active_pack_id)

    def test_review_page_toggle_reenable_persists_to_store_and_summary(self) -> None:
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
        for panel in (page.threats, page.tools):
            index = panel["proxy"].index(0, 0)
            panel["view"].selectionModel().select(
                index,
                QtCore.QItemSelectionModel.Select | QtCore.QItemSelectionModel.Rows,
            )
        page.build_preview()
        page.generate()
        QApplication.processEvents()

        review = window.review_page
        model = review.plan_model
        step_index = next(
            model.index(row, 0)
            for row in range(model.rowCount())
            if model.index(row, 0).data(QtCore.Qt.CheckStateRole) == QtCore.Qt.Checked
            and not str(model.index(row, 1).data()).endswith("enabled")
        )
        review.plan_view.setCurrentIndex(step_index)
        QApplication.processEvents()

        QtTest.QTest.keyClick(review.plan_view, QtCore.Qt.Key_Space)
        QApplication.processEvents()
        disabled = store.get_hunt_pack(review._active_pack_id)
        self.assertFalse(disabled["payload"]["steps"][0].get("enabled", True))

        step_index = model.index_for_step_id(disabled["payload"]["steps"][0]["step_id"]).siblingAtColumn(0)
        review.plan_view.setCurrentIndex(step_index)
        QtTest.QTest.keyClick(review.plan_view, QtCore.Qt.Key_Space)
        QApplication.processEvents()
        enabled = store.get_hunt_pack(review._active_pack_id)
        self.assertTrue(enabled["payload"]["steps"][0].get("enabled", False))
        self.assertEqual(enabled["summary"]["enabled_steps"], enabled["summary"]["candidate_steps"])


if __name__ == "__main__":
    unittest.main()
