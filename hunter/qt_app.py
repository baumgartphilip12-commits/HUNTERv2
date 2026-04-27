"""Qt application entrypoint for HUNTER."""

from __future__ import annotations

import sys

from PySide6 import QtWidgets

from hunter.models.knowledge_store import KnowledgeStore
from hunter.qt.main_window import HunterMainWindow
from hunter.runtime_paths import project_root
from hunter.services.authoring_service import AuthoringService
from hunter.services.hunt_service import HuntGenerator
from hunter.services.layered_entity_service import LayeredEntityService
from hunter.services.sigma_service import SigmaRuleService
from hunter.services.sync_service import SyncService


def build_main_window(project_dir: str | None = None) -> HunterMainWindow:
    """Construct the Qt shell with the existing backend services."""

    root = project_root(project_dir)
    store = KnowledgeStore.open_bootstrapped(str(root))
    sync_service = SyncService(store)
    layered_entity_service = LayeredEntityService(store, sync_service, root)
    return HunterMainWindow(
        store=store,
        sync_service=sync_service,
        hunt_generator=HuntGenerator(store),
        sigma_rule_service=SigmaRuleService(store),
        authoring_service=AuthoringService(store, layered_entity_service),
        project_dir=str(root),
    )


def run(project_dir: str | None = None) -> int:
    """Run the Qt desktop application."""

    app = QtWidgets.QApplication.instance()
    owns_app = app is None
    if app is None:
        app = QtWidgets.QApplication(sys.argv)
    window = build_main_window(project_dir)
    window.show()
    if owns_app:
        return int(app.exec())
    return 0
