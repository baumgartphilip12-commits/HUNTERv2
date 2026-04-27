"""Shared helpers for PySide6 HUNTER shell tests."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6 import QtCore, QtWidgets
from PySide6.QtWidgets import QApplication

from hunter.models.knowledge_store import KnowledgeStore
from hunter.services.authoring_service import AuthoringService
from hunter.services.hunt_service import HuntGenerator
from hunter.services.layered_entity_service import LayeredEntityService
from hunter.services.sigma_service import SigmaRuleService
from hunter.services.sync_service import SyncService
from tests.support import create_temp_project, make_store, seed_sigma_rule, seed_technique, seed_threat, seed_tool


def qt_app() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


class QtShellTestCase(unittest.TestCase):
    def _build_store(self) -> tuple[KnowledgeStore, Path, object]:
        tempdir = create_temp_project()
        self.addCleanup(tempdir.cleanup)
        root = Path(tempdir.name)
        store = make_store(root)
        self.addCleanup(store.close)
        seed_technique(store, external_id="T1001", name="Data Obfuscation")
        seed_technique(store, external_id="T1041", name="Exfiltration Over C2 Channel")
        seed_threat(store, technique_id="T1001")
        seed_sigma_rule(store, technique_ids=["T1001"])
        seed_tool(store, technique_ids=["T1001", "T1041"])
        return store, root, tempdir

    def _enable_default_tool_sigma_translation(self, store: KnowledgeStore) -> None:
        tool = store.get_entity_by_external_id("ToolPack", "aws_hunting")
        self.assertIsNotNone(tool)
        payload = dict(tool["payload"])
        payload["sigma_translation"] = {
            "enabled": True,
            "backend": "elasticsearch",
            "pipelines": [],
            "output_format": "lucene",
        }
        payload["sigma_scope"] = {"default_families": ["windows"]}
        store.upsert_entity(
            entity_type="ToolPack",
            external_id=tool["external_id"],
            name=tool["name"],
            short_description=tool["short_description"],
            status=tool["status"],
            confidence=tool["confidence"],
            priority=tool["priority"],
            source_name=tool["source_name"],
            source_ref=tool["source_ref"],
            source_url=tool["source_url"],
            retrieved_at=tool["retrieved_at"],
            last_seen=tool["last_seen"],
            valid_until=tool["valid_until"],
            tags=tool["tags"],
            payload=payload,
        )
