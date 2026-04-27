"""Tests for the shared hunt-pack summary service."""

from __future__ import annotations

import unittest
from pathlib import Path

from hunter.controllers.export_controller import ExportController
from hunter.services.hunt_pack_summary_service import HuntPackSummaryService
from hunter.services.hunt_service import HuntGenerator
from tests.support import create_temp_project, make_store, seed_technique, seed_threat, seed_tool


class HuntPackSummaryServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = create_temp_project()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.store = make_store(self.root)
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        seed_technique(self.store, external_id="T1041", name="Exfiltration Over C2 Channel")
        threat_id = seed_threat(self.store, technique_id="T1001")
        tool_id = seed_tool(self.store, technique_ids=["T1001", "T1041"])
        draft = HuntGenerator(self.store).generate(
            mission_name="Summary Service Test",
            threat_ids=[threat_id],
            tool_ids=[tool_id],
            manual_technique_ids=[],
        )
        self.hunt_pack = {
            "name": draft.name,
            "summary": draft.summary,
            "payload": draft.payload,
        }

    def test_service_matches_review_summary_rebuild(self) -> None:
        steps = self.hunt_pack["payload"]["steps"]
        steps[0]["enabled"] = False

        rebuilt = HuntPackSummaryService.summarize(self.hunt_pack["summary"], steps)
        summarized = HuntPackSummaryService.summarize(self.hunt_pack["summary"], steps)

        self.assertEqual(summarized, rebuilt)

    def test_export_sanitization_uses_same_summary_shape(self) -> None:
        hunt_pack = {
            "name": self.hunt_pack["name"],
            "summary": dict(self.hunt_pack["summary"]),
            "payload": {
                "steps": [dict(step) for step in self.hunt_pack["payload"]["steps"]],
            },
        }
        hunt_pack["payload"]["steps"][0]["enabled"] = False

        sanitized = ExportController._sanitize_hunt_pack(hunt_pack)
        expected = HuntPackSummaryService.summarize(
            hunt_pack["summary"],
            sanitized["payload"]["steps"],
        )

        self.assertEqual(sanitized["summary"], expected)
        self.assertEqual(sanitized["payload"]["summary"], expected)


if __name__ == "__main__":
    unittest.main()
