"""Tests for review-step plan persistence and hunt-pack deletion."""

from __future__ import annotations

import unittest
from pathlib import Path

from hunter.services.hunt_pack_summary_service import HuntPackSummaryService
from hunter.services.hunt_service import HuntGenerator
from tests.support import create_temp_project, make_store, seed_technique, seed_threat, seed_tool


class ReviewPlanUpdateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = create_temp_project()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.store = make_store(self.root)
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        seed_technique(self.store, external_id="T1041", name="Exfiltration Over C2 Channel")
        self.threat_id = seed_threat(self.store, technique_id="T1001")
        self.tool_id = seed_tool(self.store, technique_ids=["T1001", "T1041"])
        generator = HuntGenerator(self.store)
        draft = generator.generate(
            mission_name="Review Test",
            threat_ids=[self.threat_id],
            tool_ids=[self.tool_id],
            manual_technique_ids=[],
        )
        self.hunt_pack_id = generator.persist(draft)

    def test_summary_rebuild_tracks_enabled_steps_and_gaps(self) -> None:
        hunt_pack = self.store.get_hunt_pack(self.hunt_pack_id)
        self.assertIsNotNone(hunt_pack)
        steps = hunt_pack["payload"]["steps"]
        self.assertGreaterEqual(len(steps), 1)

        steps[0]["enabled"] = False
        summary = HuntPackSummaryService.summarize(hunt_pack["summary"], steps)

        self.assertEqual(summary["candidate_steps"], len(steps))
        self.assertEqual(summary["enabled_steps"], len([step for step in steps if step.get("enabled", True)]))
        self.assertIn("missing_techniques", summary)

    def test_store_update_hunt_pack_persists_disabled_step(self) -> None:
        hunt_pack = self.store.get_hunt_pack(self.hunt_pack_id)
        self.assertIsNotNone(hunt_pack)
        payload = hunt_pack["payload"]
        steps = payload["steps"]
        steps[0]["enabled"] = False

        summary = HuntPackSummaryService.summarize(hunt_pack["summary"], steps)
        payload["steps"] = steps
        payload["summary"] = summary
        self.store.update_hunt_pack(self.hunt_pack_id, summary=summary, payload=payload)

        refreshed = self.store.get_hunt_pack(self.hunt_pack_id)
        self.assertFalse(refreshed["payload"]["steps"][0]["enabled"])
        self.assertEqual(refreshed["summary"]["enabled_steps"], summary["enabled_steps"])

    def test_store_delete_hunt_pack_removes_pack(self) -> None:
        deleted = self.store.delete_hunt_pack(self.hunt_pack_id)
        self.assertTrue(deleted)
        self.assertIsNone(self.store.get_hunt_pack(self.hunt_pack_id))
        self.assertFalse(self.store.delete_hunt_pack(self.hunt_pack_id))


if __name__ == "__main__":
    unittest.main()
