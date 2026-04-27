"""Generation flow tests for threat, tool, and manual MITRE selection."""

from __future__ import annotations

import unittest
from pathlib import Path

from hunter.services.hunt_service import HuntGenerator
from tests.support import create_temp_project, make_store, seed_technique, seed_threat, seed_tool


class GenerateFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = create_temp_project()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.store = make_store(self.root)
        self.generator = HuntGenerator(self.store)

    def test_threat_and_tool_generation_produces_ranked_steps(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        threat_id = seed_threat(self.store, technique_id="T1001")
        tool_id = seed_tool(self.store, technique_ids=["T1001"])

        draft = self.generator.generate(
            mission_name="Threat Driven",
            threat_ids=[threat_id],
            tool_ids=[tool_id],
            manual_technique_ids=[],
        )

        self.assertEqual(draft.summary["selected_threats"], ["APT Test"])
        self.assertEqual(draft.summary["selected_tools"], ["AWS Hunting"])
        self.assertGreater(draft.summary["candidate_steps"], 0)
        self.assertEqual(draft.summary["missing_techniques"], [])

    def test_tool_plus_manual_mitre_generation_is_supported(self) -> None:
        manual_technique_id = seed_technique(
            self.store,
            external_id="T1041",
            name="Exfiltration Over C2 Channel",
        )
        tool_id = seed_tool(self.store, technique_ids=["T1041"])

        draft = self.generator.generate(
            mission_name="Manual ATT&CK Hunt",
            threat_ids=[],
            tool_ids=[tool_id],
            manual_technique_ids=[manual_technique_id],
        )

        self.assertEqual(draft.summary["selected_threats"], [])
        self.assertEqual(draft.summary["selected_manual_mitre"], ["T1041"])
        self.assertGreater(draft.summary["candidate_steps"], 0)

    def test_tool_only_without_scope_returns_no_steps(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        tool_id = seed_tool(self.store, technique_ids=["T1001"])

        draft = self.generator.generate(
            mission_name="No Scope",
            threat_ids=[],
            tool_ids=[tool_id],
            manual_technique_ids=[],
        )

        self.assertEqual(draft.summary["candidate_steps"], 0)
        self.assertEqual(draft.payload["steps"], [])


if __name__ == "__main__":
    unittest.main()
