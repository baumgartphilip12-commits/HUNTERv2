"""Regression tests for hunt-pack export sanitization."""

from __future__ import annotations

import unittest
from unittest import mock

from hunter.controllers.docx_runtime import DocxRuntimeHelper
from hunter.controllers.export_controller import ExportController


class ExportControllerTests(unittest.TestCase):
    def test_sanitize_hunt_pack_preserves_sigma_origin_metadata(self) -> None:
        hunt_pack = {
            "name": "Sigma Export Test",
            "summary": {
                "mission_name": "Sigma Export Test",
                "combined_selected_techniques": ["T1001"],
            },
            "payload": {
                "steps": [
                    {
                        "enabled": True,
                        "tool_pack": "Kibana",
                        "techniques": ["T1001"],
                        "title": "Translated Sigma Step",
                        "content_origin": "sigma_translated",
                        "sigma_rule_id": "88888888-8888-8888-8888-888888888888",
                        "sigma_title": "Suspicious PowerShell Download",
                        "translation_target": "elasticsearch",
                        "raw_rule_url": "https://example.test/sigma.yml",
                    }
                ]
            },
        }

        sanitized = ExportController._sanitize_hunt_pack(hunt_pack)
        step = sanitized["payload"]["steps"][0]

        self.assertEqual(step["content_origin"], "sigma_translated")
        self.assertEqual(step["sigma_rule_id"], "88888888-8888-8888-8888-888888888888")
        self.assertEqual(step["sigma_title"], "Suspicious PowerShell Download")
        self.assertEqual(step["translation_target"], "elasticsearch")
        self.assertEqual(step["raw_rule_url"], "https://example.test/sigma.yml")

    def test_export_hunt_pack_docx_uses_docx_runtime_helper(self) -> None:
        hunt_pack = {
            "name": "Sigma Export Test",
            "summary": {
                "mission_name": "Sigma Export Test",
                "combined_selected_techniques": ["T1001"],
            },
            "payload": {"steps": []},
        }

        with mock.patch.object(DocxRuntimeHelper, "export_word") as export_word:
            ExportController.export_hunt_pack_docx(
                parent_window=mock.sentinel.parent,
                hunt_pack=hunt_pack,
                script_dir="C:/repo",
            )

        export_word.assert_called_once()
        _, kwargs = export_word.call_args
        self.assertEqual(kwargs["initial_filename"], "sigma_export_test_report.docx")

    def test_export_hunt_pack_docx_adds_sanitized_threat_context(self) -> None:
        hunt_pack = {
            "name": "Threat Context Export",
            "summary": {"mission_name": "Threat Context Export"},
            "payload": {"audit": {"threat_ids": [42]}, "steps": []},
        }
        threat = {
            "id": 42,
            "type": "ThreatProfile",
            "external_id": "apt_test",
            "name": "APT Test",
            "short_description": "Short threat description.",
            "status": "active",
            "tags": ["apt", "test"],
            "payload": {
                "summary": "Threat summary for export.",
                "aliases": ["APT Unit"],
                "mitre_techniques": ["T1001", "T1041"],
                "indicators": [
                    {"type": "domain", "value": "evil.example"},
                    {"type": "ip", "value": "10.0.0.1"},
                ],
                "extra_hunts": ["Review outbound traffic."],
                "references": ["https://example.test/report"],
                "internal_notes": {"do_not_export": True},
            },
        }
        store = mock.Mock()
        store.get_entity.return_value = threat

        with mock.patch.object(DocxRuntimeHelper, "export_word") as export_word:
            ExportController.export_hunt_pack_docx(
                parent_window=mock.sentinel.parent,
                hunt_pack=hunt_pack,
                script_dir="C:/repo",
                store=store,
            )

        payload = export_word.call_args.kwargs["plan_dict"]
        context = payload["threat_context"][0]
        self.assertEqual(context["name"], "APT Test")
        self.assertEqual(context["external_id"], "apt_test")
        self.assertEqual(context["summary"], "Threat summary for export.")
        self.assertEqual(context["aliases"], ["APT Unit"])
        self.assertEqual(context["techniques"], ["T1001", "T1041"])
        self.assertEqual(context["indicator_count"], 2)
        self.assertIn({"type": "domain", "value": "evil.example"}, context["indicators"])
        self.assertNotIn("internal_notes", context)

    def test_export_hunt_pack_docx_falls_back_to_selected_threat_names(self) -> None:
        hunt_pack = {
            "name": "Fallback Export",
            "summary": {"mission_name": "Fallback Export", "selected_threats": ["APT Fallback"]},
            "payload": {"steps": []},
        }

        with mock.patch.object(DocxRuntimeHelper, "export_word") as export_word:
            ExportController.export_hunt_pack_docx(
                parent_window=mock.sentinel.parent,
                hunt_pack=hunt_pack,
                script_dir="C:/repo",
                store=mock.Mock(),
            )

        kwargs = export_word.call_args.kwargs
        self.assertEqual(
            kwargs["plan_dict"]["threat_context"],
            [{"name": "APT Fallback", "summary": "", "aliases": [], "techniques": [], "indicators": [], "indicator_count": 0, "extra_hunts": [], "references": [], "tags": []}],
        )


if __name__ == "__main__":
    unittest.main()
