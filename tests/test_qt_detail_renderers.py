"""Readable Qt entity detail renderer regressions."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hunter.models.knowledge_store import KnowledgeStore
from hunter.services.sigma_service import SigmaRuleService
from tests.support import seed_sigma_rule, seed_technique, seed_threat, seed_tool


class QtEntityDetailRendererTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.store = KnowledgeStore.open_bootstrapped(str(Path(self.tempdir.name)))
        self.addCleanup(self.store.close)
        self.sigma_rule_service = SigmaRuleService(self.store)

    def render_entity(self, entity_type: str, external_id: str) -> str:
        from hunter.qt.detail_renderers import EntityDetailRenderer

        entity = self.store.get_entity_by_external_id(entity_type, external_id)
        assert entity is not None
        return EntityDetailRenderer.render(entity, self.store, self.sigma_rule_service)

    def test_mitre_detail_includes_readable_attack_metadata(self) -> None:
        seed_technique(
            self.store,
            external_id="T1001",
            name="Data Obfuscation",
            description="Adversaries may obfuscate command and control traffic.",
        )

        html = self.render_entity("MitreTechnique", "T1001")

        self.assertIn("ATT&amp;CK Metadata", html)
        self.assertIn("Technique Description", html)
        self.assertIn("Detection Notes", html)
        self.assertIn("Execution", html)
        self.assertIn("Windows", html)
        self.assertIn("Process monitoring", html)

    def test_threat_detail_includes_iocs_techniques_and_sigma_overlap(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        seed_threat(self.store, technique_id="T1001")
        seed_sigma_rule(self.store, technique_ids=["T1001"], title="Suspicious PowerShell Download")

        html = self.render_entity("ThreatProfile", "apt_test")

        self.assertIn("Aliases", html)
        self.assertIn("APT Unit", html)
        self.assertIn("Mapped ATT&amp;CK Techniques", html)
        self.assertIn("T1001 - Data Obfuscation", html)
        self.assertIn("Threat Indicators", html)
        self.assertIn("domain: evil.example", html)
        self.assertIn("Sigma Coverage", html)
        self.assertIn("Suspicious PowerShell Download", html)

    def test_tool_detail_includes_surface_methods_and_sigma_summary(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        seed_sigma_rule(self.store, technique_ids=["T1001"], title="Suspicious PowerShell Download")
        seed_tool(
            self.store,
            external_id="aws_hunting",
            technique_ids=["T1001"],
            sigma_translation={
                "enabled": True,
                "backend": "elasticsearch",
                "pipelines": [],
                "output_format": "lucene",
            },
            sigma_scope={"default_families": ["windows"]},
        )

        html = self.render_entity("ToolPack", "aws_hunting")

        self.assertIn("Execution Surface", html)
        self.assertIn("CloudWatch Logs Insights", html)
        self.assertIn("Tool-Level Defaults", html)
        self.assertIn("AWS_LOG_SOURCE", html)
        self.assertIn("Sigma Translation", html)
        self.assertIn("Translation Enabled", html)
        self.assertIn("Hunt Methods", html)
        self.assertIn("Methods: 1", html)
        self.assertIn("T1001 Hunt", html)
        self.assertIn("primary hunt", html)
        self.assertIn("behavior hunt", html)

    def test_detail_styles_use_legible_text_and_table_backed_chips(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        seed_tool(self.store, technique_ids=["T1001"])

        html = self.render_entity("ToolPack", "aws_hunting")

        self.assertIn("font-size:11pt", html)
        self.assertIn("line-height:1.55", html)
        self.assertIn("class=\"chips\"", html)
        self.assertIn("cellspacing=\"6\"", html)
        self.assertIn("border:1px solid", html)
        self.assertNotIn("display:inline-block", html)

    def test_mitre_chips_are_chunked_and_wrap_instead_of_forcing_one_row(self) -> None:
        technique_ids = [f"T{index:04d}" for index in range(1, 10)]
        for technique_id in technique_ids:
            seed_technique(
                self.store,
                external_id=technique_id,
                name=f"Long Technique Name {technique_id}",
            )
        self.store.upsert_entity(
            entity_type="ThreatProfile",
            external_id="many_techniques",
            name="Many Techniques",
            payload={
                "summary": "Threat with many mapped techniques.",
                "mitre_techniques": technique_ids,
            },
        )

        html = self.render_entity("ThreatProfile", "many_techniques")

        self.assertNotIn("nowrap", html)
        self.assertIn("width=\"25%\"", html)
        self.assertGreaterEqual(html.count("<tr>"), 3)
        self.assertIn("</tr><tr>", html)

    def test_detail_html_escapes_content_and_caps_payload_preview(self) -> None:
        self.store.upsert_entity(
            entity_type="ThreatProfile",
            external_id="escape_test",
            name="<script>alert(1)</script>",
            short_description="Synthetic threat",
            payload={
                "summary": "<b>not html</b>",
                "aliases": ["<img src=x onerror=alert(1)>"],
                "mitre_techniques": [],
                "large": "x" * 20000,
            },
        )

        html = self.render_entity("ThreatProfile", "escape_test")

        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertIn("&lt;b&gt;not html&lt;/b&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("Structured Payload Preview", html)
        self.assertIn("truncated for UI preview", html)
        self.assertLess(len(html), 16000)


if __name__ == "__main__":
    unittest.main()
