"""Regression tests for the Node-backed DOCX report layout."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class DocxExportScriptTests(unittest.TestCase):
    def test_hunt_pack_docx_uses_compact_threat_scope_and_collapsed_details(self) -> None:
        if shutil.which("node") is None:
            self.skipTest("Node.js is not available")
        if not (PROJECT_ROOT / "node_modules" / "docx").exists():
            self.skipTest("node_modules/docx is not installed")

        payload = {
            "document_type": "hunt_pack_v2",
            "name": "DOCX Layout Test",
            "summary": {
                "mission_name": "DOCX Layout Test",
                "selected_threats": ["APT Test"],
                "selected_tools": ["Kibana"],
                "covered_techniques": ["T1001"],
                "missing_techniques": [],
            },
            "threat_context": [
                {
                    "name": "APT Test",
                    "external_id": "apt_test",
                    "summary": "Short threat summary.",
                    "aliases": ["APT Unit"],
                    "techniques": ["T1001", "T1041"],
                    "indicator_count": 2,
                    "indicators": [
                        {"type": "domain", "value": "evil.example"},
                        {"type": "ip", "value": "10.0.0.1"},
                    ],
                    "extra_hunts": ["Review outbound traffic."],
                    "references": ["https://example.test/report"],
                    "tags": ["apt", "test"],
                }
            ],
            "payload": {
                "steps": [
                    {
                        "enabled": True,
                        "title": "T1001 Hunt",
                        "tool_pack": "Kibana",
                        "techniques": ["T1001"],
                        "rendered_query": "event.dataset:process",
                    }
                ]
            },
        }

        with tempfile.TemporaryDirectory() as tempdir:
            temp = Path(tempdir)
            json_path = temp / "hunt_pack.json"
            out_path = temp / "hunt_pack.docx"
            json_path.write_text(json.dumps(payload), encoding="utf-8")

            result = subprocess.run(
                ["node", str(PROJECT_ROOT / "export_docx.js"), str(json_path), str(out_path)],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr or result.stdout)
            with zipfile.ZipFile(out_path) as archive:
                document_xml = archive.read("word/document.xml").decode("utf-8")

        self.assertIn("Threat Scope", document_xml)
        self.assertIn("Short threat summary.", document_xml)
        self.assertIn("Additional Details: APT Test", document_xml)
        self.assertIn("evil.example", document_xml)
        self.assertIn("Review outbound traffic.", document_xml)
        self.assertIn("T1001 Hunt", document_xml)
        self.assertIn("<w:collapsed/>", document_xml)


if __name__ == "__main__":
    unittest.main()
