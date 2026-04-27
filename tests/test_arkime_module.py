"""Content regression checks for the hand-authored Arkime tool module."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ARKIME_MODULE = PROJECT_ROOT / "modules" / "tools" / "arkime.json"


class ArkimeModuleTests(unittest.TestCase):
    def test_arkime_module_uses_authored_primary_and_supporting_methods(self) -> None:
        payload = json.loads(ARKIME_MODULE.read_text(encoding="utf-8"))
        methods = payload["hunt_methods"]

        self.assertEqual(payload["external_id"], "arkime")
        self.assertGreaterEqual(len(methods), 20)
        self.assertTrue(any(method["method_strength"] == "primary_hunt" for method in methods))
        self.assertTrue(any(method["method_strength"] == "supporting_pivot" for method in methods))

    def test_t1011_primary_hunt_is_behavior_led_not_keyword_led(self) -> None:
        payload = json.loads(ARKIME_MODULE.read_text(encoding="utf-8"))
        method = next(
            item
            for item in payload["hunt_methods"]
            if item["title"] == "T1011 Alternate-Medium Egress Hunt"
        )

        search_line = next(
            line for line in method["template"].splitlines() if line.startswith("Search expression:")
        ).lower()
        self.assertNotIn("upload", search_line)
        self.assertNotIn("download", search_line)
        self.assertNotIn("exfil", search_line)
        self.assertIn("bytes >=", search_line)
        self.assertIn("protocols !=", search_line)


if __name__ == "__main__":
    unittest.main()
