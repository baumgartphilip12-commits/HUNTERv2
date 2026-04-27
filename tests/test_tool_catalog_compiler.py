"""Compatibility tests for legacy tool-method metadata normalization."""

from __future__ import annotations

import unittest

from hunter.services.tool_catalog_compiler import ToolCatalogCompiler


class ToolCatalogCompilerTests(unittest.TestCase):
    def test_supporting_pivot_metadata_is_backfilled_from_legacy_titles(self) -> None:
        legacy_method = {
            "title": "T1041 Exfiltration Over C2 Channel IOC Pivot",
            "techniques": ["T1041"],
            "template": "Search expression: ip.dst == <IP_IOC>",
            "supported_ioc_types": ["ip"],
            "required_placeholders": ["<IP_IOC>"],
            "output_format": "arkime_query",
            "execution_surface": "Arkime Session Search / Pivot Workflow",
            "surface_details": "Session metadata review.",
            "service_examples": ["Sessions"],
            "prerequisites": ["PCAP or session metadata available"],
            "noise_level": "medium",
            "privilege_required": "user",
            "time_cost": 2,
            "data_sources": ["Arkime session metadata"],
            "expectation": "Use known indicators to pivot into related sessions.",
        }

        normalized = ToolCatalogCompiler.ensure_method_metadata(legacy_method)

        self.assertEqual(normalized["method_strength"], "supporting_pivot")
        self.assertEqual(normalized["method_kind"], "ioc_pivot")
        self.assertTrue(normalized["strength_reason"])
        self.assertTrue(normalized["behavior_focus"])

    def test_primary_hunt_metadata_is_backfilled_from_behavior_titles(self) -> None:
        legacy_method = {
            "title": "T1011 Exfiltration Over Other Network Medium Session Search",
            "techniques": ["T1011"],
            "template": "# Arkime session search for T1011\nTechnique Context\n- Validate unusual outbound volume and destination reuse.",
            "supported_ioc_types": ["ip", "domain"],
            "required_placeholders": ["<ARKIME_SESSION_SCOPE>"],
            "output_format": "arkime_query",
            "execution_surface": "Arkime Session Search / Pivot Workflow",
            "surface_details": "Session metadata review.",
            "service_examples": ["Sessions"],
            "prerequisites": ["Session metadata available"],
            "noise_level": "medium",
            "privilege_required": "user",
            "time_cost": 2,
            "data_sources": ["Arkime session metadata"],
            "expectation": "Validate suspicious outbound session behavior.",
        }

        normalized = ToolCatalogCompiler.ensure_method_metadata(legacy_method)

        self.assertEqual(normalized["method_strength"], "primary_hunt")
        self.assertEqual(normalized["method_kind"], "behavior_hunt")
        self.assertIn("Primary hunt", normalized["strength_reason"])
        self.assertTrue(normalized["behavior_focus"])


if __name__ == "__main__":
    unittest.main()
