"""Tests for JSON feed dataset normalization helpers."""

from __future__ import annotations

import unittest
from pathlib import Path

from hunter.services.connectors.json_feed_builder import JsonFeedDatasetBuilder
from hunter.services.connectors.json_feed_normalizers import (
    normalize_addon_pack,
    normalize_indicator_set,
    normalize_placeholder_techniques,
    normalize_threat_profile,
    normalize_tool_pack,
)
from tests.support import create_temp_project, make_store, seed_technique


class JsonFeedDatasetBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = create_temp_project()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.store = make_store(self.root)
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")

    def test_builder_normalizes_entities_relationships_and_placeholders(self) -> None:
        builder = JsonFeedDatasetBuilder(self.store, create_mitre_placeholders=True)
        source = {"name": "Curated Feed"}
        payload = {
            "threat_profiles": [
                {
                    "name": "APT Example",
                    "external_id": "apt_example",
                    "summary": "Example threat.",
                    "techniques": ["T1001", "T9999"],
                }
            ],
            "tool_packs": [
                {
                    "name": "Tool Example",
                    "external_id": "tool_example",
                    "summary": "Example tool.",
                    "platform": "Elastic",
                    "hunt_methods": [
                        {
                            "title": "Suspicious query",
                            "techniques": ["T1001"],
                            "template": "process.name:cmd.exe",
                        }
                    ],
                }
            ],
            "addon_packs": [
                {
                    "name": "Addon Example",
                    "external_id": "addon_example",
                    "target_tool_ids": ["tool_example"],
                    "target_threat_ids": ["apt_example"],
                }
            ],
        }

        dataset = builder.build_dataset(source, payload, connector_name="json_feed")

        entities = {(item["type"], item["external_id"]) for item in dataset["entities"]}
        relationships = {
            (item["src_type"], item["src_external_id"], item["rel_type"], item["dst_type"], item["dst_external_id"])
            for item in dataset["relationships"]
        }

        self.assertIn(("ThreatProfile", "apt_example"), entities)
        self.assertIn(("ToolPack", "tool_example"), entities)
        self.assertIn(("AddonPack", "addon_example"), entities)
        self.assertIn(("MitreTechnique", "T9999"), entities)
        self.assertIn(("ThreatProfile", "apt_example", "USES", "MitreTechnique", "T1001"), relationships)
        self.assertIn(("ThreatProfile", "apt_example", "USES", "MitreTechnique", "T9999"), relationships)
        self.assertIn(("ToolPack", "tool_example", "COVERS", "MitreTechnique", "T1001"), relationships)
        self.assertIn(("AddonPack", "addon_example", "EXTENDS", "ToolPack", "tool_example"), relationships)
        self.assertIn(("AddonPack", "addon_example", "EXTENDS", "ThreatProfile", "apt_example"), relationships)

    def test_builder_passthrough_dataset_keeps_existing_entities_and_relationships(self) -> None:
        builder = JsonFeedDatasetBuilder(self.store, create_mitre_placeholders=True)
        source = {"name": "Curated Feed"}
        payload = {
            "entities": [
                {
                    "type": "ThreatProfile",
                    "external_id": "existing_threat",
                    "name": "Existing Threat",
                }
            ],
            "relationships": [
                {
                    "src_type": "ThreatProfile",
                    "src_external_id": "existing_threat",
                    "dst_type": "MitreTechnique",
                    "dst_external_id": "T1001",
                    "rel_type": "USES",
                }
            ],
        }

        dataset = builder.build_dataset(source, payload, connector_name="json_feed")

        self.assertEqual(dataset["entities"], payload["entities"])
        self.assertEqual(dataset["relationships"], payload["relationships"])
        self.assertEqual(dataset["source_name"], "Curated Feed")
        self.assertEqual(dataset["connector"], "json_feed")

    def test_threat_normalizer_returns_entity_and_owned_relationships(self) -> None:
        source = {"name": "Curated Feed"}
        threat = {
            "name": "APT Example",
            "external_id": "apt_example",
            "summary": "Example threat.",
            "techniques": ["T1001", "T9999"],
            "indicator_set_ids": ["indicator_example"],
            "source_ref": "threats/apt_example.json",
            "confidence": 0.8,
        }

        entities, relationships = normalize_threat_profile(source, threat)

        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0]["type"], "ThreatProfile")
        self.assertEqual(entities[0]["external_id"], "apt_example")
        self.assertEqual(entities[0]["payload"]["mitre_techniques"], ["T1001", "T9999"])
        rel_keys = {
            (item["rel_type"], item["dst_type"], item["dst_external_id"])
            for item in relationships
        }
        self.assertEqual(
            rel_keys,
            {
                ("USES", "MitreTechnique", "T1001"),
                ("USES", "MitreTechnique", "T9999"),
                ("USES_INDICATOR_SET", "IndicatorSet", "indicator_example"),
            },
        )

    def test_indicator_normalizer_preserves_indicator_payload(self) -> None:
        source = {"name": "Curated Feed"}
        indicator_set = {
            "name": "Indicator Example",
            "external_id": "indicator_example",
            "summary": "Example indicators.",
            "indicators": [{"type": "domain", "value": "evil.example"}],
            "lifecycle": {"phase": "active"},
        }

        entities, relationships = normalize_indicator_set(source, indicator_set)

        self.assertEqual(relationships, [])
        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0]["type"], "IndicatorSet")
        self.assertEqual(entities[0]["payload"]["indicators"], indicator_set["indicators"])
        self.assertEqual(entities[0]["payload"]["lifecycle"], {"phase": "active"})

    def test_tool_normalizer_preserves_sigma_fields_and_covers_all_method_techniques(self) -> None:
        source = {"name": "Curated Feed"}
        tool = {
            "name": "Tool Example",
            "external_id": "tool_example",
            "summary": "Example tool.",
            "platform": "Elastic",
            "techniques": ["T1001"],
            "sigma_translation": {"enabled": True, "backend": "elasticsearch"},
            "sigma_scope": {"default_families": ["windows"]},
            "hunt_methods": [
                {
                    "title": "Suspicious query",
                    "techniques": ["T1041"],
                    "template": "process.name:cmd.exe",
                }
            ],
        }

        entities, relationships = normalize_tool_pack(source, tool)

        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0]["type"], "ToolPack")
        self.assertEqual(entities[0]["payload"]["sigma_translation"], tool["sigma_translation"])
        self.assertEqual(entities[0]["payload"]["sigma_scope"], tool["sigma_scope"])
        rel_keys = {(item["rel_type"], item["dst_external_id"]) for item in relationships}
        self.assertEqual(rel_keys, {("COVERS", "T1001"), ("COVERS", "T1041")})

    def test_addon_normalizer_returns_extends_relationships(self) -> None:
        source = {"name": "Curated Feed"}
        addon = {
            "name": "Addon Example",
            "external_id": "addon_example",
            "target_tool_ids": ["tool_example"],
            "target_threat_ids": ["apt_example"],
        }

        entities, relationships = normalize_addon_pack(source, addon)

        self.assertEqual(len(entities), 1)
        self.assertEqual(entities[0]["type"], "AddonPack")
        rel_keys = {
            (item["rel_type"], item["dst_type"], item["dst_external_id"])
            for item in relationships
        }
        self.assertEqual(
            rel_keys,
            {
                ("EXTENDS", "ToolPack", "tool_example"),
                ("EXTENDS", "ThreatProfile", "apt_example"),
            },
        )

    def test_placeholder_normalizer_creates_only_missing_placeholder_techniques(self) -> None:
        source = {"name": "Curated Feed"}
        relationships = [
            {"dst_type": "MitreTechnique", "dst_external_id": "T1001"},
            {"dst_type": "MitreTechnique", "dst_external_id": "T9999"},
        ]

        entities = normalize_placeholder_techniques(
            source,
            existing_entities=[],
            relationships=relationships,
            store=self.store,
            create_mitre_placeholders=True,
        )

        self.assertEqual([(item["type"], item["external_id"]) for item in entities], [("MitreTechnique", "T9999")])
        self.assertEqual(entities[0]["status"], "placeholder")
        self.assertIn("placeholder", entities[0]["tags"])

    def test_placeholder_normalizer_can_be_disabled(self) -> None:
        source = {"name": "Curated Feed"}
        relationships = [{"dst_type": "MitreTechnique", "dst_external_id": "T9999"}]

        entities = normalize_placeholder_techniques(
            source,
            existing_entities=[],
            relationships=relationships,
            store=self.store,
            create_mitre_placeholders=False,
        )

        self.assertEqual(entities, [])


if __name__ == "__main__":
    unittest.main()
