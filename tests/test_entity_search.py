"""Visible entity-browser search grammar tests."""

from __future__ import annotations

import unittest

from tests.support import create_temp_project, make_store, seed_technique, seed_tool


class EntitySearchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_project = create_temp_project()
        self.addCleanup(self.temp_project.cleanup)
        self.store = make_store(self.temp_project.name)
        seed_technique(
            self.store,
            external_id="T1001",
            name="Data Obfuscation",
            description="Adversaries may use encoded command lines.",
        )
        seed_technique(
            self.store,
            external_id="T1041",
            name="Exfiltration Over C2 Channel",
            description="Adversaries may steal data over command and control channels.",
        )
        self.store.upsert_entity(
            entity_type="ThreatProfile",
            external_id="apt_search",
            name="APT Search",
            short_description="Threat known for outbound pivots.",
            payload={
                "summary": "Threat known for outbound pivots.",
                "aliases": ["Search Unit"],
                "mitre_techniques": ["T1041"],
                "indicators": [{"type": "domain", "value": "evil.example"}],
                "extra_hunts": ["Review outbound traffic."],
            },
        )
        seed_tool(
            self.store,
            external_id="elastic_search_tool",
            name="Elastic Search Tool",
            technique_ids=["T1041"],
        )
        self.store.upsert_entity(
            entity_type="ToolPack",
            external_id="elastic_active_tool",
            name="Elastic Active Tool",
            short_description="Active Elastic tool variant.",
            payload={
                "summary": "Active Elastic tool variant.",
                "platform": "Elastic",
                "hunt_methods": [
                    {
                        "title": "Domain IOC pivot",
                        "techniques": ["T1041"],
                        "template": "dns.question.name: <DOMAIN_IOC>",
                        "supported_ioc_types": ["domain"],
                        "execution_surface": "Kibana",
                    }
                ],
            },
        )
        self.store.upsert_entity(
            entity_type="ToolPack",
            external_id="deprecated_tool",
            name="Deprecated Tool",
            short_description="Old tool variant.",
            status="deprecated",
            payload={
                "summary": "Old tool variant.",
                "platform": "Elastic",
                "hunt_methods": [
                    {
                        "title": "Domain IOC pivot",
                        "techniques": ["T1041"],
                        "template": "dns.question.name: <DOMAIN_IOC>",
                        "supported_ioc_types": ["domain"],
                        "execution_surface": "Kibana",
                    }
                ],
            },
        )

    def test_mitre_search_supports_id_and_quoted_technique_names(self) -> None:
        self.assertEqual(
            [item["external_id"] for item in self.store.list_entities("MitreTechnique", search="id:T1001")],
            ["T1001"],
        )
        self.assertEqual(
            [
                item["external_id"]
                for item in self.store.list_entities(
                    "MitreTechnique",
                    search='"Exfiltration Over C2 Channel"',
                )
            ],
            ["T1041"],
        )

    def test_threat_search_supports_alias_indicator_and_technique_fields(self) -> None:
        self.assertEqual(
            [item["external_id"] for item in self.store.list_entities("ThreatProfile", search='alias:"Search Unit"')],
            ["apt_search"],
        )
        self.assertEqual(
            [item["external_id"] for item in self.store.list_entities("ThreatProfile", search="indicator:evil.example")],
            ["apt_search"],
        )
        self.assertEqual(
            [item["external_id"] for item in self.store.list_entities("ThreatProfile", search="technique:T1041")],
            ["apt_search"],
        )

    def test_tool_search_supports_platform_method_and_exclusion_terms(self) -> None:
        self.assertEqual(
            [
                item["external_id"]
                for item in self.store.list_entities(
                    "ToolPack",
                    search='platform:AWS method:"T1041 Hunt"',
                )
            ],
            ["elastic_search_tool"],
        )
        self.assertEqual(
            [
                item["external_id"]
                for item in self.store.list_entities(
                    "ToolPack",
                    search="platform:Elastic -deprecated",
                )
            ],
            ["elastic_active_tool"],
        )


if __name__ == "__main__":
    unittest.main()
