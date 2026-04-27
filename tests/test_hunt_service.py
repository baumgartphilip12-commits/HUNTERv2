"""Unit tests for hunt-pack generation and persistence helpers."""

from __future__ import annotations

import unittest
from pathlib import Path

from hunter.services.hunt_service import HuntGenerator
from hunter.services.sigma_service import SigmaRuleService
from tests.support import (
    create_temp_project,
    make_store,
    seed_sigma_rule,
    seed_technique,
    seed_threat,
    seed_tool,
)


class HuntServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = create_temp_project()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.store = make_store(self.root)

    def _seed_relevance_threat(
        self,
        *,
        technique_ids: list[str],
        aliases: list[str] | None = None,
        summary: str = "APT relevance test threat.",
        extra_hunts: list[str] | None = None,
        indicators: list[dict] | None = None,
    ) -> int:
        threat_id = self.store.upsert_entity(
            entity_type="ThreatProfile",
            external_id="apt_relevance",
            name="APT Relevance",
            short_description=summary,
            payload={
                "summary": summary,
                "aliases": aliases or ["Relevance Unit"],
                "mitre_techniques": technique_ids,
                "indicators": indicators or [{"type": "domain", "value": "tickler.example"}],
                "extra_hunts": extra_hunts or ["Hunt for Tickler backdoor command activity."],
                "references": ["https://example.test/apt-relevance"],
            },
        )
        for technique_id in technique_ids:
            technique = self.store.get_entity_by_external_id("MitreTechnique", technique_id)
            assert technique is not None
            self.store.upsert_relationship(
                src_entity_id=threat_id,
                dst_entity_id=technique["id"],
                rel_type="USES",
                source_name="Layered Local Modules",
                source_ref=f"threats/apt_relevance.json::{technique_id}",
                weight=1.0,
                confidence=0.9,
                context={"origin": "test"},
            )
        return threat_id

    def test_generate_includes_manual_mitre_and_surface_metadata(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        manual_technique_id = seed_technique(self.store, external_id="T1041", name="Exfiltration Over C2 Channel")
        threat_id = seed_threat(self.store, technique_id="T1001")
        tool_id = seed_tool(self.store, technique_ids=["T1001", "T1041"])

        generator = HuntGenerator(self.store)
        draft = generator.generate(
            mission_name="Unit Test Hunt",
            threat_ids=[threat_id],
            tool_ids=[tool_id],
            manual_technique_ids=[manual_technique_id],
        )

        self.assertEqual(draft.name, "Unit Test Hunt")
        self.assertIn("T1041", draft.summary["selected_manual_mitre"])
        self.assertIn("T1001", draft.summary["combined_selected_techniques"])
        self.assertIn("T1041", draft.summary["combined_selected_techniques"])
        self.assertGreaterEqual(draft.summary["candidate_steps"], 2)
        self.assertTrue(draft.selected_entity_ids)

        for step in draft.payload["steps"]:
            self.assertTrue(step["enabled"])
            self.assertTrue(step["step_id"])
            self.assertEqual(step["execution_surface"], "CloudWatch Logs Insights")
            self.assertIn("surface_details", step)

    def test_persist_round_trip_keeps_payload(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        threat_id = seed_threat(self.store, technique_id="T1001")
        tool_id = seed_tool(self.store, technique_ids=["T1001"])
        generator = HuntGenerator(self.store)

        draft = generator.generate(
            mission_name="Persisted Hunt",
            threat_ids=[threat_id],
            tool_ids=[tool_id],
            manual_technique_ids=[],
        )
        hunt_pack_id = generator.persist(draft)
        saved = self.store.get_hunt_pack(hunt_pack_id)

        self.assertIsNotNone(saved)
        self.assertEqual(saved["name"], "Persisted Hunt")
        self.assertEqual(saved["summary"]["mission_name"], "Persisted Hunt")
        self.assertTrue(saved["payload"]["steps"])

    def test_generate_adds_sigma_steps_for_translation_enabled_tools(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        threat_id = seed_threat(self.store, technique_id="T1001")
        tool_id = seed_tool(
            self.store,
            external_id="kibana",
            name="Kibana",
            technique_ids=["T1001"],
            sigma_translation={
                "enabled": True,
                "backend": "elasticsearch",
                "pipelines": [],
                "output_format": "lucene",
            },
            sigma_scope={"default_families": ["windows"]},
        )
        seed_sigma_rule(
            self.store,
            external_id="22222222-2222-2222-2222-222222222222",
            title="APT Unit Sigma T1001 Rule",
            technique_ids=["T1001"],
        )

        draft = HuntGenerator(self.store).generate(
            mission_name="Sigma Enabled Hunt",
            threat_ids=[threat_id],
            tool_ids=[tool_id],
        )

        authored_steps = [
            step for step in draft.payload["steps"] if step.get("content_origin") == "authored_tool_hunt"
        ]
        sigma_steps = [
            step for step in draft.payload["steps"] if step.get("content_origin") == "sigma_translated"
        ]

        self.assertTrue(authored_steps)
        self.assertTrue(sigma_steps)
        self.assertEqual(draft.payload["steps"][0]["content_origin"], "authored_tool_hunt")
        self.assertEqual(sigma_steps[0]["sigma_rule_id"], "22222222-2222-2222-2222-222222222222")
        self.assertEqual(sigma_steps[0]["sigma_title"], "APT Unit Sigma T1001 Rule")
        self.assertEqual(sigma_steps[0]["translation_target"], "elasticsearch")
        self.assertTrue(sigma_steps[0]["raw_rule_url"].startswith("https://"))
        self.assertGreater(sigma_steps[0]["sigma_relevance_score"], 0)
        self.assertTrue(sigma_steps[0]["sigma_relevance_reasons"])

    def test_generate_keeps_sigma_as_reference_only_for_unsupported_tools(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        threat_id = seed_threat(self.store, technique_id="T1001")
        tool_id = seed_tool(
            self.store,
            external_id="arkime",
            name="Arkime",
            technique_ids=["T1001"],
            sigma_translation={
                "enabled": False,
                "backend": "elasticsearch",
                "pipelines": [],
                "output_format": "lucene",
            },
        )
        seed_sigma_rule(
            self.store,
            external_id="33333333-3333-3333-3333-333333333333",
            title="Reference Only Sigma Rule",
            technique_ids=["T1001"],
        )

        draft = HuntGenerator(self.store).generate(
            mission_name="Sigma Reference Hunt",
            threat_ids=[threat_id],
            tool_ids=[tool_id],
        )

        self.assertTrue(draft.payload["steps"])
        self.assertFalse(
            any(step.get("content_origin") == "sigma_translated" for step in draft.payload["steps"])
        )

    def test_generate_filters_sigma_by_selected_families(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        threat_id = seed_threat(self.store, technique_id="T1001")
        tool_id = seed_tool(
            self.store,
            external_id="kibana",
            name="Kibana",
            technique_ids=["T1001"],
            sigma_translation={
                "enabled": True,
                "backend": "elasticsearch",
                "pipelines": [],
                "output_format": "lucene",
            },
            sigma_scope={"default_families": ["windows"]},
        )
        seed_sigma_rule(
            self.store,
            external_id="44444444-4444-4444-4444-444444444444",
            title="APT Unit Windows Sigma Rule",
            technique_ids=["T1001"],
            logsource={"product": "windows", "category": "process_creation"},
        )
        seed_sigma_rule(
            self.store,
            external_id="55555555-5555-5555-5555-555555555555",
            title="APT Unit Azure Sigma Rule",
            technique_ids=["T1001"],
            logsource={"product": "azure", "service": "activitylogs"},
        )

        draft = HuntGenerator(self.store).generate(
            mission_name="Family Filter Hunt",
            threat_ids=[threat_id],
            tool_ids=[tool_id],
            selected_sigma_families=["windows"],
        )

        sigma_rule_ids = {
            step.get("sigma_rule_id")
            for step in draft.payload["steps"]
            if step.get("content_origin") == "sigma_translated"
        }
        self.assertEqual(
            sigma_rule_ids,
            {"44444444-4444-4444-4444-444444444444"},
        )

    def test_generate_excludes_sigma_family_outside_tool_scope_even_if_selected(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        threat_id = self._seed_relevance_threat(
            technique_ids=["T1001"],
            aliases=["Peach Sandstorm"],
            summary="Peach Sandstorm uses Tickler malware and Azure-hosted infrastructure.",
            extra_hunts=["Hunt for Tickler malware and staging behavior."],
        )
        tool_id = seed_tool(
            self.store,
            external_id="kibana",
            name="Kibana",
            technique_ids=["T1001"],
            sigma_translation={
                "enabled": True,
                "backend": "elasticsearch",
                "pipelines": [],
                "output_format": "lucene",
            },
            sigma_scope={"default_families": ["windows"]},
        )
        seed_sigma_rule(
            self.store,
            external_id="56565656-5656-5656-5656-565656565656",
            title="Tickler Windows Sigma Rule",
            technique_ids=["T1001"],
            logsource={"product": "windows", "category": "process_creation"},
            raw_yaml=(
                "title: Tickler Windows Sigma Rule\n"
                "id: 56565656-5656-5656-5656-565656565656\n"
                "status: stable\n"
                "level: high\n"
                "logsource:\n"
                "  product: windows\n"
                "  category: process_creation\n"
                "detection:\n"
                "  selection:\n"
                "    CommandLine|contains: Tickler\n"
                "  condition: selection\n"
            ),
        )
        seed_sigma_rule(
            self.store,
            external_id="57575757-5757-5757-5757-575757575757",
            title="Tickler Azure Sigma Rule",
            technique_ids=["T1001"],
            logsource={"product": "azure", "service": "activitylogs"},
            raw_yaml=(
                "title: Tickler Azure Sigma Rule\n"
                "id: 57575757-5757-5757-5757-575757575757\n"
                "status: stable\n"
                "level: high\n"
                "logsource:\n"
                "  product: azure\n"
                "  service: activitylogs\n"
                "detection:\n"
                "  selection:\n"
                "    OperationName|contains: Tickler\n"
                "  condition: selection\n"
            ),
        )

        draft = HuntGenerator(self.store).generate(
            mission_name="Tool Scope Sigma Hunt",
            threat_ids=[threat_id],
            tool_ids=[tool_id],
            selected_sigma_families=["windows", "azure"],
        )

        sigma_rule_ids = [
            step.get("sigma_rule_id")
            for step in draft.payload["steps"]
            if step.get("content_origin") == "sigma_translated"
        ]
        self.assertEqual(sigma_rule_ids, ["56565656-5656-5656-5656-565656565656"])

    def test_sigma_selector_treats_translation_tool_without_scope_as_reference_only(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        threat_id = self._seed_relevance_threat(
            technique_ids=["T1001"],
            aliases=["Peach Sandstorm"],
            summary="Peach Sandstorm uses Tickler malware.",
            extra_hunts=["Hunt for Tickler command activity."],
        )
        tool_id = seed_tool(
            self.store,
            external_id="generic_elastic",
            name="Generic Elastic",
            technique_ids=["T1001"],
            sigma_translation={
                "enabled": True,
                "backend": "elasticsearch",
                "pipelines": [],
                "output_format": "lucene",
            },
            sigma_scope=None,
        )
        seed_sigma_rule(
            self.store,
            external_id="58585858-5858-5858-5858-585858585858",
            title="Tickler Windows Sigma Rule",
            technique_ids=["T1001"],
            logsource={"product": "windows", "category": "process_creation"},
            raw_yaml=(
                "title: Tickler Windows Sigma Rule\n"
                "id: 58585858-5858-5858-5858-585858585858\n"
                "status: stable\n"
                "level: high\n"
                "logsource:\n"
                "  product: windows\n"
                "  category: process_creation\n"
                "detection:\n"
                "  selection:\n"
                "    CommandLine|contains: Tickler\n"
                "  condition: selection\n"
            ),
        )

        service = SigmaRuleService(self.store)
        threat = self.store.get_entity(threat_id)
        tool = self.store.get_entity(tool_id)
        assert threat is not None and tool is not None
        selection = service.select_generation_rules(
            tool=tool,
            technique_scores={"T1001": {"confidence": 1.0}},
            selected_families=["windows"],
            relevance_context=service.build_relevance_context([threat]),
        )

        self.assertEqual(selection["selected_infos"], [])
        self.assertEqual(selection["effective_families"], [])
        self.assertEqual(selection["omitted_by_tool_scope_count"], 1)

    def test_generate_excludes_sigma_with_only_generic_ioc_type_relevance(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        threat_id = self._seed_relevance_threat(
            technique_ids=["T1001"],
            aliases=["Peach Sandstorm"],
            summary="Peach Sandstorm uses Tickler malware.",
            extra_hunts=["Hunt for Tickler command activity."],
            indicators=[{"type": "domain", "value": "tickler.example"}],
        )
        tool_id = seed_tool(
            self.store,
            external_id="kibana",
            name="Kibana",
            technique_ids=["T1001"],
            sigma_translation={
                "enabled": True,
                "backend": "elasticsearch",
                "pipelines": [],
                "output_format": "lucene",
            },
            sigma_scope={"default_families": ["windows"]},
        )
        seed_sigma_rule(
            self.store,
            external_id="59595959-5959-5959-5959-595959595959",
            title="Generic Domain Field Rule",
            technique_ids=["T1001"],
            logsource={"product": "windows", "category": "process_creation"},
            fields=["DestinationHostname"],
            raw_yaml=(
                "title: Generic Domain Field Rule\n"
                "id: 59595959-5959-5959-5959-595959595959\n"
                "status: stable\n"
                "level: medium\n"
                "logsource:\n"
                "  product: windows\n"
                "  category: process_creation\n"
                "detection:\n"
                "  selection:\n"
                "    DestinationHostname|contains: suspicious.example\n"
                "  condition: selection\n"
            ),
        )
        seed_sigma_rule(
            self.store,
            external_id="60606060-6060-6060-6060-606060606060",
            title="Tickler Domain Field Rule",
            technique_ids=["T1001"],
            logsource={"product": "windows", "category": "process_creation"},
            fields=["DestinationHostname"],
            raw_yaml=(
                "title: Tickler Domain Field Rule\n"
                "id: 60606060-6060-6060-6060-606060606060\n"
                "status: stable\n"
                "level: medium\n"
                "logsource:\n"
                "  product: windows\n"
                "  category: process_creation\n"
                "detection:\n"
                "  selection:\n"
                "    DestinationHostname|contains: tickler.example\n"
                "  condition: selection\n"
            ),
        )

        draft = HuntGenerator(self.store).generate(
            mission_name="Strict IOC Relevance Hunt",
            threat_ids=[threat_id],
            tool_ids=[tool_id],
            selected_sigma_families=["windows"],
        )

        sigma_rule_ids = [
            step.get("sigma_rule_id")
            for step in draft.payload["steps"]
            if step.get("content_origin") == "sigma_translated"
        ]
        self.assertEqual(sigma_rule_ids, ["60606060-6060-6060-6060-606060606060"])

    def test_sigma_selector_preview_rule_ids_match_generated_sigma_steps(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        threat_id = self._seed_relevance_threat(
            technique_ids=["T1001"],
            aliases=["Peach Sandstorm"],
            summary="Peach Sandstorm uses Tickler malware.",
            extra_hunts=["Hunt for Tickler command activity."],
        )
        tool_id = seed_tool(
            self.store,
            external_id="kibana",
            name="Kibana",
            technique_ids=["T1001"],
            sigma_translation={
                "enabled": True,
                "backend": "elasticsearch",
                "pipelines": [],
                "output_format": "lucene",
            },
            sigma_scope={"default_families": ["windows"]},
        )
        seed_sigma_rule(
            self.store,
            external_id="61616161-6161-6161-6161-616161616161",
            title="Tickler Windows Selector Rule",
            technique_ids=["T1001"],
            logsource={"product": "windows", "category": "process_creation"},
            raw_yaml=(
                "title: Tickler Windows Selector Rule\n"
                "id: 61616161-6161-6161-6161-616161616161\n"
                "status: stable\n"
                "level: high\n"
                "logsource:\n"
                "  product: windows\n"
                "  category: process_creation\n"
                "detection:\n"
                "  selection:\n"
                "    CommandLine|contains: Tickler\n"
                "  condition: selection\n"
            ),
        )
        seed_sigma_rule(
            self.store,
            external_id="62626262-6262-6262-6262-626262626262",
            title="Tickler Azure Selector Rule",
            technique_ids=["T1001"],
            logsource={"product": "azure", "service": "activitylogs"},
            raw_yaml=(
                "title: Tickler Azure Selector Rule\n"
                "id: 62626262-6262-6262-6262-626262626262\n"
                "status: stable\n"
                "level: high\n"
                "logsource:\n"
                "  product: azure\n"
                "  service: activitylogs\n"
                "detection:\n"
                "  selection:\n"
                "    OperationName|contains: Tickler\n"
                "  condition: selection\n"
            ),
        )

        service = SigmaRuleService(self.store)
        threat = self.store.get_entity(threat_id)
        tool = self.store.get_entity(tool_id)
        assert threat is not None and tool is not None
        relevance_context = service.build_relevance_context([threat])
        summary = service.summarize_tool_coverage(
            tool,
            ["T1001"],
            selected_families=["windows", "azure"],
            relevance_context=relevance_context,
            apply_caps=True,
            include_rules=True,
        )
        preview_rule_ids = [rule["external_id"] for rule in summary["rules"]]
        step_rule_ids = [
            step["sigma_rule_id"]
            for _score, step in service.build_translated_steps(
                tool=tool,
                technique_scores={"T1001": {"confidence": 1.0}},
                selected_families=["windows", "azure"],
                indicator_context={},
                relevance_context=relevance_context,
            )
        ]

        self.assertEqual(preview_rule_ids, step_rule_ids)

    def test_generate_excludes_sigma_that_only_matches_attack_not_apt_relevance(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        threat_id = self._seed_relevance_threat(
            technique_ids=["T1001"],
            aliases=["Peach Sandstorm"],
            summary="Peach Sandstorm uses Tickler backdoor infrastructure and Azure-hosted C2.",
            extra_hunts=["Hunt for Tickler malware, Azure App Service C2, and related staging."],
        )
        tool_id = seed_tool(
            self.store,
            external_id="kibana",
            name="Kibana",
            technique_ids=["T1001"],
            sigma_translation={
                "enabled": True,
                "backend": "elasticsearch",
                "pipelines": [],
                "output_format": "lucene",
            },
            sigma_scope={"default_families": ["windows"]},
        )
        seed_sigma_rule(
            self.store,
            external_id="12121212-1212-1212-1212-121212121212",
            title="Tickler Backdoor Command Rule",
            technique_ids=["T1001"],
            logsource={"product": "windows", "category": "process_creation"},
            raw_yaml=(
                "title: Tickler Backdoor Command Rule\n"
                "id: 12121212-1212-1212-1212-121212121212\n"
                "status: stable\n"
                "level: high\n"
                "logsource:\n"
                "  product: windows\n"
                "  category: process_creation\n"
                "detection:\n"
                "  selection:\n"
                "    CommandLine|contains: Tickler\n"
                "  condition: selection\n"
            ),
        )
        seed_sigma_rule(
            self.store,
            external_id="13131313-1313-1313-1313-131313131313",
            title="Generic Encoded Command Rule",
            technique_ids=["T1001"],
            logsource={"product": "windows", "category": "process_creation"},
            raw_yaml=(
                "title: Generic Encoded Command Rule\n"
                "id: 13131313-1313-1313-1313-131313131313\n"
                "status: stable\n"
                "level: high\n"
                "logsource:\n"
                "  product: windows\n"
                "  category: process_creation\n"
                "detection:\n"
                "  selection:\n"
                "    CommandLine|contains: EncodedCommand\n"
                "  condition: selection\n"
            ),
        )

        draft = HuntGenerator(self.store).generate(
            mission_name="Strict Sigma Relevance Hunt",
            threat_ids=[threat_id],
            tool_ids=[tool_id],
            selected_sigma_families=["windows"],
        )

        sigma_steps = [
            step for step in draft.payload["steps"] if step.get("content_origin") == "sigma_translated"
        ]
        self.assertEqual([step["sigma_rule_id"] for step in sigma_steps], ["12121212-1212-1212-1212-121212121212"])
        self.assertIn("APT relevance", sigma_steps[0]["why_selected"])
        self.assertTrue(sigma_steps[0]["sigma_relevance_matches"])

    def test_sigma_selector_excludes_rules_matching_only_generic_threat_prose(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        threat_id = self._seed_relevance_threat(
            technique_ids=["T1001"],
            aliases=["Peach Sandstorm"],
            summary="Review credential activity, execution chains, process telemetry, and documents.",
            extra_hunts=[
                "Hunt for Azure-hosted infrastructure, credential access, execution, process activity, and document lures."
            ],
            indicators=[{"type": "domain", "value": "tickler.example"}],
        )
        tool_id = seed_tool(
            self.store,
            external_id="kibana",
            name="Kibana",
            technique_ids=["T1001"],
            sigma_translation={
                "enabled": True,
                "backend": "elasticsearch",
                "pipelines": [],
                "output_format": "lucene",
            },
            sigma_scope={"default_families": ["windows"]},
        )
        seed_sigma_rule(
            self.store,
            external_id="14141414-1414-1414-1414-141414141414",
            title="Generic Credential Execution Document Activity",
            technique_ids=["T1001"],
            logsource={"product": "windows", "category": "process_creation"},
            raw_yaml=(
                "title: Generic Credential Execution Document Activity\n"
                "id: 14141414-1414-1414-1414-141414141414\n"
                "status: stable\n"
                "level: medium\n"
                "logsource:\n"
                "  product: windows\n"
                "  category: process_creation\n"
                "detection:\n"
                "  selection:\n"
                "    CommandLine|contains:\n"
                "      - credential\n"
                "      - execution\n"
                "      - documents\n"
                "  condition: selection\n"
            ),
        )

        service = SigmaRuleService(self.store)
        threat = self.store.get_entity(threat_id)
        tool = self.store.get_entity(tool_id)
        assert threat is not None and tool is not None
        selection = service.select_generation_rules(
            tool=tool,
            technique_scores={"T1001": {"confidence": 1.0}},
            selected_families=["windows"],
            relevance_context=service.build_relevance_context([threat]),
        )

        self.assertEqual(selection["selected_infos"], [])
        self.assertEqual(selection["omitted_by_relevance_count"], 1)

    def test_generate_caps_relevant_sigma_steps_per_tool_and_technique(self) -> None:
        technique_ids = [f"T100{index}" for index in range(1, 7)]
        for technique_id in technique_ids:
            seed_technique(self.store, external_id=technique_id, name=f"Technique {technique_id}")
        threat_id = self._seed_relevance_threat(
            technique_ids=technique_ids,
            aliases=["Peach Sandstorm"],
            summary="Peach Sandstorm uses Tickler malware across many related behaviors.",
            extra_hunts=["Hunt for repeated Tickler malware behavior."],
        )
        tool_id = seed_tool(
            self.store,
            external_id="kibana",
            name="Kibana",
            technique_ids=technique_ids,
            sigma_translation={
                "enabled": True,
                "backend": "elasticsearch",
                "pipelines": [],
                "output_format": "lucene",
            },
            sigma_scope={"default_families": ["windows"]},
        )
        for technique_id in technique_ids:
            for index in range(6):
                suffix = f"{technique_id.replace('T', '')}{index:02d}"
                seed_sigma_rule(
                    self.store,
                    external_id=f"aaaaaaaa-aaaa-aaaa-aaaa-{int(suffix):012d}",
                    title=f"Tickler {technique_id} Rule {index}",
                    technique_ids=[technique_id],
                    logsource={"product": "windows", "category": "process_creation"},
                    raw_yaml=(
                        f"title: Tickler {technique_id} Rule {index}\n"
                        f"id: aaaaaaaa-aaaa-aaaa-aaaa-{int(suffix):012d}\n"
                        "status: stable\n"
                        "level: high\n"
                        "logsource:\n"
                        "  product: windows\n"
                        "  category: process_creation\n"
                        "detection:\n"
                        "  selection:\n"
                        "    CommandLine|contains: Tickler\n"
                        "  condition: selection\n"
                    ),
                )

        draft = HuntGenerator(self.store).generate(
            mission_name="Capped Sigma Hunt",
            threat_ids=[threat_id],
            tool_ids=[tool_id],
            selected_sigma_families=["windows"],
        )

        sigma_steps = [
            step for step in draft.payload["steps"] if step.get("content_origin") == "sigma_translated"
        ]
        self.assertEqual(len(sigma_steps), 25)
        for technique_id in technique_ids:
            self.assertLessEqual(
                sum(1 for step in sigma_steps if technique_id in step.get("techniques", [])),
                5,
            )

    def test_manual_mitre_only_sigma_generation_bypasses_apt_gate_but_still_caps(self) -> None:
        manual_technique_id = seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        tool_id = seed_tool(
            self.store,
            external_id="kibana",
            name="Kibana",
            technique_ids=["T1001"],
            sigma_translation={
                "enabled": True,
                "backend": "elasticsearch",
                "pipelines": [],
                "output_format": "lucene",
            },
            sigma_scope={"default_families": ["windows"]},
        )
        for index in range(8):
            seed_sigma_rule(
                self.store,
                external_id=f"bbbbbbbb-bbbb-bbbb-bbbb-{index:012d}",
                title=f"Generic Manual MITRE Rule {index}",
                technique_ids=["T1001"],
                logsource={"product": "windows", "category": "process_creation"},
            )

        draft = HuntGenerator(self.store).generate(
            mission_name="Manual Sigma Hunt",
            threat_ids=[],
            tool_ids=[tool_id],
            manual_technique_ids=[manual_technique_id],
            selected_sigma_families=["windows"],
        )

        sigma_steps = [
            step for step in draft.payload["steps"] if step.get("content_origin") == "sigma_translated"
        ]
        self.assertEqual(len(sigma_steps), 5)

    def test_generate_adds_sigma_ioc_guidance_without_mutating_query(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        threat_id = seed_threat(self.store, technique_id="T1001")
        tool_id = seed_tool(
            self.store,
            external_id="kibana",
            name="Kibana",
            technique_ids=["T1001"],
            sigma_translation={
                "enabled": True,
                "backend": "elasticsearch",
                "pipelines": [],
                "output_format": "lucene",
            },
            sigma_scope={"default_families": ["windows"]},
        )
        raw_yaml = (
            "title: APT Unit IOC Domain Sigma Rule\n"
            "id: 66666666-6666-6666-6666-666666666666\n"
            "status: stable\n"
            "level: medium\n"
            "logsource:\n"
            "  product: windows\n"
            "  category: process_creation\n"
            "detection:\n"
            "  selection:\n"
            "    DestinationHostname|contains: suspicious.example\n"
            "  condition: selection\n"
        )
        seed_sigma_rule(
            self.store,
            external_id="66666666-6666-6666-6666-666666666666",
            title="APT Unit IOC Domain Sigma Rule",
            technique_ids=["T1001"],
            logsource={"product": "windows", "category": "process_creation"},
            fields=["DestinationHostname"],
            raw_yaml=raw_yaml,
        )

        draft = HuntGenerator(self.store).generate(
            mission_name="IOC Guidance Hunt",
            threat_ids=[threat_id],
            tool_ids=[tool_id],
            selected_sigma_families=["windows"],
        )

        sigma_step = next(
            step for step in draft.payload["steps"] if step.get("sigma_rule_id") == "66666666-6666-6666-6666-666666666666"
        )
        self.assertEqual(sigma_step["ioc_insertions"], {})
        self.assertEqual(sigma_step["sigma_detected_ioc_types"], ["domain"])
        self.assertEqual(sigma_step["sigma_ioc_guidance"], ["domain = evil.example"])
        self.assertNotIn("evil.example", sigma_step["rendered_query"])

    def test_generate_auto_classifies_sigma_method_kind(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        threat_id = seed_threat(self.store, technique_id="T1001")
        tool_id = seed_tool(
            self.store,
            external_id="kibana",
            name="Kibana",
            technique_ids=["T1001"],
            sigma_translation={
                "enabled": True,
                "backend": "elasticsearch",
                "pipelines": [],
                "output_format": "lucene",
            },
            sigma_scope={"default_families": ["windows"]},
        )
        seed_sigma_rule(
            self.store,
            external_id="77777777-7777-7777-7777-777777777777",
            title="APT Unit IOC Sigma Rule",
            technique_ids=["T1001"],
            logsource={"product": "windows", "category": "process_creation"},
            fields=["DestinationHostname"],
            raw_yaml=(
                "title: APT Unit IOC Sigma Rule\n"
                "id: 77777777-7777-7777-7777-777777777777\n"
                "status: stable\n"
                "level: medium\n"
                "logsource:\n"
                "  product: windows\n"
                "  category: process_creation\n"
                "detection:\n"
                "  selection:\n"
                "    DestinationHostname|contains: suspicious.example\n"
                "  condition: selection\n"
            ),
        )
        seed_sigma_rule(
            self.store,
            external_id="88888888-8888-8888-8888-888888888888",
            title="APT Unit Correlation Sigma Rule",
            technique_ids=["T1001"],
            logsource={"product": "windows", "category": "process_creation"},
            raw_yaml=(
                "title: APT Unit Correlation Sigma Rule\n"
                "id: 88888888-8888-8888-8888-888888888888\n"
                "status: stable\n"
                "level: medium\n"
                "logsource:\n"
                "  product: windows\n"
                "  category: process_creation\n"
                "detection:\n"
                "  selection_process:\n"
                "    Image|endswith: '\\\\powershell.exe'\n"
                "  selection_net:\n"
                "    CommandLine|contains: http\n"
                "  condition: selection_process and selection_net\n"
            ),
        )
        seed_sigma_rule(
            self.store,
            external_id="99999999-9999-9999-9999-999999999999",
            title="APT Unit Behavior Sigma Rule",
            technique_ids=["T1001"],
            logsource={"product": "windows", "category": "process_creation"},
            raw_yaml=(
                "title: APT Unit Behavior Sigma Rule\n"
                "id: 99999999-9999-9999-9999-999999999999\n"
                "status: stable\n"
                "level: medium\n"
                "logsource:\n"
                "  product: windows\n"
                "  category: process_creation\n"
                "detection:\n"
                "  selection:\n"
                "    Image|endswith: '\\\\powershell.exe'\n"
                "  condition: selection\n"
            ),
        )

        draft = HuntGenerator(self.store).generate(
            mission_name="Sigma Kinds Hunt",
            threat_ids=[threat_id],
            tool_ids=[tool_id],
            selected_sigma_families=["windows"],
        )

        sigma_steps = {
            step["sigma_rule_id"]: step
            for step in draft.payload["steps"]
            if step.get("content_origin") == "sigma_translated"
        }
        self.assertEqual(sigma_steps["77777777-7777-7777-7777-777777777777"]["method_kind"], "ioc_pivot")
        self.assertEqual(sigma_steps["88888888-8888-8888-8888-888888888888"]["method_kind"], "correlation")
        self.assertEqual(sigma_steps["99999999-9999-9999-9999-999999999999"]["method_kind"], "behavior_hunt")

    def test_generate_handles_string_time_cost_values(self) -> None:
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        threat_id = seed_threat(self.store, technique_id="T1001")
        tool_id = seed_tool(self.store, technique_ids=["T1001"])
        tool = self.store.get_entity(tool_id)
        assert tool is not None
        payload = dict(tool["payload"])
        payload["hunt_methods"] = [dict(method) for method in payload.get("hunt_methods", [])]
        payload["hunt_methods"][0]["time_cost"] = "medium"
        self.store.upsert_entity(
            entity_type="ToolPack",
            external_id=tool["external_id"],
            name=tool["name"],
            short_description=tool.get("short_description", ""),
            status=tool.get("status", "active"),
            source_name=tool.get("source_name", "local"),
            source_ref=tool.get("source_ref", ""),
            payload=payload,
        )

        draft = HuntGenerator(self.store).generate(
            mission_name="String Time Cost Hunt",
            threat_ids=[threat_id],
            tool_ids=[tool_id],
        )

        self.assertTrue(draft.payload["steps"])


if __name__ == "__main__":
    unittest.main()
