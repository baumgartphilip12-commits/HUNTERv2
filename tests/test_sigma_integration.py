"""Regression coverage for SigmaHQ sync and Sigma-aware tool metadata."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from textwrap import dedent

from hunter.services.sigma_service import SigmaRuleService
from hunter.services.sync_service import SyncService
from tests.support import (
    create_temp_project,
    make_store,
    seed_technique,
    seed_tool,
    write_sigma_archive,
    write_tool_module,
)


class SigmaIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = create_temp_project()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.store = make_store(self.root)
        seed_technique(self.store, external_id="T1001", name="Data Obfuscation")
        seed_technique(self.store, external_id="T1041", name="Exfiltration Over C2 Channel")
        self.sync = SyncService(self.store)
        self.sigma_source = self.store.get_source_by_name("SigmaHQ Rules")
        assert self.sigma_source is not None

    @staticmethod
    def _rule_yaml(
        *,
        title: str,
        rule_id: str,
        technique_id: str,
        extra: str = "",
    ) -> str:
        base = dedent(
            f"""
            title: {title}
            id: {rule_id}
            status: stable
            level: medium
            references:
              - https://example.test/{rule_id}
            tags:
              - attack.{technique_id.lower()}
            logsource:
              product: windows
              category: process_creation
            detection:
              selection:
                Image|endswith: '\\powershell.exe'
                CommandLine|contains:
                  - DownloadString
                  - http
              condition: selection
            """
        ).strip()
        if extra.strip():
            return base + "\n" + extra.strip()
        return base

    def _configure_sigma_source(self, archive_path: Path) -> None:
        self.store.update_source(
            self.sigma_source["id"],
            config={
                "archive_path": str(archive_path),
                "repo_url": "https://github.com/SigmaHQ/sigma",
                "raw_base_url": "https://raw.githubusercontent.com/SigmaHQ/sigma/master",
            },
        )

    def test_sigma_source_imports_rules_and_links_attack(self) -> None:
        archive_path = write_sigma_archive(
            self.root,
            files={
                "sigma-master/rules/windows/process_creation/test_rule.yml": self._rule_yaml(
                    title="PowerShell Download",
                    rule_id="44444444-4444-4444-4444-444444444444",
                    technique_id="T1001",
                ),
                "sigma-master/rules-threat-hunting/windows/hunt_rule.yml": self._rule_yaml(
                    title="Exfiltration Hunt",
                    rule_id="55555555-5555-5555-5555-555555555555",
                    technique_id="T1041",
                ),
                "sigma-master/deprecated/windows/ignored.yml": self._rule_yaml(
                    title="Deprecated Rule",
                    rule_id="66666666-6666-6666-6666-666666666666",
                    technique_id="T1001",
                ),
                "sigma-master/rules/windows/process_creation/filter_only.yml": dedent(
                    """
                    title: Unsupported Filter File
                    filter:
                      selection:
                        Image|endswith: '\\cmd.exe'
                    """
                ).strip(),
            },
        )
        self._configure_sigma_source(archive_path)

        preview = self.sync.preview_source(self.sigma_source["id"])
        self.assertEqual(preview.summary["entity_count"], 2)
        self.assertEqual(preview.summary["relationship_count"], 2)
        self.assertGreaterEqual(preview.summary["warning_count"], 1)

        self.sync.apply_source(self.sigma_source["id"])

        imported = self.store.get_entity_by_external_id(
            "SigmaRule", "sigma::sigmahq-rules::44444444-4444-4444-4444-444444444444"
        )
        self.assertIsNotNone(imported)
        self.assertEqual(imported["name"], "PowerShell Download")
        self.assertEqual(imported["payload"]["attack_techniques"], ["T1001"])
        self.assertEqual(
            imported["payload"]["raw_rule_url"],
            "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/test_rule.yml",
        )

        relationships = self.store.list_relationships(
            entity_id=imported["id"],
            direction="out",
            rel_type="DETECTS",
        )
        self.assertEqual([rel["dst_external_id"] for rel in relationships], ["T1001"])
        self.assertIsNone(
            self.store.get_entity_by_external_id(
                "SigmaRule", "66666666-6666-6666-6666-666666666666"
            )
        )

    def test_sigma_source_imports_rules_from_modules_sigma_directory(self) -> None:
        sigma_dir = self.root / "modules" / "SIGMA" / "local_lab"
        nested_dir = sigma_dir / "nested"
        nested_dir.mkdir(parents=True)
        (sigma_dir / "local_rule.yml").write_text(
            self._rule_yaml(
                title="Local Windows Rule",
                rule_id="01010101-0101-0101-0101-010101010101",
                technique_id="T1001",
            ),
            encoding="utf-8",
        )
        (nested_dir / "azure_rule.yaml").write_text(
            self._rule_yaml(
                title="Local Azure Rule",
                rule_id="02020202-0202-0202-0202-020202020202",
                technique_id="T1041",
                extra="logsource:\n  product: azure\n  service: activitylogs",
            ),
            encoding="utf-8",
        )
        (nested_dir / "bad.yml").write_text("title: [unterminated", encoding="utf-8")
        self.store.update_source(
            self.sigma_source["id"],
            config={
                "rules_dir": "modules/SIGMA/local_lab",
                "repo_url": "file://modules/SIGMA/local_lab",
            },
        )

        preview = self.sync.preview_source(self.sigma_source["id"])
        self.assertEqual(preview.summary["entity_count"], 2)
        self.assertGreaterEqual(preview.summary["warning_count"], 1)

        self.sync.apply_source(self.sigma_source["id"])

        imported = self.store.get_entity_by_external_id(
            "SigmaRule", "sigma::sigmahq-rules::02020202-0202-0202-0202-020202020202"
        )
        self.assertIsNotNone(imported)
        self.assertEqual(imported["source_name"], "SigmaHQ Rules")
        self.assertEqual(imported["source_ref"], "nested/azure_rule.yaml")
        self.assertEqual(imported["payload"]["source_family"], "azure")
        self.assertIn("Local Azure Rule", imported["payload"]["raw_yaml"])
        relationships = self.store.list_relationships(
            entity_id=imported["id"],
            direction="out",
            rel_type="DETECTS",
        )
        self.assertEqual([rel["dst_external_id"] for rel in relationships], ["T1041"])

    def test_sigma_source_imports_single_modules_sigma_file(self) -> None:
        sigma_file = self.root / "modules" / "SIGMA" / "single.yml"
        sigma_file.parent.mkdir(parents=True, exist_ok=True)
        sigma_file.write_text(
            self._rule_yaml(
                title="Single Local Rule",
                rule_id="03030303-0303-0303-0303-030303030303",
                technique_id="T1001",
            ),
            encoding="utf-8",
        )
        self.store.update_source(
            self.sigma_source["id"],
            config={"rules_file": "modules/SIGMA/single.yml"},
        )

        preview = self.sync.preview_source(self.sigma_source["id"])
        self.assertEqual(preview.summary["entity_count"], 1)
        self.sync.apply_source(self.sigma_source["id"])

        imported = self.store.get_entity_by_external_id(
            "SigmaRule", "sigma::sigmahq-rules::03030303-0303-0303-0303-030303030303"
        )
        self.assertIsNotNone(imported)
        self.assertEqual(imported["source_ref"], "single.yml")

    def test_sigma_sources_with_same_rule_uuid_do_not_overwrite_each_other(self) -> None:
        rule_uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        for source_suffix, title in (("one", "First Source Rule"), ("two", "Second Source Rule")):
            sigma_dir = self.root / "modules" / "SIGMA" / source_suffix
            sigma_dir.mkdir(parents=True)
            (sigma_dir / "rule.yml").write_text(
                self._rule_yaml(title=title, rule_id=rule_uuid, technique_id="T1001"),
                encoding="utf-8",
            )
            source_id = self.store.create_source(
                name=f"Sigma {source_suffix.title()}",
                connector="sigmahq_rules",
                config={"rules_dir": f"modules/SIGMA/{source_suffix}"},
            )
            self.sync.apply_source(source_id)

        first = self.store.get_entity_by_external_id("SigmaRule", f"sigma::sigma-one::{rule_uuid}")
        second = self.store.get_entity_by_external_id("SigmaRule", f"sigma::sigma-two::{rule_uuid}")
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertEqual(first["payload"]["rule_uuid"], rule_uuid)
        self.assertEqual(second["payload"]["rule_uuid"], rule_uuid)
        self.assertEqual(first["source_name"], "Sigma One")
        self.assertEqual(second["source_name"], "Sigma Two")

        self.store.delete_source("Sigma Two")

        self.assertIsNotNone(self.store.get_entity_by_external_id("SigmaRule", f"sigma::sigma-one::{rule_uuid}"))
        self.assertIsNone(self.store.get_entity_by_external_id("SigmaRule", f"sigma::sigma-two::{rule_uuid}"))

    def test_sigma_source_handles_yaml_dates_in_preview_apply_and_payload(self) -> None:
        archive_path = write_sigma_archive(
            self.root,
            files={
                "sigma-master/rules/windows/process_creation/date_rule.yml": self._rule_yaml(
                    title="Date Rule",
                    rule_id="99999999-9999-9999-9999-999999999999",
                    technique_id="T1001",
                    extra=dedent(
                        """
                        date: 2024-01-01
                        falsepositives:
                          - 2024-02-02
                        detection:
                          selection:
                            Image|endswith: '\\powershell.exe'
                            EventDate: 2024-03-03
                          condition: selection
                        """
                    ).strip(),
                ),
            },
        )
        self._configure_sigma_source(archive_path)

        preview = self.sync.preview_source(self.sigma_source["id"])
        self.assertEqual(preview.summary["entity_count"], 1)
        self.assertEqual(preview.summary["relationship_count"], 1)

        self.sync.apply_source(self.sigma_source["id"])

        imported = self.store.get_entity_by_external_id(
            "SigmaRule", "sigma::sigmahq-rules::99999999-9999-9999-9999-999999999999"
        )
        self.assertIsNotNone(imported)
        self.assertEqual(imported["payload"]["date"], "2024-01-01")
        self.assertEqual(imported["payload"]["falsepositives"], ["2024-02-02"])
        self.assertEqual(
            imported["payload"]["detection"]["selection"]["EventDate"],
            "2024-03-03",
        )

    def test_sigma_source_normalizes_source_family(self) -> None:
        archive_path = write_sigma_archive(
            self.root,
            files={
                "sigma-master/rules/cloud/azure/rule.yml": self._rule_yaml(
                    title="Azure Rule",
                    rule_id="12121212-1212-1212-1212-121212121212",
                    technique_id="T1001",
                    extra="logsource:\n  product: azure\n  service: activitylogs",
                ),
            },
        )
        self._configure_sigma_source(archive_path)

        self.sync.apply_source(self.sigma_source["id"])
        imported = self.store.get_entity_by_external_id(
            "SigmaRule", "sigma::sigmahq-rules::12121212-1212-1212-1212-121212121212"
        )
        self.assertIsNotNone(imported)
        self.assertEqual(imported["payload"]["source_family"], "azure")

    def test_sigma_source_links_attack_tags_before_mitre_sync(self) -> None:
        tempdir = create_temp_project()
        self.addCleanup(tempdir.cleanup)
        root = Path(tempdir.name)
        store = make_store(root)
        self.addCleanup(store.close)
        sync = SyncService(store)
        sigma_source = store.get_source_by_name("SigmaHQ Rules")
        assert sigma_source is not None
        archive_path = write_sigma_archive(
            root,
            filename="sigma_before_mitre.zip",
            files={
                "sigma-master/rules/windows/process_creation/no_mitre_yet.yml": self._rule_yaml(
                    title="Pre MITRE Rule",
                    rule_id="abababab-abab-abab-abab-abababababab",
                    technique_id="T9999",
                ),
            },
        )
        store.update_source(
            sigma_source["id"],
            config={
                "archive_path": str(archive_path),
                "repo_url": "https://github.com/SigmaHQ/sigma",
                "raw_base_url": "https://raw.githubusercontent.com/SigmaHQ/sigma/master",
            },
        )

        preview = sync.preview_source(sigma_source["id"])

        self.assertEqual(preview.summary["entity_count"], 2)
        self.assertEqual(preview.summary["relationship_count"], 1)

        sync.apply_source(sigma_source["id"])

        imported = store.get_entity_by_external_id(
            "SigmaRule", "sigma::sigmahq-rules::abababab-abab-abab-abab-abababababab"
        )
        placeholder = store.get_entity_by_external_id("MitreTechnique", "T9999")
        self.assertIsNotNone(imported)
        self.assertIsNotNone(placeholder)
        self.assertEqual(placeholder["status"], "placeholder")
        relationships = store.list_relationships(
            entity_id=imported["id"],
            direction="out",
            rel_type="DETECTS",
        )
        self.assertEqual([rel["dst_external_id"] for rel in relationships], ["T9999"])

    def test_sigma_source_rollback_restores_previous_snapshot(self) -> None:
        first_archive = write_sigma_archive(
            self.root,
            filename="sigma_first.zip",
            files={
                "sigma-master/rules/windows/process_creation/test_rule.yml": self._rule_yaml(
                    title="Initial Rule Title",
                    rule_id="77777777-7777-7777-7777-777777777777",
                    technique_id="T1001",
                    extra="date: 2024-01-01",
                ),
            },
        )
        self._configure_sigma_source(first_archive)
        self.sync.apply_source(self.sigma_source["id"])

        second_archive = write_sigma_archive(
            self.root,
            filename="sigma_second.zip",
            files={
                "sigma-master/rules/windows/process_creation/test_rule.yml": self._rule_yaml(
                    title="Updated Rule Title",
                    rule_id="77777777-7777-7777-7777-777777777777",
                    technique_id="T1001",
                    extra="date: 2024-01-02",
                ),
            },
        )
        self._configure_sigma_source(second_archive)
        self.sync.apply_source(self.sigma_source["id"])

        updated = self.store.get_entity_by_external_id(
            "SigmaRule", "sigma::sigmahq-rules::77777777-7777-7777-7777-777777777777"
        )
        self.assertEqual(updated["name"], "Updated Rule Title")

        self.sync.rollback_latest(self.sigma_source["id"])

        restored = self.store.get_entity_by_external_id(
            "SigmaRule", "sigma::sigmahq-rules::77777777-7777-7777-7777-777777777777"
        )
        self.assertEqual(restored["name"], "Initial Rule Title")
        self.assertEqual(restored["payload"]["date"], "2024-01-01")

    def test_layered_tool_validation_accepts_complete_sigma_translation_block(self) -> None:
        tool_path = write_tool_module(
            self.root,
            external_id="kibana",
            name="Kibana",
            platform="Elastic",
            technique_ids=["T1001"],
        )
        payload = json.loads(tool_path.read_text(encoding="utf-8"))
        payload["sigma_translation"] = {
            "enabled": True,
            "backend": "elasticsearch",
            "pipelines": [],
            "output_format": "lucene",
        }

        self.sync.validate_layered_tool_module(payload, tool_path)

        broken = json.loads(json.dumps(payload))
        broken["sigma_translation"] = {
            "enabled": True,
            "backend": "elasticsearch",
        }
        with self.assertRaisesRegex(ValueError, "sigma_translation"):
            self.sync.validate_layered_tool_module(broken, tool_path)

    def test_compact_sigma_summary_omits_full_rules_by_default(self) -> None:
        archive_path = write_sigma_archive(
            self.root,
            filename="sigma_summary.zip",
            files={
                f"sigma-master/rules/windows/process_creation/rule_{index}.yml": self._rule_yaml(
                    title=f"Rule {index}",
                    rule_id=f"aaaaaaaa-aaaa-aaaa-aaaa-{index:012d}",
                    technique_id="T1001",
                )
                for index in range(12)
            },
        )
        self._configure_sigma_source(archive_path)
        self.sync.apply_source(self.sigma_source["id"])

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
        )
        tool = self.store.get_entity(tool_id)
        assert tool is not None

        summary = SigmaRuleService(self.store).summarize_tool_coverage(tool, ["T1001"])

        self.assertEqual(summary["rule_count"], 12)
        self.assertNotIn("rules", summary)
        self.assertLessEqual(len(summary["rule_preview"]), 10)
        self.assertEqual(summary["matched_techniques"], ["T1001"])

    def test_full_sigma_summary_can_opt_into_hydrated_rules(self) -> None:
        archive_path = write_sigma_archive(
            self.root,
            filename="sigma_hydrated.zip",
            files={
                "sigma-master/rules/windows/process_creation/rule.yml": self._rule_yaml(
                    title="Hydrated Rule",
                    rule_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                    technique_id="T1001",
                )
            },
        )
        self._configure_sigma_source(archive_path)
        self.sync.apply_source(self.sigma_source["id"])

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
        )
        tool = self.store.get_entity(tool_id)
        assert tool is not None

        summary = SigmaRuleService(self.store).summarize_tool_coverage(
            tool,
            ["T1001"],
            include_rules=True,
        )

        self.assertEqual(summary["rule_count"], 1)
        self.assertIn("rules", summary)
        self.assertEqual(summary["rules"][0]["name"], "Hydrated Rule")


if __name__ == "__main__":
    unittest.main()
