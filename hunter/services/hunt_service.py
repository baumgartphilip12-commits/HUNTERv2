"""Hunt-pack generation and template rendering for HUNTER v2."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from hunter.models.knowledge_store import KnowledgeStore, utc_now
from hunter.services.hunt_pack_summary_service import HuntPackSummaryService
from hunter.services.sigma_service import SigmaRuleService


PLACEHOLDER_TYPES = {
    "<IP_IOC>": ["ip", "ipv4", "ipv6"],
    "<DOMAIN_IOC>": ["domain", "fqdn"],
    "<URL_IOC>": ["url", "uri"],
    "<HASH_SHA256>": ["sha256", "hash_sha256"],
    "<HASH_MD5>": ["md5", "hash_md5"],
    "<HOSTNAME_IOC>": ["hostname", "host"],
}

NOISE_SCORES = {
    "low": 1.0,
    "medium": 0.7,
    "high": 0.4,
}

PRIVILEGE_SCORES = {
    "none": 1.0,
    "user": 0.8,
    "elevated": 0.55,
    "admin": 0.45,
    "unknown": 0.6,
}


@dataclass
class HuntDraft:
    """Generated hunt-pack payload plus summary metadata."""

    name: str
    summary: dict
    payload: dict
    selected_entity_ids: list[int]


class HuntGenerator:
    """Build ranked hunt packs from threats, tools, and threat-carried indicators."""

    def __init__(self, store: KnowledgeStore):
        self.store = store
        self.sigma_rules = SigmaRuleService(store)

    def generate(
        self,
        *,
        mission_name: str,
        threat_ids: list[int],
        tool_ids: list[int],
        manual_technique_ids: list[int] | None = None,
        selected_sigma_families: list[str] | None = None,
    ) -> HuntDraft:
        manual_technique_ids = manual_technique_ids or []
        normalized_sigma_families = (
            None
            if selected_sigma_families is None
            else [
                str(value).strip().lower()
                for value in selected_sigma_families
                if str(value).strip()
            ]
        )
        threats = [self.store.get_entity(entity_id) for entity_id in threat_ids]
        tools = [self.store.get_entity(entity_id) for entity_id in tool_ids]
        manual_techniques = [
            self.store.get_entity(entity_id) for entity_id in manual_technique_ids
        ]

        threats = [entity for entity in threats if entity]
        tools = [entity for entity in tools if entity]
        manual_techniques = [entity for entity in manual_techniques if entity]

        technique_scores = self._collect_technique_scores(threats)
        self._merge_manual_techniques(technique_scores, manual_techniques)
        indicator_context = self._collect_indicator_context(threats)
        sigma_relevance_context = self.sigma_rules.build_relevance_context(threats)

        ranked_steps: list[tuple[int, float, dict]] = []
        sigma_rule_ids: set[str] = set()

        for tool in tools:
            methods = list(tool["payload"].get("hunt_methods", []))
            overlay_context = self._collect_tool_context(tool)
            for method in methods:
                method_techniques = method.get("techniques", [])
                matched_techniques = [
                    technique_id
                    for technique_id in method_techniques
                    if technique_id in technique_scores
                ]
                if not matched_techniques:
                    continue

                rendered = self._render_template(
                    method.get("template", ""),
                    indicator_context,
                    overlay_context,
                )
                score = self._score_method(
                    matched_techniques,
                    technique_scores,
                    method,
                    tool,
                )
                safety = self._build_safety_labels(method)
                why = self._build_selection_reason(
                    tool=tool,
                    techniques=matched_techniques,
                    method=method,
                    rendered=rendered,
                )
                ranked_steps.append(
                    (
                        1,
                        score,
                        {
                            "tool_pack": tool["name"],
                            "tool_external_id": tool["external_id"],
                            "title": method.get("title", "Untitled hunt method"),
                            "techniques": matched_techniques,
                            "method_strength": method.get("method_strength", "primary_hunt"),
                            "method_kind": method.get("method_kind", "behavior_hunt"),
                            "strength_reason": method.get(
                                "strength_reason",
                                "No explicit strength rationale was authored for this method.",
                            ),
                            "behavior_focus": method.get(
                                "behavior_focus",
                                method.get("technique_intent", "Validate the mapped ATT&CK behavior."),
                            ),
                            "noise_level": method.get("noise_level", "medium"),
                            "privilege_required": method.get("privilege_required", "unknown"),
                            "time_cost": method.get("time_cost", 1),
                            "data_sources": method.get("data_sources", []),
                            "prerequisites": method.get("prerequisites", []),
                            "supported_ioc_types": method.get("supported_ioc_types", []),
                            "rendered_query": rendered["text"],
                            "unresolved_placeholders": rendered["unresolved"],
                            "ioc_insertions": rendered["insertions"],
                            "why_selected": why,
                            "safety_labels": safety,
                            "enabled": True,
                            "execution_surface": (
                                method.get("execution_surface")
                                or tool["payload"].get("execution_surface")
                                or tool.get("name", "Tool surface")
                            ),
                            "surface_details": (
                                method.get("surface_details")
                                or tool["payload"].get("surface_details", "")
                            ),
                            "service_examples": (
                                method.get("service_examples")
                                or tool["payload"].get("service_examples", [])
                            ),
                            "expectation": method.get(
                                "expectation",
                                "Review hits for evidence aligned to the mapped ATT&CK behavior.",
                            ),
                            "content_origin": "authored_tool_hunt",
                        },
                    )
                )

            for sigma_score, sigma_step in self.sigma_rules.build_translated_steps(
                tool=tool,
                technique_scores=technique_scores,
                selected_families=normalized_sigma_families,
                indicator_context=indicator_context,
                relevance_context=sigma_relevance_context,
            ):
                sigma_rule_ids.add(sigma_step.get("sigma_rule_id", ""))
                ranked_steps.append((0, sigma_score, sigma_step))

        ranked_steps.sort(key=lambda item: (item[0], item[1]), reverse=True)
        steps = [step for _priority, _score, step in ranked_steps]
        for index, step in enumerate(steps, 1):
            if step.get("content_origin") == "sigma_translated":
                sigma_id = str(step.get("sigma_rule_id", "sigma")).replace("-", "_")
                step["step_id"] = f"{step.get('tool_external_id', 'tool')}__sigma__{sigma_id}__{index:03d}"
            else:
                primary_technique = step.get("techniques", ["coverage"])[0].replace(".", "_")
                step["step_id"] = (
                    f"{step.get('tool_external_id', 'tool')}__{primary_technique}__{index:03d}"
                )

        base_summary = {
            "generated_at": utc_now(),
            "mission_name": mission_name or "Generated Hunt Pack",
            "selected_threats": [entity["name"] for entity in threats],
            "selected_tools": [entity["name"] for entity in tools],
            "selected_manual_mitre": [
                technique["external_id"] for technique in manual_techniques
            ],
            "selected_sigma_families": normalized_sigma_families or [],
            "combined_selected_techniques": sorted(technique_scores.keys()),
        }
        summary = HuntPackSummaryService.summarize(base_summary, steps)

        payload = {
            "summary": summary,
            "steps": steps,
            "audit": {
                "threat_ids": threat_ids,
                "tool_ids": tool_ids,
                "manual_technique_ids": manual_technique_ids,
                "selected_sigma_families": normalized_sigma_families or [],
                "sigma_rule_ids": sorted(rule_id for rule_id in sigma_rule_ids if rule_id),
            },
        }

        selected_entity_ids = sorted(
            {
                *(entity["id"] for entity in threats),
                *(entity["id"] for entity in tools),
                *(entity["id"] for entity in manual_techniques),
            }
        )

        return HuntDraft(
            name=mission_name or "Generated Hunt Pack",
            summary=summary,
            payload=payload,
            selected_entity_ids=selected_entity_ids,
        )

    def persist(self, draft: HuntDraft) -> int:
        return self.store.save_hunt_pack(
            name=draft.name,
            status="draft",
            summary=draft.summary,
            payload=draft.payload,
            entity_ids=draft.selected_entity_ids,
        )

    def _merge_manual_techniques(
        self,
        technique_scores: dict[str, dict],
        manual_techniques: list[dict],
    ) -> None:
        for technique in manual_techniques:
            technique_id = technique["external_id"]
            technique_scores[technique_id] = {
                "weight": 1.0,
                "confidence": 1.0,
                "status": "manual",
                "threat": "Manual ATT&CK selection",
            }

    def _collect_technique_scores(self, threats: list[dict]) -> dict[str, dict]:
        technique_scores: dict[str, dict] = {}
        for threat in threats:
            for rel in self.store.list_relationships(
                entity_id=threat["id"], rel_type="USES", direction="out"
            ):
                technique_id = rel["dst_external_id"]
                existing = technique_scores.get(technique_id)
                candidate = {
                    "weight": rel.get("weight", 1.0),
                    "confidence": rel.get("confidence", threat.get("confidence", 0.6)),
                    "status": rel.get("status", "confirmed"),
                    "threat": threat["name"],
                }
                if existing is None or candidate["confidence"] > existing["confidence"]:
                    technique_scores[technique_id] = candidate

            for technique_id in threat["payload"].get("mitre_techniques", []):
                technique_scores.setdefault(
                    technique_id,
                    {
                        "weight": 0.8,
                        "confidence": threat.get("confidence", 0.6),
                        "status": threat.get("status", "active"),
                        "threat": threat["name"],
                    },
                )
        return technique_scores

    def _collect_indicator_context(self, threats: list[dict]) -> dict[str, list[str]]:
        indicators: dict[str, list[str]] = {}

        def add_indicator(indicator_type: str, value: str) -> None:
            key = indicator_type.lower().strip()
            if not key or not value:
                return
            indicators.setdefault(key, [])
            if value not in indicators[key]:
                indicators[key].append(value)

        for threat in threats:
            for indicator in threat["payload"].get("indicators", []):
                add_indicator(indicator.get("type", ""), indicator.get("value", ""))

            related = self.store.get_related_entities(threat["id"]).get("IndicatorSet", [])
            for indicator_ref in related:
                indicator_set = self.store.get_entity(indicator_ref["entity_id"])
                if not indicator_set:
                    continue
                for indicator in indicator_set["payload"].get("indicators", []):
                    add_indicator(indicator.get("type", ""), indicator.get("value", ""))

        return indicators

    def _collect_tool_context(self, tool: dict) -> dict[str, str]:
        overlay_context: dict[str, str] = {}
        for key, value in tool["payload"].get("environment_defaults", {}).items():
            overlay_context[f"<{key.upper()}>"] = str(value)
        for key, value in tool["payload"].get("template_values", {}).items():
            overlay_context[f"<{key.upper()}>"] = str(value)
        return overlay_context

    def _render_template(
        self,
        template: str,
        indicators: dict[str, list[str]],
        overlay_context: dict[str, str],
    ) -> dict:
        rendered = template
        insertions: dict[str, str] = {}
        for placeholder, indicator_types in PLACEHOLDER_TYPES.items():
            replacement = ""
            for indicator_type in indicator_types:
                values = indicators.get(indicator_type, [])
                if values:
                    replacement = ", ".join(values[:5])
                    break
            if replacement:
                rendered = rendered.replace(placeholder, replacement)
                insertions[placeholder] = replacement

        for placeholder, replacement in overlay_context.items():
            if placeholder in rendered:
                rendered = rendered.replace(placeholder, replacement)
                insertions[placeholder] = replacement

        unresolved = sorted(set(re.findall(r"<[A-Z0-9_]+>", rendered)))
        return {
            "text": rendered,
            "insertions": insertions,
            "unresolved": unresolved,
        }

    def _score_method(
        self,
        techniques: list[str],
        technique_scores: dict[str, dict],
        method: dict,
        tool: dict,
    ) -> float:
        technique_score = max(technique_scores[tech]["confidence"] for tech in techniques)
        coverage_bonus = min(1.0, 0.15 * len(techniques))
        method_confidence = float(method.get("confidence", tool.get("confidence", 0.6)))
        noise_score = NOISE_SCORES.get(method.get("noise_level", "medium"), 0.65)
        privilege_score = PRIVILEGE_SCORES.get(
            method.get("privilege_required", "unknown"),
            0.6,
        )
        time_penalty = max(0.3, 1.0 - (self._coerce_time_cost(method.get("time_cost", 1)) * 0.05))
        strength_bonus = 0.12 if method.get("method_strength") == "primary_hunt" else -0.04
        return (
            (technique_score * 0.35)
            + (method_confidence * 0.25)
            + (noise_score * 0.15)
            + (privilege_score * 0.1)
            + (time_penalty * 0.1)
            + coverage_bonus
            + strength_bonus
        )

    @staticmethod
    def _coerce_time_cost(value: Any) -> float:
        if isinstance(value, (int, float)):
            return float(value)
        lowered = str(value or "").strip().lower()
        named_costs = {
            "low": 1.0,
            "short": 1.0,
            "medium": 2.0,
            "moderate": 2.0,
            "high": 4.0,
            "long": 4.0,
        }
        if lowered in named_costs:
            return named_costs[lowered]
        try:
            return float(lowered)
        except ValueError:
            return 2.0

    @staticmethod
    def _build_safety_labels(method: dict) -> list[str]:
        labels: list[str] = []
        noise = method.get("noise_level", "medium")
        privilege = method.get("privilege_required", "unknown")
        if noise == "high":
            labels.append("High-noise")
        if privilege in {"admin", "elevated"}:
            labels.append("Privileged")
        if method.get("disruptive"):
            labels.append("Potentially disruptive")
        if method.get("destructive"):
            labels.append("Potentially destructive")
        if not labels:
            labels.append("Operator review")
        return labels

    @staticmethod
    def _build_selection_reason(
        *,
        tool: dict,
        techniques: list[str],
        method: dict,
        rendered: dict,
    ) -> str:
        reasons = [
            f"Selected because {tool['name']} covers {', '.join(techniques)}."
        ]
        if method.get("method_strength") == "primary_hunt":
            reasons.append("This method is authored as a primary hunt.")
        elif method.get("method_strength") == "supporting_pivot":
            reasons.append("This method is authored as a supporting pivot and should follow stronger primary hunts.")
        execution_surface = method.get("execution_surface") or tool.get("payload", {}).get("execution_surface")
        if execution_surface:
            reasons.append(f"This hunt runs through {execution_surface}.")
        if method.get("strength_reason"):
            reasons.append(method["strength_reason"])
        if rendered["insertions"]:
            reasons.append(
                "IOC/environment placeholders were resolved for "
                + ", ".join(sorted(rendered["insertions"].keys()))
                + "."
            )
        if rendered["unresolved"]:
            reasons.append(
                "Manual review is still needed for "
                + ", ".join(rendered["unresolved"])
                + "."
            )
        if method.get("noise_level") == "low":
            reasons.append("This method is tagged as low-noise.")
        return " ".join(reasons)
