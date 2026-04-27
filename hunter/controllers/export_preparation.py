"""Pure export-preparation helpers for hunt packs and questionnaires.

UI code calls these helpers before writing JSON or handing data to the DOCX
runtime.  Keeping sanitization pure makes export behavior testable without file
dialogs or Node.js.
"""

from __future__ import annotations

import json
from datetime import datetime

from hunter.services.hunt_pack_summary_service import HuntPackSummaryService


class HuntPackExportPreparation:
    """Pure shaping helpers shared by UI export flows."""

    @staticmethod
    def summarize_enabled_steps(summary: dict, steps: list[dict]) -> dict:
        return HuntPackSummaryService.summarize(summary, steps)

    @classmethod
    def sanitize_hunt_pack(cls, hunt_pack: dict, *, enabled_only: bool = True) -> dict:
        """Return an export-safe copy, optionally filtering disabled steps."""

        cloned = json.loads(json.dumps(hunt_pack))
        payload = cloned.get("payload", {})
        steps = payload.get("steps", [])
        sanitized_steps: list[dict] = []
        for step in steps:
            step.pop("score", None)
            step.pop("confidence", None)
            if enabled_only and not step.get("enabled", True):
                continue
            sanitized_steps.append(step)
        payload["steps"] = sanitized_steps
        cloned["summary"] = cls.summarize_enabled_steps(
            cloned.get("summary", {}),
            sanitized_steps,
        )
        payload["summary"] = cloned["summary"]
        cloned["payload"] = payload
        return cloned

    @staticmethod
    def initial_hunt_pack_name(hunt_pack: dict) -> str:
        """Choose the default filename stem from mission summary or pack name."""

        summary = hunt_pack.get("summary", {})
        return (
            summary.get("mission_name")
            or hunt_pack.get("name")
            or "generated_hunt_pack"
        )

    @classmethod
    def build_hunt_pack_report_lines(cls, hunt_pack: dict) -> list[str]:
        hunt_pack = cls.sanitize_hunt_pack(hunt_pack)
        summary = hunt_pack.get("summary", {})
        payload = hunt_pack.get("payload", {})
        steps = payload.get("steps", hunt_pack.get("payload", {}).get("steps", []))
        lines = [
            "=" * 80,
            f"HUNTER v2 HUNT PACK REPORT: {summary.get('mission_name', hunt_pack.get('name', 'Draft'))}",
            f"Generated: {summary.get('generated_at', datetime.now().isoformat())}",
            "",
            "SELECTIONS",
            f"Threats: {', '.join(summary.get('selected_threats', [])) or 'None'}",
            f"Tools: {', '.join(summary.get('selected_tools', [])) or 'None'}",
            f"Legacy Add-ons: {', '.join(summary.get('selected_addons', [])) or 'None'}",
            "",
            "MITRE COVERAGE",
            f"Covered: {', '.join(summary.get('covered_techniques', [])) or 'None'}",
            f"Gaps: {', '.join(summary.get('missing_techniques', [])) or 'None'}",
            "=" * 80,
            "",
        ]

        for index, step in enumerate(steps, 1):
            lines.extend(
                [
                    f"[{index:02d}] {step.get('title', 'Untitled step')}",
                    f"Tool Pack: {step.get('tool_pack', 'Unknown')}",
                    f"Techniques: {', '.join(step.get('techniques', [])) or 'None'}",
                    f"Noise: {step.get('noise_level', 'unknown')}  |  Privilege: {step.get('privilege_required', 'unknown')}",
                    f"Safety: {', '.join(step.get('safety_labels', [])) or 'Operator review'}",
                    f"Why Selected: {step.get('why_selected', '')}",
                    f"Expected Result: {step.get('expectation', '')}",
                    "Rendered Query / Workflow:",
                    step.get("rendered_query", ""),
                ]
            )
            unresolved = step.get("unresolved_placeholders", [])
            if unresolved:
                lines.append("Unresolved Placeholders: " + ", ".join(unresolved))
            sigma_ioc_guidance = step.get("sigma_ioc_guidance", [])
            if sigma_ioc_guidance:
                lines.append("Sigma IOC Guidance: " + "; ".join(sigma_ioc_guidance))
            prerequisites = step.get("prerequisites", [])
            if prerequisites:
                lines.append("Prerequisites: " + "; ".join(prerequisites))
            lines.append("-" * 80)
        return lines

    @staticmethod
    def build_questionnaire_lines(plan_modules: list[dict]) -> list[str]:
        all_q = [
            (m["name"], q)
            for m in plan_modules
            for q in m.get("questions", [])
        ]
        lines = [
            "=" * 70,
            "  HUNTER — THREAT HUNT PRE-ENGAGEMENT QUESTIONNAIRE",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            f"  Modules in Plan : {len(plan_modules)}",
            f"  Total Questions : {len(all_q)}",
            "=" * 70, "",
            "  INSTRUCTIONS:",
            "  Complete this questionnaire with the mission partner prior to",
            "  or at the outset of the threat hunt engagement.  Accurate and",
            "  complete responses ensure hunt actions are performed safely,",
            "  within authorized scope, and with appropriate tooling available.",
            "", "=" * 70, "",
        ]

        q_num = 1
        cur_mod = None
        for mod_name, question in all_q:
            if mod_name != cur_mod:
                cur_mod = mod_name
                lines += ["", f"  ── {mod_name.upper()} ──", "  " + "─" * 62, ""]
            lines += [
                f"  Q{q_num:02d}. {question}", "",
                "        Answer:",
                "        " + "_" * 58, "",
                "        Notes / Evidence:",
                "        " + "_" * 58,
                "        " + "_" * 58, "",
                "  " + "·" * 66, "",
            ]
            q_num += 1

        lines += [
            "", "=" * 70,
            "  END OF QUESTIONNAIRE  —  HUNTER Threat Hunt Plan Builder",
            "=" * 70,
        ]
        return lines
