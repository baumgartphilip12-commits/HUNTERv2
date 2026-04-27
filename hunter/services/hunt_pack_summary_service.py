"""Shared hunt-pack summary calculations for generation, review, and export."""

from __future__ import annotations

from typing import Any


class HuntPackSummaryService:
    """Compute normalized hunt-pack summary fields from a step list."""

    @staticmethod
    def summarize(
        base_summary: dict[str, Any] | None,
        steps: list[dict[str, Any]],
    ) -> dict[str, Any]:
        base_summary = dict(base_summary or {})
        enabled_steps = [step for step in steps if step.get("enabled", True)]
        selected_scope = set(base_summary.get("combined_selected_techniques", []))
        if not selected_scope:
            selected_scope = set(base_summary.get("covered_techniques", [])) | set(
                base_summary.get("missing_techniques", [])
            )
        covered_techniques = sorted(
            {
                technique_id
                for step in enabled_steps
                for technique_id in step.get("techniques", [])
            }
        )
        coverage_by_tool: dict[str, set[str]] = {}
        for step in enabled_steps:
            coverage_by_tool.setdefault(step.get("tool_pack", "Unknown"), set()).update(
                step.get("techniques", [])
            )

        base_summary["candidate_steps"] = len(steps)
        base_summary["enabled_steps"] = len(enabled_steps)
        base_summary["covered_techniques"] = covered_techniques
        base_summary["missing_techniques"] = sorted(selected_scope - set(covered_techniques))
        base_summary["coverage_by_tool"] = {
            tool: sorted(values) for tool, values in coverage_by_tool.items()
        }
        base_summary["content_origin_counts"] = {
            "authored_tool_hunt": len(
                [step for step in enabled_steps if step.get("content_origin") == "authored_tool_hunt"]
            ),
            "sigma_translated": len(
                [step for step in enabled_steps if step.get("content_origin") == "sigma_translated"]
            ),
        }
        return base_summary
