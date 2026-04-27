"""Compatibility helpers for authored tool modules in ``modules/tools``.

The old tool compiler/assembler pipeline has been retired.  ``modules/tools``
is now the only source of truth for tool content, and layered sync reads those
JSON files directly.  This module survives as a tiny compatibility shim for
normalizing newer method metadata when legacy local variants are edited.
"""

from __future__ import annotations

import json
from typing import Any


class ToolCatalogCompiler:
    """Legacy compatibility wrapper for tool-method metadata normalization.

    The class name stays stable because the editor save path already imports it.
    It no longer compiles, assembles, or writes tool packs.
    """

    @classmethod
    def ensure_method_metadata(cls, method: dict[str, Any]) -> dict[str, Any]:
        """Backfill method metadata required by modern tool modules.

        Older saved tool variants may predate the explicit method truthfulness
        fields.  When such a variant is edited again, HUNTER normalizes the
        method into the current ``modules/tools`` schema before validation.
        """

        authored = json.loads(json.dumps(method))
        title = str(authored.get("title", "")).lower()
        template = str(authored.get("template", "")).strip()
        if "method_strength" not in authored:
            authored["method_strength"] = cls._infer_method_strength(title)
        if "method_kind" not in authored:
            authored["method_kind"] = cls._infer_method_kind(
                title,
                authored.get("output_format", ""),
            )
        if "strength_reason" not in authored:
            authored["strength_reason"] = cls._infer_strength_reason(
                authored["method_strength"],
                authored["method_kind"],
            )
        if "behavior_focus" not in authored:
            authored["behavior_focus"] = (
                str(authored.get("technique_intent", "")).strip()
                or str(authored.get("coverage_reason", "")).strip()
                or str(authored.get("expectation", "")).strip()
                or cls._first_heading_or_line(template)
                or "Validate the ATT&CK behavior through the tool-native execution surface."
            )
        return authored

    @staticmethod
    def _infer_method_strength(title: str) -> str:
        supporting_tokens = (
            "ioc pivot",
            "metadata pivot",
            "visibility gap",
            "corroboration",
        )
        if any(token in title for token in supporting_tokens):
            return "supporting_pivot"
        return "primary_hunt"

    @staticmethod
    def _infer_method_kind(title: str, output_format: str) -> str:
        lowered_output = str(output_format or "").lower()
        if "ioc pivot" in title:
            return "ioc_pivot"
        if "metadata pivot" in title:
            return "metadata_pivot"
        if "visibility gap" in title:
            return "visibility_gap"
        if "corroboration" in title:
            return "corroboration"
        if "stream follow" in title or "display filter" in title or lowered_output == "wireshark_filter":
            return "stream_validation"
        if lowered_output in {"workflow", "powershell", "eql", "vql"}:
            return "workflow"
        if lowered_output in {"spl", "esql", "kql", "sql", "cloudwatch_insights", "arkime_query", "shodan_query"}:
            return "behavior_hunt"
        return "behavior_hunt"

    @staticmethod
    def _infer_strength_reason(method_strength: str, method_kind: str) -> str:
        if method_strength == "supporting_pivot":
            return (
                "Supporting pivot retained because it helps analysts move from a lead into adjacent evidence, "
                "but it should not outrank stronger behavior-led hunts."
            )
        reason_by_kind = {
            "behavior_hunt": "Primary hunt because the method directly targets behavior the tool can surface well.",
            "workflow": "Primary hunt because the tool is best used as a guided operator workflow rather than a single query.",
            "stream_validation": "Primary hunt because the method validates packet or stream behavior directly in the tool.",
        }
        return reason_by_kind.get(
            method_kind,
            "Primary hunt because the method aligns directly to the technique through the tool's native workflow.",
        )

    @staticmethod
    def _first_heading_or_line(template: str) -> str:
        for line in str(template or "").splitlines():
            cleaned = line.strip().lstrip("#").strip()
            if cleaned and ":" not in cleaned:
                return cleaned
        return ""
