"""Shared persistence constants and helpers for HUNTER models."""

from __future__ import annotations

from datetime import datetime, timezone


ENTITY_TYPES = (
    "MitreTechnique",
    "ThreatProfile",
    "ToolPack",
    "SigmaRule",
    "AddonPack",
    "IndicatorSet",
    "SyncSource",
)


def utc_now() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
