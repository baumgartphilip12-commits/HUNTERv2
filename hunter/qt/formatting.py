"""Formatting helpers shared by Qt views and dialogs."""

from __future__ import annotations

import json
from typing import Any


def json_preview(value: Any, *, limit: int = 12000) -> str:
    """Return a bounded, stable JSON preview string.

    Preview panes should never render unbounded module payloads; large ToolPack
    method catalogs can otherwise make dialogs sluggish.
    """

    try:
        text = json.dumps(value, indent=2, sort_keys=True, default=str)
    except TypeError:
        text = json.dumps(str(value), indent=2)
    if len(text) > limit:
        return text[:limit] + "\n\n... truncated for UI preview ..."
    return text
