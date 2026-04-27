"""Disk helpers for layered v2 module files.

The active runtime uses the layered directories under ``modules/threats``,
``modules/tools``, and ``modules/mitre``.  This module is a thin wrapper around
:mod:`hunter.runtime_paths` so callers can work with the current project root
instead of baking absolute paths into SQLite or the UI.
"""

from __future__ import annotations

import json
from pathlib import Path

from hunter.runtime_paths import ensure_layered_module_dirs as ensure_runtime_layered_module_dirs
from hunter.runtime_paths import layered_module_dirs, layered_module_target_path


def get_layered_modules_dirs(project_dir: str | Path | None = None) -> dict[str, str]:
    """Return the layered module directories as absolute paths."""

    return {
        name: str(path)
        for name, path in layered_module_dirs(project_dir).items()
    }


def ensure_layered_module_dirs(project_dir: str | Path | None = None) -> dict[str, str]:
    """Create the layered module directories and return their absolute paths."""

    return {
        name: str(path)
        for name, path in ensure_runtime_layered_module_dirs(project_dir).items()
    }


def list_layered_module_files(
    layer: str | None = None,
    project_dir: str | Path | None = None,
) -> list[str]:
    """Return JSON files from the layered v2 module directories."""

    dirs = layered_module_dirs(project_dir)
    layers = [layer] if layer else ["mitre", "threats", "tools"]
    files: list[str] = []
    for layer_name in layers:
        directory = dirs.get(layer_name)
        if directory is None or not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.json")):
            files.append(str(path.resolve()))
    return files


def has_layered_module_files(project_dir: str | Path | None = None) -> bool:
    """Return ``True`` when any layered v2 module file exists on disk."""

    return bool(list_layered_module_files(project_dir=project_dir))


def save_layered_module_json(
    layer: str,
    external_id: str,
    payload: dict,
    project_dir: str | Path | None = None,
) -> str:
    """Write a layered module JSON file and return its absolute path."""

    target = layered_module_target_path(layer, external_id, project_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return str(target)
