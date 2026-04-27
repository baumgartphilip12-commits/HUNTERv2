"""Portable runtime path helpers for the HUNTER workspace.

The desktop app stores layered local content in ``modules/`` and keeps the
runtime database under ``data/``.  Those locations need to remain stable even
when the whole repository is copied to another machine or moved to a different
folder.  This module centralises the conversion between repo-relative refs and
the current absolute filesystem paths.
"""

from __future__ import annotations

import os
from pathlib import Path


LAYER_NAMES = ("mitre", "threats", "tools")
PORTABLE_ROOT_ENV = "HUNTER_PORTABLE_ROOT"
OFFLINE_ENV = "HUNTER_OFFLINE"


def project_root(project_dir: str | Path | None = None) -> Path:
    """Return the active HUNTER project root.

    When ``project_dir`` is provided, it wins.  Otherwise the root is derived
    from ``HUNTER_PORTABLE_ROOT`` or this module's location inside ``hunter/``.
    """

    if project_dir is not None:
        return Path(project_dir).expanduser().resolve()
    portable_root = os.environ.get(PORTABLE_ROOT_ENV, "").strip()
    if portable_root:
        return Path(portable_root).expanduser().resolve()
    return Path(__file__).resolve().parent.parent


def offline_mode() -> bool:
    """Return whether runtime repair paths should avoid network installers."""

    return os.environ.get(OFFLINE_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def data_dir(project_dir: str | Path | None = None) -> Path:
    """Return the repo-local ``data/`` directory."""

    return project_root(project_dir) / "data"


def bootstrap_dir(project_dir: str | Path | None = None) -> Path:
    """Return the repo-local bootstrap data directory."""

    return data_dir(project_dir) / "bootstrap"


def bootstrap_bundle_path(project_dir: str | Path | None = None) -> Path:
    """Return the default offline seed knowledge bundle path."""

    return bootstrap_dir(project_dir) / "seed_knowledge_bundle.json"


def modules_root(project_dir: str | Path | None = None) -> Path:
    """Return the repo-local ``modules/`` directory."""

    return project_root(project_dir) / "modules"


def sigma_modules_dir(project_dir: str | Path | None = None) -> Path:
    """Return the repo-local directory for user-managed Sigma YAML sources."""

    return modules_root(project_dir) / "SIGMA"


def export_docx_script_path(project_dir: str | Path | None = None) -> Path:
    """Return the absolute path to the DOCX export script."""

    return project_root(project_dir) / "export_docx.js"


def runtime_dir(project_dir: str | Path | None = None) -> Path:
    """Return the portable runtime directory used by offline bundles."""

    return project_root(project_dir) / "runtime"


def bundled_node_path(project_dir: str | Path | None = None) -> Path:
    """Return the expected bundled Windows Node.js executable path."""

    return runtime_dir(project_dir) / "node" / "node.exe"


def vendor_root(project_dir: str | Path | None = None) -> Path:
    """Return the repo-local ``vendor/`` directory."""

    return project_root(project_dir) / "vendor"


def vendor_python_dir(project_dir: str | Path | None = None) -> Path:
    """Return the repo-local Python vendor directory."""

    return vendor_root(project_dir) / "python"


def vendor_requirements_path(project_dir: str | Path | None = None) -> Path:
    """Return the committed repo-local Python vendor manifest."""

    return vendor_root(project_dir) / "requirements.txt"


def normalize_repo_ref(value: str | Path) -> str:
    """Normalise a stored repo-relative reference into a portable form."""

    text = str(value or "").strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    while text.startswith("/"):
        text = text[1:]
    return text


def resolve_repo_path(path_ref: str | Path, project_dir: str | Path | None = None) -> Path:
    """Resolve a repo-relative or absolute path against the current project."""

    path = Path(path_ref)
    if path.is_absolute():
        return path.resolve()
    return (project_root(project_dir) / Path(normalize_repo_ref(path))).resolve()


def repo_relative_path(path: str | Path, project_dir: str | Path | None = None) -> str:
    """Return a project-relative path for display or portable persistence."""

    resolved = Path(path).resolve()
    root = project_root(project_dir)
    try:
        relative = resolved.relative_to(root)
    except ValueError:
        relative = Path(os.path.relpath(resolved, root))
    return normalize_repo_ref(relative)


def layered_module_dirs(project_dir: str | Path | None = None) -> dict[str, Path]:
    """Return the canonical layered module directories for the active project."""

    root = modules_root(project_dir)
    return {
        "root": root,
        "mitre": root / "mitre",
        "threats": root / "threats",
        "tools": root / "tools",
    }


def ensure_layered_module_dirs(project_dir: str | Path | None = None) -> dict[str, Path]:
    """Create the layered module directory structure when it is missing."""

    dirs = layered_module_dirs(project_dir)
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    sigma_modules_dir(project_dir).mkdir(parents=True, exist_ok=True)
    return dirs


def layered_source_config(project_dir: str | Path | None = None) -> dict[str, str]:
    """Return the portable layered-source configuration stored in SQLite."""

    _ = project_root(project_dir)
    return {
        "root": "modules",
        "threats_dir": "modules/threats",
        "tools_dir": "modules/tools",
        "mitre_dir": "modules/mitre",
    }


def resolve_layered_source_paths(
    config: dict | None,
    project_dir: str | Path | None = None,
) -> dict[str, Path]:
    """Resolve layered-source config values against the current project root."""

    resolved_config = layered_source_config(project_dir)
    config = config or {}
    return {
        "root": resolve_repo_path(config.get("root") or resolved_config["root"], project_dir),
        "threats": resolve_repo_path(config.get("threats_dir") or resolved_config["threats_dir"], project_dir),
        "tools": resolve_repo_path(config.get("tools_dir") or resolved_config["tools_dir"], project_dir),
        "mitre": resolve_repo_path(config.get("mitre_dir") or resolved_config["mitre_dir"], project_dir),
    }


def _layered_tail_from_path(path: Path) -> str | None:
    """Extract ``threats/foo.json``-style refs from an arbitrary file path."""

    parts = list(path.parts)
    lowered = [part.lower() for part in parts]
    for layer in LAYER_NAMES:
        if layer in lowered:
            layer_index = lowered.index(layer)
            tail = Path(*parts[layer_index:])
            if tail.suffix.lower() == ".json":
                return normalize_repo_ref(tail)
    if len(parts) >= 2 and parts[-2].lower() in LAYER_NAMES and path.suffix.lower() == ".json":
        return normalize_repo_ref(Path(parts[-2]) / parts[-1])
    return None


def relative_module_ref(path: str | Path, project_dir: str | Path | None = None) -> str:
    """Return a portable ``threats/foo.json`` ref for a layered module file."""

    resolved = Path(path).resolve()
    root = modules_root(project_dir)
    try:
        relative = resolved.relative_to(root)
        return normalize_repo_ref(relative)
    except ValueError:
        tail = _layered_tail_from_path(resolved)
        if tail:
            return tail
        raise


def layered_module_path(relative_ref: str | Path, project_dir: str | Path | None = None) -> Path:
    """Resolve a portable layered module ref against the current project."""

    ref = normalize_repo_ref(relative_ref)
    return (modules_root(project_dir) / Path(ref)).resolve()


def layered_module_target_path(
    layer: str,
    external_id: str,
    project_dir: str | Path | None = None,
) -> Path:
    """Return the canonical JSON file path for a layered module."""

    dirs = layered_module_dirs(project_dir)
    if layer not in dirs:
        raise ValueError(f"Unsupported layered module directory: {layer}")
    return (dirs[layer] / f"{external_id}.json").resolve()


def infer_layered_ref(
    *,
    entity_type: str = "",
    external_id: str = "",
    layer: str = "",
    source_ref: str = "",
    source_url: str = "",
    project_dir: str | Path | None = None,
) -> str:
    """Infer the canonical layered ref from stored legacy path fields."""

    normalized_ref = normalize_repo_ref(source_ref)
    if normalized_ref:
        ref_path = Path(normalized_ref)
        if ref_path.is_absolute() or ref_path.suffix.lower() == ".json":
            try:
                return relative_module_ref(ref_path, project_dir)
            except Exception:
                tail = _layered_tail_from_path(ref_path)
                if tail:
                    return tail
        if ref_path.parts and ref_path.parts[0].lower() == "modules":
            return normalize_repo_ref(Path(*ref_path.parts[1:]))
        if ref_path.parts and ref_path.parts[0].lower() in LAYER_NAMES:
            return normalize_repo_ref(ref_path)

    if source_url:
        url_path = Path(source_url)
        if url_path.suffix.lower() == ".json":
            try:
                return relative_module_ref(url_path, project_dir)
            except Exception:
                tail = _layered_tail_from_path(url_path)
                if tail:
                    return tail

    inferred_layer = layer
    if not inferred_layer:
        inferred_layer = {
            "ThreatProfile": "threats",
            "ToolPack": "tools",
            "MitreTechnique": "mitre",
        }.get(entity_type, "")
    if inferred_layer and external_id:
        return normalize_repo_ref(Path(inferred_layer) / f"{external_id}.json")
    return normalized_ref
