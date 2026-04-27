"""Build a Windows offline HUNTER release bundle.

The builder keeps development checkouts clean by copying generated dependency
folders into ``dist/`` only when a release bundle is produced.
"""

from __future__ import annotations

import argparse
import json
import shutil
import zipfile
from pathlib import Path
from typing import Any

from hunter.models.knowledge_store import KnowledgeStore
from hunter.runtime_paths import project_root


DEFAULT_BUNDLE_NAME = "HUNTER-v2.1-offline-win64"
EXCLUDED_TOP_LEVEL_DIRS = {
    ".git",
    ".pytest_cache",
    "dist",
    "data",
    "node_modules",
}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}
EXCLUDED_FILES = {
    "generated_hunt_pack_report.docx",
    "mission_partner_hunt_pack_report.docx",
    "_tmp_hunt_plan.json",
}


def build_offline_bundle(
    *,
    project_root_path: str | Path | None = None,
    output_path: str | Path | None = None,
    include_current_knowledge: bool = False,
    python_embed_zip: str | Path | None = None,
    node_zip: str | Path | None = None,
) -> dict[str, Any]:
    """Create the offline bundle directory and zip archive."""

    root = project_root(project_root_path)
    output = Path(output_path or (root / "dist" / DEFAULT_BUNDLE_NAME)).resolve()
    if output.exists():
        shutil.rmtree(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True)

    _copy_project_tree(root, output)
    _copy_optional_tree(root / "vendor" / "python", output / "vendor" / "python")
    _copy_optional_tree(root / "node_modules", output / "node_modules")
    _extract_optional_zip(python_embed_zip, output / "runtime" / "python")
    _extract_optional_zip(node_zip, output / "runtime" / "node")
    _write_launcher(output)
    seed_path = _write_seed_bundle(root, output, include_current_knowledge)

    manifest = {
        "bundle_name": output.name,
        "version": "2.1",
        "platform": "windows",
        "offline": True,
        "seed_bundle": str(seed_path.relative_to(output)).replace("\\", "/"),
        "includes_vendor_python": (output / "vendor" / "python").exists(),
        "includes_node_modules": (output / "node_modules").exists(),
        "includes_bundled_node": (output / "runtime" / "node" / "node.exe").exists(),
    }
    manifest_path = output / "offline_bundle_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    zip_path = _zip_bundle(output)
    manifest["zip_path"] = str(zip_path)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest


def _copy_project_tree(root: Path, output: Path) -> None:
    for item in root.iterdir():
        if _should_exclude(item, root):
            continue
        target = output / item.name
        if item.is_dir():
            shutil.copytree(item, target, ignore=_copytree_ignore)
        else:
            shutil.copy2(item, target)


def _copytree_ignore(directory: str, names: list[str]) -> set[str]:
    base = Path(directory)
    ignored: set[str] = set()
    for name in names:
        if _should_exclude(base / name, base):
            ignored.add(name)
    return ignored


def _should_exclude(path: Path, root: Path) -> bool:
    if path.name in EXCLUDED_FILES or path.suffix.lower() in EXCLUDED_SUFFIXES:
        return True
    parts = path.parts
    if "__pycache__" in parts:
        return True
    try:
        relative = path.relative_to(root)
        relative_parts = relative.parts
    except ValueError:
        relative_parts = path.parts
    if relative_parts[:1] and relative_parts[0] in EXCLUDED_TOP_LEVEL_DIRS:
        return True
    return len(relative_parts) >= 2 and relative_parts[0] == "vendor" and relative_parts[1] == "python"


def _copy_optional_tree(source: Path, target: Path) -> None:
    if source.exists():
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(source, target, ignore=_copytree_ignore)


def _extract_optional_zip(zip_ref: str | Path | None, target: Path) -> None:
    if not zip_ref:
        return
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_ref) as archive:
        archive.extractall(target)


def _write_launcher(output: Path) -> None:
    launcher = """@echo off
setlocal
set "HUNTER_PORTABLE_ROOT=%~dp0"
set "HUNTER_OFFLINE=1"
if exist "%HUNTER_PORTABLE_ROOT%runtime\\python\\python.exe" (
  set "PATH=%HUNTER_PORTABLE_ROOT%runtime\\python;%PATH%"
  "%HUNTER_PORTABLE_ROOT%runtime\\python\\python.exe" "%HUNTER_PORTABLE_ROOT%main.py"
) else (
  python "%HUNTER_PORTABLE_ROOT%main.py"
)
endlocal
"""
    (output / "run_hunter.bat").write_text(launcher, encoding="utf-8")


def _write_seed_bundle(root: Path, output: Path, include_current_knowledge: bool) -> Path:
    seed_path = output / "data" / "bootstrap" / "seed_knowledge_bundle.json"
    seed_path.parent.mkdir(parents=True, exist_ok=True)
    if include_current_knowledge:
        store = KnowledgeStore.open_bootstrapped(str(root))
        try:
            store.export_knowledge_bundle(str(seed_path))
        finally:
            store.close()
        _mark_online_sources_optional(seed_path)
    else:
        seed_path.write_text(
            json.dumps(
                {
                    "metadata": {"project": "HUNTER v2", "stats": {}},
                    "sources": [],
                    "entities": [],
                    "relationships": [],
                    "hunt_packs": [],
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
    return seed_path


def _mark_online_sources_optional(seed_path: Path) -> None:
    bundle = json.loads(seed_path.read_text(encoding="utf-8"))
    for source in bundle.get("sources", []):
        config = source.get("config", {}) if isinstance(source.get("config"), dict) else {}
        if source.get("connector") == "mitre_attack" and not any(config.get(key) for key in ("bundle_file", "bundle_path")):
            source["enabled"] = False
            source["health"] = "offline_optional"
        if source.get("connector") == "sigmahq_rules" and not any(config.get(key) for key in ("archive_path", "rules_dir", "rules_file")):
            source["enabled"] = False
            source["health"] = "offline_optional"
    seed_path.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")


def _zip_bundle(output: Path) -> Path:
    zip_path = output.with_suffix(".zip")
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(output.rglob("*")):
            if path.is_file():
                archive.write(path, output.name / path.relative_to(output))
    return zip_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the HUNTER v2.1 Windows offline bundle.")
    parser.add_argument("--project-root", default=None)
    parser.add_argument("--output", default=None)
    parser.add_argument("--include-current-knowledge", action="store_true")
    parser.add_argument("--python-embed-zip", default=None)
    parser.add_argument("--node-zip", default=None)
    args = parser.parse_args()
    manifest = build_offline_bundle(
        project_root_path=args.project_root,
        output_path=args.output,
        include_current_knowledge=args.include_current_knowledge,
        python_embed_zip=args.python_embed_zip,
        node_zip=args.node_zip,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
