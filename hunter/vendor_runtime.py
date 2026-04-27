"""Repo-local Python vendor bootstrap and install helpers.

HUNTER can run from a copied project folder, so optional Python dependencies are
installed into ``vendor/python`` instead of a global environment.  The helpers
below keep that directory first on ``sys.path`` and provide UI-safe prompts for
repairing missing packages.
"""

from __future__ import annotations

import importlib
import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from hunter.runtime_paths import offline_mode, project_root, vendor_python_dir, vendor_requirements_path, vendor_root


KNOWN_PACKAGE_IMPORTS = {
    "pyyaml": "yaml",
    "pysigma": "sigma",
    "pysigma-backend-elasticsearch": "sigma.backends.elasticsearch",
    "sigma-cli": "sigma.cli",
    "pyside6": "PySide6",
}


class VendorDependencyError(RuntimeError):
    """Raised when an optional repo-local dependency is unavailable."""


def bootstrap_vendor_path(project_dir: str | Path | None = None) -> Path:
    """Insert the repo-local Python vendor directory at the front of ``sys.path``."""

    vendor_python = vendor_python_dir(project_dir).resolve()
    if vendor_python.is_dir():
        vendor_text = str(vendor_python)
        if vendor_text in sys.path:
            sys.path.remove(vendor_text)
        sys.path.insert(0, vendor_text)
    return vendor_python


def duplicate_vendor_distributions(project_dir: str | Path | None = None) -> dict[str, list[str]]:
    """Return duplicate dist-info package names in the repo-local vendor runtime.

    Duplicate distributions can make import/version resolution unpredictable,
    so repo-integrity tests use this as an early warning before startup does.
    """

    vendor_python = vendor_python_dir(project_dir)
    if not vendor_python.exists():
        return {}
    by_name: dict[str, list[str]] = {}
    for dist_info in sorted(vendor_python.glob("*.dist-info")):
        stem = dist_info.name.removesuffix(".dist-info")
        package_name = stem.rsplit("-", 1)[0].replace("_", "-").lower()
        by_name.setdefault(package_name, []).append(dist_info.name)
    return {
        name: entries
        for name, entries in sorted(by_name.items())
        if len(entries) > 1
    }


def ensure_vendor_packages(
    *,
    project_dir: str | Path | None = None,
    interactive: bool = True,
    parent: Any | None = None,
) -> dict[str, Any]:
    """Ensure required repo-local Python vendor packages are present.

    Non-interactive callers receive status only.  Interactive callers may prompt
    and run pip into ``vendor/python`` but never install globally.
    """

    status = _vendor_status(project_dir)
    status["installed_packages"] = []
    status["declined"] = False
    status["prompted"] = False
    status["install_attempted"] = False
    if status.get("manifest_missing"):
        if interactive:
            _notify_user(
                "Python Vendor Manifest Missing",
                "HUNTER is missing the committed repo-local Python vendor manifest.\n\n"
                f"Expected file:\n  {status['requirements_path']}\n\n"
                "Restore vendor/requirements.txt to enable startup dependency checks.",
            )
        return status
    if status["ready"] or not interactive:
        return status
    if offline_mode():
        status["offline"] = True
        status["error"] = (
            "HUNTER is running from an offline bundle and cannot repair Python "
            "packages with pip. Rebuild the offline bundle with vendor/python "
            "included, then copy the rebuilt bundle to this system."
        )
        _notify_user("Offline Vendor Packages Missing", status["error"])
        return status

    install_message = (
        "HUNTER uses repo-local Python packages for the Qt UI, portable Sigma sync, "
        "and local Elastic translation.\n\n"
        f"Missing packages: {', '.join(status['missing_packages'])}\n\n"
        f"HUNTER will run:\n  {sys.executable} -m pip install --upgrade --target vendor/python -r vendor/requirements.txt\n\n"
        f"in:\n  {status['project_dir']}\n\n"
        "Install them now?"
    )
    status["prompted"] = True
    if not _ask_yes_no("Install Python Vendor Packages", install_message):
        status["declined"] = True
        _notify_user(
            "Python Vendor Packages Missing",
            "HUNTER will keep running, but the Qt shell, Sigma sync, or official local Elastic translator may stay limited until repo-local Python vendor packages are installed.",
        )
        return status

    install_result = _run_pip_install(
        project_dir=status["project_dir"],
        vendor_python=status["vendor_python"],
        requirements_path=status["requirements_path"],
    )
    status["install_attempted"] = True
    if not install_result["success"]:
        status["error"] = install_result["error"]
        _notify_user(
            "Python Vendor Install Failed",
            "HUNTER will keep running, but the Qt shell, Sigma sync, or official local Elastic translator may stay limited until repo-local Python vendor packages are installed.\n\n"
            f"Error:\n{install_result['error'][:800]}",
        )
        return status

    bootstrap_vendor_path(status["project_dir"])
    refreshed = _vendor_status(status["project_dir"])
    refreshed.update(
        {
            "installed_packages": install_result["installed_packages"],
            "declined": False,
            "prompted": True,
            "install_attempted": True,
        }
    )
    return refreshed


def require_optional_dependency(
    import_name: str,
    *,
    package_name: str,
    purpose: str,
    project_dir: str | Path | None = None,
):
    """Import an optional dependency with a user-facing error message."""

    bootstrap_vendor_path(project_dir)
    try:
        return importlib.import_module(import_name)
    except ModuleNotFoundError as exc:
        root_name = import_name.split(".", 1)[0]
        if exc.name not in {root_name, import_name}:
            raise
        raise VendorDependencyError(
            f"{package_name} is required for {purpose}. "
            "Use Settings / Sync -> Install/Repair Python Vendor Packages, "
            "or restart HUNTER and accept the startup install prompt."
        ) from exc


def _vendor_status(project_dir: str | Path | None = None) -> dict[str, Any]:
    """Probe the committed vendor manifest and importability from vendor/python."""

    root = project_root(project_dir)
    vendor_dir = vendor_root(root)
    vendor_python = bootstrap_vendor_path(root)
    requirements_path = vendor_requirements_path(root)
    manifest_missing = not requirements_path.exists()
    specs = _read_requirements(requirements_path)
    missing_packages: list[str] = []
    missing_modules: list[str] = []
    probe_errors: list[str] = []

    if not manifest_missing:
        for spec in specs:
            package_name = _package_name_from_spec(spec)
            import_name = _import_name_for_package(package_name)
            try:
                module_exists = _vendor_module_exists(import_name, vendor_python)
            except Exception as exc:
                module_exists = False
                probe_errors.append(f"{import_name}: {exc}")
            if not module_exists:
                missing_packages.append(package_name)
                missing_modules.append(import_name)

    error = ""
    if manifest_missing:
        error = (
            "Missing committed repo-local Python vendor manifest "
            "(vendor/requirements.txt): "
            f"{requirements_path}"
        )
    elif probe_errors:
        error = "Vendor runtime probe failed: " + "; ".join(probe_errors[:3])

    return {
        "ready": (not manifest_missing) and (not missing_packages),
        "project_dir": str(root),
        "vendor_dir": str(vendor_dir),
        "vendor_python": str(vendor_python),
        "requirements_path": str(requirements_path),
        "required_specs": specs,
        "missing_packages": missing_packages,
        "missing_modules": missing_modules,
        "error": error,
        "manifest_missing": manifest_missing,
        "offline": offline_mode(),
    }


def _read_requirements(path: Path) -> list[str]:
    if not path.exists():
        return []
    specs: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        specs.append(line)
    return specs


def _package_name_from_spec(spec: str) -> str:
    match = re.match(r"([A-Za-z0-9_.-]+)", spec.strip())
    return match.group(1) if match else spec.strip()


def _import_name_for_package(package_name: str) -> str:
    key = package_name.strip().lower()
    return KNOWN_PACKAGE_IMPORTS.get(key, key.replace("-", "_"))


def _vendor_module_exists(import_name: str, vendor_python: Path) -> bool:
    """Check that a module resolves from vendor/python, not the user environment."""

    if not vendor_python.exists():
        return False
    vendor_root = vendor_python.resolve()
    vendor_text = str(vendor_root)
    if sys.path[:1] != [vendor_text]:
        while vendor_text in sys.path:
            sys.path.remove(vendor_text)
        sys.path.insert(0, vendor_text)

    cached_modules: dict[str, Any] = {}
    prefix = ""
    for part in import_name.split("."):
        prefix = part if not prefix else f"{prefix}.{part}"
        if prefix in sys.modules:
            cached_modules[prefix] = sys.modules.pop(prefix)
    try:
        spec = importlib.util.find_spec(import_name)
    finally:
        sys.modules.update(cached_modules)
    if spec is None:
        return False
    return _spec_is_from_vendor(spec, vendor_root)


def _spec_is_from_vendor(spec, vendor_root: Path) -> bool:
    locations = getattr(spec, "submodule_search_locations", None)
    if locations is not None:
        return any(_path_is_within_vendor(Path(location), vendor_root) for location in locations)

    origin = getattr(spec, "origin", None)
    if not origin or origin in {"built-in", "frozen"}:
        return False
    return _path_is_within_vendor(Path(origin), vendor_root)


def _path_is_within_vendor(candidate: Path, vendor_root: Path) -> bool:
    try:
        candidate.resolve().relative_to(vendor_root)
        return True
    except Exception:
        return False


def _notify_user(title: str, message: str) -> None:
    print(f"{title}: {message}", file=sys.stderr)
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, message, title, 0x30)
    except Exception:
        return


def _ask_yes_no(title: str, message: str) -> bool:
    if sys.platform == "win32":
        try:
            import ctypes

            return ctypes.windll.user32.MessageBoxW(None, message, title, 0x24) == 6
        except Exception:
            pass
    if sys.stdin is not None and sys.stdin.isatty():
        answer = input(f"{title}\n{message}\nInstall now? [y/N] ")
        return answer.strip().lower() in {"y", "yes"}
    return False


def _run_pip_install(
    *,
    project_dir: str,
    vendor_python: str,
    requirements_path: str,
) -> dict[str, Any]:
    """Install manifest packages into vendor/python and return a status dict."""

    Path(vendor_python).mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {"success": False, "installed_packages": [], "error": ""}

    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--upgrade",
        "--target",
        vendor_python,
        "-r",
        requirements_path,
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=project_dir,
            timeout=900,
            check=False,
        )
        if completed.returncode == 0:
            result["success"] = True
            result["installed_packages"] = [
                _package_name_from_spec(spec)
                for spec in _read_requirements(Path(requirements_path))
            ]
        else:
            result["error"] = completed.stderr or completed.stdout or "pip install failed."
    except subprocess.TimeoutExpired:
        result["error"] = "pip install timed out after 900 seconds."
    except Exception as exc:
        result["error"] = str(exc)
    return result
