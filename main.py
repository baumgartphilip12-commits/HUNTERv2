"""
HUNTER v2 - Layered Threat-Hunting Knowledge Graph
Entry point. Run with:  python main.py
"""

import sys
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=ResourceWarning)
warnings.filterwarnings("ignore", category=UserWarning)

from hunter.vendor_runtime import ensure_vendor_packages


def _startup_error(title: str, message: str) -> None:
    print(f"{title}: {message}", file=sys.stderr)
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, message, title, 0x10)
    except Exception:
        return


def main() -> None:
    ensure_vendor_packages(interactive=True)

    try:
        from hunter.qt_app import run
    except ModuleNotFoundError as exc:
        if exc.name not in {"PySide6", "shiboken6"}:
            raise
        _startup_error(
            "Missing Qt Runtime",
            "PySide6 is required to launch HUNTER's desktop UI.\n\n"
            "Install repo-local dependencies from vendor/requirements.txt, then restart HUNTER.",
        )
        raise SystemExit(1) from exc

    raise SystemExit(run())


if __name__ == "__main__":
    main()
