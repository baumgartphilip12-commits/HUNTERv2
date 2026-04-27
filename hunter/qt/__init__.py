"""PySide6 desktop shell for HUNTER."""

from __future__ import annotations

__all__ = ["HunterMainWindow"]


def __getattr__(name: str):
    if name == "HunterMainWindow":
        from hunter.qt.main_window import HunterMainWindow

        return HunterMainWindow
    raise AttributeError(name)
