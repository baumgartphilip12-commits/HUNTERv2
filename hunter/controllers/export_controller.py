"""Desktop export actions for generated hunt packs.

The active UI surface exports generated hunt packs as portable JSON or polished
Word reports. Legacy whole-plan JSON, text report, and questionnaire exports
were removed once they were no longer wired into the workflow.

Word export pipeline
--------------------
Word export is implemented in JavaScript (export_docx.js) using the ``docx``
npm package, because Python's docx libraries do not support the professional
formatting required. Runtime discovery and installation support lives in
``DocxRuntimeHelper``.
"""

from __future__ import annotations

import json

from PySide6 import QtWidgets

from hunter.controllers.docx_runtime import DocxRuntimeHelper
from hunter.controllers.export_preparation import HuntPackExportPreparation


class ExportController:
    """Stateless export helpers for the active hunt-pack export workflow."""

    @staticmethod
    def _sanitize_hunt_pack(hunt_pack: dict, *, enabled_only: bool = True) -> dict:
        """Delegate export shaping to the pure preparation layer."""

        return HuntPackExportPreparation.sanitize_hunt_pack(
            hunt_pack,
            enabled_only=enabled_only,
        )

    @staticmethod
    def export_hunt_pack_json(hunt_pack: dict) -> None:
        """Export a generated hunt pack as a portable JSON package."""

        hunt_pack = ExportController._sanitize_hunt_pack(hunt_pack)
        initial_name = HuntPackExportPreparation.initial_hunt_pack_name(hunt_pack)
        path, _selected_filter = QtWidgets.QFileDialog.getSaveFileName(
            None,
            "Export Hunt Pack JSON",
            f"{initial_name.lower().replace(' ', '_')}.json",
            "JSON files (*.json)",
        )
        if not path:
            return

        with open(path, "w", encoding="utf-8") as handle:
            json.dump(hunt_pack, handle, indent=2)
        QtWidgets.QMessageBox.information(
            None,
            "Export Complete",
            f"Hunt pack exported to:\n{path}",
        )

    @staticmethod
    def export_hunt_pack_docx(
        parent_window: QtWidgets.QWidget | None,
        hunt_pack: dict,
        script_dir: str,
        store=None,
    ) -> None:
        """Export a generated hunt pack as a polished Word document."""

        hunt_pack = ExportController._sanitize_hunt_pack(hunt_pack)
        summary = hunt_pack.get("summary", {})
        initial_name = HuntPackExportPreparation.initial_hunt_pack_name(hunt_pack)
        doc_payload = {
            "document_type": "hunt_pack_v2",
            "name": hunt_pack.get("name", "Generated Hunt Pack"),
            "summary": summary,
            "payload": hunt_pack.get("payload", {}),
            "threat_context": ExportController._build_threat_context(hunt_pack, store=store),
            "created_at": hunt_pack.get("created_at", ""),
            "updated_at": hunt_pack.get("updated_at", ""),
        }
        DocxRuntimeHelper.export_word(
            parent_window=parent_window,
            plan_dict=doc_payload,
            script_dir=script_dir,
            initial_filename=f"{initial_name.lower().replace(' ', '_')}_report.docx",
        )

    @staticmethod
    def _build_threat_context(hunt_pack: dict, *, store=None) -> list[dict]:
        """Resolve compact DOCX threat context from audit IDs with safe fallback."""

        payload = hunt_pack.get("payload", {}) if isinstance(hunt_pack.get("payload"), dict) else {}
        audit = payload.get("audit", {}) if isinstance(payload.get("audit"), dict) else {}
        threat_ids = audit.get("threat_ids", []) if isinstance(audit.get("threat_ids", []), list) else []
        context: list[dict] = []

        if store is not None:
            for threat_id in threat_ids:
                try:
                    threat = store.get_entity(threat_id)
                except Exception:
                    threat = None
                if threat:
                    context.append(ExportController._sanitize_threat_context(threat))

        if context:
            return context

        summary = hunt_pack.get("summary", {}) if isinstance(hunt_pack.get("summary"), dict) else {}
        selected = summary.get("selected_threats", [])
        if not isinstance(selected, list):
            return []
        return [
            {
                "name": str(name),
                "summary": "",
                "aliases": [],
                "techniques": [],
                "indicators": [],
                "indicator_count": 0,
                "extra_hunts": [],
                "references": [],
                "tags": [],
            }
            for name in selected
        ]

    @staticmethod
    def _sanitize_threat_context(threat: dict) -> dict:
        """Keep DOCX threat sections readable and free of raw entity internals."""

        payload = threat.get("payload", {}) if isinstance(threat.get("payload"), dict) else {}
        indicators = payload.get("indicators", [])
        indicators = indicators if isinstance(indicators, list) else []
        techniques = payload.get("mitre_techniques") or payload.get("techniques") or []

        def string_list(value) -> list[str]:
            return [str(item) for item in value] if isinstance(value, list) else []

        sanitized_indicators: list[dict[str, str]] = []
        for indicator in indicators:
            if not isinstance(indicator, dict):
                continue
            kind = str(indicator.get("type", "")).strip()
            value = str(indicator.get("value", "")).strip()
            if kind and value:
                sanitized_indicators.append({"type": kind, "value": value})

        return {
            "name": str(threat.get("name", "")),
            "external_id": str(threat.get("external_id", "")),
            "summary": str(payload.get("summary") or threat.get("short_description", "")),
            "aliases": string_list(payload.get("aliases", [])),
            "techniques": string_list(techniques),
            "indicator_count": len(sanitized_indicators),
            "indicators": sanitized_indicators,
            "extra_hunts": string_list(payload.get("extra_hunts", [])),
            "references": string_list(payload.get("references", [])),
            "tags": string_list(threat.get("tags", [])),
        }
