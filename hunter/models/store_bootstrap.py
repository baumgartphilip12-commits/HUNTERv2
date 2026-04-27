"""Runtime bootstrap helpers for :mod:`hunter.models.knowledge_store`."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from hunter.runtime_paths import relative_module_ref, layered_module_dirs

if TYPE_CHECKING:
    from hunter.models.knowledge_store import KnowledgeStore


class KnowledgeRuntimeBootstrap:
    """Explicit runtime bootstrap entrypoints for a knowledge store."""

    @staticmethod
    def ensure(store: "KnowledgeStore") -> None:
        """Apply startup reconciliation and source seeding for a knowledge store."""

        store.seed_default_sources()
        store.import_seed_bundle_if_empty()
        store.reconcile_portable_runtime_paths()
        store.enforce_authored_catalog_mode()
        KnowledgeRuntimeBootstrap.reconcile_layered_tool_runtime_payloads(store)
        store.reconcile_portable_runtime_paths()

    @staticmethod
    def reconcile_layered_tool_runtime_payloads(store: "KnowledgeStore") -> int:
        """Repair runtime ToolPack payload fields from trusted layered module files."""

        repaired = 0
        tools_dir = layered_module_dirs(store.project_dir)["tools"]
        if not tools_dir.exists():
            return repaired
        for path in sorted(tools_dir.glob("*.json")):
            try:
                module = json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:
                print(f"[WARN] Could not inspect layered tool module {path}: {exc}")
                continue
            if not isinstance(module, dict):
                continue
            external_id = str(module.get("external_id", "")).strip()
            if not external_id:
                continue
            existing = store.get_entity_by_external_id("ToolPack", external_id)
            if existing is None:
                continue
            relative_ref = relative_module_ref(path, store.project_dir)
            if (
                existing.get("source_name") != "Layered Local Modules"
                or existing.get("source_ref") != relative_ref
            ):
                continue
            payload = dict(existing.get("payload", {}))
            changed = False
            for field in ("sigma_translation", "sigma_scope"):
                if field not in module:
                    continue
                if payload.get(field) != module.get(field):
                    if field == "sigma_scope" and not payload.get(field):
                        print(
                            f"[WARN] Runtime ToolPack {external_id} was missing sigma_scope; "
                            f"repairing from {relative_ref}."
                        )
                    payload[field] = module.get(field)
                    changed = True
            if not changed:
                continue
            store.upsert_entity(
                entity_type="ToolPack",
                external_id=external_id,
                name=str(module.get("name") or existing.get("name") or external_id),
                short_description=str(
                    module.get("summary")
                    or existing.get("short_description")
                    or ""
                ),
                status=str(module.get("status") or existing.get("status") or "active"),
                confidence=float(module.get("confidence", existing.get("confidence", 0.7) or 0.7)),
                priority=str(module.get("priority") or existing.get("priority") or ""),
                source_name="Layered Local Modules",
                source_ref=relative_ref,
                source_url="",
                retrieved_at=existing.get("retrieved_at", ""),
                last_seen=existing.get("last_seen", ""),
                valid_until=existing.get("valid_until", ""),
                tags=module.get("tags", existing.get("tags", [])) or [],
                payload=payload,
            )
            repaired += 1
        return repaired


def bootstrap_runtime_store(store: "KnowledgeStore") -> None:
    """Apply startup reconciliation and source seeding for a knowledge store."""
    KnowledgeRuntimeBootstrap.ensure(store)
