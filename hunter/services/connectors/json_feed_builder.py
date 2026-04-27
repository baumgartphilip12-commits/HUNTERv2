"""Dataset-building helpers for curated local JSON feed sources."""

from __future__ import annotations

from typing import Any

from hunter.models.knowledge_store import utc_now
from hunter.services.connectors.json_feed_normalizers import (
    normalize_addon_pack,
    normalize_indicator_set,
    normalize_placeholder_techniques,
    normalize_threat_profile,
    normalize_tool_pack,
)


class JsonFeedDatasetBuilder:
    """Orchestrate JSON-feed normalization into sync-ready datasets."""

    def __init__(self, store=None, *, create_mitre_placeholders: bool = True):
        self.store = store
        self.create_mitre_placeholders = create_mitre_placeholders

    def build_dataset(
        self,
        source: dict[str, Any],
        payload: dict[str, Any],
        *,
        connector_name: str = "json_feed",
    ) -> dict[str, Any]:
        if "entities" in payload and "relationships" in payload:
            return {
                "source_name": source["name"],
                "connector": connector_name,
                "fetched_at": utc_now(),
                "entities": payload.get("entities", []),
                "relationships": payload.get("relationships", []),
            }

        entities: list[dict[str, Any]] = []
        relationships: list[dict[str, Any]] = []

        self._extend_from_items(source, payload.get("threat_profiles", []), normalize_threat_profile, entities, relationships)
        self._extend_from_items(source, payload.get("indicator_sets", []), normalize_indicator_set, entities, relationships)
        self._extend_from_items(source, payload.get("tool_packs", []), normalize_tool_pack, entities, relationships)

        entities.extend(
            normalize_placeholder_techniques(
                source,
                existing_entities=entities,
                relationships=relationships,
                store=self.store,
                create_mitre_placeholders=self.create_mitre_placeholders,
            )
        )

        self._extend_from_items(source, payload.get("addon_packs", []), normalize_addon_pack, entities, relationships)

        return {
            "source_name": source["name"],
            "connector": connector_name,
            "fetched_at": utc_now(),
            "entities": entities,
            "relationships": relationships,
        }

    @staticmethod
    def _extend_from_items(
        source: dict[str, Any],
        items: list[dict[str, Any]],
        normalizer,
        entities: list[dict[str, Any]],
        relationships: list[dict[str, Any]],
    ) -> None:
        for item in items:
            item_entities, item_relationships = normalizer(source, item)
            entities.extend(item_entities)
            relationships.extend(item_relationships)
