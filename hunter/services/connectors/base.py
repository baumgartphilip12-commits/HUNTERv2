"""Connector base classes and JSON-feed normalization."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from hunter.models.knowledge_store import KnowledgeStore, utc_now
from hunter.services.connectors.json_feed_builder import JsonFeedDatasetBuilder


@dataclass
class SyncResult:
    """Preview or apply result from a connector."""

    source_id: int
    source_name: str
    connector: str
    summary: dict
    diff: dict
    dataset: dict
    event_id: int | None = None


class BaseConnector:
    """Base class for source connectors."""

    name = "base"

    def build_dataset(self, source: dict) -> dict:
        raise NotImplementedError


class JsonFeedConnector(BaseConnector):
    """Connector for curated local JSON feeds."""

    name = "json_feed"

    def __init__(
        self,
        store: KnowledgeStore | None = None,
        *,
        create_mitre_placeholders: bool = True,
    ):
        self.store = store
        self.create_mitre_placeholders = create_mitre_placeholders
        self.dataset_builder = JsonFeedDatasetBuilder(
            store,
            create_mitre_placeholders=create_mitre_placeholders,
        )

    def build_dataset(self, source: dict) -> dict:
        config = source.get("config", {})
        path = config.get("path", "")
        if not path:
            raise ValueError("JSON feed source config is missing path")
        feed_path = Path(path)
        if not feed_path.exists():
            raise FileNotFoundError(f"Feed file not found: {feed_path}")

        payload = json.loads(feed_path.read_text(encoding="utf-8"))
        dataset = self.dataset_builder.build_dataset(
            source,
            payload,
            connector_name=self.name,
        )
        dataset["metadata"] = {
            "path": str(feed_path),
            "loaded_at": utc_now(),
        }
        return dataset

    def _normalize_payload(
        self,
        source: dict,
        payload: dict,
        *,
        connector_name: str | None = None,
    ) -> dict:
        """Compatibility hook for specialized connectors that extend JSON-feed normalization."""
        return self.dataset_builder.build_dataset(
            source,
            payload,
            connector_name=connector_name or self.name,
        )
