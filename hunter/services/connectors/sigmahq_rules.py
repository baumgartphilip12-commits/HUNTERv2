"""SigmaHQ rules sync connector."""

from __future__ import annotations

import io
import re
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from hunter.models.knowledge_store import KnowledgeStore, utc_now
from hunter.runtime_paths import repo_relative_path, resolve_repo_path
from hunter.services.connectors.base import BaseConnector
from hunter.services.connectors.common import short_text, zip_datetime_iso
from hunter.services.sigma_service import SIGMA_PLUGIN_DIRECTORY_URL, normalize_sigma_source_family
from hunter.vendor_runtime import require_optional_dependency


class SigmaHQRulesConnector(BaseConnector):
    """Connector for the official SigmaHQ rule repository."""

    name = "sigmahq_rules"
    INCLUDED_PREFIXES = (
        "rules/",
        "rules-threat-hunting/",
        "rules-emerging-threats/",
        "rules-dfir/",
    )
    SKIPPED_PREFIXES = (
        "deprecated/",
        "unsupported/",
        "documentation/",
        "tests/",
        "regression_data/",
        "other/",
        "rules-placeholder/",
        "rules-compliance/",
    )

    def __init__(self, store: KnowledgeStore):
        self.store = store

    @staticmethod
    def _source_slug(source_name: str) -> str:
        slug = re.sub(r"[^a-z0-9]+", "-", str(source_name).strip().lower()).strip("-")
        return slug or "sigma-source"

    def build_dataset(self, source: dict) -> dict:
        config = source.get("config", {})
        documents, archive_label, archive_last_modified = self._load_documents(config)
        now = utc_now()
        yaml = require_optional_dependency(
            "yaml",
            package_name="PyYAML",
            purpose="SigmaHQ sync",
        )
        entities: list[dict] = []
        relationships: list[dict] = []
        warnings: list[str] = []
        sync_stats = {
            "files_scanned": 0,
            "rules_imported": 0,
            "skipped_deprecated": 0,
            "skipped_unsupported": 0,
            "unsupported_documents": 0,
            "warning_count": 0,
        }

        for item in documents:
            repo_path = item["repo_path"]
            if not repo_path or not repo_path.lower().endswith((".yml", ".yaml")):
                continue
            if any(repo_path.startswith(prefix) for prefix in self.SKIPPED_PREFIXES):
                if repo_path.startswith("deprecated/"):
                    sync_stats["skipped_deprecated"] += 1
                elif repo_path.startswith("unsupported/"):
                    sync_stats["skipped_unsupported"] += 1
                continue
            if item.get("source_kind") == "archive" and not any(
                repo_path.startswith(prefix) for prefix in self.INCLUDED_PREFIXES
            ):
                continue

            sync_stats["files_scanned"] += 1
            raw_text = item.get("raw_text", "")

            try:
                docs = [doc for doc in yaml.safe_load_all(raw_text) if doc is not None]
            except Exception as exc:
                warnings.append(f"{repo_path}: {exc}")
                sync_stats["warning_count"] += 1
                continue

            for index, doc in enumerate(docs, 1):
                try:
                    normalized = self._normalize_rule_document(
                        source=source,
                        config=config,
                        repo_path=repo_path,
                        raw_text=raw_text,
                        info=item.get("info"),
                        archive_last_modified=item.get("last_modified") or archive_last_modified,
                        document=doc,
                        document_index=index,
                    )
                except ValueError as exc:
                    warnings.append(f"{repo_path}: {exc}")
                    sync_stats["warning_count"] += 1
                    sync_stats["unsupported_documents"] += 1
                    continue
                if normalized is None:
                    continue
                entity, rule_relationships = normalized
                entities.append(entity)
                relationships.extend(rule_relationships)
                sync_stats["rules_imported"] += 1
        entities.extend(
            self._placeholder_techniques_for_missing_targets(
                source,
                entities,
                relationships,
            )
        )

        return {
            "source_name": source["name"],
            "connector": self.name,
            "fetched_at": now,
            "entities": entities,
            "relationships": relationships,
            "metadata": {
                "repo_url": config.get("repo_url", "https://github.com/SigmaHQ/sigma"),
                "archive": archive_label,
                "archive_last_modified": archive_last_modified,
                "included_folders": list(self.INCLUDED_PREFIXES),
                "warnings": warnings,
                "sync_stats": sync_stats,
            },
        }

    def _load_documents(self, config: dict[str, Any]) -> tuple[list[dict[str, Any]], str, str]:
        rules_file = str(config.get("rules_file", "")).strip()
        if rules_file:
            path = resolve_repo_path(rules_file, self.store.project_dir)
            if not path.exists():
                raise FileNotFoundError(f"Sigma rule file not found: {path}")
            return ([self._local_document(path, path.parent)], repo_relative_path(path, self.store.project_dir), self._file_mtime(path))

        rules_dir = str(config.get("rules_dir", "")).strip()
        if rules_dir:
            path = resolve_repo_path(rules_dir, self.store.project_dir)
            if not path.exists() or not path.is_dir():
                raise FileNotFoundError(f"Sigma rules directory not found: {path}")
            files = sorted(
                file
                for file in path.rglob("*")
                if file.is_file() and file.suffix.lower() in {".yml", ".yaml"}
            )
            last_modified = max((self._file_mtime(file) for file in files), default="")
            return (
                [self._local_document(file, path) for file in files],
                repo_relative_path(path, self.store.project_dir),
                last_modified,
            )

        archive_bytes, archive_label, archive_last_modified = self._load_archive(config)
        return self._archive_documents(archive_bytes), archive_label, archive_last_modified

    @staticmethod
    def _file_mtime(path: Path) -> str:
        return (
            datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            .replace(microsecond=0)
            .isoformat()
        )

    def _local_document(self, path: Path, root: Path) -> dict[str, Any]:
        try:
            repo_path = path.relative_to(root).as_posix()
        except ValueError:
            repo_path = path.name
        return {
            "repo_path": repo_path,
            "raw_text": path.read_text(encoding="utf-8"),
            "last_modified": self._file_mtime(path),
            "source_kind": "local",
        }

    def _archive_documents(self, archive_bytes: bytes) -> list[dict[str, Any]]:
        documents: list[dict[str, Any]] = []
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            file_names = sorted(name for name in archive.namelist() if not name.endswith("/"))
            root_prefix = self._archive_root_prefix(file_names)
            for archive_name in file_names:
                repo_path = self._repo_path(archive_name, root_prefix)
                if not repo_path or not repo_path.lower().endswith((".yml", ".yaml")):
                    continue
                if any(repo_path.startswith(prefix) for prefix in self.SKIPPED_PREFIXES):
                    documents.append({"repo_path": repo_path, "source_kind": "archive"})
                    continue
                if not any(repo_path.startswith(prefix) for prefix in self.INCLUDED_PREFIXES):
                    continue
                try:
                    raw_text = archive.read(archive_name).decode("utf-8")
                    info = archive.getinfo(archive_name)
                except Exception:
                    continue
                documents.append(
                    {
                        "repo_path": repo_path,
                        "raw_text": raw_text,
                        "info": info,
                        "last_modified": zip_datetime_iso(info),
                        "source_kind": "archive",
                    }
                )
        return documents

    def _load_archive(self, config: dict[str, Any]) -> tuple[bytes, str, str]:
        archive_path = str(config.get("archive_path", "")).strip()
        if archive_path:
            path = resolve_repo_path(archive_path, self.store.project_dir)
            if not path.exists():
                raise FileNotFoundError(f"Sigma archive not found: {path}")
            return (
                path.read_bytes(),
                repo_relative_path(path, self.store.project_dir),
                self._file_mtime(path),
            )

        archive_url = str(config.get("archive_url", "")).strip()
        if not archive_url:
            raise ValueError("SigmaHQ source config is missing archive_url or archive_path")
        request = urllib.request.Request(
            archive_url,
            headers={
                "User-Agent": "HUNTER-v2-sync",
                "Accept": "application/zip",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return (
                    response.read(),
                    archive_url,
                    response.headers.get("Last-Modified", ""),
                )
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Unable to fetch SigmaHQ archive: {exc}") from exc

    @staticmethod
    def _archive_root_prefix(file_names: list[str]) -> str:
        if not file_names:
            return ""
        first = file_names[0].split("/", 1)
        return first[0] + "/" if len(first) == 2 else ""

    @staticmethod
    def _repo_path(archive_name: str, root_prefix: str) -> str:
        if root_prefix and archive_name.startswith(root_prefix):
            return archive_name[len(root_prefix) :]
        return archive_name

    def _normalize_rule_document(
        self,
        *,
        source: dict,
        config: dict[str, Any],
        repo_path: str,
        raw_text: str,
        info: zipfile.ZipInfo | None,
        archive_last_modified: str,
        document: Any,
        document_index: int,
    ) -> tuple[dict, list[dict]] | None:
        if not isinstance(document, dict):
            raise ValueError("unsupported Sigma document type")
        if "correlation" in document or "filters" in document or "filter" in document:
            raise ValueError("correlation and filter documents are deferred in v1")
        if "detection" not in document or "title" not in document:
            raise ValueError("document is not a standard Sigma rule")
        document = KnowledgeStore.json_safe(document)

        status = str(document.get("status", "stable")).strip().lower()
        if status in {"deprecated", "unsupported"}:
            return None

        rule_uuid = str(document.get("id", "")).strip()
        source_ref = repo_path if document_index == 1 else f"{repo_path}#{document_index}"
        source_slug = self._source_slug(source.get("name", ""))
        external_id = f"sigma::{source_slug}::{rule_uuid or source_ref}"
        raw_base_url = str(config.get("raw_base_url", "")).rstrip("/")
        raw_rule_url = f"{raw_base_url}/{repo_path}" if raw_base_url else ""
        tags = [str(tag).strip() for tag in document.get("tags", []) if str(tag).strip()]
        attack_tags = [
            tag
            for tag in tags
            if re.match(r"^attack\.t\d{4}(?:\.\d{3})?$", tag.lower())
        ]
        attack_techniques = [tag.split(".", 1)[1].upper() for tag in attack_tags]
        description = short_text(document.get("description", ""), limit=6000)
        last_modified = archive_last_modified or (zip_datetime_iso(info) if info else "")
        entity = {
            "type": "SigmaRule",
            "external_id": external_id,
            "name": str(document.get("title", external_id)).strip() or external_id,
            "short_description": short_text(description or document.get("title", "")),
            "status": status or "stable",
            "confidence": 0.7,
            "priority": str(document.get("level", "")).strip().lower(),
            "source_name": source["name"],
            "source_ref": source_ref,
            "source_url": raw_rule_url,
            "retrieved_at": utc_now(),
            "last_seen": last_modified,
            "valid_until": "",
            "tags": tags,
            "payload": {
                "rule_uuid": rule_uuid,
                "title": str(document.get("title", "")).strip(),
                "status": status or "stable",
                "level": str(document.get("level", "")).strip().lower(),
                "summary": short_text(description or document.get("title", "")),
                "description": description,
                "references": document.get("references", []),
                "tags": tags,
                "attack_tags": attack_tags,
                "attack_techniques": attack_techniques,
                "author": document.get("author", ""),
                "date": document.get("date", ""),
                "falsepositives": document.get("falsepositives", []),
                "fields": document.get("fields", []),
                "logsource": document.get("logsource", {}),
                "source_family": normalize_sigma_source_family(document.get("logsource", {})),
                "detection": document.get("detection", {}),
                "repo_path": repo_path,
                "repo_url": config.get("repo_url", "https://github.com/SigmaHQ/sigma"),
                "raw_rule_url": raw_rule_url,
                "raw_yaml": raw_text,
                "last_modified": last_modified,
                "plugin_directory_url": SIGMA_PLUGIN_DIRECTORY_URL,
            },
        }

        relationships: list[dict] = []
        for technique_id in attack_techniques:
            relationships.append(
                {
                    "src_type": "SigmaRule",
                    "src_external_id": external_id,
                    "dst_type": "MitreTechnique",
                    "dst_external_id": technique_id,
                    "rel_type": "DETECTS",
                    "weight": 1.0,
                    "confidence": 0.8,
                    "status": status or "stable",
                    "source_name": source["name"],
                    "source_ref": source_ref,
                    "context": {"origin": "sigmahq_attack_tag"},
                    "first_seen": utc_now(),
                    "last_seen": last_modified or utc_now(),
                    "valid_until": "",
                }
            )

        return entity, relationships

    def _placeholder_techniques_for_missing_targets(
        self,
        source: dict,
        entities: list[dict],
        relationships: list[dict],
    ) -> list[dict]:
        referenced_techniques = {
            rel["dst_external_id"]
            for rel in relationships
            if rel.get("dst_type") == "MitreTechnique"
        }
        existing_in_dataset = {
            entity["external_id"]
            for entity in entities
            if entity.get("type") == "MitreTechnique"
        }
        placeholders: list[dict] = []
        for technique_id in sorted(referenced_techniques - existing_in_dataset):
            existing = self.store.get_entity_by_external_id("MitreTechnique", technique_id)
            if existing is not None:
                continue
            placeholders.append(
                {
                    "type": "MitreTechnique",
                    "external_id": technique_id,
                    "name": technique_id,
                    "short_description": "Placeholder technique created from Sigma ATT&CK tags.",
                    "status": "placeholder",
                    "confidence": 0.35,
                    "priority": "",
                    "source_name": source["name"],
                    "source_ref": technique_id,
                    "source_url": "",
                    "retrieved_at": utc_now(),
                    "last_seen": utc_now(),
                    "valid_until": "",
                    "tags": ["placeholder", "mitre"],
                    "payload": {
                        "technique_id": technique_id,
                        "parent_technique_id": technique_id.split(".", 1)[0],
                        "is_subtechnique": "." in technique_id,
                    },
                }
            )
        return placeholders
