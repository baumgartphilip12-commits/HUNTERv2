"""Sigma rule lookup and translation helpers for HUNTER."""

from __future__ import annotations

import json
import importlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from hunter.models.knowledge_store import KnowledgeStore
from hunter.vendor_runtime import VendorDependencyError, require_optional_dependency


SIGMA_PLUGIN_DIRECTORY_URL = (
    "https://raw.githubusercontent.com/SigmaHQ/pySigma-plugin-directory/main/pySigma-plugins-v1.json"
)
SIGMA_TRANSLATION_REQUIRED_FIELDS = ("enabled", "backend", "pipelines", "output_format")
SIGMA_LEVEL_SCORES = {
    "informational": 0.45,
    "low": 0.55,
    "medium": 0.7,
    "high": 0.82,
    "critical": 0.95,
}
SIGMA_STATUS_SCORES = {
    "stable": 1.0,
    "test": 0.85,
    "experimental": 0.72,
}
SIGMA_MAX_STEPS_PER_TOOL = 25
SIGMA_MAX_STEPS_PER_TECHNIQUE = 5
SIGMA_IOC_TYPE_ALIASES = {
    "ip": ("ip", "ipv4", "ipv6"),
    "domain": ("domain", "fqdn"),
    "url": ("url", "uri"),
    "sha256": ("sha256", "hash_sha256"),
    "md5": ("md5", "hash_md5"),
    "hostname": ("hostname", "host"),
    "email": ("email",),
}
SIGMA_RELEVANCE_STOPWORDS = {
    "about",
    "access",
    "account",
    "accounts",
    "ad",
    "activity",
    "against",
    "aligned",
    "also",
    "analysis",
    "attack",
    "azure",
    "azure-hosted",
    "behavior",
    "behaviors",
    "campaign",
    "cloud",
    "cloud-hosted",
    "command",
    "control",
    "credential",
    "credentials",
    "data",
    "detect",
    "detection",
    "document",
    "documents",
    "dns",
    "event",
    "events",
    "exchange",
    "execution",
    "explorer",
    "ews",
    "file",
    "files",
    "ftp",
    "hosted",
    "http",
    "https",
    "identity",
    "iis",
    "iranian",
    "kitten",
    "hunt",
    "hunting",
    "infrastructure",
    "known",
    "linux",
    "malicious",
    "malware",
    "mapped",
    "macos",
    "mfa",
    "microsoft",
    "net",
    "observed",
    "office",
    "operator",
    "outbound",
    "owa",
    "powershell",
    "process",
    "rdp",
    "registry",
    "related",
    "remote",
    "review",
    "rmm",
    "run",
    "rule",
    "selected",
    "service",
    "services",
    "sigma",
    "smb",
    "staging",
    "suspicious",
    "technique",
    "telemetry",
    "threat",
    "task",
    "tasks",
    "tool",
    "tools",
    "traffic",
    "validate",
    "vbscript",
    "vpn",
    "windows",
    "with",
}


def normalize_sigma_source_family(logsource: Any) -> str:
    """Normalize the Sigma source family using product > service > category."""

    if not isinstance(logsource, dict):
        return ""
    for key in ("product", "service", "category"):
        value = str(logsource.get(key, "")).strip().lower()
        if value:
            return value
    return ""


def normalize_sigma_translation(config: Any) -> dict[str, Any] | None:
    """Return a normalized Sigma translation block or ``None`` when absent."""

    if not isinstance(config, dict):
        return None
    if not all(field in config for field in SIGMA_TRANSLATION_REQUIRED_FIELDS):
        return None
    pipelines = config.get("pipelines", [])
    if not isinstance(pipelines, list):
        return None
    normalized = {
        "enabled": bool(config.get("enabled", False)),
        "backend": str(config.get("backend", "")).strip().lower(),
        "pipelines": [str(value).strip() for value in pipelines if str(value).strip()],
        "output_format": str(config.get("output_format", "")).strip() or "default",
    }
    if not normalized["backend"]:
        return None
    return normalized


class SigmaTranslationService:
    """Translate Sigma rules into tool-ready hunt text."""

    SUPPORTED_BACKENDS = {"elasticsearch"}

    def supports(self, translation: dict[str, Any] | None) -> bool:
        config = normalize_sigma_translation(translation)
        return bool(config and config["backend"] in self.SUPPORTED_BACKENDS)

    def translate_rule(self, rule: dict, translation: dict[str, Any] | None) -> dict[str, str] | None:
        config = normalize_sigma_translation(translation)
        if not config or not config.get("enabled") or not self.supports(config):
            return None

        for translator in (
            self._translate_with_pysigma,
            self._translate_with_sigma_cli,
            self._translate_with_builtin_fallback,
        ):
            try:
                query = translator(rule, config)
            except VendorDependencyError:
                raise
            except Exception:
                continue
            if query:
                return {
                    "query": query,
                    "translation_target": config["backend"],
                    "output_format": config["output_format"],
                }
        return None

    def _translate_with_pysigma(self, rule: dict, config: dict[str, Any]) -> str | None:
        try:
            from sigma.collection import SigmaCollection
            from sigma.processing.resolver import ProcessingPipelineResolver
            from sigma.backends.elasticsearch import LuceneBackend
        except Exception:
            return None

        pipeline_resolver = ProcessingPipelineResolver()
        for pipeline_name in config.get("pipelines", []):
            pipeline = self._load_pysigma_pipeline(pipeline_name)
            if pipeline is not None:
                pipeline_resolver.add_pipeline_class(pipeline)

        resolved_pipeline = None
        if getattr(pipeline_resolver, "pipelines", None):
            resolved_pipeline = pipeline_resolver.resolve(pipeline_resolver.pipelines)

        backend = LuceneBackend(resolved_pipeline)
        collection = SigmaCollection.from_yaml(rule.get("payload", {}).get("raw_yaml", ""))
        queries = backend.convert(
            collection,
            output_format=self._normalize_output_format(config.get("output_format", "default")),
        )
        if not queries:
            return None
        query = queries[0]
        if isinstance(query, str):
            return query.strip()
        return json.dumps(query, indent=2, sort_keys=True)

    def _load_pysigma_pipeline(self, pipeline_name: str):
        pipeline_map = {
            "ecs_windows": ("sigma.pipelines.elasticsearch.windows", "ecs_windows"),
            "ecs_windows_old": ("sigma.pipelines.elasticsearch.windows", "ecs_windows_old"),
            "ecs_zeek_beats": ("sigma.pipelines.elasticsearch.zeek", "ecs_zeek_beats"),
            "ecs_zeek_corelight": ("sigma.pipelines.elasticsearch.zeek", "ecs_zeek_corelight"),
            "zeek_raw": ("sigma.pipelines.elasticsearch.zeek", "zeek_raw"),
            "ecs_kubernetes": ("sigma.pipelines.elasticsearch.kubernetes", "ecs_kubernetes"),
        }
        target = pipeline_map.get(pipeline_name)
        if target is None:
            return None
        module_name, attr_name = target
        module = __import__(module_name, fromlist=[attr_name])
        factory = getattr(module, attr_name)
        return factory()

    def _translate_with_sigma_cli(self, rule: dict, config: dict[str, Any]) -> str | None:
        executable = shutil.which("sigma")
        if not executable:
            return None
        with tempfile.TemporaryDirectory() as tempdir:
            temp_path = Path(tempdir) / "rule.yml"
            temp_path.write_text(rule.get("payload", {}).get("raw_yaml", ""), encoding="utf-8")
            command = [
                executable,
                "convert",
                "-t",
                config["backend"],
                "-f",
                self._normalize_output_format(config.get("output_format", "default")),
            ]
            for pipeline_name in config.get("pipelines", []):
                command.extend(["-p", pipeline_name])
            command.append(str(temp_path))
            result = subprocess.run(
                command,
                capture_output=True,
                check=False,
                text=True,
                encoding="utf-8",
            )
            if result.returncode != 0:
                return None
            return result.stdout.strip()

    def _translate_with_builtin_fallback(self, rule: dict, _config: dict[str, Any]) -> str | None:
        payload = rule.get("payload", {})
        detection = payload.get("detection")
        if not isinstance(detection, dict):
            raw_yaml = payload.get("raw_yaml", "")
            yaml = require_optional_dependency(
                "yaml",
                package_name="PyYAML",
                purpose="Sigma rule translation",
            )
            docs = [doc for doc in yaml.safe_load_all(raw_yaml) if isinstance(doc, dict)]
            if not docs:
                return None
            detection = docs[0].get("detection")
        if not isinstance(detection, dict):
            return None
        return self._compile_condition(detection)

    @staticmethod
    def _normalize_output_format(output_format: str) -> str:
        lowered = str(output_format or "default").strip().lower()
        return "default" if lowered in {"", "default", "lucene"} else lowered

    def _compile_condition(self, detection: dict[str, Any]) -> str:
        selections = {
            key: self._compile_selection(value)
            for key, value in detection.items()
            if key != "condition"
        }
        if not selections:
            return ""
        condition = str(detection.get("condition", "")).strip()
        if not condition:
            if len(selections) == 1:
                return next(iter(selections.values()))
            raise ValueError("Sigma detection is missing a condition.")

        def expand_pattern(match: re.Match[str]) -> str:
            quantity = match.group(1).lower()
            pattern = match.group(2)
            if pattern == "them":
                names = sorted(selections.keys())
            elif "*" in pattern:
                regex = re.compile("^" + re.escape(pattern).replace("\\*", ".*") + "$")
                names = [name for name in sorted(selections.keys()) if regex.match(name)]
            else:
                names = [pattern] if pattern in selections else []
            if not names:
                raise ValueError(f"Unsupported Sigma condition pattern: {pattern}")
            joiner = " OR " if quantity == "1" else " AND "
            return "(" + joiner.join(f"({selections[name]})" for name in names) + ")"

        condition = re.sub(
            r"\b(all|1)\s+of\s+([A-Za-z0-9_*]+|them)\b",
            expand_pattern,
            condition,
            flags=re.IGNORECASE,
        )

        for name in sorted(selections.keys(), key=len, reverse=True):
            condition = re.sub(
                rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])",
                f"({selections[name]})",
                condition,
            )

        condition = re.sub(r"\band\b", "AND", condition, flags=re.IGNORECASE)
        condition = re.sub(r"\bor\b", "OR", condition, flags=re.IGNORECASE)
        condition = re.sub(r"\bnot\b", "NOT", condition, flags=re.IGNORECASE)
        return re.sub(r"\s+", " ", condition).strip()

    def _compile_selection(self, value: Any) -> str:
        if isinstance(value, dict):
            return self._compile_mapping(value)
        if isinstance(value, list):
            compiled_items = [self._compile_selection(item) for item in value]
            return "(" + " OR ".join(item for item in compiled_items if item) + ")"
        raise ValueError("Unsupported Sigma selection shape.")

    def _compile_mapping(self, mapping: dict[str, Any]) -> str:
        clauses: list[str] = []
        for field_spec, value in mapping.items():
            field, modifiers = self._split_field_spec(str(field_spec))
            clauses.append(self._compile_field_clause(field, modifiers, value))
        return "(" + " AND ".join(clause for clause in clauses if clause) + ")"

    @staticmethod
    def _split_field_spec(field_spec: str) -> tuple[str, list[str]]:
        if "|" not in field_spec:
            return field_spec, []
        parts = [part.strip() for part in field_spec.split("|") if part.strip()]
        return parts[0], parts[1:]

    def _compile_field_clause(
        self,
        field: str,
        modifiers: list[str],
        value: Any,
    ) -> str:
        lowered_modifiers = {modifier.lower() for modifier in modifiers}
        if any(modifier in {"base64", "base64offset", "cidr", "windash"} for modifier in lowered_modifiers):
            raise ValueError(f"Unsupported Sigma modifier set: {sorted(lowered_modifiers)}")
        if field.lower() == "keywords":
            return self._compile_keywords(value, require_all="all" in lowered_modifiers)
        if isinstance(value, list):
            joiner = " AND " if "all" in lowered_modifiers else " OR "
            clauses = [
                self._compile_single_value(field, lowered_modifiers, item)
                for item in value
            ]
            return "(" + joiner.join(clauses) + ")"
        return self._compile_single_value(field, lowered_modifiers, value)

    def _compile_keywords(self, value: Any, *, require_all: bool) -> str:
        items = value if isinstance(value, list) else [value]
        joiner = " AND " if require_all else " OR "
        compiled = [self._format_keyword(item) for item in items]
        return "(" + joiner.join(compiled) + ")"

    def _compile_single_value(
        self,
        field: str,
        modifiers: set[str],
        value: Any,
    ) -> str:
        if isinstance(value, bool):
            return f"{field}:{str(value).lower()}"
        if isinstance(value, (int, float)):
            return f"{field}:{value}"
        raw_value = str(value)
        if "re" in modifiers:
            return f"{field}:/{raw_value}/"
        if "contains" in modifiers:
            pattern = f"*{self._escape_lucene_term(raw_value, preserve_wildcards=False)}*"
            return f"{field}:{pattern}"
        if "startswith" in modifiers:
            pattern = f"{self._escape_lucene_term(raw_value, preserve_wildcards=False)}*"
            return f"{field}:{pattern}"
        if "endswith" in modifiers:
            pattern = f"*{self._escape_lucene_term(raw_value, preserve_wildcards=False)}"
            return f"{field}:{pattern}"
        formatted = self._format_term(raw_value)
        return f"{field}:{formatted}"

    def _format_keyword(self, value: Any) -> str:
        if isinstance(value, (int, float)):
            return str(value)
        return self._format_term(str(value))

    @staticmethod
    def _format_term(value: str) -> str:
        escaped = SigmaTranslationService._escape_lucene_term(value)
        if any(char.isspace() for char in value):
            return f"\"{escaped}\""
        return escaped

    @staticmethod
    def _escape_lucene_term(value: str, *, preserve_wildcards: bool = True) -> str:
        special = r'+-!(){}[]^"~:/\\'
        escaped: list[str] = []
        for char in value:
            if char in {"*", "?"} and preserve_wildcards:
                escaped.append(char)
            elif char in special:
                escaped.append("\\" + char)
            else:
                escaped.append(char)
        return "".join(escaped)


class SigmaRuleService:
    """Resolve Sigma coverage and produce supplemental translated hunt steps."""

    def __init__(self, store: KnowledgeStore):
        self.store = store
        self.translator = SigmaTranslationService()
        self._coverage_summary_cache: dict[tuple[Any, ...], dict[str, Any]] = {}

    def build_relevance_context(
        self,
        threats: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        """Build the APT-side profile used to suppress broad ATT&CK-only Sigma hits."""

        threats = [threat for threat in (threats or []) if threat]
        strong_terms: dict[str, dict[str, Any]] = {}
        weak_terms: dict[str, dict[str, Any]] = {}
        indicator_types: set[str] = set()
        indicator_values: set[str] = set()

        def add_term(value: Any, *, weight: float, reason: str, strong: bool) -> None:
            text = str(value or "").strip()
            if not self._is_relevance_term(text):
                return
            key = text.casefold()
            target = strong_terms if strong else weak_terms
            existing = target.get(key)
            if existing is None or weight > existing["weight"]:
                target[key] = {
                    "term": text,
                    "weight": float(weight),
                    "reason": reason,
                }

        for threat in threats:
            payload = threat.get("payload", {})
            add_term(threat.get("name"), weight=3.2, reason="APT name", strong=True)
            add_term(threat.get("external_id"), weight=2.2, reason="APT external ID", strong=True)
            for alias in payload.get("aliases", []):
                add_term(alias, weight=3.5, reason="APT alias", strong=True)
            for tag in threat.get("tags", []) or []:
                add_term(tag, weight=0.7, reason="APT tag context", strong=False)
            for indicator in payload.get("indicators", []):
                if not isinstance(indicator, dict):
                    continue
                indicator_type = str(indicator.get("type", "")).strip().lower()
                indicator_value = str(indicator.get("value", "")).strip()
                if indicator_type:
                    indicator_types.add(indicator_type)
                if indicator_value:
                    indicator_values.add(indicator_value.casefold())
                    add_term(
                        indicator_value,
                        weight=4.0,
                        reason=f"APT {indicator_type or 'indicator'}",
                        strong=True,
                    )
            for field_name in (
                "known_tools",
                "known_malware",
                "malware",
                "tooling",
                "tools",
                "software",
                "families",
            ):
                for value in self._iter_relevance_values(payload.get(field_name)):
                    add_term(value, weight=3.0, reason=f"APT {field_name.replace('_', ' ')}", strong=True)
            for text in payload.get("extra_hunts", []):
                for term in self._extract_strong_relevance_terms(text):
                    add_term(term, weight=2.8, reason="APT high-signal hunt term", strong=True)
                for term in self._extract_relevance_terms(text):
                    add_term(term, weight=0.45, reason="APT hunt context", strong=False)
            for term in self._extract_strong_relevance_terms(payload.get("summary", "")):
                add_term(term, weight=2.0, reason="APT high-signal summary term", strong=True)
            for term in self._extract_relevance_terms(payload.get("summary", "")):
                add_term(term, weight=0.35, reason="APT summary context", strong=False)

        strong_list = sorted(
            strong_terms.values(),
            key=lambda item: (-item["weight"], item["term"].casefold()),
        )
        weak_list = sorted(
            weak_terms.values(),
            key=lambda item: (-item["weight"], item["term"].casefold()),
        )

        return {
            "has_threats": bool(threats),
            "terms": strong_list + weak_list,
            "strong_terms": strong_list,
            "weak_terms": weak_list,
            "indicator_types": sorted(indicator_types),
            "indicator_values": sorted(indicator_values),
        }

    def tool_translation(self, tool: dict) -> dict[str, Any] | None:
        return normalize_sigma_translation(tool.get("payload", {}).get("sigma_translation"))

    def tool_translation_mode(self, tool: dict) -> str:
        translation = self.tool_translation(tool)
        if translation and translation.get("enabled") and self.translator.supports(translation):
            return "translation_enabled"
        return "reference_only"

    @staticmethod
    def normalize_selected_families(
        selected_families: list[str] | set[str] | tuple[str, ...] | None,
    ) -> tuple[str, ...]:
        if not selected_families:
            return ()
        return tuple(
            sorted(
                {
                    str(value).strip().lower()
                    for value in selected_families
                    if str(value).strip()
                }
            )
        )

    @staticmethod
    def _rule_matches_selected_families(
        rule: dict[str, Any],
        selected_families: tuple[str, ...],
    ) -> bool:
        if not selected_families:
            return True
        family = normalize_sigma_source_family(rule.get("payload", {}).get("logsource", {}))
        if not family:
            family = str(rule.get("payload", {}).get("source_family", "")).strip().lower()
        return family in set(selected_families)

    @staticmethod
    def _is_relevance_term(value: str) -> bool:
        text = str(value or "").strip()
        if len(text) < 4:
            return False
        if text.casefold() in SIGMA_RELEVANCE_STOPWORDS:
            return False
        return any(char.isalnum() for char in text)

    def _extract_relevance_terms(self, text: Any) -> list[str]:
        raw = str(text or "")
        terms: list[str] = []
        for token in re.findall(r"[A-Za-z][A-Za-z0-9._/-]{3,}", raw):
            normalized = token.strip(".,;:()[]{}\"'")
            if self._is_relevance_term(normalized):
                terms.append(normalized)
        return terms

    def _iter_relevance_values(self, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, dict):
            return [
                nested_value
                for nested in value.values()
                for nested_value in self._iter_relevance_values(nested)
            ]
        if isinstance(value, (list, tuple, set)):
            return [
                nested_value
                for nested in value
                for nested_value in self._iter_relevance_values(nested)
            ]
        return [str(value)]

    def _is_high_signal_threat_token(self, value: str) -> bool:
        token = str(value or "").strip(".,;:()[]{}\"'")
        if not self._is_relevance_term(token):
            return False
        if token.casefold() in SIGMA_RELEVANCE_STOPWORDS:
            return False
        if any(char.isdigit() for char in token):
            return True
        if token.isupper() and len(token) > 2:
            return True
        if token[:1].isupper() and any(char.isupper() for char in token[1:]):
            return True
        if token[:1].isupper() and len(token) >= 5:
            return True
        return False

    def _extract_strong_relevance_terms(self, text: Any) -> list[str]:
        raw = str(text or "")
        terms: set[str] = set()
        for token in re.findall(r"[A-Za-z][A-Za-z0-9._/-]{2,}", raw):
            normalized = token.strip(".,;:()[]{}\"'")
            if self._is_high_signal_threat_token(normalized):
                terms.add(normalized)
        for match in re.finditer(
            r"\b([A-Za-z][A-Za-z0-9._/-]{2,})\s+(?:backdoor|implant|loader|malware|rmm|tool|tooling|trojan)\b",
            raw,
            flags=re.IGNORECASE,
        ):
            normalized = match.group(1).strip(".,;:()[]{}\"'")
            if self._is_relevance_term(normalized):
                terms.add(normalized)
        return sorted(terms, key=str.casefold)

    def _relevance_cache_signature(self, relevance_context: dict[str, Any] | None) -> tuple[Any, ...]:
        if not relevance_context:
            return ()
        return (
            bool(relevance_context.get("has_threats")),
            tuple(
                (item.get("term", ""), item.get("weight", 0), item.get("reason", ""))
                for item in relevance_context.get("strong_terms", relevance_context.get("terms", []))
            ),
            tuple(
                (item.get("term", ""), item.get("weight", 0), item.get("reason", ""))
                for item in relevance_context.get("weak_terms", [])
            ),
            tuple(relevance_context.get("indicator_types", [])),
            tuple(relevance_context.get("indicator_values", [])),
        )

    def _sigma_rule_search_text(self, rule: dict[str, Any]) -> str:
        payload = rule.get("payload", {})
        values = [
            rule.get("name"),
            rule.get("external_id"),
            rule.get("short_description"),
            rule.get("tags", []),
            payload.get("title"),
            payload.get("summary"),
            payload.get("description"),
            payload.get("tags", []),
            payload.get("references", []),
            payload.get("author"),
            payload.get("falsepositives", []),
            payload.get("fields", []),
            payload.get("logsource", {}),
            payload.get("source_family"),
            payload.get("detection", {}),
            payload.get("repo_path"),
            payload.get("raw_yaml"),
        ]
        return " ".join(self._flatten_relevance_value(value) for value in values).casefold()

    def _flatten_relevance_value(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, dict):
            return " ".join(
                part
                for key, nested in value.items()
                for part in (
                    self._flatten_relevance_value(key),
                    self._flatten_relevance_value(nested),
                )
                if part
            )
        if isinstance(value, (list, tuple, set)):
            return " ".join(
                part
                for item in value
                for part in (self._flatten_relevance_value(item),)
                if part
            )
        return str(value)

    def evaluate_rule_relevance(
        self,
        rule: dict[str, Any],
        *,
        relevance_context: dict[str, Any] | None,
        detected_ioc_types: list[str] | None = None,
    ) -> dict[str, Any]:
        """Return strict APT relevance scoring for a candidate Sigma rule."""

        if not relevance_context or not relevance_context.get("has_threats"):
            return {
                "passes": True,
                "score": 0.0,
                "reasons": ["Manual ATT&CK scope: APT relevance gate bypassed."],
                "matches": [],
            }

        rule_text = self._sigma_rule_search_text(rule)
        score = 0.0
        concrete_score = 0.0
        reasons: list[str] = []
        matches: list[str] = []
        strong_terms = relevance_context.get("strong_terms")
        if strong_terms is None:
            strong_terms = relevance_context.get("terms", [])
        for term in strong_terms:
            value = str(term.get("term", "")).strip()
            if not value:
                continue
            if value.casefold() in rule_text:
                weight = float(term.get("weight", 1.0))
                score += weight
                concrete_score += weight
                reason = str(term.get("reason", "APT relevance"))
                match = f"{reason}: {value}"
                if match not in matches:
                    matches.append(match)
                if reason not in reasons:
                    reasons.append(reason)

        for term in relevance_context.get("weak_terms", []):
            value = str(term.get("term", "")).strip()
            if not value:
                continue
            if value.casefold() in rule_text:
                weight = float(term.get("weight", 0.0))
                score += weight
                reason = str(term.get("reason", "APT context"))
                match = f"{reason}: {value}"
                if match not in matches:
                    matches.append(match)
                if reason not in reasons:
                    reasons.append(reason)

        detected = set(detected_ioc_types if detected_ioc_types is not None else self._infer_sigma_ioc_types(rule))
        threat_ioc_types = set(relevance_context.get("indicator_types", []))
        matched_ioc_types = sorted(detected & threat_ioc_types)
        if matched_ioc_types:
            score += 1.2
            reasons.append("APT indicator type")
            matches.append(f"APT indicator type: {', '.join(matched_ioc_types)}")

        indicator_values = set(relevance_context.get("indicator_values", []))
        for value in sorted(indicator_values):
            if value and value in rule_text:
                score += 4.0
                concrete_score += 4.0
                reasons.append("APT indicator value")
                matches.append(f"APT indicator value: {value}")

        return {
            "passes": concrete_score > 0,
            "score": round(score, 3),
            "reasons": list(dict.fromkeys(reasons)),
            "matches": list(dict.fromkeys(matches)),
        }

    def _rule_ref_from_rule(
        self,
        rule: dict[str, Any],
        matched_techniques: list[str],
        relevance: dict[str, Any] | None = None,
        tool_compatibility: dict[str, Any] | None = None,
        effective_families: list[str] | tuple[str, ...] | None = None,
    ) -> dict[str, Any]:
        payload = rule.get("payload", {})
        ref = {
            "entity_id": rule.get("id"),
            "external_id": rule.get("external_id", ""),
            "name": rule.get("name", ""),
            "source_family": normalize_sigma_source_family(payload.get("logsource", {}))
            or str(payload.get("source_family", "")).strip().lower(),
            "techniques": sorted(matched_techniques),
        }
        if relevance is not None:
            ref.update(
                {
                    "sigma_relevance_score": relevance.get("score", 0.0),
                    "sigma_relevance_reasons": relevance.get("reasons", []),
                    "sigma_relevance_matches": relevance.get("matches", []),
                }
            )
        if tool_compatibility is not None:
            ref.update(
                {
                    "sigma_tool_compatibility_reasons": tool_compatibility.get("reasons", []),
                    "sigma_tool_compatibility_matches": tool_compatibility.get("matches", []),
                    "sigma_tool_scope_reasons": tool_compatibility.get("reasons", []),
                    "sigma_tool_scope_matches": tool_compatibility.get("matches", []),
                }
            )
        if effective_families is not None:
            ref["sigma_effective_families"] = list(effective_families)
        return ref

    def _tool_sigma_default_families(self, tool: dict[str, Any]) -> set[str]:
        scope = tool.get("payload", {}).get("sigma_scope", {})
        if not isinstance(scope, dict):
            return set()
        values = scope.get("default_families", [])
        if not isinstance(values, list):
            return set()
        return {
            str(value).strip().lower()
            for value in values
            if str(value).strip()
        }

    def _rule_source_family(self, rule: dict[str, Any]) -> str:
        payload = rule.get("payload", {})
        return (
            normalize_sigma_source_family(payload.get("logsource", {}))
            or str(payload.get("source_family", "")).strip().lower()
        )

    def evaluate_rule_tool_compatibility(
        self,
        rule: dict[str, Any],
        *,
        tool: dict[str, Any],
    ) -> dict[str, Any]:
        """Return whether a Sigma rule belongs to the selected tool's declared Sigma scope."""

        default_families = self._tool_sigma_default_families(tool)
        if not default_families:
            return {
                "passes": False,
                "reasons": ["Tool has no explicit Sigma family scope for generation."],
                "matches": [],
            }
        payload = rule.get("payload", {})
        family = self._rule_source_family(rule)
        if not family:
            return {
                "passes": False,
                "reasons": ["Sigma rule has no source family to compare against tool scope."],
                "matches": [],
            }
        if family not in default_families:
            return {
                "passes": False,
                "reasons": ["Outside selected tool Sigma scope"],
                "matches": [f"{family} not in {', '.join(sorted(default_families))}"],
            }
        return {
            "passes": True,
            "reasons": ["Tool Sigma family scope"],
            "matches": [f"{family} supported by {tool.get('name', 'selected tool')}"],
        }

    def _apply_sigma_caps(
        self,
        rule_infos: list[dict[str, Any]],
        *,
        max_per_tool: int = SIGMA_MAX_STEPS_PER_TOOL,
        max_per_technique: int = SIGMA_MAX_STEPS_PER_TECHNIQUE,
    ) -> tuple[list[dict[str, Any]], int]:
        capped: list[dict[str, Any]] = []
        technique_counts: dict[str, int] = {}
        omitted = 0
        for info in rule_infos:
            if len(capped) >= max_per_tool:
                omitted += 1
                continue
            matched_techniques = list(info.get("matched_techniques", []))
            if matched_techniques and not any(
                technique_counts.get(technique_id, 0) < max_per_technique
                for technique_id in matched_techniques
            ):
                omitted += 1
                continue
            capped.append(info)
            for technique_id in matched_techniques:
                technique_counts[technique_id] = technique_counts.get(technique_id, 0) + 1
        return capped, omitted

    def select_generation_rules(
        self,
        *,
        tool: dict[str, Any],
        technique_scores: dict[str, dict[str, Any]],
        selected_families: list[str] | set[str] | tuple[str, ...] | None = None,
        relevance_context: dict[str, Any] | None = None,
        apply_caps: bool = True,
    ) -> dict[str, Any]:
        """Select Sigma rules for Generate using the same gates for preview and draft output."""

        normalized_scores = {
            str(technique_id).strip(): dict(score_data or {})
            for technique_id, score_data in technique_scores.items()
            if str(technique_id).strip()
        }
        candidate_rules = self.matching_rules(normalized_scores.keys())
        tool_scope_families = sorted(self._tool_sigma_default_families(tool))
        requested_families = (
            None
            if selected_families is None
            else set(self.normalize_selected_families(selected_families))
        )
        effective_families = (
            tool_scope_families
            if requested_families is None
            else sorted(set(tool_scope_families) & requested_families)
        )
        effective_family_set = set(effective_families)

        relevant_infos: list[dict[str, Any]] = []
        omitted_by_tool_scope = 0
        omitted_by_family_scope = 0
        omitted_by_relevance = 0

        if not tool_scope_families:
            return {
                "selected_infos": [],
                "eligible_infos": [],
                "candidate_count": len(candidate_rules),
                "tool_scope_families": [],
                "effective_families": [],
                "omitted_by_tool_scope_count": len(candidate_rules),
                "omitted_by_family_scope_count": 0,
                "omitted_by_relevance_count": 0,
                "omitted_by_apt_relevance_count": 0,
                "omitted_by_cap_count": 0,
            }

        for rule in candidate_rules:
            matched_techniques = [
                technique_id
                for technique_id in rule.get("payload", {}).get("attack_techniques", [])
                if technique_id in normalized_scores
            ]
            if not matched_techniques:
                omitted_by_relevance += 1
                continue
            family = self._rule_source_family(rule)
            if not family or family not in tool_scope_families:
                omitted_by_tool_scope += 1
                continue
            if family not in effective_family_set:
                omitted_by_family_scope += 1
                continue

            tool_compatibility = self.evaluate_rule_tool_compatibility(rule, tool=tool)
            if not tool_compatibility.get("passes"):
                omitted_by_tool_scope += 1
                continue
            detected_ioc_types = self._infer_sigma_ioc_types(rule)
            relevance = self.evaluate_rule_relevance(
                rule,
                relevance_context=relevance_context,
                detected_ioc_types=detected_ioc_types,
            )
            if not relevance.get("passes"):
                omitted_by_relevance += 1
                continue
            base_score = self._score_sigma_rule(rule, matched_techniques, normalized_scores)
            relevant_infos.append(
                {
                    "rule": rule,
                    "matched_techniques": matched_techniques,
                    "detected_ioc_types": detected_ioc_types,
                    "relevance": relevance,
                    "tool_compatibility": tool_compatibility,
                    "effective_families": effective_families,
                    "base_score": base_score,
                    "rank_score": (float(relevance.get("score", 0.0)) * 10.0) + base_score,
                }
            )

        relevant_infos.sort(
            key=lambda item: (
                item["rank_score"],
                item["base_score"],
                item["rule"].get("name", ""),
                item["rule"].get("external_id", ""),
            ),
            reverse=True,
        )
        selected_infos = relevant_infos
        omitted_by_cap = 0
        if apply_caps:
            selected_infos, omitted_by_cap = self._apply_sigma_caps(relevant_infos)
        return {
            "selected_infos": selected_infos,
            "eligible_infos": relevant_infos,
            "candidate_count": len(candidate_rules),
            "tool_scope_families": tool_scope_families,
            "effective_families": effective_families,
            "omitted_by_tool_scope_count": omitted_by_tool_scope,
            "omitted_by_family_scope_count": omitted_by_family_scope,
            "omitted_by_relevance_count": omitted_by_relevance,
            "omitted_by_apt_relevance_count": omitted_by_relevance,
            "omitted_by_cap_count": omitted_by_cap,
        }

    def matching_rule_refs(
        self,
        technique_ids: list[str] | set[str],
        *,
        selected_families: list[str] | set[str] | tuple[str, ...] | None = None,
    ) -> list[dict[str, Any]]:
        selected_family_values = self.normalize_selected_families(selected_families)
        matched: dict[int, dict[str, Any]] = {}
        for technique_id in sorted(set(technique_ids)):
            technique = self.store.get_entity_by_external_id("MitreTechnique", technique_id)
            if technique is None:
                continue
            related = self.store.get_related_entities(technique["id"]).get("SigmaRule", [])
            for sigma_ref in related:
                entity_id = int(sigma_ref["entity_id"])
                sigma_rule = self.store.get_entity(entity_id)
                if sigma_rule is None or not self._rule_matches_selected_families(
                    sigma_rule,
                    selected_family_values,
                ):
                    continue
                rule_ref = matched.setdefault(
                    entity_id,
                    {
                        "entity_id": entity_id,
                        "external_id": sigma_ref.get("external_id", ""),
                        "name": sigma_ref.get("name", ""),
                        "techniques": set(),
                        "source_family": normalize_sigma_source_family(
                            sigma_rule.get("payload", {}).get("logsource", {})
                        )
                        or str(sigma_rule.get("payload", {}).get("source_family", "")).strip().lower(),
                    },
                )
                rule_ref["techniques"].add(technique_id)
        refs: list[dict[str, Any]] = []
        for ref in matched.values():
            refs.append(
                {
                    "entity_id": ref["entity_id"],
                    "external_id": ref["external_id"],
                    "name": ref["name"],
                    "source_family": ref.get("source_family", ""),
                    "techniques": sorted(ref["techniques"]),
                }
            )
        return sorted(
            refs,
            key=lambda item: (
                item.get("name", ""),
                item.get("external_id", ""),
            ),
            reverse=True,
        )

    def matching_rules(
        self,
        technique_ids: list[str] | set[str],
        *,
        selected_families: list[str] | set[str] | tuple[str, ...] | None = None,
    ) -> list[dict]:
        selected_family_values = self.normalize_selected_families(selected_families)
        matched: dict[int, dict] = {}
        for technique_id in sorted(set(technique_ids)):
            technique = self.store.get_entity_by_external_id("MitreTechnique", technique_id)
            if technique is None:
                continue
            related = self.store.get_related_entities(technique["id"]).get("SigmaRule", [])
            for sigma_ref in related:
                if sigma_ref["entity_id"] in matched:
                    continue
                sigma_rule = self.store.get_entity(sigma_ref["entity_id"])
                if sigma_rule is not None and self._rule_matches_selected_families(
                    sigma_rule,
                    selected_family_values,
                ):
                    matched[sigma_ref["entity_id"]] = sigma_rule
        return sorted(
            matched.values(),
            key=lambda item: (
                item.get("payload", {}).get("level", ""),
                item.get("name", ""),
                item.get("external_id", ""),
            ),
            reverse=True,
        )

    def summarize_tool_coverage(
        self,
        tool: dict,
        technique_ids: list[str] | set[str],
        *,
        selected_families: list[str] | set[str] | tuple[str, ...] | None = None,
        relevance_context: dict[str, Any] | None = None,
        apply_caps: bool = False,
        include_rules: bool = False,
        preview_limit: int = 10,
    ) -> dict[str, Any]:
        normalized_techniques = tuple(sorted(set(technique_ids)))
        normalized_families = self.normalize_selected_families(selected_families)
        cache_key = (
            tool.get("id"),
            tool.get("updated_at", ""),
            normalized_techniques,
            normalized_families,
            selected_families is None,
            self._relevance_cache_signature(relevance_context),
            bool(apply_caps),
            include_rules,
            int(preview_limit),
        )
        cached = self._coverage_summary_cache.get(cache_key)
        if cached is not None:
            return dict(cached)

        omitted_by_relevance = 0
        omitted_by_tool_scope = 0
        omitted_by_family_scope = 0
        omitted_by_cap = 0
        effective_families: list[str] = []
        tool_scope_families = sorted(self._tool_sigma_default_families(tool))
        if relevance_context is not None:
            technique_scores = {
                technique_id: {"confidence": 1.0}
                for technique_id in normalized_techniques
            }
            selection = self.select_generation_rules(
                tool=tool,
                technique_scores=technique_scores,
                selected_families=selected_families,
                relevance_context=relevance_context,
                apply_caps=apply_caps,
            )
            selected_infos = selection["selected_infos"]
            tool_scope_families = list(selection["tool_scope_families"])
            effective_families = list(selection["effective_families"])
            omitted_by_relevance = int(selection["omitted_by_relevance_count"])
            omitted_by_tool_scope = int(selection["omitted_by_tool_scope_count"])
            omitted_by_family_scope = int(selection["omitted_by_family_scope_count"])
            omitted_by_cap = int(selection["omitted_by_cap_count"])
            rule_refs = [
                self._rule_ref_from_rule(
                    info["rule"],
                    info["matched_techniques"],
                    info["relevance"],
                    info["tool_compatibility"],
                    info["effective_families"],
                )
                for info in selected_infos
            ]
        else:
            selected_infos = []
            rule_refs = self.matching_rule_refs(
                normalized_techniques,
                selected_families=normalized_families,
            )
        matched_techniques = sorted(
            {
                technique_id
                for rule_ref in rule_refs
                for technique_id in rule_ref.get("techniques", [])
                if technique_id in normalized_techniques
            }
        )
        translation = self.tool_translation(tool)
        mode = self.tool_translation_mode(tool)
        if relevance_context is not None and not effective_families:
            mode = "reference_only"
        sigma_scope_missing = self.tool_translation_mode(tool) == "translation_enabled" and not tool_scope_families
        summary = {
            "mode": mode,
            "translation": translation,
            "rule_count": len(rule_refs),
            "relevant_rule_count": len(rule_refs) + omitted_by_cap,
            "omitted_by_relevance_count": omitted_by_relevance,
            "omitted_by_apt_relevance_count": omitted_by_relevance,
            "omitted_by_tool_scope_count": omitted_by_tool_scope,
            "omitted_by_family_scope_count": omitted_by_family_scope,
            "omitted_by_cap_count": omitted_by_cap,
            "tool_scope_families": tool_scope_families,
            "effective_families": effective_families,
            "sigma_scope_missing": sigma_scope_missing,
            "matched_techniques": matched_techniques,
            "selected_families": list(normalized_families),
            "rule_preview": rule_refs[: max(0, int(preview_limit))],
        }
        if include_rules:
            if relevance_context is not None:
                selected_rule_ids = {info["rule"].get("id") for info in selected_infos}
                summary["rules"] = [
                    info["rule"]
                    for info in selected_infos
                    if info["rule"].get("id") in selected_rule_ids
                ]
            else:
                summary["rules"] = self.matching_rules(
                    normalized_techniques,
                    selected_families=normalized_families,
                )
        self._coverage_summary_cache[cache_key] = summary
        return dict(summary)

    def build_translated_steps(
        self,
        *,
        tool: dict,
        technique_scores: dict[str, dict],
        selected_families: list[str] | set[str] | tuple[str, ...] | None = None,
        indicator_context: dict[str, list[str]] | None = None,
        relevance_context: dict[str, Any] | None = None,
    ) -> list[tuple[float, dict]]:
        translation = self.tool_translation(tool)
        if not translation or not translation.get("enabled") or not self.translator.supports(translation):
            return []

        ranked_steps: list[tuple[float, dict]] = []
        indicator_context = indicator_context or {}
        selection = self.select_generation_rules(
            tool=tool,
            technique_scores=technique_scores,
            selected_families=selected_families,
            relevance_context=relevance_context,
            apply_caps=True,
        )
        for info in selection["selected_infos"]:
            rule = info["rule"]
            matched_techniques = info["matched_techniques"]
            detected_ioc_types = info["detected_ioc_types"]
            relevance = info["relevance"]
            tool_compatibility = info["tool_compatibility"]
            effective_families = info["effective_families"]
            translated = self.translator.translate_rule(rule, translation)
            if translated is None:
                continue
            payload = rule.get("payload", {})
            sigma_ioc_guidance = self._build_sigma_ioc_guidance(
                detected_ioc_types,
                indicator_context,
            )
            method_kind = self._classify_sigma_method_kind(rule, detected_ioc_types)
            score = info["base_score"] + min(0.35, float(relevance.get("score", 0.0)) * 0.03)
            ranked_steps.append(
                (
                    score,
                    {
                        "tool_pack": tool["name"],
                        "tool_external_id": tool["external_id"],
                        "title": f"{rule['name']} (Sigma)",
                        "techniques": matched_techniques,
                        "method_strength": "supporting_pivot",
                        "method_kind": method_kind,
                        "strength_reason": (
                            "Supplemental Sigma rule translation added to broaden ATT&CK coverage behind the authored tool-native hunts."
                        ),
                        "behavior_focus": payload.get("description")
                        or payload.get("title")
                        or "Validate hits from the translated Sigma rule against the mapped ATT&CK behavior.",
                        "noise_level": self._noise_level_from_sigma_level(payload.get("level", "")),
                        "privilege_required": "unknown",
                        "time_cost": 2,
                        "data_sources": self._data_sources_from_logsource(payload.get("logsource", {})),
                        "prerequisites": self._prerequisites_from_translation(tool, payload),
                        "supported_ioc_types": detected_ioc_types,
                        "rendered_query": translated["query"],
                        "unresolved_placeholders": [],
                        "ioc_insertions": {},
                        "sigma_detected_ioc_types": detected_ioc_types,
                        "sigma_ioc_guidance": sigma_ioc_guidance,
                        "why_selected": self._build_sigma_selection_reason(
                            tool=tool,
                            rule=rule,
                            techniques=matched_techniques,
                            translation_target=translated["translation_target"],
                            relevance=relevance,
                            tool_compatibility=tool_compatibility,
                        ),
                        "safety_labels": ["Operator review", "Translated Sigma"],
                        "enabled": True,
                        "execution_surface": (
                            tool.get("payload", {}).get("execution_surface")
                            or tool.get("name", "Tool surface")
                        ),
                        "surface_details": tool.get("payload", {}).get("surface_details", ""),
                        "service_examples": tool.get("payload", {}).get("service_examples", []),
                        "expectation": (
                            "Review Sigma-matched hits in the target tool and validate whether they represent the mapped ATT&CK behavior in context."
                        ),
                        "content_origin": "sigma_translated",
                        "sigma_rule_id": rule["external_id"],
                        "sigma_title": rule["name"],
                        "sigma_relevance_score": relevance.get("score", 0.0),
                        "sigma_relevance_reasons": relevance.get("reasons", []),
                        "sigma_relevance_matches": relevance.get("matches", []),
                        "sigma_tool_compatibility_reasons": tool_compatibility.get("reasons", []),
                        "sigma_tool_compatibility_matches": tool_compatibility.get("matches", []),
                        "sigma_tool_scope_reasons": tool_compatibility.get("reasons", []),
                        "sigma_tool_scope_matches": tool_compatibility.get("matches", []),
                        "sigma_effective_families": effective_families,
                        "sigma_source_family": normalize_sigma_source_family(payload.get("logsource", {}))
                        or str(payload.get("source_family", "")).strip().lower(),
                        "translation_target": translated["translation_target"],
                        "raw_rule_url": payload.get("raw_rule_url") or rule.get("source_url", ""),
                        "output_format": translated["output_format"],
                    },
                )
            )
        return ranked_steps

    def available_source_families(
        self,
        technique_ids: list[str] | set[str] | None = None,
    ) -> dict[str, int]:
        if technique_ids:
            rules = self.matching_rules(technique_ids)
        else:
            rules = self.store.list_entities("SigmaRule")
        counts: dict[str, int] = {}
        for rule in rules:
            family = normalize_sigma_source_family(rule.get("payload", {}).get("logsource", {}))
            if not family:
                family = str(rule.get("payload", {}).get("source_family", "")).strip().lower()
            if not family:
                continue
            counts[family] = counts.get(family, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))

    def _sigma_document_metadata(self, rule: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
        payload = rule.get("payload", {})
        detection = payload.get("detection")
        fields = payload.get("fields", [])
        if isinstance(detection, dict) and isinstance(fields, list):
            return detection, [str(field).strip() for field in fields if str(field).strip()]
        raw_yaml = str(payload.get("raw_yaml", "") or "").strip()
        if not raw_yaml:
            return (
                detection if isinstance(detection, dict) else {},
                [str(field).strip() for field in fields if str(field).strip()],
            )
        try:
            yaml = importlib.import_module("yaml")
            docs = [doc for doc in yaml.safe_load_all(raw_yaml) if isinstance(doc, dict)]
        except Exception:
            docs = []
        if not docs:
            return (
                detection if isinstance(detection, dict) else {},
                [str(field).strip() for field in fields if str(field).strip()],
            )
        document = docs[0]
        parsed_detection = document.get("detection")
        parsed_fields = document.get("fields", [])
        return (
            parsed_detection if isinstance(parsed_detection, dict) else {},
            [str(field).strip() for field in parsed_fields if str(field).strip()],
        )

    def _selection_field_names(self, value: Any) -> list[str]:
        field_names: list[str] = []
        if isinstance(value, dict):
            for field_spec, nested in value.items():
                field = str(field_spec).split("|", 1)[0].strip()
                if field and field.lower() != "condition":
                    field_names.append(field)
                field_names.extend(self._selection_field_names(nested))
        elif isinstance(value, list):
            for item in value:
                field_names.extend(self._selection_field_names(item))
        return field_names

    def _infer_sigma_ioc_types(self, rule: dict[str, Any]) -> list[str]:
        detection, fields = self._sigma_document_metadata(rule)
        field_names = list(fields)
        for key, value in detection.items():
            if key == "condition":
                continue
            field_names.extend(self._selection_field_names(value))

        inferred: list[str] = []
        for field_name in field_names:
            normalized = str(field_name).strip().lower()
            if not normalized:
                continue
            candidate = self._ioc_type_for_field(normalized)
            if candidate and candidate not in inferred:
                inferred.append(candidate)
        return inferred

    @staticmethod
    def _ioc_type_for_field(field_name: str) -> str | None:
        if any(token in field_name for token in ("sha256", "sha-256")):
            return "sha256"
        if "md5" in field_name:
            return "md5"
        if any(token in field_name for token in ("email", "mail")):
            return "email"
        if any(token in field_name for token in ("url", "uri")):
            return "url"
        if any(token in field_name for token in ("domain", "fqdn", "dns", "destinationhostname", "server_name")):
            return "domain"
        if any(token in field_name for token in ("ipv4", "ipv6", ".ip", "_ip", "sourceip", "destinationip", "clientip", "serverip")):
            return "ip"
        if field_name.endswith("ip") or field_name == "ip":
            return "ip"
        if any(token in field_name for token in ("hostname", "host.name", "computername", "devicehostname")):
            return "hostname"
        return None

    def _build_sigma_ioc_guidance(
        self,
        detected_ioc_types: list[str],
        indicator_context: dict[str, list[str]],
    ) -> list[str]:
        guidance: list[str] = []
        seen: set[str] = set()
        for ioc_type in detected_ioc_types:
            values: list[str] = []
            for alias in SIGMA_IOC_TYPE_ALIASES.get(ioc_type, (ioc_type,)):
                values.extend(indicator_context.get(alias, []))
            for value in values:
                normalized = str(value).strip()
                if not normalized:
                    continue
                entry = f"{ioc_type} = {normalized}"
                if entry in seen:
                    continue
                seen.add(entry)
                guidance.append(entry)
        return guidance

    def _classify_sigma_method_kind(
        self,
        rule: dict[str, Any],
        detected_ioc_types: list[str],
    ) -> str:
        detection, _fields = self._sigma_document_metadata(rule)
        condition = str(detection.get("condition", "")).strip().lower()
        selection_names = [
            str(key).strip().lower()
            for key in detection.keys()
            if str(key).strip() and str(key).strip().lower() != "condition"
        ]
        if len(selection_names) > 1:
            named_mentions = sum(
                1
                for name in selection_names
                if re.search(rf"(?<![a-z0-9_]){re.escape(name)}(?![a-z0-9_])", condition)
            )
            if named_mentions > 1 or re.search(r"\b(all|1)\s+of\b", condition):
                return "correlation"
        if detected_ioc_types:
            return "ioc_pivot"
        return "behavior_hunt"

    @staticmethod
    def _score_sigma_rule(
        rule: dict,
        techniques: list[str],
        technique_scores: dict[str, dict],
    ) -> float:
        technique_score = max(technique_scores[tech]["confidence"] for tech in techniques)
        payload = rule.get("payload", {})
        level_score = SIGMA_LEVEL_SCORES.get(str(payload.get("level", "")).lower(), 0.6)
        status_score = SIGMA_STATUS_SCORES.get(str(payload.get("status", "")).lower(), 0.75)
        coverage_bonus = min(0.08, 0.04 * max(len(techniques) - 1, 0))
        return (technique_score * 0.45) + (level_score * 0.25) + (status_score * 0.2) + coverage_bonus

    @staticmethod
    def _noise_level_from_sigma_level(level: str) -> str:
        lowered = str(level or "").lower()
        if lowered in {"critical", "high"}:
            return "low"
        if lowered in {"low", "informational"}:
            return "high"
        return "medium"

    @staticmethod
    def _data_sources_from_logsource(logsource: dict[str, Any]) -> list[str]:
        values = [
            str(logsource.get("product", "")).strip(),
            str(logsource.get("service", "")).strip(),
            str(logsource.get("category", "")).strip(),
        ]
        return [value for value in values if value]

    @staticmethod
    def _prerequisites_from_translation(tool: dict, payload: dict[str, Any]) -> list[str]:
        prerequisites = []
        if payload.get("logsource"):
            logsource = payload["logsource"]
            context = " / ".join(
                value
                for value in (
                    str(logsource.get("product", "")).strip(),
                    str(logsource.get("service", "")).strip(),
                    str(logsource.get("category", "")).strip(),
                )
                if value
            )
            if context:
                prerequisites.append(f"Mapped Elastic fields should exist for Sigma logsource: {context}.")
        execution_surface = tool.get("payload", {}).get("execution_surface", "")
        if execution_surface:
            prerequisites.append(f"Run and validate results in {execution_surface}.")
        return prerequisites

    @staticmethod
    def _build_sigma_selection_reason(
        *,
        tool: dict,
        rule: dict,
        techniques: list[str],
        translation_target: str,
        relevance: dict[str, Any] | None = None,
        tool_compatibility: dict[str, Any] | None = None,
    ) -> str:
        parts = [
            f"Selected because Sigma rule '{rule['name']}' overlaps ATT&CK coverage for {', '.join(techniques)}.",
            f"The rule was translated for {tool['name']} via the {translation_target} backend.",
        ]
        if tool_compatibility:
            matches = ", ".join(tool_compatibility.get("matches", []))
            if matches:
                parts.append(f"Tool/family compatibility: {matches}.")
        if relevance:
            reasons = ", ".join(relevance.get("reasons", [])) or "manual ATT&CK scope"
            parts.append(f"APT relevance: {reasons}.")
        parts.append("Authored tool-native hunts stay ranked first and Sigma fills narrower supporting coverage.")
        return " ".join(parts)
