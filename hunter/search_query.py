"""Shared miniquery parsing and matching for visible search boxes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


DEFAULT_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "name": ("name", "title"),
    "title": ("title", "name"),
    "id": ("id", "external_id", "technique"),
    "external_id": ("external_id", "id", "technique"),
    "description": ("description", "short_description"),
    "summary": ("summary", "description", "short_description"),
    "tag": ("tag", "tags"),
    "tags": ("tag", "tags"),
    "status": ("status",),
    "source": ("source", "source_name", "source_ref", "source_url"),
    "technique": ("technique", "techniques", "attack", "mitre", "id", "external_id"),
    "attack": ("attack", "technique", "techniques", "mitre", "id", "external_id"),
    "mitre": ("mitre", "technique", "techniques", "attack", "id", "external_id"),
    "template": ("template",),
    "kind": ("kind", "method_kind"),
    "strength": ("strength", "method_strength"),
    "ioc": ("ioc", "iocs", "indicator", "indicators", "placeholder", "placeholders"),
    "behavior": ("behavior", "behavior_focus"),
    "expectation": ("expectation",),
    "prerequisite": ("prerequisite", "prerequisites"),
    "datasource": ("datasource", "data_source", "data_sources", "datasources"),
    "placeholder": ("placeholder", "placeholders"),
    "surface": ("surface", "execution_surface", "surface_details"),
    "service": ("service", "service_examples"),
    "alias": ("alias", "aliases"),
    "indicator": ("indicator", "indicators", "ioc", "iocs"),
    "hunt": ("hunt", "hunts", "extra_hunts", "method"),
    "platform": ("platform",),
    "method": ("method", "methods", "hunt_methods", "hunt", "hunts"),
}


@dataclass(frozen=True)
class SearchTerm:
    value: str
    field: str | None = None
    excluded: bool = False
    literal: str | None = None


@dataclass(frozen=True)
class SearchQuery:
    raw: str
    terms: tuple[SearchTerm, ...]


def parse_search_query(query: str) -> SearchQuery:
    """Parse a tolerant miniquery string.

    The parser intentionally never raises for malformed user input. Unmatched
    quotes are treated as a phrase ending at the input boundary.
    """

    raw = str(query or "")
    terms: list[SearchTerm] = []
    index = 0
    length = len(raw)
    while index < length:
        while index < length and raw[index].isspace():
            index += 1
        if index >= length:
            break

        excluded = False
        if raw[index] in "+-":
            excluded = raw[index] == "-"
            index += 1

        field: str | None = None
        field_start = index
        if index < length and raw[index] != '"':
            while index < length and not raw[index].isspace() and raw[index] not in ':"':
                index += 1
            if index < length and raw[index] == ":" and index > field_start:
                field = raw[field_start:index].strip().casefold()
                index += 1
            else:
                index = field_start

        value, index = _read_value(raw, index)
        if not value:
            continue
        literal = f"{field}:{value}" if field else value
        terms.append(SearchTerm(value=value, field=field, excluded=excluded, literal=literal))
    return SearchQuery(raw=raw, terms=tuple(terms))


def matches_search_query(
    query: str | SearchQuery,
    document: Mapping[str, Any],
    *,
    field_aliases: Mapping[str, tuple[str, ...]] | None = None,
) -> bool:
    parsed = query if isinstance(query, SearchQuery) else parse_search_query(query)
    if not parsed.terms:
        return True
    normalized_document = _normalize_document(document)
    aliases = field_aliases or DEFAULT_FIELD_ALIASES
    full_text = " ".join(value for values in normalized_document.values() for value in values)

    for term in parsed.terms:
        matched = _term_matches(term, normalized_document, full_text, aliases)
        if term.excluded and matched:
            return False
        if not term.excluded and not matched:
            return False
    return True


def _read_value(raw: str, index: int) -> tuple[str, int]:
    if index >= len(raw):
        return "", index
    if raw[index] == '"':
        return _read_quoted_value(raw, index + 1)
    start = index
    while index < len(raw) and not raw[index].isspace():
        index += 1
    return raw[start:index], index


def _read_quoted_value(raw: str, index: int) -> tuple[str, int]:
    chars: list[str] = []
    while index < len(raw):
        char = raw[index]
        if char == "\\" and index + 1 < len(raw):
            chars.append(raw[index + 1])
            index += 2
            continue
        if char == '"':
            return "".join(chars), index + 1
        chars.append(char)
        index += 1
    return "".join(chars), index


def _term_matches(
    term: SearchTerm,
    document: dict[str, list[str]],
    full_text: str,
    field_aliases: Mapping[str, tuple[str, ...]],
) -> bool:
    needle = term.value.casefold()
    if term.field:
        field_values = _field_values(term.field, document, field_aliases)
        if field_values:
            return any(needle in value for value in field_values)
        return str(term.literal or term.value).casefold() in full_text
    return needle in full_text


def _field_values(
    field: str,
    document: dict[str, list[str]],
    field_aliases: Mapping[str, tuple[str, ...]],
) -> list[str]:
    keys = field_aliases.get(field, (field,))
    values: list[str] = []
    for key in keys:
        values.extend(document.get(key.casefold(), []))
    return values


def _normalize_document(document: Mapping[str, Any]) -> dict[str, list[str]]:
    normalized: dict[str, list[str]] = {}
    for key, value in document.items():
        normalized[str(key).casefold()] = [
            text.casefold()
            for text in _flatten_values(value)
            if text.strip()
        ]
    return normalized


def _flatten_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        values: list[str] = []
        for key, item in value.items():
            values.extend(_flatten_values(key))
            values.extend(_flatten_values(item))
        return values
    if isinstance(value, (list, tuple, set)):
        values: list[str] = []
        for item in value:
            values.extend(_flatten_values(item))
        return values
    return [str(value)]
