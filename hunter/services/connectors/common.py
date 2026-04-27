"""Shared text and archive helpers for sync connectors."""

from __future__ import annotations

import html
import re
import zipfile
from datetime import datetime, timezone


def clean_attack_markup(text: str) -> str:
    text = html.unescape(text or "")
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</(p|div|h\d)>", "\n\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<li[^>]*>", "\n- ", text, flags=re.IGNORECASE)
    text = re.sub(r"</li>", "", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    return text.strip()


def attack_text_blocks(text: str) -> list[dict[str, str]]:
    cleaned = clean_attack_markup(text)
    if not cleaned:
        return []

    blocks: list[dict[str, str]] = []
    for raw_block in re.split(r"\n\s*\n", cleaned):
        lines = [line.strip() for line in raw_block.splitlines() if line.strip()]
        if not lines:
            continue
        paragraph_lines: list[str] = []
        for line in lines:
            if re.match(r"^[-*•]\s+", line) or re.match(r"^\d+\.\s+", line):
                if paragraph_lines:
                    blocks.append(
                        {"type": "paragraph", "text": " ".join(paragraph_lines).strip()}
                    )
                    paragraph_lines = []
                blocks.append(
                    {
                        "type": "bullet",
                        "text": re.sub(r"^([-*•]|\d+\.)\s+", "", line).strip(),
                    }
                )
                continue
            if ":" in line and len(line) < 120:
                label, value = line.split(":", 1)
                if label and label[:1].isupper() and value.strip():
                    if paragraph_lines:
                        blocks.append(
                            {"type": "paragraph", "text": " ".join(paragraph_lines).strip()}
                        )
                        paragraph_lines = []
                    blocks.append(
                        {
                            "type": "label",
                            "label": label.strip(),
                            "text": value.strip(),
                        }
                    )
                    continue
            paragraph_lines.append(line)
        if paragraph_lines:
            blocks.append({"type": "paragraph", "text": " ".join(paragraph_lines).strip()})
    return blocks


def attack_text_html(blocks: list[dict[str, str]]) -> str:
    html_parts: list[str] = []
    for block in blocks:
        block_type = block.get("type")
        if block_type == "paragraph":
            html_parts.append(f"<p>{html.escape(block.get('text', ''))}</p>")
        elif block_type == "bullet":
            html_parts.append(f"<li>{html.escape(block.get('text', ''))}</li>")
        elif block_type == "label":
            label = html.escape(block.get("label", ""))
            text = html.escape(block.get("text", ""))
            html_parts.append(f"<p><strong>{label}:</strong> {text}</p>")
    return "\n".join(html_parts)


def short_attack_summary(text: str, *, limit: int = 280) -> str:
    cleaned = clean_attack_markup(text)
    if not cleaned:
        return ""
    first = re.split(r"\n\s*\n", cleaned, maxsplit=1)[0].strip()
    if len(first) <= limit:
        return first
    return first[: limit - 1].rstrip() + "…"


def short_text(value: str, *, limit: int = 280) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def zip_datetime_iso(info: zipfile.ZipInfo) -> str:
    try:
        return datetime(*info.date_time, tzinfo=timezone.utc).replace(microsecond=0).isoformat()
    except Exception:
        return ""
