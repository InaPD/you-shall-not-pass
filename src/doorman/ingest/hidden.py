"""Hidden-text and metadata rules, ING-001 to ING-009 (spec 8.3).

These always compute. What changes with `DefenseConfig.hidden_text_rules` is what
the *caller* does with the result: whether flagged spans are withheld from the
reader and whether taint flips. Computing regardless is what lets the report show
which rules would have fired in the undefended baseline.

Nothing here mutates its input; `evaluate` returns a new Document.
"""

from __future__ import annotations

import re
import unicodedata

from doorman.config import Settings
from doorman.models import Document, Span

ZERO_WIDTH_CHARS = ("​", "‌", "‍", "⁠", "﻿")

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_WORD_RE = re.compile(r"\S+")

# Scripts that look enough alike to be used for homoglyph substitution.
_SCRIPT_PREFIXES = ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC")

_METADATA_MAX_CHARS = 500
_METADATA_MAX_NEWLINES = 2
_IMAGE_COVERAGE = 0.80

# Spec 8.3: an ING-009 hit on its own does not flip taint. Metadata is never shown
# to the reader, so an oversized value is a logging signal, not a capability change.
NON_TAINTING = frozenset({"ING-009"})


def _luminance(color_rgb: tuple[int, int, int]) -> float:
    r, g, b = (channel / 255.0 for channel in color_rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _scripts_in(word: str) -> set[str]:
    scripts: set[str] = set()
    for char in word:
        if not char.isalpha():
            continue
        try:
            name = unicodedata.name(char)
        except ValueError:
            continue
        for prefix in _SCRIPT_PREFIXES:
            if name.startswith(prefix):
                scripts.add(prefix)
                break
    return scripts


def _mixes_scripts(text: str) -> bool:
    return any(len(_scripts_in(word)) > 1 for word in _WORD_RE.findall(text))


def _intersects(a: tuple[float, ...], b: tuple[float, ...]) -> bool:
    return not (a[2] <= b[0] or a[0] >= b[2] or a[3] <= b[1] or a[1] >= b[3])


def _overlap_area(a: tuple[float, ...], b: tuple[float, ...]) -> float:
    width = min(a[2], b[2]) - max(a[0], b[0])
    height = min(a[3], b[3]) - max(a[1], b[1])
    return width * height if width > 0 and height > 0 else 0.0


def _covered_by_image(span: Span, images: list[tuple[float, float, float, float]]) -> bool:
    """ING-004.

    Simplification: any sufficiently overlapping image counts as covering. True
    z-order needs content-stream parsing, and the one case that matters - a payload
    drawn and then painted over - is caught by the geometry alone.
    """
    area = (span.bbox[2] - span.bbox[0]) * (span.bbox[3] - span.bbox[1])
    if area <= 0:
        return False
    return any(_overlap_area(span.bbox, image) / area >= _IMAGE_COVERAGE for image in images)


def span_reasons(span: Span, doc: Document, settings: Settings) -> list[str]:
    """Every ING-* rule that fires on this span, sorted and deduplicated."""
    reasons: set[str] = set()

    if _luminance(span.color_rgb) >= settings.near_white_luminance:
        reasons.add("ING-001")
    if 0.0 < span.size < settings.hidden_font_pt:
        reasons.add("ING-002")

    page_rect = doc.page_rects.get(span.page)
    if page_rect is not None and not _intersects(span.bbox, page_rect):
        reasons.add("ING-003")
    if _covered_by_image(span, doc.image_rects.get(span.page, [])):
        reasons.add("ING-004")

    if any(char in span.text for char in ZERO_WIDTH_CHARS):
        reasons.add("ING-005")
    if _mixes_scripts(span.text):
        reasons.add("ING-006")
    if _BASE64_RE.search(span.text):
        reasons.add("ING-008")

    return sorted(reasons)


def metadata_reasons(value: str) -> list[str]:
    reasons: set[str] = set()
    if _BASE64_RE.search(value):
        reasons.add("ING-008")
    if len(value) > _METADATA_MAX_CHARS or value.count("\n") >= _METADATA_MAX_NEWLINES:
        reasons.add("ING-009")
    if any(char in value for char in ZERO_WIDTH_CHARS):
        reasons.add("ING-005")
    if _mixes_scripts(value):
        reasons.add("ING-006")
    return sorted(reasons)


def evaluate(doc: Document, settings: Settings) -> Document:
    """Return a new Document with `hidden_reasons` and `metadata_flags` filled in."""
    spans = [
        span.model_copy(update={"hidden_reasons": span_reasons(span, doc, settings)})
        for span in doc.spans
    ]
    flags = {
        key: reasons
        for key, value in doc.metadata.items()
        if (reasons := metadata_reasons(value))
    }
    return doc.model_copy(update={"spans": spans, "metadata_flags": flags})


def fired_rules(doc: Document) -> list[str]:
    """Every ING-* id that fired anywhere in the document, sorted."""
    fired: set[str] = set()
    for span in doc.spans:
        fired.update(span.hidden_reasons)
    for reasons in doc.metadata_flags.values():
        fired.update(reasons)
    return sorted(fired)


def taint_causes(doc: Document) -> list[str]:
    """The subset of fired rules that flips taint to suspicious (spec 8.3)."""
    return [rule_id for rule_id in fired_rules(doc) if rule_id not in NON_TAINTING]
