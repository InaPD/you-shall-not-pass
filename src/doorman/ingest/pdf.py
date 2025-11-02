"""PDF parsing with span-level provenance (spec 8.1).

Produces a `Document` whose spans carry enough layout detail for the ING-* rules
to run: size, colour, bounding box, plus the page and image rectangles the
geometric rules need. No rule evaluation happens here - see `hidden.py`.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from xml.etree import ElementTree

import pymupdf

from doorman.models import Document, Span

# Info-dict fields worth carrying. `format` and `encryption` are parser artefacts,
# not author-controlled, so they are skipped.
_INFO_FIELDS = ("title", "author", "subject", "keywords", "creator", "producer")


def _decode_color(color: int) -> tuple[int, int, int]:
    """PyMuPDF gives sRGB packed into an int."""
    return ((color >> 16) & 255, (color >> 8) & 255, color & 255)


def _flatten_xmp(xml: str) -> dict[str, str]:
    """Flatten XMP to `pdf.xmp.<prefix:localname>` keys.

    XMP is attacker-controlled and may be malformed; a parse failure is recorded
    rather than raised, because refusing to ingest is itself an attack outcome.
    """
    out: dict[str, str] = {}
    if not xml or not xml.strip():
        return out
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return {"pdf.xmp.parse_error": "malformed XMP packet"}
    for element in root.iter():
        text = (element.text or "").strip()
        if not text:
            continue
        tag = element.tag
        if tag.startswith("{"):
            namespace, _, local = tag[1:].partition("}")
            prefix = namespace.rstrip("/#").rsplit("/", 1)[-1]
            key = f"pdf.xmp.{prefix}:{local}"
        else:
            key = f"pdf.xmp.{tag}"
        # Repeated tags (rdf:li) are joined rather than overwritten, so no payload
        # is silently dropped before the classifier sees it.
        out[key] = f"{out[key]}\n{text}" if key in out else text
    return out


def _image_rects(page: pymupdf.Page) -> list[tuple[float, float, float, float]]:
    rects: list[tuple[float, float, float, float]] = []
    for image in page.get_images(full=True):
        xref = image[0]
        try:
            for rect in page.get_image_rects(xref):
                rects.append((rect.x0, rect.y0, rect.x1, rect.y1))
        except (ValueError, RuntimeError):
            continue
    return rects


def _spans_for_page(page: pymupdf.Page, page_no: int) -> list[Span]:
    spans: list[Span] = []
    # INFINITE_RECT, not the default clip. PyMuPDF clips extraction to the page
    # rect by default and silently drops text drawn outside it - which is exactly
    # what ING-003 exists to catch. Not extracting it would be an accidental
    # defence that any other PDF-to-text tool would fail to reproduce.
    text_dict = page.get_text("dict", clip=pymupdf.INFINITE_RECT())
    for block_no, block in enumerate(text_dict.get("blocks", [])):
        if block.get("type") != 0:  # 0 = text; images are handled separately
            continue
        for line_no, line in enumerate(block.get("lines", [])):
            for span_no, span in enumerate(line.get("spans", [])):
                bbox = span.get("bbox", (0.0, 0.0, 0.0, 0.0))
                spans.append(
                    Span(
                        id=f"p{page_no}-b{block_no}-l{line_no}-s{span_no}",
                        page=page_no,
                        text=span.get("text", ""),
                        bbox=tuple(float(v) for v in bbox),
                        size=float(span.get("size", 0.0)),
                        color_rgb=_decode_color(int(span.get("color", 0))),
                    )
                )
    return spans


def parse(path: Path) -> Document:
    """Parse a PDF into a Document. Rule evaluation happens in `hidden.py`."""
    raw = Path(path).read_bytes()
    spans: list[Span] = []
    page_rects: dict[int, tuple[float, float, float, float]] = {}
    image_rects: dict[int, list[tuple[float, float, float, float]]] = {}
    metadata: dict[str, str] = {}

    with pymupdf.open(stream=raw, filetype="pdf") as doc:
        for index, page in enumerate(doc):
            page_no = index + 1
            rect = page.rect
            page_rects[page_no] = (rect.x0, rect.y0, rect.x1, rect.y1)
            image_rects[page_no] = _image_rects(page)
            spans.extend(_spans_for_page(page, page_no))

        info = doc.metadata or {}
        for field in _INFO_FIELDS:
            value = (info.get(field) or "").strip()
            if value:
                metadata[f"pdf.info.{field}"] = value
        metadata.update(_flatten_xmp(doc.get_xml_metadata()))
        page_count = doc.page_count

    return Document(
        doc_id=Path(path).stem,
        kind="pdf",
        sha256=hashlib.sha256(raw).hexdigest(),
        page_count=page_count,
        spans=spans,
        metadata=metadata,
        page_rects=page_rects,
        image_rects=image_rects,
    )
