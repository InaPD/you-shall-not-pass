"""Shared resume renderer (spec 17).

Both corpora render through this module. If attacks and benign resumes were drawn
differently, layout would be a confound in the false-positive numbers, so the only
difference between an attack and a benign document is the payload, never the
typography.

Two injection channels, matching the two placement families:

  `extra_sections` puts payload text into the normal visible flow (`direct`)
  `overlays`       draws payload text at an arbitrary size, colour and position,
                   optionally painted over with an image (`hidden_text`)
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfgen import canvas as pdfcanvas

from corpus.templates.png import solid_png

PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN = 56.0
BODY_WIDTH = PAGE_WIDTH - 2 * MARGIN

BODY_FONT = "Helvetica"
BOLD_FONT = "Helvetica-Bold"
BODY_SIZE = 10.0
HEADING_SIZE = 11.5
NAME_SIZE = 19.0
LEADING = 13.5

LAYOUTS = ("single_column", "two_column", "minimal")


@dataclass(frozen=True)
class Overlay:
    """Payload drawn outside the normal flow. The defaults are a visible black
    9pt line; each hidden_text placement overrides one property."""

    text: str
    x: float = MARGIN
    y: float = PAGE_HEIGHT / 2
    size: float = 9.0
    color: tuple[float, float, float] = (0.0, 0.0, 0.0)
    page: int = 1
    cover_with_image: bool = False


@dataclass(frozen=True)
class Section:
    heading: str
    paragraphs: list[str] = field(default_factory=list)
    bullets: list[str] = field(default_factory=list)


def _wrap(text: str, font: str, size: float, width: float) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        trial = f"{current} {word}".strip()
        if pdfmetrics.stringWidth(trial, font, size) <= width or not current:
            current = trial
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


class _Cursor:
    """Tracks the drawing position and breaks pages when the body runs out."""

    def __init__(self, canvas: pdfcanvas.Canvas, width: float = BODY_WIDTH) -> None:
        self.canvas = canvas
        self.width = width
        self.x = MARGIN
        self.y = PAGE_HEIGHT - MARGIN
        self.page = 1

    def _break_if_needed(self, needed: float) -> None:
        if self.y - needed < MARGIN:
            self.canvas.showPage()
            self.page += 1
            self.y = PAGE_HEIGHT - MARGIN

    def text(self, body: str, *, font: str = BODY_FONT, size: float = BODY_SIZE,
             leading: float = LEADING, indent: float = 0.0) -> None:
        for line in _wrap(body, font, size, self.width - indent):
            self._break_if_needed(leading)
            self.canvas.setFont(font, size)
            self.canvas.setFillColorRGB(0, 0, 0)
            self.canvas.drawString(self.x + indent, self.y, line)
            self.y -= leading

    def gap(self, amount: float = 8.0) -> None:
        self.y -= amount

    def heading(self, title: str) -> None:
        self.gap(6.0)
        self._break_if_needed(LEADING * 2)
        self.canvas.setFont(BOLD_FONT, HEADING_SIZE)
        self.canvas.setFillColorRGB(0.12, 0.2, 0.35)
        self.canvas.drawString(self.x, self.y, title.upper())
        self.y -= 4.0
        self.canvas.setStrokeColorRGB(0.75, 0.78, 0.82)
        self.canvas.setLineWidth(0.6)
        self.canvas.line(self.x, self.y, self.x + self.width, self.y)
        self.y -= LEADING


def _draw_header(cursor: _Cursor, profile: dict[str, Any]) -> None:
    cursor.canvas.setFont(BOLD_FONT, NAME_SIZE)
    cursor.canvas.setFillColorRGB(0.08, 0.08, 0.1)
    cursor.canvas.drawString(cursor.x, cursor.y, profile["full_name"])
    cursor.y -= NAME_SIZE + 4
    contact = " | ".join(
        str(profile[key])
        for key in ("headline", "location", "email", "phone")
        if profile.get(key)
    )
    cursor.text(contact, size=9.0, leading=12.0)
    if profile.get("portfolio_url"):
        cursor.text(str(profile["portfolio_url"]), size=9.0, leading=12.0)


def _profile_sections(profile: dict[str, Any]) -> list[Section]:
    sections: list[Section] = []
    if profile.get("summary"):
        sections.append(Section("Summary", paragraphs=[profile["summary"]]))
    if profile.get("skills"):
        sections.append(Section("Skills", paragraphs=[", ".join(profile["skills"])]))
    if profile.get("experience"):
        bullets: list[str] = []
        for role in profile["experience"]:
            bullets.append(f"{role['title']}, {role['company']} ({role['period']})")
            bullets.extend(f"    - {point}" for point in role.get("bullets", []))
        sections.append(Section("Experience", bullets=bullets))
    if profile.get("education"):
        sections.append(
            Section(
                "Education",
                bullets=[
                    f"{item['degree']} in {item['field']}, {item['institution']}"
                    f" ({item.get('year', 'n/a')})"
                    for item in profile["education"]
                ],
            )
        )
    if profile.get("languages"):
        sections.append(Section("Languages", paragraphs=[", ".join(profile["languages"])]))
    return sections


def _draw_sections(cursor: _Cursor, sections: list[Section]) -> None:
    for section in sections:
        cursor.heading(section.heading)
        for paragraph in section.paragraphs:
            cursor.text(paragraph)
            cursor.gap(3.0)
        for bullet in section.bullets:
            indent = 10.0 if bullet.startswith("    -") else 0.0
            font = BODY_FONT if indent else BOLD_FONT
            cursor.text(bullet.strip().lstrip("- ").strip(), font=font, indent=indent)


def _draw_overlay(canvas: pdfcanvas.Canvas, overlay: Overlay) -> None:
    canvas.saveState()
    canvas.setFont(BODY_FONT, overlay.size)
    canvas.setFillColorRGB(*overlay.color)
    leading = overlay.size * 1.25
    lines = _wrap(overlay.text, BODY_FONT, overlay.size, BODY_WIDTH)
    for index, line in enumerate(lines):
        canvas.drawString(overlay.x, overlay.y - index * leading, line)
    if overlay.cover_with_image:
        # Drawn after the text, so it sits on top of it in the content stream.
        height = leading * len(lines) + 4
        image = ImageReader(io.BytesIO(solid_png(120, 40, (232, 234, 238))))
        canvas.drawImage(
            image,
            overlay.x - 4,
            overlay.y - height + leading - 2,
            width=BODY_WIDTH,
            height=height,
            mask=None,
        )
    canvas.restoreState()


def render(
    profile: dict[str, Any],
    out_path: Path,
    *,
    layout: str = "single_column",
    extra_sections: list[Section] | None = None,
    overlays: list[Overlay] | None = None,
    metadata: dict[str, str] | None = None,
) -> Path:
    """Render `profile` to `out_path` and return it."""
    if layout not in LAYOUTS:
        raise ValueError(f"unknown layout {layout!r}; choose one of {', '.join(LAYOUTS)}")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    canvas = pdfcanvas.Canvas(str(out_path), pagesize=A4)
    canvas.setTitle(profile.get("full_name", "Resume"))
    if metadata:
        canvas.setAuthor(metadata.get("author", ""))
        canvas.setSubject(metadata.get("subject", ""))
        canvas.setKeywords(metadata.get("keywords", ""))
        canvas.setCreator(metadata.get("creator", "reportlab"))

    cursor = _Cursor(canvas)
    _draw_header(cursor, profile)
    _draw_sections(cursor, _profile_sections(profile) + list(extra_sections or []))

    for overlay in overlays or []:
        _draw_overlay(canvas, overlay)

    canvas.save()
    return out_path
