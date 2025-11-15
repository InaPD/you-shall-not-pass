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


@dataclass(frozen=True)
class Style:
    """What a layout variant is allowed to change.

    Nothing here touches the words, only how they are set, so the same profile
    rendered under any variant carries identical text. That is what keeps layout
    a variable in the false-positive numbers rather than a confound.
    """

    accent: tuple[float, float, float] = (0.12, 0.2, 0.35)
    heading_rule: bool = True
    heading_size: float = HEADING_SIZE
    leading: float = LEADING
    columns: int = 1


# Spec 17: single column; two column with coloured headings; minimal.
LAYOUT_STYLES: dict[str, Style] = {
    "single_column": Style(),
    "two_column": Style(accent=(0.06, 0.42, 0.44), columns=2),
    "minimal": Style(
        accent=(0.0, 0.0, 0.0), heading_rule=False, heading_size=10.5, leading=12.5
    ),
}

LAYOUTS = tuple(LAYOUT_STYLES)

# Which sections move to the narrow column under `two_column`. Anything not named
# here - every injected `extra_sections` entry included - stays in the main flow.
SIDEBAR_HEADINGS = ("Skills", "Education", "Languages")
SIDEBAR_FRACTION = 0.34
COLUMN_GAP = 20.0


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
    # Rows of an optional grid, first row treated as the header. Spec 17 asks for
    # one benign resume laid out with tables; nothing else uses this.
    table: list[list[str]] = field(default_factory=list)


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

    def __init__(
        self,
        canvas: Any,  # a reportlab Canvas, or a _PageRecorder standing in for one
        width: float = BODY_WIDTH,
        *,
        style: Style | None = None,
        x: float = MARGIN,
    ) -> None:
        self.canvas = canvas
        self.width = width
        self.style = style or LAYOUT_STYLES["single_column"]
        self.x = x
        self.y = PAGE_HEIGHT - MARGIN
        self.page = 1

    def _break_if_needed(self, needed: float) -> None:
        if self.y - needed < MARGIN:
            self.canvas.showPage()
            self.page += 1
            self.y = PAGE_HEIGHT - MARGIN

    def text(self, body: str, *, font: str = BODY_FONT, size: float = BODY_SIZE,
             leading: float | None = None, indent: float = 0.0) -> None:
        leading = self.style.leading if leading is None else leading
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
        self._break_if_needed(self.style.leading * 2)
        self.canvas.setFont(BOLD_FONT, self.style.heading_size)
        self.canvas.setFillColorRGB(*self.style.accent)
        self.canvas.drawString(self.x, self.y, title.upper())
        self.y -= 4.0
        if self.style.heading_rule:
            self.canvas.setStrokeColorRGB(0.75, 0.78, 0.82)
            self.canvas.setLineWidth(0.6)
            self.canvas.line(self.x, self.y, self.x + self.width, self.y)
        self.y -= self.style.leading

    def table(self, rows: list[list[str]]) -> None:
        """A plain grid. Cells are single lines, truncated rather than wrapped, so
        a table never silently reflows into something the reader cannot match."""
        if not rows:
            return
        columns = max(len(row) for row in rows)
        cell_width = self.width / columns
        for index, row in enumerate(rows):
            self._break_if_needed(self.style.leading)
            font = BOLD_FONT if index == 0 else BODY_FONT
            self.canvas.setFont(font, BODY_SIZE - 0.5)
            self.canvas.setFillColorRGB(0, 0, 0)
            for column, cell in enumerate(row):
                self.canvas.drawString(
                    self.x + column * cell_width + 2.0,
                    self.y,
                    _clip(str(cell), font, BODY_SIZE - 0.5, cell_width - 6.0),
                )
            self.y -= 4.0
            self.canvas.setStrokeColorRGB(0.82, 0.84, 0.88)
            self.canvas.setLineWidth(0.4)
            self.canvas.line(self.x, self.y, self.x + self.width, self.y)
            self.y -= self.style.leading - 4.0


def _clip(text: str, font: str, size: float, width: float) -> str:
    if pdfmetrics.stringWidth(text, font, size) <= width:
        return text
    while text and pdfmetrics.stringWidth(text + "...", font, size) > width:
        text = text[:-1]
    return text + "..."


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
        cursor.table(section.table)


class _PageRecorder:
    """A canvas stand-in that records drawing calls against a page number.

    Two columns share one canvas but are drawn one after the other, and
    `showPage()` is global state: if the sidebar overflowed onto page two, every
    later `drawString` from the main column would land there too, next to
    nothing. Recording each column and replaying page by page keeps the columns
    side by side however long either one runs.
    """

    _METHODS = ("setFont", "setFillColorRGB", "drawString", "setStrokeColorRGB",
                "setLineWidth", "line", "drawImage", "saveState", "restoreState")

    def __init__(self) -> None:
        self.page = 0
        self.ops: dict[int, list[tuple[str, tuple[Any, ...], dict[str, Any]]]] = {}

    def __getattr__(self, name: str) -> Any:
        if name not in self._METHODS:
            raise AttributeError(name)

        def record(*args: Any, **kwargs: Any) -> None:
            self.ops.setdefault(self.page, []).append((name, args, kwargs))

        return record

    def showPage(self) -> None:  # noqa: N802 - the reportlab canvas spelling
        self.page += 1

    def pages(self) -> int:
        return max(self.ops, default=0) + 1

    def replay(self, canvas: pdfcanvas.Canvas, page: int) -> None:
        for name, args, kwargs in self.ops.get(page, ()):
            getattr(canvas, name)(*args, **kwargs)


def _draw_two_column(
    canvas: pdfcanvas.Canvas,
    profile: dict[str, Any],
    sections: list[Section],
    style: Style,
) -> None:
    """Header across the full width, then a narrow left column beside a main one.

    Each column is recorded independently and the two are replayed page by page,
    so a sidebar that runs long never displaces the main column.
    """
    side_width = BODY_WIDTH * SIDEBAR_FRACTION
    main_width = BODY_WIDTH - side_width - COLUMN_GAP

    head = _PageRecorder()
    header = _Cursor(head, style=style)
    _draw_header(header, profile)
    top = header.y - 6.0

    left = _PageRecorder()
    sidebar = _Cursor(left, side_width, style=style)
    sidebar.y = top
    _draw_sections(sidebar, [s for s in sections if s.heading in SIDEBAR_HEADINGS])

    right = _PageRecorder()
    main = _Cursor(right, main_width, style=style, x=MARGIN + side_width + COLUMN_GAP)
    main.y = top
    _draw_sections(main, [s for s in sections if s.heading not in SIDEBAR_HEADINGS])

    for page in range(max(head.pages(), left.pages(), right.pages())):
        if page:
            canvas.showPage()
        head.replay(canvas, page)
        left.replay(canvas, page)
        right.replay(canvas, page)


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

    style = LAYOUT_STYLES[layout]
    sections = _profile_sections(profile) + list(extra_sections or [])
    if style.columns == 2:
        _draw_two_column(canvas, profile, sections, style)
    else:
        cursor = _Cursor(canvas, style=style)
        _draw_header(cursor, profile)
        _draw_sections(cursor, sections)

    for overlay in overlays or []:
        _draw_overlay(canvas, overlay)

    canvas.save()
    return out_path
