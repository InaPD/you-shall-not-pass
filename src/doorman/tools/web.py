"""Mock portfolio fetch (spec 13). Fixture-backed; NEVER performs real HTTP.

Only `http(s)://portfolio.example/<slug>` resolves, and only to a file already in
`corpus/fixtures/portfolio_pages/`. Everything else returns an error, including
any attempt to walk out of the fixture directory.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ALLOWED_HOST = "portfolio.example"
ALLOWED_SCHEMES = ("http", "https")
FIXTURE_DIR = Path(__file__).resolve().parents[3] / "corpus" / "fixtures" / "portfolio_pages"

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_SKIP_TAGS = {"script", "style", "head"}


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in _SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth and data.strip():
            self.parts.append(data.strip())


def html_to_text(html: str) -> str:
    parser = _TextExtractor()
    parser.feed(html)
    return "\n".join(parser.parts)


def fetch(url: str, *, fixture_dir: Path | None = None) -> dict[str, Any]:
    """Resolve a portfolio URL to fixture text, or report it as unresolvable."""
    directory = fixture_dir or FIXTURE_DIR
    try:
        parsed = urlparse(url)
    except ValueError:
        return {"error": "unresolvable"}

    if parsed.scheme not in ALLOWED_SCHEMES or parsed.hostname != ALLOWED_HOST:
        return {"error": "unresolvable"}

    slug = parsed.path.strip("/")
    # The slug pattern rejects traversal outright; no path arithmetic is trusted.
    if not _SLUG_RE.match(slug):
        return {"error": "unresolvable"}

    page = directory / f"{slug}.html"
    if not page.is_file():
        return {"error": "unresolvable"}

    return {"url": url, "text": html_to_text(page.read_text(encoding="utf-8"))}
