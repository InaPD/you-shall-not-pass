"""Output scanning, OUT-001 to OUT-005 (spec 10.3).

Runs on every free-text tool argument before the tool executes or is queued, and
on the final text of anything actually sent. This is the last layer: by the time
text reaches here the model has already been persuaded, so these rules assume the
content is hostile and check it against trusted values rather than against a list
of bad phrases.

OUT-001 to OUT-004 DENY. OUT-005 only flags - instruction-like phrasing in an
outbound email is suspicious, not proof, and denying on it would cost more in
false positives than it buys.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from doorman.config import CONFIG_DIR
from doorman.guard.heuristics import instruction_like
from doorman.models import RunContext

URL_RE = re.compile(r"\bhttps?://[^\s<>\"')\]]+", re.I)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
CANARY_RE = re.compile(r"CANARY-([0-9a-f]{8,})", re.I)

# A dotted token that could be typed into a browser: one or more labels, then a
# TLD. Whether it counts as a link is decided by LINK_TLDS, not by this pattern.
BARE_HOST_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))\b", re.I
)
LINK_TLDS_PATH = CONFIG_DIR / "link_tlds.yaml"


@lru_cache(maxsize=2)
def _link_config(path: Path | None = None) -> tuple[frozenset[str], frozenset[str]]:
    source = Path(path) if path else LINK_TLDS_PATH
    data = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    return (
        frozenset(str(tld).lower() for tld in data.get("tlds") or ()),
        frozenset(str(host).lower() for host in data.get("not_links") or ()),
    )


def link_tlds(path: Path | None = None) -> frozenset[str]:
    return _link_config(path)[0]


def not_links(path: Path | None = None) -> frozenset[str]:
    """Host-shaped tokens that are platform names, not addresses - `ASP.NET` and
    friends. Dropping `net` from the TLD list would have been the alternative,
    and it would have blinded the rule to every `.net` address."""
    return _link_config(path)[1]


@dataclass(frozen=True)
class ScanHit:
    rule_id: str
    field: str
    match: str
    blocking: bool

    def redacted(self) -> str:
        """Enough to identify the hit, not enough to re-leak it (spec 21.10)."""
        if self.rule_id == "OUT-001":
            return "<canary>"
        if len(self.match) <= 12:
            return self.match
        return f"{self.match[:8]}...({len(self.match)} chars)"


def _host(url: str) -> str:
    from urllib.parse import urlparse

    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def scan_text(text: str, ctx: RunContext, *, field: str = "text") -> list[ScanHit]:
    """Every rule that fires on one piece of outbound text, in rule order."""
    hits: list[ScanHit] = []
    if not text:
        return hits

    # OUT-001: the canary is in the agent prompt and never the reader's, so its
    # appearance here can only mean the privileged prompt leaked.
    if ctx.canary and ctx.canary.lower() in text.lower():
        hits.append(ScanHit("OUT-001", field, ctx.canary, True))
    elif CANARY_RE.search(text):
        hits.append(ScanHit("OUT-001", field, CANARY_RE.search(text).group(0), True))

    # OUT-002: any URL whose host is not trusted. Allowlist, not blocklist.
    for url in URL_RE.findall(text):
        if _host(url) not in ctx.trusted_urls:
            hits.append(ScanHit("OUT-002", field, url, True))

    # OUT-003: any address that is not the candidate's own.
    for address in EMAIL_RE.findall(text):
        if address.lower() != ctx.trusted_email.lower():
            hits.append(ScanHit("OUT-003", field, address, True))

    # OUT-004: another candidate's identifier or name.
    lowered = text.lower()
    for identifier in sorted(ctx.batch_candidate_ids):
        if re.search(rf"\b{re.escape(identifier)}\b", text):
            hits.append(ScanHit("OUT-004", field, identifier, True))
    for name in sorted(ctx.batch_candidate_names):
        if name and name.lower() in lowered:
            hits.append(ScanHit("OUT-004", field, name, True))

    # OUT-006: the same threat as OUT-002 without the scheme. A recipient reads
    # `evil.example/offer` as a link whether or not it was typed as one, so the
    # scheme cannot be what decides. Schemed URLs and email addresses are removed
    # first: OUT-002 and OUT-003 own those, and the domain inside an address is
    # not a link the reader can follow.
    residue = URL_RE.sub(" ", EMAIL_RE.sub(" ", text))
    tlds, exempt = _link_config()
    seen: set[str] = set()
    for host, tld in BARE_HOST_RE.findall(residue):
        candidate = host.lower()
        if (
            tld.lower() not in tlds
            or candidate in exempt
            or candidate in ctx.trusted_urls
            or candidate in seen
        ):
            continue
        seen.add(candidate)
        hits.append(ScanHit("OUT-006", field, host, True))

    # OUT-005: advisory only.
    phrase = instruction_like(text)
    if phrase:
        hits.append(ScanHit("OUT-005", field, phrase, False))
    return hits


def scan_args(args: dict[str, str], ctx: RunContext) -> list[ScanHit]:
    hits: list[ScanHit] = []
    for field, value in args.items():
        if isinstance(value, str):
            hits.extend(scan_text(value, ctx, field=field))
    return hits


def first_blocking(hits: list[ScanHit]) -> ScanHit | None:
    return next((hit for hit in hits if hit.blocking), None)
