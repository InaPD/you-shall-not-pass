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

from doorman.guard.heuristics import instruction_like
from doorman.models import RunContext

URL_RE = re.compile(r"\bhttps?://[^\s<>\"')\]]+", re.I)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
CANARY_RE = re.compile(r"CANARY-([0-9a-f]{8,})", re.I)


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
