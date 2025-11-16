"""Rule registry - the single source of truth for rule IDs (spec 11.1).

Every rule ID that can ever appear in a log lives here, including rules whose
implementation lands in a later phase. `trace` validates against this registry on
every event, so an unknown ID is a programming error and raises (spec 21.4).

IDs are never reused or renumbered. The gap at POL-008/POL-009 is intentional: the
spec skips them, and closing the gap would silently renumber rules that appear in
already-written reports.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Layer = Literal["ING", "CLS", "POL", "OUT", "APR"]
Action = Literal["FLAG", "DOWNGRADE", "DENY", "REQUIRE_APPROVAL"]


@dataclass(frozen=True)
class Rule:
    id: str
    layer: Layer
    action: Action
    description: str


def _r(rule_id: str, layer: Layer, action: Action, description: str) -> Rule:
    return Rule(id=rule_id, layer=layer, action=action, description=description)


_ALL: tuple[Rule, ...] = (
    # --- Ingestion: hidden text and metadata (spec 8.3). FLAG only. -------------
    _r("ING-001", "ING", "FLAG", "Span luminance at or above the near-white threshold"),
    _r("ING-002", "ING", "FLAG", "Span font size below the hidden-font threshold"),
    _r("ING-003", "ING", "FLAG", "Span bounding box does not intersect the page rect"),
    _r("ING-004", "ING", "FLAG", "Span at least 80% covered by an image drawn after it"),
    _r("ING-005", "ING", "FLAG", "Span contains zero-width characters"),
    _r("ING-006", "ING", "FLAG", "A single word mixes scripts (for example Latin and Cyrillic)"),
    _r("ING-007", "ING", "FLAG", "DOCX run has hidden or vanish set"),
    _r("ING-008", "ING", "FLAG", "Text or metadata contains a base64-like run of 40+ characters"),
    _r("ING-009", "ING", "FLAG", "Metadata value over 500 chars or containing 2+ newlines"),
    # --- Classifier (spec 10.1). DOWNGRADE only: never blocks. -----------------
    _r("CLS-001", "CLS", "DOWNGRADE", "Injection score at or above threshold on a document span"),
    _r("CLS-002", "CLS", "DOWNGRADE", "Injection score at or above threshold on a metadata value"),
    _r("CLS-003", "CLS", "DOWNGRADE", "Injection score at or above threshold on a tool result"),
    # --- Heuristics (spec 10.2). Advisory: log only, never change taint. -------
    _r("CLS-101", "CLS", "FLAG", "Instruction-like phrasing addressed to the system or assistant"),
    _r("CLS-102", "CLS", "FLAG", "Forged delimiters or role markers in untrusted text"),
    # --- Policy engine (spec 11.3). Evaluated in this order; first failure wins.
    _r("POL-001", "POL", "DENY", "Tool is not in the allowlist for the current phase"),
    _r("POL-002", "POL", "DENY", "Irreversible tool called while taint is suspicious"),
    _r("POL-003", "POL", "DENY", "Tool input fails the tool's schema"),
    _r("POL-004", "POL", "DENY", "Argument that must equal a trusted value does not"),
    _r("POL-005", "POL", "DENY", "Enum argument outside permitted values"),
    _r("POL-006", "POL", "DENY", "Numeric argument out of range"),
    _r("POL-007", "POL", "DENY", "Free-text argument over its length cap"),
    _r("POL-010", "POL", "DENY", "Per-run budget exceeded for this tool"),
    _r("POL-011", "POL", "DENY", "Tool call references a candidate_id other than the current one"),
    # --- Output scan (spec 10.3). Runs on outbound free text. ------------------
    _r("OUT-001", "OUT", "DENY", "Run canary appears in outbound text"),
    _r("OUT-002", "OUT", "DENY", "URL whose host is not in the trusted set"),
    _r("OUT-003", "OUT", "DENY", "Email address that is not the trusted candidate address"),
    _r("OUT-004", "OUT", "DENY", "Another candidate's id or full name appears in outbound text"),
    _r("OUT-005", "OUT", "FLAG", "Instruction-like phrasing in outbound text"),
    # Phase 5: closes BYP-001. OUT-002 only recognised a URL with a scheme, so
    # dropping `https://` walked the same link past it (docs/BYPASSES.md).
    _r("OUT-006", "OUT", "DENY", "Schemeless host whose domain is not in the trusted set"),
    # --- Approvals (spec 11.3). ------------------------------------------------
    _r("APR-001", "APR", "REQUIRE_APPROVAL", "send_email leaves the system boundary"),
    _r("APR-002", "APR", "REQUIRE_APPROVAL", "ats_update sets status to advance or reject"),
)

RULES: dict[str, Rule] = {rule.id: rule for rule in _ALL}

# Integrity checks at import: a duplicate or mislabelled ID is a build error, not a
# runtime surprise.
if len(RULES) != len(_ALL):  # pragma: no cover - import-time guard
    raise RuntimeError("duplicate rule id in the registry")
for _rule in _ALL:  # pragma: no cover - import-time guard
    if not _rule.id.startswith(f"{_rule.layer}-"):
        raise RuntimeError(f"rule {_rule.id} does not match its layer {_rule.layer}")


def get(rule_id: str) -> Rule:
    """Look up a rule. Raises KeyError on an unknown ID - callers must not guess."""
    try:
        return RULES[rule_id]
    except KeyError:
        raise KeyError(
            f"unknown rule_id {rule_id!r}; add it to doorman.policy.rules.RULES"
        ) from None


def ids_for_layer(layer: Layer) -> list[str]:
    return [rule.id for rule in _ALL if rule.layer == layer]


def all_ids() -> list[str]:
    return [rule.id for rule in _ALL]
