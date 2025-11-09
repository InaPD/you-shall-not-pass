"""Phases, per-phase tool allowlists and budgets (spec 11.2).

The allowlist is the control the spec's thesis rests on: a tool that is not in
the list for the current phase cannot be called, no matter how convincing the
document was. Phase transitions are driven by orchestrator code, never by the
model and never by a tool result.
"""

from __future__ import annotations

from doorman.models import Phase

# Phase -> tools callable in it. A phase absent from this map allows nothing.
ALLOWLISTS: dict[Phase, tuple[str, ...]] = {
    Phase.INGEST: (),
    Phase.EXTRACT: ("emit_profile",),
    Phase.SCORE: ("score_candidate", "ats_lookup", "fetch_portfolio"),
    Phase.DECIDE: ("propose_decision", "ats_lookup"),
    Phase.COMMUNICATE: ("send_email",),
    Phase.WRITE_ATS: ("ats_update",),
    Phase.REVIEW: ("request_human_review",),
    # The undefended flow has no phase structure; the allowlist is not consulted
    # because `none` and `prompt_only` run with the policy engine switched off.
    Phase.SINGLE: (
        "score_candidate", "propose_decision", "send_email",
        "ats_update", "ats_lookup", "fetch_url",
    ),
}

# Per candidate per run (spec 11.2).
BUDGETS: dict[str, int] = {
    "send_email": 1,
    "ats_update": 1,
    "fetch_portfolio": 1,
    "ats_lookup": 2,
    "score_candidate": 1,
    "propose_decision": 1,
}

# Tools that leave the system boundary or change a durable record. These are the
# only ones the taint gate and the approval queue care about.
IRREVERSIBLE = ("send_email", "ats_update")

# The order the orchestrator drives them in.
PHASE_ORDER = (Phase.SCORE, Phase.DECIDE, Phase.COMMUNICATE, Phase.WRITE_ATS)


def allowed(phase: Phase) -> tuple[str, ...]:
    return ALLOWLISTS.get(phase, ())


def is_allowed(phase: Phase, tool: str) -> bool:
    return tool in allowed(phase)


def budget_for(tool: str) -> int | None:
    return BUDGETS.get(tool)
