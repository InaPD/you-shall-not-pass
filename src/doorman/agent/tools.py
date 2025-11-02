"""Anthropic tool schemas (spec 11.4).

NAIVE_TOOLS is what an undefended team ships: free-text recipient, free-text
body, an arbitrary candidate_id, an arbitrary URL. It exists to be beaten.

HARDENED_TOOLS lands in Phase 2. The point of it is the parameters that do not
exist - no `to`, no `candidate_id`, no free `body` - so nothing here should ever
grow a parameter for convenience (spec 21.7).
"""

from __future__ import annotations

from typing import Any

STATUSES = ("screening", "hold", "advance", "reject")
DECISIONS = ("advance", "hold", "reject")

NAIVE_TOOLS: list[dict[str, Any]] = [
    {
        "name": "score_candidate",
        "description": "Record a 0-100 fit score for this candidate against the job spec.",
        "input_schema": {
            "type": "object",
            "required": ["score", "rationale"],
            "properties": {
                "score": {"type": "integer", "description": "Fit score from 0 to 100."},
                "rationale": {"type": "string", "description": "Why this score."},
            },
        },
    },
    {
        "name": "propose_decision",
        "description": "Record a screening decision for this candidate.",
        "input_schema": {
            "type": "object",
            "required": ["status", "rationale"],
            "properties": {
                "status": {"type": "string", "enum": list(DECISIONS)},
                "rationale": {"type": "string"},
            },
        },
    },
    {
        "name": "send_email",
        "description": "Send an email to the candidate.",
        "input_schema": {
            "type": "object",
            "required": ["to", "subject", "body"],
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
        },
    },
    {
        "name": "ats_update",
        "description": "Update a candidate's record in the applicant tracking system.",
        "input_schema": {
            "type": "object",
            "required": ["candidate_id", "status"],
            "properties": {
                "candidate_id": {"type": "string"},
                "status": {"type": "string", "enum": list(STATUSES)},
                "note": {"type": "string"},
            },
        },
    },
    {
        "name": "ats_lookup",
        "description": "Look up a candidate record in the applicant tracking system.",
        "input_schema": {
            "type": "object",
            "required": ["candidate_id"],
            "properties": {"candidate_id": {"type": "string"}},
        },
    },
    {
        "name": "fetch_url",
        "description": "Fetch the text content of a web page, such as a portfolio site.",
        "input_schema": {
            "type": "object",
            "required": ["url"],
            "properties": {"url": {"type": "string"}},
        },
    },
]

NAIVE_TOOL_NAMES = tuple(tool["name"] for tool in NAIVE_TOOLS)


def by_name(tools: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {tool["name"]: tool for tool in tools}
