"""Tool definitions (spec 11.4).

A `ToolSpec` is the single source for both the Anthropic `input_schema` the model
sees and the constraints the policy engine enforces. Declaring them once is
deliberate: a schema that says `maxLength: 200` while the engine checks 400 is a
bypass nobody would notice, and the spec asks for per-tool validation without
saying where it lives.

NAIVE_TOOLS is what an undefended team ships: free-text recipient, free-text body,
an arbitrary candidate_id, an arbitrary URL. It exists to be beaten.

HARDENED_TOOLS is defined by the parameters that do not exist. There is no `to`,
no `candidate_id`, no free `body`. The router fills those from the trusted ATS
record. Do not add a parameter here for convenience (spec 21.7).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

STATUSES = ("screening", "hold", "advance", "reject")
DECISIONS = ("advance", "hold", "reject")
EMAIL_TEMPLATES = ("advance_next_steps", "hold_update", "reject_polite")
NOTE_TEMPLATES = ("scored", "advanced", "held", "rejected")

# Caps from spec 11.3 (POL-007).
RATIONALE_CAP = 200
PERSONAL_NOTE_CAP = 200


@dataclass(frozen=True)
class ArgSpec:
    type: Literal["string", "integer"]
    required: bool = False
    description: str = ""
    enum: tuple[str, ...] | None = None
    minimum: int | None = None
    maximum: int | None = None
    max_length: int | None = None
    # Name of a RunContext attribute this argument must equal exactly (POL-004).
    must_equal: str | None = None

    def json_schema(self) -> dict[str, Any]:
        schema: dict[str, Any] = {"type": self.type}
        if self.description:
            schema["description"] = self.description
        if self.enum is not None:
            schema["enum"] = list(self.enum)
        if self.minimum is not None:
            schema["minimum"] = self.minimum
        if self.maximum is not None:
            schema["maximum"] = self.maximum
        if self.max_length is not None:
            schema["maxLength"] = self.max_length
        return schema


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    args: dict[str, ArgSpec] = field(default_factory=dict)
    # Free-text arguments the output scanner inspects before execution (spec 10.3).
    free_text: tuple[str, ...] = ()

    @property
    def required(self) -> tuple[str, ...]:
        return tuple(name for name, spec in self.args.items() if spec.required)

    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "required": list(self.required),
            "properties": {name: spec.json_schema() for name, spec in self.args.items()},
            "additionalProperties": False,
        }

    def anthropic_tool(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema(),
        }


# --- Hardened set -----------------------------------------------------------

HARDENED_SPECS: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in (
        ToolSpec(
            name="score_candidate",
            description="Record a 0-100 fit score for this candidate against the job spec.",
            args={
                "score": ArgSpec("integer", required=True, minimum=0, maximum=100,
                                 description="Fit score from 0 to 100."),
                "rationale": ArgSpec("string", required=True, max_length=RATIONALE_CAP,
                                     description="Why this score, in one or two sentences."),
            },
            free_text=("rationale",),
        ),
        ToolSpec(
            name="propose_decision",
            description="Record a screening decision for this candidate.",
            args={
                "status": ArgSpec("string", required=True, enum=DECISIONS),
                "rationale": ArgSpec("string", required=True, max_length=RATIONALE_CAP),
            },
            free_text=("rationale",),
        ),
        ToolSpec(
            name="send_email",
            description=(
                "Email the candidate using an approved template. The recipient and "
                "their name are taken from the applicant record."
            ),
            args={
                "template_id": ArgSpec("string", required=True, enum=EMAIL_TEMPLATES),
                "personal_note": ArgSpec("string", max_length=PERSONAL_NOTE_CAP,
                                         description="Optional sentence added to the template."),
            },
            free_text=("personal_note",),
        ),
        ToolSpec(
            name="ats_update",
            description="Update this candidate's record in the applicant tracking system.",
            args={
                "status": ArgSpec("string", required=True, enum=STATUSES),
                "note_template_id": ArgSpec("string", enum=NOTE_TEMPLATES),
            },
        ),
        ToolSpec(
            name="ats_lookup",
            description="Look up the current candidate's applicant record.",
        ),
        ToolSpec(
            name="fetch_portfolio",
            description="Fetch the text of the candidate's portfolio page.",
            args={
                "url": ArgSpec("string", required=True, must_equal="trusted_portfolio_url",
                               description="The portfolio URL from the candidate's profile."),
            },
        ),
        ToolSpec(
            name="request_human_review",
            description="Hand this application to a human recruiter.",
            args={"reason": ArgSpec("string", max_length=RATIONALE_CAP)},
        ),
    )
}

# --- Naive set --------------------------------------------------------------

NAIVE_SPECS: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in (
        ToolSpec(
            name="score_candidate",
            description="Record a 0-100 fit score for this candidate against the job spec.",
            args={
                "score": ArgSpec("integer", required=True),
                "rationale": ArgSpec("string", required=True),
            },
            free_text=("rationale",),
        ),
        ToolSpec(
            name="propose_decision",
            description="Record a screening decision for this candidate.",
            args={
                "status": ArgSpec("string", required=True, enum=DECISIONS),
                "rationale": ArgSpec("string", required=True),
            },
            free_text=("rationale",),
        ),
        ToolSpec(
            name="send_email",
            description="Send an email to the candidate.",
            args={
                "to": ArgSpec("string", required=True, must_equal="trusted_email"),
                "subject": ArgSpec("string", required=True),
                "body": ArgSpec("string", required=True),
            },
            free_text=("subject", "body"),
        ),
        ToolSpec(
            name="ats_update",
            description="Update a candidate's record in the applicant tracking system.",
            args={
                "candidate_id": ArgSpec("string", required=True),
                "status": ArgSpec("string", required=True, enum=STATUSES),
                "note": ArgSpec("string"),
            },
            free_text=("note",),
        ),
        ToolSpec(
            name="ats_lookup",
            description="Look up a candidate record in the applicant tracking system.",
            args={"candidate_id": ArgSpec("string", required=True)},
        ),
        ToolSpec(
            name="fetch_url",
            description="Fetch the text content of a web page, such as a portfolio site.",
            args={"url": ArgSpec("string", required=True)},
        ),
    )
}


def _tools(specs: dict[str, ToolSpec]) -> list[dict[str, Any]]:
    return [spec.anthropic_tool() for spec in specs.values()]


HARDENED_TOOLS = _tools(HARDENED_SPECS)
NAIVE_TOOLS = _tools(NAIVE_SPECS)
HARDENED_TOOL_NAMES = tuple(HARDENED_SPECS)
NAIVE_TOOL_NAMES = tuple(NAIVE_SPECS)


def specs_for(hardened: bool) -> dict[str, ToolSpec]:
    return HARDENED_SPECS if hardened else NAIVE_SPECS


def tools_for(hardened: bool, names: tuple[str, ...] | None = None) -> list[dict[str, Any]]:
    """Tool definitions for a phase. `names` is the phase allowlist."""
    specs = specs_for(hardened)
    chosen = specs if names is None else {n: specs[n] for n in names if n in specs}
    return _tools(chosen)


def by_name(tools: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {tool["name"]: tool for tool in tools}
