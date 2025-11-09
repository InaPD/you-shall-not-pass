"""The quarantined reader (spec 9).

One call, no tools but a single forced `emit_profile`, and an input consisting of
visible resume text and nothing else. No metadata, no hidden spans, no job spec.

The system prompt contains no security language on purpose. The reader's
isolation is structural, not persuasive: it cannot be talked into calling a tool
it was never given, and it cannot pass an instruction forward through a schema
with no free field to carry one.
"""

from __future__ import annotations

from typing import Any

from doorman import trace
from doorman.config import DefenseConfig, Settings
from doorman.models import CandidateProfile, Document, RunContext
from doorman.reader.normalize import normalize_skills
from doorman.reader.schema import EMIT_PROFILE_TOOL, TOOL_CHOICE

SYSTEM = (
    "You extract structured facts from a resume. Report only what the text "
    "states. If a value is absent, use the schema's minimum or empty value. "
    "Set reader_confidence low if the text is unusual."
)

MAX_ATTEMPTS = 2
MAX_TOKENS = 1500


class ReaderFailed(Exception):
    """Validation failed twice. The caller routes the candidate to review."""


def _usage(response: Any) -> tuple[int, int]:
    usage = getattr(response, "usage", None)
    return (
        int(getattr(usage, "input_tokens", 0) or 0),
        int(getattr(usage, "output_tokens", 0) or 0),
    )


def _first_tool_input(response: Any) -> dict[str, Any] | None:
    for block in response.content:
        if block.type == "tool_use" and block.name == EMIT_PROFILE_TOOL["name"]:
            return dict(block.input)
    return None


def _field_lengths(profile: CandidateProfile) -> dict[str, int]:
    return {
        "current_title": len(profile.current_title),
        "summary": len(profile.summary),
        "skills": len(profile.skills),
        "education": len(profile.education),
        "languages": len(profile.languages),
    }


def read_profile(
    client: Any,
    settings: Settings,
    cfg: DefenseConfig,
    ctx: RunContext,
    doc: Document,
) -> tuple[CandidateProfile, int, int]:
    """Extract a CandidateProfile. Raises ReaderFailed after two bad attempts.

    Hidden spans are withheld only when the ING-* rules are switched on, which is
    what separates `isolation_only` from `full_minus_classifier` (spec 8.3).
    """
    resume_text = doc.visible_text(exclude_hidden=cfg.hidden_text_rules)
    messages: list[dict[str, Any]] = [{"role": "user", "content": resume_text}]
    input_tokens = output_tokens = 0

    for attempt in range(1, MAX_ATTEMPTS + 1):
        response = client.messages.create(
            model=settings.reader_model,
            max_tokens=MAX_TOKENS,
            system=SYSTEM,
            tools=[EMIT_PROFILE_TOOL],
            tool_choice=TOOL_CHOICE,
            messages=messages,
        )
        used_in, used_out = _usage(response)
        input_tokens += used_in
        output_tokens += used_out
        trace.model_call(
            ctx,
            model=settings.reader_model,
            input_tokens=used_in,
            output_tokens=used_out,
            stop_reason=getattr(response, "stop_reason", None),
        )

        raw = _first_tool_input(response)
        if raw is None:
            errors = ["the model did not call emit_profile"]
        else:
            try:
                profile = CandidateProfile.model_validate(raw)
            except Exception as exc:  # pydantic ValidationError
                errors = str(exc).splitlines()[:12]
            else:
                skills, dropped = normalize_skills(profile.skills)
                profile = profile.model_copy(update={"skills": skills})
                trace.reader_output(
                    ctx,
                    profile_sha256=trace.sha256_text(profile.model_dump_json()),
                    field_lengths=_field_lengths(profile),
                    dropped_skills=dropped,
                    attempt=attempt,
                )
                return profile, input_tokens, output_tokens

        trace.reader_validation_failed(ctx, errors=errors, attempt=attempt)
        if attempt == MAX_ATTEMPTS:
            break
        messages = [
            {"role": "user", "content": resume_text},
            {
                "role": "user",
                "content": (
                    "The previous attempt did not validate. Correct these and "
                    "emit the profile again:\n" + "\n".join(errors)
                ),
            },
        ]

    raise ReaderFailed("emit_profile did not validate after two attempts")
