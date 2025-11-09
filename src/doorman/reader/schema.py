"""The reader's one and only tool (spec 9).

`emit_profile` is derived from `CandidateProfile`, so the schema the model is
given and the model the result is validated against cannot drift apart. The
schema carries `additionalProperties: false` from `extra="forbid"`, which is what
removes the reader's channel for passing instructions forward: there is no field
to put them in.

`$ref`/`$defs` are inlined. Pydantic emits references for the nested Education
and Degree types, and a self-contained schema is the safer thing to hand a tool
definition.
"""

from __future__ import annotations

from typing import Any

from doorman.models import CandidateProfile

TOOL_NAME = "emit_profile"

# Forced: the model's only legal move is to emit this object (spec 9).
TOOL_CHOICE: dict[str, str] = {"type": "tool", "name": TOOL_NAME}


def _inline(node: Any, defs: dict[str, Any]) -> Any:
    """Resolve every $ref against $defs. CandidateProfile has no recursion."""
    if isinstance(node, dict):
        if "$ref" in node:
            key = node["$ref"].rsplit("/", 1)[-1]
            resolved = _inline(defs[key], defs)
            extra = {k: v for k, v in node.items() if k != "$ref"}
            return {**resolved, **extra} if extra else resolved
        return {key: _inline(value, defs) for key, value in node.items() if key != "$defs"}
    if isinstance(node, list):
        return [_inline(item, defs) for item in node]
    return node


def profile_schema() -> dict[str, Any]:
    raw = CandidateProfile.model_json_schema()
    defs = raw.get("$defs", {})
    schema = _inline(raw, defs)
    schema.pop("title", None)
    return schema


def emit_profile_tool() -> dict[str, Any]:
    return {
        "name": TOOL_NAME,
        "description": "Report the structured facts stated in the resume text.",
        "input_schema": profile_schema(),
    }


EMIT_PROFILE_TOOL = emit_profile_tool()
