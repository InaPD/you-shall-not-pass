"""The shape a generated benign resume has to take (spec 17).

The reader model is given this as a forced tool schema, so a generation either
validates or fails loudly - there is no partially-filled resume that quietly
renders as a half-empty page and then reads as a low-confidence profile.

Deliberately the same shape as `corpus/profiles/*.yaml`, the hand-written attack
targets, because both corpora go through the same renderer. A benign resume that
carried different fields would be a different document class, and the
false-positive numbers would be measuring that difference instead of the
defences.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Role(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(max_length=80)
    company: str = Field(max_length=80)
    period: str = Field(max_length=40)
    bullets: list[str] = Field(min_length=1, max_length=6)


class Degree(BaseModel):
    model_config = ConfigDict(extra="forbid")

    degree: str = Field(max_length=60)
    field: str = Field(max_length=80)
    institution: str = Field(max_length=100)
    year: int = Field(ge=1970, le=2026)


class ResumeProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str = Field(max_length=60)
    headline: str = Field(max_length=80)
    email: str = Field(max_length=100)
    phone: str = Field(max_length=30)
    location: str = Field(max_length=80)
    years_experience: int = Field(ge=0, le=45)
    portfolio_url: str | None = Field(default=None, max_length=200)
    summary: str = Field(max_length=1400)
    skills: list[str] = Field(min_length=3, max_length=16)
    experience: list[Role] = Field(min_length=1, max_length=5)
    education: list[Degree] = Field(min_length=1, max_length=3)
    languages: list[str] = Field(min_length=1, max_length=5)

    def searchable_text(self) -> str:
        """Every word the rendered document will carry, for requirement checks."""
        parts = [
            self.full_name, self.headline, self.location, self.summary,
            *self.skills, *self.languages,
            *(f"{r.title} {r.company} {r.period} {' '.join(r.bullets)}"
              for r in self.experience),
            *(f"{d.degree} {d.field} {d.institution}" for d in self.education),
        ]
        return "\n".join(parts)


TOOL_NAME = "emit_resume"
TOOL_CHOICE: dict[str, str] = {"type": "tool", "name": TOOL_NAME}


def _inline(node: Any, defs: dict[str, Any]) -> Any:
    """Resolve $refs the way `reader/schema.py` does - a self-contained schema is
    the safer thing to hand a tool definition."""
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


def emit_resume_tool() -> dict[str, Any]:
    raw = ResumeProfile.model_json_schema()
    schema = _inline(raw, raw.get("$defs", {}))
    schema.pop("title", None)
    return {
        "name": TOOL_NAME,
        "description": "Report one fictional applicant's resume as structured fields.",
        "input_schema": schema,
    }
