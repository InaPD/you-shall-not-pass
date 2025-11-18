"""The policy engine (spec 11.3).

Deterministic Python. No LLM calls, ever (spec 21.2). Checks run in the order
below and the FIRST failure is returned, so a denial always names the outermost
reason rather than an incidental one.

Ordering matters for more than tidiness. POL-001 (wrong phase) precedes POL-003
(bad schema) so that a tool called in the wrong phase is reported as a phase
violation even when its arguments are also malformed, which is what makes the
"rules fired" column in the report readable.
"""

from __future__ import annotations

from typing import Any

from doorman.agent.tools import ArgSpec, ToolSpec, specs_for
from doorman.config import DefenseConfig
from doorman.models import (
    Allow,
    Deny,
    PolicyDecision,
    RequireApproval,
    RunContext,
    Taint,
    ToolCall,
)
from doorman.policy import phases


def _deny(rule_id: str, reason: str) -> Deny:
    return Deny(rule_id=rule_id, reason=reason)


def _check_phase(call: ToolCall, ctx: RunContext) -> Deny | None:
    if not phases.is_allowed(ctx.phase, call.name):
        return _deny(
            "POL-001",
            f"{call.name} is not callable in phase {ctx.phase}",
        )
    return None


def _check_taint(call: ToolCall, ctx: RunContext) -> Deny | None:
    if call.name in phases.IRREVERSIBLE and ctx.taint is Taint.SUSPICIOUS:
        return _deny("POL-002", f"{call.name} blocked while the document is suspicious")
    return None


def _check_schema(call: ToolCall, spec: ToolSpec) -> Deny | None:
    """POL-003: structure only. Value constraints are POL-005/006/007."""
    unknown = sorted(set(call.input) - set(spec.args))
    if unknown:
        return _deny("POL-003", f"unknown argument(s): {', '.join(unknown)}")
    missing = sorted(set(spec.required) - set(call.input))
    if missing:
        return _deny("POL-003", f"missing required argument(s): {', '.join(missing)}")
    for name, value in call.input.items():
        if not _type_ok(spec.args[name].type, value):
            return _deny("POL-003", f"{name} must be {_article(spec.args[name].type)}")
    return None


def _type_ok(expected: str, value: object) -> bool:
    if expected == "integer":
        # bool is a subclass of int, so `score: true` would otherwise pass here.
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "string":
        return isinstance(value, str)
    return True


def _article(type_name: str) -> str:
    return "an integer" if type_name == "integer" else "a string"


def _check_trusted_values(
    call: ToolCall, spec: ToolSpec, ctx: RunContext
) -> Deny | None:
    """POL-004: an argument that must equal a trusted value."""
    for name, arg in spec.args.items():
        if arg.must_equal is None or name not in call.input:
            continue
        expected = getattr(ctx, arg.must_equal, None)
        if expected is None or call.input[name] != expected:
            return _deny("POL-004", f"{name} does not match the trusted value")
    return None


def _check_enums(call: ToolCall, spec: ToolSpec) -> Deny | None:
    for name, arg in spec.args.items():
        if arg.enum is None or name not in call.input:
            continue
        if call.input[name] not in arg.enum:
            return _deny("POL-005", f"{name} is not one of {', '.join(arg.enum)}")
    return None


def _check_ranges(call: ToolCall, spec: ToolSpec) -> Deny | None:
    for name, arg in spec.args.items():
        if name not in call.input:
            continue
        value = call.input[name]
        if not isinstance(value, int) or isinstance(value, bool):
            continue
        if arg.minimum is not None and value < arg.minimum:
            return _deny("POL-006", f"{name} is below {arg.minimum}")
        if arg.maximum is not None and value > arg.maximum:
            return _deny("POL-006", f"{name} is above {arg.maximum}")
    return None


def _check_caps(call: ToolCall, spec: ToolSpec) -> Deny | None:
    for name, arg in spec.args.items():
        if arg.max_length is None or name not in call.input:
            continue
        value = call.input[name]
        if isinstance(value, str) and len(value) > arg.max_length:
            return _deny("POL-007", f"{name} exceeds {arg.max_length} characters")
    return None


def _check_budget(call: ToolCall, ctx: RunContext) -> Deny | None:
    budget = phases.budget_for(call.name)
    if budget is None:
        return None
    if ctx.budgets_used.get(call.name, 0) >= budget:
        return _deny("POL-010", f"{call.name} budget of {budget} already used")
    return None


def _check_candidate(call: ToolCall, ctx: RunContext) -> Deny | None:
    referenced = call.input.get("candidate_id")
    if referenced is not None and referenced != ctx.candidate_id:
        return _deny("POL-011", "tool call references another candidate")
    return None


def _check_approval(call: ToolCall) -> RequireApproval | None:
    if call.name == "send_email":
        return RequireApproval(
            rule_id="APR-001", reason="sending email leaves the system boundary"
        )
    if call.name == "ats_update" and call.input.get("status") in {"advance", "reject"}:
        return RequireApproval(
            rule_id="APR-002", reason="advance/reject is an irreversible status change"
        )
    return None


def evaluate(call: ToolCall, ctx: RunContext, cfg: DefenseConfig) -> PolicyDecision:
    """Return the first failing rule, or Allow.

    Scoring, decisions, lookups and fetches are reversible or read-only and never
    require approval (spec 11.3).
    """
    specs = specs_for(cfg.hardened_tools)
    spec = specs.get(call.name)
    if spec is None:
        return _deny("POL-001", f"{call.name} is not a known tool")

    for check in (
        lambda: _check_phase(call, ctx),
        lambda: _check_taint(call, ctx),
        lambda: _check_schema(call, spec),
        lambda: _check_trusted_values(call, spec, ctx),
        lambda: _check_enums(call, spec),
        lambda: _check_ranges(call, spec),
        lambda: _check_caps(call, spec),
        lambda: _check_budget(call, ctx),
        lambda: _check_candidate(call, ctx),
    ):
        failure = check()
        if failure is not None:
            return failure

    if cfg.require_approval:
        approval = _check_approval(call)
        if approval is not None:
            return approval
    return Allow()


def free_text_args(call: ToolCall, cfg: DefenseConfig) -> dict[str, Any]:
    """The arguments the output scanner should inspect (spec 10.3)."""
    spec = specs_for(cfg.hardened_tools).get(call.name)
    if spec is None:
        return {}
    return {
        name: call.input[name]
        for name in spec.free_text
        if isinstance(call.input.get(name), str)
    }


def enum_args(call: ToolCall, cfg: DefenseConfig) -> dict[str, tuple[str, ...]]:
    """The closed vocabularies this call's arguments are drawn from.

    Handed to `trace.redact` so a choice from a fixed set survives redaction.
    Derived from the same ToolSpec the schema comes from, so the two cannot
    drift.
    """
    spec = specs_for(cfg.hardened_tools).get(call.name)
    if spec is None:
        return {}
    return {
        name: arg.enum for name, arg in spec.args.items() if arg.enum
    }


__all__ = ["ArgSpec", "enum_args", "evaluate", "free_text_args"]
