"""Tool-use loop and router (spec 12.1, 12.2).

Phase 1 wires the undefended path: every proposed call is executed. The policy
engine, output scan and approval queue hook into `Router.dispatch` in Phases 2
and 3, which is why the decision is threaded through as a parameter now rather
than being assumed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from doorman import trace
from doorman.agent import tools as tool_defs
from doorman.config import DefenseConfig, Settings
from doorman.models import Allow, PolicyDecision, RunContext, ToolCall
from doorman.tools import web
from doorman.tools.ats import ATS, NOTE_TEMPLATES
from doorman.tools.email import Outbox


@dataclass
class PhaseResult:
    status: str  # done | no_tool_call | max_turns
    input_tokens: int = 0
    output_tokens: int = 0
    turns: int = 0


@dataclass
class Router:
    """Executes tool calls against the mocks and records their effects."""

    ctx: RunContext
    cfg: DefenseConfig
    settings: Settings
    ats: ATS
    outbox: Outbox
    score: int | None = None
    decision: str | None = None
    email_sent: bool = False
    ats_written: bool = False
    executed: list[str] = field(default_factory=list)

    def dispatch(self, call: ToolCall, decision: PolicyDecision) -> str:
        if not isinstance(decision, Allow):
            # Phases 2 and 3 return Deny / RequireApproval here.
            return json.dumps({"error": "denied", "rule": getattr(decision, "rule_id", None)})
        result, effect = self._execute(call)
        self.ctx.budgets_used[call.name] = self.ctx.budgets_used.get(call.name, 0) + 1
        self.executed.append(call.name)
        trace.tool_executed(self.ctx, tool=call.name, effect=effect)
        return json.dumps(result)

    def _execute(self, call: ToolCall) -> tuple[dict[str, Any], dict[str, Any]]:
        handler = getattr(self, f"_tool_{call.name}", None)
        if handler is None:
            return {"error": f"unknown tool {call.name}"}, {"unknown_tool": call.name}
        return handler(call.input)

    # --- tool implementations -------------------------------------------------

    def _tool_score_candidate(self, args: dict) -> tuple[dict, dict]:
        score = int(args.get("score", 0))
        self.score = score
        self.ats.record_score(
            run_id=self.ctx.run_id,
            candidate_id=self.ctx.candidate_id,
            score=score,
            rationale=str(args.get("rationale", "")),
        )
        return {"ok": True, "score": score}, {"score": score}

    def _tool_propose_decision(self, args: dict) -> tuple[dict, dict]:
        status = str(args.get("status", ""))
        self.decision = status
        self.ats.record_decision(
            run_id=self.ctx.run_id,
            candidate_id=self.ctx.candidate_id,
            status=status,
            rationale=str(args.get("rationale", "")),
        )
        return {"ok": True, "status": status}, {"decision": status}

    def _tool_send_email(self, args: dict) -> tuple[dict, dict]:
        if "template_id" in args:  # hardened path (Phase 2)
            row = self.outbox.send_template(
                run_id=self.ctx.run_id,
                candidate_id=self.ctx.candidate_id,
                to=self.ctx.trusted_email,
                full_name=self.ctx.trusted_full_name,
                template_id=str(args["template_id"]),
                personal_note=args.get("personal_note"),
            )
        else:  # naive path: recipient and body come straight from the model
            row = self.outbox.send(
                run_id=self.ctx.run_id,
                candidate_id=self.ctx.candidate_id,
                to=str(args.get("to", "")),
                subject=str(args.get("subject", "")),
                body=str(args.get("body", "")),
            )
        self.email_sent = True
        return {"ok": True, "sent": True}, {
            "email_to": row["to"],
            "template_id": row["template_id"],
        }

    def _tool_ats_update(self, args: dict) -> tuple[dict, dict]:
        note = args.get("note")
        if "note_template_id" in args:  # hardened path (Phase 2)
            note = NOTE_TEMPLATES.get(str(args["note_template_id"]))
        target = str(args.get("candidate_id") or self.ctx.candidate_id)
        effect = self.ats.update_status(
            candidate_id=target, status=str(args.get("status", "")), note=note
        )
        self.ats_written = True
        return {"ok": True, **effect}, effect

    def _tool_ats_lookup(self, args: dict) -> tuple[dict, dict]:
        target = str(args.get("candidate_id") or self.ctx.candidate_id)
        record = self.ats.get(target)
        # `notes` is untrusted and is returned as-is here. Phases 2 and 3 run the
        # classifier over it and wrap it in an envelope before the agent sees it.
        return record.model_dump(), {"looked_up": target}

    def _tool_fetch_url(self, args: dict) -> tuple[dict, dict]:
        result = web.fetch(str(args.get("url", "")))
        return result, {"fetched": str(args.get("url", "")), "resolved": "text" in result}

    _tool_fetch_portfolio = _tool_fetch_url


def _usage(response: Any) -> tuple[int, int]:
    usage = getattr(response, "usage", None)
    return (
        int(getattr(usage, "input_tokens", 0) or 0),
        int(getattr(usage, "output_tokens", 0) or 0),
    )


def run_phase(
    client: Any,
    settings: Settings,
    cfg: DefenseConfig,
    ctx: RunContext,
    *,
    system: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    router: Router,
    max_turns: int,
    tool_choice: dict[str, Any] | None = None,
    evaluate: Any = None,
    is_complete: Any = None,
) -> PhaseResult:
    """Drive one phase to completion.

    `evaluate` is the policy hook: None means allow everything, which is the
    undefended path. `is_complete` lets the orchestrator - never the model and
    never a tool result - decide when the phase is finished (spec 3).
    """
    result = PhaseResult(status="max_turns")
    for turn in range(max_turns):
        # No `temperature`: sampling parameters were removed on the Claude 5
        # family and return a 400. Run-to-run variation is handled by the
        # harness repeats (spec 18), not by pinning a sampling temperature.
        response = client.messages.create(
            model=settings.agent_model,
            max_tokens=settings.max_tokens,
            system=system,
            tools=tools,
            messages=messages,
            **({"tool_choice": tool_choice} if tool_choice else {}),
        )
        input_tokens, output_tokens = _usage(response)
        result.input_tokens += input_tokens
        result.output_tokens += output_tokens
        result.turns = turn + 1
        trace.model_call(
            ctx,
            model=settings.agent_model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            stop_reason=getattr(response, "stop_reason", None),
        )

        messages.append({"role": "assistant", "content": response.content})
        tool_uses = [block for block in response.content if block.type == "tool_use"]
        if not tool_uses:
            result.status = "no_tool_call"
            return result

        results = []
        for block in tool_uses:
            call = ToolCall(id=block.id, name=block.name, input=dict(block.input), phase=ctx.phase)
            trace.tool_call_proposed(
                ctx,
                tool=call.name,
                args_sha256=trace.sha256_text(json.dumps(call.input, sort_keys=True, default=str)),
                args_redacted=trace.redact(call.input),
            )
            decision = evaluate(call, ctx, cfg) if evaluate else Allow()
            trace.policy_decision(
                ctx,
                tool=call.name,
                decision=decision.kind,
                rule_id=getattr(decision, "rule_id", None),
                reason=getattr(decision, "reason", None),
            )
            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": router.dispatch(call, decision),
                }
            )
        messages.append({"role": "user", "content": results})

        if is_complete is not None and is_complete(router):
            result.status = "done"
            return result
    return result


__all__ = ["PhaseResult", "Router", "run_phase", "tool_defs"]
