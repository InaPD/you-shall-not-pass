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
from doorman.approvals.queue import ApprovalQueue, auto_resolver
from doorman.config import DefenseConfig, Settings
from doorman.guard import envelope, output_scan
from doorman.guard.classifier import Guard, NullGuard, score_unit
from doorman.models import (
    Allow,
    Deny,
    PolicyDecision,
    RequireApproval,
    RunContext,
    Taint,
    ToolCall,
)
from doorman.policy.engine import free_text_args
from doorman.tools import effects, web
from doorman.tools.ats import ATS
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
    approval_mode: str = "human"
    guard: Guard = field(default_factory=NullGuard)
    score: int | None = None
    decision: str | None = None
    email_sent: bool = False
    ats_written: bool = False
    review_requested: bool = False
    rationale: str = ""
    # Set when an irreversible action is queued rather than executed. Always
    # False until the approval queue lands in Phase 3; the phase-completion
    # checks read them now so that queueing counts as finishing the phase.
    email_pending: bool = False
    ats_pending: bool = False
    executed: list[str] = field(default_factory=list)

    def dispatch(self, call: ToolCall, decision: PolicyDecision) -> str:
        """Spec 12.2. Output scanning runs before execution AND before queueing:
        a DENY there beats an approval, so a human is never asked to rubber-stamp
        something the scanner already rejected."""
        if isinstance(decision, Deny):
            return json.dumps({"error": "denied", "rule": decision.rule_id})

        blocked = self._scan_output(call)
        if blocked is not None:
            return blocked

        if isinstance(decision, RequireApproval):
            return self._queue(call, decision)
        return self._run(call)

    def _scan_output(self, call: ToolCall) -> str | None:
        """OUT-* on the call's free-text arguments. Returns a denial, or None."""
        if not self.cfg.output_scan:
            return None
        hits = output_scan.scan_args(free_text_args(call, self.cfg), self.ctx)
        # Every hit is logged, not only the one that decides. The decision is
        # still the first blocking rule, but logging only that would hide what
        # the other rules caught whenever an earlier rule happened to match too.
        for hit in hits:
            trace.output_blocked(
                self.ctx, tool=call.name, rule_id=hit.rule_id,
                field=hit.field, match_redacted=hit.redacted(),
            )
        blocking = output_scan.first_blocking(hits)
        if blocking is None:
            return None
        trace.policy_decision(
            self.ctx, tool=call.name, decision="deny", rule_id=blocking.rule_id,
            reason="outbound text failed the output scan",
        )
        return json.dumps({"error": "denied", "rule": blocking.rule_id})

    def _queue(self, call: ToolCall, decision: RequireApproval) -> str:
        queue = ApprovalQueue(self.ats)
        action_id = queue.enqueue(
            run_id=self.ctx.run_id, trace_id=self.ctx.trace_id,
            candidate_id=self.ctx.candidate_id, tool=call.name,
            args=call.input, rule_id=decision.rule_id,
        )
        trace.approval_requested(
            self.ctx, action_id=action_id, tool=call.name, rule_id=decision.rule_id
        )
        self._mark_pending(call.name)

        resolution = auto_resolver(self.approval_mode)
        if resolution is None:  # human: the run stops here and `doorman approve` continues
            return json.dumps({"status": "pending_approval", "action_id": action_id})

        approved, resolver = resolution
        queue.resolve(action_id, approved=approved, resolver=resolver)
        trace.approval_resolved(
            self.ctx, action_id=action_id, tool=call.name,
            status="approved" if approved else "rejected", resolver=resolver,
        )
        if not approved:
            return json.dumps({"status": "rejected", "action_id": action_id})
        return self._run(call)

    def _mark_pending(self, tool: str) -> None:
        if tool == "send_email":
            self.email_pending = True
        elif tool == "ats_update":
            self.ats_pending = True

    def _run(self, call: ToolCall) -> str:
        result, effect = self._execute(call)
        self.ctx.budgets_used[call.name] = self.ctx.budgets_used.get(call.name, 0) + 1
        self.executed.append(call.name)
        trace.tool_executed(self.ctx, tool=call.name, effect=effect)
        return json.dumps(result)

    def classify_result(self, source: str, text: str, locator: str) -> None:
        """CLS-003 on an untrusted tool result. Downgrades taint; never blocks."""
        if not self.cfg.classifier or not text:
            return
        score, chunk_index = score_unit(
            self.guard, text,
            size=self.settings.classifier_chunk_tokens,
            overlap=self.settings.classifier_chunk_overlap,
        )
        threshold = self.settings.classifier_threshold
        fired = score >= threshold
        trace.classifier_verdict(
            self.ctx, rule_id="CLS-003" if fired else None, source=source,
            locator=locator, score=round(score, 4), chunk_index=chunk_index,
            threshold=threshold,
        )
        if fired and self.ctx.taint is not Taint.SUSPICIOUS:
            trace.taint_changed(
                self.ctx, from_taint=self.ctx.taint, to_taint=Taint.SUSPICIOUS,
                cause_rule_id="CLS-003",
            )
            self.ctx.taint = Taint.SUSPICIOUS

    def _execute(self, call: ToolCall) -> tuple[dict[str, Any], dict[str, Any]]:
        handler = getattr(self, f"_tool_{call.name}", None)
        if handler is None:
            return {"error": f"unknown tool {call.name}"}, {"unknown_tool": call.name}
        return handler(call.input)

    # --- tool implementations -------------------------------------------------

    def _tool_score_candidate(self, args: dict) -> tuple[dict, dict]:
        score = int(args.get("score", 0))
        self.score = score
        self.rationale = str(args.get("rationale", ""))
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
        self.rationale = str(args.get("rationale", ""))
        self.ats.record_decision(
            run_id=self.ctx.run_id,
            candidate_id=self.ctx.candidate_id,
            status=status,
            rationale=str(args.get("rationale", "")),
        )
        return {"ok": True, "status": status}, {"decision": status}

    def _tool_send_email(self, args: dict) -> tuple[dict, dict]:
        row = effects.send_email(
            self.outbox, run_id=self.ctx.run_id,
            record=self.ats.get(self.ctx.candidate_id), args=args,
        )
        self.email_sent = True
        return {"ok": True, "sent": True}, {
            "email_to": row["to"],
            "template_id": row["template_id"],
        }

    def _tool_ats_update(self, args: dict) -> tuple[dict, dict]:
        effect = effects.ats_update(
            self.ats, candidate_id=self.ctx.candidate_id, args=args
        )
        self.ats_written = True
        return {"ok": True, **effect}, effect

    def _tool_ats_lookup(self, args: dict) -> tuple[dict, dict]:
        target = str(args.get("candidate_id") or self.ctx.candidate_id)
        record = self.ats.get(target)
        payload = record.model_dump()
        # `notes` is free text of unknown provenance (spec 7). The trusted fields
        # pass through; the note is classified, then enveloped so the agent can
        # see where the trustworthy part of this result stops.
        if payload.get("notes"):
            self.classify_result("ats_notes", str(payload["notes"]), f"ats.notes.{target}")
            if self.cfg.isolate_reader:
                payload["notes"] = envelope.wrap("ats_notes", str(payload["notes"]))
        return payload, {"looked_up": target}

    def _tool_request_human_review(self, args: dict) -> tuple[dict, dict]:
        self.review_requested = True
        return {"ok": True, "queued": True}, {"review": True}

    def _tool_fetch_url(self, args: dict) -> tuple[dict, dict]:
        url = str(args.get("url", ""))
        result = web.fetch(url)
        if "text" in result:
            self.classify_result("portfolio_page", result["text"], url)
            if self.cfg.isolate_reader:
                result = {**result, "text": envelope.wrap("portfolio_page", result["text"])}
        return result, {"fetched": url, "resolved": "text" in result}

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
