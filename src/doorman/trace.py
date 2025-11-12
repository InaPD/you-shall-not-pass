"""ActionLog - structured events for every step of a run (spec 15).

All events go to `runs/<run_id>/events.jsonl`; INFO and above also go to stderr.
Policy passes are logged at debug, so they land in the file without flooding the
console.

Two invariants are enforced here rather than at the call sites:

1. Every `rule_id` written to a log exists in `rules.RULES` (spec 21.4). This is a
   structlog processor, so it also catches ids buried in a `rules_fired` list.
2. Raw document text, raw tool results and full free-text arguments are never
   logged (spec 21.10). Call sites pass hashes, lengths and locators; `redact` and
   `sha256_text` are here to make that the easy path.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
import threading
from pathlib import Path
from typing import Any

import structlog

from doorman.models import RunContext
from doorman.policy import rules

_RULE_ID_KEYS = ("rule_id", "cause_rule_id")
_RULE_LIST_KEYS = ("rules_fired",)

_sinks: dict[str, Any] = {}
_sinks_lock = threading.Lock()
_configured = False


# --- Helpers call sites use to stay inside spec 21.10 ------------------------

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def redact(value: Any) -> Any:
    """Replace free text with its length. Structure is preserved so the log still
    shows the shape of what was proposed."""
    if isinstance(value, str):
        return f"<{len(value)} chars>"
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


# --- structlog wiring --------------------------------------------------------

class _JsonlSink:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("a", encoding="utf-8")
        self._lock = threading.Lock()
        self.path = path

    def write(self, event_dict: dict[str, Any]) -> None:
        line = json.dumps(event_dict, default=str, sort_keys=False)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            self._fh.close()


def _validate_rule_ids(_logger: Any, _name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    for key in _RULE_ID_KEYS:
        value = event_dict.get(key)
        if value is not None:
            rules.get(value)  # raises KeyError on an unknown id
    for key in _RULE_LIST_KEYS:
        for value in event_dict.get(key) or ():
            rules.get(value)
    return event_dict


def _route_to_run_file(_logger: Any, _name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    run_id = event_dict.get("run_id")
    if run_id:
        with _sinks_lock:
            sink = _sinks.get(run_id)
        if sink is not None:
            sink.write(event_dict)
    return event_dict


def _drop_below_info(_logger: Any, _name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    if event_dict.get("level") == "debug":
        raise structlog.DropEvent
    return event_dict


class _StderrLogger:
    """Writes to whatever `sys.stderr` is *now*.

    structlog's PrintLoggerFactory binds the stream when the logger is built,
    and with cache_logger_on_first_use that handle outlives its owner: under
    pytest, stderr is a per-test capture buffer, so the cached logger ends up
    writing to a closed file and raises. Resolving it per call costs nothing and
    removes the whole class of problem.
    """

    def msg(self, message: str) -> None:
        print(message, file=sys.stderr)

    log = debug = info = warning = warn = error = critical = exception = failure = msg


def _stderr_logger_factory(*_args: Any) -> _StderrLogger:
    return _StderrLogger()


def configure_logging() -> None:
    """Idempotent. Safe to call from the CLI, the harness and tests."""
    global _configured
    if _configured:
        return
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", key="ts", utc=True),
            _validate_rule_ids,
            _route_to_run_file,
            _drop_below_info,
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=_stderr_logger_factory,
        wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
        cache_logger_on_first_use=True,
    )
    _configured = True


def open_run(run_id: str, run_path: Path) -> Path:
    """Start capturing this run's events to `<run_path>/events.jsonl`."""
    configure_logging()
    events_path = run_path / "events.jsonl"
    sink = _JsonlSink(events_path)
    with _sinks_lock:
        existing = _sinks.pop(run_id, None)
        _sinks[run_id] = sink
    if existing is not None:
        existing.close()
    return events_path


def close_run(run_id: str) -> None:
    with _sinks_lock:
        sink = _sinks.pop(run_id, None)
    if sink is not None:
        sink.close()


# --- Event emission ----------------------------------------------------------

def _base(ctx: RunContext) -> dict[str, Any]:
    return {
        "run_id": ctx.run_id,
        "trace_id": ctx.trace_id,
        "config": ctx.config_name,
        "candidate_id": ctx.candidate_id,
        "phase": str(ctx.phase),
    }


def _emit(ctx: RunContext, event: str, *, level: str = "info", **fields: Any) -> None:
    configure_logging()
    logger = structlog.get_logger()
    payload = {**_base(ctx), **{k: v for k, v in fields.items() if v is not None}}
    getattr(logger, level)(event, **payload)


def run_started(
    ctx: RunContext,
    *,
    agent_model: str,
    reader_model: str,
    config: dict[str, Any],
    doc_sha256: str,
    corpus_item_id: str | None = None,
    classifier: str | None = None,
) -> None:
    _emit(
        ctx,
        "run_started",
        agent_model=agent_model,
        reader_model=reader_model,
        classifier=classifier,
        defense_config=config,
        doc_sha256=doc_sha256,
        corpus_item_id=corpus_item_id,
    )


def hidden_text_detected(
    ctx: RunContext,
    *,
    rule_id: str,
    text_len: int,
    span_id: str | None = None,
    metadata_key: str | None = None,
    size: float | None = None,
    color_rgb: tuple[int, int, int] | None = None,
) -> None:
    _emit(
        ctx,
        "hidden_text_detected",
        rule_id=rule_id,
        span_id=span_id,
        metadata_key=metadata_key,
        size=size,
        color_rgb=list(color_rgb) if color_rgb else None,
        text_len=text_len,
    )


def classifier_verdict(
    ctx: RunContext,
    *,
    source: str,
    locator: str,
    score: float,
    chunk_index: int,
    threshold: float,
    rule_id: str | None = None,
) -> None:
    _emit(
        ctx,
        "classifier_verdict",
        rule_id=rule_id,
        source=source,
        locator=locator,
        score=score,
        chunk_index=chunk_index,
        threshold=threshold,
    )


def taint_changed(ctx: RunContext, *, from_taint: str, to_taint: str, cause_rule_id: str) -> None:
    _emit(ctx, "taint_changed", cause_rule_id=cause_rule_id, **{"from": from_taint, "to": to_taint})


def reader_output(
    ctx: RunContext,
    *,
    profile_sha256: str,
    field_lengths: dict[str, int],
    dropped_skills: int,
    attempt: int,
) -> None:
    _emit(
        ctx,
        "reader_output",
        profile_sha256=profile_sha256,
        field_lengths=field_lengths,
        dropped_skills=dropped_skills,
        attempt=attempt,
    )


def reader_validation_failed(ctx: RunContext, *, errors: list[str], attempt: int) -> None:
    _emit(ctx, "reader_validation_failed", errors=errors, attempt=attempt)


def model_call(
    ctx: RunContext,
    *,
    model: str,
    input_tokens: int,
    output_tokens: int,
    stop_reason: str | None,
) -> None:
    _emit(
        ctx,
        "model_call",
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        stop_reason=stop_reason,
    )


def tool_call_proposed(
    ctx: RunContext, *, tool: str, args_sha256: str, args_redacted: dict[str, Any]
) -> None:
    _emit(
        ctx,
        "tool_call_proposed",
        tool=tool,
        args_sha256=args_sha256,
        args_redacted=args_redacted,
    )


def policy_decision(
    ctx: RunContext,
    *,
    tool: str,
    decision: str,
    rule_id: str | None = None,
    reason: str | None = None,
) -> None:
    # Passes are debug (file only); anything that changes the outcome is info.
    level = "debug" if decision == "allow" else "info"
    _emit(ctx, "policy_decision", level=level, tool=tool, decision=decision, rule_id=rule_id,
          reason=reason)


def output_blocked(
    ctx: RunContext, *, tool: str, rule_id: str, field: str, match_redacted: str
) -> None:
    _emit(
        ctx,
        "output_blocked",
        tool=tool,
        rule_id=rule_id,
        field=field,
        match_redacted=match_redacted,
    )


def approval_requested(ctx: RunContext, *, action_id: int, tool: str, rule_id: str) -> None:
    _emit(ctx, "approval_requested", action_id=action_id, tool=tool, rule_id=rule_id)


def approval_resolved(
    ctx: RunContext, *, action_id: int, tool: str, status: str, resolver: str
) -> None:
    _emit(
        ctx,
        "approval_resolved",
        action_id=action_id,
        tool=tool,
        status=status,
        resolver=resolver,
    )


def tool_executed(ctx: RunContext, *, tool: str, effect: dict[str, Any]) -> None:
    _emit(ctx, "tool_executed", tool=tool, effect=effect)


def review_requested(
    ctx: RunContext, *, cause_rule_id: str | None = None, reason: str | None = None
) -> None:
    """`cause_rule_id` only when a rule actually caused it (the taint gate).

    A reader that failed to validate, or a phase that ran out of turns, is not a
    policy denial and must not borrow a POL-* id for one: the "rules fired"
    column in the report would then attribute mechanical failures to the policy
    layer and overstate what it caught.
    """
    _emit(ctx, "review_requested", cause_rule_id=cause_rule_id, reason=reason)


def run_finished(
    ctx: RunContext,
    *,
    status: str,
    duration_s: float,
    total_input_tokens: int,
    total_output_tokens: int,
    score: int | None = None,
    decision: str | None = None,
) -> None:
    _emit(
        ctx,
        "run_finished",
        status=status,
        score=score,
        decision=decision,
        duration_s=duration_s,
        total_input_tokens=total_input_tokens,
        total_output_tokens=total_output_tokens,
    )


def heuristic_flagged(
    ctx: RunContext, *, rule_id: str, locator: str, match_redacted: str, text_len: int
) -> None:
    """CLS-101 / CLS-102. Advisory only: this event never accompanies a taint
    change or a denial, which is what makes it readable as 'what phrase-matching
    would have caught' in the report."""
    _emit(
        ctx,
        "heuristic_flagged",
        rule_id=rule_id,
        locator=locator,
        match_redacted=match_redacted,
        text_len=text_len,
    )
