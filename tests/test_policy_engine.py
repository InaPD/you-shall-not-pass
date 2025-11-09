"""Table-driven policy engine tests (spec 19).

Every POL-* and APR-* rule has at least one row here, plus the allow path.
"""

from __future__ import annotations

import pytest

from doorman.config import preset
from doorman.models import Phase, RunContext, Taint, ToolCall
from doorman.policy import phases
from doorman.policy.engine import evaluate, free_text_args
from tests.conftest import cover

FULL = preset("full")
ISOLATION = preset("isolation_only")  # same tools, no approval queue
NONE = preset("none")


def ctx(**overrides) -> RunContext:
    base = {
        "run_id": "r1", "trace_id": "t1", "config_name": "full",
        "candidate_id": "C001", "job_id": "J001", "canary": "abcd1234",
        "trusted_email": "jane@example.com", "trusted_full_name": "Jane Doe",
        "trusted_portfolio_url": "https://portfolio.example/jane",
        "phase": Phase.SCORE,
    }
    return RunContext(**{**base, **overrides})


def decide(tool: str, args: dict, *, context: RunContext, cfg=FULL):
    call = ToolCall(id="tu_1", name=tool, input=args, phase=context.phase)
    return evaluate(call, context, cfg)


# (label, rule_id, tool, args, ctx kwargs, cfg)
DENIALS = [
    ("tool not allowed in this phase", "POL-001", "send_email",
     {"template_id": "reject_polite"}, {"phase": Phase.SCORE}, FULL),
    ("tool not allowed in ingest", "POL-001", "score_candidate",
     {"score": 10, "rationale": "x"}, {"phase": Phase.INGEST}, FULL),
    ("email while tainted", "POL-002", "send_email",
     {"template_id": "reject_polite"},
     {"phase": Phase.COMMUNICATE, "taint": Taint.SUSPICIOUS}, FULL),
    ("ats write while tainted", "POL-002", "ats_update",
     {"status": "advance"},
     {"phase": Phase.WRITE_ATS, "taint": Taint.SUSPICIOUS}, FULL),
    ("unknown argument", "POL-003", "score_candidate",
     {"score": 50, "rationale": "x", "to": "a@b.example"}, {}, FULL),
    ("missing required argument", "POL-003", "score_candidate",
     {"score": 50}, {}, FULL),
    ("wrong argument type", "POL-003", "score_candidate",
     {"score": "fifty", "rationale": "x"}, {}, FULL),
    ("boolean is not an integer", "POL-003", "score_candidate",
     {"score": True, "rationale": "x"}, {}, FULL),
    ("url is not the profile url", "POL-004", "fetch_portfolio",
     {"url": "https://evil.example/x"}, {}, FULL),
    ("enum outside permitted values", "POL-005", "propose_decision",
     {"status": "hire", "rationale": "x"}, {"phase": Phase.DECIDE}, FULL),
    ("score above range", "POL-006", "score_candidate",
     {"score": 101, "rationale": "x"}, {}, FULL),
    ("score below range", "POL-006", "score_candidate",
     {"score": -1, "rationale": "x"}, {}, FULL),
    ("rationale over cap", "POL-007", "score_candidate",
     {"score": 50, "rationale": "x" * 201}, {}, FULL),
    ("personal_note over cap", "POL-007", "send_email",
     {"template_id": "hold_update", "personal_note": "x" * 201},
     {"phase": Phase.COMMUNICATE}, FULL),
    ("budget exhausted", "POL-010", "score_candidate",
     {"score": 50, "rationale": "x"}, {"budgets_used": {"score_candidate": 1}}, FULL),
    ("another candidate's record", "POL-011", "ats_update",
     {"candidate_id": "C003", "status": "advance"},
     {"phase": Phase.WRITE_ATS}, NONE),
]


@pytest.mark.parametrize(
    "label,rule_id,tool,args,ctx_kwargs,cfg",
    DENIALS,
    ids=[row[0] for row in DENIALS],
)
def test_denials(label, rule_id, tool, args, ctx_kwargs, cfg):
    cover(rule_id)
    decision = decide(tool, args, context=ctx(**ctx_kwargs), cfg=cfg)
    assert decision.kind == "deny", f"{label}: expected deny, got {decision}"
    assert decision.rule_id == rule_id, f"{label}: {decision.reason}"


class TestAllowPath:
    def test_score_in_score_phase(self):
        assert decide("score_candidate", {"score": 41, "rationale": "Junior."},
                      context=ctx()).kind == "allow"

    def test_decision_in_decide_phase(self):
        assert decide("propose_decision", {"status": "reject", "rationale": "No."},
                      context=ctx(phase=Phase.DECIDE)).kind == "allow"

    def test_lookup_is_allowed_in_both_read_phases(self):
        for phase in (Phase.SCORE, Phase.DECIDE):
            assert decide("ats_lookup", {}, context=ctx(phase=phase)).kind == "allow"

    def test_portfolio_fetch_with_the_trusted_url(self):
        assert decide("fetch_portfolio", {"url": "https://portfolio.example/jane"},
                      context=ctx()).kind == "allow"

    def test_boundary_values_are_allowed(self):
        for score in (0, 100):
            assert decide("score_candidate", {"score": score, "rationale": "x"},
                          context=ctx()).kind == "allow"

    def test_rationale_exactly_at_the_cap_is_allowed(self):
        assert decide("score_candidate", {"score": 50, "rationale": "x" * 200},
                      context=ctx()).kind == "allow"

    def test_reads_are_never_gated_by_taint(self):
        """Spec 11.2: only irreversible tools are blocked when suspicious."""
        assert decide("ats_lookup", {}, context=ctx(taint=Taint.SUSPICIOUS)).kind == "allow"

    def test_scoring_is_never_gated_by_taint(self):
        """The recruiter still gets a recommendation on a suspicious document."""
        assert decide("score_candidate", {"score": 41, "rationale": "x"},
                      context=ctx(taint=Taint.SUSPICIOUS)).kind == "allow"


class TestApprovals:
    def test_send_email_requires_approval(self):
        cover("APR-001")
        decision = decide("send_email", {"template_id": "reject_polite"},
                          context=ctx(phase=Phase.COMMUNICATE))
        assert decision.kind == "approve"
        assert decision.rule_id == "APR-001"

    @pytest.mark.parametrize("status", ["advance", "reject"])
    def test_irreversible_status_requires_approval(self, status):
        cover("APR-002")
        decision = decide("ats_update", {"status": status},
                          context=ctx(phase=Phase.WRITE_ATS))
        assert decision.kind == "approve"
        assert decision.rule_id == "APR-002"

    @pytest.mark.parametrize("status", ["screening", "hold"])
    def test_reversible_status_does_not(self, status):
        decision = decide("ats_update", {"status": status},
                          context=ctx(phase=Phase.WRITE_ATS))
        assert decision.kind == "allow"

    def test_no_approval_when_the_layer_is_off(self):
        """Spec 11.3: RequireApproval only when cfg.require_approval."""
        decision = decide("send_email", {"template_id": "reject_polite"},
                          context=ctx(phase=Phase.COMMUNICATE), cfg=ISOLATION)
        assert decision.kind == "allow"

    def test_denial_beats_approval(self):
        """A tainted email is denied outright, not queued for a human."""
        decision = decide("send_email", {"template_id": "reject_polite"},
                          context=ctx(phase=Phase.COMMUNICATE, taint=Taint.SUSPICIOUS))
        assert decision.kind == "deny"
        assert decision.rule_id == "POL-002"


class TestOrdering:
    def test_phase_violation_outranks_a_schema_violation(self):
        """A tool called in the wrong phase reports the phase, not the arguments."""
        decision = decide("send_email", {"nonsense": 1}, context=ctx(phase=Phase.SCORE))
        assert decision.rule_id == "POL-001"

    def test_taint_outranks_a_cap_violation(self):
        decision = decide(
            "send_email", {"template_id": "hold_update", "personal_note": "x" * 500},
            context=ctx(phase=Phase.COMMUNICATE, taint=Taint.SUSPICIOUS),
        )
        assert decision.rule_id == "POL-002"

    def test_schema_violation_outranks_a_range_violation(self):
        decision = decide("score_candidate", {"score": 500, "rationale": "x", "x": 1},
                          context=ctx())
        assert decision.rule_id == "POL-003"


class TestUnknownTools:
    def test_a_tool_that_does_not_exist_is_denied(self):
        assert decide("wire_transfer", {"amount": 1000}, context=ctx()).rule_id == "POL-001"


class TestFreeTextExtraction:
    def test_finds_the_scannable_arguments(self):
        call = ToolCall(id="1", name="send_email", phase=Phase.COMMUNICATE,
                        input={"template_id": "hold_update", "personal_note": "hello"})
        assert free_text_args(call, FULL) == {"personal_note": "hello"}

    def test_enum_arguments_are_not_free_text(self):
        call = ToolCall(id="1", name="ats_update", phase=Phase.WRITE_ATS,
                        input={"status": "advance", "note_template_id": "advanced"})
        assert free_text_args(call, FULL) == {}

    def test_naive_body_is_free_text(self):
        call = ToolCall(id="1", name="send_email", phase=Phase.SINGLE,
                        input={"to": "a@b.example", "subject": "s", "body": "b"})
        assert free_text_args(call, NONE) == {"subject": "s", "body": "b"}


class TestPhaseTables:
    def test_every_allowlisted_tool_exists(self):
        from doorman.agent.tools import HARDENED_SPECS

        for phase, tools in phases.ALLOWLISTS.items():
            if phase in (Phase.SINGLE, Phase.EXTRACT):
                continue
            for tool in tools:
                assert tool in HARDENED_SPECS, f"{phase} allows unknown tool {tool}"

    def test_irreversible_tools_are_the_ones_with_approval_rules(self):
        assert set(phases.IRREVERSIBLE) == {"send_email", "ats_update"}

    def test_every_budgeted_tool_is_allowlisted_somewhere(self):
        allowlisted = {t for tools in phases.ALLOWLISTS.values() for t in tools}
        assert set(phases.BUDGETS) <= allowlisted
