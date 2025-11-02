"""Registry integrity and the log-consistency check (spec 19)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from doorman.policy import rules
from tests.rule_coverage import KNOWN_UNIMPLEMENTED

FIXTURES = Path(__file__).parent / "fixtures"
_RULE_ID_KEYS = ("rule_id", "cause_rule_id")


def test_registry_is_not_empty():
    assert len(rules.RULES) == 30


def test_every_rule_id_matches_its_layer():
    for rule_id, rule in rules.RULES.items():
        assert rule_id.startswith(f"{rule.layer}-")
        assert rule.id == rule_id


def test_every_rule_has_a_description():
    for rule in rules.RULES.values():
        assert rule.description.strip()
        assert not rule.description.endswith(".")


def test_actions_are_valid_for_their_layer():
    # The classifier never blocks (spec 21.3): no CLS rule may DENY.
    for rule in rules.RULES.values():
        if rule.layer == "CLS":
            assert rule.action in {"DOWNGRADE", "FLAG"}
        if rule.layer == "ING":
            assert rule.action == "FLAG"
        if rule.layer == "POL":
            assert rule.action == "DENY"
        if rule.layer == "APR":
            assert rule.action == "REQUIRE_APPROVAL"


def test_pol_numbering_gap_is_preserved():
    # Spec 11.3 skips POL-008 and POL-009; ids are never renumbered.
    assert "POL-008" not in rules.RULES
    assert "POL-009" not in rules.RULES
    assert "POL-010" in rules.RULES


def test_get_raises_on_unknown_id():
    with pytest.raises(KeyError, match="unknown rule_id"):
        rules.get("POL-999")


def test_known_unimplemented_entries_all_exist():
    unknown = sorted(set(KNOWN_UNIMPLEMENTED) - set(rules.RULES))
    assert not unknown, f"allowlist names rules that do not exist: {unknown}"


def test_every_rule_id_in_fixture_logs_exists():
    """Spec 19: no events.jsonl fixture may reference an unregistered rule."""
    checked = 0
    for events_file in FIXTURES.rglob("events.jsonl"):
        for line in events_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            for key in _RULE_ID_KEYS:
                if event.get(key) is not None:
                    rules.get(event[key])
                    checked += 1
            for value in event.get("rules_fired") or ():
                rules.get(value)
                checked += 1
    assert checked >= 0  # no fixtures yet is fine; the walk must not raise
