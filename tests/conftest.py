from __future__ import annotations

import pytest

from doorman.policy import rules
from tests.rule_coverage import KNOWN_UNIMPLEMENTED

COVERED_RULES: set[str] = set()


def cover(rule_id: str) -> str:
    """Mark a rule as asserted by the calling test. Validates the id on the way."""
    rules.get(rule_id)
    COVERED_RULES.add(rule_id)
    return rule_id


@pytest.fixture(scope="session", autouse=True)
def _dead_rule_check():
    """Spec 19: no rule in the registry may go unasserted."""
    yield
    stale = sorted(COVERED_RULES & set(KNOWN_UNIMPLEMENTED))
    assert not stale, (
        "these rules are now covered by a test but still listed in "
        f"tests/rule_coverage.py - remove them: {stale}"
    )
    missing = sorted(set(rules.RULES) - COVERED_RULES - set(KNOWN_UNIMPLEMENTED))
    assert not missing, (
        "these rules are asserted by no test and are not in the known-unimplemented "
        f"allowlist: {missing}"
    )
