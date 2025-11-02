from __future__ import annotations

from pathlib import Path

import pytest

from doorman.policy import rules
from tests.rule_coverage import KNOWN_UNIMPLEMENTED

TESTS_DIR = Path(__file__).parent
COVERED_RULES: set[str] = set()


def cover(rule_id: str) -> str:
    """Mark a rule as asserted by the calling test. Validates the id on the way."""
    rules.get(rule_id)
    COVERED_RULES.add(rule_id)
    return rule_id


def pytest_configure(config: pytest.Config) -> None:
    """The dead-rule check is only meaningful when the whole suite ran.

    Running a single file would otherwise report every rule the other files cover
    as missing, which trains people to ignore the check.
    """
    selected_subset = bool(config.option.keyword or config.option.markexpr)
    named_paths = any(Path(arg).resolve() != TESTS_DIR for arg in config.args)
    config.stash_full_run = not (selected_subset or named_paths)  # type: ignore[attr-defined]


@pytest.fixture(scope="session", autouse=True)
def _dead_rule_check(request):
    """Spec 19: no rule in the registry may go unasserted."""
    yield
    if not getattr(request.config, "stash_full_run", False):
        return

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
