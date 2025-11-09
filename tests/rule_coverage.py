"""Which rules are not yet asserted by a test, and the phase that will fix that.

Spec 19 requires every rule in the registry to be asserted by at least one test.
This allowlist carries the remainder and MUST shrink every phase, reaching empty
at the end of Phase 3.

Two guards in conftest keep it honest:
  - a rule here that a test now covers fails the suite (remove the entry)
  - a rule neither here nor covered fails the suite (write the test)

Phase 1 closed ING-001 to ING-006, ING-008 and ING-009.
Phase 2 closed every POL-* rule and both APR-* rules.
"""

KNOWN_UNIMPLEMENTED: dict[str, str] = {
    # Phase 3 - DOCX ingestion; the only ING rule with no PDF equivalent
    "ING-007": "Phase 3",
    # Phase 3 - classifier, heuristics and output scan
    "CLS-001": "Phase 3",
    "CLS-002": "Phase 3",
    "CLS-003": "Phase 3",
    "CLS-101": "Phase 3",
    "CLS-102": "Phase 3",
    "OUT-001": "Phase 3",
    "OUT-002": "Phase 3",
    "OUT-003": "Phase 3",
    "OUT-004": "Phase 3",
    "OUT-005": "Phase 3",
}
