"""Which rules are not yet asserted by a test, and the phase that will fix that.

Spec 19 requires every rule in the registry to be asserted by at least one test.
This allowlist carries the remainder and MUST shrink every phase, reaching empty
at the end of Phase 3.

Two guards in conftest keep it honest:
  - a rule here that a test now covers fails the suite (remove the entry)
  - a rule neither here nor covered fails the suite (write the test)

Phase 1 closed ING-001 to ING-006, ING-008 and ING-009.
"""

KNOWN_UNIMPLEMENTED: dict[str, str] = {
    # Phase 3 - DOCX ingestion; the only ING rule with no PDF equivalent
    "ING-007": "Phase 3",
    # Phase 2 - policy engine
    "POL-001": "Phase 2",
    "POL-002": "Phase 2",
    "POL-003": "Phase 2",
    "POL-004": "Phase 2",
    "POL-005": "Phase 2",
    "POL-006": "Phase 2",
    "POL-007": "Phase 2",
    "POL-010": "Phase 2",
    "POL-011": "Phase 2",
    # Phase 3 - classifier, heuristics, output scan, approvals
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
    "APR-001": "Phase 3",
    "APR-002": "Phase 3",
}
