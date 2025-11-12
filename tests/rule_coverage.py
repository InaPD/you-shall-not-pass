"""Which rules are not yet asserted by a test, and the phase that will fix that.

Spec 19 requires every rule in the registry to be asserted by at least one test.
This allowlist carried the remainder while the layers were being built, and is
now empty: every rule in `RULES` has a test.

The two guards in conftest keep it that way:
  - a rule listed here that a test covers fails the suite (remove the entry)
  - a rule neither here nor covered fails the suite (write the test)

So a new rule added to the registry without a test fails the build, which is the
property this file exists for. Adding an entry here is a deliberate, temporary
act and should come with the phase that will close it.

  Phase 1 closed ING-001 to ING-006, ING-008 and ING-009.
  Phase 2 closed every POL-* rule and both APR-* rules.
  Phase 3 closed ING-007, every CLS-* rule and every OUT-* rule.
"""

KNOWN_UNIMPLEMENTED: dict[str, str] = {}
