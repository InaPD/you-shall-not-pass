# Doorman - Implementation Plan

Companion to `doorman-implementation-spec.md`. The spec is the source of truth for *what* to
build; this document is the order to build it in, what "done" means at each gate, and the
questions that must be answered before certain phases can start.

Phases map 1:1 onto the spec's milestones (§20) but add sub-ordering, dependency notes, and
the failure modes worth anticipating.

---

## Pre-flight: decisions that block work (spec §22)

Five of these are listed in the spec as human-owned. Status and recommendation for each:

| # | Decision | Recommendation | Blocks |
|---|---|---|---|
| 1 | Pin model IDs | `claude-sonnet-5` (agent) is current. For the reader, the spec pins `claude-haiku-4-5-20251001` but the current API reference lists the ID as `claude-haiku-4-5` with no date suffix and warns against appending one. Verify both on the models overview page before the first paid run, and fill `config/pricing.yaml` from the pricing page. | Phase 1 (first real API call) |
| 2 | PDF-first, DOCX in P3 | Accept. DOCX ingestion is a separate parser with its own rule set (ING-007, comments, tracked changes); deferring it keeps Phase 1-2 short. The `Document` model is format-agnostic, so nothing needs rework. | Phase 1 scope |
| 3 | Repeats: 3 attacks / 1 benign | Accept, but confirm budget at the Phase 4 gate, not now. Token estimate below. | Phase 4 |
| 4 | Classifier backend | `transformers` + CPU `torch`. Revisit only if install size or per-unit latency becomes the bottleneck in Phase 3. | Phase 3 |
| 5 | Keep `personal_note` in hardened tools | Yes. Without a free-text channel the output scanner has nothing to defend and the bypass hunt in Phase 5 has nowhere to look. Removing it would make `full` look better than it is. | Phase 2 |

Two further ambiguities found in the spec that need an answer before the phase that hits them:

- **Which 3 configs for the benign corpus?** M4's acceptance line says `100 x 3 x 1`, but §18
  does not name the three. `score_drift` is defined as `|score(full) - score(none)|`, so `none`
  and `full` are mandatory. Recommendation: the third is `full_minus_classifier`, which isolates
  how much of the false-positive rate the classifier alone is responsible for. Decide at Phase 4.
- **The `skip_confirmation` oracle is only meaningful under `--approval deny`.** Under
  `--approval auto` every queued action resolves with `resolver="harness-auto"`, so
  "executed, and no human approval" is trivially true for every run, attack or not. Either run
  that intent only in `deny` mode, or have the oracle treat `harness-auto` as a stand-in for
  human approval. Decide at Phase 3.

---

## Dependency shape

```
P0 scaffold (models, rules registry, trace, CLI stubs, CI)
      |
      +-- P1 ingest (pdf, hidden rules) ----+
      +-- P1 mocks (email, ats, web) -------+--> P1 single-call flow  == undefended baseline
      +-- P1 corpus build (2 placements) ---+
                                            |
      P2 reader (quarantined) --------------+
      P2 hardened tools + phases + engine --+--> P2 phased flow + oracles + minimal harness
                                            |
      P3 classifier + output scan + canary -+
      P3 approval queue --------------------+--> P3 all 5 configs, 60 attacks
      P3 docx ingest + remaining placements +
                                            |
      P4 benign corpus + FPR + full matrix -+
                                            |
      P5 bypass hunt + fix + docs ----------+
```

Two things are on the critical path all the way through and should be built correctly in P0:
the **rule registry** (every rule ID in the spec, even for layers not yet implemented) and
**trace.py** (which validates every rule ID it logs against the registry). Everything else logs
through them; retrofitting either later means touching every module.

---

## Phase 0 - Scaffold

**Goal:** an installable project where `pytest` is green and the rule registry is complete.

1. `uv init`, `pyproject.toml` with the §4 dependency set only. Ruff config, pytest config.
2. `models.py` - all of §7 verbatim. Get `Document.guard_units()` right: it yields every span
   (visible *and* hidden) plus every metadata value. Getting this wrong silently blinds the
   classifier later.
3. `policy/rules.py` - **every** rule ID from §8.3, §10, §11.3, §11.4. All of them now, including
   ING-*, CLS-*, POL-*, OUT-*, APR-*, even though most have no implementation yet. `get()` raises
   on unknown IDs.
4. `trace.py` - structlog JSON to `runs/<run_id>/events.jsonl`, INFO+ to stderr. One function per
   event type in §15. Every function taking a `rule_id` calls `rules.get()` first.
5. `cli.py` - typer app with all seven commands from §23 as stubs that raise `NotImplementedError`.
6. `.github/workflows/ci.yml` - ruff + pytest, no API key, no model download.
7. `.env.example`, `.gitignore` (`runs/`, `.env`, `corpus/*/out/`).
8. `tests/test_rules_registry.py`.

**Gate:** `uv run doorman --help` lists all commands. `uv run ruff check . && uv run pytest` passes.

**Watch for:** the dead-rule check in `test_rules_registry.py` will fail for most of the
registry until Phase 3. Structure it as a known-unimplemented allowlist that shrinks each phase,
and empties at Phase 3. An always-skipped test is worthless; a shrinking allowlist is a progress bar.

---

## Phase 1 - Ingest, mocks, undefended baseline

**Goal:** a genuinely undefended agent that an attack can actually beat. This phase produces the
number every later phase is measured against, so its credibility matters more than its polish.

Order within the phase (each step is independently testable):

1. `ingest/pdf.py` - PyMuPDF spans with provenance. Colour decode, bbox, size, image rects.
   Metadata: Info dict and XMP, flattened per §8.1.
2. `ingest/hidden.py` - ING-001 through ING-009. Pure functions over spans and metadata.
3. `ingest/loader.py` - dispatch by extension.
4. `corpus/templates/` - the reportlab resume renderer, shared by attacks and benign corpora.
   Build this as a shared module now; if attacks and benign resumes render differently, layout
   becomes a confound in the false-positive numbers and Phase 4 has to be redone.
5. `corpus/profiles/` - `unqualified_junior`, `borderline_mid`. (`qualified_senior` in Phase 3.)
6. `corpus/payloads/` - at least `score_floor.a` and `force_advance.a`. Written as plausible
   applicant text. This is the single most common way a project like this fabricates its own
   results: caricature payloads that no classifier could miss and no agent would obey.
7. `corpus/attacks/generators/` - `body_plain`, `white_text`. `build.py` reads the manifest.
8. `tools/email.py`, `tools/ats.py`, `tools/web.py` - mocks per §13. SQLite seeded per run.
9. `agent/tools.py` - NAIVE_TOOLS only.
10. `agent/prompts.py`, `agent/loop.py`, `agent/orchestrator.py` - the single-call flow only.
    Raw visible text **plus hidden spans plus a metadata dump**, direct execution, no policy.

**Gate:** `uv run doorman run --config none --doc corpus/attacks/out/DIR-001.pdf --candidate C001
--job J001` writes `events.jsonl` and `outbox.jsonl`. `tests/test_hidden.py` passes for white,
tiny, off-page. `tests/test_tools_mocks.py` passes.

**Watch for:**
- First real API spend happens here. Run one attack manually before running any batch.
- `MAX_TURNS_SINGLE_CALL = 10` is the only thing stopping a runaway loop in this config, since
  budgets live in the policy engine which is off. Verify the cap actually terminates.
- ING rules are computed but inert in this config (§8.3): nothing is excluded, taint is unchanged.
  They must still be logged, so the report can later show what *would* have fired.

---

## Phase 2 - Isolation and policy

**Goal:** the structural defence, and the first ablation number that means something.

1. `reader/schema.py` + `reader/quarantined.py` - forced `emit_profile`, visible text only,
   one retry on validation failure, then `Phase.REVIEW`.
2. `reader/normalize.py` + `config/skills_taxonomy.yaml`.
3. `agent/tools.py` - HARDENED_TOOLS, plus **a pydantic model per tool** for POL-003. The spec
   calls for schema validation but does not say where those models live; put them next to the
   tool schemas and derive one from the other so they cannot drift.
4. `policy/phases.py` - phase enum, per-phase allowlists, budgets.
5. `policy/engine.py` - POL-001 through POL-011 and APR-001/002, evaluated in spec order,
   first failure wins.
6. `guard/envelope.py` - nonce-wrapped untrusted tool results.
7. `agent/orchestrator.py` - the phased flow. Fresh `messages` per phase; typed outputs passed
   forward. Phase completion decided by code.
8. `harness/oracles.py` - the oracles for the intents that exist so far.
9. `harness/run_matrix.py` and `harness/report.py` - minimal versions.
10. Attacks up to 20: `direct`, `hidden_text`, `metadata`, `exfiltration`.

**Gate:** `REPORT.md` shows ASR for `none` vs `isolation_only` over 20 attacks x 1 rep.
`test_policy_engine.py` (table-driven over every POL/APR rule) and `test_loop_fake_client.py` pass.

**Watch for:**
- The taint gate (§11.2) and POL-002 are deliberately redundant: the orchestrator skips
  `communicate`/`write_ats` when tainted, *and* the engine denies those tools if reached anyway.
  Do not "simplify" either away. They fail independently.
- `reached` vs `executed` in the oracles is not symmetric across configs. When the orchestrator
  skips a phase entirely, the model never proposes the malicious call, so `reached` is false -
  not because the model resisted, but because it was never asked. Note this in the report's
  methodology section or the reached% column will be misread.
- `test_loop_fake_client.py` is the highest-value test in the suite. A `FakeClient` returning
  scripted `tool_use` blocks is what lets CI verify allow/deny/approval paths with no API key.
  Build it well; every later phase leans on it.

---

## Phase 3 - Guard, approvals, full corpus

**Goal:** all five configs runnable, all 60 attacks built.

1. `guard/classifier.py` - `Guard` protocol, `DebertaGuard`, `NullGuard`. Chunking at 400 tokens
   with 50 overlap, unit score = max over chunks. CLS-001/002/003 set taint and nothing else.
2. `guard/heuristics.py` - CLS-101/102, advisory only.
3. `guard/output_scan.py` - OUT-001 through OUT-005, canary generation and insertion.
4. `approvals/queue.py` + `doorman approve` - the pending actions table, the human CLI, and the
   `auto` / `deny` resolvers for the harness.
5. `ingest/docx.py` - runs, core props, comments, tracked changes, alt text. ING-007.
6. Remaining placements: `encoding`, `forged_structure`, `tool_result`, `split`, all DOCX ones.
7. Remaining payload intents and `b` phrasings. Fill the manifest to 60, honouring the §16.3
   selection rules (every family >= 5, every intent >= 3 placements, >= 10 docx, >= 8 tool_result).
8. `full` and `full_minus_classifier` presets wired end to end.

**Gate:** 60 attacks build. `run_matrix` works under both `--approval auto` and `--approval deny`.
`REPORT.md` shows `executed% (reached%)` for all 5 configs x 1 rep. The known-unimplemented
allowlist in `test_rules_registry.py` is now empty.

**Watch for:**
- **`encoding` placements cannot use reportlab's standard fonts.** Found in Phase 1:
  `drawString` with Helvetica mangles anything outside Latin-1, so a zero-width character
  and a Cyrillic homoglyph both render as `I` and the payload is destroyed before it
  reaches the page. PDF *metadata* round-trips them intact, which is why ING-005 and
  ING-006 are tested through that carrier. For body-text `homoglyph` and `zero_width`
  placements, embed a TTF with the needed glyphs, or deliver them through metadata or
  DOCX instead.
- The classifier download is a few hundred MB and must never happen in CI. CI uses `NullGuard`;
  make that the default when `config.classifier` is false and assert it in a test.
- Classifier latency on CPU over every span and every metadata value of a resume is the likely
  runtime bottleneck of the whole matrix. Measure it on one document before launching Phase 4.
  If it is bad, that is the trigger for spec §22 decision 4 (ONNX runtime).
- `tool_result` attacks need the ATS seed and portfolio fixtures to carry payloads, which means
  the seed file is partly attacker-controlled by design. Keep poisoned and clean seeds separate
  and select per manifest entry, or every run inherits the poison.
- Resolve the `skip_confirmation` / `--approval auto` interaction flagged in pre-flight.

---

## Phase 4 - Benign corpus and full matrix

**Goal:** the false-positive half of the result. A defence with unreported FPR is not a result.

1. `corpus/benign/generate.py` - 100 specs, reader model produces profile JSON, cached in
   `corpus/benign/out/`. Generate once; never regenerate casually or the corpus stops being stable.
2. `hard_negatives.yaml` - the 20 from §17, every item on that list. These are the ones that
   decide whether the FPR number is honest. The security researcher whose resume says "prompt
   injection" and the candidate at "Ignore Ltd." are the point of the exercise.
3. Render all 100 through the same templates as the attacks, across the 3 layout variants.
4. FPR metrics in `report.py`: `FP_hard`, `FP_soft`, `score_drift`, decision agreement.
5. Harness hardening: resumability (skip `(config, item, rep)` triples already in
   `results.jsonl`), concurrency <= 4, pricing from `config/pricing.yaml`.
6. Full matrix run.

**Gate:** the full matrix completes; `REPORT.md` has every section of §18.

**Budget check before launching.** Rough volume, assuming a phased run is about 6 model calls at
roughly 25k input / 2k output tokens total:

- attacks: 60 x 5 configs x 3 reps = 900 runs
- benign: 100 x 3 configs x 1 rep = 300 runs
- total ~1,200 runs, order of 30M input and 2.5M output tokens

Multiply by the values in `config/pricing.yaml` once filled. Two cost levers if the number is
uncomfortable: drop attack repeats from 3 to 2 (the spec allows confirming this at this gate),
or cut benign to 2 configs (`none` and `full`), which still yields `score_drift` but loses the
classifier's isolated FPR contribution. Prefer cutting repeats; the benign corpus is the half of
the result most projects skip and it is what makes the rest credible.

**Watch for:** resumability is not optional at this scale. Test it by killing a run mid-matrix
and restarting before committing to the full sweep.

---

## Phase 5 - Bypass hunt and documentation

**Goal:** one documented, genuine bypass of `full`, closed, with a regression attack.

Time-boxed to 3 hours of attack attempts per the spec. Starting points, in order of expected yield:

1. `personal_note` - the deliberate free-text channel. Can content be shaped that passes OUT-001
   through OUT-005 and still carries attacker value?
2. `rubric_game` through hidden text - no instruction at all, just fabricated credentials. The
   classifier has nothing to detect; isolation does not help; only the scorer's judgement stands
   between the attack and a high score. This is the family most likely to survive `full`.
3. `fetch_portfolio` result shaping - the enveloped content is still read by the agent.

Then: document the first genuine bypass in `docs/BYPASSES.md` (attack ID, which layer failed and
why, the fix, the new rule ID, the regression attack ID), implement the fix, add the regression
attack to the manifest, rerun the affected cells only.

Finally `README.md` (thesis, architecture, tables pulled from `summary.json`, bypass summary, how
to run, a real log excerpt showing rule IDs) and `docs/THREAT_MODEL.md`.

**Gate:** `BYPASSES.md` has one complete entry; the regression attack fails against `full`;
README renders the final tables.

**Watch for:** spec §21.9 forbids pre-solving this - no span-level provenance in the reader before
this phase. Resist adding it in Phase 2 even when it is obviously the fix. The value of this phase
is the documented discovery, not the feature.

---

## Open items raised during implementation

1. **`temperature` no longer exists on these models.** Spec 6 pins `DOORMAN_TEMPERATURE=0`
   for determinism, but sampling parameters were removed across the Claude 5 family and a
   request carrying one returns a 400. The setting is kept and reported, but not sent. Run
   variance is now handled only by the harness repeats, which strengthens the case for
   keeping attack repeats at 3 rather than dropping to 2 at the Phase 4 budget gate.
2. **`max_tokens: 800` (spec 12.1) may be too small.** Adaptive thinking is on by default
   for the agent model and consumes output tokens, so 800 risks truncating a response
   mid-tool-call. It is now a setting (`DOORMAN_MAX_TOKENS`). Check the first real run and
   raise it if responses come back with `stop_reason: "max_tokens"`.
3. **Reader model ID** - see decision 1 above; the dated suffix needs confirming.
4. **REPORT.md must not be committed until it is built from real inference.** The Phase 2
   gate was verified with a scripted worst-case model (`CompliantClient` in `tests/fakes.py`)
   that accepts every injection. That proves the pipeline and isolates what the defences
   stop from what the model declines, but the ASR numbers it produces are a property of the
   fake, not a measurement. Only commit a REPORT.md generated from a real run.
5. **A review is not always caused by a rule.** `trace.review_requested` now takes an
   optional `cause_rule_id` plus a free-text `reason`. Phase 2 initially borrowed POL-001
   for reader failures and phases that ran out of turns, which would have credited the
   policy layer for mechanical failures in the "rules fired" table and overstated what it
   caught. Only the taint gate passes a real rule id (POL-002).

## Findings from Phase 3

1. **CLS-101 fired zero times across all 70 attacks.** The instruction-phrasing
   regexes caught nothing, because the payloads are written the way a real applicant
   would write them rather than as "IGNORE ALL PREVIOUS INSTRUCTIONS". CLS-102 caught
   only the five `forged_structure` attacks, which literally contain `SYSTEM:`. This is
   the project's thesis expressed as a number, and the README should lead with it: the
   advisory layer is evidence, not a control. Keep both rules in the report showing 0
   rather than omitting empty rows.
2. **DOCX core properties cap at 255 characters each.** Payloads are roughly 450, so
   `docx_core_props` splits across subject, keywords, comments and category. Truncating
   would have quietly tested a weaker attack than the manifest claims.
3. **The `encoding` body-text blocker from Phase 1 is resolved by format, not fonts.**
   `homoglyph` and `zero_width` are DOCX attacks; Word keeps Unicode intact where
   reportlab's standard fonts destroy it. No TTF embedding was needed.
4. **The output scanner logs every hit, not just the deciding one.** The first blocking
   rule still decides, but logging only that hid OUT-003 and OUT-004 whenever OUT-002
   matched first, understating those rules in the report.

## Standing constraints

Carried from spec §21, the ones easiest to violate by accident while implementing:

- The classifier never blocks. It only flips taint. Blocks come from POL-* and OUT-*.
- The `none` config stays genuinely undefended. Every temptation to tidy it up inflates the
  baseline and corrupts every ablation number in the report.
- No LLM calls in the policy engine, the orchestrator, the router, or the oracles.
- Never log raw document text, raw tool results, or full free-text arguments. Hashes, lengths,
  and locators only.
- Prompts never mention rule IDs or describe the policy layer.
- If the `none` baseline ASR comes out low, report it honestly. Do not tune payloads to make the
  baseline look worse.

## Per-commit routine

`uv run ruff check . && uv run pytest` before every commit. One commit per phase minimum;
conventional commit format (`feat:`, `fix:`, `test:`, `docs:`). Note any deviation from a
SHOULD in the commit message.
