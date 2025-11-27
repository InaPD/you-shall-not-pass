# You Shall Not Pass

A recruiting agent that reads resumes, scores them, emails candidates and updates
an applicant tracking system (ATS), with layered defences against prompt injection
hidden in the resume. It is a measurement rig: email, ATS and web access are mocks,
and the harness measures how many attacks get through each defence configuration.

## Architecture

```
document ──► ingest ──► Document(spans + metadata) ─┬─► ING-*  hidden text, metadata rules
 (untrusted)                                        ├─► CLS-*  classifier, sets taint only
                                                    │
                                                    └─► quarantined reader
                                                        (no tools, forced JSON call)
                                                              │
                                                              ▼
                                                     CandidateProfile
                                                     typed, capped, extra=forbid
                                                              │
  JobSpec + ATSRecord (trusted) ──────────────────────────────┤
                                                              ▼
              orchestrator (code, not the model) drives the phases:
                  extract ─► score ─► decide ─► communicate ─► write_ats
              each phase is one model call whose tool list holds only that
              phase's tools
                                                              │ tool_use
                                                              ▼
                              policy.engine.evaluate(call, ctx)
                              Allow │ Deny(rule) │ RequireApproval(rule)
                                                              │
                                        ┌─────────────────────┴───────────┐
                                        ▼                                 ▼
                                  OUT-* output scan              APR-* approval queue
                                  (canary, urls, addresses,      (human confirms
                                   other candidates)              irreversible actions)
                                        │                                 │
                                        └────────────► mock email / ATS / web
```

- The classifier (CLS-*) only sets taint; it never blocks. Blocks come from the
  POL-* and OUT-* rules.
- The policy engine, orchestrator and oracles contain no LLM.
- Oracles check final state (outbox, ATS rows, approval queue), not model output.

Five configurations switch layers on and off: `none`, `prompt_only`,
`isolation_only`, `full_minus_classifier` and `full`.

[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) describes the attacker and what is out
of scope. [docs/BYPASSES.md](docs/BYPASSES.md) lists known bypasses of `full`,
including the closed one (OUT-006) and the ones still open.

## Results

<!-- results:start -->

_No matrix has been run yet. `doorman report` writes this section from `harness/out/summary.json`; until then there are no numbers to show, and typing any in by hand would be inventing them._
<!-- results:end -->

`REPORT.md` holds the full tables: attack success rate by family, false-positive
rate over the benign applicants, rule firing counts per config and a per-attack
appendix. `reached` means the model proposed the malicious action; `executed`
means the effect exists in final state.

## Running it

The CLI is `doorman`.

```bash
uv sync                          # base install, no classifier
uv sync --extra classifier       # adds the DeBERTa guard
cp .env.example .env             # then set ANTHROPIC_API_KEY

uv run doorman configs                      # list the five configurations
uv run doorman redteam build                # render the attack corpus
uv run doorman ingest corpus/attacks/out/HID-001.pdf
uv run doorman run --config full --doc corpus/attacks/out/DIR-001.pdf \
                   --candidate C001 --job J001 --approval human
uv run doorman approve --run <run_id>       # review held actions
```

Full matrix:

```bash
uv run doorman benign build
uv run doorman redteam run --configs none,prompt_only,isolation_only,full_minus_classifier,full \
                          --repeats 3 --approval auto
uv run doorman benign run --configs none,full_minus_classifier,full
uv run doorman report                       # writes REPORT.md, summary.json and the Results section above
```

Runs already in `harness/out/results.jsonl` are skipped, so an interrupted sweep
resumes. Cost estimates use `config/pricing.yaml`.

Tests need no API key and no classifier download:

```bash
uv run ruff check . && uv run pytest
```

## Layout

| path | contents |
|---|---|
| `src/doorman/ingest/` | PDF and DOCX parsing; ING-* rules |
| `src/doorman/reader/` | quarantined reader and its schema |
| `src/doorman/guard/` | classifier, heuristics, output scan |
| `src/doorman/policy/` | rule registry, phases, policy engine |
| `src/doorman/agent/` | tool definitions, agent loop, orchestrator |
| `corpus/attacks/` | attack manifest, payloads, generators |
| `corpus/benign/` | benign applicants, including hard negatives |
| `harness/` | matrix runner, oracles, pricing, report |
| `docs/` | threat model, bypasses |
