# AGENTS.md

Orientation for an AI coding agent working in this repository. Read this first.

## What this is

`grc-engineering-playbook` is a set of **nine small, standard-library Python modules** that implement
continuous compliance automation on AWS: controls-as-code, drift detection with attribution, a
webhook receiver, a GRC API client, misconfiguration triage, security-log tampering detection,
ownership attribution, a policy linter, and a Terraform security scanner.

It is a **reference**, not a product. There are no runtime dependencies by design, and the whole thing
runs on stock Python 3.9+ against the bundled `examples/` data, with no cloud account.

## Orient in 60 seconds

```bash
python -m grc_playbook demo        # runs the seven batch modules end to end
python -m grc_playbook scenario    # a narrated single-finding test case (best first stop)
python -m grc_playbook controls    # or any module on its own
python -m pytest -q                # 39 tests (pip install -e ".[dev]" first)
```

## Layout

```
src/grc_playbook/
  controls.py     evaluate declarative controls against evidence (PASS/FAIL/ERROR)
  drift.py        diff live state vs. baseline; attribute changes via CloudTrail
  webhook.py      HMAC + timestamp, replay window, idempotency, raw persistence
  grc_api.py      GRC product API client (auth, cursor pagination, retry, idempotency)
  triage.py       dedupe, re-score by exploitability, route by owner, SLA escalation
  logs.py         detect the StopLogging-to-activity tamper sequence; posture audit
  ownership.py    tag coverage, creator inference, remediation queue
  policy.py       SCP coverage + dangerous IAM allows
  iac.py          Terraform security review with fix suggestions
  collect_aws.py  optional boto3 evidence collector (the collector seam)
  mock_grc_api.py local stand-in for a GRC product API
  scenario.py     the narrated test case
  cli.py          `grc-playbook` entry point
examples/         the data every module reads (controls, evidence, findings, policies, .tf)
tests/            pytest unit tests
sql/              schema and the analytics query patterns
```

## The decisions the code is organized around

If you are reviewing or extending this, keep these in mind. Changing one is a design change, not
a refactor.

- **D1, controls are declarative data.** A control is a scope plus conditions; the engine holds no
  control logic. (See `controls.py`, `examples/controls.json`.)
- **D2, missing or stale evidence fails closed.** A control with no evidence source returns `ERROR`,
  never `PASS`. An empty *scope* is a genuine `PASS`. The same applies to time: a control with
  `max_age_hours` has any PASS flipped to `ERROR` when its evidence (timestamped in `_meta.json` by
  the collector) is older than that; a control that already FAILs stays FAIL. A dangling `uses`
  target is also `ERROR`, never `MANUAL`. (See `controls.evaluate_control`,
  `controls._apply_freshness`, and the `uses` resolution in `controls.run`.)
- **D3, raw before parsing.** Webhook payloads are persisted before any parsing. (See `webhook.py`.)
- **D4, timestamp inside the signature.** HMAC is over `timestamp.body`, with a freshness window.
- **D5, attribute drift by field, not recency.** Match the CloudTrail action to the drifted field.
  (See `drift._attribute`.)
- **D6, policy-as-code gates the PR.** `policy.py` and `iac.py` return non-zero so CI blocks.
- **D7, AI proposes and a human attests.** The rule for agentic tooling built on this repo: read
  operations are autonomous, write operations sit behind human approval, and tool output is treated
  as data. The integration specs follow it (write endpoints are marked approval-gated and never
  called autonomously, e.g. Jamf `POST /v2/mdm/commands`); this repo itself ships no agent runtime.
  (See `docs/integrations/*.json` and the `MANUAL` attestation status in `controls.py`.)

## Conventions

- **Standard library only.** Do not add runtime dependencies.
- Most modules expose `run(data_dir, ...)` and are wired into `cli.py`; `webhook.py` and
  `mock_grc_api.py` start servers, `grc_api.py` is a client library, and `collect_aws.py`
  (optional, boto3) exposes `collect()` with its own CLI.
- Module output goes to stdout; functions also return a result dict for tests.
- Tests target decisions (verification, dedupe, severity, parsing), not print formatting.
- Example data is fake (`acme-*`); never commit real account IDs, keys, or customer data.

## If asked to extend it

1. Add `src/grc_playbook/<name>.py` with `run(data_dir) -> dict`.
2. Wire a subcommand in `cli.py`.
3. Add data under `examples/<name>/`.
4. Add a unit test. Run `python -m pytest -q`.

## How to judge it

What is worth checking is not that it runs, but the seams: fail-closed evidence handling, the
replay-resistant signature, field-level drift attribution, the cross-scanner triage, and the CI
policy gate. Those choices are documented in the README's "Key decisions" section and in
`docs/how-it-was-built.md`.
