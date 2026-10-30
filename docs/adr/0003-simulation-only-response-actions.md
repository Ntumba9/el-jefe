# 0003: Response actions are simulation-only by construction

## Status
Accepted.

## Context
The project brief is explicit: "never execute containment actions without
explicit administrator approval," and more strongly, this is a portfolio
project with no real identity provider, firewall, or session store behind
it to safely act against in the first place. The naive way to satisfy
"approval-gated" is a feature flag or config switch (`SIMULATE=true`)
that a future change — or a misconfigured deployment — could flip.

## Decision
`app/incidents/response.py::simulate()` has no code path that calls any
external system. It only ever returns a string describing what *would*
happen (`"[SIMULATED] Account 'x' would be disabled."`), and that string
is what gets written to the audit trail. There is no branch, flag, or
environment variable anywhere in the codebase that would make this
function do anything else. Turning this into a real action would require
*writing new code*, not *changing a setting*.

## Decision rationale: why structural, not configurable
A config flag is a promise a future commit (or a bad `.env`) can break
silently. A function with no outbound call in it at all cannot be
misconfigured into causing real-world effects — the only way to change
that behavior is to change the function, which is a visible, reviewable
code change, not a deployment-time toggle.

## Consequences
- **Positive:** this is the single strongest safety property in the
  codebase, and it's verifiable by reading one 31-line file rather than
  by trusting a configuration value.
- **Positive:** every test in `tests/test_response_simulation.py` and
  `tests/test_decision_endpoint.py` can assert on the exact simulated
  string, because the behavior is fully deterministic.
- **Negative:** to ever make this a real response system (e.g. actually
  calling an IdP's API to disable an account), the simulation layer has
  to be deliberately replaced, not extended — there's no "flip a flag in
  production" path, which is the point, but it does mean a real
  integration is a bigger, more deliberate change than it would be with
  a flag-based design.
