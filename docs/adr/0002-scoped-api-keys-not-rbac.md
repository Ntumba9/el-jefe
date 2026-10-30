# 0002: Scoped API keys instead of full RBAC

## Status
Accepted. Scoped down from an earlier, broader request during the EL JEFE
V2 engineering assessment.

## Context
The original V2 upgrade request asked for "role-based access control
where appropriate." The real risk being addressed is specific: the
credential an automated pipeline uses to submit events (`/events`)
should not also be able to approve a containment decision
(`/incidents/{id}/decision`) — those are different trust levels, and a
compromised or misconfigured ingestion integration shouldn't be able to
approve its own containment actions.

Full RBAC — user accounts, login, roles, permission matrices — solves a
different problem: multiple *human* operators with different privilege
levels. EL JEFE has no multi-user concept anywhere else in the system;
adding one just for this would mean building (and securing, and testing)
an entire subsystem to protect a single endpoint.

## Decision
Two static environment-variable credentials: `ELJEFE_INGEST_API_KEY` and
`ELJEFE_DECISION_API_KEY`. `require_ingest_key` and `require_decision_key`
are separate FastAPI dependencies; `/events` and `GET /incidents/{id}`
require the ingest key, `POST /incidents/{id}/decision` requires the
decision key specifically. See `app/main.py`.

## Consequences
- **Positive:** closes the actual risk (ingestion-can't-approve) with two
  env vars and ~10 lines of code, fully covered by a test
  (`test_ingest_key_alone_cannot_approve_a_decision`).
- **Positive:** no new attack surface — no login flow, no session/token
  issuance, no password storage to get wrong.
- **Negative:** doesn't scale to multiple human analysts with different
  permissions (e.g. "can view incidents but not approve them"). If that
  becomes a real requirement, it's a genuinely new feature, not an
  extension of this ADR's decision — revisit then, not preemptively.
- **Negative:** key rotation is manual (update the env var, restart).
  Acceptable at this scale; a secrets-manager-backed rotation story
  would be the natural next step for a real deployment, not for this
  portfolio project's threat model.
