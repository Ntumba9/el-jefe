# EL JEFE

EL JEFE is an automated identity threat detection and response system. A FastAPI backend handles detection and risk scoring, and an Activepieces flow orchestrates notifications and a human approval gate on top of it. I built it as a cybersecurity engineering portfolio project.

## The problem

Identity based attacks like credential compromise, brute force, password spraying, account takeover, and privileged account abuse all show up as a stream of authentication events that security teams mostly have to triage by hand. Someone pulls the IP's reputation, checks whether the account is privileged, and has to decide whether this is just the fifth mistyped password of the day or an actual intrusion, then decides what to do about it. Heading into 2026, credential based attacks are still the dominant way attackers get initial access, and identity providers log far more authentication events than any analyst could read individually. The bottleneck isn't a lack of detection signal, it's triage and making consistent, auditable decisions quickly. EL JEFE automates the enrichment and scoring step and keeps a human in the loop for the decision that actually matters: whether to act.

## What's implemented vs. planned

**Implemented and tested:**
- Event ingestion with strict schema validation, scoped API key auth (a separate credential for submitting events vs. approving a decision), and rate limiting on every endpoint
- Six deterministic detection rules, each with a documented correlation window and documented limitations
- AbuseIPDB and VirusTotal clients with local SQLite caching, retry with backoff on transient failures, and graceful degradation when retries are exhausted or the key is missing
- Configurable risk scoring with MITRE ATT&CK technique mapping and finding deduplication
- Cross-incident correlation context (how many prior HIGH/CRITICAL incidents this account or IP has had recently), surfaced as read-only context, not folded into the score
- Idempotency-key support on event ingestion, so a retried delivery (e.g. from Activepieces) replays the original response instead of being scored twice
- Structured JSON logging to stdout, no new dependency
- A SQLite backed incident store with a full audit trail, running in WAL mode so reads don't block on writes
- Simulation only response actions, so no real containment is ever possible from this code path
- 45 automated tests (pytest) covering every rule, the scoring boundaries, the API, retry/idempotency/correlation behavior, and the end to end scenarios described under [Testing](#testing)

**Documented but not provisioned:** the Activepieces flow itself. Building it live needs your own Activepieces workspace, a Telegram bot token, and a reachable backend URL. See [`activepieces/workflow-documentation/el-jefe-flow.md`](activepieces/workflow-documentation/el-jefe-flow.md) for the exact piece and action names (verified against the live Activepieces catalog) and the setup steps.

## Architecture

```
Identity Provider / synthetic event source
        │ HTTP POST
        ▼
Activepieces: Catch Webhook ──HTTP──▶ FastAPI /events
        │                                   │
        │                      validate → detect → enrich → score
        │                                   │
        │◀──── {risk_score, band, incident_id, findings} ────┘
        ▼
  Router on risk_band
   ├─ LOW/MEDIUM ─▶ Telegram notification
   └─ HIGH/CRITICAL ─▶ Telegram approval request (pauses flow)
                              │
                              ▼
                 HTTP POST /incidents/{id}/decision
                              │
                              ▼
                 app/incidents/response.py (SIMULATED outcome only)
                              │
                              ▼
                      audit trail (SQLite)
```

Activepieces handles orchestration and the human in the loop gate. The Python app handles validation, detection, enrichment, scoring, and the system of record. See [`activepieces/workflow-documentation/el-jefe-flow.md`](activepieces/workflow-documentation/el-jefe-flow.md) for the full flow.

## Technology stack

- **FastAPI** and **Pydantic** for event ingestion and validation
- **SQLite** (the standard library's `sqlite3`) for event history, the threat intel cache, incidents, and the audit trail
- **httpx** for the AbuseIPDB and VirusTotal API clients
- **slowapi** for rate limiting
- **Activepieces** for webhook ingress, branching, and Telegram notifications and approvals
- **pytest** and **respx** for automated tests, including mocked threat intel responses

## Installation

You'll need Python 3.11 or newer. It was developed and tested on 3.13; I'd avoid very new interpreter releases until third party wheels catch up.

```bash
python -m venv .venv
.venv/Scripts/activate   # Windows
# source .venv/bin/activate   # macOS/Linux

pip install -r requirements.txt
cp .env.example .env     # then fill in your API key and secrets
```

Run the API:

```bash
uvicorn app.main:app --reload
```

## Environment configuration

See [`.env.example`](.env.example) for every variable. The essentials:

| Variable | Purpose |
|---|---|
| `ELJEFE_INGEST_API_KEY` | Required in the `X-API-Key` header on `POST /events` and `GET /incidents/{id}` |
| `ELJEFE_DECISION_API_KEY` | Required in the `X-API-Key` header on `POST /incidents/{id}/decision` only. Deliberately a different value from the ingest key |
| `ELJEFE_DB_PATH` | SQLite file path (created automatically) |
| `ABUSEIPDB_API_KEY` | Optional. Without it, IP reputation checks are skipped, not failed |
| `VIRUSTOTAL_API_KEY` | Optional. Without it, domain checks are skipped |
| `ELJEFE_CORRELATION_WINDOW_MINUTES` | How far back detection rules look for related events (default 15) |
| `ELJEFE_FAILED_LOGIN_THRESHOLD` | Failures before `repeated_failed_logins` fires (default 5) |
| `ELJEFE_SPRAY_DISTINCT_ACCOUNTS_THRESHOLD` | Distinct accounts from one IP before `password_spray` fires (default 4) |
| `ELJEFE_ABUSEIPDB_SCORE_THRESHOLD` | AbuseIPDB confidence score before `malicious_ip_reputation` fires (default 50) |
| `ELJEFE_INCIDENT_CORRELATION_LOOKBACK_DAYS` | How far back the cross-incident correlation context looks (default 30) |
| `ELJEFE_INTEL_MAX_RETRIES` / `ELJEFE_INTEL_RETRY_BACKOFF_SECONDS` | Retry behavior for AbuseIPDB/VirusTotal on connection errors and 429/5xx (default 2 retries, 0.5s base backoff) |
| `ELJEFE_LOG_LEVEL` | Python logging level for the JSON logs on stdout (default INFO) |

No secret is ever logged. API keys are read only from the environment (see `app/config.py`) and are never written to the SQLite database.

## API documentation

### `POST /events`
Headers: `X-API-Key: <ingest key>`, optionally `Idempotency-Key: <any string>`. Body: an authentication event (see `app/models/schemas.py:AuthEvent` or `sample_events/`). Unknown fields are rejected (`extra="forbid"`), and so is any field with the wrong type or a malformed IP; all of those return `422`. Re-submitting the same `event_id` returns `409`. Re-submitting the same `Idempotency-Key` instead returns the first response verbatim, without re-scoring or re-storing anything — use this when retrying a delivery that may have already succeeded.

Response: `{event_id, incident_id, findings[], intel[], risk_score, risk_band, correlation}`. `incident_id` is `null` unless the band is `HIGH` or `CRITICAL`. `correlation` reports how many prior HIGH/CRITICAL incidents this username or source IP has had within the lookback window — informational only, it does not affect `risk_score`.

### `GET /incidents/{incident_id}`
Headers: `X-API-Key: <ingest key>`. Returns the stored incident: the original event, findings, threat intel results, score and band, and, once it's been decided, who decided it, what was approved, and the simulated outcome. Returns `404` if the incident doesn't exist or was never created because its band was LOW or MEDIUM.

### `POST /incidents/{incident_id}/decision`
Headers: `X-API-Key: <decision key>` — the ingest key will not work here, on purpose; see [Security limitations](#security-limitations). Body: `{approved: bool, decided_by: str, response_action: str, notes?: str}`. `response_action` is one of `revoke_sessions`, `disable_account`, `block_ip`, or `request_password_reset`, and none of these actually do anything real. The endpoint returns the simulated outcome and records it to the audit trail.

## Detection methodology

There are six deterministic rules, implemented in `app/detection/rules.py`, each with its own documented blind spots. The docstrings are worth reading; they're not boilerplate.

1. **`repeated_failed_logins`**: fires when one account gets at least N failed attempts within the correlation window.
2. **`password_spray`**: fires when at least N distinct accounts receive failed attempts from one IP within the window.
3. **`success_after_failures`**: fires on a success preceded by at least 3 failures for the same account. This is deliberately the noisiest rule, since it's also exactly what a user mistyping their own password looks like.
4. **`malicious_ip_reputation`**: fires when the AbuseIPDB confidence score is above a threshold.
5. **`geographic_anomaly`**: fires on a login from a location different from the last known (non "Unknown") location for that account. It only runs when that history actually exists, and it's a label comparison rather than true impossible travel physics.
6. **`privileged_account_anomaly`**: fires on any of the above, or any failed attempt, for an account whose role matches a fixed list of privileged roles.

Rules run against a correlation window queried from SQLite (`app/detection/engine.py`) rather than against the single incoming event in isolation, which is what lets rules 1 and 2 tell a burst apart from a trickle.

## Risk scoring methodology

In `app/risk/scoring.py`, each distinct finding contributes its `severity_weight`. Findings are deduplicated by rule name first, with the highest weight winning, specifically so the same signal can't get counted twice. The total is capped at 100.

| Score | Band |
|---|---|
| 0 to 29 | LOW |
| 30 to 59 | MEDIUM |
| 60 to 79 | HIGH |
| 80 to 100 | CRITICAL |

Only `HIGH` or `CRITICAL` events become a persisted incident and go through the Activepieces approval gate; see `app/incidents/store.py:INCIDENT_BANDS`. Each finding also carries a MITRE ATT&CK technique ID. A few rules map to the same technique (`T1078`, Valid Accounts) because the underlying signal, whether that's a bad IP reputation or a geographic anomaly, points to likely use of already compromised credentials rather than a distinct technique of its own. That mapping is a judgment call, and it's documented in the relevant rule's docstring.

## Activepieces setup

See [`activepieces/workflow-documentation/el-jefe-flow.md`](activepieces/workflow-documentation/el-jefe-flow.md).

## Testing

```bash
pytest -q
```

There are 45 tests across:
- `tests/test_detection_rules.py`: each rule tested in isolation, both fire and no fire cases
- `tests/test_risk_scoring.py`: deduplication and the band boundaries
- `tests/test_events_endpoint.py`: auth, validation, duplicates, and the full pipeline
- `tests/test_decision_endpoint.py`: the approval and disapproval paths, and that the ingest key specifically cannot approve a decision
- `tests/test_scenarios.py`: the full scenario list from the project brief, including a mocked AbuseIPDB response and a mocked AbuseIPDB outage, to prove ingestion degrades gracefully instead of failing
- `tests/test_v2_hardening.py`: idempotency-key replay, cross-incident correlation counts, and AbuseIPDB retry-then-succeed / retry-then-degrade behavior

## Example incident report

```json
{
  "incident_id": "b2e1...",
  "username": "victim3",
  "source_ip": "203.0.113.50",
  "risk_score": 75,
  "risk_band": "HIGH",
  "findings": [
    {"rule": "repeated_failed_logins", "severity_weight": 25, "mitre_technique_id": "T1110.001", "description": "5 failed authentication attempts for 'victim3' within the correlation window."},
    {"rule": "password_spray", "severity_weight": 30, "mitre_technique_id": "T1110.003", "description": "4 distinct accounts received failed authentication attempts from 203.0.113.50 within the correlation window."},
    {"rule": "privileged_account_anomaly", "severity_weight": 20, "mitre_technique_id": "T1078.003", "description": "Anomalous activity involves privileged account 'victim3' (role: admin)."}
  ],
  "decided_by": "soc-analyst",
  "approved": true,
  "response_action": "disable_account",
  "outcome": "[SIMULATED] Account 'victim3' would be disabled."
}
```

## Security limitations

- **Response actions are entirely simulated.** `app/incidents/response.py` never calls a real identity provider, firewall, or session store. That's true by construction, not by a configuration flag, so there's no "production mode" switch that would make this dangerous.
- **Detection rules are heuristic, not ground truth.** A few are explicitly documented as noisy, especially `success_after_failures`. This is a detection engine, not a verdict machine; the risk score and the human approval step exist to absorb that ambiguity.
- **Threat intel enrichment degrades silently on failure.** A down or rate limited AbuseIPDB or VirusTotal call is treated as unknown, not as malicious or clean. Ingestion never blocks on a third party outage, but that also means a real outage could mask a real signal.
- **Geographic anomaly detection is just a label comparison**, not an actual distance and time feasibility calculation for impossible travel.
- **The privileged role list is static** (`admin`, `root`, `superuser`, and a few others), so it won't recognize a custom role name from a provider that doesn't use one of those.
- **Detection-rule correlation happens per window, not cumulatively.** A slow attack spread across more time than `ELJEFE_CORRELATION_WINDOW_MINUTES` won't accumulate into a higher score. The separate cross-incident `correlation` field (prior HIGH/CRITICAL incidents for this user/IP) is informational only and deliberately does not feed back into the score yet — see `app/risk/correlation.py` for why.
- **Retries are bounded, not a queue.** AbuseIPDB/VirusTotal calls retry a fixed number of times with backoff (`ELJEFE_INTEL_MAX_RETRIES`), then degrade to "unknown" like before. There's no durable retry queue, so an outage longer than the retry window still loses that signal for that event.
- **The idempotency cache has no expiry or cleanup.** `idempotency_keys` grows without bound. Fine for a portfolio demo; a long-running deployment would want a TTL or periodic prune.
- **WAL mode needs real file locking.** It's enabled unconditionally in `app/models/db.py`; if `ELJEFE_DB_PATH` ever points at a network or cloud-sync filesystem, WAL can misbehave there, and journal mode would need to be made configurable.
- **There's no authentication provider integration.** Events are accepted exactly as they're posted. This project intentionally doesn't include a connector to any real identity provider, per the project brief's instruction to avoid introducing technologies without a clear purpose.
- **Scoped API keys are two static env vars, not full RBAC.** This was a deliberate scope cut: a single-operator detection pipeline doesn't need user accounts and permission roles, it needs the ingestion credential and the approval credential to not be the same secret. See the assessment history for the fuller reasoning if you want to revisit it.

## Future improvements

- Adaptive, per account baseline thresholds instead of static global ones
- A real impossible travel calculation using IP geolocation plus a haversine distance and time feasibility check
- An allowlist for known shared egress IPs to cut down on spray and geo false positives
- A webhook signature verification example wired into the `sample_events/` replay tooling
- A second notification channel (email) alongside Telegram, using Activepieces' existing email pieces
- Threat-intel confidence weighting (discount a reputation score backed by very few reports)
- A scheduled Activepieces trigger that re-checks IP reputation for still-open incidents, plus the `GET /incidents?status=open` endpoint it would need
- Provisioning the real Activepieces flow (webhook → HTTP → backend → Telegram approval → decision callback) against this hardened backend, replacing the router-only demo flow used to verify orchestration
