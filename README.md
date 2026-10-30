# SENTINEL

Automated identity threat detection and response — a FastAPI detection/
risk-scoring engine orchestrated by an Activepieces flow with a
human-approval gate, built as a cybersecurity engineering portfolio
project.

## The problem

Identity-based attacks — credential compromise, brute force, password
spraying, account takeover, privileged-account abuse — produce a stream
of authentication events that security teams still largely triage by
hand: pull the IP's reputation, check whether the account is privileged,
decide whether this is the fifth mistyped password of the day or an
active intrusion, then decide what to do about it. In 2026, with
credential-based attacks still the dominant initial-access vector and
identity providers logging more authentication events than any analyst
can read individually, the bottleneck isn't detection signal — it's
triage and consistent, auditable decision-making. SENTINEL automates the
enrichment and scoring step and keeps a human in the loop for the
decision that actually matters: whether to act.

## What's implemented vs. planned

**Implemented and tested:**
- Event ingestion with strict schema validation, API-key auth, rate limiting
- Six deterministic detection rules with a documented correlation window and documented limitations per rule
- AbuseIPDB and VirusTotal clients with local SQLite caching and graceful degradation on error/rate-limit
- Configurable risk scoring with MITRE ATT&CK technique mapping and finding deduplication
- SQLite-backed incident store with a full audit trail
- Simulation-only response actions — no real containment is ever possible from this code path
- 38 automated tests (pytest) covering every rule, the scoring boundaries, the API, and the end-to-end scenarios in [Testing](#testing)

**Documented but not provisioned:** the Activepieces flow itself. Building
it live requires your own Activepieces workspace, a Telegram bot token,
and a reachable backend URL — see
[`activepieces/workflow-documentation/sentinel-flow.md`](activepieces/workflow-documentation/sentinel-flow.md)
for exact piece/action names (verified against the live Activepieces
catalog) and setup steps.

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

Activepieces owns orchestration and the human-in-the-loop gate. The
Python app owns validation, detection, enrichment, scoring, and the
system of record. See
[`activepieces/workflow-documentation/sentinel-flow.md`](activepieces/workflow-documentation/sentinel-flow.md)
for the flow in full detail.

## Technology stack

- **FastAPI** + **Pydantic** — event ingestion and validation
- **SQLite** (stdlib `sqlite3`) — event history, threat-intel cache, incidents, audit trail
- **httpx** — AbuseIPDB and VirusTotal API clients
- **slowapi** — rate limiting
- **Activepieces** — webhook ingress, branching, Telegram notifications/approval
- **pytest** + **respx** — automated tests, including mocked threat-intel responses

## Installation

Requires Python 3.11+ (developed and tested on 3.13 — avoid very new
interpreter releases until third-party wheels catch up).

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
| `SENTINEL_API_KEY` | Required in the `X-API-Key` header on every request |
| `SENTINEL_DB_PATH` | SQLite file path (created automatically) |
| `ABUSEIPDB_API_KEY` | Optional — without it, IP-reputation checks are skipped (not failed) |
| `VIRUSTOTAL_API_KEY` | Optional — without it, domain checks are skipped |
| `SENTINEL_CORRELATION_WINDOW_MINUTES` | How far back detection rules look for related events (default 15) |
| `SENTINEL_FAILED_LOGIN_THRESHOLD` | Failures before `repeated_failed_logins` fires (default 5) |
| `SENTINEL_SPRAY_DISTINCT_ACCOUNTS_THRESHOLD` | Distinct accounts from one IP before `password_spray` fires (default 4) |
| `SENTINEL_ABUSEIPDB_SCORE_THRESHOLD` | AbuseIPDB confidence score before `malicious_ip_reputation` fires (default 50) |

No secret is ever logged; API keys are read only from the environment
(see `app/config.py`) and are never written to the SQLite database.

## API documentation

### `POST /events`
Headers: `X-API-Key: <key>`. Body: an authentication event (see
`app/models/schemas.py:AuthEvent` or `sample_events/`). Unknown fields are
rejected (`extra="forbid"`), as is any field with the wrong type or a
malformed IP — all return `422`. Re-submitting the same `event_id`
returns `409`.

Response: `{event_id, incident_id, findings[], intel[], risk_score, risk_band}`.
`incident_id` is `null` unless the band is `HIGH` or `CRITICAL`.

### `GET /incidents/{incident_id}`
Returns the stored incident: the original event, findings, threat-intel
results, score/band, and (once decided) who decided, what was approved,
and the simulated outcome. `404` if the incident doesn't exist or was
never created (because its band was LOW/MEDIUM).

### `POST /incidents/{incident_id}/decision`
Body: `{approved: bool, decided_by: str, response_action: str, notes?: str}`.
`response_action` is one of `revoke_sessions`, `disable_account`,
`block_ip`, `request_password_reset` — see
[Security limitations](#security-limitations) for why none of these do
anything real. Returns the simulated outcome and records it to the audit
trail.

## Detection methodology

Six deterministic rules, implemented in `app/detection/rules.py`, each
with its own documented blind spots (read the docstrings — they're not
boilerplate):

1. **`repeated_failed_logins`** — ≥ N failed attempts for one account within the correlation window.
2. **`password_spray`** — ≥ N distinct accounts receiving failed attempts from one IP within the window.
3. **`success_after_failures`** — a success preceded by ≥ 3 failures for the same account. Deliberately the noisiest rule: it's also the signature of a user who simply mistyped their password.
4. **`malicious_ip_reputation`** — AbuseIPDB confidence score above a threshold.
5. **`geographic_anomaly`** — a login from a location different from the last *known* (non-"Unknown") location for that account. Only runs when such history exists — not true impossible-travel physics, just a label comparison.
6. **`privileged_account_anomaly`** — any of the above, or any failed attempt, on an account whose role matches a fixed privileged-role list.

Rules run against a correlation window queried from SQLite
(`app/detection/engine.py`), not against the single incoming event in
isolation, which is what lets 1 and 2 distinguish a burst from a trickle.

## Risk-scoring methodology

`app/risk/scoring.py`: each distinct finding contributes its
`severity_weight`; findings are deduplicated by rule name first (highest
weight wins) specifically so the same signal can't be counted twice; the
total is capped at 100.

| Score | Band |
|---|---|
| 0–29 | LOW |
| 30–59 | MEDIUM |
| 60–79 | HIGH |
| 80–100 | CRITICAL |

Only `HIGH`/`CRITICAL` events become a persisted incident and go through
the Activepieces approval gate — see `app/incidents/store.py:INCIDENT_BANDS`.
Each finding also carries a MITRE ATT&CK technique ID; several rules map
to the same technique (`T1078`, Valid Accounts) because the signal itself
(bad IP reputation, geographic anomaly) indicates likely use of
already-compromised credentials rather than a distinct technique of its
own — that mapping is a judgment call, documented in the relevant rule's
docstring.

## Activepieces setup

See [`activepieces/workflow-documentation/sentinel-flow.md`](activepieces/workflow-documentation/sentinel-flow.md).

## Testing

```bash
pytest -q
```

38 tests across:
- `tests/test_detection_rules.py` — each rule in isolation, fire and no-fire cases
- `tests/test_risk_scoring.py` — dedup and band boundaries
- `tests/test_events_endpoint.py` — auth, validation, duplicates, the full pipeline
- `tests/test_decision_endpoint.py` — approval and disapproval paths
- `tests/test_scenarios.py` — the §9 scenario list, including a mocked AbuseIPDB response and a mocked AbuseIPDB *outage* to prove ingestion degrades gracefully instead of failing

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

- **Response actions are 100% simulated.** `app/incidents/response.py`
  never calls a real identity provider, firewall, or session store — by
  construction, not by configuration flag, so there is no "production
  mode" switch that would make this dangerous.
- **Detection rules are heuristic, not ground truth.** Several are
  explicitly documented as noisy (`success_after_failures` especially);
  this is a detection *engine*, not a verdict machine — the risk score and
  human approval exist to absorb that ambiguity.
- **Threat-intel enrichment degrades silently on failure.** A down or
  rate-limited AbuseIPDB/VirusTotal is treated as "unknown", not
  "malicious" or "clean" — ingestion never blocks on a third-party outage,
  but that also means a real outage could mask a real signal.
- **Geographic anomaly detection is a label comparison**, not a
  distance/time-feasibility ("impossible travel") calculation.
- **The privileged-role list is static** (`admin`, `root`, `superuser`, …)
  and will not recognize a custom role name from a provider that doesn't
  use one of those.
- **Correlation is per-window, not cumulative.** A slow attack spread
  across many windows longer than `SENTINEL_CORRELATION_WINDOW_MINUTES`
  will not accumulate into a higher score.
- **No authentication-provider integration.** Events are accepted exactly
  as POSTed; this project does not include a connector to any real IdP,
  by design (§3 of the brief — avoid introducing technologies without a
  clear purpose).

## Future improvements

- Adaptive/baseline thresholds per account instead of static global ones
- A real impossible-travel calculation using IP geolocation + haversine distance/time feasibility
- An allowlist for known shared-egress IPs to reduce spray/geo false positives
- Webhook signature verification example wired into `sample_events/` replay tooling
- A second notification channel (email) alongside Telegram, using Activepieces' existing email pieces
