# Sample events

Synthetic, fictional data only — no real usernames, IPs, or company names.
Each file is either a single event object or a JSON array of events meant
to be posted **in order** to `POST /events`, with a short pause between
calls, so that each one lands in the correlation window used by the
detection engine (15 minutes by default).

| File | Demonstrates |
|---|---|
| `01_normal_employee_login.json` | Clean login, LOW risk, no incident |
| `02_repeated_failed_logins.json` | Brute-force rule (`repeated_failed_logins`) |
| `03_password_spraying.json` | Spray rule (`password_spray`) |
| `04_success_after_repeated_failures.json` | `success_after_failures` |
| `05_suspicious_ip_reputation.json` | `malicious_ip_reputation` — only fires with `ABUSEIPDB_API_KEY` set to a real key; against this fictional IP it will return a low/zero score from the real API, so to see it fire locally without a key, use the mocked test in `tests/test_scenarios.py` as a reference |
| `06_privileged_account_anomaly.json` | `privileged_account_anomaly` |
| `07_geographic_anomaly.json` | `geographic_anomaly` (needs the first event to establish history) |
| `08_false_positive_mistyped_password.json` | Below-threshold failures then success — must stay LOW risk |
| `09_missing_and_malformed_fields.json` | Each entry fails validation (HTTP 422) for a different reason |

Replay a sequence file with curl:

```bash
for row in $(jq -c '.[]' sample_events/02_repeated_failed_logins.json); do
  curl -s -X POST http://localhost:8000/events \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $ELJEFE_API_KEY" \
    -d "$row"
  echo
done
```
