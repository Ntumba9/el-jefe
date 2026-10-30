# EL JEFE Activepieces Flow

This flow is the orchestration layer described in the project README. It
does not implement any detection or scoring logic itself — it forwards
events to the FastAPI backend, branches on the risk band the backend
returns, and gates high-risk incidents behind a Telegram approval.

Every piece/action name below was verified against the live Activepieces
piece catalog (not assumed) before being written down here.

## Flow steps

| # | Piece | Action / Trigger | Configuration |
|---|---|---|---|
| Trigger | `@activepieces/piece-webhook` | `catch_webhook` | Authentication: HMAC signature over the raw body, using a shared secret you set in Activepieces and in your identity provider / event source. Rejects unsigned or badly-signed requests before the flow runs. |
| Step 1 | `@activepieces/piece-http` | `send_request` | `POST {{ELJEFE_BASE_URL}}/events`, header `X-API-Key: {{ELJEFE_API_KEY}}`, body = `{{trigger['output'].body}}` (pass the webhook payload straight through) |
| Step 2 | Router (core branching) | — | Branch on `{{step_1['output'].body.risk_band}}`: route A = `LOW` or `MEDIUM`, route B = `HIGH` or `CRITICAL` |
| Step 3A | `@activepieces/piece-telegram-bot` | `send_text_message` | chat_id = your SOC notification chat; text = a short FYI built from `{{step_1['output'].body.risk_score}}` and `{{step_1['output'].body.findings}}` |
| Step 3B | `@activepieces/piece-telegram-bot` | `request_approval_message` | chat_id = your on-call admin chat; message text includes `{{step_1['output'].body.incident_id}}`, the risk score/band, and the finding descriptions. This action itself pauses the flow until Approve/Disapprove is clicked — no separate Delay or Approval piece is needed. |
| Step 4 | `@activepieces/piece-http` | `send_request` | `POST {{ELJEFE_BASE_URL}}/incidents/{{step_1['output'].body.incident_id}}/decision`, header `X-API-Key: {{ELJEFE_API_KEY}}`, body: `{"approved": {{step_3b['output'].approved}}, "decided_by": "{{step_3b['output'].respondedBy}}", "response_action": "disable_account"}` (pick the response action appropriate to the finding, or expose it as a Telegram poll if you want the admin to choose it — see "Extending" below) |

Route A (LOW/MEDIUM) ends at step 3A: no incident was created by the
backend for those bands (see `app/incidents/store.py`), so there is
nothing to decide on.

## Why this shape

- Activepieces never scores or stores anything. All of that is in the
  FastAPI app, which is unit-tested; the flow is just HTTP calls plus one
  human gate, which is what's realistic to show working end-to-end
  without needing a second persistence layer inside Activepieces.
- `request_approval_message` was chosen over the legacy `@activepieces/piece-approval`
  `wait_for_approval` action specifically because it both *delivers* the
  prompt and *waits* in a single step, and it has no connection
  requirement for the generic legacy piece — it uses your Telegram bot
  connection directly.
- Containment is never executed by Activepieces or by the backend: step 4
  always lands in `app/incidents/response.py`, which only ever returns a
  `[SIMULATED] ...` string and writes it to the audit trail.

## Setting it up

1. In Activepieces, create a connection for `Telegram Bot` using a bot
   token from `@BotFather`, and note the chat ID(s) you want notifications
   and approvals sent to.
2. Create the flow with the steps above, in order.
3. Set `ELJEFE_BASE_URL` (e.g. `http://localhost:8000` for local testing,
   or your deployed URL) and `ELJEFE_API_KEY` (matching your `.env`) as
   flow-level or connection variables.
4. Point your event source (or `sample_events/`, replayed via curl) at the
   webhook trigger's URL instead of directly at `/events`, so the full
   path — webhook → backend → Telegram → decision — is exercised.
5. Test with Activepieces' built-in flow tester before publishing.

## Extending

- To let the admin pick *which* response action to take (instead of a
  fixed one), send a Telegram poll (`send_poll`) with the four actions
  from `app/incidents/response.py` as options before step 3B, and read the
  chosen option in step 4's body instead of a hardcoded string.
- To notify on repeated findings for the same account across incidents,
  add a `Tables` lookup/write step keyed by username between steps 1 and
  2 — deliberately left out here, since the project's audit trail (in
  SQLite, via the FastAPI app) already is that system of record, and
  duplicating it in Activepieces Tables would be the "unnecessary
  database architecture" the project brief asks to avoid.
