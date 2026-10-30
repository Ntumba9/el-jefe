# 0005: Activepieces for orchestration, not a custom workflow engine

## Status
Accepted.

## Context
The system needs to: receive an event, call the detection backend, branch
on the result, notify or request human approval, and route the decision
back. That's a small, fixed workflow — but it still needs a trigger
(webhook), conditional branching, a human-in-the-loop pause/resume
primitive, and a notification integration (Telegram). Building that from
scratch means writing and maintaining a webhook receiver, a state machine
for the pause/resume semantics, and direct Telegram Bot API integration
code, none of which is the actual detection/security logic this project
exists to demonstrate.

## Decision
Use Activepieces (the project brief's original choice) as the
orchestration layer, and keep it *thin*: a webhook trigger, one router
step, and calls out to the FastAPI backend for every decision that
requires logic. Verified concretely, not just assumed: pieces and
actions were looked up against the live Activepieces catalog
(`ap_research_pieces`) before being referenced in documentation, and a
flow was built and test-run against real detection-engine output via the
Activepieces API before being described as working.

Specifically, `@activepieces/piece-telegram-bot`'s
`request_approval_message` action was chosen over the legacy
`@activepieces/piece-approval` piece because it combines "deliver the
prompt" and "wait for the response" in one step, with no separate
connection-less approval-link piece needed.

## Consequences
- **Positive:** the pause/resume-on-human-approval primitive, webhook
  signature verification, and Telegram integration are all pieces of
  infrastructure EL JEFE gets for free and doesn't have to secure,
  test, or maintain itself.
- **Positive:** the split keeps the codebase's own test suite focused on
  what's actually novel here (detection, scoring, correlation) rather
  than diluting it with orchestration-framework tests.
- **Negative:** the fully-designed production flow
  (`activepieces/workflow-documentation/el-jefe-flow.md`) depends on a
  publicly reachable backend URL and a live Telegram bot connection,
  neither of which exists in every environment this project might be
  reviewed in. The live demo flow built to prove the orchestration layer
  works is deliberately a reduced version (webhook → router → two CODE
  steps, no backend call, no Telegram) for exactly that reason — it's
  documented as a demo, not presented as the production flow.
- **Negative:** Activepieces is a dependency this project doesn't
  control the uptime or API stability of. Acceptable here since it's the
  orchestration layer, not the detection logic — a different
  orchestrator could replace it without touching `app/` at all.
