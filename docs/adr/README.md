# Architecture Decision Records

Short records of the decisions in EL JEFE that weren't obvious, that someone
might reasonably ask "why didn't you just use X instead." Each one follows
Michael Nygard's format: Status, Context, Decision, Consequences.

These aren't written after the fact to justify what already exists — they're
the actual reasoning behind each choice, several of which were explicitly
pushed back on and scoped down during the project's own engineering
assessment (see the ADR text for which).

- [0001: SQLite instead of Postgres](0001-sqlite-not-postgres.md)
- [0002: Scoped API keys instead of full RBAC](0002-scoped-api-keys-not-rbac.md)
- [0003: Response actions are simulation-only by construction](0003-simulation-only-response-actions.md)
- [0004: SQLite WAL mode with a busy timeout](0004-wal-mode-and-busy-timeout.md)
- [0005: Activepieces for orchestration, not a custom workflow engine](0005-activepieces-for-orchestration.md)
