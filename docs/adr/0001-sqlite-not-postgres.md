# 0001: SQLite instead of Postgres

## Status
Accepted.

## Context
The system needs to persist events, a threat-intel cache, incidents, an
audit trail, and idempotency keys. Postgres is the default reach for most
teams building something like this, and it's a reasonable choice at
real production scale.

## Decision
Use SQLite (stdlib `sqlite3`), with WAL mode enabled (see [ADR 0004](0004-wal-mode-and-busy-timeout.md)).

The actual write pattern here is one process, one file, append-mostly,
at a scale (a single security team's authentication event volume) that
SQLite handles comfortably. Reaching for Postgres would mean a second
service to run, configure, back up, and secure, for a workload that
doesn't need what Postgres adds: concurrent multi-writer access,
replication, or a separate connection pool to manage. The project's own
brief explicitly warns against introducing a database "simply because
it's popular" — this is that warning applied literally.

## Consequences
- **Positive:** zero operational surface beyond a file on disk; trivial to
  back up (copy the file); nothing to provision, patch, or credential.
- **Positive:** every reviewer of this codebase can read exactly how data
  is stored by reading `app/models/db.py`, with no ORM layer translating
  intent into SQL.
- **Negative:** a true horizontally-scaled deployment (multiple backend
  instances behind a load balancer) is not supported by this design —
  SQLite is single-writer. That's a real limit, not a hidden one; it's
  listed under the README's Security limitations.
- **Negative:** no built-in replication or point-in-time recovery; a
  production deployment beyond a single team's scale would need to
  revisit this, at which point the migration path is adding a proper
  migration tool (e.g. Alembic) before changing engines — not before.
