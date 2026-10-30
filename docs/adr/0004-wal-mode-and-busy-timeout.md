# 0004: SQLite WAL mode with a busy timeout

## Status
Accepted.

## Context
SQLite's default journal mode (rollback journal) takes an exclusive lock
for the duration of a write transaction, which blocks readers until the
writer commits. Under the original design (one FastAPI process, synchronous
request handlers, each opening its own connection per request) a `GET
/incidents/{id}` arriving while `POST /events` is mid-transaction would
block, and under enough concurrent webhook deliveries (e.g. from
Activepieces retrying) that queuing becomes visible latency.

## Decision
`app/models/db.py::get_raw_connection()` sets two pragmas on every
connection:
```sql
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
```
WAL (write-ahead logging) lets readers proceed against the last
committed state while a writer is active, instead of blocking. The busy
timeout means that if two writers do contend, the second one waits up to
5 seconds and retries internally rather than immediately raising
`database is locked`.

## Consequences
- **Positive:** reads no longer block on writes; verified live (see the
  project's git history) by connecting directly and checking
  `PRAGMA journal_mode` returns `wal`.
- **Positive:** two extra lines, no new dependency, no schema change.
- **Negative:** WAL requires real POSIX/Win32 file locking semantics.
  It can misbehave on a network filesystem or certain cloud-sync folders
  (documented in the README's Security limitations) — this matters in
  practice for this specific project, since local development happens in
  a OneDrive-synced folder; it has worked without issue there, but a
  production deployment should set `ELJEFE_DB_PATH` to local disk, not
  a synced or network path.
- **Negative:** WAL mode creates `-wal` and `-shm` sidecar files next to
  the database file, which `.gitignore` now accounts for.
