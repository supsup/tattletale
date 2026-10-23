# Tattletale data format

This is the contract every Tattletale version writes and the dashboard reads. The Python and
Java versions must produce the same database schema, the same data file and the same log
lines, so either one can run against the same `data/` folder (one at a time; see
[The pid file](#the-pid-file)) and the one dashboard serves both.

Format version: **schema 1**, written by Tattletale 0.0.2. The reference implementation is
`python/tattletale.py`; where this page and that file disagree, the file wins and this page is
the bug.

## The data folder

Both versions default to `<repo>/data/`. Everything in it is machine data and is git-ignored.

| File | What it is |
|---|---|
| `tattletale.db` | the SQLite database (WAL mode, so also `-wal` and `-shm` while running), mode 0600 |
| `tattletale.log` | the human-readable log, one line per event; rotated to `tattletale.log.1`, `.2`, ... |
| `tattletale-data.js` | the dashboard's data, rewritten about once a minute, atomically (temp file and rename) |
| `tattletale.html` | a copy of `dashboard/tattletale.html`, refreshed on start whenever its bytes differ |
| `tattletale.pid` | the running watcher's pid |
| `startup-snapshots/` | a copy of every version of every startup item seen |
| `tattletale-map.json` | optional; an old mac-watch JSON map, imported once into an empty database, never written |

Settings live in `<repo>/tattletale.env`, shared by both versions.

## Database (schema 1)

The schema, exactly as created (`CREATE ... IF NOT EXISTS`):

```sql
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS programs(
  exe TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, user TEXT, first_pid INTEGER,
  first_args TEXT, parent TEXT, sha256 TEXT, size INTEGER, signer TEXT, team TEXT,
  signing_id TEXT);
CREATE TABLE IF NOT EXISTS sightings(
  id INTEGER PRIMARY KEY, time TEXT, pid INTEGER, exe TEXT, user TEXT, args TEXT, chain TEXT);
CREATE TABLE IF NOT EXISTS listeners(
  key TEXT PRIMARY KEY, exe TEXT, address TEXT, port INTEGER, command TEXT, pid INTEGER,
  user TEXT, args TEXT, chain TEXT, exposed INTEGER, present INTEGER, first_seen TEXT,
  last_seen TEXT);
CREATE TABLE IF NOT EXISTS credential_events(
  id INTEGER PRIMARY KEY, time TEXT, source TEXT, pid INTEGER, user TEXT, exe TEXT, args TEXT,
  chain TEXT);
CREATE TABLE IF NOT EXISTS startup_items(path TEXT PRIMARY KEY, hash TEXT, last_checked TEXT);
CREATE TABLE IF NOT EXISTS startup_versions(
  id INTEGER PRIMARY KEY, path TEXT, hash TEXT, copy_path TEXT, seen_at TEXT);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, time TEXT, kind TEXT, message TEXT);
CREATE INDEX IF NOT EXISTS programs_first_seen ON programs(first_seen);
CREATE INDEX IF NOT EXISTS sightings_time ON sightings(time);
CREATE INDEX IF NOT EXISTS sightings_exe ON sightings(exe);
CREATE INDEX IF NOT EXISTS listeners_first_seen ON listeners(first_seen);
CREATE INDEX IF NOT EXISTS credential_events_time ON credential_events(time);
CREATE INDEX IF NOT EXISTS startup_versions_seen_at ON startup_versions(seen_at);
CREATE INDEX IF NOT EXISTS events_time ON events(time);
```

Rules:

- `schema_version` holds one row. A database whose version is higher than the watcher knows
  is refused at start, never written.
- Every time is UTC ISO-8601 to the second with a `Z` (`2026-10-23T15:02:28Z`).
- `programs.exe` is the full executable path (spaces kept). Identity columns (`sha256`, `size`,
  `signer`, `team`, `signing_id`) are NULL until the identity worker has read the file.
  `signer` is the first codesign `Authority=` line (for example
  `Developer ID Application: Example Inc (ABCDE12345)`); `adhoc` for an ad-hoc signature;
  `signed, no authority` when codesign reports a signature with no authority and no ad-hoc
  marker; and text starting `unsigned or unreadable: ` when codesign fails. `sha256` holds
  `unreadable: <reason>` when the file could not be read.
- `listeners.key` is `<exe> <address>` with address `host:port` as lsof prints it (`*:8000`,
  `127.0.0.1:5173`, `[::1]:631`). `exposed` is 1 when the host is `*`, `0.0.0.0`, `[::]` or
  `::`. `present` is 1 while the port is listening and 0 after it stopped.
- `credential_events.source` is `ps` (seen in the process list) or `log` (caught from the
  unified log).
- `startup_items.path` is a file path, or the literal `crontab -l` for the user's crontab.
  `hash` is the SHA-256 of the content. `startup_versions.copy_path` is the saved copy.
- Retention: rows of `sightings` older than `sightings_retention_days`, and of `events` and
  `credential_events` older than `retention_days`, are deleted hourly (0 keeps them forever).
  `programs`, `listeners` and `startup_*` are never trimmed.

## The dashboard data file

`tattletale-data.js` is one line of JavaScript, so the page can load it from disk:

```js
window.TATTLETALE = {"generatedAt":"...","version":"0.0.2","pid":4242,"map":{...},"log":[...]};
```

JSON is written compactly (no spaces after `,` and `:`).

| Key | Shape |
|---|---|
| `generatedAt` | when the file was written (the page shows Stale after 180 s) |
| `version` | the writer's version |
| `pid` | the writer's pid |
| `map.programs` | object keyed by exe: `firstSeen`, `lastSeen`, `user`, `firstPid`, `firstArgs`, `parent`, and, only once known, `sha256`, `size`, `signer`, `team`, `signingId` |
| `map.listeners` | object keyed by listener key: `firstSeen`, `lastSeen`, `pid`, `command`, `exposed` (boolean), `user`, `args`, `chain`, `present` (boolean) |
| `map.credentials` | array, oldest first, the last 500: `time`, `pid`, `user`, `exe`, `args`, `chain`, `source` |
| `map.startup` | object: path to content hash |
| `log` | the last 500 lines of `tattletale.log`, as strings |

An absent identity key means "not checked yet" (the page tests `"signer" in v`), which is
different from a present key with an empty value.

## Log lines

```
<time>  <KIND padded to 9> <message>
```

Two spaces after the time; the kind is left-aligned in 9 characters, then one space. Each line
is also stored in `events(time, kind, message)`.

| Kind | Meaning | Notifies |
|---|---|---|
| `START`, `STOP` | the watcher started (`tattletale <version> pid <pid> db <path>`) or stopped | |
| `BASELINE` | first-run inventory: `programs: N recorded`, `listeners: ...`, `startup items: ...` | |
| `IMPORT` | the one-time JSON map import, with counts | |
| `NEW-PROG` | an executable ran for the first time after the baseline | |
| `IDENTITY` | its hash and signer, once read | |
| `UNSIGNED` | a new program with no named signer (unsigned or ad-hoc) | yes |
| `CREDENTIAL` | a credential helper seen in the process list | yes |
| `CRED-NET` | a git network helper caught from the unified log | yes |
| `PASSWORD` | the macOS password dialog (SecurityAgent), from the unified log | yes |
| `LISTEN` | a new listener on loopback | |
| `LISTEN!` | a new listener on all interfaces (`EXPOSED on all interfaces ...`) | yes |
| `UNLISTEN` | a listener stopped (`stopped listening: <key>`) | |
| `STARTUP+`, `STARTUP~`, `STARTUP-` | a startup item added, changed or removed; messages begin `added: <path> \| copy: ...`, `changed: <path> \| before: ... \| after: ...` (followed by a unified diff), `removed: <path> \| last copy: ...` | yes |
| `RETENTION` | rows trimmed by retention | |
| `NOTE` | a degraded but working state (for example no `log stream`) | |
| `ERROR` | a check failed; the watcher keeps going | |

Notifications are rate-limited to one per kind per minute. The page also understands
`CRED-LOG`, a kind older mac-watch logs used; current versions do not write it.

## Settings

One name each, usable three ways; highest priority first:

1. a flag: `--keep-logs 5` (booleans also have `--no-<name>`)
2. an environment variable: `TATTLETALE_KEEP_LOGS=5`
3. a line in `<repo>/tattletale.env` (or `--config PATH`): `TATTLETALE_KEEP_LOGS=5`

Unknown names and malformed values are refused, never ignored. Names, types and defaults:
`log`, `db`, `map` (paths in `data/`), `process_interval` (3 s), `listen_interval` (30 s),
`startup_interval` (300 s), `notify` (true), `rotate_mb` (20), `keep_logs` (3),
`extra_startup` (none; colon-separated in env and file), `retention_days` (30),
`sightings_retention_days` (7).

## The pid file

`tattletale.pid` sits next to the database and holds the watcher's pid. A start refuses while
a live Tattletale (either version) holds it, takes over a file whose pid is gone or belongs to
another program, and removes the file on a clean stop. One database, one watcher.
