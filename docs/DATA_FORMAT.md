# Tattletale data format

This is the contract every Tattletale version writes and the dashboard reads. The Python and
Java versions must produce the same database schema, the same data file and the same log
lines, so either one can run against the same `data/` folder (one at a time; see
[The pid file](#the-pid-file)) and the one dashboard serves both.

The generated dashboard data uses **formatVersion 2**. The SQLite database remains
**schema 1**, unchanged. These numbers are independent of the producer's `version` string;
this format change does not announce a new release or tag. Python and Java follow the same
contract below.

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
  `::`: this is a legacy wildcard-binding flag, not a reachability result. `present` is 1
  when the last accepted listener sample contained the port and 0 after an accepted sample
  no longer contained it. A failed or partial sample does not mark it absent.
- `credential_events.source` is `ps` (seen in the process list) or `log` (caught from the
  unified log).
- `startup_items.path` is a file path, or the literal `crontab -l` for the user's crontab.
  `hash` is the SHA-256 of the content, except that an accepted absent crontab uses the
  existing `none` sentinel. An accepted empty crontab hashes the empty bytes instead.
  `startup_versions.copy_path` is the saved copy.
- Retention: rows of `sightings` older than `sightings_retention_days`, and of `events` and
  `credential_events` older than `retention_days`, are deleted hourly (0 keeps them forever).
  `programs`, `listeners` and `startup_*` are never trimmed.

## The dashboard data file

`tattletale-data.js` assigns `window.TATTLETALE`, so the page can load it from disk.
This empty, newly started example is expanded for readability; the writer emits compact
JSON on one line:

```js
window.TATTLETALE = {
  "formatVersion": 2,
  "generatedAt": "2000-01-01T00:00:00Z",
  "version": "0.0.2",
  "pid": 4242,
  "collectionHealth": {
    "processes": {"lastAttempt":null,"lastSuccess":null,"status":"unknown","error":null},
    "listeners": {"lastAttempt":null,"lastSuccess":null,"status":"unknown","error":null},
    "startup": {"lastAttempt":null,"lastSuccess":null,"status":"unknown","error":null},
    "crontab": {"lastAttempt":null,"lastSuccess":null,"status":"unknown","error":null}
  },
  "map": {"programs":{},"listeners":{},"credentials":[],"startup":{}},
  "log": []
};
```

JSON is written compactly (no spaces after `,` and `:`).

| Key | Shape |
|---|---|
| `formatVersion` | integer `2`, the generated-data contract version, independent of SQLite schema and producer version |
| `generatedAt` | when the file was written; the page's Live/Stale state becomes Stale after 180 s, independently of collection health |
| `version` | the writer's version string, not the data format or SQLite schema version |
| `pid` | the writer's pid |
| `collectionHealth` | object with exactly `processes`, `listeners`, `startup`, `crontab`; each entry has the four fields below |
| `map.programs` | object keyed by exe: `firstSeen`, `lastSeen`, `user`, `firstPid`, `firstArgs`, `parent`, and, only once known, `sha256`, `size`, `signer`, `team`, `signingId` |
| `map.listeners` | object keyed by listener key: `firstSeen`, `lastSeen`, `pid`, `command`, `bindScope`, `exposed` (legacy boolean), `user`, `args`, `chain`, `present` (boolean) |
| `map.credentials` | array, oldest first, the last 500: `time`, `pid`, `user`, `exe`, `args`, `chain`, `source` |
| `map.startup` | object: path to content hash |
| `log` | the last 500 lines of `tattletale.log`, as strings |

An absent identity key means "not checked yet" (the page tests `"signer" in v`), which is
different from a present key with an empty value.

### Collection health

Every `collectionHealth` entry has exactly these fields:

| Field | Meaning |
|---|---|
| `lastAttempt` | UTC ISO-8601 second with `Z`, or null before this watcher has attempted the check |
| `lastSuccess` | UTC ISO-8601 second with `Z` for the last accepted sample in this watcher epoch, or null before one succeeds |
| `status` | `unknown` before an attempt, `ok` after an accepted sample, or `degraded` after a failed or rejected sample |
| `error` | null or a bounded generic stage/reason/exit diagnostic; never raw stderr, an exception message, observed command arguments or a path |

The four entries cover the named polling checks only. They do not certify code-signing
identity work, the unified log stream, notifications, or the watcher as a whole. Health is
current-epoch state in the generated data, not durable audit history. Each watcher restart
resets all four entries to `unknown` with null timestamps and errors, even if the database
already contains inventory. Missing or unsupported health data is also shown as unknown,
never all-clear.

An accepted sample, including legitimate empty output, advances its success timestamp.
Failed commands, decoding errors and structurally partial samples degrade the affected
check and retain its entire last-good inventory, baseline, in-memory mirrors and events.
They do not invent `UNLISTEN` or startup-removal events or consume the first successful
baseline. Retained values are **last-known**, not proof of a current observation. File
freshness is separate: a newly generated Live page can still report degraded or unknown
collection health. Polling intervals are unchanged; there is no added automatic retry.

Process collection requires both `ps` commands to succeed and their output to decode and
parse. An empty all-system process sample is degraded. Normal PID churn between the two
commands is allowed; their PID sets need not be identical.

Startup collection stages and validates the filesystem first, then attempts crontab last.
Only an accepted combined sample advances **both** startup and crontab successes. Failure
before a crontab attempt leaves the previous crontab health untouched. Rejection after a
crontab attempt degrades both entries without advancing either success, and preserves the
prior startup/crontab inventory, text, baseline and events. A successful command exit alone
is not an accepted aggregate. Inventory/event changes are staged before the database
transaction; mirrors are adopted only after commit.

New saved copies are published only after their bytes are written. An existing copy must
match the expected saved bytes; a mismatched or symbolic-link copy rejects the sample and
is left untouched for operator review. A prepared copy may remain unreferenced after a
later database rejection. No copy cleanup or automatic repair is added. If rollback itself
fails, the database connection is closed rather than reused with unknown pending state;
restarting the watcher is then necessary.

### Accepted empty command results

These are explicit source-based policies, not observations from a live host collector:

- **lsof:** exit 0 with empty output is accepted when stderr is also empty. Exit 1 is
  accepted as empty only when **both** stdout and stderr are empty. Diagnostics, other
  statuses, nonempty output with exit 1, and structurally partial output degrade the check.
  The installed `lsof(8)` DIAGNOSTICS section says exit 1 covers errors as well as failed
  searches and describes diagnostics on stderr; exit 1 by itself is not absence proof.
- **crontab:** a clean exit 0 with empty stdout is an existing empty crontab and uses
  SHA-256 of the empty bytes. Absence is accepted only with exit 1, empty stdout, and one
  anchored diagnostic line `no crontab for <username>`, optionally prefixed by `crontab: `,
  with no other diagnostics. That uses the existing `none` sentinel. An empty stderr on
  exit 1 is not accepted as absence. This narrow convention follows the ENOENT branch in
  Apple's [`list_cmd` source](https://github.com/apple-oss-distributions/cron/blob/main/crontab/crontab.c).

These checks reject detected errors and structural partial results. They cannot universally
detect a producer that silently returns well-formed but incomplete data.
The listener parser accepts file-descriptor boundaries as well as the selected process,
command and address fields: older lsof versions also emit descriptor fields for this
selection. An incomplete descriptor record rejects the whole sample. See the upstream
[field-output contract](https://github.com/lsof-org/lsof/blob/master/docs/manpage.md).

### Listener bind scope

`map.listeners[*].bindScope` is derived from the host in the existing SQLite
`listeners.address`; it adds no database column or migration. Its values are:

| Value | Host classification |
|---|---|
| `loopback` | IPv4 `127.0.0.0/8`, IPv6 loopback, or IPv4-mapped loopback, such as `127.23.4.5`, `::1`, `::ffff:127.0.0.1` |
| `wildcard` | star or an unspecified address: `*`, `0.0.0.0`, `::` |
| `non-loopback` | another valid explicit IP literal, such as `192.0.2.10`, `2001:db8::10`, or `fe80::1%fixture0` |
| `unknown` | missing or malformed host, or a name such as `localhost`; no DNS lookup is made |

Valid bracketed IPv6 forms are classified the same way. Malformed brackets, empty zone
identifiers and invalid IP literals remain unknown. The legacy `exposed` boolean continues
to mean wildcard binding only; false does not mean loopback. Neither bind scope nor that
boolean proves remote reachability, firewall behavior or network access. No network probe
is performed.

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
| `LISTEN` | a new listener without wildcard binding; its scope may be loopback, non-loopback or unknown | |
| `LISTEN!` | a new wildcard-bound listener; the retained legacy message is `EXPOSED on all interfaces ...`, not a reachability result | yes |
| `UNLISTEN` | a previously present listener is absent from an accepted sample (`stopped listening: <key>`); failed samples do not emit this | |
| `STARTUP+`, `STARTUP~`, `STARTUP-` | a startup item added, changed or removed; messages begin `added: <path> \| copy: ...`, `changed: <path> \| before: ... \| after: ...` (followed by a unified diff), `removed: <path> \| last copy: ...` | yes |
| `RETENTION` | rows trimmed by retention | |
| `NOTE` | a degraded but working state (for example no `log stream`) | |
| `ERROR` | a check failed; the watcher keeps going | |

Notifications are rate-limited to one per kind per minute. The page also understands
`CRED-LOG`, a kind older mac-watch logs used; current versions do not write it.
The existing log kinds are retained; collection health does not introduce a new event-kind
vocabulary. Startup additions, changes and removals require an accepted aggregate sample.

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
