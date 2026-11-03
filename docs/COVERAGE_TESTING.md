# Synthetic heartbeat and review checks

These controls use temporary SQLite databases, fake command results, and fake stream children.
Some controls drive Python's actual `Watch.run` schedule with fake threads and mocked host
calls; they launch no daemon, real `log stream`, or host process/startup collector. Java
requires JDK 25 (`JAVA_HOME`) and the existing `/usr/bin/sqlite3` protocol. The jar-only runner
does not build a native image. XML comes from the repository's custom fixture runners, not
Gradle. Run only in an admitted machine-execution window.

Create a fresh receipt directory, then run from the repository root:

```sh
receipts=$(mktemp -d /tmp/tattletale-coverage.XXXXXX)
python3 tests/run_python_health_tests.py --suite coverage \
  --xml "$receipts/python-coverage.xml" --parity-output "$receipts/python-coverage.json"
sh tests/run_java_coverage_tests.sh --xml "$receipts/java-coverage.xml" \
  --scratch "$receipts/java-fixtures" --parity-output "$receipts/java-coverage.json"
python3 tests/compare_coverage_parity.py \
  "$receipts/python-coverage.json" "$receipts/java-coverage.json"
python3 -m unittest discover -s tests -p test_review_regressions.py -v
python3 -m unittest discover -s tests -p test_review_round3.py -v
```

Expected: both producer suites exit 0, each XML reports zero failures/errors/skips, and the
comparison reports `dataComparison: equal`, 63 reader cases, 20 framing cases, 5 poll-producer
cases, 20 invalid-interval cases, and 9 worker cases comparing 44 actual emitted heartbeat
rows. All reported counts come from fixture arrays. The
comparison validates the full declared case census/expected outputs, not just equality
between possibly incomplete artifacts. Its `producerExecutionCertified: false` is deliberate:
fresh execution receipts and successful suite exits establish execution, not JSON equality.
The Python suite also verifies that missing/duplicate cases, a false QUIET for no heartbeats,
boolean counts, a future artifact version, a wrong emitted process cadence, and independent
mutations of a terminal row's error, stop disposition, or retained worker failure make that
comparator fail. The producer artifact requires `producerResults`; an old reader-only
artifact cannot certify the repaired producer paths.

The published 13 regressions remain separate and unchanged: seven deciding cases and six
positive controls. The repaired candidate should pass all 13. They cover the hourly
producer/reader mismatch, irrelevant old bad payload, actual default five-second lsof inside
the serial Python loop, emitted default/fractional cadence, banner/stderr separation and
unsupported-style restart. A 15-second process gap and malformed required anchor must still
refuse. Historical RED/GREEN receipts do not establish that a later candidate ran these tests.

The producer controls query all seven fields from rows emitted by real poll commit methods,
then compare with fixed expected JSON for default, hourly, maximum and fractional settings,
plus failure/recovery. Invalid/nonfinite intervals must fail before directory/DB creation.
The independent expectations are not calculated by producer cadence helpers. Explicit daily
startup (86400) and quarter-second process (0.25) settings are refused by both constructors
before filesystem creation; Python CLI controls also prove refusal before migration, watcher
construction or signal-handler registration. Controls include healthy-empty
counts, failed/partial samples, independent startup/crontab errors, recovery, retained
inventory, and an injected success-heartbeat failure that must roll back inventory too.
Stream controls cover idle-worker pulses, final buffered records, terminal degradation,
and delayed restart only after the previous child is cleaned up. Shared parser cases cover
empty/live/ended/truncated/malformed/duplicate-field/invalid-UTF8 records, raw tab/CR rejection,
signed Unicode-escape rejection, and a valid escaped-control positive. No process-list
fallback can create a keychain heartbeat.

Java reader controls distinguish a genuinely idle pipe from closed stdout with a still-live
child, inject read failure/unexpected interruption, and prove bounded backpressure and
cleanup before restart. Stderr is a separate bounded drain, not a JSON record source.
The diagnostic flood is generated from a fixture repeat count (196625 bytes, more than three
64-KiB chunks), and verifies a stored stdout record and pulse while diagnostic chunks remain
ready, full draining, and 4-KiB retention. A separate fixed-dead-child deadline control proves
continued descendant diagnostics cannot renew the drain forever. An unconfirmed live child or pipe close retains ownership and prevents a second
start. Python injects the same closed-stdout/live-child edge with an immediate fake wait
timeout, proving degraded evidence, termination/close, and no overlapping restart without
real processes or delay. Raw unescaped controls were already rejected by the parser; the strict-only repair
rejects signed Unicode escapes while retaining permissive `Json.parse` compatibility.

Shared terminal worker cases call each producer's real stream method and compare actual
seven-field database rows, `stopRequested`, retained `workerFailure`, retry eligibility,
credential-event count and retained diagnostic size against independent literals. A dead
child with continuously ready diagnostics must reach `keychain-reader-stalled`, request
stop, retain that failure and decline retry after confirmed cleanup. Both pipes at EOF with
a still-live child must report `keychain-closed`, terminate/close the owned child and decline
retry. These single terminal rows use a fixed independent UTC observation time; synthetic
monotonic clocks exercise the drain deadline without making seam-call counts part of parity.
Mocked Python `Watch.run` failures verify clean stderr and exit 1 for `keychain-cleanup` and
`keychain-reader-stalled`, without running a watcher or registering real signal handlers.

Read controls include all five missing collectors, internal/start/end silence, exact grace
boundaries, fresh recovery windows, legacy/future/ambiguous schemas, malformed evidence,
expired events, invalid windows, CLI conflicts, no missing-DB creation, static file-byte
nonmutation, and committed active-WAL visibility. The WAL fixture establishes a reader
snapshot, commits a new writer event, proves the old snapshot remains internally consistent,
then proves a new review sees that event without changing writer logical state.

Additional old-history controls span four 512-row pages, including the minimum and maximum
signed SQLite rowids and large old event messages. They verify exact traversal/counts and
refusal for malformed or unsupported evidence in the final out-of-window page. Anchor
controls insert older failures/successes after newer samples, exercise equal-time rowid
ordering, and reverse in-window insertion order. Additional cases check old bad payload
supersession, malformed required anchors, exact-start supersession, both directions of mixed
cadences, tight five-second bounds, and process cadence-six end freshness at 14 versus 15
seconds. Unknown protocol/collector/unlocatable time and future evidence retain conservative
refusal. Malformed event evidence is still validated globally.
Startup and listener reader cases independently accept exactly 7200 seconds and refuse
7200.0001; keychain-only bounds cannot stand in for these generic cadence checks.

Existing assertions change only where policy changes: default emitted process cadence 3→6,
the generic out-of-range cadence input 3601→7201, and an explicit check that keychain cadence
3603 remains invalid. Existing pipe mocks now provide distinct stderr descriptors and EOF;
the Java fake wait no longer fabricates child termination. The 13 published regression
assertions and file bytes remain unchanged. The local Python dead-child assertion changes
`keychain-io` to `keychain-reader-stalled` and adds stop/failure checks to match the shared
contract. The local closed-pipe assertion now requires exactly `keychain-closed`, no stop
request and no retained worker failure; its existing degradation/cleanup checks remain.

Child/pipe cleanup proof is distinct from full parent-worker shutdown. Python retains its
existing two-second worker join without a subsequent alive check; this amendment does not
claim complete Python/Java worker-lifecycle parity. That remaining parent-shutdown boundary
requires a separate change, beyond these child/pipe controls.

The following items remain OPEN, owned by Lattice and tracked in the filed follow-up
`31c3bea5-9dbc-4cc2-9116-8e84cfef737d` (coverage recovery and operational followups). The
follow-up is backlog work, not an activated part of this amendment.

- OPEN L2 — Owner: Lattice; follow-up: `31c3bea5-9dbc-4cc2-9116-8e84cfef737d`.
  An exit-0 child with zero valid records can still retry every ten seconds. Next proof:
  inject repeated clean zero-record exits and assert the chosen bounded retry/diagnostic
  policy without weakening the zero-valid-record/nonzero-exit no-restart control.
- OPEN L3 — Owner: Lattice; follow-up: `31c3bea5-9dbc-4cc2-9116-8e84cfef737d`.
  An older writer can prune events without advancing the newer event floor under retained
  heartbeats. Next proof: simulate legacy pruning during otherwise healthy coverage and
  require refusal for the lost interval before selecting a writer-compatibility policy.
- OPEN L4 — Owner: Lattice; follow-up: `31c3bea5-9dbc-4cc2-9116-8e84cfef737d`.
  A database failure while recording a degraded pulse can stop Java while Python continues
  after reporting it. Next proof: inject the same recovered and unrecoverable degraded-pulse
  write failures in both producers and compare retained evidence and stop disposition.
- OPEN L5 — Owner: Lattice; follow-up: `31c3bea5-9dbc-4cc2-9116-8e84cfef737d`.
  One transient credential-event insertion failure stops the watcher even if its database
  connection recovered. Next proof: inject a recovered credential transaction failure and
  assert rollback, degraded evidence and the selected stop/recovery policy in both producers.

N3 remains the accepted conservative policy: malformed or future timestamps refuse reviews
globally, including when outside the requested window. Its recovery choice remains OPEN in
the same Lattice-owned follow-up; the next proof must cover a forward clock jump followed
by a healthy window and retention without treating ambiguous evidence as quiet.

Separate residuals in that follow-up remain open: the fixed dead-child deadline may discard
slow final buffered records (the window degrades); the retained 4-KiB diagnostic prefix is
not reported to users; and Python's two-second parent join has no alive check. Next proofs
need slow final-drain inputs, diagnostic reporting controls and a worker surviving the join,
respectively. Java's serial-loop fixture calls poll methods and advances a synthetic clock;
it does not execute actual `Watch.run`, so full scheduler parity remains unproved. Python's
clean CLI exit still uses the internal `FatalDatabaseError` name for non-database stream
failures; exception-type cleanup is also deferred. None of these controls proves complete
worker-lifecycle parity.

Run existing health/dashboard regression controls separately, using fresh output paths:

```sh
python3 tests/run_python_health_tests.py --xml "$receipts/python-health.xml" \
  --parity-output "$receipts/python-health.json"
sh tests/run_java_health_tests.sh --xml "$receipts/java-health.xml" \
  --scratch "$receipts/java-health-fixtures" --parity-output "$receipts/java-health.json"
python3 tests/compare_health_parity.py "$receipts/python-health.json" "$receipts/java-health.json"
node --test tests/test_dashboard_health.js
```

Review is a sampled-coverage decision, so no live personal-data collection is needed for
these acceptance controls. The [data contract](DATA_FORMAT.md#durable-heartbeats-and-read-only-review)
documents the exact review CLI, result shape, cadence limits and freshness rules. This
document describes proposed checks; it is not evidence that a particular candidate ran them.
