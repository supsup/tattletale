# Synthetic heartbeat and review checks

These controls use temporary SQLite databases, fake command results, and fake stream children.
They do not launch a watcher, a real `log stream`, or a host process/startup collector. Java
requires JDK 25 (`JAVA_HOME`) and the existing `/usr/bin/sqlite3` protocol. The jar-only runner
does not build a native image. Run only in an admitted machine-execution window.

Create a fresh receipt directory, then run from the repository root:

```sh
receipts=$(mktemp -d /tmp/tattletale-coverage.XXXXXX)
python3 tests/run_python_health_tests.py --suite coverage \
  --xml "$receipts/python-coverage.xml" --parity-output "$receipts/python-coverage.json"
sh tests/run_java_coverage_tests.sh --xml "$receipts/java-coverage.xml" \
  --scratch "$receipts/java-fixtures" --parity-output "$receipts/java-coverage.json"
python3 tests/compare_coverage_parity.py \
  "$receipts/python-coverage.json" "$receipts/java-coverage.json"
```

Expected: both producer suites exit 0, each XML reports zero failures/errors/skips, and the
comparison reports `dataComparison: equal`, 43 coverage cases and 15 stream cases, with the
reported census derived from the fixture arrays. The
comparison validates the full declared case census/expected outputs, not just equality
between possibly incomplete artifacts. Its `producerExecutionCertified: false` is deliberate:
fresh execution receipts and successful suite exits establish execution, not JSON equality.
The Python suite also verifies that missing/duplicate cases, a false QUIET for no heartbeats,
boolean counts and a future artifact version make that comparator fail.

The producer controls exercise real poll commit methods with fake sources: healthy-empty
counts, failed/partial samples, independent startup/crontab errors, recovery, retained
inventory, and an injected success-heartbeat failure that must roll back inventory too.
Stream controls cover idle-worker pulses, final buffered records, terminal degradation,
and delayed restart only after the previous child is cleaned up. Shared parser cases cover
empty/live/ended/truncated/malformed/duplicate-field/invalid-UTF8 records, raw tab/CR rejection,
signed Unicode-escape rejection, and a valid escaped-control positive. No process-list
fallback can create a keychain heartbeat.

Java reader controls distinguish a genuinely idle pipe from closed stdout with a still-live
child, inject read failure/unexpected interruption, and prove bounded backpressure and
cleanup before restart. An unconfirmed live child retains ownership and prevents a second
start. Python injects the same closed-stdout/live-child edge with an immediate fake wait
timeout, proving degraded evidence, termination/close, and no overlapping restart without
real processes or delay. Raw unescaped controls were already rejected by the parser; the strict-only repair
rejects signed Unicode escapes while retaining permissive `Json.parse` compatibility.

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
ordering, and reverse in-window insertion order. These controls preserve the shared 43+15
case contract while checking bounded historical reads and chronological boundary selection.

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
