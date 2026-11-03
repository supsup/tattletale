"""Heartbeat/review fault controls. All inputs are synthetic; no host collector is run."""
import argparse
import contextlib
import copy
import datetime as dt
import io
import json
import pathlib
import sqlite3
import sys
import tempfile
import unittest
import types
from unittest import mock

import test_collection_health as health
import compare_coverage_parity as parity
import test_review_regressions as regressions
TT, LSOF, CRON = health.TT, health.LSOF, health.CRON

FIXTURE = json.loads((pathlib.Path(__file__).parent / 'fixtures/coverage.json').read_text())
T0 = FIXTURE['since']
RESULTS = []
PRODUCER_RESULTS = []


def stamp(second):
    return (dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=second)).strftime('%Y-%m-%dT%H:%M:%SZ')


def seed(conn):
    conn.executescript(TT.SCHEMA)
    conn.execute('INSERT INTO schema_version VALUES (1)')
    conn.execute('INSERT INTO heartbeat_schema VALUES (1)')
    for key in TT.COLLECTORS:
        for second in range(0, 31, 5):
            conn.execute('INSERT INTO collector_heartbeats VALUES (NULL,1,?,?,0,\'ok\',NULL,3)', (key, stamp(second)))


def mutate(conn, case):
    op = case['op']
    if op == 'none':
        return
    if op == 'events':
        for at in ['1999-12-31T23:59:59Z', stamp(0), stamp(15), stamp(30), stamp(31)]:
            conn.execute('INSERT INTO events VALUES (NULL,?,\'FIXTURE\',\'synthetic\')', (at,))
    elif op == 'empty': conn.execute('DELETE FROM collector_heartbeats')
    elif op == 'missing': conn.execute('DELETE FROM collector_heartbeats WHERE collector=?', (case['target'],))
    elif op in ('failure', 'partial', 'recovery', 'anchor'):
        key, error, at = {'failure': ('listeners', 'lsof-command', 10), 'partial': ('startup', 'startup-unreadable', 10),
                          'recovery': ('keychain', 'keychain-ended', 5), 'anchor': ('keychain', 'keychain-ended', 0)}[op]
        conn.execute("UPDATE collector_heartbeats SET status='degraded',error=?,observed_count=NULL WHERE collector=? AND time=?", (error, key, stamp(at)))
    elif op in ('early', 'gap', 'end', 'start'):
        where = {'early': "collector='keychain' AND time>'" + stamp(0) + "'",
                 'gap': "collector='processes' AND time IN ('" + "','".join(stamp(s) for s in (10, 15, 20)) + "')",
                 'end': "collector='keychain' AND time>='" + stamp(25) + "'",
                 'start': "collector='startup' AND time='" + stamp(0) + "'"}[op]
        conn.execute('DELETE FROM collector_heartbeats WHERE ' + where)
    elif op == 'legacy': conn.execute('DROP TABLE collector_heartbeats')
    elif op == 'schema': conn.execute('UPDATE schema_version SET version=?', (case['value'],))
    elif op == 'duplicate-schema': conn.execute('INSERT INTO schema_version VALUES (1)')
    elif op == 'extension': conn.execute('UPDATE heartbeat_schema SET version=2')
    elif op == 'mutate':
        assert case['field'] in {'version', 'collector', 'observed_count', 'status', 'error', 'time', 'cadence_seconds'}
        conn.execute('UPDATE collector_heartbeats SET ' + case['field'] + "=? WHERE collector='keychain' AND time=?", (case['value'], stamp(0)))
    elif op == 'floor': conn.execute("INSERT INTO coverage_metadata VALUES ('event_floor',?)", (case['value'],))
    elif op == 'bad-event': conn.execute("INSERT INTO events VALUES (NULL,?,'FIXTURE','synthetic')", (case['value'],))
    elif op == 'cadence': conn.execute('UPDATE collector_heartbeats SET cadence_seconds=? WHERE collector=?', (case['value'], case['target']))
    elif op in ('old-payload', 'required-payload', 'later-payload'):
        at = {'old-payload': -1, 'required-payload': 1, 'later-payload': 31}[op]
        conn.execute("INSERT INTO collector_heartbeats VALUES (NULL,1,'startup',?,0,'ok',NULL,7201)", (stamp(at),))
    elif op in ('mixed-gap', 'mixed-reverse-gap', 'tight-gap'):
        conn.execute("DELETE FROM collector_heartbeats WHERE collector='processes'")
        if op == 'tight-gap':
            samples = [(second, 1) for second in (0, case['value'], 10, 15, 20, 25, 30)]
        else:
            first, later = (3, 6) if op == 'mixed-gap' else (6, 3)
            samples = [(0, first)] + [(second, later) for second in (case['value'], 15, 22, 30)]
        for second, cadence in samples:
            conn.execute("INSERT INTO collector_heartbeats VALUES (NULL,1,'processes',?,0,'ok',NULL,?)", (stamp(second), cadence))
    elif op == 'process-end':
        conn.execute("UPDATE collector_heartbeats SET cadence_seconds=6 WHERE collector='processes'")
        for key in ('listeners', 'startup', 'crontab', 'keychain'):
            for at in (35, 40, 45): conn.execute("INSERT INTO collector_heartbeats VALUES (NULL,1,?,?,0,'ok',NULL,3)", (key, stamp(at)))
    elif op == 'anchor-age':
        conn.execute("DELETE FROM collector_heartbeats WHERE collector='startup' AND time<?", (stamp(2),))
        conn.execute("INSERT INTO collector_heartbeats VALUES (NULL,1,'startup',?,0,'ok',NULL,3)", (stamp(2 - case['value']),))
    else: raise AssertionError('unhandled fixture operation')


def normalized_issues(result):
    return [(row['collector'] or '-') + '/' + row['reason'] for row in result['issues']]


def snapshot_guard(conn, since=None):
    """Use the production guard in one owned read snapshot; setup writes happen outside it."""
    conn.commit()
    conn.execute('PRAGMA query_only=ON')
    conn.execute('BEGIN')
    try:
        return TT.coverage_guard(conn, since or T0, FIXTURE['until'], FIXTURE['now'])
    finally:
        conn.execute('ROLLBACK')
        conn.execute('PRAGMA query_only=OFF')


class CoverageTests(unittest.TestCase):
    def test_review_hud_conflict_is_usage_error_before_any_read_or_write(self):
        output, error = io.StringIO(), io.StringIO()
        flags = ['fixture', '--review', '--hud', '--since', T0, '--until', FIXTURE['until']]
        with mock.patch.object(TT.sys, 'argv', flags), \
                mock.patch.object(TT, 'resolve_settings', side_effect=AssertionError('settings must not be read')), \
                mock.patch.object(TT, 'review', side_effect=AssertionError('review must not run')), \
                mock.patch.object(TT, 'hud_main', side_effect=AssertionError('HUD must not run')), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            with self.assertRaises(SystemExit) as raised: TT.main()
        self.assertEqual(raised.exception.code, 2)
        self.assertIn('--review and --hud are mutually exclusive', error.getvalue())
        self.assertEqual(output.getvalue(), '')

    def test_invalid_cli_interval_is_rejected_before_migration_or_watch(self):
        with tempfile.TemporaryDirectory() as directory:
            config = pathlib.Path(directory) / 'fixture.env'; config.write_text('')
            flags = ['fixture', '--config', str(config), '--process-interval', '0.49']
            with mock.patch.object(TT.sys, 'argv', flags), \
                    mock.patch.object(TT, 'migrate_v001', side_effect=AssertionError('migration forbidden')), \
                    mock.patch.object(TT, 'Watch', side_effect=AssertionError('watch construction forbidden')), \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised: TT.main()
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [config])

    def test_review_main_success_ignores_watcher_only_invalid_interval(self):
        with tempfile.TemporaryDirectory() as directory:
            path, config = pathlib.Path(directory) / 'db', pathlib.Path(directory) / 'fixture.env'
            config.write_text(''); writer = sqlite3.connect(path); seed(writer); writer.commit(); writer.close()
            flags = ['fixture', '--config', str(config), '--db', str(path), '--review', '--since', T0,
                     '--until', FIXTURE['until'], '--process-interval', '0']
            output = io.StringIO()
            with mock.patch.object(TT.sys, 'argv', flags), \
                    mock.patch.object(TT, 'Watch', side_effect=AssertionError('watcher forbidden')), \
                    mock.patch.object(TT, 'migrate_v001', side_effect=AssertionError('migration forbidden')), \
                    contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit) as raised: TT.main()
            self.assertEqual(raised.exception.code, 0)
            self.assertEqual(json.loads(output.getvalue())['outcome'], 'QUIET')

    def test_stream_raw_controls_rejected_but_valid_escapes_are_accepted(self):
        for control in range(32):
            raw = ('{"processID":42,"processImagePath":"/fixture/SecurityAgent","eventMessage":"raw' + chr(control) + '"}').encode()
            progress = TT.KeychainProgress()
            self.assertIsNone(progress.line(raw))
            self.assertEqual(progress.cycle(), (None, 'keychain-malformed'))
            escaped = json.dumps({'processID': 42, 'processImagePath': '/fixture/SecurityAgent', 'eventMessage': chr(control)}).encode()
            progress = TT.KeychainProgress()
            self.assertIsNotNone(progress.line(escaped))
            self.assertEqual(progress.cycle(), (1, None))

    def test_old_history_signed_rowids_and_out_of_window_faults(self):
        conn = sqlite3.connect(':memory:')
        self.addCleanup(conn.close)
        seed(conn)
        mutate(conn, {'op': 'events'})
        old = '1999-12-31T23:00:00Z'
        ids = [-(1 << 63)] + list(range(-1537, 0)) + [(1 << 63) - 1]
        conn.executemany("INSERT INTO collector_heartbeats VALUES (?,1,'keychain',?,0,'ok',NULL,3)", ((rowid, old) for rowid in ids))
        conn.executemany("INSERT INTO events VALUES (?,?,'FIXTURE',?)", ((rowid, old, 'x' * 4096) for rowid in ids))
        result = snapshot_guard(conn, stamp(2))
        self.assertEqual((result['outcome'], result['eventCount']), ('EVENTS', 2))
        # An old record inserted last must not replace the true, newer start anchor.
        self.assertEqual(result['issues'], [])
        # Even the final signed-rowid page outside the window must be validated.
        conn.execute('UPDATE collector_heartbeats SET version=2 WHERE rowid=?', ((1 << 63) - 1,))
        self.assertEqual(normalized_issues(snapshot_guard(conn, stamp(2))), ['-/unsupported-heartbeat-version'])
        conn.execute('UPDATE collector_heartbeats SET version=1 WHERE rowid=?', ((1 << 63) - 1,))
        conn.execute("UPDATE events SET message=NULL WHERE rowid=?", ((1 << 63) - 1,))
        self.assertEqual(normalized_issues(snapshot_guard(conn, stamp(2))), ['-/malformed-event'])

    def test_anchor_uses_time_then_rowid_and_in_window_rows_are_sorted(self):
        conn = sqlite3.connect(':memory:')
        self.addCleanup(conn.close)
        seed(conn)
        # Later insertion of an older failed row cannot replace a newer healthy anchor.
        conn.execute("INSERT INTO collector_heartbeats VALUES (NULL,1,'keychain','1999-12-31T23:59:59Z',NULL,'degraded','keychain-ended',3)")
        self.assertEqual(snapshot_guard(conn, stamp(2))['outcome'], 'QUIET')
        # Nor may an older healthy row conceal the real, newer failed anchor.
        conn.execute("UPDATE collector_heartbeats SET observed_count=NULL,status='degraded',error='keychain-ended' WHERE collector='keychain' AND time=?", (T0,))
        conn.execute("INSERT INTO collector_heartbeats VALUES (NULL,1,'keychain','1999-12-31T23:59:59Z',0,'ok',NULL,3)")
        self.assertEqual(normalized_issues(snapshot_guard(conn, stamp(2))), ['keychain/start-silence'])
        # For the same timestamp the greater signed rowid is the later accepted anchor.
        conn.execute("INSERT INTO collector_heartbeats VALUES (NULL,1,'keychain',?,0,'ok',NULL,3)", (T0,))
        self.assertEqual(snapshot_guard(conn, stamp(2))['outcome'], 'QUIET')
        conn.execute("DELETE FROM collector_heartbeats WHERE collector='keychain'")
        for second in range(30, -1, -5):
            conn.execute("INSERT INTO collector_heartbeats VALUES (NULL,1,'keychain',?,0,'ok',NULL,3)", (stamp(second),))
        self.assertEqual(snapshot_guard(conn)['outcome'], 'QUIET')

    def test_parity_gate_rejects_missing_duplicate_false_quiet_and_wrong_types(self):
        good = parity.oracle(FIXTURE)
        parity.validate(good, FIXTURE)
        mutations = []
        missing = copy.deepcopy(good); missing['results'].pop(); mutations.append(missing)
        duplicate = copy.deepcopy(good); duplicate['results'].append(duplicate['results'][0]); mutations.append(duplicate)
        false_quiet = copy.deepcopy(good)
        row = next(r for r in false_quiet['results'] if r['name'] == 'no-heartbeats-cannot-be-quiet')
        row['result'].update(outcome='QUIET', eventCount=0, issues=[]); mutations.append(false_quiet)
        wrong_type = copy.deepcopy(good)
        row = next(r for r in wrong_type['results'] if r['name'] == 'healthy-zero')
        row['result']['eventCount'] = False; mutations.append(wrong_type)
        future = copy.deepcopy(good); future['fixtureVersion'] = 2; mutations.append(future)
        wrong_producer = copy.deepcopy(good)
        row = next(r for r in wrong_producer['producerResults'] if r['name'] == 'producer-default')
        next(r for r in row['rows'] if r['collector'] == 'processes')['cadence_seconds'] = 3.0
        mutations.append(wrong_producer)
        for value in mutations:
            with self.assertRaises(ValueError): parity.validate(value, FIXTURE)

    def test_missing_db_never_created(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = pathlib.Path(directory) / 'absent' / 'db'
            result = TT.review(str(missing), T0, FIXTURE['until'], FIXTURE['now'])
            self.assertEqual(normalized_issues(result), ['-/no-database'])
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [])

    def test_static_database_and_directory_not_mutated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'db'
            conn = sqlite3.connect(path)
            seed(conn)
            conn.commit()
            conn.close()
            before = {p.name: p.read_bytes() for p in pathlib.Path(directory).iterdir()}
            result = TT.review(str(path), T0, FIXTURE['until'], FIXTURE['now'])
            self.assertEqual(result['outcome'], 'QUIET')
            self.assertEqual(before, {p.name: p.read_bytes() for p in pathlib.Path(directory).iterdir()})

    def test_live_wal_commits_visible_and_read_snapshot_is_consistent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(pathlib.Path(directory) / 'db')
            writer = sqlite3.connect(path, isolation_level=None)
            self.addCleanup(writer.close)
            writer.execute('PRAGMA journal_mode=WAL')
            seed(writer)
            self.assertGreater(pathlib.Path(path + '-wal').stat().st_size, 0)
            self.assertEqual(TT.review(path, T0, FIXTURE['until'], FIXTURE['now'])['outcome'], 'QUIET')
            reader = TT.open_db_readonly(path)
            self.addCleanup(reader.close)
            reader.execute('BEGIN')
            reader.execute('SELECT count(*) FROM events').fetchone()  # establish snapshot
            writer.execute("INSERT INTO events VALUES (NULL,?,'CREDENTIAL','synthetic')", (stamp(15),))
            before = writer.total_changes
            self.assertEqual(TT.coverage_guard(reader, T0, FIXTURE['until'], FIXTURE['now'])['outcome'], 'QUIET')
            reader.execute('ROLLBACK')
            self.assertEqual(TT.review(path, T0, FIXTURE['until'], FIXTURE['now'])['eventCount'], 1)
            self.assertEqual(writer.total_changes, before)
            self.assertEqual(writer.execute('SELECT count(*) FROM events').fetchone()[0], 1)

    def test_database_failure_and_malformed_bytes_refuse(self):
        conn = sqlite3.connect(':memory:')
        conn.close()
        self.assertEqual(normalized_issues(TT.coverage_guard(conn, T0, FIXTURE['until'], FIXTURE['now'])), ['-/database-read'])
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'db'
            path.write_bytes(b'synthetic non-SQLite bytes')
            self.assertEqual(normalized_issues(TT.review(str(path), T0, FIXTURE['until'], FIXTURE['now'])), ['-/database-read'])

    def test_writer_refuses_future_header_or_rows_before_schema_extension(self):
        changes = ['UPDATE schema_version SET version=2', 'UPDATE heartbeat_schema SET version=2',
                   'UPDATE collector_heartbeats SET version=2']
        with tempfile.TemporaryDirectory() as directory:
            for index, change in enumerate(changes):
                path = pathlib.Path(directory) / ('future-%d' % index)
                conn = sqlite3.connect(path); seed(conn); conn.execute(change); conn.commit(); conn.close()
                before = path.read_bytes()
                with self.assertRaises(SystemExit): TT.open_db(str(path))
                self.assertEqual(path.read_bytes(), before)
                self.assertFalse(pathlib.Path(str(path) + '-wal').exists())

    def test_legacy_writer_extension_preserves_inventory_but_invents_no_history(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'legacy'
            conn = sqlite3.connect(path); seed(conn)
            for table in ('collector_heartbeats', 'heartbeat_schema', 'coverage_metadata'): conn.execute('DROP TABLE ' + table)
            conn.execute("INSERT INTO programs(exe) VALUES ('/fixture/retained')")
            conn.commit(); conn.close()
            writer = TT.open_db(str(path))
            try:
                self.assertEqual(writer.execute('SELECT exe FROM programs').fetchall(), [('/fixture/retained',)])
                self.assertEqual(writer.execute('SELECT count(*) FROM collector_heartbeats').fetchone()[0], 0)
                result = TT.review(str(path), T0, FIXTURE['until'], FIXTURE['now'])
                self.assertEqual(result['outcome'], 'REFUSED')
                self.assertEqual(len(result['issues']), 5)
            finally: writer.close()

    def test_cli_conflicts_do_not_start_or_create_watcher(self):
        requests = [[], ['--since', T0], ['--until', FIXTURE['until']], ['--review'],
                    ['--review', '--since', T0], ['--review', '--report', '--since', T0, '--until', FIXTURE['until']],
                    ['--review', '--query', 'SELECT 1', '--since', T0, '--until', FIXTURE['until']],
                    ['--review', '--show-settings', '--since', T0, '--until', FIXTURE['until']]]
        for flags in requests[1:]:
            with self.subTest(flags=flags), mock.patch.object(TT, 'Watch', side_effect=AssertionError('watcher forbidden')), \
                    mock.patch.object(TT.sys, 'argv', ['fixture'] + flags), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised: TT.main()
                self.assertEqual(raised.exception.code, 2)

    def test_cli_review_invalid_window_is_json_refusal_without_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'db'
            writer = sqlite3.connect(path)
            seed(writer)
            writer.commit(); writer.close()
            config = pathlib.Path(directory) / 'fixture.env'
            config.write_text('')
            output = io.StringIO()
            with mock.patch.object(TT.sys, 'argv', ['fixture', '--review', '--config', str(config), '--db', str(path), '--since', 'bad', '--until', FIXTURE['until']]), \
                    mock.patch.object(TT, 'Watch', side_effect=AssertionError('watcher forbidden')), \
                    mock.patch.object(TT, 'migrate_v001', side_effect=AssertionError('migration forbidden')), contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit) as raised: TT.main()
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(json.loads(output.getvalue())['outcome'], 'REFUSED')


def coverage_case(case):
    def test(self):
        conn = sqlite3.connect(':memory:', isolation_level=None)
        self.addCleanup(conn.close)
        seed(conn); mutate(conn, case)
        conn.execute('PRAGMA query_only=ON'); conn.execute('BEGIN')
        before = conn.total_changes
        result = TT.coverage_guard(conn, case.get('since', T0), case.get('until', FIXTURE['until']), FIXTURE['now'])
        self.assertEqual(result['outcome'], case['outcome'])
        self.assertEqual(normalized_issues(result), case['issues'])
        self.assertEqual(result['eventCount'], case.get('eventCount', 0) if case['outcome'] != 'REFUSED' else None)
        self.assertEqual(conn.total_changes, before)
        RESULTS.append({'name': case['name'], 'result': result})
    return test


def stream_case(case):
    def test(self):
        progress = TT.KeychainProgress()
        for line in case['lines']: progress.line(line.encode())
        if 'hex' in case: progress.line(bytes.fromhex(case['hex']))
        count, error = progress.cycle(case['alive'], case['partial'])
        self.assertEqual((count, error), (case['count'], case['error']))
        # A later, fully serviced live interval can recover; a dead child still cannot.
        self.assertEqual(progress.cycle(), (0, None))
        RESULTS.append({'name': 'stream-' + case['name'], 'count': count, 'error': error})
    return test


for index, case in enumerate(FIXTURE['cases']):
    setattr(CoverageTests, 'test_fixture_%02d_%s' % (index, case['name'].replace('-', '_')), coverage_case(case))
for index, case in enumerate(FIXTURE['streamCases']):
    setattr(CoverageTests, 'test_stream_%02d_%s' % (index, case['name'].replace('-', '_')), stream_case(case))


class ProducerHeartbeatTests(unittest.TestCase):
    setUp = health.CollectionHealthTests.setUp
    commands = health.CollectionHealthTests.commands
    ps_responses = health.CollectionHealthTests.ps_responses
    seed_listener = health.CollectionHealthTests.seed_listener
    rows = regressions.ReviewRegressionTests.rows
    worker = regressions.ReviewRegressionTests.worker

    def pulses(self, key):
        return self.w.db.execute('SELECT observed_count,status,error FROM collector_heartbeats WHERE collector=? ORDER BY id', (key,)).fetchall()

    def test_actual_poll_counts_failure_partial_recovery_and_inventory_retention(self):
        self.seed_listener()
        with self.commands({LSOF: (1, '', '')}): self.assertTrue(self.w.check_listeners())
        self.assertEqual(self.pulses('listeners')[-1], (0, 'ok', None))
        with self.commands(self.ps_responses()): self.assertTrue(self.w.check_processes())
        self.assertEqual(self.pulses('processes')[-1], (1, 'ok', None))
        for response in [(7, '', ''), (0, 'p42\ncpartial\n', '')]:
            before = self.w.db.execute('SELECT * FROM listeners').fetchall()
            with self.commands({LSOF: response}): self.assertFalse(self.w.check_listeners())
            self.assertEqual(self.w.db.execute('SELECT * FROM listeners').fetchall(), before)
            self.assertEqual(self.pulses('listeners')[-1][:2], (None, 'degraded'))
        with self.commands({LSOF: (1, '', '')}): self.assertTrue(self.w.check_listeners())
        self.assertEqual(self.pulses('listeners')[-1], (0, 'ok', None))
        with self.commands({CRON: (1, '', 'crontab: no crontab for fixture\n')}): self.assertTrue(self.w.check_startup())
        self.assertEqual(self.pulses('startup')[-1], (0, 'ok', None))
        self.assertEqual(self.pulses('crontab')[-1], (0, 'ok', None))

    def test_startup_partial_and_crontab_failure_have_independent_nonzero_proof(self):
        with mock.patch.object(self.w, '_startup_files', return_value=({'/fixture/blocked': 'unreadable: permission-denied'}, {})), \
                self.commands({CRON: (7, '', '')}):
            self.assertFalse(self.w.check_startup())
        self.assertEqual(self.pulses('startup')[-1], (None, 'degraded', 'startup-unreadable'))
        self.assertEqual(self.pulses('crontab')[-1], (None, 'degraded', 'crontab-command'))
        with self.commands({CRON: (1, '', 'no crontab for fixture\n')}): self.assertTrue(self.w.check_startup())
        self.assertEqual(self.pulses('startup')[-1], (0, 'ok', None))
        self.assertEqual(self.pulses('crontab')[-1], (0, 'ok', None))

    def test_inventory_and_success_heartbeat_rollback_together(self):
        self.w.db.execute("CREATE TRIGGER reject_pulse BEFORE INSERT ON collector_heartbeats WHEN NEW.status='ok' BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with self.commands(self.ps_responses()): self.assertFalse(self.w.check_processes())
        self.assertEqual(self.w.db.execute('SELECT count(*) FROM programs').fetchone()[0], 0)
        self.assertEqual(self.pulses('processes'), [(None, 'degraded', 'collection-db')])

    def test_configured_cadence_and_retention_floor(self):
        self.assertEqual([self.w._cadence(k) for k in TT.COLLECTORS], [6, 33, 303, 303, 3])
        self.w.retention_days = 1
        self.w.retain()
        self.assertIsNotNone(self.w.db.execute("SELECT value FROM coverage_metadata WHERE key='event_floor'").fetchone())

    def test_idle_stream_worker_pulses_and_drains_final_output_before_exit(self):
        class Child:
            code = None
            stdout = mock.Mock()
            stderr = mock.Mock()
            def poll(self): return self.code
            def wait(self, **kwargs): return self.code
            def terminate(self): self.code = 0
            def kill(self): self.code = -9
        child, tick, reads = Child(), [0], []
        child.stdout.fileno.return_value, child.stderr.fileno.return_value = 31, 32
        final = b'{"processID":42,"processImagePath":"/fixture/SecurityAgent"}\n'
        def selected(timeout):
            tick[0] += 3
            if tick[0] >= 6: child.code = 0
            if tick[0] == 3:
                return [(types.SimpleNamespace(data='stderr'), TT.selectors.EVENT_READ)]
            return [(types.SimpleNamespace(data='stdout'), TT.selectors.EVENT_READ)] if child.code is not None else []
        def read(fd, size):
            if fd == 32: return b''
            reads.append(size)
            return final if len(reads) == 1 else b''
        selector = mock.MagicMock()
        selector.__enter__.return_value.select.side_effect = selected
        with mock.patch.object(TT.subprocess, 'Popen', return_value=child), \
                mock.patch.object(TT.os, 'set_blocking'), mock.patch.object(TT.os, 'read', side_effect=read), \
                mock.patch.object(TT.selectors, 'DefaultSelector', return_value=selector), \
                mock.patch.object(TT.time, 'monotonic', side_effect=lambda: tick[0]), \
                mock.patch.object(self.w, '_stream_event') as events:
            self.assertTrue(self.w._log_stream_once())
        self.assertEqual(events.call_count, 1)
        self.assertEqual(self.pulses('keychain'), [(0, 'ok', None), (None, 'degraded', 'keychain-ended')])
        child.stdout.close.assert_called_once()
        child.stderr.close.assert_called_once()
        self.assertIsNone(self.w.stream_proc)

    def test_stream_restart_is_delayed_and_previous_child_is_closed(self):
        children, delays = [], []
        def start(*args, **kwargs):
            if children: children[-1].stdout.close.assert_called_once()
            child = mock.Mock()
            child.poll.return_value = 0
            child.wait.return_value = 0
            child.stdout.fileno.return_value, child.stderr.fileno.return_value = 31, 32
            children.append(child)
            return child
        def pause(seconds):
            delays.append(seconds)
            if len(delays) == 2: self.w.stop.set()
            return self.w.stop.is_set()
        selector = mock.MagicMock()
        selector.__enter__.return_value.select.return_value = [(types.SimpleNamespace(data=name), TT.selectors.EVENT_READ) for name in ('stdout', 'stderr')]
        with mock.patch.object(TT.subprocess, 'Popen', side_effect=start), mock.patch.object(TT.os, 'set_blocking'), \
                mock.patch.object(TT.os, 'read', return_value=b''), \
                mock.patch.object(TT.selectors, 'DefaultSelector', return_value=selector), mock.patch.object(self.w.stop, 'wait', side_effect=pause):
            self.w.log_stream()
        self.assertEqual(len(children), 2)
        self.assertEqual(delays, [10, 10])
        self.assertTrue(all(row == (None, 'degraded', 'keychain-ended') for row in self.pulses('keychain')))

    def test_initial_no_output_nonzero_stream_does_not_restart_or_credit_fallback(self):
        child = mock.Mock()
        child.poll.return_value = 2
        child.wait.return_value = 2
        child.stdout.fileno.return_value, child.stderr.fileno.return_value = 31, 32
        selector = mock.MagicMock()
        selector.__enter__.return_value.select.return_value = [(types.SimpleNamespace(data=name), TT.selectors.EVENT_READ) for name in ('stdout', 'stderr')]
        with mock.patch.object(TT.subprocess, 'Popen', return_value=child) as starts, mock.patch.object(TT.os, 'set_blocking'), \
                mock.patch.object(TT.os, 'read', return_value=b''), \
                mock.patch.object(TT.selectors, 'DefaultSelector', return_value=selector), \
                mock.patch.object(self.w.stop, 'wait', side_effect=AssertionError('unsupported stream retry forbidden')):
            self.w.log_stream()
        self.assertEqual(starts.call_count, 1)
        self.assertEqual(self.pulses('keychain'), [(None, 'degraded', 'keychain-ended')])

    def test_closed_stdout_alive_child_degrades_cleans_and_does_not_restart(self):
        class Child:
            code = None
            stdout = mock.Mock()
            stderr = mock.Mock()
            terminated = False
            def poll(self): return self.code
            def wait(self, timeout):
                if self.code is None: raise TT.subprocess.TimeoutExpired('fixture-log', timeout)
                return self.code
            def terminate(self): self.terminated, self.code = True, 0
            def kill(self): raise AssertionError('terminated fake child should not need kill')
        child = Child()
        child.stdout.fileno.return_value, child.stderr.fileno.return_value = 31, 32
        selector = mock.MagicMock()
        selector.__enter__.return_value.select.return_value = [(types.SimpleNamespace(data=name), TT.selectors.EVENT_READ) for name in ('stdout', 'stderr')]
        with mock.patch.object(TT.subprocess, 'Popen', return_value=child) as starts, \
                mock.patch.object(TT.os, 'set_blocking'), mock.patch.object(TT.os, 'read', return_value=b''), \
                mock.patch.object(TT.selectors, 'DefaultSelector', return_value=selector), \
                mock.patch.object(self.w.stop, 'wait', side_effect=AssertionError('closed pipe must not authorize restart')):
            self.w.log_stream()
        rows = self.pulses('keychain')
        self.assertTrue(rows)
        self.assertTrue(all(count is None and status == 'degraded' for count, status, error in rows))
        self.assertEqual(starts.call_count, 1)
        self.assertTrue(child.terminated)
        self.assertEqual(child.poll(), 0)
        child.stdout.close.assert_called_once()
        child.stderr.close.assert_called_once()
        self.assertIsNone(self.w.stream_proc)

    def test_dead_child_diagnostic_flood_cannot_renew_drain_deadline(self):
        child, clock = regressions.FixtureChild(), [0]
        child.stderr, child.code = child.diagnostics, 0
        selector = regressions.FixtureSelector(child, clock, 0)
        def select(timeout):
            clock[0] += 1
            self.assertLessEqual(clock[0], 8, 'stderr progress renewed the dead-child deadline')
            return [(key, TT.selectors.EVENT_READ) for key in list(selector.keys.values())]
        selector.select = select
        def read(fd, size): return b'' if fd == 31 else b'x' * size
        with mock.patch.object(TT.subprocess, 'Popen', return_value=child), mock.patch.object(TT.os, 'set_blocking'), \
                mock.patch.object(TT.os, 'read', side_effect=read), \
                mock.patch.object(TT.selectors, 'DefaultSelector', return_value=selector), \
                mock.patch.object(TT.time, 'monotonic', side_effect=lambda: clock[0]):
            self.assertFalse(self.w._log_stream_once())
        self.assertEqual(self.pulses('keychain')[-1], (None, 'degraded', 'keychain-io'))
        self.assertEqual(len(self.w.stream_diagnostics), 4096)
        self.assertTrue(child.stdout.closed and child.stderr.closed)
        self.assertIsNone(self.w.stream_proc)

    def test_unconfirmed_child_cleanup_retains_ownership_and_blocks_retry(self):
        class Child(regressions.FixtureChild):
            def wait(self, timeout): raise TT.subprocess.TimeoutExpired('fixture-log', timeout)
            def terminate(self): self.terminated = True
            def kill(self): self.terminated = True
        child, clock = Child(), [0]
        child.stderr = child.diagnostics
        child.stdout.eof = child.stderr.eof = True
        selector = regressions.FixtureSelector(child, clock, 0)
        selector.select = lambda timeout: [(key, TT.selectors.EVENT_READ) for key in list(selector.keys.values())]
        with mock.patch.object(TT.subprocess, 'Popen', return_value=child) as starts, \
                mock.patch.object(TT.os, 'set_blocking'), mock.patch.object(TT.os, 'read', return_value=b''), \
                mock.patch.object(TT.selectors, 'DefaultSelector', return_value=selector):
            self.assertFalse(self.w._log_stream_once())
            self.assertTrue(self.w.stop.is_set())
            self.assertIs(self.w.stream_proc, child)
            self.assertEqual(self.pulses('keychain')[-1], (None, 'degraded', 'keychain-cleanup'))
            self.assertFalse(self.w._log_stream_once())
            self.assertEqual(starts.call_count, 1)
        self.assertTrue(child.stdout.closed and child.stderr.closed)

    def test_unconfirmed_pipe_close_blocks_otherwise_eligible_restart(self):
        child, clock = regressions.FixtureChild(), [0]
        child.stderr, child.code = child.diagnostics, 0
        child.stdout.eof = child.stderr.eof = True
        child.stderr.close = mock.Mock(side_effect=OSError('synthetic diagnostic close failure'))
        selector = regressions.FixtureSelector(child, clock, 0)
        selector.select = lambda timeout: [(key, TT.selectors.EVENT_READ) for key in list(selector.keys.values())]
        with mock.patch.object(TT.subprocess, 'Popen', return_value=child) as starts, mock.patch.object(TT.os, 'set_blocking'), \
                mock.patch.object(TT.os, 'read', return_value=b''), mock.patch.object(TT.selectors, 'DefaultSelector', return_value=selector):
            self.assertFalse(self.w._log_stream_once(), 'zero exit cannot waive an unconfirmed owned pipe close')
            self.assertIs(self.w.stream_proc, child)
            self.assertTrue(self.w.stop.is_set())
            self.assertFalse(self.w._log_stream_once())
            self.assertEqual(starts.call_count, 1)
        self.assertEqual(self.pulses('keychain')[-1], (None, 'degraded', 'keychain-cleanup'))


ROW_SQL = ('SELECT version,collector,time,observed_count,status,error,cadence_seconds '
           'FROM collector_heartbeats ORDER BY collector,time,id')


def actual_rows(watch):
    cursor = watch.db.execute(ROW_SQL)
    columns = [column[0] for column in cursor.description]
    return [dict(zip(columns, row)) for row in cursor]


def producer_case(case):
    def test(self):
        root = self.root / case['name']
        self.w = TT.Watch(str(root / 'log'), str(root / 'db'), process_every=case['process'],
                          listen_every=case['listen'], startup_every=case['startup'], notify=False)
        self.addCleanup(self.w.db.close)
        self.w.load_state()
        def healthy():
            with self.commands(self.ps_responses()): self.assertTrue(self.w.check_processes())
            with self.commands({LSOF: (1, '', '')}): self.assertTrue(self.w.check_listeners())
            with self.commands({CRON: (1, '', 'no crontab for fixture\n')}): self.assertTrue(self.w.check_startup())
        healthy()
        if case['scenario'] == 'failure-recovery':
            with mock.patch.object(TT, 'now', return_value=stamp(1)):
                with self.commands({health.PS_COMM: (7, '', '')}): self.assertFalse(self.w.check_processes())
                with self.commands({LSOF: (0, 'p42\ncpartial\n', '')}): self.assertFalse(self.w.check_listeners())
                with mock.patch.object(self.w, '_startup_files', side_effect=TT.CollectionError('startup-read')), self.commands({CRON: (7, '', '')}):
                    self.assertFalse(self.w.check_startup())
            with mock.patch.object(TT, 'now', return_value=stamp(2)): healthy()
        rows = actual_rows(self.w)
        parity.equal(rows, case['expectedRows'])
        PRODUCER_RESULTS.append({'name': case['name'], 'rows': rows})
    return test


def invalid_interval_case(case):
    def test(self):
        root = self.root / case['name']
        values = {'process_every': 3, 'listen_every': 30, 'startup_every': 300}
        values[{'process': 'process_every', 'listen': 'listen_every', 'startup': 'startup_every'}[case['field']]] = float(case['value'])
        with self.assertRaises(ValueError): TT.Watch(str(root / 'log'), str(root / 'db'), notify=False, **values)
        self.assertFalse(root.exists(), 'invalid configuration created a directory or database')
        PRODUCER_RESULTS.append({'name': case['name'], 'rejected': True, 'directoryEmpty': True})
    return test


def worker_case(case):
    def test(self):
        stdout = ''.join(line + '\n' for line in case['stdoutLines']).encode()
        stderr = (case['stderr'] * case.get('stderrRepeat', 1)).encode()
        pulses_with_backlog = []
        class DrainSelector(regressions.FixtureSelector):
            def select(selector, timeout=None):
                if case.get('stderrRepeat') and selector.turn == 2:
                    accepted = self.w.db.execute("SELECT observed_count,status FROM collector_heartbeats WHERE collector='keychain' ORDER BY id DESC LIMIT 1").fetchone()
                    pulses_with_backlog.append(accepted == (1, 'ok') and bool(selector.child.diagnostics.chunks))
                if selector.turn < 3:
                    return super().select(timeout)
                selector.turn += 1
                if selector.turn > 12: raise AssertionError('diagnostic drain failed to finish')
                return [(key, TT.selectors.EVENT_READ) for key in list(selector.keys.values())
                        if key.fileobj.chunks or key.fileobj.eof]
        with mock.patch.object(regressions, 'FixtureSelector', DrainSelector):
            retry, delays, child, ignored = self.worker(stdout, stderr, case['exitCode'])
        rows = actual_rows(self.w)
        result = {'name': case['name'], 'rows': rows, 'retry': retry,
                  'diagnosticBytes': len(self.w.stream_diagnostics),
                  'credentialEvents': self.w.db.execute("SELECT count(*) FROM credential_events WHERE source='log'").fetchone()[0]}
        expected = {'name': case['name'], 'rows': case['expectedRows'], 'retry': case['retry'],
                    'diagnosticBytes': case['diagnosticBytes'], 'credentialEvents': case['credentialEvents']}
        parity.equal(result, expected)
        self.assertEqual(child.diagnostics.bytes_read, len(stderr))
        self.assertTrue(child.stderr.closed)
        if case.get('stderrRepeat'):
            self.assertIn(True, pulses_with_backlog, 'stdout count and deadline pulse were starved by continuously ready diagnostics')
        PRODUCER_RESULTS.append(result)
    return test


for index, case in enumerate(FIXTURE['producerCases']):
    setattr(ProducerHeartbeatTests, 'test_row_parity_%02d' % index, producer_case(case))
for index, case in enumerate(FIXTURE['invalidIntervalCases']):
    setattr(ProducerHeartbeatTests, 'test_invalid_interval_%02d' % index, invalid_interval_case(case))
for index, case in enumerate(FIXTURE['workerCases']):
    setattr(ProducerHeartbeatTests, 'test_worker_row_parity_%02d' % index, worker_case(case))


def parity_snapshots():
    result = {'fixtureVersion': 1, 'results': sorted(RESULTS, key=lambda row: row['name']),
              'producerResults': sorted(PRODUCER_RESULTS, key=lambda row: row['name'])}
    parity.validate(result, FIXTURE)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--parity-output')
    args, remaining = parser.parse_known_args()
    if args.parity_output and pathlib.Path(args.parity_output).exists(): parser.error('refusing existing parity output')
    run = unittest.main(argv=[sys.argv[0]] + remaining, exit=False)
    if run.result.wasSuccessful() and args.parity_output:
        pathlib.Path(args.parity_output).write_text(json.dumps(parity_snapshots(), sort_keys=True) + '\n')
    sys.exit(0 if run.result.wasSuccessful() else 1)
