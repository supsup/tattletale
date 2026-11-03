"""F119 deciding regressions against existing APIs; synthetic clocks, pipes and SQLite only.

This file intentionally expects the accepted repair policy. On unchanged d68 the RED
results must be semantic assertions, never missing symbols or attempted host collection.
It does not alter the existing fixture/comparator protocol or certify Java parity.
"""
import contextlib
import datetime as dt
import errno
import io
import json
import types
import unittest
from collections import deque
from unittest import mock

import test_collection_health as health

TT = health.TT
START = health.T0
BASE = dt.datetime.strptime(START, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=dt.timezone.utc)
VALID_RECORD = json.dumps({'processID': 42, 'processImagePath': '/fixture/SecurityAgent',
                           'eventMessage': 'synthetic credential record'}).encode() + b'\n'
BANNER = b'Filtering the log data using "process == SecurityAgent"\n'


def stamp(seconds):
    return (BASE + dt.timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')


class FixtureThread:
    """Watch.run control flow without starting either background target."""
    def __init__(self, **kwargs): pass
    def start(self): pass
    def join(self, **kwargs): pass


class FixtureStop:
    def __init__(self, clock):
        self.clock, self.stopped, self.waits = clock, False, []
    def is_set(self): return self.stopped
    def set(self): self.stopped = True
    def wait(self, seconds):
        self.waits.append(seconds)
        self.clock[0] += seconds
        if len(self.waits) == 2: self.stopped = True
        return self.stopped


class FixturePipe:
    def __init__(self, fd):
        self.fd, self.chunks, self.eof, self.closed, self.bytes_read = fd, deque(), False, False, 0
    def fileno(self): return self.fd
    def close(self): self.closed = True
    def read_chunk(self, size):
        if self.chunks:
            data = self.chunks.popleft()
            if len(data) > size: self.chunks.appendleft(data[size:])
            data = data[:size]
            self.bytes_read += len(data)
            return data
        if self.eof: return b''
        raise BlockingIOError(errno.EAGAIN, 'synthetic idle pipe')


class FixtureChild:
    def __init__(self):
        self.stdout, self.diagnostics = FixturePipe(31), FixturePipe(32)
        self.stderr, self.code, self.terminated = None, None, False
    def poll(self): return self.code
    def wait(self, timeout):
        if self.code is None: raise TT.subprocess.TimeoutExpired('fixture-log', timeout)
        return self.code
    def terminate(self): self.terminated, self.code = True, 0
    def kill(self): self.terminated, self.code = True, -9


class FixtureSelector:
    """Deliver data at t=1, a live idle interval at t=3, and confirmed EOF at t=4."""
    def __init__(self, child, clock, exit_code):
        self.child, self.clock, self.exit_code = child, clock, exit_code
        self.keys, self.turn = {}, 0
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def register(self, fileobj, events, data=None):
        key = types.SimpleNamespace(fileobj=fileobj, fd=fileobj.fileno(), events=events, data=data)
        self.keys[key.fd] = key
        return key
    def unregister(self, fileobj):
        return self.keys.pop(fileobj if isinstance(fileobj, int) else fileobj.fileno())
    def get_map(self): return self.keys
    def select(self, timeout=None):
        self.turn += 1
        if self.turn == 1: self.clock[0] = 1
        elif self.turn == 2: self.clock[0] = 3
        elif self.turn == 3:
            self.clock[0], self.child.code = 4, self.exit_code
            self.child.stdout.eof = self.child.diagnostics.eof = True
        else: raise AssertionError('synthetic worker failed to finish after confirmed EOF')
        return [(key, TT.selectors.EVENT_READ) for key in list(self.keys.values())
                if key.fileobj.chunks or key.fileobj.eof]


class ReviewRegressionTests(unittest.TestCase):
    setUp = health.CollectionHealthTests.setUp
    commands = health.CollectionHealthTests.commands
    ps_responses = health.CollectionHealthTests.ps_responses

    def rows(self, collector, watch=None):
        watch = watch or self.w
        return watch.db.execute('SELECT version,collector,time,observed_count,status,error,cadence_seconds '
                                'FROM collector_heartbeats WHERE collector=? ORDER BY rowid', (collector,)).fetchall()

    def guard(self, watch=None, since=0, until=1):
        watch = watch or self.w
        watch.db.execute('PRAGMA query_only=ON')
        watch.db.execute('BEGIN')
        before = watch.db.total_changes
        try:
            result = TT.coverage_guard(watch.db, stamp(since), stamp(until), stamp(7200))
            self.assertEqual(watch.db.total_changes, before)
            return result
        finally:
            watch.db.execute('ROLLBACK')
            watch.db.execute('PRAGMA query_only=OFF')

    def controls(self, watch=None, times=(0,), exclude=()):
        """Independent synthetic positive controls isolate the collector under test."""
        watch = watch or self.w
        for collector in ('processes', 'listeners', 'startup', 'crontab', 'keychain'):
            if collector not in exclude:
                for at in times: watch._heartbeat(collector, 0, at=stamp(at))

    def test_m1_hourly_producer_rows_are_supported_by_reader(self):
        hourly = TT.Watch(str(self.root / 'hourly.log'), str(self.root / 'hourly.db'),
                          startup_every=3600, process_every=3, notify=False)
        self.addCleanup(hourly.db.close)
        hourly.load_state()
        with self.commands({health.CRON: (1, '', 'no crontab for fixture\n')}):
            self.assertTrue(hourly.check_startup())
        self.assertEqual(self.rows('startup', hourly), [(1, 'startup', START, 0, 'ok', None, 3603.0)])
        self.assertEqual(self.rows('crontab', hourly), [(1, 'crontab', START, 0, 'ok', None, 3603.0)])
        self.controls(hourly, exclude=('startup', 'crontab'))
        result = self.guard(hourly)
        self.assertEqual(result['issues'], [], 'producer-emitted hourly cadence must be readable')
        self.assertEqual((result['outcome'], result['eventCount']), ('EVENTS', 2))

    def test_m1_superseded_old_bad_payload_does_not_poison_new_window(self):
        self.controls(times=(0, 5, 10, 15, 20))
        self.w.db.execute("INSERT INTO collector_heartbeats VALUES (NULL,1,'startup',?,0,'ok',NULL,7201)", (stamp(-1),))
        result = self.guard(since=10, until=20)
        self.assertEqual((result['outcome'], result['issues']), ('QUIET', []))

    def test_control_malformed_required_anchor_is_not_skipped(self):
        self.controls(times=(0, 5, 8, 15, 20))
        self.w.db.execute("INSERT INTO collector_heartbeats VALUES (NULL,1,'startup',?,0,'ok',NULL,7201)", (stamp(9),))
        result = self.guard(since=10, until=20)
        self.assertEqual(result['outcome'], 'REFUSED')
        self.assertIn({'collector': 'startup', 'reason': 'malformed-heartbeat'}, result['issues'])

    def test_m2_default_process_row_declares_minimal_loop_allowance(self):
        with self.commands(self.ps_responses()): self.assertTrue(self.w.check_processes())
        self.assertEqual(self.rows('processes'), [(1, 'processes', START, 1, 'ok', None, 6.0)])

    def test_m2_fractional_process_row_uses_twice_interval(self):
        self.w.process_every = 0.5
        with self.commands(self.ps_responses()): self.assertTrue(self.w.check_processes())
        self.assertEqual(self.rows('processes'), [(1, 'processes', START, 1, 'ok', None, 1.0)])

    def shared_loop(self, lsof_seconds):
        """Run the actual two-iteration Watch.run schedule; fake each ps costs 0.5s.

        A 5s lsof yields accepted process samples at t=1 and t=10 (gap 9).
        An 11s lsof yields samples at t=1 and t=16 (gap 15, beyond new grace 14).
        """
        clock = [0.0]
        finish = lsof_seconds + 5
        self.controls(times=(1,), exclude=('processes', 'keychain'))
        for at in range(1, int(finish) + 1, 3): self.w._heartbeat('keychain', 0, at=stamp(at))
        def run(argv, **kwargs):
            key = tuple(argv)
            if key in (health.PS_COMM, health.PS_ARGS):
                clock[0] += 0.5
                return health.completed(argv, *self.ps_responses()[key])
            if key == health.LSOF:
                clock[0] += lsof_seconds
                return health.completed(argv, 1, '', '')
            if key == health.CRON: return health.completed(argv, 1, '', 'no crontab for fixture\n')
            raise AssertionError('unoffered synthetic collector ' + repr(key))
        stop = FixtureStop(clock)
        with contextlib.ExitStack() as patches:
            for name in ('claim_pid_file', 'release_pid_file', 'install_dashboard', 'load_state', 'retain', 'save', 'log'):
                patches.enter_context(mock.patch.object(self.w, name))
            patches.enter_context(mock.patch.object(self.w, 'stop', stop))
            patches.enter_context(mock.patch.object(TT.threading, 'Thread', FixtureThread))
            patches.enter_context(mock.patch.object(TT.time, 'monotonic', side_effect=lambda: clock[0]))
            patches.enter_context(mock.patch.object(TT, 'now', side_effect=lambda: stamp(clock[0])))
            patches.enter_context(mock.patch.object(TT.subprocess, 'run', side_effect=run))
            self.w.run()
        # Watch.run closes its owned connection. Inspect the same synthetic DB read-only.
        conn = TT.open_db_readonly(self.w.db_path)
        self.addCleanup(conn.close)
        conn.execute('BEGIN')
        rows = conn.execute("SELECT version,collector,time,observed_count,status,error,cadence_seconds FROM collector_heartbeats WHERE collector='processes' ORDER BY rowid").fetchall()
        result = TT.coverage_guard(conn, stamp(1), stamp(finish), stamp(clock[0]))
        self.assertEqual([row[2] for row in rows], [stamp(1), stamp(finish)])
        self.assertTrue(all(row[3:6] == (1, 'ok', None) for row in rows))
        self.assertEqual(stop.waits, [3, 3])
        return rows, result

    def test_m2_actual_shared_loop_five_second_lsof_preserves_coverage(self):
        rows, result = self.shared_loop(5)
        self.assertEqual(result['issues'], [], 'healthy sibling delay must fit the declared loop allowance')
        self.assertEqual(result['outcome'], 'EVENTS')
        self.assertEqual([row[6] for row in rows], [6.0, 6.0])

    def test_control_shared_loop_gap_fifteen_still_refuses(self):
        rows, result = self.shared_loop(11)
        self.assertEqual(result['outcome'], 'REFUSED')
        self.assertIn({'collector': 'processes', 'reason': 'heartbeat-gap'}, result['issues'])

    def worker(self, stdout, stderr=b'', exit_code=0, outer=False):
        child, clock, delays = FixtureChild(), [0.0], []
        selector = FixtureSelector(child, clock, exit_code)
        def spawn(argv, **kwargs):
            if kwargs.get('stderr') == TT.subprocess.STDOUT:
                child.stdout.chunks.append(stdout + stderr)
            else:
                child.stdout.chunks.append(stdout)
                if kwargs.get('stderr') == TT.subprocess.PIPE:
                    child.stderr = child.diagnostics
                    if stderr: child.diagnostics.chunks.append(stderr)
            return child
        def read(fd, size):
            return {31: child.stdout, 32: child.diagnostics}[fd].read_chunk(size)
        def pause(seconds):
            delays.append(seconds)
            self.w.stop.set()  # bound a broken restart without starting a second fake child
            return True
        with mock.patch.object(TT.subprocess, 'Popen', side_effect=spawn) as starts, \
                mock.patch.object(TT.os, 'set_blocking'), mock.patch.object(TT.os, 'read', side_effect=read), \
                mock.patch.object(TT.selectors, 'DefaultSelector', return_value=selector), \
                mock.patch.object(TT.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(TT, 'now', side_effect=lambda: stamp(clock[0])), \
                mock.patch.object(self.w, 'lookup_now', return_value=('synthetic args', 'fixture parent')), \
                mock.patch.object(self.w.stop, 'wait', side_effect=pause), contextlib.redirect_stdout(io.StringIO()):
            retry = self.w.log_stream() if outer else self.w._log_stream_once()
        self.assertEqual(starts.call_count, 1)
        self.assertTrue(child.stdout.closed)
        self.assertIsNone(self.w.stream_proc)
        return retry, delays, child, self.rows('keychain')

    def test_m3_known_prelude_and_independent_stderr_allow_idle_zero(self):
        retry, delays, child, rows = self.worker(BANNER, b'synthetic informational diagnostic\n')
        self.assertEqual(rows[0], (1, 'keychain', stamp(3), 0, 'ok', None, 3.0))
        self.assertGreater(child.diagnostics.bytes_read, 0, 'stderr must be drained separately, not discarded')
        self.assertIsNotNone(child.stderr)
        self.assertTrue(child.stderr.closed)

    def test_m3_unsupported_style_without_valid_records_does_not_retry(self):
        retry, delays, child, rows = self.worker(BANNER, b'log: unsupported style ndjson\n', exit_code=2, outer=True)
        self.assertEqual(delays, [], 'banner/usage text is not record evidence authorizing restart')
        self.assertTrue(all(row[4] == 'degraded' and row[3] is None for row in rows[-1:]))

    def test_control_ordinary_valid_record_is_counted_and_stored(self):
        retry, delays, child, rows = self.worker(VALID_RECORD)
        self.assertTrue(retry, 'ordinary confirmed terminal exit must retain eligible recovery')
        self.assertEqual(rows[0], (1, 'keychain', stamp(3), 1, 'ok', None, 3.0))
        self.assertEqual(self.w.db.execute("SELECT count(*) FROM credential_events WHERE source='log'").fetchone()[0], 1)

    def test_control_arbitrary_first_non_json_stdout_still_degrades(self):
        retry, delays, child, rows = self.worker(b'not an approved log prelude\n')
        self.assertEqual(rows[0][3:6], (None, 'degraded', 'keychain-malformed'))

    def test_control_banner_after_record_still_degrades(self):
        retry, delays, child, rows = self.worker(VALID_RECORD + BANNER)
        self.assertEqual(rows[0][3:6], (None, 'degraded', 'keychain-malformed'))

    def test_control_repeated_banner_still_degrades(self):
        retry, delays, child, rows = self.worker(BANNER + BANNER)
        self.assertEqual(rows[0][3:6], (None, 'degraded', 'keychain-malformed'))


if __name__ == '__main__': unittest.main()
