#!/usr/bin/env python3
"""HUD (--hud) checks against a synthetic fixture database in a temp dir. No network, no TTY,
no watcher, no user data. Run: python3 -I tests/test_hud.py"""
import contextlib
import ctypes
import datetime as dt
import hashlib
import importlib.util
import io
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
with mock.patch.object(ctypes, 'CDLL', side_effect=OSError('fixture native loader disabled')):
    SPEC = importlib.util.spec_from_file_location('tattletale_hud_fixture', ROOT / 'python/tattletale.py')
    TT = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(TT)

NOW = dt.datetime(2000, 1, 1, 12, 0, 0, tzinfo=dt.timezone.utc)
DEAD = lambda pid: 'dead'


def width(line):
    return sum(TT._hud_width(c) for c in line)


class FakeTty(io.StringIO):
    def isatty(self):
        return True


class HudTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='tattletale-hud-')
        self.addCleanup(self.tmp.cleanup)
        self.dir = pathlib.Path(self.tmp.name)
        self.db = str(self.dir / 'fixture.db')

    def make_db(self):
        """The real schema, created by the watcher's own open_db; rows written by this test."""
        conn = TT.open_db(self.db)
        self.addCleanup(conn.close)
        return conn

    def event(self, conn, time, kind, message):
        conn.execute('INSERT INTO events(time, kind, message) VALUES (?,?,?)', (time, kind, message))

    def listener(self, conn, key, exposed, present, pid=4100, command='fixture-server'):
        conn.execute('INSERT INTO listeners(key, exe, address, port, command, pid, user, args, chain,'
                     ' exposed, present, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                     (key, '/fixture/bin/server', '*', 8000, command, pid, 'fixture', '', '', exposed,
                      present, '2000-01-01T11:00:00Z', '2000-01-01T11:00:00Z'))

    def frame(self, state, size=(100, 40), baseline=()):
        snap = TT.hud_snapshot(self.db, state['cursor'], state['recovery'], pid_status=DEAD)
        return TT.hud_render(snap, state, size, NOW, baseline)

    @staticmethod
    def pane(lines):
        start = next(i for i, l in enumerate(lines) if l.startswith('ALERTS since HUD start'))
        return lines[start + 1:]

    def test_two_refreshes_against_fixture(self):
        conn = self.make_db()
        self.event(conn, '2000-01-01T10:00:00Z', 'START', 'tattletale 0.0.2 pid 11 db x')
        self.event(conn, '2000-01-01T10:00:01Z', 'NEW-PROG', 'pid 12 user fixture /old/before-start | args: x')
        self.event(conn, '2000-01-01T11:00:00Z', 'START', 'tattletale 0.0.3 pid 4242 db x')
        self.event(conn, '2000-01-01T11:00:01Z', 'BASELINE', 'programs: 3 recorded')
        self.event(conn, '2000-01-01T11:00:02Z', 'NEW-PROG', 'pid 50 user fixture /fixture/bin/tool | args: --x')
        self.event(conn, '2000-01-01T11:00:03Z', 'NEW-PROG', 'pid 51 user fixture /fixture/bin/other | args: --y')
        self.event(conn, '2000-01-01T11:00:04Z', 'CREDENTIAL', 'pid 60 before the HUD started')
        self.listener(conn, '/fixture/bin/server *:8000', 1, 1)
        self.listener(conn, '/fixture/bin/server *:8001', 1, 0)           # exposed, gone
        self.listener(conn, '/fixture/bin/server 127.0.0.1:8002', 0, 1)   # present, loopback
        conn.execute('INSERT INTO credential_events(time, source, pid, user, exe, args, chain)'
                     ' VALUES (?,?,?,?,?,?,?)', ('2000-01-01T11:00:04Z', 'ps', 60, 'fixture',
                                                 '/fixture/bin/git-credential-fixture', 'get',
                                                 'git-credential-fixture(60) <- git(59)'))
        baseline_file = self.dir / 'baseline'
        baseline_file.write_text('# fixture baseline\nre:LISTEN! .*fixture-test-runner\n')
        baseline = TT.hud_load_baseline(str(baseline_file))

        lines0, state = self.frame(TT.hud_new_state(), baseline=baseline)   # the HUD starts here
        text0 = '\n'.join(lines0)
        self.assertIn('watcher not running (pid 4242 from START event is gone)', text0)
        self.assertIn('events since last start: NEW-PROG 2  BASELINE 1  CREDENTIAL 1  START 1', text0)
        self.assertIn('exposed on all interfaces (1):', text0)
        self.assertIn('  /fixture/bin/server *:8000  pid 4100  fixture-server', lines0)
        self.assertNotIn('*:8001', text0)
        self.assertNotIn('127.0.0.1:8002', text0)
        self.assertIn('git-credential-fixture', text0)
        self.assertIn('/fixture/bin/other', text0)
        self.assertEqual(self.pane(lines0), [])    # rows from before the HUD started are not alerts
        self.assertIn('ALERTS since HUD start (0): none yet', text0)

        self.event(conn, '2000-01-01T11:01:00Z', 'CREDENTIAL', 'pid 61 first-alert')
        self.event(conn, '2000-01-01T11:01:01Z', 'NEW-PROG', 'pid 62 user fixture /fixture/not-an-alert | args:')
        self.event(conn, '2000-01-01T11:01:02Z', 'IDENTITY', '/fixture/known | signer: Developer ID Application:'
                   ' Fixture Inc (ABCDE12345) team: ABCDE12345 | sha256: aa')
        self.event(conn, '2000-01-01T11:01:03Z', 'IDENTITY', '/fixture/mystery | signer: None team: None | sha256: failed')
        self.event(conn, '2000-01-01T11:01:04Z', 'LISTEN!', 'EXPOSED on all interfaces fixture-test-runner pid 70')
        self.event(conn, '2000-01-01T11:01:05Z', 'UNSIGNED', '/fixture/unsigned ran with no named signer (adhoc)')
        lines1, state = self.frame(state, baseline=baseline)
        pane1 = self.pane(lines1)
        self.assertEqual([l.split()[2] for l in pane1], ['CREDENTIAL', 'IDENTITY', 'LISTEN!', 'UNSIGNED'])
        self.assertIn('first-alert', pane1[0])
        self.assertTrue(pane1[0].startswith('ALERT 11:01:00 CREDENTIAL'))
        self.assertIn('/fixture/mystery', pane1[1])
        self.assertTrue(pane1[2].startswith('known 11:01:04 LISTEN!'))    # labelled by the baseline
        self.assertTrue(all(l.startswith('ALERT') for i, l in enumerate(pane1) if i != 2))
        self.assertFalse(any('not-an-alert' in l or '/fixture/known' in l for l in pane1))
        self.assertFalse(any('CRED-NET' in l for l in pane1))

        self.event(conn, '2000-01-01T11:02:00Z', 'CRED-NET', 'git-remote-https pid 80 second-refresh-only')
        self.event(conn, '2000-01-01T11:02:01Z', 'STARTUP~', 'changed: /fixture/plist')
        lines2, state = self.frame(state, baseline=baseline)
        pane2 = self.pane(lines2)
        self.assertEqual(pane2[:4], pane1)                         # nothing repeated or reordered
        self.assertEqual(len(pane2), 5)
        self.assertIn('second-refresh-only', pane2[-1])          # newest at the bottom
        self.assertEqual(sum('first-alert' in l for l in pane2), 1)
        self.assertFalse(any('STARTUP~' in l for l in pane2))
        self.assertIn('ALERTS since HUD start (5)', '\n'.join(lines2))
        lines3, state = self.frame(state, baseline=baseline)     # no new rows: identical pane
        self.assertEqual(self.pane(lines3), pane2)

    def test_absent_watcher_without_pid_or_start(self):
        conn = self.make_db()
        self.event(conn, '2000-01-01T11:00:00Z', 'NOTE', 'fixture')
        lines, _ = self.frame(TT.hud_new_state())
        self.assertIn('watcher not running (no pid file or START event)', lines)

    def test_pid_file_and_liveness(self):
        conn = self.make_db()
        self.event(conn, '2000-01-01T11:00:00Z', 'START', 'tattletale 0.0.3 pid 1 db x')
        pid_file = self.dir / 'tattletale.pid'
        # A live pid that is not a watcher: this test's own process (real kill(0) + ps check).
        pid_file.write_text(f'{os.getpid()}\n')
        snap = TT.hud_snapshot(self.db, None)
        self.assertEqual((snap['pid'], snap['pidSource'], snap['pidStatus']), (os.getpid(), 'pid file', 'other'))
        lines, _ = TT.hud_render(snap, TT.hud_new_state(), (80, 24), NOW)
        self.assertIn(f'watcher not running (pid {os.getpid()} alive but not tattletale)', lines)
        # A live pid whose command line names tattletale.py (a sleeping stand-in, not a watcher).
        child = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(60)',
                                  str(self.dir / 'tattletale.py')])
        self.addCleanup(child.wait)
        self.addCleanup(child.kill)
        pid_file.write_text(f'{child.pid}\n')
        snap = TT.hud_snapshot(self.db, None)
        self.assertEqual(snap['pidStatus'], 'tattletale')
        lines, _ = TT.hud_render(snap, TT.hud_new_state(), (80, 24), NOW)
        self.assertIn(f'watcher: running pid {child.pid} (pid file)  up 01:00:00', lines)
        child.kill()
        child.wait()
        self.assertEqual(TT.hud_pid_status(child.pid), 'dead')
        self.event(conn, '2000-01-01T11:30:00Z', 'STOP', 'tattletale stopped')
        pid_file.unlink()
        snap = TT.hud_snapshot(self.db, None, pid_status=lambda pid: 'tattletale')
        lines, _ = TT.hud_render(snap, TT.hud_new_state(), (80, 24), NOW)
        self.assertIn('watcher not running (stopped after its START, pid 1)', lines)

    def test_missing_database_is_shown_and_not_created(self):
        lines, state = self.frame(TT.hud_new_state(), size=(400, 40))
        self.assertTrue(any(l.startswith('no database at ') and l.endswith('(waiting)') for l in lines))
        self.assertFalse(os.path.exists(self.db))
        self.assertEqual(state['cursor'], TT.HUD_CURSOR_ZERO)    # a database that appears later is all new
        conn = self.make_db()
        self.event(conn, '2000-01-01T11:00:00Z', 'UNSIGNED', '/fixture/x ran with no named signer (adhoc)')
        lines, state = self.frame(state)
        self.assertEqual(len(self.pane(lines)), 1)

    def test_connection_is_read_only(self):
        self.assertIsNone(TT.hud_connect(self.db))
        self.assertFalse(os.path.exists(self.db))
        self.make_db()
        conn = TT.hud_connect(self.db)
        self.addCleanup(conn.close)
        with self.assertRaises(sqlite3.OperationalError) as caught:
            conn.execute("INSERT INTO events(time, kind, message) VALUES ('t', 'NOTE', 'x')")
        self.assertIn('readonly', str(caught.exception))
        conn.execute('PRAGMA query_only=OFF')          # the URI alone still refuses a write
        with self.assertRaises(sqlite3.OperationalError) as caught:
            conn.execute("INSERT INTO events(time, kind, message) VALUES ('t', 'NOTE', 'x')")
        self.assertIn('attempt to write a readonly database', str(caught.exception))

    def test_lines_never_exceed_width(self):
        conn = self.make_db()
        self.event(conn, '2000-01-01T11:00:00Z', 'START', 'tattletale 0.0.3 pid 4242 db ' + 'x' * 300)
        self.listener(conn, '/very/long/' + 'd' * 200 + ' *:8000', 1, 1, command='c' * 100)
        _, state = self.frame(TT.hud_new_state())
        for n in range(40):
            self.event(conn, '2000-01-01T11:01:00Z', 'CRED-NET', f'alert {n} ' + '\u5bbd' * 80 + ' \x1b[2J tail')
        for cols, rows in ((80, 24), (40, 24), (40, 10), (80, 6)):
            lines, _ = self.frame(dict(state), size=(cols, rows))
            self.assertLessEqual(len(lines), rows)
            for line in lines:
                self.assertLessEqual(width(line), cols, line)
                self.assertNotIn('\x1b', line)
            pane = self.pane(lines)
            self.assertTrue(pane[0].startswith('  (') and 'older not shown' in pane[0], pane)
            self.assertIn('alert 39', pane[-1])                    # newest kept, at the bottom
            hidden = int(pane[0].split('(')[1].split()[0])
            self.assertEqual(hidden + len(pane) - 1, 40)

    def test_hud_interval_below_two_is_rejected(self):
        for raw in ('1.99', '0', '-5', 'nan', 'inf', 'soon'):
            with self.assertRaises(TT.argparse.ArgumentTypeError):
                TT.hud_interval(raw)
        self.assertEqual(TT.hud_interval('2'), 2.0)
        r = subprocess.run([sys.executable, '-I', str(ROOT / 'python/tattletale.py'), '--db', self.db,
                            '--hud', '--hud-interval', '1'], capture_output=True, text=True, timeout=60,
                           env={'PATH': os.environ.get('PATH', ''), 'TATTLETALE_CONFIG': str(self.dir / 'none.env'),
                                'HOME': str(self.dir)})
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn('--hud-interval: must be at least 2 seconds', r.stderr)
        self.assertFalse(os.path.exists(self.db))

    def test_main_loop_writes_nothing_and_restores_cursor(self):
        conn = self.make_db()
        self.event(conn, '2000-01-01T11:00:00Z', 'START', 'tattletale 0.0.3 pid 4242 db x')
        conn.close()
        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.dir.iterdir()}
        out = FakeTty()
        ticks = []

        def sleep(seconds):
            ticks.append(seconds)
            if len(ticks) == 2:
                raise KeyboardInterrupt
        with mock.patch.object(TT.shutil, 'get_terminal_size', return_value=os.terminal_size((80, 24))):
            TT.hud_main(self.db, 3.0, str(self.dir / 'absent-baseline'), out=out, sleep=sleep,
                        clock=lambda: NOW)
        text = out.getvalue()
        self.assertEqual(ticks, [3.0, 3.0])
        self.assertTrue(text.startswith('\x1b[?25l\x1b[H\x1b[2J'))
        self.assertTrue(text.endswith('\x1b[?25h\n'))
        self.assertEqual(text.count('\x1b[H\x1b[2J'), 2)
        after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.dir.iterdir()}
        # The database and its WAL are byte-identical. A WAL reader (this HUD, like --query)
        # takes read marks in the -shm shared-memory index; that is SQLite coordination, not data.
        self.assertEqual(set(after), set(before))
        self.assertEqual({k: v for k, v in after.items() if not k.endswith('-shm')},
                         {k: v for k, v in before.items() if not k.endswith('-shm')})
        self.assertNotIn('tattletale.pid', after)

    # ---- alert continuity when SQLite reuses event ids (events has no AUTOINCREMENT) ----
    def watcher(self, retention_days):
        """The watcher's own Watch on the fixture, for its real log() and retain() paths only
        (no loop, no collectors, no notifications, no pid file)."""
        with contextlib.redirect_stdout(io.StringIO()):
            w = TT.Watch(str(self.dir / 'fixture.log'), self.db, notify=False, retention_days=retention_days)
        self.addCleanup(w.db.close)
        return w

    def quiet(self, fn, *args):
        with contextlib.redirect_stdout(io.StringIO()):
            return fn(*args)

    def fill_old(self, w, n, kind='NOTE', tag='old'):
        for i in range(n):
            self.event(w.db, '2000-01-01T10:00:00Z', kind, f'{tag} {i}')

    def snap_frame(self, state):
        snap = TT.hud_snapshot(self.db, state['cursor'], state['recovery'], pid_status=DEAD)
        lines, state = TT.hud_render(snap, state, (120, 60), NOW)
        return snap, self.pane(lines), state

    def shown_once(self, pane, needle):
        self.assertEqual(sum(needle in l for l in pane), 1, (needle, pane))

    def test_retention_id_reuse_new_alert_shown_once(self):
        # Lattice's sequence: a high cursor, retention empties events, a new alert gets a low id.
        w = self.watcher(retention_days=1)
        self.fill_old(w, 97)
        _, _, state = self.snap_frame(TT.hud_new_state())                      # HUD starts
        self.event(w.db, '2000-01-01T10:00:01Z', 'CREDENTIAL', 'pid 61 shown-before-retention-1')
        self.event(w.db, '2000-01-01T10:00:02Z', 'CRED-NET', 'pid 62 shown-before-retention-2')
        self.event(w.db, '2000-01-01T10:00:03Z', 'NOTE', 'old newest row')
        snap, pane1, state = self.snap_frame(state)
        self.assertEqual(state['cursor'][0], 100)
        self.assertEqual(len(pane1), 2)
        self.quiet(w.retain)                                                   # the real retention path
        self.assertEqual(w.db.execute('SELECT id, kind FROM events').fetchall(), [(1, 'RETENTION')])
        self.quiet(w.log, 'UNSIGNED', '/fixture/after-retention ran with no named signer (adhoc)')
        self.assertEqual(w.db.execute("SELECT id FROM events WHERE kind = 'UNSIGNED'").fetchone()[0], 2)
        snap, pane2, state = self.snap_frame(state)
        self.assertTrue(snap['reset'])
        snap, pane3, state = self.snap_frame(state)
        self.assertFalse(snap['reset'])
        # The reused LOW id itself is delivered (not only later high-id rows).
        self.assertEqual([a[0] for a in state['alerts']], [98, 99, 2])
        self.assertIn('/fixture/after-retention', state['alerts'][-1][3])
        for pane in (pane2, pane3):
            self.assertEqual(len(pane), 3, pane)
            self.assertEqual(pane[:2], pane1)                                  # no repeats
            self.shown_once(pane, '/fixture/after-retention')
        self.assertEqual(pane3, pane2)

    def test_retention_reset_between_redraws_ids_pass_old_cursor(self):
        # Between two redraws: retention empties the table and enough new rows arrive that ids
        # pass the old cursor again, so only the changed row at the cursor's id reveals it.
        w = self.watcher(retention_days=1)
        self.fill_old(w, 98)
        self.event(w.db, '2000-01-01T10:00:01Z', 'UNSIGNED', '/fixture/old ran with no named signer (adhoc)')
        _, _, state = self.snap_frame(TT.hud_new_state())
        self.event(w.db, '2000-01-01T10:00:02Z', 'LISTEN!', 'EXPOSED on all interfaces shown-early pid 9')
        _, pane1, state = self.snap_frame(state)
        self.assertEqual((state['cursor'][0], len(pane1)), (100, 1))
        self.quiet(w.retain)
        self.quiet(w.log, 'CREDENTIAL', 'pid 70 low-id-new-alert')             # id 2
        for i in range(150):
            self.quiet(w.log, 'NOTE', f'filler {i}')
        self.quiet(w.log, 'CRED-NET', 'pid 71 high-id-new-alert')              # id 153
        self.assertEqual(w.db.execute('SELECT max(id) FROM events').fetchone()[0], 153)
        snap, pane2, state = self.snap_frame(state)
        self.assertTrue(snap['reset'])
        _, pane3, state = self.snap_frame(state)
        self.assertEqual([a[0] for a in state['alerts']], [100, 2, 153])     # low id 2 delivered
        for pane in (pane2, pane3):
            self.assertEqual(len(pane), 3, pane)
            self.assertEqual(pane[0], pane1[0])
            self.shown_once(pane, 'low-id-new-alert')
            self.shown_once(pane, 'high-id-new-alert')
            self.assertLess(pane.index(next(l for l in pane if 'low-id' in l)),
                            pane.index(next(l for l in pane if 'high-id' in l)))

    def test_reset_recovery_pages_in_time_order_without_skipping_low_id(self):
        # Lattice 80 (HUD-H2): after a reset the producer can insert out of time order. A low-id
        # alert timed AFTER a full page of higher-id rows must still be delivered, exactly once.
        w = self.watcher(retention_days=1)
        self.fill_old(w, 97)
        _, _, state = self.snap_frame(TT.hud_new_state())
        self.event(w.db, '2000-01-01T10:00:01Z', 'CREDENTIAL', 'pid 61 shown-before-retention-1')
        self.event(w.db, '2000-01-01T10:00:02Z', 'CRED-NET', 'pid 62 shown-before-retention-2')
        self.event(w.db, '2000-01-01T10:00:03Z', 'NOTE', 'old newest row')          # cursor 100, T0
        _, pane1, state = self.snap_frame(state)
        self.assertEqual(state['cursor'][:2], (100, '2000-01-01T10:00:03Z'))
        self.quiet(w.retain)
        self.assertEqual(w.db.execute('SELECT id, kind FROM events').fetchall(), [(1, 'RETENTION')])
        T2, T3 = '2000-01-02T00:00:00Z', '2000-01-03T00:00:00Z'
        self.event(w.db, T3, 'CREDENTIAL', 'pid 90 low-id-late-time')                 # id 2 at T3
        page = TT.HUD_FETCH_LIMIT
        for i in range(page):                                                         # ids 3..2002 at T2
            self.event(w.db, T2, 'CRED-NET', f'bulk {i}')
        self.assertEqual(w.db.execute('SELECT max(id) FROM events').fetchone()[0], page + 2)
        with mock.patch.object(TT, 'HUD_KEEP_ALERTS', 100000):   # remember all, to check each one
            snap, _, state = self.snap_frame(state)
            self.assertTrue(snap['reset'])
            self.assertTrue(snap['recoveryFull'])
            self.event(w.db, T3, 'UNSIGNED', '/fixture/during-recovery ran with no named signer (adhoc)')
            _, _, state = self.snap_frame(state)
            _, _, state = self.snap_frame(state)
            self.assertIsNone(state['recovery'])
            delivered = [a[0] for a in state['alerts']]
            _, _, again = self.snap_frame(state)
        self.assertEqual(delivered, [98, 99] + list(range(3, page + 3)) + [2, page + 3])
        prints = [TT.hud_fingerprint(a) for a in state['alerts']]
        self.assertEqual(len(prints), len(set(prints)))      # ids 98 and 99 are reused: compare rows
        self.assertEqual(sum(a[3].startswith('bulk ') for a in state['alerts']), page)
        self.assertEqual([a[0] for a in again['alerts']], delivered)                  # nothing repeats
        self.assertEqual(again['older'], 0)
        self.assertIn('low-id-late-time', next(a for a in state['alerts'] if a[0] == 2)[3])

    def test_healthy_twin_without_retention(self):
        w = self.watcher(retention_days=0)                                     # 0 keeps events forever
        self.fill_old(w, 97)
        _, _, state = self.snap_frame(TT.hud_new_state())
        self.event(w.db, '2000-01-01T10:00:01Z', 'CREDENTIAL', 'pid 61 shown-before-retention-1')
        self.event(w.db, '2000-01-01T10:00:02Z', 'CRED-NET', 'pid 62 shown-before-retention-2')
        self.event(w.db, '2000-01-01T10:00:03Z', 'NOTE', 'old newest row')
        _, pane1, state = self.snap_frame(state)
        self.quiet(w.retain)
        self.assertEqual(w.db.execute('SELECT count(*) FROM events').fetchone()[0], 100)
        self.quiet(w.log, 'UNSIGNED', '/fixture/after-retention ran with no named signer (adhoc)')
        snap, pane2, state = self.snap_frame(state)
        self.assertFalse(snap['reset'])
        self.assertEqual(state['cursor'][0], 101)
        snap, pane3, state = self.snap_frame(state)
        self.assertFalse(snap['reset'])
        self.assertEqual(pane2[:2], pane1)
        self.assertEqual(pane3, pane2)
        self.assertEqual(len(pane2), 3)
        self.shown_once(pane2, '/fixture/after-retention')

    def test_sanitizer_replaces_bidi_zero_width_and_controls(self):
        hidden = ['\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2066', '\u2067', '\u2068',
                  '\u2069', '\u200b', '\u200c', '\u200d', '\u200e', '\u200f', '\u2028', '\u2029',
                  '\ufeff', '\u061c', '\u00ad', '\x00', '\x1b', '\x7f', '\x9b']
        for ch in hidden:
            self.assertIn(TT.unicodedata.category(ch), ('Cc', 'Cf', 'Zl', 'Zp'), repr(ch))
        conn = self.make_db()
        _, state = self.frame(TT.hud_new_state())
        # U+202E RIGHT-TO-LEFT OVERRIDE before "exe.live" would make "evil<RLO>exe.live" render
        # as "evil.exe"-looking text; it must come out as a visible '?' with the order intact.
        self.event(conn, '2000-01-01T11:01:00Z', 'UNSIGNED',
                   'pid 5 /tmp/evil\u202eexe.live ran with no named signer (adhoc)')
        self.event(conn, '2000-01-01T11:01:01Z', 'CRED-NET',
                   'mix ' + 'x'.join(hidden) + ' end caf\u00e9 \u0645\u0631\u062d\u0628\u0627 \u5bbd')
        lines, state = self.frame(state, size=(400, 40))
        pane = self.pane(lines)
        self.assertIn('/tmp/evil?exe.live', pane[0])
        for line in lines:
            for ch in hidden:
                self.assertNotIn(ch, line)
        self.assertIn('mix ' + 'x'.join('?' * len(hidden)) + ' end', pane[1])
        self.assertIn('caf\u00e9 \u0645\u0631\u062d\u0628\u0627 \u5bbd', pane[1])   # ordinary letters kept

    def test_initial_unreadable_frame_marks_the_start(self):
        pathlib.Path(self.db).write_bytes(b'not a database, ' * 64)
        lines, state = self.frame(TT.hud_new_state(), size=(300, 40))
        self.assertTrue(any(l.startswith('database unreadable: ') for l in lines), lines)
        self.assertIsNone(state['cursor'])
        os.unlink(self.db)
        conn = self.make_db()
        self.event(conn, '2000-01-01T11:00:00Z', 'UNSIGNED', '/fixture/during-unreadable ran (adhoc)')
        lines, state = self.frame(state)               # first readable frame: the start mark
        self.assertEqual(self.pane(lines), [])
        self.event(conn, '2000-01-01T11:00:01Z', 'UNSIGNED', '/fixture/after-start ran (adhoc)')
        lines, state = self.frame(state)
        self.assertEqual(len(self.pane(lines)), 1)
        self.assertIn('/fixture/after-start', self.pane(lines)[0])

    def test_health_sidecar_age_and_stale(self):
        self.make_db()
        def health_line(generated):
            body = {'generatedAt': generated, 'collectionHealth': {
                k: {'status': 'ok', 'error': None, 'lastAttempt': None, 'lastSuccess': None}
                for k in ('processes', 'listeners', 'startup', 'crontab')}}
            (self.dir / 'tattletale-data.js').write_text('window.TATTLETALE = ' + TT.json.dumps(body) + ';\n')
            lines, _ = self.frame(TT.hud_new_state())
            return next(l for l in lines if l.startswith('collection health:'))
        self.assertEqual(health_line('2000-01-01T11:59:00Z'), 'collection health: all ok (as of 11:59:00)')
        self.assertEqual(health_line('2000-01-01T11:50:00Z'), 'collection health: all ok (as of 11:50:00, STALE)')
        self.assertIn('time unknown: may be stale', health_line(None))

    def test_baseline_file_format(self):
        path = self.dir / 'b'
        path.write_text('# comment\n\n  plain substring  \nre:^LISTEN! .*java\n')
        baseline = TT.hud_load_baseline(str(path))
        self.assertTrue(TT.hud_known(baseline, 'x plain substring y'))
        self.assertTrue(TT.hud_known(baseline, 'LISTEN! EXPOSED java pid 1'))
        self.assertFalse(TT.hud_known(baseline, 'CRED-NET java'))
        self.assertEqual(TT.hud_load_baseline(str(self.dir / 'missing')), [])
        path.write_text('re:(\n')
        with self.assertRaises(SystemExit):
            TT.hud_load_baseline(str(path))
        example = ROOT / 'tattletale.hud-baseline.example'
        self.assertTrue(TT.hud_load_baseline(str(example)))


if __name__ == '__main__':
    unittest.main(verbosity=2)
