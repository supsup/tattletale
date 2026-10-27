#!/usr/bin/env python3
"""HUD (--hud) checks against a synthetic fixture database in a temp dir. No network, no TTY,
no watcher, no user data. Run: python3 -I tests/test_hud.py"""
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
DEAD = lambda pid: False


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
        snap = TT.hud_snapshot(self.db, state['cursor'], alive=DEAD)
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
        (self.dir / 'tattletale.pid').write_text(f'{os.getpid()}\n')
        snap = TT.hud_snapshot(self.db, None)                    # real os.kill(pid, 0) check
        self.assertEqual((snap['pid'], snap['pidSource'], snap['alive']), (os.getpid(), 'pid file', True))
        lines, _ = TT.hud_render(snap, TT.hud_new_state(), (80, 24), NOW)
        self.assertIn(f'watcher: running pid {os.getpid()} (pid file)  up 01:00:00', lines)
        self.event(conn, '2000-01-01T11:30:00Z', 'STOP', 'tattletale stopped')
        (self.dir / 'tattletale.pid').unlink()
        snap = TT.hud_snapshot(self.db, None, alive=lambda pid: True)
        lines, _ = TT.hud_render(snap, TT.hud_new_state(), (80, 24), NOW)
        self.assertIn('watcher not running (stopped after its START, pid 1)', lines)

    def test_missing_database_is_shown_and_not_created(self):
        lines, state = self.frame(TT.hud_new_state(), size=(400, 40))
        self.assertTrue(any(l.startswith('no database at ') and l.endswith('(waiting)') for l in lines))
        self.assertFalse(os.path.exists(self.db))
        self.assertEqual(state['cursor'], 0)    # a database that appears later is all new
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
            self.event(conn, '2000-01-01T11:01:00Z', 'CRED-NET', f'alert {n} ' + '宽' * 80 + ' \x1b[2J tail')
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
