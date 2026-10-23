"""Synthetic real-method controls. No watcher loop, host collectors, or user data."""
import contextlib
import copy
import ctypes
import importlib.util
import io
import json
import pathlib
import sqlite3
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / 'tests/fixtures/collection-health.json').read_text())
with mock.patch.object(ctypes, 'CDLL', side_effect=OSError('fixture native loader disabled')):
    SPEC = importlib.util.spec_from_file_location('tattletale_health_fixture', ROOT / 'python/tattletale.py')
    TT = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(TT)
T0 = FIXTURE['clock']
T1 = '2000-01-01T00:01:00Z'
REAL_PID_PATH = TT.pid_path
PS_COMM = ('ps', '-axo', 'pid=,ppid=,user=,comm=')
PS_ARGS = ('ps', '-axo', 'pid=,args=')
LSOF = ('lsof', '-nP', '-iTCP', '-sTCP:LISTEN', '-F', 'pcn')
CRON = ('crontab', '-l')
LISTENER = 'p42\ncfixture\nn127.0.0.1:12345\n'
KEY = '/fixture/service 127.0.0.1:12345'


def completed(argv, code=0, out='', err=''):
    return subprocess.CompletedProcess(argv, code, out.encode() if isinstance(out, str) else out,
                                       err.encode() if isinstance(err, str) else err)


class CollectionHealthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='collection-health-')
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(TT, 'now', return_value=T0))
        self.stack.enter_context(mock.patch.object(TT, 'STARTUP_DIRS', []))
        self.stack.enter_context(mock.patch.object(TT, 'STARTUP_FILES', []))
        self.stack.enter_context(mock.patch.object(TT, 'pid_path', return_value=None))
        self.run_mock = self.stack.enter_context(mock.patch.object(
            TT.subprocess, 'run', side_effect=AssertionError('unexpected real collector')))
        self.stack.enter_context(mock.patch.object(
            TT.subprocess, 'Popen', side_effect=AssertionError('background process forbidden')))
        self.w = TT.Watch(str(self.root / 'fixture.log'), str(self.root / 'fixture.db'), notify=False)
        self.addCleanup(self.w.db.close)
        self.w.load_state()

    @contextlib.contextmanager
    def commands(self, responses):
        def fake(argv, **kwargs):
            key = tuple(argv)
            if key not in responses:
                raise AssertionError('unexpected synthetic collector: ' + repr(key))
            result = responses[key]
            if isinstance(result, BaseException):
                raise result
            return completed(argv, *result)
        with mock.patch.object(TT.subprocess, 'run', side_effect=fake) as calls:
            yield calls

    def ps_responses(self):
        return {PS_COMM: (0, '42 1 fixture /fixture/service\n', ''),
                PS_ARGS: (0, '42 /fixture/service --public-fixture\n', '')}

    def seed_listener(self, address='127.0.0.1', present=1):
        key = '/fixture/service ' + address + ':12345'
        self.w.db.execute('INSERT OR REPLACE INTO listeners VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                          (key, '/fixture/service', address, 12345, 'fixture', 42, 'fixture', '', '?',
                           int(address in ('*', '0.0.0.0', '::', '[::]')), present, T0, T0))
        self.w.load_state()
        return key

    def seed_startup(self):
        self.w.db.execute('INSERT INTO startup_items VALUES (?,?,?)', ('/fixture/old.rc', 'a' * 64, T0))
        self.w.db.execute('INSERT INTO startup_items VALUES (?,?,?)', ('crontab -l', 'none', T0))
        self.w.load_state()
        self.w.crontab_text = 'accepted fixture text'

    def inventory(self):
        tables = ['programs', 'sightings', 'listeners', 'credential_events', 'startup_items',
                  'startup_versions', 'events']
        return {'db': {t: self.w.db.execute('SELECT * FROM ' + t).fetchall() for t in tables},
                'known': set(self.w.known_progs), 'listeners': copy.deepcopy(self.w.listeners),
                'startup': dict(self.w.startup), 'previous': copy.deepcopy(self.w.prev_pids),
                'cred_seen': set(self.w.cred_seen_pids), 'announce': dict(self.w.announce),
                'dirty_progs': dict(self.w.dirty_progs), 'dirty_listeners': dict(self.w.dirty_listeners),
                'baseline': dict(self.w.baseline), 'queue': list(self.w.ident_q.queue),
                'crontab_text': self.w.crontab_text}

    def assert_degraded(self, key):
        h = self.w.collection_health[key]
        self.assertEqual(h['status'], 'degraded')
        self.assertEqual(h['lastAttempt'], T0)
        self.assertIsNone(h['lastSuccess'])
        self.assertTrue(h['error'])
        self.assertLessEqual(len(h['error']), 64)

    def test_failed_empty_lsof_preserves_real_inventory(self):
        self.seed_listener()
        before = self.inventory()
        with self.commands({LSOF: (7, '', '')}):
            self.assertFalse(self.w.check_listeners())
        self.assertEqual(before, self.inventory())
        self.assert_degraded('listeners')

    def test_partial_lsof_valid_prefix_has_no_effect(self):
        self.seed_listener()
        for suffix in ['pbad\n', 'p43\n', 'n127.0.0.1:bad\n', 'qunsupported\n']:
            before = self.inventory()
            with self.commands({LSOF: (0, LISTENER + suffix, '')}):
                self.assertFalse(self.w.check_listeners())
            self.assertEqual(before, self.inventory())

    def test_listener_enrichment_failure_keeps_keys(self):
        self.seed_listener()
        before = self.inventory()
        with self.commands({LSOF: (0, LISTENER, ''), PS_COMM: (7, '', '')}):
            self.assertFalse(self.w.check_listeners())
        self.assertEqual(before, self.inventory())

    def test_lsof_exit0_warning_preserves_every_listener_and_reports_distinct_code(self):
        self.seed_listener(); before = self.inventory()
        self.w.collection_health['listeners']['lastSuccess'] = T1
        for diagnostic in ['WARNING: cannot stat synthetic storage\n', 'unrecognized diagnostic', '\n']:
            with self.commands({LSOF: (0, LISTENER, diagnostic)}) as calls:
                self.assertFalse(self.w.check_listeners())
            expected = copy.deepcopy(before)
            expected['db']['events'] = [(1, T0, 'NOTE', 'listeners collection degraded: lsof-warning')]
            self.assertEqual(expected, self.inventory())
            self.assertEqual(self.w.collection_health['listeners']['status'], 'degraded')
            self.assertEqual(self.w.collection_health['listeners']['error'], 'lsof-warning')
            self.assertEqual(self.w.collection_health['listeners']['lastSuccess'], T1)
            self.assertEqual([tuple(c.args[0]) for c in calls.call_args_list], [LSOF])
        responses = self.ps_responses(); responses[LSOF] = (0, LISTENER, '')
        with self.commands(responses): self.assertTrue(self.w.check_listeners())
        after_recovery = self.inventory()
        with self.commands({LSOF: (0, LISTENER, 'WARNING: public fixture\n')}): self.assertFalse(self.w.check_listeners())
        expected = copy.deepcopy(after_recovery)
        expected['db']['events'] = [(1, T0, 'NOTE', 'listeners collection degraded: lsof-warning'),
                                    (2, T0, 'NOTE', 'listeners collection degraded: lsof-warning')]
        self.assertEqual(expected, self.inventory())

    def test_listener_missing_identity_rejects_sample(self):
        self.seed_listener()
        before = self.inventory()
        responses = self.ps_responses()
        responses[PS_COMM] = (0, '99 1 fixture /fixture/other\n', '')
        responses[LSOF] = (0, LISTENER, '')
        responses[('ps', '-o', 'comm=', '-p', '42')] = (7, '', '')
        with self.commands(responses):
            self.assertFalse(self.w.check_listeners())
        self.assertEqual(before, self.inventory())

    def test_listener_recovery_does_not_emit_false_transition(self):
        self.seed_listener()
        with self.commands({LSOF: (7, '', '')}):
            self.assertFalse(self.w.check_listeners())
        responses = self.ps_responses(); responses[LSOF] = (0, LISTENER, '')
        with self.commands(responses), mock.patch.object(TT, 'now', return_value=T1):
            self.assertTrue(self.w.check_listeners())
        self.assertEqual(self.w.collection_health['listeners']['lastSuccess'], T1)
        self.assertEqual(self.w.db.execute('SELECT count(*) FROM events').fetchone()[0], 0)
        with self.commands({LSOF: (0, '', '')}):
            self.assertTrue(self.w.check_listeners())
            self.assertTrue(self.w.check_listeners())
        self.assertEqual(self.w.db.execute("SELECT count(*) FROM events WHERE kind='UNLISTEN'").fetchone()[0], 1)

    def test_listener_rollback_preserves_mirrors_and_events(self):
        self.seed_listener()
        self.w.db.execute("CREATE TRIGGER refuse_listener BEFORE UPDATE ON listeners BEGIN SELECT RAISE(ABORT,'fixture rollback'); END")
        before = self.inventory()
        with self.commands({LSOF: (0, '', '')}):
            self.assertFalse(self.w.check_listeners())
        self.assertEqual(before, self.inventory())
        self.assertEqual(self.w.collection_health['listeners']['error'], 'collection-db')

    def test_each_ps_producer_failure_preserves_all_state(self):
        for failed in [PS_COMM, PS_ARGS]:
            before = self.inventory(); responses = self.ps_responses()
            responses[failed] = (7, 'fake private diagnostic', 'fake private diagnostic')
            with self.commands(responses):
                self.assertFalse(self.w.check_processes())
            self.assertEqual(before, self.inventory())
            self.assert_degraded('processes')
            self.assertNotIn('private', self.w.collection_health['processes']['error'])

    def test_ps_partial_and_bad_encoding_preserve_all_state(self):
        for output in ['42 1 fixture /fixture/service\nmalformed\n', b'42 1 fixture /fixture/\xff\n', '']:
            before = self.inventory(); responses = self.ps_responses(); responses[PS_COMM] = (0, output, '')
            with self.commands(responses):
                self.assertFalse(self.w.check_processes())
            self.assertEqual(before, self.inventory())

    def test_ps_normal_race_and_defunct_are_supported(self):
        responses = {PS_COMM: (0, '42 1 fixture /fixture/service\n43 1 fixture (exiting)\n', ''),
                     PS_ARGS: (0, '99 /fixture/already-exited\n43\n', '')}
        with self.commands(responses):
            self.assertTrue(self.w.check_processes())
        self.assertEqual(self.w.prev_pids, {42: '/fixture/service'})
        self.assertEqual(self.w.db.execute('SELECT count(*) FROM programs').fetchone()[0], 1)
        self.assertEqual(self.w.collection_health['processes']['status'], 'ok')

    def test_process_rollback_has_no_identity_queue_or_baseline_effect(self):
        self.w.known_progs = {"/fixture/old"}
        self.w.prev_pids = {7: "/fixture/old"}
        self.w.cred_seen_pids = {7}
        self.w.dirty_progs = {"/fixture/old": T1}
        self.w.announce = {"/fixture/old": "public fixture"}
        self.w.ident_q.put("/fixture/old")
        self.w.baseline["programs"] = False
        self.w.db.execute("CREATE TRIGGER refuse_program BEFORE INSERT ON programs BEGIN SELECT RAISE(ABORT,'fixture rollback'); END")
        before = self.inventory()
        with self.commands(self.ps_responses()):
            self.assertFalse(self.w.check_processes())
        self.assertEqual(before, self.inventory())

    def test_process_recovery_records_once_after_failure(self):
        with self.commands({PS_COMM: (7, '', '')}):
            self.assertFalse(self.w.check_processes())
        with self.commands(self.ps_responses()):
            self.assertTrue(self.w.check_processes())
            self.assertTrue(self.w.check_processes())
        self.assertEqual(self.w.db.execute('SELECT count(*) FROM sightings').fetchone()[0], 1)
        self.assertEqual(list(self.w.ident_q.queue), ['/fixture/service'])

    def test_startup_directory_failure_keeps_files_but_attempts_crontab(self):
        self.seed_startup(); before = dict(self.w.startup)
        with mock.patch.object(TT, 'STARTUP_DIRS', ['/fixture/unreadable']), mock.patch.object(
                TT.os, 'listdir', side_effect=PermissionError('fake private filename')), self.commands(
                {CRON: (0, '* * * * * fixture\n', '')}) as calls:
            self.assertFalse(self.w.check_startup())
        self.assertEqual(self.w.startup['/fixture/old.rc'], before['/fixture/old.rc'])
        self.assert_degraded('startup')
        self.assertEqual(self.w.collection_health['crontab']['status'], 'ok')
        self.assertEqual(self.w.collection_health['crontab']['lastAttempt'], T0)
        self.assertEqual(self.w.crontab_text, '* * * * * fixture\n')
        self.assertEqual([tuple(c.args[0]) for c in calls.call_args_list], [CRON])

    def test_startup_late_permission_marker_does_not_hide_readable_peer(self):
        self.seed_startup(); first = self.root / 'first'; second = self.root / 'second'
        first.write_bytes(b'public fixture'); second.write_bytes(b'public fixture')
        original = open
        def read_file(path, *args, **kwargs):
            if str(path) == str(second): raise PermissionError('fake private path')
            return original(path, *args, **kwargs)
        with mock.patch.object(TT, 'STARTUP_FILES', [str(first), str(second)]), mock.patch('builtins.open', side_effect=read_file), self.commands({CRON: (1, '', 'no crontab for fixture\n')}):
            self.assertFalse(self.w.check_startup())
        self.assertEqual(self.w.startup[str(first)], TT.hashlib.sha256(first.read_bytes()).hexdigest())
        self.assertEqual(self.w.startup[str(second)], 'unreadable: permission-denied')
        self.assertEqual(self.w.collection_health['startup']['error'], 'startup-unreadable')
        self.assertIsNone(self.w.collection_health['startup']['lastSuccess'])
        self.assertEqual(self.w.collection_health['crontab']['status'], 'ok')
        self.assertIsNone(self.w.db.execute('SELECT copy_path FROM startup_versions WHERE path=?', (str(second),)).fetchone()[0])

    def test_startup_optional_missing_is_accepted(self):
        with mock.patch.object(TT, 'STARTUP_DIRS', [str(self.root / 'missing-dir')]), mock.patch.object(
                TT, 'STARTUP_FILES', [str(self.root / 'missing-file')]), self.commands({CRON: (1, '', 'no crontab for fixture\n')}):
            self.assertTrue(self.w.check_startup())
        self.assertEqual(self.w.startup, {'crontab -l': 'none'})
        self.assertEqual(self.w.collection_health['startup']['status'], 'ok')
        self.assertEqual(self.w.collection_health['crontab']['status'], 'ok')

    def test_optional_broken_source_or_ancestor_is_not_absence(self):
        self.seed_startup()
        broken = self.root / 'broken'; broken.symlink_to(self.root / 'missing-target')
        for name in ['STARTUP_DIRS', 'STARTUP_FILES']:
            for path in [broken, broken / 'child']:
                with mock.patch.object(TT, name, [str(path)]), self.commands({CRON: (1, '', 'no crontab for fixture\n')}):
                    self.assertFalse(self.w.check_startup())
                expected = 'startup-unreadable' if name == 'STARTUP_FILES' and path == broken else 'startup-read'
                self.assertEqual(self.w.collection_health['startup']['error'], expected)
                self.assertEqual(self.w.collection_health['crontab']['status'], 'ok')

    def test_crontab_timeout_preserves_only_cron_and_good_files_adopt(self):
        self.seed_startup(); previous = self.w.crontab_text
        for key in ['startup', 'crontab']: self.w.collection_health[key]['lastSuccess'] = T1
        with self.commands({CRON: subprocess.TimeoutExpired(['crontab', '-l'], 20)}):
            self.assertFalse(self.w.check_startup())
        self.assertEqual(self.w.startup, {'crontab -l': 'none'})
        self.assertEqual(self.w.crontab_text, previous)
        self.assertEqual(self.w.collection_health['crontab']['status'], 'degraded')
        self.assertEqual(self.w.collection_health['crontab']['lastSuccess'], T1)
        self.assertEqual(self.w.collection_health['startup']['status'], 'ok')
        self.assertEqual(self.w.collection_health['startup']['lastSuccess'], T0)

    def test_startup_rollback_preserves_text_versions_events_and_baseline(self):
        self.seed_startup()
        self.w.db.execute("CREATE TRIGGER refuse_startup BEFORE DELETE ON startup_items BEGIN SELECT RAISE(ABORT,'fixture rollback'); END")
        before = self.inventory()
        with self.commands({CRON: (0, '', '')}):
            self.assertFalse(self.w.check_startup())
        self.assertEqual(before, self.inventory())
        for key in ['startup', 'crontab']: self.assert_degraded(key)

    def test_startup_recovery_accepts_real_file_once(self):
        source = self.root / 'public.rc'; source.write_bytes(b'public synthetic fixture\n')
        with mock.patch.object(TT, 'STARTUP_FILES', [str(source)]), self.commands({CRON: (1, '', 'no crontab for fixture\n')}):
            self.assertTrue(self.w.check_startup())
            count = self.w.db.execute('SELECT count(*) FROM startup_versions').fetchone()[0]
            self.assertTrue(self.w.check_startup())
        self.assertEqual(count, self.w.db.execute('SELECT count(*) FROM startup_versions').fetchone()[0])
        self.assertEqual(self.w.startup[str(source)], TT.hashlib.sha256(source.read_bytes()).hexdigest())

    def test_format2_health_serialization_keeps_database_schema1(self):
        self.seed_listener('192.0.2.10')
        with self.commands({LSOF: (7, '', 'fake private diagnostic')}): self.w.check_listeners()
        with TT.lock: page = self.w.page_map()
        self.w.write_page_data(str(self.root), page)
        raw = (self.root / 'tattletale-data.js').read_text()
        payload = json.loads(raw[len('window.TATTLETALE = '):-2])
        self.assertEqual(payload['formatVersion'], 2)
        self.assertEqual(payload['generatedAt'], T0)
        self.assertEqual(set(payload['collectionHealth']), set(TT.CHECKS))
        self.assertNotIn('private', json.dumps(payload['collectionHealth']))
        self.assertEqual(payload['collectionHealth']['processes']['status'], 'unknown')
        self.assertEqual(self.w.db.execute('SELECT max(version) FROM schema_version').fetchone()[0], 1)
        self.assertEqual(next(iter(payload['map']['listeners'].values()))['bindScope'], 'non-loopback')

    def test_bracketed_ipv4_is_not_an_ip_literal(self):
        self.assertEqual(TT.bind_scope('[127.0.0.1]'), 'unknown')

    def test_checked_per_pid_comm_can_preserve_listener_key(self):
        self.seed_listener()
        responses = self.ps_responses()
        responses[PS_COMM] = (0, '99 1 fixture /fixture/other\n', '')
        responses[LSOF] = (0, LISTENER, '')
        responses[('ps', '-o', 'comm=', '-p', '42')] = (0, '/fixture/service\n', '')
        with self.commands(responses): self.assertTrue(self.w.check_listeners())
        self.assertEqual(self.w.db.execute('SELECT present FROM listeners WHERE key=?', (KEY,)).fetchone()[0], 1)
        self.assertEqual(self.w.db.execute('SELECT count(*) FROM events').fetchone()[0], 0)

    def test_checked_comm_preserves_executable_spaces(self):
        exe = '/fixture/Example App.app/service'
        key = exe + ' 127.0.0.1:12345'
        self.w.db.execute('INSERT INTO listeners VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                          (key, exe, '127.0.0.1', 12345, 'fixture', 42, 'fixture', '', '?', 0, 1, T0, T0))
        self.w.load_state()
        responses = self.ps_responses()
        responses[PS_COMM] = (0, '99 1 fixture /fixture/other\n', '')
        responses[LSOF] = (0, LISTENER, '')
        responses[('ps', '-o', 'comm=', '-p', '42')] = (0, exe + '\n', '')
        with self.commands(responses): self.assertTrue(self.w.check_listeners())
        self.assertEqual(set(self.w.listeners), {key})
        self.assertTrue(self.w.listeners[key]['present'])
        self.assertEqual(self.w.db.execute('SELECT count(*) FROM events').fetchone()[0], 0)

    def test_lsof_optional_file_descriptors_accept_complete_records(self):
        self.seed_listener()
        responses = self.ps_responses()
        responses[LSOF] = (0, 'p42\ncfixture\nf10\nn127.0.0.1:12345\nf11\nn[::1]:54321\n', '')
        with self.commands(responses): self.assertTrue(self.w.check_listeners())
        self.assertTrue(self.w.listeners[KEY]['present'])
        self.assertTrue(self.w.listeners['/fixture/service [::1]:54321']['present'])
        self.assertEqual(self.w.collection_health['listeners']['status'], 'ok')

    def test_lsof_incomplete_descriptor_preserves_entire_sample(self):
        self.seed_listener()
        before = self.inventory()
        for suffix in ['f11\n', 'f11\nf12\n', 'f11\np43\ncnext\nn127.0.0.1:10\n', 'fbad\n']:
            with self.commands({LSOF: (0, 'p42\ncfixture\nf10\nn127.0.0.1:12345\n' + suffix, '')}):
                self.assertFalse(self.w.check_listeners())
            self.assertEqual(before, self.inventory())
            self.assertEqual(self.w.collection_health['listeners']['error'], 'lsof-parse')

    def test_ps_args_partial_and_empty_are_degraded(self):
        for output in ['42 /fixture/service\nbad\n', b'42 /fixture/\xff\n', '']:
            before = self.inventory(); responses = self.ps_responses(); responses[PS_ARGS] = (0, output, '')
            with self.commands(responses): self.assertFalse(self.w.check_processes())
            self.assertEqual(before, self.inventory())

    def test_identity_announcement_completion_is_not_overwritten(self):
        self.w.announce['/fixture/old'] = 'public fixture'
        self.w.announce['/fixture/pending'] = 'public pending fixture'
        self.w.baseline['programs'] = False
        original = TT.transaction
        @contextlib.contextmanager
        def completed_identity(conn):
            self.w.announce.pop('/fixture/old', None)
            with original(conn) as value: yield value
        with self.commands(self.ps_responses()), mock.patch.object(TT, 'transaction', completed_identity):
            self.assertTrue(self.w.check_processes())
        self.assertNotIn('/fixture/old', self.w.announce)
        self.assertEqual(self.w.announce['/fixture/pending'], 'public pending fixture')
        self.assertIn('/fixture/service', self.w.announce)

    def test_startup_copy_failure_after_crontab_preserves_everything(self):
        self.seed_startup(); source = self.root / 'public.rc'; source.write_bytes(b'public fixture')
        before = self.inventory()
        with mock.patch.object(TT, 'STARTUP_FILES', [str(source)]), self.commands({CRON: (0, '', '')}), mock.patch.object(
                self.w, 'keep_copy', side_effect=OSError('public simulated copy failure')):
            self.assertFalse(self.w.check_startup())
        self.assertEqual(before, self.inventory())
        for key in ['startup', 'crontab']: self.assert_degraded(key)

    def test_mapped_wildcard_and_invalid_literal_edges(self):
        for host in ['::ffff:0.0.0.0', '[::ffff:0.0.0.0]']:
            self.assertEqual(TT.bind_scope(host), 'wildcard')
        for host in ['[127.0.0.1]', ' 127.0.0.1', '::1%', '::ffff:127.000.0.1', '[[::1]]']:
            self.assertEqual(TT.bind_scope(host), 'unknown')

    def test_process_event_insert_failure_rolls_back_nonempty_sample(self):
        self.w.announce['/fixture/old'] = 'public fixture'
        self.w.cred_seen_pids = {7}; self.w.prev_pids = {7: '/fixture/old'}
        self.w.ident_q.put('/fixture/old'); self.w.baseline['programs'] = False
        self.w.db.execute("CREATE TRIGGER refuse_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'fixture event rollback'); END")
        before = self.inventory()
        with self.commands(self.ps_responses()): self.assertFalse(self.w.check_processes())
        self.assertEqual(before, self.inventory())
        self.assertEqual(self.w.collection_health['processes']['error'], 'collection-db')

    def test_listener_event_insert_failure_rolls_back_present_listener(self):
        self.seed_listener()
        self.w.db.execute("CREATE TRIGGER refuse_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'fixture event rollback'); END")
        before = self.inventory()
        with self.commands({LSOF: (0, '', '')}): self.assertFalse(self.w.check_listeners())
        self.assertEqual(before, self.inventory())

    def test_startup_event_insert_failure_rolls_back_nonempty_inventory(self):
        self.seed_startup(); source = self.root / 'public.rc'; source.write_bytes(b'public fixture')
        self.w.db.execute("CREATE TRIGGER refuse_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'fixture event rollback'); END")
        before = self.inventory()
        with mock.patch.object(TT, 'STARTUP_FILES', [str(source)]), self.commands({CRON: (1, '', 'no crontab for fixture\n')}):
            self.assertFalse(self.w.check_startup())
        self.assertEqual(before, self.inventory())
        for key in ['startup', 'crontab']: self.assert_degraded(key)

    def test_large_startup_hashes_full_bytes_file_copy_capped_crontab_full(self):
        data = b'x' * (4 * 1024 * 1024 + 1)
        source = self.root / 'large-public.rc'; source.write_bytes(data)
        with mock.patch.object(TT, 'STARTUP_FILES', [str(source)]), self.commands({CRON: (0, data, b'')}):
            self.assertTrue(self.w.check_startup())
        expected = TT.hashlib.sha256(data).hexdigest()
        self.assertEqual(self.w.startup[str(source)], expected)
        self.assertEqual(self.w.startup['crontab -l'], expected)
        copies = dict(self.w.db.execute('SELECT path,copy_path FROM startup_versions'))
        self.assertEqual(pathlib.Path(copies[str(source)]).read_bytes(), data[:4 * 1024 * 1024])
        self.assertEqual(pathlib.Path(copies['crontab -l']).read_bytes(), data)

    def test_commit_failure_rolls_back_inventory_events_mirrors_then_recovers(self):
        self.w.db.execute('PRAGMA foreign_keys=ON')
        self.w.db.execute('CREATE TABLE fixture_parent(id INTEGER PRIMARY KEY)')
        self.w.db.execute('CREATE TABLE fixture_child(id INTEGER REFERENCES fixture_parent(id) DEFERRABLE INITIALLY DEFERRED)')
        self.w.db.execute('CREATE TRIGGER fixture_deferred AFTER INSERT ON programs BEGIN INSERT INTO fixture_child VALUES(1); END')
        self.w.baseline['programs'] = False
        self.w.prev_pids = {7: '/fixture/old'}; self.w.cred_seen_pids = {7}
        self.w.announce['/fixture/old'] = 'public fixture'; self.w.ident_q.put('/fixture/old')
        before = self.inventory()
        with self.commands(self.ps_responses()): self.assertFalse(self.w.check_processes())
        self.assertFalse(self.w.db.in_transaction)
        self.assertEqual(self.w.db.execute('SELECT count(*) FROM fixture_child').fetchone()[0], 0)
        self.assertEqual(before, self.inventory())
        self.assertEqual(self.w.collection_health['processes']['error'], 'collection-db')
        self.w.db.execute('DROP TRIGGER fixture_deferred')
        with self.commands(self.ps_responses()): self.assertTrue(self.w.check_processes())
        self.assertFalse(self.w.db.in_transaction)
        self.assertIn('/fixture/service', self.w.known_progs)
        self.assertEqual(self.w.db.execute('SELECT count(*) FROM events').fetchone()[0], 1)

    def test_corrupt_existing_copy_rejects_until_external_repair(self):
        self.seed_startup(); before = self.inventory()
        data = b'complete public synthetic fixture\n'
        source = self.root / 'public.rc'; source.write_bytes(data)
        digest = TT.hashlib.sha256(data).hexdigest()
        directory = pathlib.Path(self.w.snap_dir) / self.w.safe_name(str(source))
        directory.mkdir(parents=True)
        dest = directory / digest[:16]; dest.write_bytes(b'partial')
        with mock.patch.object(TT, 'STARTUP_FILES', [str(source)]), self.commands({CRON: (1, '', 'no crontab for fixture\n')}):
            self.assertFalse(self.w.check_startup())
            after = self.inventory()
            self.assertEqual({p: h for p, h in before['startup'].items() if p != 'crontab -l'},
                             {p: h for p, h in after['startup'].items() if p != 'crontab -l'})
            self.assertEqual(before['db']['startup_versions'], after['db']['startup_versions'])
            self.assertEqual(before['db']['events'], after['db']['events'])
            self.assertEqual(self.w.collection_health['crontab']['status'], 'ok')
            self.assertEqual(dest.read_bytes(), b'partial')
            self.assertEqual(self.w.collection_health['startup']['status'], 'degraded')
            dest.write_bytes(data)  # Explicit synthetic operator repair, outside collector.
            self.assertTrue(self.w.check_startup())
        self.assertEqual(dest.read_bytes(), data)
        self.assertEqual(list(directory.iterdir()), [dest])
        self.assertEqual(self.w.startup[str(source)], digest)

    def test_rollback_failure_closes_connection_and_preserves_primary_error(self):
        class FailedRollback:
            def __init__(self, conn): self.conn = conn; self.closed = False
            def execute(self, sql):
                if sql == 'ROLLBACK': raise sqlite3.OperationalError('injected rollback failure')
                return self.conn.execute(sql)
            def close(self): self.closed = True; self.conn.close()
            @property
            def in_transaction(self): return self.conn.in_transaction
        conn = sqlite3.connect(':memory:', isolation_level=None)
        conn.execute('PRAGMA foreign_keys=ON')
        conn.execute('CREATE TABLE parent(id INTEGER PRIMARY KEY)')
        conn.execute('CREATE TABLE child(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED)')
        wrapped = FailedRollback(conn)
        with self.assertRaises(TT.FatalDatabaseError) as commit_failure:
            with TT.transaction(wrapped) as c: c.execute('INSERT INTO child VALUES(1)')
        self.assertIsInstance(commit_failure.exception.__cause__, sqlite3.IntegrityError)
        self.assertTrue(wrapped.closed)
        with self.assertRaises(sqlite3.ProgrammingError): conn.execute('SELECT 1')
        wrapped = FailedRollback(sqlite3.connect(':memory:', isolation_level=None))
        original = ValueError('public synthetic body failure')
        with self.assertRaises(TT.FatalDatabaseError) as caught:
            with TT.transaction(wrapped): raise original
        self.assertIs(caught.exception.__cause__, original)
        self.assertTrue(wrapped.closed)

    def test_atomic_copy_publish_failure_preserves_state_and_recovers(self):
        self.seed_startup(); before = self.inventory()
        data = b'complete public synthetic fixture\n'
        source = self.root / 'public.rc'; source.write_bytes(data)
        digest = TT.hashlib.sha256(data).hexdigest()
        directory = pathlib.Path(self.w.snap_dir) / self.w.safe_name(str(source))
        dest = directory / digest[:16]
        with mock.patch.object(TT, 'STARTUP_FILES', [str(source)]), self.commands({CRON: (1, '', 'no crontab for fixture\n')}):
            with mock.patch.object(TT.os, 'link', side_effect=OSError('public fixture publish failure')):
                self.assertFalse(self.w.check_startup())
            self.assertFalse(dest.exists())
            self.assertEqual(list(directory.iterdir()), [])
            after = self.inventory()
            self.assertEqual({p: h for p, h in before['startup'].items() if p != 'crontab -l'},
                             {p: h for p, h in after['startup'].items() if p != 'crontab -l'})
            self.assertEqual(before['db']['startup_versions'], after['db']['startup_versions'])
            self.assertEqual(before['db']['events'], after['db']['events'])
            self.assertEqual(self.w.collection_health['crontab']['status'], 'ok')
            self.assertTrue(self.w.check_startup())
        self.assertEqual(dest.read_bytes(), data)
        self.assertEqual(self.w.startup[str(source)], digest)

    def test_existing_mismatch_is_never_replaced(self):
        data = b'complete public synthetic fixture\n'
        digest = TT.hashlib.sha256(data).hexdigest()
        directory = pathlib.Path(self.w.snap_dir) / self.w.safe_name('/fixture/public.rc')
        directory.mkdir(parents=True)
        dest = directory / digest[:16]; dest.write_bytes(b'existing partial fixture')
        with mock.patch.object(TT.os, 'link', side_effect=AssertionError('existing target must not publish')):
            with self.assertRaises(OSError): self.w.keep_copy('/fixture/public.rc', digest, data)
        self.assertEqual(dest.read_bytes(), b'existing partial fixture')
        self.assertEqual(list(directory.iterdir()), [dest])
        dest.write_bytes(data)  # Explicit fixture repair, not collector behavior.
        self.assertEqual(self.w.keep_copy('/fixture/public.rc', digest, data), str(dest))
        self.assertEqual(dest.read_bytes(), data)

    def test_existing_symlink_copy_rejects_without_reading_target(self):
        data = b'public fixture'; digest = TT.hashlib.sha256(data).hexdigest()
        directory = pathlib.Path(self.w.snap_dir) / self.w.safe_name('/fixture/public.rc')
        directory.mkdir(parents=True); target = self.root / 'public-target'; target.write_bytes(data)
        dest = directory / digest[:16]; dest.symlink_to(target)
        with mock.patch.object(TT.os, 'link', side_effect=AssertionError('symlink target must not publish')):
            with self.assertRaises(OSError): self.w.keep_copy('/fixture/public.rc', digest, data)
        self.assertTrue(dest.is_symlink())
        self.assertEqual(target.read_bytes(), data)

    def test_no_overwrite_publication_race_compares_existing_bytes(self):
        data = b'public fixture'; digest = TT.hashlib.sha256(data).hexdigest()
        directory = pathlib.Path(self.w.snap_dir) / self.w.safe_name('/fixture/public.rc')
        def race(source, dest):
            pathlib.Path(dest).write_bytes(data)
            raise FileExistsError('public fixture destination race')
        with mock.patch.object(TT.os, 'link', side_effect=race):
            dest = self.w.keep_copy('/fixture/public.rc', digest, data)
        self.assertEqual(pathlib.Path(dest).read_bytes(), data)
        self.assertEqual(list(directory.iterdir()), [pathlib.Path(dest)])

    def test_no_overwrite_publication_race_refuses_different_bytes(self):
        data = b'public fixture'; digest = TT.hashlib.sha256(data).hexdigest()
        directory = pathlib.Path(self.w.snap_dir) / self.w.safe_name('/fixture/public.rc')
        def race(source, dest):
            pathlib.Path(dest).write_bytes(b'existing concurrent fixture')
            raise FileExistsError('public fixture destination race')
        with mock.patch.object(TT.os, 'link', side_effect=race):
            with self.assertRaises(OSError): self.w.keep_copy('/fixture/public.rc', digest, data)
        dest = directory / digest[:16]
        self.assertEqual(dest.read_bytes(), b'existing concurrent fixture')
        self.assertEqual(list(directory.iterdir()), [dest])

    def test_partial_copy_write_failure_leaves_no_final_or_pending_copy(self):
        data = b'complete public synthetic fixture\n'
        digest = TT.hashlib.sha256(data).hexdigest()
        directory = pathlib.Path(self.w.snap_dir) / self.w.safe_name('/fixture/public.rc')
        original = TT.os.fdopen
        class PartialWrite:
            def __init__(self, fd, mode): self.file = original(fd, mode)
            def __enter__(self): return self
            def write(self, value):
                self.file.write(value[:3])
                raise OSError('public injected partial write')
            def __exit__(self, *args): self.file.close()
        with mock.patch.object(TT.os, 'fdopen', side_effect=PartialWrite):
            with self.assertRaises(OSError): self.w.keep_copy('/fixture/public.rc', digest, data)
        self.assertEqual(list(directory.iterdir()), [])
        dest = self.w.keep_copy('/fixture/public.rc', digest, data)
        self.assertEqual(pathlib.Path(dest).read_bytes(), data)


    def test_unreadable_entries_keep_peers_and_never_invent_copies(self):
        directory = self.root / 'agents'; directory.mkdir()
        good = directory / 'a.plist'; good.write_bytes(b'a0')
        denied = directory / 'denied'; denied.write_bytes(b'private synthetic fixture')
        (directory / 'sub.bundle').mkdir()
        (directory / 'dangling').symlink_to(directory / 'missing')
        original = open
        def read(path, *args, **kwargs):
            if str(path) == str(denied): raise PermissionError('not a health diagnostic')
            return original(path, *args, **kwargs)
        with mock.patch.object(TT, 'STARTUP_DIRS', [str(directory)]), mock.patch('builtins.open', side_effect=read), self.commands({CRON: (1, '', 'no crontab for fixture\n')}):
            self.assertFalse(self.w.check_startup())
        expected = {str(denied): 'unreadable: permission-denied', str(directory / 'sub.bundle'): 'unreadable: directory', str(directory / 'dangling'): 'unreadable: dangling-link'}
        for path, digest in expected.items():
            self.assertEqual(self.w.startup[path], digest)
            self.assertIsNone(self.w.db.execute('SELECT copy_path FROM startup_versions WHERE path=?', (path,)).fetchone()[0])
        self.assertEqual(self.w.startup[str(good)], TT.hashlib.sha256(b'a0').hexdigest())
        self.assertFalse(self.w.baseline['startup'])
        self.assertEqual(self.w.collection_health['startup']['error'], 'startup-unreadable')
        self.assertIsNone(self.w.collection_health['startup']['lastSuccess'])
        self.assertEqual(self.w.collection_health['crontab']['status'], 'ok')

    def test_transient_read_or_listed_disappearance_preserves_all_files(self):
        self.seed_startup(); old = self.w.startup['/fixture/old.rc']
        directory = self.root / 'agents'; directory.mkdir(); path = directory / 'a'; path.write_bytes(b'a0')
        original = open
        for error in [OSError(5, 'public injected EIO'), FileNotFoundError('public disappearing file')]:
            def read(candidate, *args, **kwargs):
                if str(candidate) == str(path): raise error
                return original(candidate, *args, **kwargs)
            with mock.patch.object(TT, 'STARTUP_DIRS', [str(directory)]), mock.patch('builtins.open', side_effect=read), self.commands({CRON: (0, '* * * * * fixture\n', '')}):
                self.assertFalse(self.w.check_startup())
            self.assertEqual(self.w.startup['/fixture/old.rc'], old)
            self.assertNotIn(str(path), self.w.startup)
            self.assertEqual(self.w.collection_health['startup']['error'], 'startup-read')
            self.assertEqual(self.w.collection_health['crontab']['status'], 'ok')
            self.assertEqual(self.w.db.execute("SELECT count(*) FROM events WHERE kind='STARTUP-'").fetchone()[0], 0)

    def test_marker_recovery_retains_good_history_and_advances_success_once(self):
        path = self.root / 'a'; path.write_bytes(b'a0')
        original = open
        with mock.patch.object(TT, 'STARTUP_FILES', [str(path)]), self.commands({CRON: (1, '', 'no crontab for fixture\n')}):
            self.assertTrue(self.w.check_startup())
            first = self.w.db.execute('SELECT copy_path FROM startup_versions WHERE path=?', (str(path),)).fetchone()[0]
            def denied(candidate, *args, **kwargs):
                if str(candidate) == str(path): raise PermissionError('public fixture')
                return original(candidate, *args, **kwargs)
            with mock.patch('builtins.open', side_effect=denied), mock.patch.object(TT, 'now', return_value=T1):
                self.assertFalse(self.w.check_startup())
            self.assertEqual(self.w.collection_health['startup']['lastSuccess'], T0)
            with mock.patch.object(TT, 'now', return_value='2000-01-01T00:02:00Z'):
                self.assertTrue(self.w.check_startup())
                self.assertTrue(self.w.check_startup())
        self.assertEqual(pathlib.Path(first).read_bytes(), b'a0')
        rows = self.w.db.execute('SELECT hash,copy_path FROM startup_versions WHERE path=? ORDER BY id', (str(path),)).fetchall()
        self.assertEqual(len(rows), 3)
        self.assertIsNone(rows[1][1])
        self.assertEqual(self.w.collection_health['startup']['lastSuccess'], '2000-01-01T00:02:00Z')
        messages = [r[0] for r in self.w.db.execute("SELECT message FROM events WHERE kind='STARTUP~' ORDER BY id")]
        self.assertEqual(len(messages), 2)
        self.assertIn('before: None', messages[1])

    def test_independent_first_baselines_and_attempt_order(self):
        path = self.root / 'a'; path.write_bytes(b'a0'); trace = []
        original_files = self.w._startup_files
        def files(): trace.append('files'); return original_files()
        def cron(): trace.append('cron'); return ('none', '')
        with mock.patch.object(TT, 'STARTUP_FILES', [str(path)]), mock.patch.object(self.w, '_startup_files', side_effect=files), self.commands({CRON: (7, '', '')}):
            self.assertFalse(self.w.check_startup())
        self.assertFalse(self.w.baseline['startup']); self.assertTrue(self.w.baseline['crontab'])
        with mock.patch.object(TT, 'STARTUP_FILES', [str(path)]), mock.patch.object(self.w, '_startup_files', side_effect=files), mock.patch.object(self.w, '_crontab_sample', side_effect=cron):
            self.assertTrue(self.w.check_startup())
        self.assertEqual(trace, ['files', 'files', 'cron'])
        self.assertFalse(self.w.baseline['crontab'])
        self.assertEqual([r[0].split(':', 1)[0] for r in self.w.db.execute("SELECT message FROM events WHERE kind='BASELINE' ORDER BY id")], ['startup items', 'crontab'])
        self.assertEqual(self.w.collection_health['crontab']['lastAttempt'], T0)

    def test_attempt_and_sampling_order_survives_filesystem_rejection(self):
        trace = []; original = self.w._attempt
        def attempted(name): trace.append('attempt-' + name); original(name)
        def files(): trace.append('files'); raise TT.CollectionError('startup-read')
        def cron(): trace.append('cron'); return ('none', '')
        with mock.patch.object(self.w, '_attempt', side_effect=attempted), mock.patch.object(self.w, '_startup_files', side_effect=files), mock.patch.object(self.w, '_crontab_sample', side_effect=cron):
            self.assertFalse(self.w.check_startup())
        self.assertEqual(trace, ['attempt-startup', 'files', 'attempt-crontab', 'cron'])
        self.assertEqual(self.w.collection_health['startup']['lastAttempt'], T0)
        self.assertEqual(self.w.collection_health['crontab']['lastAttempt'], T0)

    def test_failed_filesystem_baseline_does_not_consume_peer_baseline(self):
        with mock.patch.object(self.w, '_startup_files', side_effect=TT.CollectionError('startup-read')), self.commands({CRON: (1, '', 'no crontab for fixture\n')}):
            self.assertFalse(self.w.check_startup())
        self.assertTrue(self.w.baseline['startup']); self.assertFalse(self.w.baseline['crontab'])
        self.assertEqual(self.w.collection_health['startup']['lastAttempt'], T0)
        self.assertEqual(self.w.collection_health['crontab']['lastAttempt'], T0)
        with self.commands({CRON: (1, '', 'no crontab for fixture\n')}): self.assertTrue(self.w.check_startup())
        self.assertEqual([r[0].split(':', 1)[0] for r in self.w.db.execute("SELECT message FROM events WHERE kind='BASELINE' ORDER BY id")], ['crontab', 'startup items'])

    def test_peer_db_failure_preserves_independent_collection_error(self):
        self.seed_startup(); before = self.inventory()
        self.w.db.execute("CREATE TRIGGER no_peer BEFORE INSERT ON startup_items BEGIN SELECT RAISE(ABORT,'public fixture'); END")
        with mock.patch.object(self.w, '_startup_files', side_effect=TT.CollectionError('startup-read')), self.commands({CRON: (0, '* * * * * fixture\n', '')}):
            self.assertFalse(self.w.check_startup())
        self.assertEqual(before, self.inventory())
        self.assertEqual(self.w.collection_health['startup']['error'], 'startup-read')
        self.assertEqual(self.w.collection_health['crontab']['error'], 'collection-db')

    def test_filesystem_copy_failure_keeps_files_and_commits_good_cron(self):
        self.seed_startup(); old = dict(self.w.startup); original = self.w.keep_copy
        source = self.root / 'new.rc'; source.write_bytes(b'new public file')
        body = '* * * * * fixture\n'; later = '2000-01-01T00:02:00Z'
        for name in ['startup', 'crontab']: self.w.collection_health[name]['lastSuccess'] = T1
        def copy_file(path, digest, data=None):
            if path != 'crontab -l': raise OSError('public filesystem copy failure')
            return original(path, digest, data)
        with mock.patch.object(TT, 'STARTUP_FILES', [str(source)]), mock.patch.object(self.w, 'keep_copy', side_effect=copy_file), mock.patch.object(TT, 'now', return_value=later), self.commands({CRON: (0, body, '')}):
            self.assertFalse(self.w.check_startup())
        self.assertEqual(self.w.startup['/fixture/old.rc'], old['/fixture/old.rc'])
        self.assertNotIn(str(source), self.w.startup)
        self.assertEqual(self.w.crontab_text, body)
        self.assertEqual(self.w.startup['crontab -l'], TT.hashlib.sha256(body.encode()).hexdigest())
        self.assertEqual(self.w.collection_health['startup']['error'], 'collection-io')
        self.assertEqual(self.w.collection_health['startup']['lastSuccess'], T1)
        self.assertEqual(self.w.collection_health['crontab']['lastSuccess'], later)
        self.assertEqual([r[0] for r in self.w.db.execute('SELECT path FROM startup_versions')], ['crontab -l'])
        self.assertEqual([r[0] for r in self.w.db.execute('SELECT message FROM events')], [
            'changed: crontab -l | before: ' + str(pathlib.Path(self.w.snap_dir) / 'crontab_-l' / 'none') + ' | after: ' + str(pathlib.Path(self.w.snap_dir) / 'crontab_-l' / TT.hashlib.sha256(body.encode()).hexdigest()[:16]) + '\n(no text diff: binary or missing copy)'])

    def test_cron_copy_failure_keeps_cron_and_commits_good_files(self):
        self.seed_startup(); old = dict(self.w.startup); old_text = self.w.crontab_text
        original = self.w.keep_copy; source = self.root / 'new.rc'; source.write_bytes(b'new public file')
        body = '* * * * * fixture\n'; later = '2000-01-01T00:02:00Z'
        self.w.collection_health['crontab']['lastSuccess'] = T1
        def copy_file(path, digest, data=None):
            if path == 'crontab -l': raise OSError('public cron copy failure')
            return original(path, digest, data)
        with mock.patch.object(TT, 'STARTUP_FILES', [str(source)]), mock.patch.object(self.w, 'keep_copy', side_effect=copy_file), mock.patch.object(TT, 'now', return_value=later), self.commands({CRON: (0, body, '')}):
            self.assertFalse(self.w.check_startup())
        self.assertNotIn('/fixture/old.rc', self.w.startup)
        self.assertIn(str(source), self.w.startup)
        self.assertEqual(self.w.startup['crontab -l'], old['crontab -l'])
        self.assertEqual(self.w.crontab_text, old_text)
        self.assertEqual(self.w.collection_health['crontab']['error'], 'collection-io')
        self.assertEqual(self.w.collection_health['crontab']['lastSuccess'], T1)
        self.assertEqual(self.w.collection_health['startup']['lastSuccess'], later)
        self.assertEqual([r[0] for r in self.w.db.execute('SELECT path FROM startup_versions')], [str(source)])
        self.assertTrue(all('crontab -l' not in row[0] for row in self.w.db.execute('SELECT message FROM events')))

    def test_copy_failure_preserves_independent_first_baseline(self):
        source = self.root / 'first.rc'; source.write_bytes(b'first public file'); original = self.w.keep_copy
        def copy_file(path, digest, data=None):
            if path != 'crontab -l': raise OSError('public first copy failure')
            return original(path, digest, data)
        with mock.patch.object(TT, 'STARTUP_FILES', [str(source)]), self.commands({CRON: (1, '', 'no crontab for fixture\n')}):
            with mock.patch.object(self.w, 'keep_copy', side_effect=copy_file): self.assertFalse(self.w.check_startup())
            self.assertTrue(self.w.baseline['startup']); self.assertFalse(self.w.baseline['crontab'])
            self.assertTrue(self.w.check_startup())
        self.assertFalse(self.w.baseline['startup'])
        self.assertEqual([r[0] for r in self.w.db.execute('SELECT kind FROM events')], ['BASELINE', 'BASELINE'])

    def test_removed_unreadable_marker_never_claims_a_saved_copy(self):
        self.w.db.execute('INSERT INTO startup_items VALUES(?,?,?)', ('/fixture/unreadable', 'unreadable: directory', T0))
        self.w.db.execute('INSERT INTO startup_items VALUES(?,?,?)', ('crontab -l', 'none', T0))
        self.w.load_state()
        with self.commands({CRON: (1, '', 'no crontab for fixture\n')}): self.assertTrue(self.w.check_startup())
        self.assertEqual(self.w.db.execute("SELECT message FROM events WHERE kind='STARTUP-'").fetchone()[0], 'removed: /fixture/unreadable | last copy: None')

    def test_collectors_normalize_both_streams_keep_locale_and_file_bytes(self):
        for newline in ['\r\n', '\r', '\n']:
            with self.commands({CRON: (1, b'', ('no crontab for fixture' + newline).encode())}) as calls:
                self.assertTrue(self.w.check_startup())
            self.assertEqual(self.w.startup['crontab -l'], 'none')
            self.assertEqual(calls.call_args.kwargs['env']['LC_ALL'], 'C')
        raw = b'public\r\nraw\rbytes'; path = self.root / 'raw'; path.write_bytes(raw)
        with mock.patch.object(TT, 'STARTUP_FILES', [str(path)]), self.commands({CRON: (0, b'public\r\ncron\rbytes', b'')}):
            self.assertTrue(self.w.check_startup())
        self.assertEqual(self.w.crontab_text, 'public\ncron\nbytes')
        self.assertEqual(self.w.startup['crontab -l'], TT.hashlib.sha256(b'public\ncron\nbytes').hexdigest())
        self.assertEqual(self.w.startup[str(path)], TT.hashlib.sha256(raw).hexdigest())

    def test_automatic_rollback_keeps_connection_usable_and_recovers(self):
        self.w.db.execute("CREATE TRIGGER auto_rollback BEFORE INSERT ON programs BEGIN SELECT RAISE(ROLLBACK,'original fixture'); END")
        before = self.inventory()
        with self.commands(self.ps_responses()): self.assertFalse(self.w.check_processes())
        self.assertFalse(self.w.db.in_transaction); self.assertEqual(before, self.inventory())
        self.w.db.execute('DROP TRIGGER auto_rollback')
        with self.commands(self.ps_responses()): self.assertTrue(self.w.check_processes())

    def test_fatal_lifecycle_propagates_and_releases_owned_resources_with_fakes(self):
        trace = []
        with self.assertRaises(TT.FatalDatabaseError) as caught: fatal_lifecycle_fixture(trace)
        self.assertEqual(str(caught.exception), 'fixture-primary-fatal')
        self.assertIn('stream-terminate', trace); self.assertIn('stream-wait', trace)
        self.assertEqual(trace.count('join'), 2)
        self.assertIn('close-db', trace); self.assertEqual(trace[-1], 'release-owned-pid')

    def test_bare_listener_fallback_cannot_replace_full_key(self):
        self.seed_listener(); before = self.inventory(); responses = self.ps_responses()
        responses[PS_COMM] = (0, '99 1 fixture /fixture/other\n', '')
        responses[LSOF] = (0, LISTENER, '')
        responses[('ps', '-o', 'comm=', '-p', '42')] = (0, 'bare-command\n', '')
        with self.commands(responses): self.assertFalse(self.w.check_listeners())
        self.assertEqual(before, self.inventory())

    def test_ps1_is_validated_before_ps2(self):
        responses = {PS_COMM: (0, 'malformed\n', ''), PS_ARGS: subprocess.TimeoutExpired(list(PS_ARGS), 20)}
        with self.commands(responses) as calls: self.assertFalse(self.w.check_processes())
        self.assertEqual([tuple(c.args[0]) for c in calls.call_args_list], [PS_COMM])
        self.assertEqual(self.w.collection_health['processes']['error'], 'ps-parse')

    def test_bounded_ascii_pids_before_bridge_or_database(self):
        for value in ['0', '-1', '2147483648', '9223372036854775808', '9' * 200, '\u0664\u0662']:
            for exe in ['/fixture/service', 'bare']:
                before = self.inventory(); responses = self.ps_responses()
                responses[PS_COMM] = (0, value + ' 1 fixture ' + exe + '\n', '')
                with self.commands(responses), mock.patch.object(TT, 'pid_path', side_effect=AssertionError('invalid PID reached bridge')):
                    self.assertFalse(self.w.check_processes())
                self.assertEqual(before, self.inventory())
            self.seed_listener(); before = self.inventory()
            with self.commands({LSOF: (0, 'p' + value + '\ncfixture\nn127.0.0.1:12345\n', '')}), mock.patch.object(TT, 'pid_path', side_effect=AssertionError('invalid lsof PID reached bridge')):
                self.assertFalse(self.w.check_listeners())
            self.assertEqual(before, self.inventory())
        responses = {PS_COMM: (0, '2147483647 0 fixture /fixture/service\n', ''), PS_ARGS: (0, '2147483647\n', '')}
        with self.commands(responses): self.assertTrue(self.w.check_processes())
        for ppid in ['-1', '2147483648']:
            responses[PS_COMM] = (0, '42 ' + ppid + ' fixture /fixture/service\n', '')
            with self.commands(responses): self.assertFalse(self.w.check_processes())

    def test_internal_blank_lsof_rejects_and_input_errors_degrade(self):
        self.seed_listener(); before = self.inventory()
        for output in ['\n' + LISTENER, LISTENER + '\n', LISTENER.replace('cfixture\n', 'cfixture\n\n')]:
            with self.commands({LSOF: (0, output, '')}): self.assertFalse(self.w.check_listeners())
            self.assertEqual(before, self.inventory())
        for error in [TypeError('fixture'), KeyError('fixture'), OverflowError('fixture'), ctypes.ArgumentError('fixture')]:
            with mock.patch.object(self.w, 'processes', side_effect=error): self.assertFalse(self.w.check_processes())
            self.assertEqual(before, self.inventory())
            self.assertEqual(self.w.collection_health['processes']['error'], 'collection-parse')

    def test_numeric_bounds_preserve_leading_zeros_and_reject_bad_argv_pids(self):
        responses = {PS_COMM: (0, '00000000000042 0000 fixture /fixture/service\n', ''), PS_ARGS: (0, '00000000000042\n', '')}
        with self.commands(responses): self.assertTrue(self.w.check_processes())
        for value in ['0', '2147483648', '9' * 200, '\u0664\u0662']:
            before = self.inventory(); responses[PS_ARGS] = (0, value + '\n', '')
            with self.commands(responses): self.assertFalse(self.w.check_processes())
            self.assertEqual(before, self.inventory())
        responses = self.ps_responses(); responses[LSOF] = (0, 'p00000000000042\ncfixture\nn127.0.0.1:0000000012345\n', '')
        with self.commands(responses): self.assertTrue(self.w.check_listeners())
        self.assertEqual(self.w.db.execute('SELECT port FROM listeners').fetchone()[0], 12345)

    def test_pid_bridge_rejects_invalid_values_without_native_call(self):
        lib = mock.Mock(); lib.proc_pidpath.return_value = 0
        with mock.patch.object(TT, '_libproc', lib):
            for value in [True, 0, -1, 2147483648, 2 ** 100, '42']:
                with self.assertRaises(TT.CollectionError): REAL_PID_PATH(value)
            lib.proc_pidpath.assert_not_called()
            self.assertIsNone(REAL_PID_PATH(2147483647))
            self.assertEqual(lib.proc_pidpath.call_count, 1)

    def test_startup_transition_ledger_and_restart_order(self):
        transitions = startup_transition_snapshots()
        self.assertEqual(len(transitions), 8)
        self.assertEqual(transitions[-1]['startupKeys'], ['/fixture/b', '/fixture/c', '/fixture/z', 'crontab -l'])

    def test_old_database_export_order_does_not_depend_on_rowids(self):
        for path in ['/fixture/z', '/fixture/a', '/fixture/c']:
            self.w.db.execute('INSERT INTO startup_items VALUES(?,?,?)', (path, 'fixture', T0))
        self.w.load_state()
        with TT.lock: page = self.w.page_map()
        self.assertEqual(list(page['startup']), ['/fixture/a', '/fixture/c', '/fixture/z'])

    def test_pid_file_unknown_refuses_takeover_and_positive_evidence_allows(self):
        path = self.root / 'tattletale.pid'; path.write_text('43\n')
        argv = ('ps', '-p', '43', '-o', 'command=')
        for response in [(7, '', ''), (0, '', ''), (0, 'other\n', 'diagnostic'), (1, '', 'diagnostic'), (0, 'one\ntwo\n', ''), subprocess.TimeoutExpired(list(argv), 20), OSError('public fixture')]:
            with self.commands({argv: response}), mock.patch.object(TT.os, 'getpid', return_value=4242):
                with self.assertRaises(SystemExit): self.w.claim_pid_file()
            self.assertEqual(path.read_text(), '43\n')
        with self.commands({argv: (0, b'/fixture/tattletale.py \xff\r\n', b'')}), mock.patch.object(TT.os, 'getpid', return_value=4242):
            with self.assertRaises(SystemExit): self.w.claim_pid_file()
        self.assertEqual(path.read_text(), '43\n')
        for response in [(1, '', ''), (0, '/fixture/other\n', '')]:
            path.write_text('43\n')
            with self.commands({argv: response}), mock.patch.object(TT.os, 'getpid', return_value=4242): self.w.claim_pid_file()
            self.assertEqual(path.read_text(), '4242\n')
        for value in ['', 'bad', '2147483648', '\u0664\u0662']:
            path.write_text(value)
            with self.assertRaises(SystemExit): self.w.claim_pid_file()
            self.assertEqual(path.read_text(), value)


def scope_case(case):
    def test(self):
        key = self.seed_listener(case['host'])
        with TT.lock: page = self.w.page_map()
        self.assertEqual(page['listeners'][key]['bindScope'], case['expected'])
    return test


def command_case(case):
    def test(self):
        before = self.inventory()
        command = LSOF if case['tool'] == 'lsof' else CRON
        with self.commands({command: (case['code'], case['out'], case['err'])}):
            ok = self.w.check_listeners() if case['tool'] == 'lsof' else self.w.check_startup()
        self.assertEqual(ok, case['expected'].startswith('ok'))
        key = 'listeners' if case['tool'] == 'lsof' else 'crontab'
        self.assertEqual(self.w.collection_health[key]['status'], 'ok' if ok else 'degraded')
        if not ok:
            if case['tool'] == 'lsof':
                if case['code'] == 0 and case['err']:
                    expected = copy.deepcopy(before)
                    expected['db']['events'] = [(1, T0, 'NOTE', 'listeners collection degraded: lsof-warning')]
                    self.assertEqual(expected, self.inventory())
                else: self.assertEqual(before, self.inventory())
            else:
                self.assertEqual(self.w.crontab_text, before['crontab_text'])
                self.assertEqual(self.w.startup.get('crontab -l'), before['startup'].get('crontab -l'))
        if case['expected'] == 'ok-absent': self.assertEqual(self.w.startup['crontab -l'], 'none')
    return test


for index, case in enumerate(FIXTURE['scopeCases']):
    setattr(CollectionHealthTests, 'test_scope_%02d' % index, scope_case(case))
for index, case in enumerate(FIXTURE['commandCases']):
    setattr(CollectionHealthTests, 'test_command_%02d' % index, command_case(case))


def fatal_lifecycle_fixture(trace):
    """Run only lifecycle control flow on fakes: no Watch instance or real thread/process."""
    class Stop:
        def is_set(self): return False
        def set(self): trace.append('stop-workers')
        def wait(self, seconds): raise AssertionError('fatal fixture must not poll again')
    class Worker:
        def __init__(self, **kwargs): pass
        def start(self): trace.append('start-fake-worker')
        def join(self, **kwargs): trace.append('join')
    class Stream:
        def poll(self): return None
        def terminate(self): trace.append('stream-terminate')
        def wait(self, **kwargs): trace.append('stream-wait')
    class Database:
        def close(self): trace.append('close-db'); raise OSError('public cleanup fixture')
    class Lifecycle:
        stop = Stop(); stream_proc = Stream(); db = Database()
        log_path = '/fixture/log'; db_path = '/fixture/db'
        def claim_pid_file(self): trace.append('claim-fake-pid')
        def install_dashboard(self): pass
        def load_state(self): pass
        def retain(self): pass
        def log_stream(self): raise AssertionError('fake thread target must not run')
        def identity_worker(self): raise AssertionError('fake thread target must not run')
        def check_processes(self): raise TT.FatalDatabaseError('fixture-primary-fatal')
        def save(self): raise TT.FatalDatabaseError('fixture-cleanup-fatal')
        def log(self, kind, message):
            trace.append('log-' + kind)
            if kind == 'STOP': raise OSError('public cleanup fixture')
        def release_pid_file(self): trace.append('release-owned-pid')
        def _safe(self, name, fn): return TT.Watch._safe(self, name, fn)
    with mock.patch.object(TT.threading, 'Thread', Worker): TT.Watch.run(Lifecycle())


def parity_snapshots():
    """Actual check/page-map results; public logical paths, deterministic clock."""
    command_results = []
    for fixture in FIXTURE['commandCases']:
        case = CollectionHealthTests('test_failed_empty_lsof_preserves_real_inventory')
        case.setUp()
        try:
            command = LSOF if fixture['tool'] == 'lsof' else CRON
            with case.commands({command: (fixture['code'], fixture['out'], fixture['err'])}):
                ok = case.w.check_listeners() if fixture['tool'] == 'lsof' else case.w.check_startup()
            actual = 'degraded' if not ok else ('ok-absent' if fixture['tool'] == 'crontab'
                     and case.w.startup['crontab -l'] == 'none' else 'ok-empty')
            command_results.append(dict(fixture, actual=actual))
            del command_results[-1]['expected']
        finally:
            case.doCleanups()
    case = CollectionHealthTests('test_failed_empty_lsof_preserves_real_inventory')
    case.setUp()
    try:
        w = case.w
        case.seed_listener('127.0.0.1')
        w.db.execute("UPDATE listeners SET key=?,exe=?", ('/fixture/a 127.0.0.1:12345', '/fixture/a'))
        w.load_state()
        w.baseline = {'programs': False, 'listeners': False, 'startup': False, 'crontab': False}
        w.snap_dir = '/fixture/copies'
        w.keep_copy = lambda path, digest, data=None: '/fixture/copies/' + TT.Watch.safe_name(path) + '/' + digest[:16]
        w.diff = lambda *args: '(fixture diff)'
        snapshots = []
        def snap(name):
            with TT.lock: page = w.page_map()
            snapshots.append({'name': name, 'collectionHealth': copy.deepcopy(w.collection_health),
                              'map': page, 'events': [{'kind': r[0], 'message': r[1]} for r in
                               w.db.execute('SELECT kind,message FROM events ORDER BY id')],
                              'schemaVersion': w.db.execute('SELECT max(version) FROM schema_version').fetchone()[0],
                              'formatVersion': TT.FORMAT_VERSION})
        responses = {PS_COMM: (0, '42 1 fixture /fixture/a\n', ''),
                     PS_ARGS: (0, '99 /fixture/vanished\n', ''), LSOF: (0, LISTENER, '')}
        snap('initial')
        with case.commands(responses): w.check_listeners()
        snap('listenerHealthy')
        with case.commands({LSOF: (7, '', '')}): w.check_listeners()
        snap('listenerFailed7')
        with case.commands({LSOF: (0, LISTENER + 'p43\ncpartial\n', '')}): w.check_listeners()
        snap('listenerPartial')
        with case.commands({LSOF: (1, '', '')}): w.check_listeners()
        snap('listenerRecovered')
        with case.commands(responses): w.check_processes()
        snap('processHealthy')
        failed = dict(responses); failed[PS_ARGS] = (7, '', '')
        with case.commands(failed): w.check_processes()
        snap('processFailed')
        with case.commands(responses): w.check_processes()
        snap('processRecovered')
        with mock.patch.object(TT, 'STARTUP_DIRS', ['/fixture/unreadable']), mock.patch.object(
                TT.os, 'listdir', side_effect=PermissionError('public fixture failure')), case.commands({CRON: (0, '', '')}):
            w.check_startup()
        snap('startupBeforeCronFailure')
        w.db.execute("CREATE TRIGGER refuse_parity_startup BEFORE INSERT ON startup_items BEGIN SELECT RAISE(ABORT,'fixture rollback'); END")
        with case.commands({CRON: (1, '', 'no crontab for fixture\n')}): w.check_startup()
        snap('startupDbFailure')
        return {'fixtureVersion': FIXTURE['fixtureVersion'],
                'scopes': [{'host': c['host'], 'actual': TT.bind_scope(c['host'])} for c in FIXTURE['scopeCases']],
                'commands': command_results, 'snapshots': snapshots,
                'startupTransitions': startup_transition_snapshots()}
    finally:
        case.doCleanups()


def startup_transition_snapshots():
    """Eight actual adoption steps with an independently constructed event/health ledger."""
    case = CollectionHealthTests('test_failed_empty_lsof_preserves_real_inventory'); case.setUp()
    try:
        w = case.w; w.snap_dir = '/fixture/copies'
        w.keep_copy = lambda path, digest, data=None: '/fixture/copies/' + TT.Watch.safe_name(path) + '/' + digest[:16]
        w.diff = lambda *args: '(fixture diff)'
        snapshots, expected_events = [], []
        clocks = ['2000-01-01T00:%02d:00Z' % i for i in range(8)]
        body = '* * * * * fixture\n'
        def digest(value): return TT.hashlib.sha256(value.encode()).hexdigest()
        names = {'/fixture/a': 'fixture_a', '/fixture/b': 'fixture_b', '/fixture/c': 'fixture_c', '/fixture/z': 'fixture_z', 'crontab -l': 'crontab_-l'}
        def cp(path, value): return '/fixture/copies/' + names[path] + '/' + ('none' if value is None else digest(value)[:16])
        def added(path, value): return {'kind': 'STARTUP+', 'message': 'added: ' + path + ' | copy: ' + cp(path, value)}
        def changed(path, before, after): return {'kind': 'STARTUP~', 'message': 'changed: ' + path + ' | before: ' + cp(path, before) + ' | after: ' + cp(path, after) + '\n(fixture diff)'}
        def health(status, attempt, success, error=None): return dict(status=status, lastAttempt=attempt, lastSuccess=success, error=error)
        expected_health = [
            (health('ok', clocks[0], clocks[0]), health('ok', clocks[0], clocks[0])),
            (health('ok', clocks[1], clocks[1]), health('ok', clocks[1], clocks[1])),
            (health('ok', clocks[2], clocks[2]), health('ok', clocks[2], clocks[2])),
            (health('ok', clocks[3], clocks[3]), health('degraded', clocks[3], clocks[2], 'crontab-command')),
            (health('degraded', clocks[4], clocks[3], 'startup-read'), health('ok', clocks[4], clocks[4])),
            (health('degraded', clocks[5], clocks[3], 'collection-db'), health('degraded', clocks[5], clocks[4], 'collection-db')),
            (health('ok', clocks[6], clocks[6]), health('ok', clocks[6], clocks[6])),
            (health('unknown', None, None), health('unknown', None, None))]
        sequence = [
            ('startupBaseline', {'/fixture/c': 'c0', '/fixture/a': 'a0'}, (1, '', 'no crontab for fixture\n')),
            ('startupTransition', {'/fixture/c': 'c1', '/fixture/b': 'b0'}, (1, '', 'no crontab for fixture\n')),
            ('startupRepeated', {'/fixture/c': 'c1', '/fixture/b': 'b0'}, (1, '', 'no crontab for fixture\n')),
            ('startupCronFailure', {'/fixture/b': 'b1', '/fixture/c': 'c1'}, (7, '', '')),
            ('startupFilesystemFailure', None, (0, body, '')),
            ('startupDbFailure', {'/fixture/b': 'b1', '/fixture/c': 'c1', '/fixture/z': 'z0'}, (0, body, '')),
            ('startupRecovered', {'/fixture/b': 'b1', '/fixture/c': 'c1', '/fixture/z': 'z0'}, (0, body, '')),
            ('startupReloaded', None, None)]
        for i, (name, files, cron) in enumerate(sequence):
            if i == 5: w.db.execute("CREATE TRIGGER fixture_transition BEFORE INSERT ON startup_items BEGIN SELECT RAISE(ABORT,'fixture transition'); END")
            if i == 6: w.db.execute('DROP TRIGGER fixture_transition')
            with mock.patch.object(TT, 'now', return_value=clocks[i]):
                if i == 7:
                    w.db.close()
                    w = TT.Watch(str(case.root / 'fixture.log'), str(case.root / 'fixture.db'), notify=False)
                    case.addCleanup(w.db.close); w.load_state()
                else:
                    staged = (mock.patch.object(w, '_startup_files', side_effect=TT.CollectionError('startup-read')) if files is None else mock.patch.object(w, '_startup_files', return_value=({p: digest(v) for p, v in files.items()}, {p: v.encode() for p, v in files.items()})))
                    with staged, case.commands({CRON: cron}):
                        case.assertEqual(w.check_startup(), i not in (3, 4, 5))
            if i == 0:
                expected_events += [{'kind': 'BASELINE', 'message': 'startup items: 2 recorded, copies in /fixture/copies'}, {'kind': 'BASELINE', 'message': 'crontab: 1 recorded, copies in /fixture/copies'}]
            elif i == 1:
                expected_events += [{'kind': 'STARTUP-', 'message': 'removed: /fixture/a | last copy: ' + cp('/fixture/a', 'a0')}, added('/fixture/b', 'b0'), changed('/fixture/c', 'c0', 'c1')]
            elif i == 3: expected_events += [changed('/fixture/b', 'b0', 'b1')]
            elif i == 4: expected_events += [changed('crontab -l', None, body)]
            elif i == 6: expected_events += [added('/fixture/z', 'z0')]
            with TT.lock: page = w.page_map()
            events = [{'kind': r[0], 'message': r[1]} for r in w.db.execute('SELECT kind,message FROM events ORDER BY id')]
            case.assertEqual(events, expected_events)
            case.assertEqual(w.collection_health['startup'], expected_health[i][0])
            case.assertEqual(w.collection_health['crontab'], expected_health[i][1])
            case.assertFalse(w.baseline['startup']); case.assertFalse(w.baseline['crontab'])
            case.assertEqual(w.db.execute('SELECT count(*) FROM startup_versions').fetchone()[0], [3, 5, 5, 6, 7, 7, 8, 8][i])
            snapshots.append(dict(name=name, collectionHealth=copy.deepcopy(w.collection_health), map=page, events=events,
                                  schemaVersion=w.db.execute('SELECT max(version) FROM schema_version').fetchone()[0], formatVersion=TT.FORMAT_VERSION,
                                  startupKeys=list(page['startup']), baselines={k: w.baseline[k] for k in ('startup', 'crontab')}))
        return snapshots
    finally:
        case.doCleanups()
