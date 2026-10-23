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

    def test_startup_directory_failure_does_not_attempt_crontab(self):
        self.seed_startup(); before = self.inventory()
        with mock.patch.object(TT, 'STARTUP_DIRS', ['/fixture/unreadable']), mock.patch.object(
                TT.os, 'listdir', side_effect=PermissionError('fake private filename')):
            self.assertFalse(self.w.check_startup())
        self.assertEqual(before, self.inventory())
        self.assert_degraded('startup')
        self.assertEqual(self.w.collection_health['crontab']['status'], 'unknown')
        self.run_mock.assert_not_called()

    def test_startup_late_file_failure_preserves_whole_sample(self):
        self.seed_startup(); first = self.root / 'first'; second = self.root / 'second'
        first.write_bytes(b'public fixture'); second.write_bytes(b'public fixture')
        original = open
        def read_file(path, *args, **kwargs):
            if str(path) == str(second): raise PermissionError('fake private path')
            return original(path, *args, **kwargs)
        before = self.inventory()
        with mock.patch.object(TT, 'STARTUP_FILES', [str(first), str(second)]), mock.patch('builtins.open', side_effect=read_file):
            self.assertFalse(self.w.check_startup())
        self.assertEqual(before, self.inventory())
        self.run_mock.assert_not_called()

    def test_startup_optional_missing_is_accepted(self):
        with mock.patch.object(TT, 'STARTUP_DIRS', [str(self.root / 'missing-dir')]), mock.patch.object(
                TT, 'STARTUP_FILES', [str(self.root / 'missing-file')]), self.commands({CRON: (1, '', 'no crontab for fixture\n')}):
            self.assertTrue(self.w.check_startup())
        self.assertEqual(self.w.startup, {'crontab -l': 'none'})
        self.assertEqual(self.w.collection_health['startup']['status'], 'ok')
        self.assertEqual(self.w.collection_health['crontab']['status'], 'ok')

    def test_optional_broken_source_or_ancestor_is_not_absence(self):
        self.seed_startup(); before = self.inventory()
        broken = self.root / 'broken'; broken.symlink_to(self.root / 'missing-target')
        for name in ['STARTUP_DIRS', 'STARTUP_FILES']:
            for path in [broken, broken / 'child']:
                with mock.patch.object(TT, name, [str(path)]):
                    self.assertFalse(self.w.check_startup())
                self.assertEqual(before, self.inventory())
                self.assertEqual(self.w.collection_health['startup']['error'], 'startup-read')
                self.assertEqual(self.w.collection_health['crontab']['status'], 'unknown')
        self.run_mock.assert_not_called()

    def test_crontab_timeout_preserves_text_and_both_successes(self):
        self.seed_startup(); before = self.inventory()
        for key in ['startup', 'crontab']: self.w.collection_health[key]['lastSuccess'] = T1
        with self.commands({CRON: subprocess.TimeoutExpired(['crontab', '-l'], 20)}):
            self.assertFalse(self.w.check_startup())
        self.assertEqual(before, self.inventory())
        for key in ['startup', 'crontab']:
            self.assertEqual(self.w.collection_health[key]['status'], 'degraded')
            self.assertEqual(self.w.collection_health[key]['lastSuccess'], T1)

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
        original = TT.transaction
        @contextlib.contextmanager
        def completed_identity(conn):
            self.w.announce.pop('/fixture/old', None)
            with original(conn) as value: yield value
        with self.commands(self.ps_responses()), mock.patch.object(TT, 'transaction', completed_identity):
            self.assertTrue(self.w.check_processes())
        self.assertNotIn('/fixture/old', self.w.announce)

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
            self.assertEqual(before, self.inventory())
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
        conn = sqlite3.connect(':memory:', isolation_level=None)
        conn.execute('PRAGMA foreign_keys=ON')
        conn.execute('CREATE TABLE parent(id INTEGER PRIMARY KEY)')
        conn.execute('CREATE TABLE child(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED)')
        wrapped = FailedRollback(conn)
        with self.assertRaises(sqlite3.IntegrityError):
            with TT.transaction(wrapped) as c: c.execute('INSERT INTO child VALUES(1)')
        self.assertTrue(wrapped.closed)
        with self.assertRaises(sqlite3.ProgrammingError): conn.execute('SELECT 1')
        wrapped = FailedRollback(sqlite3.connect(':memory:', isolation_level=None))
        original = ValueError('public synthetic body failure')
        with self.assertRaises(ValueError) as caught:
            with TT.transaction(wrapped): raise original
        self.assertIs(caught.exception, original)
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
            self.assertEqual(before, self.inventory())
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
        if not ok: self.assertEqual(before, self.inventory())
        if case['expected'] == 'ok-absent': self.assertEqual(self.w.startup['crontab -l'], 'none')
    return test


for index, case in enumerate(FIXTURE['scopeCases']):
    setattr(CollectionHealthTests, 'test_scope_%02d' % index, scope_case(case))
for index, case in enumerate(FIXTURE['commandCases']):
    setattr(CollectionHealthTests, 'test_command_%02d' % index, command_case(case))


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
        w.baseline = {'programs': False, 'listeners': False, 'startup': False}
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
                TT.os, 'listdir', side_effect=PermissionError('public fixture failure')):
            w.check_startup()
        snap('startupBeforeCronFailure')
        w.db.execute("CREATE TRIGGER refuse_parity_startup BEFORE INSERT ON startup_items BEGIN SELECT RAISE(ABORT,'fixture rollback'); END")
        with case.commands({CRON: (1, '', 'no crontab for fixture\n')}): w.check_startup()
        snap('startupDbFailure')
        return {'fixtureVersion': FIXTURE['fixtureVersion'],
                'scopes': [{'host': c['host'], 'actual': TT.bind_scope(c['host'])} for c in FIXTURE['scopeCases']],
                'commands': command_results, 'snapshots': snapshots}
    finally:
        case.doCleanups()
