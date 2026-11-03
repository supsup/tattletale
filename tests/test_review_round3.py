"""Round-3 CLI/bounds discriminators; existing APIs, synthetic inputs, no host collection.

Unexpected production exceptions are observed and then compared with the desired public
CLI outcome, so the current unhandled stream failure is an assertion RED, not a test error.
"""
import contextlib
import io
import pathlib
import tempfile
import unittest
from unittest import mock

import test_collection_health as health

TT = health.TT


class Round3CliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='review-round3-')
        self.addCleanup(temporary.cleanup)
        self.root = pathlib.Path(temporary.name)
        self.config = self.root / 'fixture.env'
        self.config.write_text('')

    def assert_constructor_refuses_before_files(self, field, value):
        directory = self.root / ('direct-' + field)
        values = {'process_every': 3, 'listen_every': 30, 'startup_every': 300}
        values[field] = value
        with self.assertRaises(ValueError) as refused:
            TT.Watch(str(directory / 'log'), str(directory / 'db'), notify=False, **values)
        self.assertIn('between 0.5 and 3600', str(refused.exception))
        self.assertFalse(directory.exists(), 'invalid configuration touched the filesystem')

    def assert_cli_refuses_before_migration(self, flag, value, field):
        flags = ['fixture', '--config', str(self.config), flag, str(value)]
        output, error, observed = io.StringIO(), io.StringIO(), None
        with mock.patch.object(TT.sys, 'argv', flags), mock.patch.dict(TT.os.environ, {}, clear=True), \
                mock.patch.object(TT, 'migrate_v001', return_value=None) as migration, \
                mock.patch.object(TT, 'Watch') as watch, mock.patch.object(TT.signal, 'signal') as handlers, \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            try:
                TT.main()
            except BaseException as exception:
                observed = exception
        self.assertIsInstance(observed, SystemExit)
        self.assertEqual(observed.code, 2)
        self.assertIn(field, error.getvalue())
        self.assertIn('between 0.5 and 3600', error.getvalue())
        self.assertEqual(output.getvalue(), '')
        migration.assert_not_called()
        watch.assert_not_called()
        handlers.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [self.config])

    def assert_clean_stream_failure(self, code):
        flags = ['fixture', '--config', str(self.config), '--db', str(self.root / 'absent' / 'db')]
        output, error, observed = io.StringIO(), io.StringIO(), None
        with mock.patch.object(TT.sys, 'argv', flags), mock.patch.dict(TT.os.environ, {}, clear=True), \
                mock.patch.object(TT, 'Watch') as watch, \
                mock.patch.object(TT, 'migrate_v001', return_value=None) as migration, \
                mock.patch.object(TT.signal, 'signal'), contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            watch.return_value.run.side_effect = TT.FatalDatabaseError(code)
            try:
                TT.main()
            except BaseException as exception:
                observed = exception
        # Baseline FatalDatabaseError is deliberately captured above. This assertion is
        # the deciding failure; no traceback escapes as an infrastructure/setup error.
        self.assertIsInstance(observed, SystemExit, 'stream fatal must have a clean public CLI exit')
        self.assertEqual(observed.code, 1)
        self.assertEqual(error.getvalue(), 'tattletale: ' + code + '\n')
        self.assertEqual(output.getvalue(), '')
        watch.return_value.run.assert_called_once_with()
        migration.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [self.config])

    def test_control_daily_startup_constructor_refuses_before_files(self):
        self.assert_constructor_refuses_before_files('startup_every', 86400)

    def test_control_quarter_second_constructor_refuses_before_files(self):
        self.assert_constructor_refuses_before_files('process_every', 0.25)

    def test_control_daily_startup_cli_refuses_before_migration(self):
        self.assert_cli_refuses_before_migration('--startup-interval', 86400, 'startup_interval')

    def test_control_quarter_second_cli_refuses_before_migration(self):
        self.assert_cli_refuses_before_migration('--process-interval', 0.25, 'process_interval')

    def test_main_keychain_cleanup_failure_is_clean_exit(self):
        self.assert_clean_stream_failure('keychain-cleanup')

    def test_main_reader_stalled_failure_is_clean_exit(self):
        self.assert_clean_stream_failure('keychain-reader-stalled')


if __name__ == '__main__': unittest.main()
