"""Synthetic parser/gate discriminators. NO Python/Java fixture producer is launched.

The constructed parity/JUnit data below is explicitly synthetic validation input,
not a collector observation or evidence that the two writers produced equal output.
"""
import contextlib
import copy
import datetime
import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

import compare_health_parity as parity
import run_health_gate as gate


def synthetic():
    fixture = parity.load(pathlib.Path(__file__).with_name('fixtures') / 'collection-health.json')
    health = {k: {'lastAttempt': None, 'lastSuccess': None, 'status': 'unknown', 'error': None} for k in parity.CHECKS}
    def row(name, transition=False):
        value = {'name': name, 'collectionHealth': copy.deepcopy(health),
                 'map': {'programs': {}, 'listeners': {}, 'credentials': [], 'startup': {}},
                 'events': [], 'schemaVersion': 1, 'formatVersion': 2}
        if transition:
            value['map']['startup'] = {'/fixture/a': 'a' * 64, 'crontab -l': 'none'}
            value.update(startupKeys=['/fixture/a', 'crontab -l'], baselines={'startup': False, 'crontab': False})
            value['events'] = [{'kind': 'BASELINE', 'message': 'synthetic baseline'},
                               {'kind': 'STARTUP+', 'message': 'synthetic transition'}]
        return value
    return {'fixtureVersion': 1,
            'scopes': [{'host': r['host'], 'actual': r['expected']} for r in fixture['scopeCases']],
            'commands': [{**{k: r[k] for k in ('tool', 'code', 'out', 'err')}, 'actual': r['expected']} for r in fixture['commandCases']],
            'snapshots': [row(name) for name in parity.SNAPSHOTS],
            'startupTransitions': [row(name, True) for name in parity.TRANSITIONS]}


class ParityDataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='synthetic-parity-')
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name).resolve()
        self.left, self.right = self.root / 'python.json', self.root / 'java.json'
        self.data = synthetic()
        self.left.write_text(json.dumps(self.data))

    def compare(self, value):
        self.right.write_text(json.dumps(value))
        return parity.compare_files(self.left, self.right)

    def test_equal_nonempty_data_explicitly_does_not_certify_producers(self):
        result = self.compare(self.data)
        self.assertEqual((result['scopes'], result['commands'], result['snapshots'], result['startupTransitions']), (23, 13, 10, 8))
        self.assertFalse(result['producerExecutionCertified'])

    def test_dictionary_key_order_is_not_whole_file_byte_identity(self):
        self.right.write_text(json.dumps(self.data, sort_keys=True))
        self.assertNotEqual(self.left.read_bytes(), self.right.read_bytes())
        self.assertEqual(parity.compare_files(self.left, self.right)['dataComparison'], 'equal')

    def test_legacy_eight_transition_absence_is_refused(self):
        value = copy.deepcopy(self.data); del value['startupTransitions']
        with self.assertRaises(parity.ParityError): self.compare(value)

    def test_lsof_warning_is_preserved_as_degraded_data_without_normalization(self):
        value = copy.deepcopy(self.data)
        value['snapshots'][0]['collectionHealth']['listeners'].update(status='degraded', lastAttempt='2000-01-01T00:00:00Z', error='lsof-warning')
        self.left.write_text(json.dumps(value))
        self.assertEqual(self.compare(value)['dataComparison'], 'equal')
        value['snapshots'][0]['collectionHealth']['listeners']['error'] = 'lsof-command'
        with self.assertRaises(parity.ParityError): self.compare(value)

    def test_boolean_and_integer_are_not_equal_json_scalars(self):
        with self.assertRaises(parity.ParityError): parity.equal(True, 1)
        value = copy.deepcopy(self.data); value['startupTransitions'][0]['baselines']['startup'] = 0
        with self.assertRaises(parity.ParityError): self.compare(value)

    def test_integer_and_float_are_not_equal_json_scalars(self):
        with self.assertRaises(parity.ParityError): parity.equal(1, 1.0)

    def test_failed_input_cannot_hide_behind_identical_empty_pair(self):
        self.left.write_text('{}'); self.right.write_text('{}')
        with self.assertRaises(parity.ParityError): parity.compare_files(self.left, self.right)

    def test_missing_file_is_refused(self):
        with self.assertRaises(OSError): parity.compare_files(self.left, self.right)

    def test_symlink_payload_is_refused(self):
        self.right.symlink_to(self.left)
        with self.assertRaises(OSError): parity.compare_files(self.left, self.right)


def mutation_test(mutate):
    def test(self):
        value = copy.deepcopy(self.data); mutate(value)
        with self.assertRaises(parity.ParityError): self.compare(value)
    return test


for name, mutate in {
    'health_drift': lambda d: d['snapshots'][0]['collectionHealth']['listeners'].update(lastAttempt='2000-01-01T00:00:00Z', lastSuccess='2000-01-01T00:00:00Z', status='ok'),
    'map_drift': lambda d: d['snapshots'][0]['map']['startup'].update({'/fixture/extra': 'b' * 64}),
    'dropped_event': lambda d: d['startupTransitions'][1]['events'].pop(),
    'reordered_event': lambda d: d['startupTransitions'][1]['events'].reverse(),
    'dropped_snapshot': lambda d: d['snapshots'].pop(),
    'dropped_startup_transition': lambda d: d['startupTransitions'].pop(),
    'reordered_snapshot': lambda d: d['startupTransitions'].reverse(),
    'duplicate_snapshot_name': lambda d: d['startupTransitions'][1].update(name='startupBaseline'),
    'empty_transitions': lambda d: d.update(startupTransitions=[]),
    'scope_census_loss': lambda d: d['scopes'].pop(),
    'wrong_code_type': lambda d: d['commands'][0].update(code=False),
    'wrong_version_type': lambda d: d.update(fixtureVersion=True),
    'wrong_map_shape': lambda d: d['snapshots'][0]['map'].update(credentials={}),
    'missing_health_check': lambda d: d['snapshots'][0]['collectionHealth'].pop('crontab'),
    'raw_health_error': lambda d: d['snapshots'][0]['collectionHealth']['listeners'].update(error='private /fixture/name'),
    'wrong_key_order': lambda d: d['startupTransitions'][0]['startupKeys'].reverse(),
    'extra_transition_field': lambda d: d['startupTransitions'][0].update(extra=True),
}.items():
    setattr(ParityDataTests, 'test_refuses_' + name, mutation_test(mutate))


def raw_test(raw):
    def test(self):
        self.right.write_bytes(raw)
        with self.assertRaises((ValueError, OSError)): parity.load(self.right)
    return test


for name, raw in {'empty': b'', 'malformed': b'{', 'duplicate': b'{"fixtureVersion":1,"fixtureVersion":1}',
                  'nan': b'{"x":NaN}', 'infinity': b'{"x":1e999}', 'invalid_utf8': b'\xff'}.items():
    setattr(ParityDataTests, 'test_refuses_raw_' + name, raw_test(raw))


class ProducerGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='synthetic-gate-')
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name).resolve()
        self.xml, self.data = self.root / 'cases.xml', self.root / 'parity.json'
        self.now = datetime.datetime.now(datetime.timezone.utc)
        self.stamp = self.now.isoformat()
        self.receipt = {'name': 'python', 'exitCode': 0, 'startUtc': (self.now - datetime.timedelta(seconds=1)).isoformat(),
                        'endUtc': (self.now + datetime.timedelta(seconds=1)).isoformat()}
        self.data.write_text('{"synthetic":"not real producer evidence"}')
        self.xml.write_text(self.report())

    def report(self, failure='', skipped='', name='python'):
        child = '<failure>synthetic</failure>' if failure else '<skipped>synthetic</skipped>' if skipped else ''
        suite, case_class = ('python.collection-health', 'CollectionHealthTests') if name == 'python' else ('CollectionHealthTest', 'dev.tattletale.CollectionHealthTest')
        return ('<testsuite name="' + suite + '" tests="1" failures="' + ('1' if failure else '0') + '" errors="0" skipped="' + ('1' if skipped else '0') +
                '" timestamp="' + self.stamp + '"><testcase classname="' + case_class + '" name="synthetic-case" timestamp="' + self.stamp + '" time="0.001">' + child + '</testcase></testsuite>')

    def verify(self):
        return gate.verify_producer(self.receipt, self.xml, self.data)

    def test_fresh_pass_fixture_counts_and_skip_are_not_discarded(self):
        self.assertEqual(self.verify()['tests'], 1)
        skipped = self.report(skipped=True).split('<testcase', 1)[1].split('</testsuite>', 1)[0].replace('name="synthetic-case"', 'name="synthetic-skipped"')
        self.xml.write_text(self.report().replace('tests="1"', 'tests="2"').replace('skipped="0"', 'skipped="1"').replace('</testsuite>', '<testcase' + skipped + '</testsuite>'))
        self.assertEqual(self.verify()['skipped'], 1)

    def test_all_skipped_is_not_a_nonempty_execution(self):
        self.xml.write_text(self.report(skipped=True))
        with self.assertRaises(parity.ParityError): self.verify()

    def test_nonzero_producer_refuses_even_with_fresh_equal_outputs(self):
        self.receipt['exitCode'] = 1
        with self.assertRaises(parity.ParityError): self.verify()

    def test_stale_xml_is_refused(self):
        os.utime(self.xml, (1, 1))
        with self.assertRaises(parity.ParityError): self.verify()

    def test_stale_parity_is_refused(self):
        os.utime(self.data, (1, 1))
        with self.assertRaises(parity.ParityError): self.verify()

    def test_fresh_files_with_stale_case_timestamp_are_refused(self):
        self.xml.write_text(self.report().replace(self.stamp, '2000-01-01T00:00:00Z'))
        with self.assertRaises(parity.ParityError): self.verify()

    def test_zero_exit_cannot_override_junit_failure(self):
        self.xml.write_text(self.report(failure=True))
        with self.assertRaises(parity.ParityError): self.verify()

    def test_forged_junit_count_is_refused(self):
        self.xml.write_text(self.report().replace('tests="1"', 'tests="2"'))
        with self.assertRaises(parity.ParityError): self.verify()

    def test_wrong_suite_cannot_substitute_for_producer_junit(self):
        self.xml.write_text(self.report().replace('python.collection-health', 'unrelated-suite'))
        with self.assertRaises(parity.ParityError): self.verify()

    def test_invalid_case_duration_is_refused(self):
        self.xml.write_text(self.report().replace('time="0.001"', 'time="NaN"'))
        with self.assertRaises(parity.ParityError): self.verify()

    def test_unstamped_junit_is_not_given_fake_timestamps(self):
        self.xml.write_text(self.report().replace(' timestamp="' + self.stamp + '"', ''))
        with self.assertRaises(parity.ParityError): self.verify()

    def test_duplicate_testcase_identity_is_refused(self):
        case = self.report().split('<testcase', 1)[1].split('</testsuite>', 1)[0]
        self.xml.write_text(self.report().replace('tests="1"', 'tests="2"').replace('</testsuite>', '<testcase' + case + '</testsuite>'))
        with self.assertRaises(parity.ParityError): self.verify()

    def test_dtd_entity_refused(self):
        self.xml.write_text('<!DOCTYPE testsuite [<!ENTITY x "synthetic">]>' + self.report())
        with self.assertRaises(parity.ParityError): self.verify()

    def test_utf16_cannot_bypass_dtd_guard(self):
        self.xml.write_bytes(('<!DOCTYPE testsuite [<!ENTITY x "synthetic">]>' + self.report()).encode('utf-16'))
        with self.assertRaises(parity.ParityError): self.verify()

    def test_reused_directory_refuses_before_any_producer(self):
        with mock.patch.object(gate.sys, 'argv', ['gate', '--output-dir', str(self.root)]), mock.patch.object(gate, 'run_producer') as producer, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(gate.main(), 1)
        producer.assert_not_called()

    def test_failed_producer_prevents_comparison_and_preserves_both_outcomes(self):
        directory = self.root / 'new-run'
        def fake_run(name, argv, destination):
            (destination / (name + '.xml')).write_text(self.report(name=name))
            (destination / (name + '-parity.json')).write_text('{"synthetic":true}')
            return {**self.receipt, 'name': name, 'exitCode': 1 if name == 'python' else 0}
        with mock.patch.object(gate.sys, 'argv', ['gate', '--output-dir', str(directory)]), mock.patch.object(gate, 'source_pins', return_value={'synthetic': 'not-real-source'}), mock.patch.object(gate, 'run_producer', side_effect=fake_run) as producer, mock.patch.object(gate, 'compare_files') as compare, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(), 1)
        self.assertEqual(producer.call_count, 2)
        compare.assert_not_called()
        saved = json.loads((directory / 'gate.json').read_text())
        self.assertEqual(saved['status'], 'FAIL')
        self.assertFalse(saved['producerExecutionCertified'])
        self.assertEqual(set(saved['producers']), {'python', 'java'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
