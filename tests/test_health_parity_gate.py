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
    def repair_state(case, step):
        if case['kind'] == 'pid':
            return {'name': step['name'], 'classification': 'other'}
        return {'name': step['name'], 'collectionHealth': copy.deepcopy(health),
                'publicationHealth': {'lastAttempt': None, 'lastSuccess': None, 'status': 'unknown', 'error': None},
                'inventoryAsOf': None, 'map': {'programs': {}, 'listeners': {}, 'credentials': [], 'startup': {}},
                'events': [], 'startupMirror': {},
                'baselines': {} if case['name'] == 'publicationNoCache' else {k: True for k in ('programs', 'listeners', 'startup', 'crontab')},
                'dirtyPrograms': {}, 'dirtyListeners': {}, 'startupVersions': [], 'copies': [], 'published': None}
    return {'fixtureVersion': 3,
            'scopes': [{'host': r['host'], 'actual': r['expected']} for r in fixture['scopeCases']],
            'commands': [{**{k: r[k] for k in ('tool', 'code', 'out', 'err')}, 'actual': r['expected']} for r in fixture['commandCases']],
            'snapshots': [row(name) for name in parity.SNAPSHOTS],
            'startupTransitions': [row(name, True) for name in parity.TRANSITIONS],
            'repairResults': [{'name': c['name'], 'kind': c['kind'], 'states': parity.first_readable_expected(c, fixture['clock']) if c['name'] in ('firstReadableBaseline', 'firstReadableAdded') else [repair_state(c, s) for s in c['steps']]} for c in fixture['repairCases']],
            'review44': {family: [{'name': row[0], **dict(zip(parity.REVIEW44_FIELDS[family], row[1:]))} for row in specs]
                         for family, specs in parity.REVIEW44_EXPECTATIONS.items()}}


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
        self.assertEqual((result['repairFamilies'], result['repairStates']), (11, 76))
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

    def test_no_cache_state_preserves_actual_empty_baseline_only_at_the_exact_exception(self):
        self.assertEqual(self.compare(self.data)['repairStates'], 76)
        value = copy.deepcopy(self.data)
        value['repairResults'][7]['states'][0]['baselines'] = {k: False for k in parity.CHECKS}
        self.left.write_text(json.dumps(value))
        with self.assertRaises(parity.ParityError): self.compare(value)

    def test_new_fixture_inputs_cannot_silently_drop_reorder_or_duplicate_cases(self):
        fixture_path = pathlib.Path(__file__).with_name('fixtures') / 'collection-health.json'
        fixture = parity.load(fixture_path)
        for change in ('drop', 'reorder', 'duplicate'):
            value = copy.deepcopy(fixture)
            if change == 'drop': value['repairCases'].pop()
            elif change == 'reorder': value['repairCases'].reverse()
            else: value['repairCases'][1] = copy.deepcopy(value['repairCases'][0])
            self.right.write_text(json.dumps(self.data))
            custom = self.root / (change + '.json'); custom.write_text(json.dumps(value))
            with self.assertRaises(parity.ParityError): parity.compare_files(self.left, self.right, custom)

    def test_repair_history_events_versions_and_copy_bytes_remain_exact_ordered_data(self):
        value = copy.deepcopy(self.data)
        state = value['repairResults'][3]['states'][3]
        state['events'] = [{'time': '2000-01-01T00:00:00Z', 'kind': 'BASELINE', 'message': 'synthetic baseline'},
                           {'time': '2000-01-01T00:01:00Z', 'kind': 'STARTUP~', 'message': 'synthetic actual-field projection'}]
        state['startupVersions'] = [{'path': '/fixture/a', 'hash': 'a' * 64, 'copyPath': '/fixture/copies/a', 'seenAt': '2000-01-01T00:00:00Z'},
                                    {'path': '/fixture/b', 'hash': 'b' * 64, 'copyPath': '/fixture/copies/b', 'seenAt': '2000-01-01T00:01:00Z'}]
        state['copies'] = [{'path': '/fixture/copies/a', 'hex': '00'}, {'path': '/fixture/copies/b', 'hex': 'ff'}]
        self.left.write_text(json.dumps(value))
        self.assertEqual(self.compare(value)['dataComparison'], 'equal')
        for field in ('events', 'startupVersions', 'copies'):
            for action in ('drop', 'reverse'):
                changed = copy.deepcopy(value); rows = changed['repairResults'][3]['states'][3][field]
                if action == 'drop': rows.pop()
                else: rows.reverse()
                with self.assertRaises(parity.ParityError): self.compare(changed)
        changed = copy.deepcopy(value); changed['repairResults'][3]['states'][3]['copies'][0]['hex'] = '01'
        with self.assertRaises(parity.ParityError): self.compare(changed)

    def test_selected_real_payload_fields_are_strict_and_not_replaced_by_a_success_boolean(self):
        value = copy.deepcopy(self.data); state = value['repairResults'][6]['states'][1]
        state['published'] = {'formatVersion': 2, 'generatedAt': '2000-01-01T00:00:00Z', 'version': '0.0.3',
                              'collectionHealth': copy.deepcopy(state['collectionHealth']),
                              'publicationHealth': copy.deepcopy(state['publicationHealth']),
                              'inventoryAsOf': None, 'map': copy.deepcopy(state['map'])}
        self.left.write_text(json.dumps(value)); self.assertEqual(self.compare(value)['dataComparison'], 'equal')
        for field in ('formatVersion', 'version', 'inventoryAsOf', 'publicationHealth', 'map'):
            changed = copy.deepcopy(value); changed['repairResults'][6]['states'][1]['published'][field] = True
            with self.assertRaises(parity.ParityError): self.compare(changed)
        changed = copy.deepcopy(value); changed['repairResults'][6]['states'][1]['published'] = True
        with self.assertRaises(parity.ParityError): self.compare(changed)

    def test_illegal_projection_type_and_malformed_history_are_refused_even_in_identical_pairs(self):
        for field, bad in [('inventoryAsOf', False), ('events', [{'time': 1, 'kind': 'NOTE', 'message': 'synthetic'}]),
                           ('startupVersions', [{'path': '/fixture/a', 'hash': 'a', 'copyPath': '', 'seenAt': '2000-01-01T00:00:00Z'}]),
                           ('dirtyPrograms', {'/fixture/a': True}), ('copies', [{'path': '/fixture/a', 'hex': 'Ff'}])]:
            value = copy.deepcopy(self.data); value['repairResults'][0]['states'][0][field] = bad
            self.left.write_text(json.dumps(value))
            with self.assertRaises(parity.ParityError): self.compare(value)


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
    'missing_repairs': lambda d: d.pop('repairResults'),
    'empty_repairs': lambda d: d.update(repairResults=[]),
    'dropped_repair_family': lambda d: d['repairResults'].pop(),
    'reordered_repair_family': lambda d: d['repairResults'].reverse(),
    'duplicate_repair_name': lambda d: d['repairResults'][1].update(name='finalEntryStates'),
    'dropped_repair_step': lambda d: d['repairResults'][0]['states'].pop(),
    'reordered_repair_step': lambda d: d['repairResults'][0]['states'].reverse(),
    'wrong_repair_kind': lambda d: d['repairResults'][0].update(kind='pid'),
    'nonboolean_repair_baseline': lambda d: d['repairResults'][0]['states'][0]['baselines'].update(startup=0),
    'empty_loaded_baseline': lambda d: d['repairResults'][0]['states'][0].update(baselines={}),
    'wrong_publication_diagnostic': lambda d: d['repairResults'][0]['states'][0]['publicationHealth'].update(status='degraded', lastAttempt='2000-01-01T00:00:00Z', error='lsof-warning'),
    'wrong_projection_type': lambda d: d['repairResults'][0]['states'][0].update(inventoryAsOf=False),
    'missing_pending_map': lambda d: d['repairResults'][0]['states'][0].pop('dirtyPrograms'),
    'old_fixture_version': lambda d: d.update(fixtureVersion=1),
    'pid_classification_drift': lambda d: d['repairResults'][8]['states'][0].update(classification='unknown'),
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


class Review44DataTests(unittest.TestCase):
    setUp = ParityDataTests.setUp
    # Synthetic validator controls only. None launches or certifies a producer.
    def identical_pair(self, value, fixture=None):
        self.left.write_text(json.dumps(value))
        self.right.write_text(json.dumps(value))
        return parity.compare_files(self.left, self.right, fixture)

    def test_v3_census_and_semantic_scope_are_reported(self):
        result = self.identical_pair(self.data)
        self.assertEqual((result['review44Observations'], result['firstReadableSemanticStates']), (37, 17))
        self.assertFalse(result['producerExecutionCertified'])

    def test_each_family_refuses_missing_extra_duplicate_reordered_rows_and_fields(self):
        for family in parity.REVIEW44_EXPECTATIONS:
            for mutation in ('missing-row', 'extra-row', 'duplicate-row', 'reorder', 'missing-field', 'extra-field'):
                with self.subTest(family=family, mutation=mutation):
                    value = copy.deepcopy(self.data); rows = value['review44'][family]
                    if mutation == 'missing-row': rows.pop()
                    elif mutation == 'extra-row': rows.append(copy.deepcopy(rows[0]))
                    elif mutation == 'duplicate-row': rows[1] = copy.deepcopy(rows[0])
                    elif mutation == 'reorder': rows.reverse()
                    elif mutation == 'missing-field': rows[0].pop(parity.REVIEW44_FIELDS[family][0])
                    else: rows[0]['extra'] = True
                    with self.assertRaises(parity.ParityError): self.identical_pair(value)

    def test_review44_envelope_refuses_missing_extra_and_wrong_types(self):
        for family in parity.REVIEW44_EXPECTATIONS:
            for bad in (None, {}, True, 37):
                value = copy.deepcopy(self.data); value['review44'][family] = bad
                with self.assertRaises(parity.ParityError): self.identical_pair(value)
            value = copy.deepcopy(self.data); value['review44'].pop(family)
            with self.assertRaises(parity.ParityError): self.identical_pair(value)
        value = copy.deepcopy(self.data); value['review44']['extra'] = []
        with self.assertRaises(parity.ParityError): self.identical_pair(value)
        value = copy.deepcopy(self.data); value.pop('review44')
        with self.assertRaises(parity.ParityError): self.identical_pair(value)

    def test_each_result_scalar_has_exact_json_type_even_in_identical_pairs(self):
        for family, rows in self.data['review44'].items():
            for index, row in enumerate(rows):
                for key, correct in row.items():
                    # Explicit bool/int distinction, no coercion or null filling.
                    bad = 1 if type(correct) is bool else True if type(correct) is int else 0
                    value = copy.deepcopy(self.data); value['review44'][family][index][key] = bad
                    with self.subTest(family=family, case=row['name'], field=key):
                        with self.assertRaises(parity.ParityError): self.identical_pair(value)

    def test_integer_counter_values_cannot_drift_in_identical_pairs(self):
        for family, counter in (('processIdentities', 'bridgeCalls'), ('listenerIdentities', 'commCalls'), ('pidFiles', 'noteCount')):
            for index, row in enumerate(self.data['review44'][family]):
                value = copy.deepcopy(self.data)
                value['review44'][family][index][counter] += 1
                with self.subTest(family=family, case=row['name'], field=counter):
                    with self.assertRaises(parity.ParityError): self.identical_pair(value)

    def test_altered_declared_expectation_cannot_make_two_wrong_producers_pass(self):
        fixture = parity.load(pathlib.Path(__file__).with_name('fixtures') / 'collection-health.json')
        for family in parity.REVIEW44_EXPECTATIONS:
            value = copy.deepcopy(self.data); changed = copy.deepcopy(fixture)
            row, declaration = value['review44'][family][0], changed['review44Cases'][family][0]
            if family == 'entryDispositions':
                row['result'] = declaration['expectedResult'] = 'rejected'
            else:
                row['accepted'] = declaration['expected']['accepted'] = not row['accepted']
            custom = self.root / (family + '-bad-fixture.json'); custom.write_text(json.dumps(changed))
            with self.assertRaises(parity.ParityError): self.identical_pair(value, custom)

    def test_each_declared_expectation_is_checked_independently_of_producer_data(self):
        fixture = parity.load(pathlib.Path(__file__).with_name('fixtures') / 'collection-health.json')
        for family, rows in fixture['review44Cases'].items():
            for index, row in enumerate(rows):
                fields = ('expectedResult',) if family == 'entryDispositions' else tuple(row['expected'])
                for field in fields:
                    changed = copy.deepcopy(fixture['review44Cases'])
                    target = changed[family][index] if family == 'entryDispositions' else changed[family][index]['expected']
                    correct = target[field]
                    target[field] = not correct if type(correct) is bool else correct + 1 if type(correct) is int else 'wrong expectation'
                    with self.subTest(family=family, case=row['name'], field=field):
                        with self.assertRaises(parity.ParityError): parity.review44_spec(changed)

    def test_fixture_row_census_order_and_scalar_mutants_are_refused(self):
        fixture = parity.load(pathlib.Path(__file__).with_name('fixtures') / 'collection-health.json')
        for family in parity.REVIEW44_EXPECTATIONS:
            for mutation in ('missing-row', 'extra-row', 'duplicate-row', 'reorder', 'missing-field', 'extra-field', 'wrong-type'):
                changed = copy.deepcopy(fixture); rows = changed['review44Cases'][family]
                if mutation == 'missing-row': rows.pop()
                elif mutation == 'extra-row': rows.append(copy.deepcopy(rows[0]))
                elif mutation == 'duplicate-row': rows[1] = copy.deepcopy(rows[0])
                elif mutation == 'reorder': rows.reverse()
                elif mutation == 'missing-field': rows[0].pop('name')
                elif mutation == 'extra-field': rows[0]['extra'] = True
                else: rows[0]['name'] = 1
                custom = self.root / (family + '-' + mutation + '.json'); custom.write_text(json.dumps(changed))
                with self.subTest(family=family, mutation=mutation):
                    with self.assertRaises(parity.ParityError): self.identical_pair(self.data, custom)

    def test_changed_frozen_setup_cannot_reuse_old_expectations_and_outputs(self):
        fixture = parity.load(pathlib.Path(__file__).with_name('fixtures') / 'collection-health.json')
        for family, fields in parity.REVIEW44_INPUT_FIELDS.items():
            for field in fields:
                changed = copy.deepcopy(fixture); row = changed['review44Cases'][family][0]
                correct = row[field]
                row[field] = not correct if type(correct) is bool else '/fixture/changed' if type(correct) is str else '/fixture/changed'
                custom = self.root / (family + '-' + field + '.json'); custom.write_text(json.dumps(changed))
                with self.subTest(family=family, field=field):
                    with self.assertRaises(parity.ParityError): self.identical_pair(self.data, custom)

    def test_first_readability_delivers_exactly_one_before_none_event_for_both_histories(self):
        for family, first_index in ((9, 2), (10, 3)):
            states = self.data['repairResults'][family]['states']
            initial_events = [e for e in states[first_index]['events'] if e['kind'] == 'STARTUP~']
            self.assertEqual(len(initial_events), 1)
            self.assertIn('before: None | after: /fixture/copies/fixture_entry/', initial_events[0]['message'])
            for mutation in ('drop', 'duplicate', 'wrong-before', 'wrong-after', 'wrong-kind', 'wrong-time', 'fake-diff'):
                value = copy.deepcopy(self.data); events = value['repairResults'][family]['states'][first_index]['events']
                if mutation == 'drop': events.pop()
                elif mutation == 'duplicate': events.append(copy.deepcopy(events[-1]))
                elif mutation == 'wrong-before': events[-1]['message'] = events[-1]['message'].replace('before: None', 'before: /fixture/fake')
                elif mutation == 'wrong-after': events[-1]['message'] = events[-1]['message'].replace('after: /fixture/copies/', 'after: /fixture/fake/')
                elif mutation == 'wrong-kind': events[-1]['kind'] = 'STARTUP+'
                elif mutation == 'wrong-time': events[-1]['time'] = '2000-01-01T00:00:00Z'
                else: events[-1]['message'] += '\n-A\n+A'
                with self.subTest(family=family, mutation=mutation):
                    with self.assertRaises(parity.ParityError): self.identical_pair(value)

    def test_first_readability_copy_and_version_evidence_cannot_be_absent_or_invented(self):
        for family, first_index in ((9, 2), (10, 3)):
            for mutation in ('drop-copy', 'wrong-bytes', 'fake-copy', 'drop-version', 'null-version-copy', 'wrong-hash', 'wrong-seen-time'):
                value = copy.deepcopy(self.data); state = value['repairResults'][family]['states'][first_index]
                copies = state['copies']; index = next(i for i, c in enumerate(copies) if '/fixture_entry/' in c['path'])
                if mutation == 'drop-copy': copies.pop(index)
                elif mutation == 'wrong-bytes': copies[index]['hex'] = '420a'
                elif mutation == 'fake-copy': copies[index]['path'] += 'fake'
                elif mutation == 'drop-version': state['startupVersions'].pop()
                elif mutation == 'null-version-copy': state['startupVersions'][-1]['copyPath'] = None
                elif mutation == 'wrong-hash': state['startupVersions'][-1]['hash'] = 'b' * 64
                else: state['startupVersions'][-1]['seenAt'] = '2000-01-01T00:00:00Z'
                with self.subTest(family=family, mutation=mutation):
                    with self.assertRaises(parity.ParityError): self.identical_pair(value)

    def test_first_readability_health_baseline_and_retained_history_are_semantic(self):
        for family, unreadable, first in ((9, 1, 2), (10, 2, 3)):
            for mutation in ('false-ok', 'lost-success', 'false-success', 'wrong-error', 'baseline', 'map-loss', 'duplicate-repeat', 'resurrection', 'wrong-diff', 'published-fiction'):
                value = copy.deepcopy(self.data); states = value['repairResults'][family]['states']
                if mutation == 'false-ok': states[unreadable]['collectionHealth']['startup'].update(status='ok', error=None, lastSuccess=states[unreadable]['collectionHealth']['startup']['lastAttempt'])
                elif mutation == 'lost-success': states[first]['collectionHealth']['startup']['lastSuccess'] = '2000-01-01T00:00:00Z'
                elif mutation == 'false-success': states[-3]['collectionHealth']['startup']['lastSuccess'] = states[-3]['collectionHealth']['startup']['lastAttempt']
                elif mutation == 'wrong-error': states[unreadable]['collectionHealth']['startup']['error'] = 'collection-io'
                elif mutation == 'baseline': states[first]['baselines']['startup'] = True
                elif mutation == 'map-loss': states[first]['map']['startup'].pop('/fixture/entry'); states[first]['startupMirror'].pop('/fixture/entry')
                elif mutation == 'duplicate-repeat': states[first + 1]['events'].append(copy.deepcopy(states[first]['events'][-1]))
                elif mutation == 'resurrection': states[-2]['events'].append(copy.deepcopy(states[first]['events'][-1]))
                elif mutation == 'wrong-diff': states[-1]['events'][-1]['message'] = states[-1]['events'][-1]['message'].replace('-B', '-A')
                else: states[first]['inventoryAsOf'] = '2000-01-02T23:59:59Z'
                with self.subTest(family=family, mutation=mutation):
                    with self.assertRaises(parity.ParityError): self.identical_pair(value)


def identical_review44_mutant(family, index):
    def test(self):
        value = copy.deepcopy(self.data); row = value['review44'][family][index]
        key = 'result' if family == 'entryDispositions' else 'accepted'
        row[key] = 'wrong disposition' if family == 'entryDispositions' else not row[key]
        with self.assertRaises(parity.ParityError): self.identical_pair(value)
    return test


for family, specs in parity.REVIEW44_EXPECTATIONS.items():
    for index, spec in enumerate(specs):
        setattr(Review44DataTests, 'test_identical_wrong_' + family + '_' + spec[0].replace('-', '_'), identical_review44_mutant(family, index))


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
