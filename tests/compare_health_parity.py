#!/usr/bin/env python3
"""Strict comparison of health fixture DATA. This cannot certify producer execution."""
import argparse
import datetime
import difflib
import hashlib
import json
import math
import os
import pathlib
import re
import stat
import sys

SNAPSHOTS = (
    'initial', 'listenerHealthy', 'listenerFailed7', 'listenerPartial',
    'listenerRecovered', 'processHealthy', 'processFailed', 'processRecovered',
    'startupBeforeCronFailure', 'startupDbFailure',
)
TRANSITIONS = (
    'startupBaseline', 'startupTransition', 'startupRepeated', 'startupCronFailure',
    'startupFilesystemFailure', 'startupDbFailure', 'startupRecovered', 'startupReloaded',
)
REPAIRS = (
    ('finalEntryStates', 'startup', ('regular', 'directory', 'permission-denied', 'fifo', 'socket', 'device', 'symlink-loop', 'dangling-link', 'file-too-large')),
    ('ancestorRetention', 'startup', ('baseline', 'ancestor-permission', 'ancestor-broken-link', 'listed-disappeared', 'transient-io', 'recovered')),
    ('readabilitySame', 'startup', ('baseline', 'unreadable', 'repeated', 'readable', 'removed')),
    ('readabilityChanged', 'startup', ('baseline', 'unreadable', 'repeated', 'readable', 'removed')),
    ('warningNotes', 'listeners', ('baseline', 'warning', 'repeated', 'otherFailure', 'warningAgain', 'recovered', 'afterRecoveryWarning')),
    ('automaticRollback', 'rollback', ('baseline', 'rolledBack', 'recovered')),
    ('publicationRecovery', 'publication', ('loaded', 'published', 'flushFailed', 'flushRepeated', 'projectionFailed', 'recovered', 'writeFailed', 'writeRecovered', 'restarted')),
    ('publicationNoCache', 'publication-no-cache', ('failed',)),
    ('pidFraming', 'pid', ('nel', 'lineSeparator', 'paragraphSeparator', 'verticalTab', 'formFeed', 'fileSeparator', 'groupSeparator', 'recordSeparator', 'watcher', 'absent', 'uncertain', 'twoLines', 'crlfTransport', 'crTransport')),
)
FIRST_READABLE = (
    ('firstReadableBaseline', 'startup', ('0-permission-denied', '1-permission-denied', '2-A', '3-A', '4-B', '5-permission-denied', '6-B', '7-C')),
    ('firstReadableAdded', 'startup', ('0-absent', '1-permission-denied', '2-permission-denied', '3-A', '4-A', '5-B', '6-permission-denied', '7-B', '8-C')),
)
REPAIRS += FIRST_READABLE

# Independent expected observations for the frozen V3 cases. These are validation
# oracles, never producer output. A matching pair of wrong producers still fails.
REVIEW44_EXPECTATIONS = {
    'processIdentities': (
        ('stable-absolute-different-bridge', True, '/fixture/app', 0),
        ('stable-absolute-no-bridge', True, '/fixture/app', 0),
        ('relative-valid-bridge', True, '/fixture/app', 1),
        ('relative-no-bridge', True, 'app', 1),
        ('escaped-meta-valid-bridge', True, '/fixture/éxecutable', 1),
        ('escaped-octal-valid-bridge', True, '/fixture/a\u00a0b', 1),
        ('escaped-control-valid-bridge', True, '/fixture/a\u0001b', 1),
        ('escaped-meta-no-bridge', False, None, 1),
        ('escaped-octal-root-bridge', False, None, 1),
        ('escaped-control-relative-bridge', False, None, 1),
        ('literal-caret-digit', True, '/fixture/app^2', 0),
        ('literal-meta-suffix', True, '/fixture/literalM-', 0),
        ('literal-backslash-q', True, '/fixture/has\\q', 0),
        ('root-valid-bridge', True, '/fixture/app', 1),
        ('root-no-bridge', False, None, 1),
        ('raw-bridge-vis-looking', True, '/fixture/raw^A\\123', 1),
    ),
    'entryDispositions': (
        ('regular', 'readable:' + hashlib.sha256(b'A\n').hexdigest()),
        ('optional-missing', None),
        ('dangling-link', 'unreadable: dangling-link'),
        ('target-directory-loop', 'unreadable: symlink-loop'),
        ('link-enotdir', 'rejected'),
        ('extra-enotdir', 'rejected'),
        ('fifo', 'unreadable: not-a-regular-file'),
        ('socket', 'unreadable: not-a-regular-file'),
        ('listed-lstat-eacces', 'rejected'),
    ),
    'listenerIdentities': (
        ('root-comm-rejected', False, None, 1),
        ('valid-comm', True, '/fixture/listener', 1),
        ('valid-bridge', True, '/fixture/listener', 0),
        ('root-bridge-valid-comm', True, '/fixture/listener', 1),
        ('escaped-comm-rejected', False, None, 1),
        ('raw-bridge-vis-looking', True, '/fixture/raw^A\\123', 0),
    ),
    'pidFiles': (
        ('invalid-ff', True, True, True, 1, False, False),
        ('invalid-42-c3', True, True, True, 1, False, False),
        ('invalid-replace-failure', False, False, False, 0, True, True),
        ('valid-absent', True, True, True, 0, False, False),
        ('unknown-identity', False, False, False, 0, True, True),
        ('watcher-identity', False, False, False, 0, True, True),
    ),
}
# Frozen setup identities are checked too; output expectations cannot outlive changed inputs.
REVIEW44_INPUT_FIELDS = {'processIdentities': ('psComm', 'bridge'), 'entryDispositions': ('state',), 'listenerIdentities': ('bridge', 'comm'), 'pidFiles': ('initialHex', 'probe', 'replaceFailure')}
REVIEW44_INPUTS = {
    'processIdentities': (
        ('/fixture/app', '/private/clone/app'),
        ('/fixture/app', None),
        ('app', '/fixture/app'),
        ('app', None),
        ('/fixture/M-CM-)xecutable', '/fixture/éxecutable'),
        ('/fixture/a\\240b', '/fixture/a\xa0b'),
        ('/fixture/a^Ab', '/fixture/a\x01b'),
        ('/fixture/M-CM-)xecutable', None),
        ('/fixture/a\\240b', '/'),
        ('/fixture/a^Ab', 'app'),
        ('/fixture/app^2', '/private/clone/app'),
        ('/fixture/literalM-', '/private/clone/app'),
        ('/fixture/has\\q', '/private/clone/app'),
        ('/', '/fixture/app'),
        ('/', None),
        ('app', '/fixture/raw^A\\123'),
    ),
    'entryDispositions': (
        ('regular',),
        ('optional-missing',),
        ('dangling-link',),
        ('target-directory-loop',),
        ('link-enotdir',),
        ('extra-enotdir',),
        ('fifo',),
        ('socket',),
        ('listed-lstat-eacces',),
    ),
    'listenerIdentities': (
        (None, '/'),
        (None, '/fixture/listener'),
        ('/fixture/listener', None),
        ('/', '/fixture/listener'),
        (None, '/fixture/M-CM-)listener'),
        ('/fixture/raw^A\\123', None),
    ),
    'pidFiles': (
        ('ff', 'must-not-call', False),
        ('3432c3', 'must-not-call', False),
        ('ff', 'must-not-call', True),
        ('3432', 'absent', False),
        ('3432', 'unknown', False),
        ('3432', 'watcher', False),
    ),
}
REVIEW44_FIELDS = {
    'processIdentities': ('accepted', 'exe', 'bridgeCalls'),
    'entryDispositions': ('result',),
    'listenerIdentities': ('accepted', 'exe', 'commCalls'),
    'pidFiles': ('accepted', 'pidFileSet', 'pidFileMatchesCurrentProcess', 'noteCount', 'originalBytesPreserved', 'errorObserved'),
}
CHECKS = ('processes', 'listeners', 'startup', 'crontab')
SCOPES = ('loopback', 'wildcard', 'non-loopback', 'unknown')
LIMIT = 16 * 1024 * 1024


class ParityError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise ParityError(message)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def nonfinite(value):
    raise ParityError('non-finite JSON value: ' + value)


def finite_float(value):
    result = float(value)
    require(math.isfinite(result), 'non-finite JSON number')
    return result


def read_regular(path, limit=LIMIT):
    """Bounded, stable, no-final-symlink receipt read; never imports a payload."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'not a single-link regular file: ' + str(path))
        require(0 < before.st_size <= limit, 'empty or oversized file: ' + str(path))
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
        require(identity(before) == identity(after) and len(raw) == before.st_size, 'file changed while reading: ' + str(path))
        return raw, after
    finally:
        os.close(fd)


def load(path):
    raw, _ = read_regular(path)
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=finite_float)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ParityError('invalid UTF-8 JSON: ' + str(path)) from error


def keys(value, expected, where):
    require(type(value) is dict and set(value) == set(expected), where + ': wrong object keys')


def utc_second(value):
    if value is None:
        return True
    if type(value) is not str or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value):
        return False
    try:
        return datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%dT%H:%M:%SZ') == value
    except ValueError:
        return False


def health(value, where):
    keys(value, CHECKS, where)
    for name, row in value.items():
        at = where + '.' + name
        keys(row, ('lastAttempt', 'lastSuccess', 'status', 'error'), at)
        require(utc_second(row['lastAttempt']) and utc_second(row['lastSuccess']), at + ': invalid time')
        status, error = row['status'], row['error']
        require(type(status) is str and status in ('unknown', 'ok', 'degraded'), at + ': invalid status')
        require(error is None or (type(error) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,63}', error)), at + ': invalid diagnostic')
        if status == 'unknown':
            require(row['lastSuccess'] is None and error is None, at + ': invalid unknown state')
        elif status == 'ok':
            require(row['lastAttempt'] is not None and row['lastSuccess'] is not None and error is None, at + ': invalid ok state')
        else:
            require(row['lastAttempt'] is not None and error is not None, at + ': invalid degraded state')


def publication_health(value, as_of, where):
    # Reuse the four-field grammar without pretending publication is a collector.
    health({key: value for key in CHECKS}, where)
    require(value['error'] in (None, 'collection-db', 'collection-io'), where + ': unsupported publication diagnostic')
    require(utc_second(as_of), where + ': invalid projection time')
    require(value['status'] != 'ok' or as_of is not None, where + ': ok without a real projection')


def string_map(value, where, times=False):
    require(type(value) is dict, where + ': not an object')
    require(all(type(k) is str and k and type(v) is str and v and
                (not times or utc_second(v)) for k, v in value.items()), where + ': invalid map scalar')


def repair_spec(cases):
    require(type(cases) is list and len(cases) == len(REPAIRS), 'repair input census mismatch')
    for case, (name, kind, names) in zip(cases, REPAIRS):
        keys(case, ('name', 'kind', 'steps'), 'repair input')
        require(case['name'] == name and case['kind'] == kind, 'repair input name/kind mismatch')
        steps = case['steps']
        require(type(steps) is list and len(steps) == len(names), name + ': input step census mismatch')
        for step, expected in zip(steps, names):
            require(type(step) is dict and step.get('name') == expected and
                    type(step.get('at')) is str and utc_second(step['at']), name + ': invalid input step identity/clock')
            op = step.get('op')
            require(type(op) is str, name + ': invalid operation')
            if kind in ('pid', 'listeners'):
                expected_op = kind
            elif name == 'publicationNoCache':
                expected_op = 'save-without-load'
            elif kind == 'publication':
                expected_op = {'loaded': 'load', 'restarted': 'restart-load'}.get(expected, 'save')
            elif kind == 'rollback':
                expected_op = {'rolledBack': 'startup-rollback', 'recovered': 'startup-drop-trigger'}.get(expected, 'startup')
            else:
                expected_op = 'startup'
            require(op == expected_op, name + ': operation differs from frozen case')
            base = ('name', 'at', 'op')
            if op in ('startup', 'startup-rollback', 'startup-drop-trigger'):
                keys(step, base + ('entries', 'sourceFailure', 'cron') + (() if op == 'startup' else ('sql',)), name)
                require(step['sourceFailure'] in (None, 'ancestor-permission', 'ancestor-broken-link', 'listed-disappeared', 'transient-io'), name + ': unsupported source failure')
                require(type(step['entries']) is list, name + ': entries not an array')
                paths = []
                for entry in step['entries']:
                    keys(entry, ('path', 'state', 'text'), name + '.entry')
                    require(type(entry['path']) is str and entry['path'].startswith('/fixture/'), name + ': invalid logical path')
                    require(entry['state'] in ('regular', 'directory', 'permission-denied', 'fifo', 'socket', 'device', 'symlink-loop', 'dangling-link', 'file-too-large'), name + ': unknown entry state')
                    require(type(entry['text']) is str if entry['state'] == 'regular' else entry['text'] is None, name + ': invalid entry content')
                    paths.append(entry['path'])
                require(len(paths) == len(set(paths)), name + ': duplicate input path')
                command = step['cron']
                if op != 'startup':
                    require(type(step['sql']) is str and step['sql'], name + ': missing real rollback SQL')
            elif op in ('listeners', 'pid'):
                keys(step, base + ('command',), name)
                command = step['command']
            elif op in ('save', 'save-without-load'):
                keys(step, base + ('fault', 'dirtyTime'), name)
                require(step['fault'] in (None, 'flush-abort', 'projection-db', 'atomic-write-io'), name + ': unsupported publication fault')
                require(utc_second(step['dirtyTime']), name + ': invalid dirty clock')
                continue
            else:
                require(op in ('load', 'restart-load'), name + ': unsupported operation')
                keys(step, base, name)
                continue
            keys(command, ('code', 'out', 'err'), name + '.command')
            require(type(command['code']) is int and type(command['out']) is str and type(command['err']) is str, name + ': invalid command scalar')


def repair_results(rows, cases):
    require(type(rows) is list and len(rows) == len(REPAIRS), 'repair result census mismatch')
    for result, case in zip(rows, cases):
        name = case['name']
        keys(result, ('name', 'kind', 'states'), name)
        require(result['name'] == name and result['kind'] == case['kind'], 'missing/duplicate/reordered repair result')
        states = result['states']
        require(type(states) is list and len(states) == len(case['steps']), name + ': missing/extra repair states')
        for state, step in zip(states, case['steps']):
            at = name + '.' + step['name']
            if case['kind'] == 'pid':
                keys(state, ('name', 'classification'), at)
                require(type(state['classification']) is str and state['classification'] in ('watcher', 'other', 'absent', 'unknown'), at + ': invalid PID classification')
            else:
                keys(state, ('name', 'collectionHealth', 'publicationHealth', 'inventoryAsOf', 'map', 'events',
                             'startupMirror', 'baselines', 'dirtyPrograms', 'dirtyListeners', 'startupVersions', 'copies', 'published'), at)
                health(state['collectionHealth'], at)
                publication_health(state['publicationHealth'], state['inventoryAsOf'], at)
                inventory(state['map'], at)
                string_map(state['startupMirror'], at + '.startupMirror')
                equal(state['startupMirror'], state['map']['startup'], at + '.startupMirror')
                if name == 'publicationNoCache' and step['name'] == 'failed':
                    keys(state['baselines'], (), at + '.baselines')
                else:
                    keys(state['baselines'], ('programs', 'listeners', 'startup', 'crontab'), at + '.baselines')
                    require(all(type(v) is bool for v in state['baselines'].values()), at + ': nonboolean baseline')
                for field in ('dirtyPrograms', 'dirtyListeners'):
                    string_map(state[field], at + '.' + field, times=True)
                require(type(state['events']) is list, at + ': events not an array')
                for row in state['events']:
                    keys(row, ('time', 'kind', 'message'), at + '.event')
                    require(all(type(v) is str and v for v in row.values()) and utc_second(row['time']), at + ': invalid event')
                require(type(state['startupVersions']) is list, at + ': versions not an array')
                for row in state['startupVersions']:
                    keys(row, ('path', 'hash', 'copyPath', 'seenAt'), at + '.version')
                    require(all(type(row[k]) is str and row[k] for k in ('path', 'hash', 'seenAt')) and
                            utc_second(row['seenAt']) and (row['copyPath'] is None or
                            (type(row['copyPath']) is str and row['copyPath'])), at + ': invalid version scalar')
                require(type(state['copies']) is list, at + ': copies not an array')
                paths = []
                for row in state['copies']:
                    keys(row, ('path', 'hex'), at + '.copy')
                    require(type(row['path']) is str and row['path'] and type(row['hex']) is str and
                            re.fullmatch(r'(?:[0-9a-f]{2})*', row['hex']) is not None, at + ': invalid copy bytes')
                    paths.append(row['path'])
                require(paths == sorted(set(paths)), at + ': duplicate/reordered copies')
                payload = state['published']
                if payload is not None:
                    keys(payload, ('formatVersion', 'generatedAt', 'version', 'collectionHealth', 'publicationHealth', 'inventoryAsOf', 'map'), at + '.published')
                    require(type(payload['formatVersion']) is int and payload['formatVersion'] == 2 and
                            type(payload['version']) is str and payload['version'] == '0.0.2' and
                            type(payload['generatedAt']) is str and utc_second(payload['generatedAt']), at + ': invalid published envelope')
                    health(payload['collectionHealth'], at + '.published')
                    publication_health(payload['publicationHealth'], payload['inventoryAsOf'], at + '.published')
                    inventory(payload['map'], at + '.published')
            require(state['name'] == step['name'], at + ': missing/duplicate/reordered state')


def review44_spec(cases):
    keys(cases, REVIEW44_EXPECTATIONS, 'review44 input')
    inputs = {'processIdentities': ('psComm', 'bridge'),
              'entryDispositions': ('state',),
              'listenerIdentities': ('bridge', 'comm'),
              'pidFiles': ('initialHex', 'probe', 'replaceFailure')}
    for family, expectations in REVIEW44_EXPECTATIONS.items():
        rows = cases[family]
        require(type(rows) is list and len(rows) == len(expectations), family + ': input census mismatch')
        for row, spec, setup in zip(rows, expectations, REVIEW44_INPUTS[family]):
            name, *values = spec
            at = family + '.' + name
            expected_key = 'expectedResult' if family == 'entryDispositions' else 'expected'
            keys(row, ('name',) + inputs[family] + (expected_key,), at)
            require(type(row['name']) is str and row['name'] == name, at + ': input identity/order mismatch')
            equal({key: row[key] for key in inputs[family]}, dict(zip(REVIEW44_INPUT_FIELDS[family], setup)), at + '.frozen setup')
            if family == 'entryDispositions':
                require(type(row['state']) is str and row['state'] == name, at + ': wrong filesystem setup')
                equal(row[expected_key], values[0], at + '.declared expectation')
            else:
                declared = dict(zip(REVIEW44_FIELDS[family], values))
                equal(row[expected_key], declared, at + '.declared expectation')
            if family == 'processIdentities':
                require(type(row['psComm']) is str and row['psComm'] and nullable(row['bridge'], str), at + ': wrong identity input')
            elif family == 'listenerIdentities':
                require(nullable(row['comm'], str) and nullable(row['bridge'], str), at + ': wrong listener input')
            elif family == 'pidFiles':
                require(type(row['initialHex']) is str and re.fullmatch(r'(?:[0-9a-f]{2})+', row['initialHex']) and
                        type(row['replaceFailure']) is bool and row['probe'] in ('must-not-call', 'absent', 'unknown', 'watcher'), at + ': wrong PID setup')


def review44_results(rows, cases):
    keys(rows, REVIEW44_EXPECTATIONS, 'review44 results')
    for family, expectations in REVIEW44_EXPECTATIONS.items():
        actual = rows[family]
        require(type(actual) is list and len(actual) == len(expectations), family + ': result census mismatch')
        for row, spec, case in zip(actual, expectations, cases[family]):
            name, *values = spec
            fields = REVIEW44_FIELDS[family]
            keys(row, ('name',) + fields, family + '.' + name)
            equal(row, {'name': name, **dict(zip(fields, values))}, family + '.' + name)
            # Validate against the independently checked fixture declaration too.
            expected = {'result': case['expectedResult']} if family == 'entryDispositions' else case['expected']
            equal({key: row[key] for key in fields}, expected, family + '.' + name + '.fixture')


def first_readable_expected(case, clock):
    """Small contract oracle for the two frozen first-content histories.

    Derives hashes/copies/events/versions/health from input bytes and transitions;
    never reads either producer's output and never launches a collector.
    """
    previous, retained, copies, versions, events, states = {}, {}, {}, [], [], []
    last_success = None
    unknown = {'lastAttempt': None, 'lastSuccess': None, 'status': 'unknown', 'error': None}
    for index, step in enumerate(case['steps']):
        at = step['at']
        entries = [(e['path'], e['text'], e['state'] == 'regular') for e in step['entries']]
        entries.append(('crontab -l', step['cron']['out'], True))
        current = {}
        for path, text, readable in entries:
            digest = hashlib.sha256(text.encode('utf-8')).hexdigest() if readable else 'unreadable: permission-denied'
            copy_path = '/fixture/copies/' + path.strip('/').replace('/', '_').replace(' ', '_') + '/' + digest[:16] if readable else None
            current[path] = digest
            if previous.get(path) == digest:
                continue
            if readable:
                copies[copy_path] = text.encode('utf-8').hex()
            versions.append({'path': path, 'hash': digest, 'copyPath': copy_path, 'seenAt': at})
            if index and path not in previous:
                events.append({'time': at, 'kind': 'STARTUP+', 'message': 'added: ' + path + ' | copy: ' + (copy_path or 'None')})
            elif index and readable and (path not in retained or retained[path][0] != digest):
                before = retained.get(path)
                diff = ('\n'.join(difflib.unified_diff(before[2].splitlines(), text.splitlines(), fromfile='before', tofile='after', lineterm=''))
                        if before else '(no text diff: binary or missing copy)')
                events.append({'time': at, 'kind': 'STARTUP~', 'message': 'changed: ' + path + ' | before: ' +
                               (before[1] if before else 'None') + ' | after: ' + copy_path + '\n' + diff})
            if readable:
                retained[path] = (digest, copy_path, text)
        if index == 0:
            events.extend([{'time': at, 'kind': 'BASELINE', 'message': 'startup items: ' + str(len(step['entries'])) + ' recorded, copies in /fixture/copies'},
                           {'time': at, 'kind': 'BASELINE', 'message': 'crontab: 1 recorded, copies in /fixture/copies'}])
        degraded = any(e['state'] != 'regular' for e in step['entries'])
        if not degraded:
            last_success = at
        healths = {key: dict(unknown) for key in CHECKS}
        healths['startup'] = {'lastAttempt': at, 'lastSuccess': last_success, 'status': 'degraded' if degraded else 'ok',
                              'error': 'startup-unreadable' if degraded else None}
        healths['crontab'] = {'lastAttempt': at, 'lastSuccess': at, 'status': 'ok', 'error': None}
        states.append({'name': step['name'], 'collectionHealth': healths, 'publicationHealth': dict(unknown), 'inventoryAsOf': clock,
                       'map': {'programs': {}, 'listeners': {}, 'credentials': [], 'startup': dict(sorted(current.items()))},
                       'events': [dict(row) for row in events], 'startupMirror': dict(sorted(current.items())),
                       'baselines': {'programs': True, 'listeners': True, 'startup': False, 'crontab': False},
                       'dirtyPrograms': {}, 'dirtyListeners': {}, 'startupVersions': [dict(row) for row in versions],
                       'copies': [{'path': path, 'hex': copies[path]} for path in sorted(copies)], 'published': None})
        previous = current
    return states


def first_readable_semantics(rows, fixture):
    for result, case in zip(rows[-2:], fixture['repairCases'][-2:]):
        equal(result['states'], first_readable_expected(case, fixture['clock']), case['name'] + '.semantic contract')


def nullable(value, kind):
    return value is None or type(value) is kind


def inventory(value, where):
    keys(value, ('programs', 'listeners', 'credentials', 'startup'), where)
    for section in ('programs', 'listeners', 'startup'):
        require(type(value[section]) is dict, where + '.' + section + ': not an object')
        require(all(type(k) is str and k for k in value[section]), where + ': invalid inventory key')
    required = {'firstSeen', 'lastSeen', 'user', 'firstPid', 'firstArgs', 'parent'}
    optional = {'sha256', 'size', 'signer', 'team', 'signingId'}
    for row in value['programs'].values():
        require(type(row) is dict and required <= set(row) <= required | optional, where + ': wrong program fields')
        require(all(nullable(v, int if k in ('firstPid', 'size') else str) for k, v in row.items()), where + ': wrong program scalar type')
    fields = ('firstSeen', 'lastSeen', 'pid', 'command', 'exposed', 'bindScope', 'user', 'args', 'chain', 'present')
    for row in value['listeners'].values():
        keys(row, fields, where + '.listener')
        require(type(row['present']) is bool and type(row['exposed']) is bool, where + ': listener flags are not booleans')
        require(type(row['bindScope']) is str and row['bindScope'] in SCOPES, where + ': invalid scope')
        require(all(nullable(row[k], int if k == 'pid' else str) for k in fields if k not in ('present', 'exposed', 'bindScope')), where + ': wrong listener scalar type')
    require(type(value['credentials']) is list, where + ': credentials not an array')
    for row in value['credentials']:
        keys(row, ('time', 'pid', 'user', 'exe', 'args', 'chain', 'source'), where + '.credential')
        require(all(nullable(v, int if k == 'pid' else str) for k, v in row.items()), where + ': wrong credential scalar type')
    require(all(type(v) is str and v for v in value['startup'].values()), where + ': invalid startup hash/marker')


def snapshots(rows, names, transition=False):
    require(type(rows) is list and len(rows) == len(names), 'missing/extra snapshots')
    require([row.get('name') if type(row) is dict else None for row in rows] == list(names), 'missing/duplicate/reordered snapshot names')
    for row in rows:
        where = row['name']
        fields = ('name', 'collectionHealth', 'map', 'events', 'schemaVersion', 'formatVersion')
        keys(row, fields + (('startupKeys', 'baselines') if transition else ()), where)
        require(type(row['schemaVersion']) is int and row['schemaVersion'] == 1, where + ': wrong database schema')
        require(type(row['formatVersion']) is int and row['formatVersion'] == 2, where + ': wrong data format')
        health(row['collectionHealth'], where)
        inventory(row['map'], where)
        require(type(row['events']) is list, where + ': events not an array')
        for event in row['events']:
            keys(event, ('kind', 'message'), where + '.event')
            require(all(type(v) is str and v for v in event.values()), where + ': empty/invalid event')
        if transition:
            keys(row['baselines'], ('startup', 'crontab'), where + '.baselines')
            require(all(type(v) is bool for v in row['baselines'].values()), where + ': baselines must be boolean')
            require(type(row['startupKeys']) is list and row['startupKeys'] and
                    all(type(k) is str for k in row['startupKeys']), where + ': missing startup key order')
            require(row['startupKeys'] == sorted(row['map']['startup']) == list(row['map']['startup']), where + ': startup key order differs from exported sorted inventory')
            require(row['events'], where + ': vacuous transition event history')


def validate(value, fixture):
    keys(value, ('fixtureVersion', 'scopes', 'commands', 'snapshots', 'startupTransitions', 'repairResults', 'review44'), 'parity')
    require(type(value['fixtureVersion']) is int and value['fixtureVersion'] == fixture['fixtureVersion'] == 3, 'unsupported fixture version')
    require(type(value['scopes']) is list and len(value['scopes']) == len(fixture['scopeCases']) == 23, 'scope census mismatch')
    for actual, expected in zip(value['scopes'], fixture['scopeCases']):
        keys(actual, ('host', 'actual'), 'scope')
        require(type(actual['host']) is str and actual['host'] == expected['host'] and actual['actual'] == expected['expected'], 'scope fixture mismatch')
    require(type(value['commands']) is list and len(value['commands']) == len(fixture['commandCases']) == 13, 'command census mismatch')
    for actual, expected in zip(value['commands'], fixture['commandCases']):
        keys(actual, ('tool', 'code', 'out', 'err', 'actual'), 'command')
        require(type(actual['code']) is int, 'command exit code not integer')
        require(all(type(actual[k]) is str for k in ('tool', 'out', 'err', 'actual')), 'command scalar type')
        require(all(actual[k] == expected[k] for k in ('tool', 'code', 'out', 'err')) and actual['actual'] == expected['expected'], 'command fixture mismatch')
    snapshots(value['snapshots'], SNAPSHOTS)
    snapshots(value['startupTransitions'], TRANSITIONS, transition=True)
    repair_results(value['repairResults'], fixture['repairCases'])
    first_readable_semantics(value['repairResults'], fixture)
    review44_results(value['review44'], fixture['review44Cases'])


def equal(left, right, where='$'):
    require(type(left) is type(right), where + ': JSON type mismatch')
    if type(left) is dict:
        require(left.keys() == right.keys(), where + ': object keys differ')
        for key in left:
            equal(left[key], right[key], where + '.' + key)
    elif type(left) is list:
        require(len(left) == len(right), where + ': array length differs')
        for i, (a, b) in enumerate(zip(left, right)):
            equal(a, b, where + '[' + str(i) + ']')
    else:
        require(left == right, where + ': value differs')


def compare_files(python_path, java_path, fixture_path=None):
    fixture = load(fixture_path or pathlib.Path(__file__).with_name('fixtures') / 'collection-health.json')
    keys(fixture, ('fixtureVersion', 'clock', 'scopeCases', 'commandCases', 'repairCases', 'review44Cases'), 'shared fixture')
    require(type(fixture['fixtureVersion']) is int and fixture['fixtureVersion'] == 3 and
            type(fixture['clock']) is str and utc_second(fixture['clock']), 'unsupported shared fixture version/clock')
    require(type(fixture['scopeCases']) is list and type(fixture['commandCases']) is list, 'invalid shared fixture census')
    for row in fixture['scopeCases']:
        keys(row, ('host', 'expected'), 'scope fixture')
        require(type(row['host']) is str and type(row['expected']) is str and row['expected'] in SCOPES, 'invalid scope fixture')
    for row in fixture['commandCases']:
        keys(row, ('tool', 'code', 'out', 'err', 'expected'), 'command fixture')
        require(type(row['code']) is int and all(type(row[k]) is str for k in ('tool', 'out', 'err', 'expected')), 'invalid command fixture')
    repair_spec(fixture['repairCases'])
    review44_spec(fixture['review44Cases'])
    left, right = load(python_path), load(java_path)
    validate(left, fixture)
    validate(right, fixture)
    equal(left, right)
    return {'dataComparison': 'equal', 'producerExecutionCertified': False,
            'scopes': len(left['scopes']), 'commands': len(left['commands']),
            'snapshots': len(left['snapshots']), 'startupTransitions': len(left['startupTransitions']),
            'repairFamilies': len(left['repairResults']), 'repairStates': sum(len(r['states']) for r in left['repairResults']),
            'review44Observations': sum(len(rows) for rows in left['review44'].values()),
            'firstReadableSemanticStates': sum(len(r['states']) for r in left['repairResults'][-2:])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('python_json')
    parser.add_argument('java_json')
    args = parser.parse_args()
    try:
        print(json.dumps(compare_files(args.python_json, args.java_json), sort_keys=True))
        return 0
    except (OSError, ValueError, RecursionError) as error:
        print('PARITY DATA REFUSED: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
