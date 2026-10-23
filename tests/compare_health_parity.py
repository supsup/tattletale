#!/usr/bin/env python3
"""Strict comparison of health fixture DATA. This cannot certify producer execution."""
import argparse
import datetime
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
    keys(value, ('fixtureVersion', 'scopes', 'commands', 'snapshots', 'startupTransitions'), 'parity')
    require(type(value['fixtureVersion']) is int and value['fixtureVersion'] == fixture['fixtureVersion'] == 1, 'unsupported fixture version')
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
    keys(fixture, ('fixtureVersion', 'clock', 'scopeCases', 'commandCases'), 'shared fixture')
    require(type(fixture['fixtureVersion']) is int and fixture['fixtureVersion'] == 1 and
            type(fixture['clock']) is str and utc_second(fixture['clock']), 'unsupported shared fixture version/clock')
    require(type(fixture['scopeCases']) is list and type(fixture['commandCases']) is list, 'invalid shared fixture census')
    for row in fixture['scopeCases']:
        keys(row, ('host', 'expected'), 'scope fixture')
        require(type(row['host']) is str and type(row['expected']) is str and row['expected'] in SCOPES, 'invalid scope fixture')
    for row in fixture['commandCases']:
        keys(row, ('tool', 'code', 'out', 'err', 'expected'), 'command fixture')
        require(type(row['code']) is int and all(type(row[k]) is str for k in ('tool', 'out', 'err', 'expected')), 'invalid command fixture')
    left, right = load(python_path), load(java_path)
    validate(left, fixture)
    validate(right, fixture)
    equal(left, right)
    return {'dataComparison': 'equal', 'producerExecutionCertified': False,
            'scopes': len(left['scopes']), 'commands': len(left['commands']),
            'snapshots': len(left['snapshots']), 'startupTransitions': len(left['startupTransitions'])}


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
