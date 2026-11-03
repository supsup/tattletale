#!/usr/bin/env python3
"""Compare two executed coverage fixture artifacts against the declared fault contract."""
import argparse
import json
import pathlib
import sys


def require(condition, why):
    if not condition: raise ValueError(why)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def load(path):
    def invalid(value): raise ValueError('nonfinite JSON value')
    return json.loads(pathlib.Path(path).read_text(), object_pairs_hook=unique, parse_constant=invalid)


def oracle(fixture):
    require(type(fixture) is dict and fixture.get('fixtureVersion') == 1, 'unsupported fixture')
    rows = []
    for case in fixture['cases']:
        issues = [{'collector': None if who == '-' else who, 'reason': reason}
                  for who, reason in (item.split('/', 1) for item in case['issues'])]
        rows.append({'name': case['name'], 'result': {
            'resultVersion': 1, 'since': case.get('since', fixture['since']), 'until': case.get('until', fixture['until']),
            'outcome': case['outcome'], 'eventCount': None if case['outcome'] == 'REFUSED' else case.get('eventCount', 0), 'issues': issues}})
    for case in fixture['streamCases']:
        rows.append({'name': 'stream-' + case['name'], 'count': case['count'], 'error': case['error']})
    require(len({row['name'] for row in rows}) == len(rows), 'duplicate fixture case')
    return {'fixtureVersion': 1, 'results': sorted(rows, key=lambda row: row['name'])}


def equal(actual, expected, at='$'):
    require(type(actual) is type(expected), at + ': JSON type mismatch')
    if type(expected) is dict:
        require(actual.keys() == expected.keys(), at + ': fields differ')
        for key in expected: equal(actual[key], expected[key], at + '.' + key)
    elif type(expected) is list:
        require(len(actual) == len(expected), at + ': missing or duplicate cases')
        for index, (left, right) in enumerate(zip(actual, expected)): equal(left, right, at + '[' + str(index) + ']')
    else:
        require(actual == expected, at + ': contract mismatch')


def validate(payload, fixture):
    equal(payload, oracle(fixture))


def compare(python_path, java_path, fixture_path):
    fixture, left, right = load(fixture_path), load(python_path), load(java_path)
    validate(left, fixture); validate(right, fixture); equal(left, right)
    return {'dataComparison': 'equal', 'producerExecutionCertified': False,
            'coverageCases': len(fixture['cases']), 'streamCases': len(fixture['streamCases'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('python_json'); parser.add_argument('java_json')
    parser.add_argument('--fixtures', default=str(pathlib.Path(__file__).parent / 'fixtures/coverage.json'))
    args = parser.parse_args()
    try:
        print(json.dumps(compare(args.python_json, args.java_json, args.fixtures), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        print('COVERAGE PARITY REFUSED: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__': sys.exit(main())
