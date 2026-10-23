#!/usr/bin/env python3
"""Run BOTH fixture producers into a fresh directory, verify JUnit, then compare data.

This is not a watcher, process supervisor, release gate or proof of live observation.
Use an outer native execution receipt/custody window; this script never invents times.
"""
import argparse
import datetime
import hashlib
import json
import math
import pathlib
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

from compare_health_parity import ParityError, compare_files, read_regular, require

REPO = pathlib.Path(__file__).resolve().parents[1]


def timestamp(value):
    require(type(value) is str and value, 'missing JUnit timestamp')
    try:
        result = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as error:
        raise ParityError('invalid JUnit timestamp') from error
    require(result.tzinfo is not None and result.utcoffset() == datetime.timedelta(0), 'JUnit timestamp is not UTC')
    return result.timestamp()


def fresh(path, start, end):
    raw, info = read_regular(path)
    # Fresh exclusive run dir is the primary stale-file defense; allow only filesystem
    # timestamp granularity, never an output from a prior run.
    require(start - 1 <= info.st_mtime <= end + 1, 'stale/future output: ' + str(path))
    return raw


def verify_producer(receipt, xml_path, parity_path):
    require(type(receipt['exitCode']) is int and receipt['exitCode'] == 0, 'producer did not exit successfully')
    start, end = timestamp(receipt['startUtc']), timestamp(receipt['endUtc'])
    require(start <= end, 'producer time interval reversed')
    raw = fresh(xml_path, start, end)
    fresh(parity_path, start, end)
    try:
        text = raw.decode('utf-8')
    except UnicodeError as error:
        raise ParityError('JUnit must be UTF-8') from error
    require('\x00' not in text and '<!DOCTYPE' not in text.upper() and '<!ENTITY' not in text.upper(), 'unsafe XML declaration')
    try:
        root = ET.fromstring(text)
    except ET.ParseError as error:
        raise ParityError('malformed JUnit') from error
    require(root.tag == 'testsuite' and len(list(root.iter())) <= 20000, 'unsupported/oversized JUnit shape')
    producer = receipt.get('name')
    require(producer in ('python', 'java'), 'unknown producer identity')
    suite_name, case_class = ('python.collection-health', 'CollectionHealthTests') if producer == 'python' else ('CollectionHealthTest', 'dev.tattletale.CollectionHealthTest')
    require(root.get('name') == suite_name, 'wrong producer JUnit suite')
    require(all(child.tag == 'testcase' for child in root), 'unexpected JUnit children')
    suite_time = timestamp(root.get('timestamp'))
    require(start - 1 <= suite_time <= end + 1, 'stale/future suite timestamp')
    counts = {'tests': len(root), 'failures': 0, 'errors': 0, 'skipped': 0}
    require(counts['tests'] > 0, 'empty JUnit census')
    identities = set()
    for case in root:
        identity = (case.get('classname'), case.get('name'))
        require(all(type(v) is str and v for v in identity) and identity not in identities, 'missing/duplicate testcase identity')
        require(identity[0] == case_class, 'wrong producer testcase class')
        identities.add(identity)
        when = timestamp(case.get('timestamp'))
        require(start - 1 <= when <= end + 1, 'stale/future testcase timestamp')
        try:
            duration = float(case.get('time'))
        except (TypeError, ValueError) as error:
            raise ParityError('missing/invalid testcase duration') from error
        require(math.isfinite(duration) and duration >= 0, 'invalid testcase duration')
        require(len(case) <= 1 and all(c.tag in ('failure', 'error', 'skipped') for c in case), 'unsupported testcase result')
        for child in case:
            counts[{'failure': 'failures', 'error': 'errors', 'skipped': 'skipped'}[child.tag]] += 1
    for field, actual in counts.items():
        declared = root.get(field)
        require(type(declared) is str and declared.isascii() and declared.isdigit() and int(declared) == actual, 'JUnit count mismatch: ' + field)
    require(counts['failures'] == counts['errors'] == 0, 'JUnit contains failures/errors despite successful producer exit')
    require(counts['tests'] > counts['skipped'], 'JUnit has no executed testcases')
    return {**counts, 'suiteTimestamp': root.get('timestamp'), 'xmlSha256': hashlib.sha256(raw).hexdigest()}


def source_pins():
    files = [REPO / 'python/tattletale.py', REPO / 'tests/test_collection_health.py',
             REPO / 'tests/run_python_health_tests.py', REPO / 'tests/run_java_health_tests.sh',
             REPO / 'tests/fixtures/collection-health.json', pathlib.Path(__file__).resolve(),
             REPO / 'tests/compare_health_parity.py', REPO / 'java/build.sh']
    files += sorted((REPO / 'java/src').rglob('*.java'))
    return {str(p.relative_to(REPO)): hashlib.sha256(read_regular(p)[0]).hexdigest() for p in files}


def write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def run_producer(name, argv, directory):
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    begin = time.monotonic()
    launch = {'name': name, 'argv': argv, 'cwd': str(REPO), 'startUtc': start}
    write(directory / (name + '-launch.json'), launch)
    with (directory / (name + '-stdout')).open('xb') as out, (directory / (name + '-stderr')).open('xb') as err:
        result = subprocess.run(argv, cwd=REPO, stdout=out, stderr=err)
    receipt = {**launch, 'endUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'elapsedSeconds': time.monotonic() - begin, 'exitCode': result.returncode}
    write(directory / (name + '-terminal.json'), receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True, help='NEW absolute directory with canonical nonsymlink ancestry; existing paths are refused')
    args = parser.parse_args()
    directory = pathlib.Path(args.output_dir)
    try:
        require(directory.is_absolute(), 'output directory must be absolute')
        require(not any(p.is_symlink() for p in (directory, *directory.parents)), 'symlink output ancestry refused')
        directory.mkdir()  # Atomic exclusive create; never reuse even an empty prior run.
    except (OSError, ValueError) as error:
        print('HEALTH GATE REFUSED before producers: ' + str(error), file=sys.stderr)
        return 1
    report = {'status': 'INCOMPLETE', 'producerExecutionCertified': False,
              'qualification': 'synthetic fixture execution only; review44 filesystem results are selected dispositions, with injected listed-child metadata denial; no live collector/release claim', 'producers': {}, 'issues': []}
    try:
        before = source_pins()
        report['sourcePinsBefore'] = before
        commands = {
            'python': [sys.executable, '-B', str(REPO / 'tests/run_python_health_tests.py'), '--xml', str(directory / 'python.xml'), '--parity-output', str(directory / 'python-parity.json')],
            'java': ['/bin/sh', str(REPO / 'tests/run_java_health_tests.sh'), '--xml', str(directory / 'java.xml'), '--scratch', str(directory / 'java-scratch'), '--parity-output', str(directory / 'java-parity.json')],
        }
        for name, argv in commands.items():
            try:
                receipt = run_producer(name, argv, directory)
                report['producers'][name] = receipt
                receipt['junit'] = verify_producer(receipt, directory / (name + '.xml'), directory / (name + '-parity.json'))
                receipt['paritySha256'] = hashlib.sha256(read_regular(directory / (name + '-parity.json'))[0]).hexdigest()
            except (OSError, ValueError) as error:
                report['issues'].append(name + ': ' + str(error))
        report['sourcePinsAfter'] = source_pins()
        require(before == report['sourcePinsAfter'], 'source changed during gate')
        require(not report['issues'] and len(report['producers']) == 2, 'both successful fresh producers/JUnit are required')
        report['comparison'] = compare_files(directory / 'python-parity.json', directory / 'java-parity.json')
        report['status'] = 'PASS'
        report['producerExecutionCertified'] = True
    except (OSError, ValueError, RecursionError) as error:
        report['issues'].append(str(error))
        report['status'] = 'FAIL'
    finally:
        report['endUtc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        write(directory / 'gate.json', report)
    print(json.dumps({'status': report['status'], 'report': str(directory / 'gate.json'), 'issues': report['issues']}))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
