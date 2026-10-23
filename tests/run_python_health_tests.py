#!/usr/bin/env python3
"""Dependency-free fixture runner with real per-case JUnit and optional parity data."""
import argparse
import datetime
import importlib.util
import io
import json
import pathlib
import sys
import time
import traceback
import unittest
import xml.etree.ElementTree as ET


class Result(unittest.TextTestResult):
    def startTest(self, test):
        self.started = time.monotonic()
        self.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.case = {'name': test.id(), 'timestamp': self.timestamp, 'status': 'passed'}
        super().startTest(test)

    def addFailure(self, test, error):
        self.case.update(status='failure', detail=''.join(traceback.format_exception(*error)))
        super().addFailure(test, error)

    def addError(self, test, error):
        self.case.update(status='error', detail=''.join(traceback.format_exception(*error)))
        super().addError(test, error)

    def addSkip(self, test, reason):
        self.case.update(status='skipped', detail=reason)
        super().addSkip(test, reason)

    def addSubTest(self, test, subtest, error):
        if error is not None:
            self.case.update(status='failure', detail=''.join(traceback.format_exception(*error)))
        super().addSubTest(test, subtest, error)

    def stopTest(self, test):
        self.case['seconds'] = time.monotonic() - self.started
        self.records.append(self.case)
        super().stopTest(test)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--xml', required=True)
    ap.add_argument('--parity-output')
    ap.add_argument('--case', action='append', help='Exact case name for focused fixture checks; default is the full suite')
    ap.add_argument('--fatal-control', action='store_true', help='Expected nonzero fully fake fatal-lifecycle discriminator')
    args = ap.parse_args()
    for output in [args.xml, args.parity_output]:
        if output and pathlib.Path(output).exists():
            ap.error('refusing an existing output')
    spec = importlib.util.spec_from_file_location('test_collection_health', pathlib.Path(__file__).with_name('test_collection_health.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if args.fatal_control:
        trace = []
        try:
            module.fatal_lifecycle_fixture(trace)
        finally:
            print(json.dumps({'fakeFatalLifecycleTrace': trace}), flush=True)
        raise AssertionError('fatal lifecycle unexpectedly returned')
    if args.case:
        names = set(unittest.defaultTestLoader.getTestCaseNames(module.CollectionHealthTests))
        if len(set(args.case)) != len(args.case) or any(name not in names for name in args.case):
            ap.error('invalid or repeated focused case')
        suite = unittest.TestSuite(module.CollectionHealthTests(name) for name in args.case)
    else:
        suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
    root = ET.Element('testsuite', name='python.collection-health', tests=str(result.testsRun),
                      failures=str(len(result.failures)), errors=str(len(result.errors)),
                      skipped=str(len(result.skipped)), timestamp=started,
                      time=str(sum(r['seconds'] for r in result.records)))
    for record in result.records:
        case = ET.SubElement(root, 'testcase', classname='CollectionHealthTests', name=record['name'],
                             timestamp=record['timestamp'], time=str(record['seconds']))
        if record['status'] != 'passed':
            ET.SubElement(case, record['status'], message=record['status']).text = record.get('detail', '')
    path = pathlib.Path(args.xml)
    path.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(path, encoding='utf-8', xml_declaration=True)
    if args.parity_output and result.wasSuccessful():
        target = pathlib.Path(args.parity_output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(module.parity_snapshots(), sort_keys=True, indent=2) + '\n')
    print(json.dumps({'tests': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
                      'skipped': len(result.skipped), 'xml': str(path), 'successful': result.wasSuccessful()}), flush=True)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
