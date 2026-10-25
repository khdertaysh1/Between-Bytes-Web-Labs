#!/usr/bin/env python3
"""Reject empty/shrunken discovery and hidden skipped/expected-failure coverage."""
import sys
import unittest
from quality import ROOT, MINIMUM_PYTHON_TESTS

suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
count = suite.countTestCases()
if count < MINIMUM_PYTHON_TESTS:
    print(f'FAILED: discovered {count} tests; minimum is {MINIMUM_PYTHON_TESTS}.', file=sys.stderr)
    raise SystemExit(1)
result = unittest.TextTestRunner(verbosity=2).run(suite)
if result.skipped or result.expectedFailures:
    print('FAILED: skipped or expected-failure tests require explicit review; '
          'the baseline has no permitted skips/xfails.', file=sys.stderr)
    raise SystemExit(1)
if result.testsRun < MINIMUM_PYTHON_TESTS:
    print('FAILED: too few tests actually ran.', file=sys.stderr)
    raise SystemExit(1)
raise SystemExit(0 if result.wasSuccessful() else 1)
