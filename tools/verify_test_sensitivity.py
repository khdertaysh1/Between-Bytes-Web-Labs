#!/usr/bin/env python3
"""Prove existing tests reject three dangerous regressions, in disposable copies.

These are deterministic mutation checks, not production source changes. A mutant
only counts as detected when a passing control test becomes an assertion failure.
An import error, syntax error or timeout is an invalid experiment and fails CI.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'artifacts' / 'sensitivity'
GUARDS = (
    {
        'name': 'payment-fixed-policy',
        'path': 'academy.py',
        'before': 'return checkout_execute(kind,fixed,d,s,integer,text)',
        'after': 'return checkout_execute(kind,False,d,s,integer,text)',
        'test': 'test_academy.ScenarioTests.test_every_nonbrowser_case_has_impact_protection_and_usable_control',
    },
    {
        'name': 'document-owner-authorization',
        'path': 'academy.py',
        'before': 'if fixed and foreign:status = 403',
        'after': 'if False and foreign:status = 403',
        'test': 'test_academy.ScenarioTests.test_cross_tenant_batch_and_mass_assignment_are_denied',
    },
    {
        'name': 'csrf-session-token',
        'path': 'studio_browser.py',
        'before': 'else 403 if origin!=expected or not correct else 200',
        'after': 'else 403 if origin!=expected or False else 200',
        'test': 'test_studio_browser.BrowserStudioHTTP.test_real_csrf_write_rejects_missing_empty_wrong_session_token_and_keeps_state',
    },
)


def execute(root, test, log):
    env = os.environ.copy()
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    # Do not let a global PYTHONPATH load the real checkout instead of its copy.
    env['PYTHONPATH'] = str(root)
    result = subprocess.run([sys.executable, '-B', '-m', 'unittest', '-v', test],
                            cwd=root / 'tests', env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=60)
    log.write_text(result.stdout, encoding='utf-8')
    return result.returncode, result.stdout


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    report = []
    with tempfile.TemporaryDirectory(prefix='between-bytes-regression-') as temp:
        for guard in GUARDS:
            root = Path(temp) / guard['name']
            shutil.copytree(ROOT, root, ignore=shutil.ignore_patterns(
                '.git', 'node_modules', '__pycache__', 'artifacts', '.venv'))
            code, output = execute(root, guard['test'], OUTPUT / (guard['name'] + '-control.log'))
            if code:
                raise RuntimeError('Control test did not pass for ' + guard['name'] + '\n' + output)
            path = root / guard['path']
            original = path.read_text(encoding='utf-8')
            if guard['before'] not in original:
                raise RuntimeError('Mutation anchor changed: review and update guard ' + guard['name'])
            path.write_text(original.replace(guard['before'], guard['after'], 1), encoding='utf-8')
            code, output = execute(root, guard['test'], OUTPUT / (guard['name'] + '-mutant.log'))
            caught = code != 0 and 'FAIL:' in output and 'AssertionError' in output and 'FAILED (' in output and 'ERROR:' not in output
            report.append({'guard': guard['name'], 'test': guard['test'], 'control_passed': True,
                           'mutation_detected_by_assertion': caught})
            if not caught:
                raise RuntimeError('Regression was not reliably detected: ' + guard['name'] + '\n' + output)
            print('PASS: existing tests rejected ' + guard['name'], flush=True)
    (OUTPUT / 'summary.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print('SENSITIVITY CHECK FAILED: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
