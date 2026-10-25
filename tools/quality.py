#!/usr/bin/env python3
"""Local/CI entry point. Fail on empty test discovery, missing suites or any failure."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / 'artifacts'
MINIMUM_PYTHON_TESTS = 69
BROWSER_GROUPS = {
    'academy': ('academy', 'payloads'),
    'workspace': ('studio', 'studio_browser', 'studio_edges'),
    'regressions': ('grouped', 'request_security', 'payment_status', 'audit_edges'),
}


def command(args, log, *, timeout=360, cwd=ROOT, env=None):
    """Preserve full logs, emit useful output and propagate nonzero exits/timeouts."""
    log.parent.mkdir(parents=True, exist_ok=True)
    print('+ ' + ' '.join(map(str, args)), flush=True)
    try:
        with log.open('w', encoding='utf-8') as out:
            result = subprocess.run(args, cwd=cwd, env=env, stdout=out,
                                    stderr=subprocess.STDOUT, timeout=timeout)
        code = result.returncode
    except subprocess.TimeoutExpired:
        code = 124
        with log.open('a', encoding='utf-8') as out:
            out.write('\nFAILED: test command exceeded its timeout.\n')
    output = log.read_text(encoding='utf-8', errors='replace')
    print(output, end='' if output.endswith('\n') else '\n', flush=True)
    return code


def python_tests():
    return command([sys.executable, 'tools/run_python_tests.py'],
                   ARTIFACTS / 'python.log', timeout=300)


def browser_tests(group):
    names = tuple(name for values in BROWSER_GROUPS.values() for name in values) if group == 'all' else BROWSER_GROUPS[group]
    for name in names:
        if not (ROOT / 'tests' / (name + '.cjs')).is_file():
            raise RuntimeError('Required browser suite is missing: ' + name)
    directory = ARTIFACTS / ('browser-' + group)
    directory.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env['BB_SCREENSHOT_DIR'] = str(directory)
    server_log = directory / 'server.log'
    failed = []
    with server_log.open('w', encoding='utf-8') as out:
        server = subprocess.Popen([sys.executable, '-u', 'app.py', '--port', '8000'],
                                  cwd=ROOT, stdout=out, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 15
            marker = 'Between Bytes Labs: http://127.0.0.1:8000'
            while marker not in server_log.read_text(encoding='utf-8', errors='replace'):
                if server.poll() is not None:
                    raise RuntimeError('Lab server exited before startup; see ' + str(server_log))
                if time.monotonic() >= deadline:
                    raise RuntimeError('Lab server startup timed out')
                time.sleep(.1)
            # Never silently attach these tests to a pre-existing service on this port.
            if server.poll() is not None:
                raise RuntimeError('Lab server exited during startup')
            with urlopen('http://127.0.0.1:8000/academy/catalog', timeout=3) as response:
                catalog = json.load(response)
            if not isinstance(catalog.get('cases'), list) or not catalog['cases']:
                raise RuntimeError('Started server did not expose a usable catalog')
            for name in names:
                code = command(['node', 'tests/' + name + '.cjs'], directory / (name + '.log'), env=env)
                complete = 'PASS:' in (directory / (name + '.log')).read_text(encoding='utf-8', errors='replace')
                if code or not complete:
                    failed.append({'suite': name, 'exit_code': code, 'completion_marker': complete})
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
    (directory / 'summary.json').write_text(json.dumps({'suites': names, 'failed': failed}, indent=2) + '\n')
    if failed:
        print('FAILED browser suites: ' + ', '.join(item['suite'] for item in failed), flush=True)
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('python', 'browser', 'sensitivity', 'all'))
    parser.add_argument('--group', choices=(*BROWSER_GROUPS, 'all'), default='all')
    args = parser.parse_args()
    ARTIFACTS.mkdir(exist_ok=True)
    results = []
    try:
        if args.mode in {'python', 'all'}:
            results.append(python_tests())
        if args.mode in {'sensitivity', 'all'}:
            results.append(command([sys.executable, 'tools/verify_test_sensitivity.py'],
                                   ARTIFACTS / 'sensitivity.log', timeout=180))
        if args.mode in {'browser', 'all'}:
            results.append(browser_tests(args.group))
    except (RuntimeError, OSError, ValueError) as error:
        print('QUALITY CHECK FAILED: ' + str(error), file=sys.stderr)
        return 1
    return 1 if any(results) else 0


if __name__ == '__main__':
    raise SystemExit(main())
