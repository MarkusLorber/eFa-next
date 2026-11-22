#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Hans 2026-11-20 (criterion 3 of 6.0.0.6) on the installed host (ci.sh --install): the base system updates with a plain dnf
in its branch, and eFa-next stays green. 1. dnf could take every update of the third-party packages now (no conflict, no
requirement of eFa-next in the way). 2. The base packages reinstalled in the same version, as an update replaces their files;
the check after the package change (efa-os-check.path) restarts the services that still ran the replaced files, Python code
included, and finds nothing; efactl status is ok. The versions on the host do not change."""
import json
import os
import subprocess
import sys
import time

CHECK = '/var/lib/eFa/os-check.json'
BASE = ('clamd', 'rspamd', 'redis', 'valkey', 'fail2ban-server', 'nginx-core', 'python3-flask', 'python3-pymilter')
OWN = ('--exclude=eFa-next', '--exclude=eFa-next-base', '--exclude=eFa', '--exclude=eFa-base')


def run(*cmd, check=False, timeout=1800):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def main():
    # 1. What dnf would do now with the third-party updates: never a problem caused by eFa-next.
    done = run('dnf', 'upgrade', '--assumeno', *OWN)
    text = done.stdout + done.stderr
    if 'Problem' in text or 'conflicting requests' in text or 'nothing provides' in text:
        raise SystemExit(f'third-party-update: dnf cannot take the updates:\n{text[-1500:]}')
    pending = [line.split()[0] for line in text.splitlines() if line.startswith(' ') and len(line.split()) >= 4 and '.' in line.split()[1]]
    print(f'third-party-update: dnf would update {len(pending)} packages, no problem')

    # 2. The base packages replaced in their version: the check after the package change restarts what still ran them.
    installed = [name for name in BASE if run('rpm', '-q', name).returncode == 0]
    before = (json.load(open(CHECK)) if os.path.exists(CHECK) else {}).get('checked')
    started = time.time()
    replaced = []
    for name in installed:
        if run('dnf', '-y', '-q', 'reinstall', name).returncode == 0:
            replaced.append(name)
        else:
            print(f'third-party-update: {name} not reinstalled (its version is no longer in the repository)')
    if not replaced:
        print('third-party-update: no base package could be reinstalled, step 2 skipped')
        return 0
    # efa-os-check waits until the package database is quiet for 30 s; the result is new once its time moved on.
    for _wait in range(120):
        result = json.load(open(CHECK)) if os.path.exists(CHECK) else {}
        if result.get('checked') and result.get('checked') != before and time.time() - started > 35:
            break
        time.sleep(5)
    else:
        raise SystemExit('third-party-update: efa-os-check gave no new result within 10 minutes')
    print(f"third-party-update: reinstalled {', '.join(replaced)}; restarted {', '.join(result.get('restarted') or []) or 'nothing'}")
    problems = []
    if not result.get('ok'):
        problems.append(f"os-check not ok: {result.get('findings')}")
    if 'python3-flask' in replaced and 'efa-web' not in (result.get('restarted') or []):
        problems.append('efa-web was not restarted after python3-flask')
    stale = run('needs-restarting', '-s').stdout.split()
    left = [unit for unit in stale if unit.startswith(('efa-web', 'efa-milter', 'efa-maillog', 'clamd@', 'rspamd', 'redis', 'valkey', 'postfix'))]
    if left:
        problems.append(f'still running replaced files: {left}')
    for _try in range(12):  # the restarted services need a moment
        status = json.loads(run('/usr/sbin/efactl', 'status').stdout or '{}')
        if status.get('status') == 'ok':
            break
        time.sleep(5)
    if status.get('status') != 'ok':
        problems.append(f"efactl status {status.get('status')}: {status.get('down')}")
    if problems:
        raise SystemExit('third-party-update: ' + '; '.join(problems))
    print('third-party-update: ok')
    return 0


if __name__ == '__main__':
    sys.exit(main())
