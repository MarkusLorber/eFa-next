#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""CI: the sshd.local that efactl writes (fail2ban CVE-2026-109786) against the sshd filter of the fail2ban on this host.

A crafted user name "x 192.0.2.1 on" must not make fail2ban find 192.0.2.1; the address found is the real client's.
Skipped (ok) where fail2ban-regex is not installed.
"""
import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile

FILTERS = '/etc/fail2ban/filter.d'
PREFIX = 'Nov 12 04:00:00 mx sshd[123]: '
LINES = {'Connection closed by invalid user x 192.0.2.1 on 192.0.2.77 port 22 [preauth]': '192.0.2.77',
         'Failed password for invalid user x 192.0.2.1 on from 192.0.2.77 port 22 ssh2': '192.0.2.77',
         'Failed password for root from 192.0.2.78 port 22 ssh2': '192.0.2.78',
         'Connection closed by authenticating user root 192.0.2.79 port 22 [preauth]': '192.0.2.79'}


def main():
    if shutil.which('fail2ban-regex') is None or not os.path.exists(FILTERS + '/sshd.conf'):
        print('fail2ban-regex not installed: skipped')
        return 0
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
    loader = importlib.machinery.SourceFileLoader('efactl', os.path.join(root, 'next', 'usr', 'sbin', 'efactl'))
    efactl = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl', loader))
    loader.exec_module(efactl)
    failed = 0
    with tempfile.TemporaryDirectory() as folder:
        for name in ('sshd.conf', 'common.conf'):
            shutil.copy(f'{FILTERS}/{name}', folder)
        with open(folder + '/sshd.local', 'w') as f:
            f.write(efactl.FAIL2BAN_SSHD_FIX_TEXT)
        for line, wanted in LINES.items():
            found = subprocess.run(['fail2ban-regex', '-o', 'ip', PREFIX + line, f'{folder}/sshd.conf[mode=aggressive]'],
                                   capture_output=True, text=True, timeout=60).stdout.split()
            ok = found == [wanted]
            failed += not ok
            print(('ok  ' if ok else 'FAIL'), line, '->', ' '.join(found) or 'nothing', '' if ok else f'(wanted {wanted})')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
