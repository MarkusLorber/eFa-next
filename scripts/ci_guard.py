#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The main.cf of Postfix around a live step of the CI that changes it.

A live step (sender_allow_live.py, maintenance_cidr_live.py, le_takeover_live.py, live_test.sh) puts its changes back in its
finally or trap. A run stopped from outside (systemctl stop sends SIGTERM) skipped that for the Python steps, and a later run
found test settings in main.cf (2026-11-18: reject_unknown_sender_domain of sender_allow_live, every live mail then 450).
So: SIGTERM ends a Python step through its finally, and each step leaves a marker with the main.cf of before while it runs;
ci.sh puts back the oldest one it finds when it starts (restore), checked by postfix check, then postfix reload.
"""
import glob
import os
import shutil
import signal
import subprocess
import sys

DIR = '/var/tmp/efa-ci-restore'
MAIN_CF = '/etc/postfix/main.cf'


def begin(name, main_cf=MAIN_CF, folder=DIR):
    """The main.cf of before as the marker of this step; SIGTERM from now on ends the step through its finally."""
    os.makedirs(folder, mode=0o700, exist_ok=True)
    shutil.copy2(main_cf, f'{folder}/{name}.main.cf')
    signal.signal(signal.SIGTERM, lambda _signum, _frame: sys.exit(143))


def end(name, folder=DIR):
    """The step put main.cf back itself: its marker goes."""
    try:
        os.remove(f'{folder}/{name}.main.cf')
    except FileNotFoundError:
        pass


def restore(main_cf=MAIN_CF, folder=DIR, run=subprocess.run):
    """Left-over markers of a stopped run: the oldest main.cf back (the one before all of them), then postfix check and
    reload; with a failed check the main.cf of now stays and the run stops. Returns what was done, [] for nothing."""
    markers = sorted(glob.glob(f'{folder}/*.main.cf'), key=os.path.getmtime)
    if not markers:
        return []
    current = main_cf + '.ci-before-restore'
    shutil.copy2(main_cf, current)
    shutil.copy2(markers[0], main_cf)
    if run(['postfix', 'check'], capture_output=True).returncode != 0:
        shutil.copy2(current, main_cf)
        raise SystemExit(f'ci: left-over {markers[0]} did not pass postfix check; main.cf left as it was ({current})')
    run(['postfix', 'reload'], capture_output=True)
    for marker in markers:
        os.remove(marker)
    return [f'main.cf of {os.path.basename(markers[0])[:-len(".main.cf")]} put back'] + [
        f'marker {os.path.basename(marker)} dropped' for marker in markers[1:]]


if __name__ == '__main__':
    for line in restore():
        print('ci: left over from a stopped run:', line)
