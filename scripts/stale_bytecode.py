#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""CI on an installed host: an upgrade must run the new code even when a module keeps its size and its (clamped) time.

    stale_bytecode.py --plant    bytecode of a changed efa_nav.py of the same size and time, as an older package left it
    stale_bytecode.py --check    after the install: Python runs the installed source, not that bytecode

The changed text replaces the first line of the module by a marker of the same length; the module itself stays as it is.
"""
import os
import py_compile
import subprocess
import sys

LIBRARY = '/usr/lib/eFa/python'
MODULE = os.path.join(LIBRARY, 'efa_nav.py')
PROBE = [sys.executable, '-I', '-c', f'import sys; sys.path.insert(0, {LIBRARY!r}); import efa_nav; print(hasattr(efa_nav, "EFA_STALE"))']


def plant():
    with open(MODULE, 'rb') as f:
        real = f.read()
    info = os.stat(MODULE)
    first, rest = real.split(b'\n', 1)
    marker = b'EFA_STALE = 1'
    if len(first) < len(marker):
        raise SystemExit(f'{MODULE}: first line shorter than the marker')
    try:
        with open(MODULE, 'wb') as f:
            f.write(marker.ljust(len(first)) + b'\n' + rest)
        os.utime(MODULE, ns=(info.st_atime_ns, info.st_mtime_ns))
        # Timestamp bytecode, as Python writes it by default: valid for every source of this size and time.
        py_compile.compile(MODULE, invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP, doraise=True)
    finally:
        with open(MODULE, 'wb') as f:
            f.write(real)
        os.utime(MODULE, ns=(info.st_atime_ns, info.st_mtime_ns))
    stale = subprocess.run(PROBE, capture_output=True, text=True, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}).stdout.strip()
    if stale != 'True':
        raise SystemExit(f'the planted bytecode is not used ({stale!r}): the test proves nothing')
    print('stale bytecode planted: the old code runs until the install compiles by hash')


def check():
    now = subprocess.run(PROBE, capture_output=True, text=True, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}).stdout.strip()
    if now != 'False':
        raise SystemExit(f'after the install Python still runs the stale bytecode of {MODULE} ({now!r})')
    print('after the install the source runs, not the stale bytecode')


if __name__ == '__main__':
    {'--plant': plant, '--check': check}.get(sys.argv[1] if len(sys.argv) > 1 else '', lambda: sys.exit(__doc__))()
