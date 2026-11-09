#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Flags direct calls of EL9-only tools and paths outside the platform layer (efa_platform*.py).

Existing calls are counted per file in scripts/os-calls-baseline.json: the check fails when a file has more than its baseline,
so new code goes through the platform layer while the old calls move there step by step (docs/FREEBSD-PORT.md).
    os_lint.py [--write-baseline]
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join(ROOT, 'scripts', 'os-calls-baseline.json')
TREES = ('next', 'src', 'migration')
# A tool as a word in quotes or at the start of a command, or a path of EL9 only.
PATTERNS = {
    'systemctl': r"['\"]systemctl['\"]|\bsystemctl\s", 'dnf/rpm': r"['\"](dnf|rpm|yum)['\"]|\b(dnf|yum)\s+-",
    'firewalld/nft/ipset': r"['\"](firewall-cmd|nft|ipset)['\"]|\bfirewall-cmd\s", 'selinux': r"\b(restorecon|semanage|chcon|setsebool)\b",
    'auditd': r"\b(augenrules|auditctl)\b", 'systemd-run': r"['\"]systemd-run['\"]|\bsystemd-run\s", 'journalctl': r"['\"]journalctl['\"]|\bjournalctl\s",
    'logrotate': r"\blogrotate\b", '/etc/sysconfig': r"/etc/sysconfig", '/proc': r"['\"]/proc/",
}
COMPILED = {name: re.compile(pattern) for name, pattern in PATTERNS.items()}


def scan(path):
    counts = {}
    try:
        with open(path, encoding='utf-8') as f:
            text = f.read()
    except (UnicodeDecodeError, OSError):
        return counts
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        for name, pattern in COMPILED.items():
            if pattern.search(line):
                counts[name] = counts.get(name, 0) + 1
    return counts


def files():
    for tree in TREES:
        for folder, _dirs, names in os.walk(os.path.join(ROOT, tree)):
            for name in names:
                if name.startswith('efa_platform') or name.endswith(('.pyc', '.png', '.svg', '.gz', '.md')):
                    continue
                yield os.path.relpath(os.path.join(folder, name), ROOT).replace('\\', '/')


def main():
    found = {path: counts for path in sorted(files()) if (counts := scan(os.path.join(ROOT, path)))}
    if '--write-baseline' in sys.argv:
        with open(BASELINE, 'w') as f:
            json.dump(found, f, indent=1, sort_keys=True)
        print(f'os-lint: baseline written, {sum(sum(c.values()) for c in found.values())} calls in {len(found)} files')
        return 0
    baseline = json.load(open(BASELINE)) if os.path.exists(BASELINE) else {}
    worse = [(path, name, count, baseline.get(path, {}).get(name, 0)) for path, counts in found.items() for name, count in counts.items()
             if count > baseline.get(path, {}).get(name, 0)]
    for path, name, count, allowed in worse:
        print(f'os-lint: {path}: {count} direct {name} calls, baseline {allowed}: use the platform layer')
    total = sum(sum(c.values()) for c in found.values())
    print(f'os-lint: {"FAILED" if worse else "ok"}, {total} direct calls outside the platform layer (baseline {sum(sum(c.values()) for c in baseline.values())})')
    return 1 if worse else 0


def self_test():
    import tempfile
    with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as f:
        f.write("subprocess.run(['systemctl', 'reload', 'x'])\n# systemctl in a comment\nx = '/proc/loadavg'\nrun('restorecon -R /x')\n")
    counts = scan(f.name)
    os.remove(f.name)
    assert counts == {'systemctl': 1, '/proc': 1, 'selinux': 1}, counts
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
        sys.exit(0)
    sys.exit(main())
