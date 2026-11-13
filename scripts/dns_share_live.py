#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""DNS-SHARE on the installed host (ci.sh --install): the own address of this host as a /32 that may ask its unbound. Asked
from that address, unbound answers; the firewall has the two rules of that source; a bad network is refused; after the removal
unbound refuses (or no longer listens) and the rules are gone. The list is put back as it was."""
import json
import subprocess
import sys


def run(*cmd, check=True):
    done = subprocess.run(cmd, capture_output=True, text=True)
    if check and done.returncode != 0:
        raise SystemExit(f'{" ".join(cmd)}: {(done.stdout + done.stderr)[-400:]}')
    return done


def efactl(*args, check=True):
    done = run('/usr/sbin/efactl', *args, check=check)
    return json.loads(done.stdout or '{}'), done.returncode


def ask(source):
    """The status of a query for the root NS from source to source: NOERROR, REFUSED, or none (no answer at all)."""
    done = run('dig', '+time=3', '+tries=1', '-b', source, f'@{source}', '.', 'NS', check=False)
    for word in ('NOERROR', 'REFUSED'):
        if f'status: {word}' in done.stdout:
            return word
    return 'none'


def rules():
    zones = [line.split()[0] for line in run('firewall-cmd', '--get-active-zones').stdout.splitlines() if line and not line[0].isspace()]
    return '\n'.join(run('firewall-cmd', f'--zone={zone}', '--list-rich-rules').stdout for zone in zones)


def main():
    own = run('ip', '-4', '-o', 'route', 'get', '192.0.2.1').stdout.split(' src ')[1].split()[0]
    net = f'{own}/32'
    listed, _rc = efactl('dns-share-list')
    if any(entry['net'] == net for entry in listed['entries']):
        print('dns-share-live: skipped, the own address is in the list already')
        return 0
    try:
        _bad, code = efactl('dns-share-add', '--nets=0.0.0.0/0', check=False)
        assert code != 0, 'an open resolver must be refused'
        efactl('dns-share-add', f'--nets={net}', '--note=CI')
        assert ask(own) == 'NOERROR', 'the allowed source gets an answer'
        assert f'source address="{net}" port port="53" protocol="udp"' in rules() and 'protocol="tcp"' in rules()
        efactl('dns-share-del', f'--nets={net}')
        assert ask(own) in ('REFUSED', 'none'), 'after the removal it is refused'
        assert f'source address="{net}"' not in rules(), 'the firewall rules are gone'
        print('dns-share-live: ok')
        return 0
    finally:
        if any(entry['net'] == net for entry in efactl('dns-share-list')[0]['entries']):
            efactl('dns-share-del', f'--nets={net}', check=False)


if __name__ == '__main__':
    sys.exit(main())
