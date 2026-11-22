#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Own host names on the installed host (ci.sh --install): a test name answers through unbound (A, AAAA, PTR of the private
address) and through /etc/hosts (getent); the name of this host alone wins and goes again; names eFa-next needs are refused;
after the removal unbound and /etc/hosts know the name no more. Everything is put back as it was."""
import json
import subprocess
import sys

NAME, ADDRESS, ADDRESS6, LOCAL = 'ci-hosts-live.example', '10.255.0.7', '2001:db8::7', '10.255.0.8'


def run(*cmd, check=True):
    done = subprocess.run(cmd, capture_output=True, text=True)
    if check and done.returncode != 0:
        raise SystemExit(f'{" ".join(cmd)}: {(done.stdout + done.stderr)[-400:]}')
    return done


def efactl(*args, check=True):
    done = run('/usr/sbin/efactl', *args, check=check)
    return json.loads(done.stdout or '{}') if done.returncode == 0 else {}, done.returncode


def dig(name, kind):
    """The answers of the unbound of this host; PTR as a reverse lookup of the address (dig -x)."""
    query = ['-x', name] if kind == 'PTR' else [name, kind]
    return run('dig', '+short', '+time=3', '+tries=1', '@127.0.0.1', *query, check=False).stdout.split()


def getent(name):
    """The first IPv4 address the system resolver (/etc/hosts first) gives; getent hosts would prefer the IPv6 one."""
    return run('getent', 'ahostsv4', name, check=False).stdout.split()[:1]


def main():
    listed, _code = efactl('hosts-list')
    if NAME in listed.get('entries', {}):
        print('hosts-live: skipped, the test name is set already')
        return 0
    try:
        for bad in ('repo.efa-next.eu', 'localhost', 'x.zen.spamhaus.org'):
            assert efactl('hosts-set', f'--name={bad}', '--action=add', f'--addresses={ADDRESS}', check=False)[1] != 0, f'{bad} must be refused'
        assert efactl('hosts-set', '--name=loop.example', '--action=add', '--addresses=127.0.0.2', check=False)[1] != 0, 'loopback refused'
        efactl('hosts-set', f'--name={NAME}', '--action=add', f'--addresses={ADDRESS} {ADDRESS6}', '--note=CI')
        assert dig(NAME, 'A') == [ADDRESS], dig(NAME, 'A')
        assert dig(NAME, 'AAAA') == [ADDRESS6], dig(NAME, 'AAAA')
        assert dig(ADDRESS, 'PTR') == [NAME + '.'], dig(ADDRESS, 'PTR')
        assert getent(NAME) == [ADDRESS], getent(NAME)
        efactl('hosts-local-set', f'--name={NAME}', '--action=add', f'--addresses={LOCAL}')
        assert dig(NAME, 'A') == [LOCAL] and getent(NAME) == [LOCAL], 'the name of this host wins'
        efactl('hosts-local-set', f'--name={NAME}', '--action=remove')
        assert dig(NAME, 'A') == [ADDRESS], 'the name of the cluster again'
        efactl('hosts-set', f'--name={NAME}', '--action=remove')
        assert dig(NAME, 'A') == [] and getent(NAME) == [], 'gone after the removal'
        with open('/etc/hosts') as f:
            assert NAME not in f.read()
        print('hosts-live: ok')
        return 0
    finally:
        entries = efactl('hosts-list')[0].get('entries', {})
        if entries.get(NAME, {}).get('scope') == 'host':
            efactl('hosts-local-set', f'--name={NAME}', '--action=remove', check=False)
            entries = efactl('hosts-list')[0].get('entries', {})
        if NAME in entries:
            efactl('hosts-set', f'--name={NAME}', '--action=remove', check=False)


if __name__ == '__main__':
    sys.exit(main())
