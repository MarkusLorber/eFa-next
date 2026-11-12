#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""MIG-DNS on the installed host (ci.sh --install): a forwarders file as eFa 5 left it (all names to 8.8.8.8, an internal zone
to its own server). efactl dns-forward-fix moves it away, keeps the internal zone under Internal DNS, unbound resolves itself:
MX lookups work and the test entries of Spamhaus ZEN and Spamcop answer listed. Everything is put back afterwards."""
import json
import os
import subprocess
import sys

PLANTED = '/etc/unbound/conf.d/forwarders.conf'
ZONE = 'ci-internal.example'
BACKUP = '/var/tmp/efa-ci-dns-forwarders'


def run(*cmd, check=True):
    done = subprocess.run(cmd, capture_output=True, text=True)
    if check and done.returncode != 0:
        raise SystemExit(f'{" ".join(cmd)}: {(done.stdout + done.stderr)[-400:]}')
    return done.stdout


def efactl(*args):
    return json.loads(run('/usr/sbin/efactl', *args))


def main():
    if os.path.exists(PLANTED) or ZONE in efactl('dns-zone-list')['zones']:
        print('dns-forward-live: skipped, this host has its own forwarders file or the test zone')
        return 0
    try:
        with open(PLANTED, 'w') as f:
            f.write(f'server:\n  domain-insecure: "{ZONE}"\nforward-zone:\n  name: "."\n  forward-addr: 8.8.8.8\n'
                    f'forward-zone:\n  name: "{ZONE}"\n  forward-addr: 192.0.2.53\n')
        run('systemctl', 'restart', 'unbound')
        before = efactl('dns-forward-status')
        assert before['forward_all'] and before['public'], before
        fixed = efactl('dns-forward-fix', f'--backup={BACKUP}')
        print(json.dumps(fixed))
        assert not os.path.exists(PLANTED) and os.path.exists(f'{BACKUP}/forwarders.conf'), 'the file is moved, not lost'
        assert fixed['internal_zones_kept'] == [ZONE] and efactl('dns-zone-list')['zones'][ZONE]['servers'] == ['192.0.2.53']
        assert efactl('dns-zone-list')['zones'][ZONE]['dnssec'] is False, 'domain-insecure of eFa 5 kept'
        assert fixed['check']['mx'] and not fixed['check']['forward_warning'], fixed['check']
        assert all(fixed['check']['lists'].values()), 'the test entries of the lists answer listed: ' + json.dumps(fixed['check'])
        assert not efactl('dns-forward-status')['forward_all']
        # Already done (a host fixed by hand or by the first run): nothing to do, no error, the zone once.
        again = efactl('dns-forward-fix', f'--backup={BACKUP}')
        assert again == {'forward_all': False, 'note': 'unbound resolves itself already.'}, again
        assert list(efactl('dns-zone-list')['zones']).count(ZONE) == 1
        print('dns-forward-live: ok')
        return 0
    finally:
        if os.path.exists(PLANTED):
            os.remove(PLANTED)
        if ZONE in efactl('dns-zone-list')['zones']:
            efactl('dns-zone-set', f'--zone={ZONE}', '--action=remove')
        run('rm', '-rf', BACKUP, check=False)
        run('systemctl', 'restart', 'unbound', check=False)


if __name__ == '__main__':
    sys.exit(main())
