#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""CI (6.0.0.6.4, G7): the parts that need a real host, each switched on for its check and put back as it was.

    g7_live.py geoip          GeoIP on, the real DB-IP Lite files (country and network), 1.1.1.1 looked up, off, files gone
    g7_live.py pyzor          Pyzor on, a made-up test mail to the local service, the service up, off again
    g7_live.py maillog-daily  maillog-setup, mailreport-run, mail-history with days, the table maillog_daily and its rights
    g7_live.py units          systemd-analyze verify of the new units, and the exposure score of their sandbox in the log
Only in CI: GeoIP and Pyzor talk to the internet while they run.
"""
import glob
import json
import os
import subprocess
import sys
import time
import urllib.request

EFACTL = '/usr/sbin/efactl'
UNITS = '/usr/lib/systemd/system'
GEOIP_DIR = '/var/lib/eFa/geoip'
PYZOR_URL = 'http://127.0.0.1:8912/check'
# The typed transfer confirmation of efactl (EU_CONFIRM): the CI may send the checksum of the made-up mail.
EU_CONFIRM = 'I accept the transfer outside the EU'
# A made-up mail: no address or text of a real mail ever goes to the Pyzor server.
TEST_MAIL = (b'From: ci@example.invalid\r\nTo: ci@example.invalid\r\nSubject: eFa-next CI Pyzor check\r\n'
             b'Message-ID: <pyzor-ci@example.invalid>\r\n\r\nA made-up text of the eFa-next CI, ' + str(time.time()).encode() + b'\r\n')


def efactl(command, **options):
    done = subprocess.run([EFACTL, command] + [f'--{key}={value}' for key, value in options.items()], capture_output=True, text=True, timeout=900)
    if done.returncode != 0:
        raise RuntimeError(f'efactl {command}: {(done.stderr or done.stdout).strip()[-300:]}')
    return json.loads(done.stdout or '{}')


def wait(check, seconds, what):
    for _ in range(seconds):
        if check():
            return
        time.sleep(1)
    raise AssertionError(f'{what}: not within {seconds} s')


def geoip():
    before = efactl('geoip-status')['active']
    try:
        efactl('geoip-set', mode='on', accept_terms='yes')
        # geoip-set starts the job in the background; the files come from download.db-ip.com.
        wait(lambda: all(item['present'] for item in efactl('geoip-status')['files'].values()), 600, 'GeoIP files')
        status = efactl('geoip-status')
        assert not status['warnings'], status['warnings']
        found = efactl('geoip-lookup', ip='1.1.1.1')
        assert found.get('cc') and found.get('asn'), f'1.1.1.1: country or network empty: {found}'
        active = subprocess.run(['systemctl', 'is-failed', '--quiet', 'efa-geoip.service']).returncode
        assert active != 0, 'efa-geoip.service failed (sandbox?)'
        result = f"1.1.1.1: {found.get('cc')} AS{found.get('asn')} {found.get('org', '')}"
    finally:
        if not before:
            efactl('geoip-set', mode='off')
    if not before:
        wait(lambda: not glob.glob(GEOIP_DIR + '/*.mmdb'), 120, 'GeoIP files removed after off')
        assert not efactl('geoip-status')['active']
    return result + ('; off again, files removed' if not before else '; it was on before, stays on')


def pyzor():
    before = efactl('pyzor-status')
    try:
        if not before['enabled']:
            try:
                efactl('pyzor-set', mode='on', accept='yes', confirm=EU_CONFIRM)
            except RuntimeError as err:
                if 'only services in the EU are allowed' in str(err):
                    return 'skipped: this host is set up for services in the EU only, the public Pyzor server is not'
                raise
        status = efactl('pyzor-status')
        assert status['enabled'] and status['package'], status
        assert status['server'] in status['transfer'] and 'outside the EU' in status['transfer'], status['transfer']
        wait(lambda: subprocess.run(['systemctl', 'is-active', '--quiet', 'efa-pyzor.service']).returncode == 0, 60, 'efa-pyzor.service')
        request = urllib.request.Request(PYZOR_URL, data=TEST_MAIL, method='POST')
        answer = json.loads(urllib.request.urlopen(request, timeout=30).read())
        # error would mean the Pyzor server did not answer: in CI with internet that is a failure.
        assert answer.get('state') in ('hit', 'clean'), answer
        result = f"efa-pyzor answers: {answer.get('state')} ({status['server']})"
    finally:
        if not before['enabled']:
            efactl('pyzor-set', mode='off')
    if not before['enabled']:
        wait(lambda: subprocess.run(['systemctl', 'is-active', '--quiet', 'efa-pyzor.service']).returncode != 0, 60, 'efa-pyzor stopped')
    return result + ('; off again' if not before['enabled'] else '; it was on before, stays on')


def mysql(sql):
    done = subprocess.run(['mysql', '-N', '-B', '-e', sql], capture_output=True, text=True, timeout=60)
    if done.returncode != 0:
        raise RuntimeError(f'mysql: {done.stderr.strip()[-200:]}')
    return done.stdout


def maillog_daily():
    efactl('maillog-setup')
    efactl('mailreport-run')
    assert mysql("SHOW TABLES FROM efa LIKE 'maillog_daily'").strip() == 'maillog_daily', 'no table maillog_daily'
    grants = mysql("SHOW GRANTS FOR 'efa_log'@'localhost'")
    line = [item for item in grants.splitlines() if 'maillog_daily' in item]
    assert line and all(right in line[0] for right in ('SELECT', 'INSERT', 'DELETE')), grants
    assert not any(right in line[0] for right in ('DROP', 'ALTER', 'ALL PRIVILEGES')), line[0]
    view = efactl('mail-history', format='')
    # days is the number of days of the course, series its points (one per day), weeks the calendar of the month.
    assert view['days'] == 30 and len(view['series']) == 30 and view['weeks'], {key: view[key] for key in ('days', 'month')}
    return f"maillog_daily there, efa_log: {line[0].split(' ON ')[0]}; mail-history: {len(view['series'])} days, {len(view['weeks'])} weeks"


def units():
    found = []
    for name in ('efa-geoip.service', 'efa-geoip.timer', 'efa-pyzor.service'):
        done = subprocess.run(['systemd-analyze', 'verify', '--man=no', os.path.join(UNITS, name)], capture_output=True, text=True)
        bad = [line for line in done.stderr.splitlines() if 'efa-' in line and ('Unknown' in line or 'Failed' in line or 'Invalid' in line)]
        assert not bad, (name, bad)
        if name.endswith('.service'):
            score = subprocess.run(['systemd-analyze', 'security', '--no-pager', name], capture_output=True, text=True).stdout.strip().splitlines()
            found.append(f"{name} {score[-1] if score else '?'}")
    return 'verify ok; ' + '; '.join(found)


def main():
    steps = {'geoip': geoip, 'pyzor': pyzor, 'maillog-daily': maillog_daily, 'units': units}
    if len(sys.argv) != 2 or sys.argv[1] not in steps:
        print(__doc__)
        return 2
    print(f'g7-live {sys.argv[1]}: ok ({steps[sys.argv[1]]()})')
    return 0


if __name__ == '__main__':
    sys.exit(main())
