#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""5n: the emergency copy of delivered mail. Postfix hands a copy for each recipient of a domain with the copy on to this pipe,
as efa-em+<local>=<domain>@efa-emergency.invalid. It is sealed with the public key of the tenant (only root holds the private
key) and kept in the database for the days of the domain. The pipe may not write files (SELinux), so the database holds it.
Exit 0 when done or when the domain has no copy any more, 75 so Postfix tries again on any other failure."""
import json
import re
import sys
import syslog
import time

for _folder in ('/usr/lib/eFa/python',):
    sys.path.insert(0, _folder)

MAX_MAIL = 15 * 1024 * 1024
MAILLOG_PW = '/etc/efa-web/maillog.pw'
KEYS = '/etc/efa-web/quarantine-keys.json'
SETTINGS = '/etc/efa-web/emergency.json'
EX_TEMPFAIL = 75


def original(recipient):
    """The address a copy is for, from efa-em+<local>=<domain>@efa-emergency.invalid; '' for anything else."""
    match = re.fullmatch(r'efa-em\+(.+)=([a-z0-9.-]+\.[a-z]{2,})@efa-emergency\.invalid', recipient.lower())
    return f'{match.group(1)}@{match.group(2)}' if match else ''


def header(raw, name):
    head = raw.split(b'\n\n', 1)[0].split(b'\r\n\r\n', 1)[0].decode('utf-8', 'replace')
    found = re.search(rf'^{name}:[ \t]*(.*(?:\r?\n[ \t].*)*)', head, re.M | re.I)
    return ' '.join(found.group(1).split())[:500] if found else ''


def main():
    sender, recipient = sys.argv[1], sys.argv[2]
    rcpt = original(recipient)
    if not rcpt:
        return 0
    try:
        with open(SETTINGS) as f:
            days = json.load(f).get('domains', {}).get(rcpt.rpartition('@')[2])
        if not days:
            return 0
        raw = sys.stdin.buffer.read(MAX_MAIL + 1)
        if len(raw) > MAX_MAIL:
            syslog.syslog(syslog.LOG_WARNING, f'efa-emergency: a mail for {rcpt.rpartition("@")[2]} is larger than {MAX_MAIL} bytes, no copy')
            return 0
        import efa_qcrypt
        import pymysql
        with open(KEYS) as f:
            keys = json.load(f)
        tenant = keys.get('domains', {}).get(rcpt.rpartition('@')[2], 'global')
        public = keys.get('keys', {}).get(tenant)
        if not public:
            raise OSError(f'no key for the tenant {tenant}')
        sealed = efa_qcrypt.encrypt(raw, {tenant: public})
        with open(MAILLOG_PW) as f:
            password = f.read().strip()
        db = pymysql.connect(unix_socket='/var/lib/mysql/mysql.sock', user='efa_log', password=password, database='efa', autocommit=True)
        try:
            with db.cursor() as cur:
                cur.execute('INSERT INTO emergency_mail (rcpt, sender, subject, size, until, sealed) VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s), %s)',
                            (rcpt[:320], sender[:255], header(raw, 'Subject'), len(raw), int(time.time() + int(days) * 86400), sealed))
        finally:
            db.close()
    except Exception as err:  # never clear text: the copy waits and Postfix tries again
        syslog.syslog(syslog.LOG_WARNING, f'efa-emergency: copy not kept: {str(err)[:120]}')
        return EX_TEMPFAIL
    return 0


def self_test():
    assert original('efa-em+anna.b=own.example@efa-emergency.invalid') == 'anna.b@own.example'
    assert original('efa-em+a+tag=sub.own.example@efa-emergency.invalid') == 'a+tag@sub.own.example'
    assert original('anna@own.example') == '' and original('efa-em+x=y@other.invalid') == ''
    assert header(b'From: a@x\r\nSubject: Hello\r\n world\r\n\r\nbody', 'Subject') == 'Hello world' and header(b'X: y\n\nb', 'Subject') == ''
    print('self-test ok')


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        self_test()
    else:
        sys.exit(main())
