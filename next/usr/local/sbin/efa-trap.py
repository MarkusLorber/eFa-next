#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M6: spam trap addresses. A mail to an address that never gets real mail is taken and dropped: Bayes learns it as spam, the
own fuzzy store (N4) keeps its hashes when it is on, and the address of the sending server goes into the database, from which
efactl builds the block map of trap senders. The mail itself is not kept. Exit 0 when done, 75 so Postfix tries again."""
import ipaddress
import json
import os
import subprocess
import sys
import syslog

MAX_MAIL = 25 * 1024 * 1024
MAILLOG_PW = '/etc/efa-web/maillog.pw'
FUZZY_FILE = '/etc/eFa/fuzzy.json'
FUZZY_FLAG = 11
FUZZY_SHARED_FLAG = 13
FUZZY_TEACH_MAX = 1024 * 1024
EX_TEMPFAIL = 75


def client_ip(text):
    """The address Postfix names as client, or '' for a local one or something else."""
    try:
        address = ipaddress.ip_address(text.strip('[]'))
    except ValueError:
        return ''
    return '' if address.is_loopback or address.is_private or address.is_link_local else str(address)


def fuzzy_on():
    try:
        with open(FUZZY_FILE) as f:
            return bool(json.load(f).get('enabled'))
    except (OSError, ValueError):
        return False


def fuzzy_shared():
    """G7-14: the shared fuzzy store of the cluster is on (its rule is there only on a node of a cluster)."""
    try:
        with open(FUZZY_FILE) as f:
            return bool(json.load(f).get('shared')) and os.path.isdir('/etc/eFa/cluster')
    except (OSError, ValueError):
        return False


def store(ip, recipient):
    import pymysql
    with open(MAILLOG_PW) as f:
        password = f.read().strip()
    db = pymysql.connect(unix_socket='/var/lib/mysql/mysql.sock', user='efa_log', password=password, database='efa', autocommit=True)
    try:
        with db.cursor() as cur:
            cur.execute('INSERT INTO trap_hits (ip, domain) VALUES (%s, %s)', (ip, recipient.rpartition('@')[2][:255]))
    finally:
        db.close()


def teach_shared(raw, call=None):
    """F1: the mail queued for efa-cluster (Redis list efa:share:fuzzy, the last 100), which hands it to the master."""
    import base64
    if call is None:
        if '/usr/lib/eFa/python' not in sys.path:
            sys.path.insert(0, '/usr/lib/eFa/python')
        import efa_redis
        call = efa_redis.call
    call([('RPUSH', 'efa:share:fuzzy', base64.b64encode(raw).decode()), ('LTRIM', 'efa:share:fuzzy', -100, -1)])


def main():
    _sender, client, recipient = sys.argv[1], sys.argv[2], sys.argv[3]
    raw = sys.stdin.buffer.read(MAX_MAIL + 1)[:MAX_MAIL]
    learned = subprocess.run(['rspamc', 'learn_spam'], input=raw, capture_output=True, timeout=60)
    if fuzzy_on():
        subprocess.run(['rspamc', '-f', str(FUZZY_FLAG), '-w', '10', 'fuzzy_add'], input=raw, capture_output=True, timeout=60)
    if fuzzy_shared() and len(raw) <= FUZZY_TEACH_MAX:
        # G7-14 (P7-5): a spam trap teaches the shared fuzzy store of the cluster too. F1: queued for efa-cluster, which hands it
        # to the master over mutual TLS; never written over UDP from a node.
        try:
            teach_shared(raw)
        except (OSError, ImportError) as err:
            syslog.syslog(syslog.LOG_WARNING, f'efa-trap: not queued for the shared fuzzy store: {err}')
    ip = client_ip(client)
    try:
        if ip:
            store(ip, recipient)
    except Exception as err:  # pymysql errors and a missing password file: Postfix tries again later
        syslog.syslog(syslog.LOG_WARNING, f'efa-trap: not stored: {str(err)[:120]}')
        return EX_TEMPFAIL
    syslog.syslog(syslog.LOG_INFO, f"efa-trap: trap hit for {recipient.rpartition('@')[2]} from {ip or 'local'}, bayes rc {learned.returncode}")
    return 0


def self_test():
    # Documentation ranges count as private in Python, so public examples here.
    assert client_ip('9.9.9.9') == '9.9.9.9' and client_ip('[2620:fe::fe]') == '2620:fe::fe'
    assert client_ip('127.0.0.1') == '' and client_ip('10.1.2.3') == '' and client_ip('unknown') == ''
    # F1: the shared fuzzy store is taught through the queue of efa-cluster, never by rspamc over UDP.
    calls = []
    teach_shared(b'spam', calls.extend)
    assert calls == [('RPUSH', 'efa:share:fuzzy', 'c3BhbQ=='), ('LTRIM', 'efa:share:fuzzy', -100, -1)]
    assert "str(FUZZY_SHARED_FLAG)" not in open(__file__, encoding='utf-8').read().split('def main', 1)[1].split('def self_test', 1)[0]
    print('self-test ok')


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        self_test()
    else:
        sys.exit(main())
