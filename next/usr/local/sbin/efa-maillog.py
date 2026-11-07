#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Stores rspamd scan results in MariaDB. rspamd posts one JSON document per message to 127.0.0.1:8906.

shortcut: any local process can post log entries, add a shared secret if untrusted local users ever exist.
"""
import base64
import queue
import threading
import email.message
import email.parser
import email.policy
import time
import zlib
import email.header
import json
import logging
import os
import secrets
import shutil
import smtplib
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pymysql

PASSWORD_FILE = '/etc/efa-web/maillog.pw'
MAX_BODY = 1024 * 1024
QUARANTINE_DIR = '/var/spool/efa-quarantine'
MAX_MAIL = 512 * 1024 * 1024
# Below this share of free disk mail takes its normal way: full disks stop the mail server.
MIN_FREE = 0.1
sys.path.insert(0, '/usr/lib/eFa/python')
try:
    import efa_evidence
except ImportError:
    efa_evidence = None
# The DNS evidence is collected beside the mail path: a full queue drops it, the mail never waits.
EVIDENCE = queue.Queue(maxsize=500)
_evidence_dropped = {'count': 0, 'logged': 0}


def evidence_add(item):
    try:
        EVIDENCE.put_nowait(item)
    except queue.Full:
        _evidence_dropped['count'] += 1
        if time.time() - _evidence_dropped['logged'] > 60:
            logging.warning('evidence queue full, %d mails without DNS evidence', _evidence_dropped['count'])
            _evidence_dropped['logged'] = time.time()


def evidence_store(cur, maillog_id, ts, domain, evidence, records):
    """Each record set once; the mail only refers to it."""
    for key, record in records.items():
        cur.execute('INSERT INTO dns_records (sha256, name, type, data, first_seen, last_seen) VALUES (%s, %s, %s, %s, NOW(), NOW()) '
                    'ON DUPLICATE KEY UPDATE last_seen = NOW()', (key, record['name'][:255], record['type'],
                                                                 zlib.compress(json.dumps(record['answers']).encode(), 6)))
    cur.execute('INSERT INTO mail_evidence (maillog_id, ts, domain, data) VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
                (maillog_id, ts, domain, zlib.compress(json.dumps(evidence).encode(), 6)))


def evidence_worker():
    while True:
        maillog_id, ts, domain, doc, headers = EVIDENCE.get()
        try:
            evidence, records = efa_evidence.collect(doc, efa_evidence.parse_headers(headers))
            db = connect()
            try:
                with db.cursor() as cur:
                    evidence_store(cur, maillog_id, ts, domain, evidence, records)
            finally:
                db.close()
        except Exception as err:  # one mail without evidence must not stop the worker
            logging.error('evidence failed: %s', err)


# Written by efactl: headers stored at all, and the domains that keep none.
HEADERS_POLICY = '/etc/efa-web/headers-policy.json'
HEADERS_FREE_MIN = 0.1
_policy = {'at': 0, 'value': {'store': True, 'off': []}}


def headers_policy():
    """Read at most once a minute: the mail path must not wait for files."""
    if time.time() - _policy['at'] > 60:
        try:
            with open(HEADERS_POLICY) as f:
                _policy['value'] = json.load(f)
        except (OSError, ValueError):
            _policy['value'] = {'store': True, 'off': []}
        _policy['at'] = time.time()
    return _policy['value']


def header_fields(headers):
    """From, Reply-To, Return-Path and X-Mailer of a header block, for the index."""
    parsed = email.parser.HeaderParser(policy=email.policy.compat32).parsestr(headers or '')
    return tuple(subject_text(parsed.get(name, ''), 255) for name in ('From', 'Reply-To', 'Return-Path', 'X-Mailer'))


def headers_row(doc, rcpts, policy, free):
    """(domain, raw size, cut, compressed) to store, or None."""
    headers = doc.get('headers') or ''
    domain = (rcpts[0].rsplit('@', 1)[-1].lower() if rcpts else '')[:253]
    if not headers or not policy.get('store', True) or domain in set(policy.get('off', [])) or free < HEADERS_FREE_MIN:
        return None
    raw = headers.encode('utf-8', 'surrogateescape')
    size = int(doc.get('headers_size') or len(raw))
    return domain, size, int(size > len(raw)), zlib.compress(raw, 6)


# Domains of tenants at their quarantine limit, written by efactl every hour.
QUARANTINE_FULL = '/etc/efa-web/quarantine-full.json'


def full_domains(path=QUARANTINE_FULL):
    try:
        with open(path) as f:
            return set(json.load(f).get('domains', []))
    except (OSError, ValueError):
        return set()


def connect():
    with open(PASSWORD_FILE) as f:
        password = f.read().strip()
    return pymysql.connect(unix_socket='/var/lib/mysql/mysql.sock', user='efa_log', password=password,
                           database='efa', charset='utf8mb4', autocommit=True)


def text(value, limit):
    if isinstance(value, list):
        value = ', '.join(str(v) for v in value)
    return str(value if value is not None else '')[:limit]


def subject_text(value, limit=500):
    """A subject as readable text: encoded words (RFC 2047) decoded, control characters gone. Escaping is for whoever shows it."""
    value = str(value or '')
    if '=?' in value:
        try:
            value = str(email.header.make_header(email.header.decode_header(value)))
        except (ValueError, LookupError, UnicodeError):
            pass
    return ''.join(ch if ch >= ' ' and ch != '\x7f' else ' ' for ch in value).strip()[:limit]


# rspamd symbols of the four checks, a mail has at most one of each group.
AUTH_SYMBOLS = {'R_SPF_ALLOW': ('spf', 'pass'), 'R_SPF_FAIL': ('spf', 'fail'), 'R_SPF_SOFTFAIL': ('spf', 'softfail'),
                'R_SPF_NEUTRAL': ('spf', 'neutral'), 'R_SPF_NA': ('spf', 'none'), 'R_SPF_DNSFAIL': ('spf', 'temperror'),
                'R_SPF_PERMFAIL': ('spf', 'permerror'), 'R_DKIM_ALLOW': ('dkim', 'pass'), 'R_DKIM_REJECT': ('dkim', 'fail'),
                'R_DKIM_NA': ('dkim', 'none'), 'R_DKIM_TEMPFAIL': ('dkim', 'temperror'),
                'R_DKIM_PERMFAIL': ('dkim', 'permerror'), 'DMARC_POLICY_ALLOW': ('dmarc', 'pass'),
                'DMARC_POLICY_REJECT': ('dmarc', 'fail'), 'DMARC_POLICY_QUARANTINE': ('dmarc', 'fail'),
                'DMARC_POLICY_SOFTFAIL': ('dmarc', 'fail'), 'DMARC_NA': ('dmarc', 'none'),
                'DMARC_DNSFAIL': ('dmarc', 'temperror'), 'DMARC_BAD_POLICY': ('dmarc', 'permerror'), 'ARC_ALLOW': ('arc', 'pass'),
                'ARC_REJECT': ('arc', 'fail'), 'ARC_INVALID': ('arc', 'permerror'), 'ARC_DNSFAIL': ('arc', 'temperror'), 'ARC_NA': ('arc', 'none')}


# What a blocked mail was stopped for: a virus name, or an attachment rspamd marked as dangerous.
FILE_SYMBOLS = ('MIME_BAD_EXTENSION', 'MIME_DOUBLE_BAD_EXTENSION')


def threat(doc):
    for symbol in doc.get('symbols') or []:
        if isinstance(symbol, dict) and symbol.get('name') == 'CLAM_VIRUS':
            return ('virus:' + text(','.join(str(item) for item in (symbol.get('options') or [])), 200)).rstrip(':')
    for symbol in doc.get('symbols') or []:
        if isinstance(symbol, dict) and symbol.get('name') in FILE_SYMBOLS:
            return 'file:' + text(','.join(str(item) for item in (symbol.get('options') or [])), 200)
    return ''


def symbol_list(doc, keep=30):
    """The symbols that changed the score, strongest first, as JSON for the verdict of the mail."""
    found = [(str(item.get('name'))[:64], round(float(item.get('score') or 0), 2)) for item in doc.get('symbols') or []
             if isinstance(item, dict) and item.get('name') and float(item.get('score') or 0)]
    return json.dumps(sorted(found, key=lambda pair: -abs(pair[1]))[:keep], separators=(',', ':'))


NOTIFY_FILE = '/etc/efa-web/notify-rules.json'
# At most one notice per rule and sender in 10 minutes, and 30 per rule in an hour: a flood of mail is no flood of notices.
NOTIFY_QUIET, NOTIFY_HOURLY = 600, 30
notify_sent = {}


def notify_rules(path=NOTIFY_FILE):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {'rules': []}


def notify_due(doc, rules, now):
    """The notices one mail causes: (rule, recipients), after the rate limit."""
    sender = str(doc.get('from') or '').lower()
    if '@' not in sender:
        return []
    due = []
    for rule in rules.get('rules', []):
        if sender not in rule['senders'] and '@' + sender.rpartition('@')[2] not in rule['senders']:
            continue
        times = [stamp for stamp in notify_sent.get(rule['name'], []) if now - stamp < 3600]
        if len(times) >= NOTIFY_HOURLY or now - notify_sent.get((rule['name'], sender), 0) < NOTIFY_QUIET:
            continue
        notify_sent[rule['name']] = times + [now]
        notify_sent[(rule['name'], sender)] = now
        due.append((rule, rule['notify']))
    # A rule matching a whole domain sees many senders; forget the per-sender stamps older than the quiet window so the
    # dict does not grow without bound in a long-running service.
    if len(notify_sent) > 10000:
        for key in [key for key, value in notify_sent.items() if isinstance(key, tuple) and now - value >= NOTIFY_QUIET]:
            del notify_sent[key]
    return due


def notify_send(doc, rule, recipients, show_subject):
    message = email.message.EmailMessage()
    message['To'] = ', '.join(recipients)
    message['Subject'] = f"eFa: mail from {text(doc.get('from'), 255)}"
    lines = [f"Rule {rule['name']}: a mail came from {text(doc.get('from'), 255)}.", f"To: {', '.join(text(item, 255) for item in (doc.get('rcpt') or []))}",
             f"Result: {text(doc.get('action'), 32)}, score {float(doc.get('score') or 0):.1f}"]
    if show_subject:
        lines.append(f"Subject: {subject_text(doc.get('subject'))}")
    message.set_content('\n'.join(lines) + '\n')
    # Over SMTP: this service may not use the setgid postdrop. The empty sender: a notice never gets a notice or a bounce of its own.
    with smtplib.SMTP('127.0.0.1', 25, timeout=15) as server:
        server.send_message(message, from_addr='')


def auth_results(doc):
    found = {'spf': '', 'dkim': '', 'dmarc': '', 'arc': ''}
    for symbol in doc.get('symbols') or []:
        name = symbol.get('name') if isinstance(symbol, dict) else symbol
        if name in AUTH_SYMBOLS:
            check, result = AUTH_SYMBOLS[name]
            found[check] = result
    return found['spf'], found['dkim'], found['dmarc'], found['arc']


def row(doc):
    return (float(doc.get('unix_time') or 0), text(doc.get('qid'), 64), text(doc.get('message_id'), 255),
            text(doc.get('from'), 255), text(doc.get('rcpt'), 1000), text(doc.get('ip'), 64),
            text(doc.get('action'), 32), float(doc.get('score') or 0), subject_text(doc.get('subject'))) + auth_results(doc) + (
            threat(doc), int(doc.get('size') or 0), symbol_list(doc))


class _Limited:
    """Reads exactly the announced length: the connection stays open afterwards."""

    def __init__(self, stream, left):
        self.stream, self.left = stream, left

    def read(self, size=-1):
        size = self.left if size < 0 else min(size, self.left)
        data = self.stream.read(size) if size else b''
        self.left -= len(data)
        return data


def quarantine_rows(meta, mail_id, size):
    """The rows of one held mail: the mail, and one line per recipient."""
    mail = (mail_id, text(meta.get('qid'), 64), text(meta.get('message_id'), 255), text(meta.get('sender'), 255), subject_text(meta.get('subject')),
            text(meta.get('ip'), 64), float(meta.get('score') or 0), 1 if meta.get('malware') else 0, size)
    return mail, [(mail_id, text(rcpt, 320).lower()) for rcpt in meta.get('rcpts') or []]


def store_quarantine(meta, reader, length, folder=QUARANTINE_DIR):
    """The file first, then the rows. rspamd drops the mail only after an answer of 200, so any failure here keeps it on its normal way."""
    usage = shutil.disk_usage(folder)
    if usage.free / usage.total < MIN_FREE or not meta.get('rcpts'):
        raise OSError('no room, or no recipient')
    full = full_domains()
    if full and any(str(rcpt).rsplit('@', 1)[-1].lower() in full for rcpt in meta['rcpts']):
        raise OSError('the quarantine of the tenant is full')
    mail_id = secrets.token_hex(16)
    path = f'{folder}/{mail_id}.eml'
    fd = os.open(path + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as out:
            shutil.copyfileobj(reader, out, length)
        os.replace(path + '.tmp', path)
        mail, rcpts = quarantine_rows(meta, mail_id, length)
        db = connect()
        try:
            with db.cursor() as cur:
                cur.execute('INSERT INTO quarantine_mail (id, qid, message_id, sender, subject, ip, score, malware, size) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)', mail)
                cur.executemany('INSERT INTO quarantine_rcpt (mail_id, rcpt) VALUES (%s, %s)', rcpts)
        finally:
            db.close()
    except BaseException:
        for leftover in (path, path + '.tmp'):
            if os.path.exists(leftover):
                os.remove(leftover)
        raise
    return mail_id


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        if self.path == '/quarantine':
            if not 0 < length <= MAX_MAIL:
                self.send_error(413)
                return
            try:
                meta = json.loads(base64.b64decode(self.headers.get('X-Efa-Meta', '')))
                data = _Limited(self.rfile, length)
                store_quarantine(meta, data, length)
            except (ValueError, pymysql.MySQLError, OSError) as err:
                logging.error('quarantine store failed: %s', err)
                self.send_error(500)
                return
            self.send_response(200)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if not 0 < length <= MAX_BODY:
            self.send_error(413)
            return
        try:
            doc = json.loads(self.rfile.read(length))
            values = row(doc) + header_fields(doc.get('headers'))
            rcpts = doc.get('rcpt') if isinstance(doc.get('rcpt'), list) else [str(doc.get('rcpt') or '')]
            usage = shutil.disk_usage('/var/lib/mysql')
            stored = headers_row(doc, rcpts, headers_policy(), usage.free / usage.total)
            db = connect()
            try:
                with db.cursor() as cur:
                    cur.execute('INSERT INTO maillog (ts, qid, message_id, sender, rcpt, ip, action, score, subject, spf, dkim, dmarc, arc, threat, size, symbols, header_from, '
                                'reply_to, return_path, x_mailer) VALUES (FROM_UNIXTIME(%s), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)', values)
                    if stored:
                        maillog_id = cur.lastrowid
                        cur.execute('INSERT INTO mail_headers (maillog_id, ts, domain, raw_size, truncated, data) VALUES (%s, FROM_UNIXTIME(%s), %s, %s, %s, %s)',
                                    (maillog_id, values[0], *stored))
                        if efa_evidence:
                            evidence_add((maillog_id, values[0], stored[0], doc, doc.get('headers') or ''))
            finally:
                db.close()
        except (ValueError, pymysql.MySQLError, OSError) as err:
            # Logging must never affect mail flow, rspamd only records the failure.
            logging.error('maillog insert failed: %s', err)
            self.send_error(500)
            return
        rules = notify_rules()
        if rules.get('rules'):
            for rule, recipients in notify_due(doc, rules, time.time()):
                try:
                    notify_send(doc, rule, recipients, rules.get('subject'))
                except (OSError, smtplib.SMTPException) as err:
                    logging.error('notice of rule %s failed: %s', rule['name'], err)
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


def self_test():
    doc = {'symbols': [{'name': 'R_SPF_ALLOW'}, {'name': 'R_DKIM_REJECT'}, {'name': 'DMARC_POLICY_QUARANTINE'}, {'name': 'X'}, {'name': 'ARC_ALLOW'}]}
    assert auth_results(doc) == ('pass', 'fail', 'fail', 'pass') and auth_results({}) == ('', '', '', '')
    assert len(row(doc)) == 16 and row({**doc, 'size': 5})[-2] == 5 and row(doc)[-3] == ''
    rules = {'rules': [{'name': 'vip', 'senders': ['boss@a.example', '@b.example'], 'notify': ['me@c.example']}]}
    assert [rule['name'] for rule, _who in notify_due({'from': 'Boss@a.example'}, rules, 1000)] == ['vip']
    assert notify_due({'from': 'boss@a.example'}, rules, 1100) == [] and len(notify_due({'from': 'x@b.example'}, rules, 1100)) == 1
    assert notify_due({'from': 'boss@a.example'}, rules, 1700) and notify_due({'from': ''}, rules, 5000) == [] and notify_due({'from': 'o@z.example'}, rules, 5000) == []
    notify_sent.clear()
    assert len([1 for minute in range(40) if notify_due({'from': f'u{minute}@b.example'}, rules, 9000 + minute)]) == NOTIFY_HOURLY
    # Per-sender stamps older than the quiet window are forgotten once the dict grows large, so it stays bounded.
    notify_sent.clear()
    notify_sent.update({('vip', f'u{i}@b.example'): 0 for i in range(10001)})
    notify_due({'from': 'new@b.example'}, rules, 1_000_000)
    assert len(notify_sent) < 10001, len(notify_sent)
    notify_sent.clear()
    assert symbol_list({'symbols': [{'name': 'A', 'score': 0.5}, {'name': 'B', 'score': -3}, {'name': 'C', 'score': 0}, 'D']}) == '[["B",-3.0],["A",0.5]]'
    assert threat({'symbols': [{'name': 'CLAM_VIRUS', 'options': ['Eicar-Signature']}, {'name': 'MIME_BAD_EXTENSION', 'options': ['exe']}]}) == 'virus:Eicar-Signature'
    assert threat({'symbols': [{'name': 'MIME_BAD_EXTENSION', 'options': ['a.exe']}]}) == 'file:a.exe' and threat({}) == ''
    block = 'From: "A" <a@x.example>\r\nReply-To: b@y.example\r\nReturn-Path: <bounce@x.example>\r\nX-Mailer: Test 1\r\nSubject: =?UTF-8?Q?Gr=C3=BC=C3=9Fe?=\r\n'
    assert header_fields(block) == ('"A" <a@x.example>', 'b@y.example', '<bounce@x.example>', 'Test 1') and header_fields(None) == ('', '', '', '')
    domain, size, cut, data = headers_row({'headers': block}, ['u@Rcpt.example'], {'store': True, 'off': []}, 0.5)
    assert domain == 'rcpt.example' and size == len(block) and cut == 0 and zlib.decompress(data).decode() == block, 'CRLF stays'
    assert headers_row({'headers': block, 'headers_size': 70000}, ['u@a.example'], {'store': True, 'off': []}, 0.5)[2] == 1
    assert headers_row({'headers': block}, ['u@a.example'], {'store': True, 'off': ['a.example']}, 0.5) is None
    assert headers_row({'headers': block}, ['u@a.example'], {'store': False}, 0.5) is None and headers_row({'headers': block}, ['u@a.example'], {}, 0.05) is None
    class Cursor:
        def __init__(self):
            self.calls = []

        def execute(self, sql, params):
            self.calls.append((sql.split()[2], params))
    cur = Cursor()
    evidence_store(cur, 5, 0, 'a.example', {'checks': []}, {'k1': {'name': 'a.example', 'type': 'TXT', 'answers': [['TXT', 60, 'v=spf1 -all']]}})
    assert [call[0] for call in cur.calls] == ['dns_records', 'mail_evidence'] and cur.calls[1][1][0] == 5
    for _ in range(EVIDENCE.maxsize + 3):
        evidence_add(('x',))
    assert EVIDENCE.qsize() == EVIDENCE.maxsize and _evidence_dropped['count'] == 3, 'a full queue drops, it never blocks'
    assert subject_text('=?UTF-8?B?w5xiZXJ3ZWlzdW5n?= und =?ISO-8859-1?Q?f=FCr_Sie?=') == 'Überweisung und für Sie'
    assert subject_text('a\x00b\r\nc\x1b[31m') == 'a b  c [31m' and subject_text(None) == '' and subject_text('=?bad?Q?x?=') == '=?bad?Q?x?='
    assert subject_text('<script>alert(1)</script>') == '<script>alert(1)</script>', 'escaped where it is shown, not changed here'
    mail, rcpts = quarantine_rows({'qid': 'Q', 'sender': 's@x', 'subject': 'y' * 900, 'score': 16.5, 'malware': 1, 'rcpts': ['A@X.example', 'b@x.example']}, 'id', 10)
    assert mail[0] == 'id' and len(mail[4]) == 500 and mail[6] == 16.5 and mail[7] == 1 and rcpts == [('id', 'a@x.example'), ('id', 'b@x.example')]
    import io
    import tempfile
    limited = _Limited(io.BytesIO(b'abcdef'), 4)
    assert limited.read(3) == b'abc' and limited.read(3) == b'd' and limited.read() == b''
    global connect

    class Failing:
        def __call__(self):
            raise OSError('database down')
    connect = Failing()
    with tempfile.TemporaryDirectory() as folder:
        try:
            store_quarantine({'rcpts': ['a@x.example']}, io.BytesIO(b'mail'), 4, folder)
            raise AssertionError('took a mail it could not record')
        except OSError:
            assert os.listdir(folder) == [], 'no file without its rows'
        try:
            store_quarantine({'rcpts': []}, io.BytesIO(b'mail'), 4, folder)
            raise AssertionError('took a mail without recipient')
        except OSError:
            pass
        with open(folder + '/full.json', 'w') as f:
            json.dump({'domains': ['x.example']}, f)
        assert full_domains(folder + '/full.json') == {'x.example'} and full_domains(folder + '/none.json') == set()
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
        sys.exit(0)
    if efa_evidence:
        threading.Thread(target=evidence_worker, daemon=True, name='evidence').start()
    ThreadingHTTPServer(('127.0.0.1', 8906), Handler).serve_forever()
