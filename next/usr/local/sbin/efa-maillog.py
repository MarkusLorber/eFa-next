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
import hashlib
import json
import logging
import os
import re
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
# The copy in the source tree first (CI), then the installed one.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'lib', 'eFa', 'python'))
try:
    import efa_qcrypt
except ImportError:
    efa_qcrypt = None
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


# 6c: the DKIM selectors of each mail, in and out, with the result of rspamd: one row per domain, selector, algorithm and
# direction, and counters per day. Only metadata, no addresses.
DKIM_RESULTS = {'R_DKIM_ALLOW': 'pass', 'R_DKIM_REJECT': 'fail', 'R_DKIM_TEMPFAIL': 'temperror', 'R_DKIM_PERMFAIL': 'permerror'}
LOCAL_DOMAINS_FILE = '/etc/eFa/outbound.json'


def dkim_rows(doc, local):
    """(domain, selector, algorithm, direction, result) of each DKIM-Signature of a mail."""
    results = {}
    for item in doc.get('symbols') or []:
        name = item.get('name') if isinstance(item, dict) else item
        for option in (item.get('options') or []) if isinstance(item, dict) else []:
            if name in DKIM_RESULTS:
                results[str(option).split(':', 1)[0].lower()] = DKIM_RESULTS[name]
    parsed = email.parser.HeaderParser(policy=email.policy.compat32).parsestr(doc.get('headers') or '')
    rows = []
    for value in parsed.get_all('DKIM-Signature') or []:
        tags = {key.strip().lower(): item.strip() for key, _, item in (part.partition('=') for part in re.sub(r'\s+', '', str(value)).split(';')) if key}
        domain, selector, alg = tags.get('d', '').lower()[:253], tags.get('s', '')[:64], tags.get('a', '').lower()[:16]
        if domain and selector:
            rows.append((domain, selector, alg, 'out' if domain in local else 'in', results.get(domain, 'none')))
    return rows[:10]


def dkim_store(cur, rows, ts):
    for domain, selector, alg, direction, result in rows:
        good, bad = int(result == 'pass'), int(result in ('fail', 'permerror'))
        cur.execute('INSERT INTO dkim_selectors (domain, selector, alg, direction, first_seen, last_seen, n_pass, n_fail, last_result) '
                    'VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s), FROM_UNIXTIME(%s), %s, %s, %s) ON DUPLICATE KEY UPDATE last_seen = VALUES(last_seen), '
                    'n_pass = n_pass + VALUES(n_pass), n_fail = n_fail + VALUES(n_fail), last_result = VALUES(last_result)',
                    (domain, selector, alg, direction, ts, ts, good, bad, result))
        cur.execute('INSERT INTO dkim_selector_daily (day, domain, selector, alg, direction, n_pass, n_fail) VALUES (DATE(FROM_UNIXTIME(%s)), %s, %s, %s, %s, %s, %s) '
                    'ON DUPLICATE KEY UPDATE n_pass = n_pass + VALUES(n_pass), n_fail = n_fail + VALUES(n_fail)', (ts, domain, selector, alg, direction, good, bad))


def local_domains(path=LOCAL_DOMAINS_FILE, cache={}):  # noqa: B006 - the default dict is the cache
    try:
        stamp = os.stat(path).st_mtime_ns
    except OSError:
        return set()
    if cache.get('stamp') != stamp:
        try:
            with open(path) as f:
                cache.update(stamp=stamp, value=set(json.load(f).get('local_domains', [])))
        except (OSError, ValueError):
            cache.update(stamp=stamp, value=set())
    return cache['value']


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
# D3: the public keys of the tenants, written by efactl uq-encrypt-set; without the file held mail is stored as it is.
QUARANTINE_KEYS = '/etc/efa-web/quarantine-keys.json'
# E1: one line per mail in the style of Suricata EVE-JSON for the SIEM, written while efactl siem-set --format eve is on.
EVE_SETTINGS = '/etc/efa-web/eve.json'
EVE_FILE = '/var/log/efa-eve/eve.json'
EVE_MAX = 200 * 1024 * 1024


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
    message['Subject'] = f"eFa-next: mail from {text(doc.get('from'), 255)}"
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


def sealed_for(rcpts, keys_path=QUARANTINE_KEYS):
    """{tenant: public key} for the recipients of a mail, None when held mail is stored as it is."""
    try:
        with open(keys_path) as f:
            keys = json.load(f)
    except OSError:
        return None
    tenants = {keys.get('domains', {}).get(str(rcpt).rsplit('@', 1)[-1].lower(), 'global') for rcpt in rcpts}
    found = {tenant: keys['keys'][tenant] for tenant in tenants if tenant in keys.get('keys', {})}
    # A key file that names no key for these recipients: never store them in clear text by mistake.
    if not found:
        raise OSError('no quarantine key for the tenants of this mail')
    return found


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
            publics = sealed_for(meta['rcpts'])
            if publics is None:
                shutil.copyfileobj(reader, out, length)
            elif efa_qcrypt is None:
                raise OSError('efa_qcrypt is missing, held mail is not stored in clear text')
            else:
                out.write(efa_qcrypt.encrypt(reader.read(length), publics))
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


def eve_settings(path=EVE_SETTINGS, cache={}):  # noqa: B006 - the default dict is the cache
    try:
        stamp = os.stat(path).st_mtime_ns
    except OSError:
        return {}
    if cache.get('stamp') != stamp:
        with open(path) as f:
            cache.update(stamp=stamp, value=json.load(f))
    return cache['value']


def eve_address(address, key):
    """The address, or with the pseudonyms of the mail log on (D2) p<16 hex>@domain with the key of the export."""
    address = str(address or '').strip()
    if not key or '@' not in address:
        return address
    import hashlib
    import hmac
    local, _, domain = address.rpartition('@')
    return 'p' + hmac.new(bytes.fromhex(key), local.lower().encode(), hashlib.sha256).hexdigest()[:16] + '@' + domain.lower()


def eve_record(doc, rcpts, settings):
    """E1: one mail as an EVE-JSON style object: timestamp, event_type, src_ip, dest_ip, proto, and the eFa-next part."""
    local = set(settings.get('local_domains', []))
    domains = [str(rcpt).rsplit('@', 1)[-1].lower() for rcpt in rcpts if rcpt]
    direction = 'inbound' if domains and all(domain in local for domain in domains) else 'outbound'
    tenants = settings.get('tenants', {})
    tenant = next((tenants[domain] for domain in domains + [str(doc.get('from') or '').rsplit('@', 1)[-1].lower()] if domain in tenants), '')
    stamp = float(doc.get('unix_time') or time.time())
    key = settings.get('key', '')
    return {'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(stamp)) + '.%06d+0000' % int((stamp % 1) * 1000000),
            'event_type': 'smtp', 'src_ip': text(doc.get('ip'), 64), 'dest_ip': settings.get('dest_ip', ''), 'proto': 'TCP', 'dest_port': 25,
            'app_proto': 'smtp', 'host': settings.get('host', ''),
            'smtp': {'mail_from': eve_address(doc.get('from'), key), 'rcpt_to': [eve_address(rcpt, key) for rcpt in rcpts if rcpt]},
            'efa': {'queue_id': text(doc.get('qid'), 64), 'direction': direction, 'verdict': text(doc.get('action'), 32),
                    'score': float(doc.get('score') or 0), 'symbols': [item.get('name') for item in doc.get('symbols') or [] if item.get('name')][:200],
                    'tenant': tenant, 'size': int(doc.get('size') or 0)}}


def eve_write(record, path=EVE_FILE):
    """Appends one line; above the size limit the file moves to .1 first. A full disk never stops the mail log."""
    try:
        if os.path.exists(path) and os.path.getsize(path) > EVE_MAX:
            os.replace(path, path + '.1')
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
        with os.fdopen(fd, 'a') as f:
            f.write(json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n')
    except OSError as err:
        logging.error('eve line not written: %s', err)


def ioc_rows(doc):
    """5v (j): hashes of the links, their hosts and the attachments of a delivered mail, for the check after new feed data.
    Only hashes: the links themselves may hold personal tokens. Nothing for a mail that was not delivered."""
    if str(doc.get('action', '')) in ('reject', 'soft reject', 'greylist'):
        return []
    found = set()
    for url in (doc.get('urls') if isinstance(doc.get('urls'), list) else [])[:50]:
        url = str(url)[:2000]
        host = re.sub(r'^[a-z][a-z0-9+.-]*://', '', url.lower()).split('/', 1)[0].split('@')[-1].split(':')[0]
        found.add(('url', hashlib.sha256(url.encode()).hexdigest()))
        if host:
            found.add(('domain', hashlib.sha256(host.encode()).hexdigest()))
    for value in (doc.get('files') if isinstance(doc.get('files'), list) else [])[:20]:
        if re.fullmatch(r'[0-9a-f]{64}', str(value)):
            found.add(('sha256', str(value)))
    return sorted(found)


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
                    maillog_row = cur.lastrowid
                    try:
                        dkim_store(cur, dkim_rows(doc, local_domains()), values[0])
                    except pymysql.MySQLError as err:  # an older database without the tables: the mail log goes on
                        logging.error('dkim selectors not stored: %s', err)
                    iocs = ioc_rows(doc)
                    if iocs:
                        try:
                            cur.executemany('INSERT INTO delivered_iocs (maillog_id, ts, kind, h) VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
                                            [(maillog_row, values[0], kind, value) for kind, value in iocs])
                        except pymysql.MySQLError as err:
                            logging.error('link hashes not stored: %s', err)
                    if stored:
                        # The id of the mail log row from before the other inserts, which change lastrowid.
                        maillog_id = maillog_row
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
        eve = eve_settings()
        if eve.get('enabled'):
            eve_write(eve_record(doc, rcpts, eve))
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
    # 6c: the selectors of a mail with the result of rspamd per domain.
    dkim_doc = {'symbols': [{'name': 'R_DKIM_ALLOW', 'options': ['own.example:+']}, {'name': 'R_DKIM_REJECT', 'options': ['bad.example:-']}],
                'headers': 'DKIM-Signature: v=1; a=rsa-sha256; d=own.example;\r\n s=sel2026; h=from; b=xx\r\n'
                           'DKIM-Signature: v=1; a=ed25519-sha256; d=Bad.Example; s=k1; b=yy\r\nDKIM-Signature: v=1; d=nosel.example; b=zz\r\n'}
    # 5v (j): hashes only, and nothing of a mail that was not delivered.
    iocs = ioc_rows({'action': 'no action', 'urls': ['https://evil.example/pay?id=1', 'https://evil.example/x'], 'files': ['a' * 64, 'nothex']})
    assert ('domain', hashlib.sha256(b'evil.example').hexdigest()) in iocs and ('sha256', 'a' * 64) in iocs and len(iocs) == 4
    assert ioc_rows({'action': 'reject', 'urls': ['https://evil.example/']}) == [] and ioc_rows({}) == []
    assert dkim_rows(dkim_doc, {'own.example'}) == [('own.example', 'sel2026', 'rsa-sha256', 'out', 'pass'), ('bad.example', 'k1', 'ed25519-sha256', 'in', 'fail')]
    import io
    import tempfile
    # E1: the EVE line of a mail, with pseudonyms when the key is set.
    eve = eve_record({'unix_time': 1700000000.25, 'qid': 'Q1', 'from': 'Anna@ext.example', 'ip': '192.0.2.5', 'action': 'reject', 'score': 17,
                      'symbols': [{'name': 'CLAM_VIRUS'}], 'size': 9}, ['b@own.example'],
                     {'local_domains': ['own.example'], 'tenants': {'own.example': '3'}, 'dest_ip': '198.51.100.1', 'host': 'mx1'})
    assert eve['timestamp'] == '2023-11-14T22:13:20.250000+0000' and eve['event_type'] == 'smtp' and eve['src_ip'] == '192.0.2.5' and eve['proto'] == 'TCP'
    assert eve['efa'] == {'queue_id': 'Q1', 'direction': 'inbound', 'verdict': 'reject', 'score': 17.0, 'symbols': ['CLAM_VIRUS'], 'tenant': '3', 'size': 9}
    assert eve['smtp'] == {'mail_from': 'Anna@ext.example', 'rcpt_to': ['b@own.example']}
    hidden = eve_record({'from': 'a@ext.example'}, ['b@far.example'], {'key': '00' * 32})
    assert hidden['efa']['direction'] == 'outbound' and hidden['smtp']['mail_from'].startswith('p') and hidden['smtp']['mail_from'].endswith('@ext.example')
    with tempfile.TemporaryDirectory() as eve_dir:
        eve_write({'a': 1}, eve_dir + '/eve.json')
        assert open(eve_dir + '/eve.json').read() == '{"a":1}\n'
    # D3: sealed for the tenants of the recipients, global for the rest; a key file without a fitting key stores nothing.
    with tempfile.TemporaryDirectory() as keys_dir:
        keys_path = keys_dir + '/keys.json'
        assert sealed_for(['a@t.example'], keys_path) is None
        with open(keys_path, 'w') as f:
            json.dump({'domains': {'t.example': '3'}, 'keys': {'3': 'K3', 'global': 'KG'}}, f)
        assert sealed_for(['a@T.example', 'b@other.example'], keys_path) == {'3': 'K3', 'global': 'KG'}
        with open(keys_path, 'w') as f:
            json.dump({'domains': {}, 'keys': {}}, f)
        try:
            sealed_for(['a@t.example'], keys_path)
            raise AssertionError('stored without a key')
        except OSError:
            pass
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
