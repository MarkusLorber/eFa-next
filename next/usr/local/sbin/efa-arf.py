#!/usr/bin/python3 -I
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""G7-18 (P7-10): complaints of the providers about bulk mail, as ARF reports (RFC 5965) to the own feedback address. A Postfix
pipe hands each report here; only a real feedback report counts: per day, per sender domain, and its recipient goes onto the
list efa-outbound leaves out of further bulk mail. Nothing of the mail is kept. Anything else at that address is dropped.

Security review 2026-11-24 (F7): a report counts only when this host's own Authentication-Results says DKIM or DMARC passed for
a domain of a known feedback loop (KNOWN_FBL); anyone else could fill the list and the statistics. A report that cannot be
read ends with 0 (dropped), never with an error Postfix would answer with a bounce. The sender table keeps at most
SENDERS_MAX domains; the rest counts under "-other"."""
import email
import email.policy
import email.utils
import hashlib
import os
import re
import sys
import syslog
import time

for _folder in ('/usr/lib/eFa/python', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'lib', 'eFa', 'python')):
    if os.path.isdir(_folder) and _folder not in sys.path:
        sys.path.insert(0, _folder)
import efa_redis  # noqa: E402
import efa_host  # noqa: E402

SUPPRESS = 'efa:arf:suppress'
SENDERS = 'efa:arf:senders'
SENDERS_MAX = 500
# The feedback loops of the large providers, by the domain that signs their reports (and its subdomains).
KNOWN_FBL = ('hotmail.com', 'outlook.com', 'microsoft.com', 'yahoo.com', 'yahoo.net', 'aol.com', 'comcast.net', 'mail.ru',
             'yandex.ru', 'yandex.net', 'fastmail.com', 'messagingengine.com', 'gmx.net', 'web.de', 'zoho.com', 'rackspace.com')


def _known(domain):
    domain = (domain or '').lower().rstrip('.')
    return any(domain == item or domain.endswith('.' + item) for item in KNOWN_FBL)


def trusted(message, host):
    """The signing domain of a known feedback loop that passed DKIM or DMARC, from the Authentication-Results this host wrote
    (its authserv-id); '' otherwise."""
    for value in message.get_all('Authentication-Results') or []:
        text = ' '.join(str(value).split())
        if not host or text.split(';', 1)[0].strip().lower() != host:
            continue
        for method, domain in re.findall(r'\b(dkim|dmarc)=pass\b[^;]*?\b(?:header\.d|header\.from)=([A-Za-z0-9.-]+)', text, re.I):
            if _known(domain):
                return domain.lower()
    return ''


def report(raw, host=None):
    """(feedback type, sender domain, recipient) of an ARF report from a known feedback loop, or None when it is none or not
    authenticated (F7)."""
    message = email.message_from_bytes(raw, policy=email.policy.default)
    if message.get_content_type() != 'multipart/report' or message.get_param('report-type', '').lower() != 'feedback-report':
        return None
    if not trusted(message, (host if host is not None else efa_host.own_hostname()).lower()):
        return None
    feedback, original = None, None
    for part in message.iter_parts():
        if part.get_content_type() == 'message/feedback-report':
            payload = part.get_payload()
            text = payload[0].as_string() if isinstance(payload, list) else str(payload)
            fields = email.message_from_string(text.strip() + '\n\n')
            feedback = fields
        elif part.get_content_type() in ('message/rfc822', 'text/rfc822-headers'):
            payload = part.get_payload()
            original = payload[0] if isinstance(payload, list) else email.message_from_string(str(payload))
    if feedback is None:
        return None
    kind = (feedback.get('Feedback-Type') or 'other').strip().lower()[:20]
    rcpt = (feedback.get('Original-Rcpt-To') or (original.get('To') if original else '') or '').strip().strip('<>').lower()
    sender = (feedback.get('Original-Mail-From') or (original.get('From') if original else '') or '').strip()
    domain = email.utils.parseaddr(sender)[1].rpartition('@')[2].lower()[:253]
    return kind, domain, email.utils.parseaddr(rcpt)[1][:254]


def count(found, call=efa_redis.call, now=None):
    kind, domain, rcpt = found
    day = time.strftime('%Y-%m-%d', time.gmtime(time.time() if now is None else now))
    field = domain or '-'
    size, known = call([('HLEN', SENDERS), ('HEXISTS', SENDERS, field)])
    if not int(known) and int(size) >= SENDERS_MAX:
        field = '-other'
    commands = [('HINCRBY', 'efa:arf:days', day, 1), ('HINCRBY', SENDERS, field, 1)]
    if rcpt and kind in ('abuse', 'fraud', 'other', 'virus'):
        # Only a hash: the list leaves the address out of bulk mail, it does not keep it.
        commands.append(('SADD', SUPPRESS, hashlib.sha256(rcpt.encode()).hexdigest()))
    call(commands)


def main():
    raw = sys.stdin.buffer.read(10 * 1024 * 1024)
    try:
        found = report(raw)
    except Exception as err:  # F7: a report it cannot read is dropped (0), never bounced back to a forged sender
        syslog.syslog(syslog.LOG_INFO, f'efa-arf: unreadable report dropped: {type(err).__name__}')
        return 0
    if found is None:
        syslog.syslog(syslog.LOG_INFO, 'efa-arf: not an authenticated feedback report of a known provider, dropped')
        return 0
    try:
        count(found)
    except OSError as err:
        syslog.syslog(syslog.LOG_ERR, f'efa-arf: not counted, try again later: {err}')
        return 75  # EX_TEMPFAIL: Postfix keeps the report and tries again
    syslog.syslog(syslog.LOG_INFO, f'efa-arf: complaint {found[0]} about mail of {found[1] or "?"}')
    return 0


def self_test():
    auth = b'Authentication-Results: mx.own.example; dkim=pass header.d=hotmail.com header.s=s1; dmarc=pass header.from=hotmail.com\r\n'
    raw = auth + (b'From: fbl@provider.example\r\nTo: fbl@own.example\r\nSubject: complaint\r\nMIME-Version: 1.0\r\n'
           b'Content-Type: multipart/report; report-type=feedback-report; boundary="b"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nA complaint\r\n'
           b'--b\r\nContent-Type: message/feedback-report\r\n\r\nFeedback-Type: abuse\r\nUser-Agent: x/1\r\nVersion: 1\r\nOriginal-Rcpt-To: <Reader@Provider.example>\r\n'
           b'\r\n--b\r\nContent-Type: message/rfc822\r\n\r\nFrom: News <news@own.example>\r\nTo: reader@provider.example\r\nSubject: Offers\r\n\r\nx\r\n--b--\r\n')
    host = 'mx.own.example'
    assert report(raw, host) == ('abuse', 'own.example', 'reader@provider.example'), report(raw, host)
    assert report(b'From: a@b.example\r\nSubject: hi\r\n\r\nno report\r\n', host) is None
    # F7: without this host's pass for a known feedback loop the report does not count.
    bare = raw[len(auth):]
    assert report(bare, host) is None, 'no Authentication-Results'
    assert report(auth.replace(b'mx.own.example', b'mx.evil.example') + bare, host) is None, 'results of another server'
    assert report(auth.replace(b'hotmail.com', b'evil.example') + bare, host) is None, 'not a known feedback loop'
    assert report(auth.replace(b'dkim=pass', b'dkim=fail').replace(b'dmarc=pass', b'dmarc=fail') + bare, host) is None, 'no pass'
    assert report(b'Authentication-Results: mx.own.example; dkim=pass header.d=fbl.mail.yahoo.com\r\n' + bare, host)[0] == 'abuse'
    store = efa_redis.Memory()
    count(report(raw, host), store, now=0)
    assert store.data['efa:arf:days'] == {'1970-01-01': 1} and store.data[SENDERS] == {'own.example': 1}
    assert store.data[SUPPRESS] == {hashlib.sha256(b'reader@provider.example').hexdigest()}
    # F7: the sender table stays at SENDERS_MAX domains.
    store.data[SENDERS] = {f'd{i}.example': 1 for i in range(SENDERS_MAX)}
    count(('abuse', 'new.example', ''), store, now=0)
    count(('abuse', 'd1.example', ''), store, now=0)
    assert 'new.example' not in store.data[SENDERS] and store.data[SENDERS]['-other'] == 1 and store.data[SENDERS]['d1.example'] == 2
    # F7: an unreadable report ends with 0 (dropped), never with an error that bounces.
    kept_read = sys.stdin
    sys.stdin = type('In', (), {'buffer': type('B', (), {'read': lambda self, n: b'\xff' * 10})()})()
    kept_report = globals()['report']
    globals()['report'] = lambda raw: (_ for _ in ()).throw(ValueError('broken'))
    try:
        assert main() == 0
    finally:
        globals()['report'], sys.stdin = kept_report, kept_read
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
        sys.exit(0)
    syslog.openlog('efa-arf', 0, syslog.LOG_MAIL)
    sys.exit(main())
