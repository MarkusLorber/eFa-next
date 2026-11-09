#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Phishing reports: a user forwards a mail to the report address of the domain, best as an attachment. This Postfix pipe puts
the reported mail, compressed, on the list of spam reports, where an admin decides whether the filter learns from it.
The database holds the mail: the pipe may not write files (SELinux). Exit 0 when done, 75 so Postfix tries again on any failure."""
import email
import email.errors
import email.policy
import re
import sys
import syslog
import zlib

MAX_MAIL = 25 * 1024 * 1024
MAILLOG_PW = '/etc/efa-web/maillog.pw'
EX_TEMPFAIL = 75


# What the email library raises on broken headers and text (found by scripts/fuzz.py). A report is never lost for it: then the
# report itself is kept, it holds the mail anyway.
BROKEN = (UnicodeError, LookupError, ValueError, AttributeError, TypeError, IndexError, email.errors.MessageError)


def reported(raw):
    """The mails a report holds: each attached message, or the report itself when it holds none (a plain forward)."""
    found = []
    try:
        message = email.message_from_bytes(raw, policy=email.policy.default)
        for part in message.walk():
            if part.get_content_type() == 'message/rfc822':
                inner = part.get_payload()
                inner = inner[0] if isinstance(inner, list) and inner else inner
                if inner is not None and not isinstance(inner, list):
                    # Without folding again: a crafted MIME parameter makes Python 3.9 loop forever there.
                    for policy in (email.policy.SMTP.clone(max_line_length=None), email.policy.compat32):
                        try:
                            found.append(inner.as_bytes(policy=policy))
                            break
                        except BROKEN:
                            continue
    except BROKEN:
        pass
    return found or [raw]


def summary(raw):
    try:
        message = email.message_from_bytes(raw, policy=email.policy.default)
        return str(message.get('From', ''))[:255], str(message.get('Subject', ''))[:500]
    except BROKEN:
        return '', ''


def store(rows):
    import pymysql
    with open(MAILLOG_PW) as f:
        password = f.read().strip()
    db = pymysql.connect(unix_socket='/var/lib/mysql/mysql.sock', user='efa_log', password=password, database='efa', autocommit=True)
    try:
        with db.cursor() as cur:
            cur.executemany("INSERT INTO train_requests (username, source, ref, sender, subject, verdict, raw) VALUES (%s, 'phish', '', %s, %s, 'spam', %s)", rows)
    finally:
        db.close()


def main():
    syslog.openlog('efa-phish', 0, syslog.LOG_MAIL)
    reporter = re.sub(r'[^\w.@+-]', '', sys.argv[1] if len(sys.argv) > 1 else '')[:100] or 'unknown'
    raw = sys.stdin.buffer.read(MAX_MAIL + 1)
    if len(raw) > MAX_MAIL:
        syslog.syslog(syslog.LOG_WARNING, f'a report of {reporter} larger than 25 MB was not kept')
        return 0
    try:
        rows = []
        for mail in reported(raw)[:20]:
            sender, subject = summary(mail)
            rows.append((reporter, sender, subject, zlib.compress(mail, 6)))
        store(rows)
    except Exception as err:  # any failure: Postfix keeps the report and tries again, it never bounces to the user
        syslog.syslog(syslog.LOG_ERR, f'not stored: {err}')
        return EX_TEMPFAIL
    syslog.syslog(syslog.LOG_INFO, f'{len(rows)} reported mails of {reporter} wait for a decision')
    return 0


def self_test():
    original = email.message.EmailMessage()
    original['From'], original['Subject'] = 'Bank <security@bank-l0gin.example>', 'Verify your account'
    original.set_content('Click here.')
    forward = email.message.EmailMessage()
    forward['From'], forward['Subject'] = 'anna@own.example', 'Fwd: Verify your account'
    forward.set_content('This looks like phishing.')
    forward.add_attachment(original)
    found = reported(forward.as_bytes())
    assert len(found) == 1 and summary(found[0]) == ('Bank <security@bank-l0gin.example>', 'Verify your account'), summary(found[0])
    simple = email.message.EmailMessage()
    simple['From'], simple['Subject'] = 'anna@own.example', 'Fwd: odd mail'
    simple.set_content('---------- Forwarded message ----------')
    raw = simple.as_bytes()
    assert reported(raw) == [raw] and zlib.decompress(zlib.compress(raw, 6)) == raw
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
    else:
        sys.exit(main())
