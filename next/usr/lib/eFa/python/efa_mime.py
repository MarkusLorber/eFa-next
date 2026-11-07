# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""What the milters of eFa share: a changed mail handed back to Postfix, its MIME headers along with its body."""
import email
import email.errors
import email.policy

MIME_HEADERS = ('MIME-Version', 'Content-Type', 'Content-Transfer-Encoding')
SEALED = ('multipart/signed', 'multipart/encrypted', 'application/pkcs7-mime', 'application/x-pkcs7-mime')


def mime_header_changes(old_headers, new_message):
    """The top MIME headers that differ after the change: (name, new value), None for a header that has to go."""
    old = {name.lower(): value for name, value in old_headers}
    changes = []
    for name in MIME_HEADERS:
        value = new_message[name]
        value = str(value) if value is not None else None
        if (old.get(name.lower()) or '').strip() != (value or '').strip():
            changes.append((name, value))
    return changes


def hand_back(milter, old_headers, changed):
    """The new body, and the new boundary or transfer encoding of a mail with one part, through the milter calls."""
    body = changed.split(b'\r\n\r\n', 1)[1] if b'\r\n\r\n' in changed else changed.split(b'\n\n', 1)[1]
    new_message = email.message_from_bytes(changed, policy=email.policy.default)
    for name, value in mime_header_changes(old_headers, new_message):
        if value is None:
            milter.chgheader(name, 1, '')
        elif any(old.lower() == name.lower() for old, _value in old_headers):
            milter.chgheader(name, 1, value)
        else:
            milter.addheader(name, value)
    milter.replacebody(body)


# What the email library raises on broken headers and text (found by scripts/fuzz.py).
BROKEN = (UnicodeError, LookupError, ValueError, AttributeError, TypeError, IndexError, email.errors.MessageError)


NO_REFOLD = email.policy.SMTP.clone(max_line_length=None)


class Unwritable(ValueError):
    """A changed mail that no policy can write again."""


def to_bytes(message):
    """The mail as bytes: with the SMTP policy, else with compat32 that writes raw 8 bit headers back as they came. Headers are not
    folded again: folding a crafted MIME parameter loops forever in Python 3.9 (found by scripts/fuzz.py), a milter thread
    would hang. The headers keep the lines the sender gave them."""
    for policy in (NO_REFOLD, email.policy.compat32):
        try:
            return message.as_bytes(policy=policy)
        except BROKEN:
            continue
    raise Unwritable('the changed mail cannot be written')


def sealed(message):
    """Signed or encrypted with S/MIME or PGP: such a mail stays as it is."""
    return message.get_content_type() in SEALED


def self_test():
    one = email.message.EmailMessage()
    one['From'] = 'a@x.example'
    one.set_content('Hello ü')
    old = [('Content-Type', 'text/plain; charset="utf-8"'), ('Content-Transfer-Encoding', '7bit'), ('MIME-Version', '1.0')]
    changes = dict(mime_header_changes(old, one))
    assert 'Content-Transfer-Encoding' in changes and changes['Content-Transfer-Encoding'] != '7bit', changes

    class Recorder:
        def __init__(self):
            self.calls = []

        def chgheader(self, *args):
            self.calls.append(('chg',) + args)

        def addheader(self, *args):
            self.calls.append(('add',) + args)

        def replacebody(self, body):
            self.calls.append(('body', body))
    recorder = Recorder()
    hand_back(recorder, old, one.as_bytes(policy=email.policy.SMTP))
    assert recorder.calls[-1][0] == 'body' and any(call[0] == 'chg' and call[1] == 'Content-Transfer-Encoding' for call in recorder.calls)
    signed = email.message.EmailMessage()
    signed['Content-Type'] = 'multipart/signed; protocol="application/pkcs7-signature"; boundary="b"'
    assert sealed(signed) and not sealed(one)
    raw8 = email.message_from_bytes(b'Subject: \xff\xfe broken\r\nFrom: a@x.example\r\n\r\nbody\r\n', policy=email.policy.default)
    raw8.set_content('changed')
    assert b'changed' in to_bytes(raw8)
    print('self-test ok')


if __name__ == '__main__':
    self_test()
