# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""M1-1: the ARC set efa-cdr adds after it changed a mail, checked by a verifier that is not ours: dkimpy (python3-dkimpy, the
ARC implementation of OpenARC's test suite and of many receivers). Instance 1 is sealed by dkimpy too, as rspamd does on the
host, so neither side of the chain is only checked by its own code. The mail goes through as bytes with CRLF, as Postfix
hands it on, and the key comes from a DNS answer the test gives dkimpy.

Without python3-dkimpy the test is skipped; the CI runs it with EFA_CI_ARC_DKIMPY=yes and then fails when it is missing
(dnf install python3-dkimpy python3-authres, EPEL)."""

import base64
import importlib.machinery
import importlib.util
import os
import shutil
import sys
import tempfile
import types
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
try:
    import syslog  # noqa: F401  the real one where there is one: later tests load services that log
except ImportError:
    sys.modules['syslog'] = types.ModuleType('syslog')
_loader = importlib.machinery.SourceFileLoader('efa_cdr_arc', os.path.join(ROOT, 'next', 'usr', 'local', 'sbin', 'efa-cdr.py'))
cdr = importlib.util.module_from_spec(importlib.util.spec_from_loader('efa_cdr_arc', _loader))
_loader.exec_module(cdr)

try:
    import dkim
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    dkim = None
REQUIRED = os.environ.get('EFA_CI_ARC_DKIMPY') == 'yes'

HOST, DOMAIN, SELECTOR = 'mx.own.example', 'own.example', 'efa-arc'
ORIGINAL = (b'Return-Path: <anna@far.example>\r\n'
            b'Authentication-Results: mx.own.example; spf=pass smtp.mailfrom=far.example; dkim=none\r\n'
            b'From: Anna <anna@far.example>\r\n'
            b'To: bob@own.example\r\n'
            b'Subject: Angebot\r\n'
            b'Date: Mon, 9 Nov 2026 10:00:00 +0000\r\n'
            b'Message-ID: <1@far.example>\r\n'
            b'MIME-Version: 1.0\r\n'
            b'Content-Type: text/plain; charset=utf-8\r\n'
            b'\r\n'
            b'Hallo, siehe https://shop.example/a?id=7&utm_source=nl&fbclid=x\r\n')


def headers_of(message):
    """(name, value) as the milter sees them: values without the line end, folded lines joined by a bare newline."""
    head = message.split(b'\r\n\r\n', 1)[0].decode()
    out = []
    for line in head.split('\r\n'):
        if line[:1] in (' ', '\t'):
            out[-1] = (out[-1][0], out[-1][1] + '\n' + line)
        else:
            name, _, value = line.partition(':')
            out.append((name, value[1:] if value.startswith(' ') else value))
    return out


def with_headers_on_top(added, message):
    """The mail as Postfix sends it on after the milter added headers at position 0 (CRLF, folded with tab)."""
    lines = b''.join(f'{name}: {value}'.replace('\n', '\r\n').encode() + b'\r\n' for name, value in added)
    return lines + message


@unittest.skipIf(dkim is None and not REQUIRED, 'python3-dkimpy is missing')
class IndependentArcTests(unittest.TestCase):
    def setUp(self):
        if dkim is None:
            self.fail('EFA_CI_ARC_DKIMPY=yes but python3-dkimpy is missing: dnf install python3-dkimpy python3-authres (EPEL)')
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
        public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.record = b'v=DKIM1; k=rsa; p=' + base64.b64encode(public)
        self.keys = tempfile.mkdtemp()
        with open(os.path.join(self.keys, f'arc-seal_{DOMAIN}.key'), 'wb') as f:
            f.write(self.private)
        with open(os.path.join(self.keys, f'arc-seal_{DOMAIN}.selector'), 'w') as f:
            f.write(SELECTOR + '\n')

    def tearDown(self):
        shutil.rmtree(self.keys, ignore_errors=True)

    def dns(self, name, timeout=5):
        name = name.decode() if isinstance(name, bytes) else name
        return self.record if name.rstrip('.') == f'{SELECTOR}._domainkey.{DOMAIN}' else None

    def verify(self, message):
        cv, results, reason = dkim.arc_verify(message, dnsfunc=self.dns)
        return cv, reason

    def rspamd_seal(self, message):
        """Instance 1 by dkimpy, in place of rspamd: over the mail as it came in."""
        added = dkim.arc_sign(message, SELECTOR.encode(), DOMAIN.encode(), self.private, HOST.encode())
        return b''.join(added) + message

    def cdr_changes(self, sealed, new_body):
        """What efa-cdr does: a new body (links without tracking), then arc_reseal_headers on the headers it saw."""
        head = sealed.split(b'\r\n\r\n', 1)[0]
        changed = head + b'\r\n\r\n' + new_body
        added = cdr.arc_reseal_headers(headers_of(sealed), changed, self.keys, HOST)
        return changed, added

    def test_foreign_first_seal_holds(self):
        sealed = self.rspamd_seal(ORIGINAL)
        self.assertEqual(self.verify(sealed)[0], dkim.CV_Pass)

    def test_chain_holds_after_the_change(self):
        sealed = self.rspamd_seal(ORIGINAL)
        changed, added = self.cdr_changes(sealed, b'Hallo, siehe https://shop.example/a?id=7\r\n')
        self.assertEqual(self.verify(changed)[0], dkim.CV_Fail, 'without the new set the change breaks instance 1')
        self.assertEqual([name for name, _value in added], ['ARC-Seal', 'ARC-Message-Signature', 'ARC-Authentication-Results'])
        # addheader(name, value, 0) for each, in this order: the last one added stands on top.
        resealed = with_headers_on_top(list(reversed(added)), changed)
        cv, reason = self.verify(resealed)
        self.assertEqual(cv, dkim.CV_Pass, reason)
        self.assertIn('spf=pass smtp.mailfrom=far.example', dict(added)['ARC-Authentication-Results'])
        self.assertIn('i=2', dict(added)['ARC-Seal'])
        self.assertIn('cv=pass', dict(added)['ARC-Seal'].replace(' ', ''))

    def test_long_body_with_folded_signature(self):
        sealed = self.rspamd_seal(ORIGINAL.replace(b'Hallo', b'Hallo ' + b'x' * 3000))
        changed, added = self.cdr_changes(sealed, b'gek\xc3\xbcrzt\r\n\r\n\r\n')
        self.assertTrue(any('\n\t' in value for _name, value in added), 'the signatures are folded as the milter sends them')
        self.assertEqual(self.verify(with_headers_on_top(list(reversed(added)), changed))[0], dkim.CV_Pass)

    def test_a_change_after_the_seal_is_found(self):
        sealed = self.rspamd_seal(ORIGINAL)
        changed, added = self.cdr_changes(sealed, b'Hallo\r\n')
        resealed = with_headers_on_top(list(reversed(added)), changed)
        self.assertEqual(self.verify(resealed.replace(b'Hallo\r\n', b'Hallo, anders\r\n'))[0], dkim.CV_Fail)
        self.assertEqual(self.verify(resealed.replace(b'Subject: Angebot', b'Subject: Rechnung'))[0], dkim.CV_Fail)

    def test_three_sets(self):
        """A mail that already came with an ARC set (a list server): rspamd adds 2, efa-cdr 3."""
        # rspamd checked the chain that came in and wrote arc=pass in its results before sealing.
        sealed = self.rspamd_seal(b'Authentication-Results: mx.own.example; arc=pass\r\n' + self.rspamd_seal(ORIGINAL))
        self.assertEqual(self.verify(sealed)[0], dkim.CV_Pass)
        changed, added = self.cdr_changes(sealed, b'Hallo\r\n')
        self.assertIn('i=3', dict(added)['ARC-Seal'])
        self.assertEqual(self.verify(with_headers_on_top(list(reversed(added)), changed))[0], dkim.CV_Pass)


if __name__ == '__main__':
    unittest.main()
