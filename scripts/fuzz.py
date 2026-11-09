#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Fuzzing of the parsers that read what strangers send: DMARC and TLS reports (with gzip and zip), phishing reports (ARF and
forwards), the CDR (OOXML, OLE, PDF, links), MIME header handling, DLP and disclaimers. Standard library only, a fixed seed and
a fixed time: the same run each time. A parser may only raise what its caller handles; each input has to be done within
MAX_SECONDS. Entity bombs and external entities are tried on purpose.
    fuzz.py [--seconds N] [--seed N]
"""
import email.message
import email.policy
import gzip
import struct
import importlib.util
import io
import os
import random
import signal
import sys
import time
import types
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'python'))
MAX_SECONDS = 2.0
HANG_SECONDS = 10
MAX_INPUT = 256 * 1024
TOKENS = [b'<', b'>', b'{', b'}', b'"', b'\x00', b'\xff', b'=?utf-8?b?', b'=?x-unknown?q?', b'--b', b'\r\n\r\n', b'\n ', b'%PDF-',
          b'PK\x03\x04', b'\x1f\x8b', b'<!DOCTYPE x [<!ENTITY a "aaaa">]>', b'&a;', b'99999999999999999999', b'-1', b'[]', b'null',
          b'Content-Type: multipart/mixed; boundary=b\r\n', b'Content-Transfer-Encoding: base64\r\n', b'charset="x-nonsense"']


class Hang(BaseException):
    """One input took too long; BaseException, so no parser catches it on the way."""


def hang(*_):
    raise Hang()


def load(path, name):
    if 'syslog' not in sys.modules:
        try:
            import syslog  # noqa: F401
        except ImportError:  # Windows: the programs only log through it
            sys.modules['syslog'] = types.SimpleNamespace(syslog=lambda *a: None, openlog=lambda *a: None, LOG_ERR=3, LOG_WARNING=4,
                                                          LOG_INFO=6, LOG_MAIL=16, LOG_CRIT=2)
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def mutate(rng, data):
    data = bytearray(data)
    for _ in range(rng.randint(1, 8)):
        kind = rng.randrange(6)
        at = rng.randrange(len(data) + 1)
        if kind == 0 and data:
            data[min(at, len(data) - 1)] ^= 1 << rng.randrange(8)
        elif kind == 1:
            data[at:at] = rng.choice(TOKENS)
        elif kind == 2:
            del data[at:at + rng.randint(1, 64)]
        elif kind == 3 and data:
            start = rng.randrange(len(data))
            data[at:at] = data[start:start + rng.randint(1, 256)] * rng.randint(1, 20)
        elif kind == 4:
            data = data[:at]
        else:
            data[at:at] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 16)))
    return bytes(data[:MAX_INPUT])


def mail_with(data, name, kind=('application', 'octet-stream')):
    message = email.message.EmailMessage()
    message['From'], message['To'], message['Subject'] = 'a@sender.example', 'b@own.example', 'report'
    message.set_content('x')
    message.add_attachment(data, maintype=kind[0], subtype=kind[1], filename=name)
    return message.as_bytes()


def zipped(files):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as target:
        for name, data in files:
            target.writestr(name, data)
    return out.getvalue()


def targets():
    reports = load('next/usr/local/sbin/efa-reports.py', 'efa_reports')
    phish = load('next/usr/local/sbin/efa-phish.py', 'efa_phish')
    cdr = load('next/usr/local/sbin/efa-cdr.py', 'efa_cdr')
    outbound = load('next/usr/local/sbin/efa-outbound.py', 'efa_outbound')
    sasl = load('next/usr/local/sbin/efa-sasl.py', 'efa_sasl')
    unlock = load('next/usr/local/sbin/efa-unlock.py', 'efa_unlock')
    import efa_mime
    import efa_webauthn
    import efa_feeds
    import efa_bimi
    import efa_domaincheck
    import efa_lookalike
    import efa_crypto

    def sasl_session(data):
        # The lines of Postfix to efa-sasl (5u): any input gives answer lines or a closed connection, never an exception.
        session = sasl.Session(sasl.Logins('/nonexistent'), sasl.Limiter(), delay=0)
        session.line('VERSION\t1\t1')
        for raw in data.split(b'\n')[:50]:
            if session.line(raw.decode('utf-8', 'replace')[:sasl.MAX_LINE]) is None:
                break

    def parsed(raw):
        return email.message_from_bytes(raw, policy=email.policy.default)

    plain = email.message.EmailMessage()
    plain['From'], plain['To'], plain['Subject'] = 'anna@own.example', 'b@x.example', 'Angebot =?utf-8?q?f=C3=BCr?= Sie'
    plain.set_content('Karte 4111 1111 1111 1111, IBAN DE89 3704 0044 0532 0130 00, https://x.example/a?b=1')
    plain.add_alternative('<html><body><a href="https://x.example/">x</a></body></html>', subtype='html')
    plain.add_attachment(b'data', maintype='application', subtype='pdf', filename='a.pdf')
    arf = email.message.EmailMessage()
    arf['From'], arf['Subject'] = 'user@own.example', 'Phishing'
    arf.set_content('see attached')
    arf.add_attachment(plain, filename='mail.eml')
    ooxml = zipped([('[Content_Types].xml', '<Types><Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>'),
                    ('word/vbaProject.bin', b'\xd0\xcf\x11\xe0' + b'x' * 64), ('word/_rels/document.xml.rels', '<Relationships/>')])
    dlp = {'cards': 'hold', 'iban': 'log', 'ids': 'log', 'rules': [{'name': 'x', 'pattern': r'\bgeheim\b', 'action': 'reject'}]}
    # name: (call, seeds, exceptions the caller handles)
    return {
        'reports': (lambda data: reports.reports_of(data), [mail_with(reports.DMARC_SAMPLE, 'r.xml'), mail_with(reports.TLS_SAMPLE, 'r.json'),
                                                             mail_with(gzip.compress(reports.DMARC_SAMPLE), 'r.xml.gz'),
                                                             mail_with(zipped([('r.xml', reports.DMARC_SAMPLE)]), 'r.zip')], ()),
        'dmarc-xml': (reports.parse_dmarc, [reports.DMARC_SAMPLE], reports.READ_ERRORS),
        'tls-json': (reports.parse_tlsrpt, [reports.TLS_SAMPLE], reports.READ_ERRORS),
        'report-archive': (lambda data: reports.unpack('r.zip', data), [zipped([('r.xml', reports.DMARC_SAMPLE)]), gzip.compress(reports.TLS_SAMPLE)],
                           reports.READ_ERRORS),
        'phish-arf': (lambda data: (phish.reported(data), phish.summary(data)), [arf.as_bytes(), plain.as_bytes()], ()),
        'cdr-ooxml': (cdr.clean_ooxml, [ooxml], (cdr.Uncleanable,)),
        'cdr-ole-pdf': (lambda data: (cdr.ole_macros(data), cdr.pdf_active(data)), [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + b'x' * 32,
                                                                                    b'%PDF-1.4\n1 0 obj << /OpenAction 2 0 R >> endobj'], ()),
        # qpdf is not run: a failing one (OSError) is what the milter handles.
        'cdr-mail': (lambda data: cdr.disarm(data, qpdf='false'), [mail_with(ooxml, 'a.docm'), plain.as_bytes()], (OSError, efa_mime.Unwritable)),
        'cdr-html': (lambda data: cdr.disarm_html(data), [plain.as_bytes()], efa_mime.BROKEN),
        'feeds': (lambda data: [efa_feeds.parse(kind, data) for kind in ('list', 'stix', 'misp', 'threatfox')],
                  [b'{"objects": []}'], (ValueError,)),
        # 6a: DNS answers of anyone's zone; an SPF record that is not SPF is a ValueError, shown as red.
        'domain-check': (lambda data: [efa_domaincheck.spf_check('own.example', [line], lambda name: [line]) and
                                       efa_domaincheck.dmarc_check('own.example', [line]) and efa_domaincheck.tlsrpt_check('own.example', [line])
                                       for line in data.decode('utf-8', 'replace').splitlines()[:20]],
                         [b'"v=spf1 include:own.example redirect=own.example -all"\n"v=DMARC1; p=reject; rua=mailto:d@own.example"'], ()),
        # 10: any archive and text of a mail: an answer, never an exception (the scan itself is not run).
        'unlock': (lambda data: unlock.unlock(data, data[:200].decode('latin-1'), lambda inner: ''), [unlock._zipcrypto({'a.txt': b'x'}, b'pw123')], ()),
        'lookalike': (lambda data: efa_lookalike.lookalike(data.decode('utf-8', 'replace')[:300], ['example.com', 'partner.de']), [b'xn--exmple-cua.com'], ()),
        # 15: any mail is cut into its header and entity and put together again, or the milter tempfails it; never an exception.
        'crypto-entity': (lambda data: (efa_crypto.join(*efa_crypto.entity(data)), efa_crypto.is_encrypted(data), efa_crypto.is_signed(data)),
                          [b'From: a@x.example\r\nContent-Type: text/plain\r\n\r\nbody\r\n'], ()),
        'bimi-svg': (efa_bimi.svg_problem, [b'<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps"><path d="M0 0"/></svg>'], ()),
        'cdr-links': (lambda data: cdr.rewrite_links(data, 'https://efa.own.example/l/', b'k' * 32, ['own.example']), [plain.as_bytes()],
                      efa_mime.BROKEN),  # unreadable or unwritable: the milter then leaves the links as they are
        'cdr-tracking': (cdr.strip_tracking, [plain.as_bytes()], efa_mime.BROKEN),  # M1: the same, the mail then goes on unchanged
        'mime': (lambda data: efa_mime.mime_header_changes([('Content-Type', 'text/plain')], parsed(data)), [plain.as_bytes()], efa_mime.BROKEN),
        # A mail the library cannot walk: the milter answers 451 while DLP is on (strict), never lets it out unchecked.
        'dlp': (lambda data: outbound.dlp_verdict(outbound.mail_text(parsed(data)), dlp), [plain.as_bytes()], efa_mime.BROKEN),
        # Parsing fails in the milter: 451 with DLP on, else the mail goes on without the disclaimer.
        'disclaimer': (lambda data: outbound.add_disclaimer(parsed(data), 'Own Ltd.', ''), [plain.as_bytes()], efa_mime.BROKEN),
        # 5s: what a browser sends for a passkey; a bad one is Invalid, which the login turns into a refusal.
        'webauthn-cbor': (lambda data: efa_webauthn.auth_data(data) if data[:1] != b'\xa3' else efa_webauthn.cbor_decode(data),
                          [efa_webauthn._cbor({'fmt': 'none', 'attStmt': {}, 'authData': b'x' * 37}), b'\x00' * 32 + b'\x45' + b'\x00' * 30],
                          (efa_webauthn.Invalid, IndexError, struct.error, ValueError)),
        'sasl': (sasl_session, [b'AUTH\t1\tPLAIN\tservice=smtp\tsecured\trip=192.0.2.1\tresp=AG14MUBleGFtcGxlLm9yZwBzZWNyZXQ=\n',
                                b'AUTH\t2\tLOGIN\tsecured\nCONT\t2\tbXgx\nCONT\t2\tc2VjcmV0\n'], ()),
    }


def bombs(found):
    """Entity expansion and external entities: refused at once, nothing is fetched or expanded."""
    reports = load('next/usr/local/sbin/efa-reports.py', 'efa_reports')
    laughs = b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">' + b''.join(
        b'<!ENTITY lol%d "%s">' % (i, (b'&lol%d;' % (i - 1) if i > 1 else b'&lol;') * 10) for i in range(1, 10)) + b']><feedback>&lol9;</feedback>'
    external = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><feedback>&e;</feedback>'
    for name, data in (('billion laughs', laughs), ('external entity', external)):
        start = time.monotonic()
        try:
            reports.parse_dmarc(data)
            found.append(f'dmarc-xml: {name} was parsed')
        except ValueError:
            pass
        if time.monotonic() - start > 0.5:
            found.append(f'dmarc-xml: {name} took {time.monotonic() - start:.1f} s')
        _dmarc, _tls, bad = reports.reports_of(mail_with(data, 'r.xml'))
        if not bad:
            found.append(f'reports: {name} not reported as unreadable')


def main():
    seconds = int(sys.argv[sys.argv.index('--seconds') + 1]) if '--seconds' in sys.argv else 20
    seed = int(sys.argv[sys.argv.index('--seed') + 1]) if '--seed' in sys.argv else 6004
    rng, found, runs = random.Random(seed), [], {}
    bombs(found)
    table = targets()
    end = time.monotonic() + seconds
    if hasattr(signal, 'SIGALRM'):
        signal.signal(signal.SIGALRM, hang)
    while time.monotonic() < end and not found:
        for name, (call, seeds, allowed) in table.items():
            data = mutate(rng, rng.choice(seeds))
            start = time.monotonic()
            problem = None
            if hasattr(signal, 'SIGALRM'):
                signal.alarm(HANG_SECONDS)
            try:
                call(data)
            except Hang:
                problem = f'hangs for more than {HANG_SECONDS} s'
            except allowed:
                pass
            except Exception as err:  # what the caller does not handle
                problem = f'{type(err).__name__}: {str(err)[:120]}'
            finally:
                if hasattr(signal, 'SIGALRM'):
                    signal.alarm(0)
            if problem is None and time.monotonic() - start > MAX_SECONDS:
                problem = f'{time.monotonic() - start:.1f} s for one input of {len(data)} bytes'
            if problem:
                path = os.path.join(os.environ.get('TMPDIR', '/tmp'), f'fuzz-{name}.bin')
                with open(path, 'wb') as f:
                    f.write(data)
                found.append(f'{name}: {problem} (input in {path})')
                break
            runs[name] = runs.get(name, 0) + 1
    for line in found:
        print('fuzz:', line)
    print(f'fuzz: {"FAILED" if found else "ok"}, {sum(runs.values())} inputs in {len(runs)} parsers, seed {seed}')
    return 1 if found else 0


if __name__ == '__main__':
    sys.exit(main())
