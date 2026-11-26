# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""5w: the BIMI check of incoming mail (draft-brand-indicators-for-message-identification). Only for a sender domain that passed
DMARC with p=quarantine or p=reject; the logo is SVG Tiny PS over HTTPS, at most 32 KB, read by a strict parser without
entities.

G7-16: the certificate of the mark (a=, a VMC or a CMC) is checked too: its chain up to a root of the mark verifying authorities
(/usr/share/eFa/bimi/vmc-roots.pem, plus /etc/eFa/bimi-roots.pem of the admin), its time, the key use of BIMI, the domain in
its names and the logo it holds; then the logo shown is the one in the certificate and the result names policy.authority=pass.
P7-3: every fetch is https only, to public addresses only (checked after DNS, the connection goes to that very address), without
redirects, at most 64 KB in 2 seconds, and in the background: a mail never waits for it, the next mail of the domain uses the
answer, kept for 24 hours. The logo is never put into a page of the web interface."""
import base64
import gzip
import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse
import xml.parsers.expat

MAX_SVG = 32 * 1024
MAX_FETCH = 64 * 1024
FETCH_SECONDS = 2
CACHE_SECONDS = 86400
ROOTS = ('/usr/share/eFa/bimi/vmc-roots.pem', '/etc/eFa/bimi-roots.pem')
EKU_BIMI = '1.3.6.1.5.5.7.3.31'
LOGOTYPE = '1.3.6.1.5.5.7.1.12'
LOGO_RE = re.compile(rb'data:image/svg\+xml;base64,([A-Za-z0-9+/=]+)')
FORBIDDEN = {'script', 'foreignobject', 'animate', 'animatemotion', 'animatetransform', 'set', 'image', 'use', 'a', 'iframe', 'embed', 'object'}
_cache = {}


def dmarc_policy(results, domain):
    """'quarantine' or 'reject' when an Authentication-Results line says dmarc=pass with that policy for the domain, else ''."""
    for line in results:
        for part in line.split(';'):
            if not re.search(r'\bdmarc=pass\b', part, re.I):
                continue
            policy, found = re.search(r'\(policy=(\w+)\)', part), re.search(r'header\.from=([^\s;]+)', part)
            if policy and found and found.group(1).lower().rstrip('.') == domain and policy.group(1).lower() in ('quarantine', 'reject'):
                return policy.group(1).lower()
    return ''


def record(text):
    """(location, authority) of a BIMI record, or None if it is none."""
    fields = dict(item.strip().split('=', 1) for item in text.split(';') if '=' in item)
    if fields.get('v', '').strip() != 'BIMI1':
        return None
    location = fields.get('l', '').strip()
    if location and not location.startswith('https://'):
        return None
    return location, fields.get('a', '').strip()


def svg_problem(data):
    """'' when data is SVG Tiny PS without active or outside content, else why not."""
    if len(data) > MAX_SVG:
        return 'larger than 32 KB'
    if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        return 'a DTD or entities are not allowed'
    state = {'root': None, 'problem': ''}
    parser = xml.parsers.expat.ParserCreate()

    def start(name, attrs):
        local = name.split(':')[-1].lower()
        if state['root'] is None:
            state['root'] = (local, attrs)
        if local in FORBIDDEN:
            state['problem'] = state['problem'] or f'element {local} not allowed'
        for key, value in attrs.items():
            key = key.lower()
            if key.startswith('on') or (key.endswith('href') and not str(value).startswith('#')) or 'javascript:' in str(value).lower():
                state['problem'] = state['problem'] or f'attribute {key} not allowed'
    parser.StartElementHandler = start
    parser.SetParamEntityParsing(xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(data, True)
    except xml.parsers.expat.ExpatError as err:
        return f'not valid XML: {err}'
    root = state['root']
    if not root or root[0] != 'svg':
        return 'not an SVG'
    if root[1].get('baseProfile', '').lower() != 'tiny-ps' or root[1].get('version', '') != '1.2':
        return 'not SVG Tiny PS (version 1.2, baseProfile tiny-ps)'
    return state['problem']


def txt(name):
    """The TXT records of a name through the own resolver, joined; [] when there are none."""
    done = subprocess.run(['dig', '+short', '+time=3', '+tries=1', name, 'TXT', '@127.0.0.1'], capture_output=True, text=True, timeout=10)
    return [''.join(re.findall(r'"([^"]*)"', line)) for line in done.stdout.splitlines() if line.strip()]


def safe_get(url, limit=MAX_FETCH, timeout=FETCH_SECONDS, resolve=socket.getaddrinfo):
    """P7-3: the body of an https URL on a public address: resolved here, checked, then that very address is asked (no second
    DNS answer can point elsewhere), with the name for TLS and its certificate. No redirect is followed. OSError otherwise."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password:
        raise OSError('only https URLs without a login')
    port = parts.port or 443
    infos = resolve(parts.hostname, port, proto=socket.IPPROTO_TCP)
    addresses = [ipaddress.ip_address(info[4][0].split('%')[0]) for info in infos]
    if not addresses or any(not address.is_global for address in addresses):
        raise OSError(f'{parts.hostname} is not a public address')
    context = ssl.create_default_context()

    class Pinned(http.client.HTTPSConnection):
        def connect(self):
            raw = socket.create_connection((str(addresses[0]), port), timeout=timeout)
            self.sock = context.wrap_socket(raw, server_hostname=parts.hostname)
    connection = Pinned(parts.hostname, port, timeout=timeout, context=context)
    try:
        connection.request('GET', (parts.path or '/') + (f'?{parts.query}' if parts.query else ''), headers={'User-Agent': 'eFa-next BIMI check'})
        data = reply_body(connection.getresponse(), limit)
    finally:
        connection.close()
    return data


def reply_body(reply, limit):
    """F9: only a 200 counts; a redirect (3xx) is an error and its Location is never asked. At most limit bytes."""
    if reply.status != 200:
        raise OSError(f'HTTP {reply.status}' + (' (redirects are not followed)' if 300 <= reply.status < 400 else ''))
    data = reply.read(limit + 1)
    if len(data) > limit:
        raise OSError(f'larger than {limit // 1024} KB')
    return data


def fetch_svg(url):
    return safe_get(url, MAX_SVG)


def _roots(paths=ROOTS):
    from cryptography import x509
    found = []
    for path in paths:
        try:
            with open(path, 'rb') as f:
                found += _pem_list(f.read())
        except OSError:
            continue
    return found


def _pem_list(data):
    from cryptography import x509
    blocks = re.findall(rb'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----', data, re.S)
    return [x509.load_pem_x509_certificate(block) for block in blocks]


def _signed_by(cert, issuer):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    key = issuer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        else:
            return False
    except (InvalidSignature, ValueError, TypeError):
        return False
    return cert.issuer == issuer.subject


def _valid_at(cert, now):
    start = getattr(cert, 'not_valid_before_utc', None) or cert.not_valid_before.replace(tzinfo=__import__('datetime').timezone.utc)
    end = getattr(cert, 'not_valid_after_utc', None) or cert.not_valid_after.replace(tzinfo=__import__('datetime').timezone.utc)
    return start.timestamp() <= now <= end.timestamp()


def vmc_check(pem, domain, now=None, roots=None):
    """('pass', logo SVG bytes) when the certificate of the mark holds: a chain to a root of the mark verifying authorities, in
    time, the key use of BIMI, the domain among its names, a logo in it; else ('fail', why)."""
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID
    now = time.time() if now is None else now
    try:
        chain = _pem_list(pem)
    except ValueError as err:
        return 'fail', f'no certificate: {err}'
    if not chain:
        return 'fail', 'no certificate'
    leaf, rest = chain[0], chain[1:]
    roots = _roots() if roots is None else roots
    current, steps = leaf, 0
    while steps < 5:
        if not _valid_at(current, now):
            return 'fail', 'a certificate of the chain is out of its time'
        anchor = next((root for root in roots if _signed_by(current, root)), None)
        if anchor is not None:
            if not _valid_at(anchor, now):
                return 'fail', 'the root is out of its time'
            break
        parent = next((item for item in rest if _signed_by(current, item)), None)
        if parent is None:
            return 'fail', 'no chain to a root of the mark verifying authorities'
        current, steps = parent, steps + 1
    else:
        return 'fail', 'the chain is too long'
    try:
        uses = [item.dotted_string for item in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value]
    except x509.ExtensionNotFound:
        uses = []
    if EKU_BIMI not in uses:
        return 'fail', 'not a certificate for BIMI (key use)'
    try:
        names = [name.lower().rstrip('.') for name in leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        names = []
    if not any(name == domain or domain.endswith('.' + name) or name.endswith('._bimi.' + domain) for name in names):
        return 'fail', f'{domain} is not among the names of the certificate'
    try:
        logotype = leaf.extensions.get_extension_for_oid(x509.ObjectIdentifier(LOGOTYPE)).value.value
    except x509.ExtensionNotFound:
        return 'fail', 'no logo in the certificate'
    found = LOGO_RE.search(logotype)
    if not found:
        return 'fail', 'no SVG logo in the certificate'
    data = base64.b64decode(found.group(1))
    if data[:2] == b'\x1f\x8b':
        try:
            data = gzip.GzipFile(fileobj=__import__('io').BytesIO(data)).read(MAX_SVG + 1)
        except (OSError, EOFError) as err:
            return 'fail', f'the logo cannot be unpacked: {err}'
    problem = svg_problem(data)
    if problem:
        return 'fail', f'the logo of the certificate: {problem}'
    return 'pass', data


_jobs, _lock = set(), threading.Lock()


def _background(key, job):
    """job() runs once per key in a thread of its own; its answer goes into the cache (P7-3: a mail never waits)."""
    with _lock:
        if key in _jobs:
            return
        _jobs.add(key)

    def run():
        try:
            answer = job()
        except Exception as err:  # noqa: BLE001  any fault: a temporary error, asked again after a while
            answer = ('temperror', str(err)[:80], [])
        with _lock:
            if len(_cache) > 5000:
                _cache.clear()
            _cache[key] = (time.time() + (CACHE_SECONDS if answer[0] != 'temperror' else 600), answer)
            _jobs.discard(key)
    threading.Thread(target=run, daemon=True).start()


def resolve_answer(domain, key, lookup=txt, fetch=fetch_svg, get=safe_get, now=None, roots=None):
    """The answer for one selector of a domain, with the network: the record, the logo, and the certificate when it names one."""
    found = [record(text) for text in lookup(key)]
    found = [item for item in found if item]
    if not found:
        return ('none', 'no BIMI record', [])
    location, authority = found[0]
    if not location:
        return ('declined', 'the domain declines BIMI', [])
    data = fetch(location)
    problem = svg_problem(data)
    if problem:
        return ('fail', problem, [])
    headers = [('BIMI-Location', f'v=BIMI1; l={location}' + (f'; a={authority}' if authority else ''))]
    if authority:
        if not authority.startswith('https://'):
            return ('fail', 'the certificate is not on https', [])
        result, logo = vmc_check(get(authority), domain, now, roots)
        if result != 'pass':
            return ('pass', f'authority={result}: {logo}', headers + [('BIMI-Indicator', base64.b64encode(data).decode())])
        # The logo of the certificate is the one shown: it is what the authority checked.
        return ('pass', 'authority=pass', headers + [('BIMI-Indicator', base64.b64encode(logo).decode())])
    return ('pass', '', headers + [('BIMI-Indicator', base64.b64encode(data).decode())])


def check(domain, selector, results, now=None, lookup=txt, fetch=fetch_svg, get=safe_get, wait=False):
    """(result, reason, headers to add): pass with BIMI-Location and BIMI-Indicator, or fail/none/skipped/temperror. The record,
    the logo and the certificate are fetched in the background (P7-3), kept 24 hours per selector and domain; wait=True is for
    the tests and the check of one domain from efactl."""
    now = time.time() if now is None else now
    if not dmarc_policy(results, domain):
        return 'skipped', 'DMARC did not pass with quarantine or reject', []
    selector = selector if re.fullmatch(r'[A-Za-z0-9_-]{1,63}', selector or '') else 'default'
    key = f'{selector}._bimi.{domain}'
    cached = _cache.get(key)
    if cached and cached[0] > now:
        return cached[1]

    def job():
        return resolve_answer(domain, key, lookup, fetch, get, now)
    if wait:
        try:
            answer = job()
        except (OSError, ValueError, subprocess.SubprocessError) as err:
            answer = ('temperror', str(err)[:80], [])
        _cache[key] = (now + CACHE_SECONDS, answer)
        return answer
    _background(key, job)
    # temperror is the result of the draft for 'not known yet'; the next mail of the domain gets the answer.
    return 'temperror', 'asked in the background', []


def self_test():
    results = ['mx.own.example; dkim=pass header.d=brand.example; spf=pass smtp.mailfrom=brand.example; dmarc=pass (policy=reject) header.from=brand.example']
    assert dmarc_policy(results, 'brand.example') == 'reject' and dmarc_policy(results, 'other.example') == ''
    assert dmarc_policy(['x; dmarc=pass (policy=none) header.from=brand.example'], 'brand.example') == ''
    assert record('v=BIMI1; l=https://brand.example/logo.svg; a=') == ('https://brand.example/logo.svg', '') and record('v=spf1') is None
    assert record('v=BIMI1; l=http://brand.example/logo.svg') is None
    good = b'<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps"><title>Brand</title><path d="M0 0h10v10z"/></svg>'
    assert svg_problem(good) == ''
    assert svg_problem(good.replace(b'<path', b'<script>alert(1)</script><path')) == 'element script not allowed'
    assert svg_problem(good.replace(b'<path ', b'<path onclick="x()" ')).startswith('attribute onclick')
    assert 'entities' in svg_problem(b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg>&x;</svg>')
    assert 'Tiny PS' in svg_problem(b'<svg xmlns="http://www.w3.org/2000/svg"></svg>') and svg_problem(b'x' * (MAX_SVG + 1)) == 'larger than 32 KB'
    _cache.clear()
    result, _reason, headers = check('brand.example', '', results, now=0, lookup=lambda name: ['v=BIMI1; l=https://brand.example/l.svg'], fetch=lambda url: good,
                                     wait=True)
    assert result == 'pass' and headers[0] == ('BIMI-Location', 'v=BIMI1; l=https://brand.example/l.svg') and base64.b64decode(headers[1][1]) == good
    assert check('brand.example', '', results, now=10, lookup=lambda name: [], fetch=lambda url: b'')[0] == 'pass', 'from the cache'
    assert check('brand.example', '', ['dmarc=fail'], now=10)[0] == 'skipped'
    _cache.clear()
    assert check('brand.example', '', results, now=0, lookup=lambda name: ['v=BIMI1; l=https://b/l.svg'], fetch=lambda url: b'<svg/>', wait=True)[0] == 'fail'
    # P7-3: the mail never waits: the first one is pending, the answer of the background job is there for the next one.
    _cache.clear()
    assert check('brand.example', '', results, lookup=lambda name: ['v=BIMI1; l=https://brand.example/l.svg'], fetch=lambda url: good)[0] == 'temperror'
    for _ in range(50):
        if 'default._bimi.brand.example' in _cache:
            break
        time.sleep(0.05)
    assert check('brand.example', '', results)[0] == 'pass'
    # P7-3: no private, loopback or link-local target, also behind a name; https only.
    for url, answer in (('http://brand.example/x', None), ('https://u:p@brand.example/x', None), ('https://brand.example/x', '127.0.0.1'),
                        ('https://brand.example/x', '10.1.2.3'), ('https://brand.example/x', '169.254.169.254'), ('https://brand.example/x', 'fd00::1'),
                        ('https://brand.example/x', '::ffff:127.0.0.1'), ('https://brand.example/x', '100.64.0.1')):
        try:
            safe_get(url, resolve=lambda host, port, proto=0, answer=answer: [(0, 0, 0, '', (answer or '192.0.2.1', port))])
            raise AssertionError(url)
        except OSError:
            pass
    # F9 (security review 2026-11-24): one non-global address among the answers is enough to refuse (no DNS rebinding to a
    # second answer); a redirect is never followed, for the logo and for the certificate of the mark alike.
    try:
        safe_get('https://brand.example/x', resolve=lambda host, port, proto=0: [(0, 0, 0, '', ('8.8.8.8', port)), (0, 0, 0, '', ('10.0.0.5', port))])
        raise AssertionError('mixed answers')
    except OSError as err:
        assert 'not a public address' in str(err)

    class Reply:
        def __init__(self, status, body=b''):
            self.status, self.body = status, body

        def read(self, size):
            return self.body[:size]
    for status in (301, 302, 303, 307, 308, 404):
        try:
            reply_body(Reply(status, b'<svg/>'), 100)
            raise AssertionError(status)
        except OSError as err:
            assert ('not followed' in str(err)) == (status != 404)
    assert reply_body(Reply(200, b'<svg/>'), 100) == b'<svg/>'
    try:
        reply_body(Reply(200, b'x' * 101), 100)
        raise AssertionError('limit')
    except OSError:
        pass
    assert resolve_answer.__defaults__[2] is safe_get and fetch_svg.__code__.co_names == ('safe_get', 'MAX_SVG')
    # G7-16: a certificate of the mark: made here (root, intermediate, leaf with the key use of BIMI, the name and the logo).
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    def make(name, key, issuer_name, issuer_key, ca, extensions=()):
        builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                   .issuer_name(issuer_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(datetime.datetime(2026, 1, 1)).not_valid_after(datetime.datetime(2028, 1, 1))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        for extension in extensions:
            builder = builder.add_extension(extension, critical=False)
        return builder.sign(issuer_key, hashes.SHA256())
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(4)]
    root = make('Test Mark Root', keys[0], x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test Mark Root')]), keys[0], True)
    middle = make('Test Mark CA', keys[1], root.subject, keys[0], True)
    logo = gzip.compress(good)
    logotype = x509.UnrecognizedExtension(x509.ObjectIdentifier(LOGOTYPE), b'\x30\x00data:image/svg+xml;base64,' + base64.b64encode(logo))
    leaf = make('Brand Inc.', keys[2], middle.subject, keys[1], False,
                [x509.ExtendedKeyUsage([x509.ObjectIdentifier(EKU_BIMI)]), x509.SubjectAlternativeName([x509.DNSName('brand.example')]), logotype])
    pem = b''.join(cert.public_bytes(serialization.Encoding.PEM) for cert in (leaf, middle))
    when = datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc).timestamp()
    assert vmc_check(pem, 'brand.example', when, [root]) == ('pass', good)
    assert vmc_check(pem, 'mail.brand.example', when, [root])[0] == 'pass', 'a subdomain of the name'
    assert 'names' in vmc_check(pem, 'other.example', when, [root])[1]
    assert 'root' in vmc_check(pem, 'brand.example', when, [make('Other Root', keys[3], x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Other Root')]), keys[3], True)])[1]
    assert 'time' in vmc_check(pem, 'brand.example', datetime.datetime(2029, 1, 1, tzinfo=datetime.timezone.utc).timestamp(), [root])[1]
    plain = make('Brand Inc.', keys[2], middle.subject, keys[1], False, [x509.SubjectAlternativeName([x509.DNSName('brand.example')]), logotype])
    assert 'key use' in vmc_check(plain.public_bytes(serialization.Encoding.PEM) + middle.public_bytes(serialization.Encoding.PEM), 'brand.example', when, [root])[1]
    assert vmc_check(b'junk', 'brand.example', when, [root])[0] == 'fail'
    _cache.clear()
    answer = check('brand.example', '', results, now=when, lookup=lambda name: ['v=BIMI1; l=https://brand.example/l.svg; a=https://brand.example/c.pem'],
                   fetch=lambda url: good, get=lambda url: pem, wait=True)
    assert answer[0] == 'pass' and answer[1] == 'authority=fail: no chain to a root of the mark verifying authorities' or answer[1] == 'authority=pass', answer[1]
    assert resolve_answer('brand.example', 'default._bimi.brand.example', lambda name: ['v=BIMI1; l=https://brand.example/l.svg; a=https://brand.example/c.pem'],
                          lambda url: good, lambda url: pem, when, [root])[1] == 'authority=pass'
    print('self-test ok')


if __name__ == '__main__':
    self_test()
