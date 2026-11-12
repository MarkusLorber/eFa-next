#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""eFa-next outbound: a milter on 127.0.0.1:8908 before rspamd for outgoing mail, from logged in users and from the relay networks.
Data loss prevention first: card numbers, IBANs, tax and social security numbers and own rules, each logged, encrypted, held or
rejected. Encrypted means: the mail and its attachments in a PDF with AES-256, the password agreed with the recipient or sent to
the sender in a mail of its own. A keyword in the subject asks for it too. Then the disclaimer of the domain of the sender,
before the mail is signed. Signed or encrypted mail, and mail that holds the disclaimer already, keeps its text.
Outgoing is mail of logged in users, of the relay networks and any mail to a domain this server does not take mail for, which
Postfix only lets through for allowed submitters. Limits per sender and hour stop a taken over account: too many recipients or
too many target domains, logged, throttled, held or rejected, with a notice to the admin and the sender.
Bulk mail (8i), named senders or automatically by Precedence or List-Unsubscribe, gets the mark X-eFa-Bulk that Postfix sends
through its own slow transport; missing sender requirements of the big providers are logged or the mail is held. Bulk mail
does not count for the limits.
A mail it cannot read goes on unchanged, one it has to encrypt and cannot waits in the queue of the sending server."""
import email
import email.policy
import email.utils
import hashlib
import hmac
import html as html_lib
import ipaddress
import json
import os
import re
import secrets
import smtplib
import socket
import subprocess
import sys
import syslog
import threading
import time

# The copy next to this program first (a checkout in CI), then the installed one: insert(0) puts the last one in front.
for _folder in ('/usr/lib/eFa/python', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'lib', 'eFa', 'python')):
    if os.path.isdir(_folder) and _folder not in sys.path:
        sys.path.insert(0, _folder)
import efa_disclaimer  # noqa: E402
import efa_redis  # noqa: E402
import efa_mime  # noqa: E402
import efa_pdf  # noqa: E402
import efa_crypto  # noqa: E402
import efa_host  # noqa: E402

PORT = 8908
DISCLAIMER_DIR = os.environ.get('EFA_DISCLAIMER_DIR', '/etc/eFa/disclaimers')
SETTINGS = os.environ.get('EFA_OUTBOUND_SETTINGS', '/etc/eFa/outbound.json')
MAX_MAIL = 30 * 1024 * 1024
# shortcut: DLP reads the first 2 MB of text of a mail; raise it if leaks hide behind long texts.
MAX_TEXT = 2 * 1024 * 1024
ACTIONS = ('off', 'log', 'encrypt', 'hold', 'reject')
PASSWORDS = os.path.join(os.environ.get('CREDENTIALS_DIRECTORY', '/nonexistent'), 'pdf-passwords')
# AD signatures: the directory fields of each sender (name, title, phone ...), a credential like the PDF passwords.
SIGNATURE_FIELDS = os.path.join(os.environ.get('CREDENTIALS_DIRECTORY', '/nonexistent'), 'signature-fields')
SIGNATURE_CACHE = {}
# The password notices come back through this milter: a mark only this process can make lets them pass.
NOTICE_KEY = os.urandom(32)
NOTICE_HEADER = 'X-eFa-Password-Notice'
ID_CONTEXT_RE = re.compile(r'(sozialvers|versicherungs|sv[- ]?n|svnr|steuer|st\.? ?nr|idnr|identifikationsn|tax|social security)', re.I)
ID_RE = re.compile(r'(?<![\d/])(\d{4} ?\d{6}|\d{2}[ /]?\d{3}[ /]?\d{4}|\d{11}|\d{2} ?\d{6} ?[A-Z] ?\d{3})(?![\d/])')
CARD_RE = re.compile(r'(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])')
IBAN_RE = re.compile(r'\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b')


def settings(path=SETTINGS, cache={}):  # noqa: B006 - the default dict is the cache of the settings file
    try:
        stamp = os.stat(path).st_mtime_ns
    except OSError:
        return {}
    if cache.get('stamp') != stamp:
        with open(path) as f:
            cache.update(stamp=stamp, value=json.load(f))
    return cache['value']


def outgoing(ip, authenticated, networks):
    if authenticated:
        return True
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(network, strict=False) for network in networks)


def luhn(digits):
    total = 0
    for index, digit in enumerate(reversed(digits)):
        value = int(digit) * (2 if index % 2 else 1)
        total += value - 9 if value > 9 else value
    return total % 10 == 0


def cards(text):
    """Card numbers: 13 to 19 digits of a known card prefix with a right Luhn check digit."""
    found = set()
    for match in CARD_RE.finditer(text):
        groups = re.split(r'[ -]', match.group())
        # As with IBANs: a number right after the card number makes it longer, so shorter by one group until it fits.
        while groups:
            digits = ''.join(groups)
            if 13 <= len(digits) <= 19 and digits[0] in '23456' and len(set(digits)) > 1 and luhn(digits):
                found.add(digits)
                break
            groups.pop()
    return found


def ibans(text, ignore=()):
    """IBANs with a right check sum, without the own ones of the ignore list."""
    found = set()
    for match in IBAN_RE.finditer(text.upper()):
        words = match.group().split(' ')
        # The pattern also takes the words after a printed IBAN: shorter by one word until the check sum fits.
        while words:
            iban = ''.join(words)
            if 15 <= len(iban) <= 34 and int(''.join(str(int(char, 36)) for char in iban[4:] + iban[:4])) % 97 == 1:
                if iban not in ignore:
                    found.add(iban)
                break
            words.pop()
    return found


def at_svnr(digits):
    """Austrian social security number: 4 digits with the check digit last, then the birth date DDMMYY."""
    if len(digits) != 10 or not digits.isdigit() or not 1 <= int(digits[4:6]) <= 31 or not 1 <= int(digits[6:8]) <= 12:
        return False
    total = sum(int(digit) * weight for digit, weight in zip(digits, (3, 7, 9, 0, 5, 8, 4, 2, 1, 6))) % 11
    return total != 10 and total == int(digits[3])


def de_tax_id(digits):
    """German tax identification number: 11 digits, ISO 7064 MOD 11,10."""
    if len(digits) != 11 or not digits.isdigit() or digits[0] == '0':
        return False
    product = 10
    for digit in digits[:10]:
        total = (int(digit) + product) % 10 or 10
        product = total * 2 % 11
    return (11 - product) % 10 == int(digits[10])


def de_svnr(value):
    """German pension insurance number: area, birth date, first letter of the birth name, serial and check digit."""
    if not re.fullmatch(r'\d{8}[A-Z]\d{3}', value) or not 1 <= int(value[2:4]) <= 31 or not 1 <= int(value[4:6]) <= 12:
        return False
    digits = value[:8] + '%02d' % (ord(value[8]) - 64) + value[9:11]
    total = sum(sum(divmod(int(digit) * weight, 10)) for digit, weight in zip(digits, (2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1)))
    return total % 10 == int(value[11])


def at_tax_number(digits):
    """Austrian tax number: tax office and 7 digits, the last one a check digit."""
    if len(digits) != 9 or not digits.isdigit():
        return False
    total = sum(sum(divmod(int(digit) * weight, 10)) for digit, weight in zip(digits, (1, 2, 1, 2, 1, 2, 1, 2)))
    return (10 - total % 10) % 10 == int(digits[8])


def national_ids(text):
    """Tax and social security numbers of Austria and Germany, with a word like Steuer or SV close before them."""
    found = set()
    for match in ID_RE.finditer(text.upper()):
        if not ID_CONTEXT_RE.search(text[max(0, match.start() - 40):match.start()]):
            continue
        value = re.sub(r'[ /]', '', match.group())
        if at_svnr(value) or de_tax_id(value) or de_svnr(value) or at_tax_number(value):
            found.add(value)
    return found


def mail_text(message):
    """Subject, text and HTML parts and text attachments, as far as they can be read. A structure the email library cannot walk
    raises: DLP would see only a part, so the milter lets the mail wait (451) instead."""
    texts = []
    try:
        texts.append(str(message.get('Subject', '')))
    except efa_mime.BROKEN:
        pass
    for part in message.walk():
        try:
            if part.is_multipart() or part.get_content_maintype() != 'text':
                continue
            texts.append(part.get_content())
        except efa_mime.BROKEN:
            # The raw text of the part: DLP still reads it.
            payload = part.get_payload(decode=True) if not part.is_multipart() else None
            if payload:
                texts.append(payload.decode('utf-8', 'replace'))
            continue
        if sum(map(len, texts)) > MAX_TEXT:
            break
    return '\n'.join(texts)[:MAX_TEXT]


def dlp_verdict(text, dlp):
    """The strongest action of all rules that hit, and the names of those rules: ('off', []) for none."""
    hits = []
    if dlp.get('cards', 'off') != 'off' and cards(text):
        hits.append(('cards', dlp['cards']))
    if dlp.get('iban', 'off') != 'off' and ibans(text, {item.replace(' ', '').upper() for item in dlp.get('ignore', [])}):
        hits.append(('iban', dlp['iban']))
    if dlp.get('ids', 'off') != 'off' and national_ids(text):
        hits.append(('ids', dlp['ids']))
    for rule in dlp.get('rules', []):
        if rule.get('action', 'off') != 'off' and re.search(rule['pattern'], text, re.I):
            hits.append((rule['name'], rule['action']))
    if not hits:
        return 'off', [], False
    return (max((action for _name, action in hits), key=ACTIONS.index), [name for name, _action in hits],
            any(action == 'encrypt' for _name, action in hits))


BULK_PRECEDENCE_RE = re.compile(r'^\s*(bulk|list|junk)\b', re.I)


def bulk_wanted(sender, message, bulk):
    """Whether a mail is bulk mail: a named sender or domain, or with auto by its Precedence or List-Unsubscribe header."""
    if not bulk.get('enabled'):
        return False
    senders = set(bulk.get('senders', []))
    if sender in senders or sender.rpartition('@')[2] in senders:
        return True
    return bool(bulk.get('auto')) and (bool(BULK_PRECEDENCE_RE.match(str(message.get('Precedence', '')))) or message.get('List-Unsubscribe') is not None)


def bulk_missing(sender, message, bulk):
    """What the big providers ask of bulk senders and this mail lacks: one-click unsubscribe (RFC 8058), DKIM, SPF, DMARC."""
    missing = []
    if message.get('List-Unsubscribe') is None or 'one-click' not in str(message.get('List-Unsubscribe-Post', '')).lower():
        missing.append('one-click-unsubscribe')
    return missing + bulk.get('ready', {}).get(sender.rpartition('@')[2], ['not-checked'])


def active(wanted):
    """Whether the milter has anything to do for a mail of this sender domain."""
    dlp = wanted.get('dlp', {})
    return any(dlp.get(key, 'off') != 'off' for key in ('cards', 'iban', 'ids')) or \
        any(rule.get('action', 'off') != 'off' for rule in dlp.get('rules', [])) or bool(wanted.get('pdf', {}).get('keyword')) or \
        wanted.get('limits', {}).get('action', 'off') != 'off' or bool(wanted.get('bulk', {}).get('enabled')) or any(wanted.get('privacy', {}).values()) or \
        bool(wanted.get('recall')) or bool(wanted.get('misdirect')) or bool(wanted.get('crypto'))


# P6 and P1: mail that waits in the hold queue for the sender. The milter holds it and leaves a note here; efactl outbound-hold-run
# sends it on (recall time over, or confirmed), or gives it back (not confirmed in time).
HOLD_NOTES = os.environ.get('EFA_HOLD_NOTES', '/var/lib/efa-outbound/held')

# 15: S/MIME and PGP. The keys come as systemd credentials (crypto_<file>); certificates of senders that signed their mail are
# kept in the state folder (harvest) and used to encrypt to them later. The own PGP keys go into a home of gpg in the private /tmp.
CRYPTO_KEYS = os.environ.get('CREDENTIALS_DIRECTORY', '/nonexistent')
HARVEST = os.environ.get('EFA_HARVEST', '/var/lib/efa-outbound/harvest')
crypto_cache = {}


def crypto_keys():
    stamp = os.stat(HARVEST).st_mtime_ns if os.path.isdir(HARVEST) else 0
    if crypto_cache.get('stamp') != stamp:
        crypto_cache.update(stamp=stamp, keys={**efa_crypto.key_files(HARVEST), **efa_crypto.key_files(CRYPTO_KEYS, 'crypto_')})
    return crypto_cache['keys']


def crypto_gpg(keys):
    if 'gpg' not in crypto_cache:
        crypto_cache['gpg'] = efa_crypto.gpg_home([path for name, path in keys.items() if name.startswith('pgp-own-')])
    return crypto_cache['gpg']


def crypto_outbound(raw, sender, rcpts, policy, keys):
    """(plan, the mail signed and/or encrypted) after the policy; plan['missing'] names recipients that must be encrypted for
    and have no key. A mail the sender signed or encrypted already stays as it is."""
    plan = efa_crypto.outbound_plan(policy, sender, rcpts, keys)
    if plan['missing'] or not (plan['sign'] or plan['encrypt']) or efa_crypto.is_encrypted(raw) or efa_crypto.is_signed(raw):
        return plan, raw
    out = raw
    if plan['encrypt'] == 'smime':
        if plan['sign'] == 'smime':
            out = efa_crypto.smime_sign(out, efa_crypto.key_for(keys, 'smime-own', sender))
        out = efa_crypto.smime_encrypt(out, [efa_crypto.key_for(keys, 'smime-peer', rcpt) for rcpt in rcpts])
    elif plan['encrypt'] == 'pgp':
        home, fingerprints = crypto_gpg(keys)
        signer = fingerprints.get(efa_crypto.key_for(keys, 'pgp-own', sender)) if plan['sign'] == 'pgp' else None
        out = efa_crypto.pgp_encrypt(out, home, [efa_crypto.key_for(keys, 'pgp-peer', rcpt) for rcpt in rcpts], signer=signer)
    elif plan['sign'] == 'smime':
        out = efa_crypto.smime_sign(out, efa_crypto.key_for(keys, 'smime-own', sender))
    else:
        home, fingerprints = crypto_gpg(keys)
        out = efa_crypto.pgp_sign(out, home, fingerprints[efa_crypto.key_for(keys, 'pgp-own', sender)])
    return plan, out


def crypto_inbound(raw, sender, rcpts, policy, keys):
    """(the mail decrypted with the key of a recipient or its domain, or None; what was done). A signed mail gives the
    certificate of its signer to the harvest, to encrypt to that sender later."""
    done, out = [], None
    if efa_crypto.is_encrypted(raw):
        kind = efa_crypto.content_type(raw)
        for rcpt in rcpts:
            try:
                if kind.startswith('multipart/encrypted'):
                    home, _fingerprints = crypto_gpg(keys)
                    out = efa_crypto.pgp_decrypt(raw, home)
                else:
                    pem = efa_crypto.key_for(keys, 'smime-own', rcpt)
                    out = efa_crypto.smime_decrypt(raw, pem) if pem else None
            except (efa_crypto.CryptoError, OSError, subprocess.SubprocessError):
                out = None
            if out:
                done.append('decrypted')
                break
    current = out or raw
    if policy.get('harvest') and efa_crypto.is_signed(current) and 'pkcs7' in efa_crypto.content_type(current) and re.fullmatch(r'[\w.%+-]+@[\w.-]+', sender):
        try:
            cert = efa_crypto.smime_signer_cert(current)
        except (OSError, subprocess.SubprocessError):
            cert = None
        if cert:
            os.makedirs(HARVEST, mode=0o700, exist_ok=True)
            with open(os.path.join(HARVEST, f'smime-peer-{sender.lower()}.pem'), 'wb') as f:
                f.write(cert)
            done.append('certificate of the sender kept')
    return out, done


def has_attachment(message):
    return any(part.get_content_disposition() == 'attachment' or (part.get_filename() and not part.is_multipart()) for part in message.walk())


def redis_exists(key, host='127.0.0.1', port=6379):
    """EXISTS of Redis in its own protocol; OSError when Redis does not answer."""
    data = key.encode()
    with socket.create_connection((host, port), timeout=2) as conn:
        conn.sendall(b'*2\r\n$6\r\nEXISTS\r\n$%d\r\n%s\r\n' % (len(data), data))
        answer = conn.recv(64)
    if not answer.startswith(b':'):
        raise OSError(f'redis: {answer[:40]!r}')
    return int(answer[1:].split(b'\r\n', 1)[0]) > 0


def unknown_recipients(sender, rcpts, local, exists=redis_exists):
    """P1: the outside recipients this sender never wrote to (the pairs of the BEC check). Redis down: all of them, fail closed."""
    outside = [rcpt for rcpt in rcpts if rcpt.rpartition('@')[2] not in local]
    try:
        return [rcpt for rcpt in outside if not exists(f'efa:bec:rel:{sender}|{rcpt}')]
    except OSError:
        return outside


def hold_note(queue_id, kind, sender, login, rcpts, subject, until, folder=None):
    folder = folder or HOLD_NOTES
    os.makedirs(folder, mode=0o700, exist_ok=True)
    if not re.fullmatch(r'[0-9A-Za-z]{6,20}', queue_id):
        raise ValueError('no queue id')
    note = {'qid': queue_id, 'kind': kind, 'sender': sender, 'login': login, 'rcpts': rcpts[:50], 'subject': subject[:200], 'until': until,
            'since': time.time()}
    with open(os.path.join(folder, queue_id + '.json.tmp'), 'w') as f:
        json.dump(note, f)
    os.replace(os.path.join(folder, queue_id + '.json.tmp'), os.path.join(folder, queue_id + '.json'))
    return note


def hold_wanted(wanted, sender, login, ip, rcpts, message, exists=redis_exists):
    """('recall', minutes) or ('confirm', [recipients], hours) or None, for a mail that left the other checks."""
    domain = sender.rpartition('@')[2]
    misdirect = (wanted.get('misdirect') or {}).get(domain)
    if misdirect and has_attachment(message):
        unknown = unknown_recipients(sender, rcpts, set(wanted.get('local_domains', [])), exists)
        if unknown:
            return 'confirm', unknown, int(misdirect)
    recall = (wanted.get('recall') or {}).get(domain)
    if recall and login:
        return 'recall', int(recall)
    return None


# M2: headers that tell the outside about the internal network and the programs of the sender.
PRIVATE_HEADERS = ('received', 'x-originating-ip', 'x-mailer', 'user-agent', 'x-forwarded-for', 'x-client-ip')


def privacy_wanted(wanted, sender, login, ip):
    """Whether the private headers of this outgoing mail go: for all, for the sender domain, or for the submitter."""
    privacy = wanted.get('privacy', {})
    if privacy.get('all') or sender.rpartition('@')[2] in privacy.get('domains', []) or (login and login in privacy.get('logins', [])):
        return True
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(network, strict=False) for network in privacy.get('networks', []))


def private_deletions(headers):
    """(name, index) of the private headers to delete, the last first; none that a DKIM signature of the sender covers."""
    signed = set()
    for name, value in headers:
        if name.lower() == 'dkim-signature':
            match = re.search(r'(?:^|;)\s*h\s*=([^;]*)', value)
            signed |= {item.strip().lower() for item in (match.group(1) if match else '').split(':')}
    seen, found = {}, []
    for name, _value in headers:
        key = name.lower()
        seen[key] = seen.get(key, 0) + 1
        if key in PRIVATE_HEADERS and key not in signed:
            found.append((name, seen[key]))
    return sorted(found, key=lambda item: -item[1])


def strict(wanted):
    """DLP or PDF encryption on: a mail that cannot be checked waits instead of leaving."""
    dlp = wanted.get('dlp', {})
    return any(dlp.get(key, 'off') != 'off' for key in ('cards', 'iban', 'ids')) or \
        any(rule.get('action', 'off') != 'off' for rule in dlp.get('rules', [])) or bool(wanted.get('pdf', {}).get('keyword'))


def keyword_in(subject, keyword):
    return bool(keyword) and keyword.lower() in subject.lower()


def without_keyword(subject, keyword):
    start = subject.lower().find(keyword.lower()) if keyword else -1
    return ' '.join((subject[:start] + subject[start + len(keyword):]).split()) if start >= 0 else subject


def password_for(recipients, agreed):
    """The agreed password, if all recipients share one (by address, else by domain), and True; else a new one and False."""
    found = {agreed.get(rcpt) or agreed.get(rcpt.rpartition('@')[2]) for rcpt in recipients}
    if len(found) == 1 and None not in found:
        return found.pop(), True
    return secrets.token_urlsafe(12), False


def body_text(message):
    part = message.get_body(('plain', 'html'))
    if part is None:
        return ''
    try:
        text = part.get_content()
    except (LookupError, ValueError):
        return ''
    if part.get_content_type() == 'text/html':
        text = re.sub(r'(?is)<(script|style).*?</\1>', '', text)
        text = html_lib.unescape(re.sub(r'(?s)<[^>]+>', '', re.sub(r'(?i)<br\s*/?>|</p>|</div>|</tr>', '\n', text)))
    return text


def encrypted_mail(message, password, agreed, keyword):
    """The mail with a short note and the PDF of the mail and its attachments, encrypted with the password."""
    names = ('From', 'To', 'Cc', 'Date', 'Subject')
    lines = [f'{name}: {message[name]}' for name in names if message[name]] + ['']
    attachments = []
    for index, part in enumerate(message.iter_attachments()):
        name = part.get_filename() or f'attachment-{index + 1}'
        attachments.append((name, part.get_payload(decode=True) or b''))
        lines.append(f'Attachment / Anhang: {name}')
    lines += [''] + body_text(message).splitlines()
    sealed = efa_pdf.encrypt(efa_pdf.build(lines, attachments), password)
    new = email.message.EmailMessage()
    for name, value in message.items():
        if name.lower() not in ('mime-version', 'content-type', 'content-transfer-encoding', 'content-disposition'):
            new[name] = without_keyword(str(value), keyword) if name.lower() == 'subject' else value
    how = ('with the password agreed with you', 'mit dem mit Ihnen vereinbarten Passwort') if agreed else \
        ('with the password the sender gives you separately', 'mit dem Passwort, das Sie getrennt vom Absender erhalten')
    new.set_content(f'Diese Nachricht wurde verschlüsselt. Öffnen Sie die angehängte PDF-Datei {how[1]}.\n\n'
                    f'This message was encrypted. Open the attached PDF file {how[0]}.\n')
    new.add_attachment(sealed, maintype='application', subtype='pdf', filename='message.pdf')
    return new


redis_call = efa_redis.call


class RedisCounts:
    """A1: the counts of RateWatch in Redis, so a restart of the service does not start them again. One key pair per sender and
    hour, gone after two hours.

    8g: on a cluster the limits hold for all nodes together. Each node lists its keys of the hour in the hash efa:rate:own:<hour>;
    efa-cluster reports them to the master every half minute and writes what the other nodes counted into :pr (recipients) and
    :pd (target domains) of the same key. A count here is the own one plus that of the others, at most half a minute old."""
    PREFIX = 'efa:rate:'
    TTL = 7200

    def __init__(self, call=redis_call):
        self.call = call

    def count(self, key, recipients, domains):
        """(recipients, target domains) of this key in this hour, these included; key ends in :<hour>."""
        base = self.PREFIX + key
        own = self.PREFIX + 'own:' + key.rsplit(':', 1)[1]
        commands = [('INCRBY', base + ':r', recipients), ('EXPIRE', base + ':r', self.TTL),
                    ('HINCRBY', own, key.rsplit(':', 1)[0], recipients), ('EXPIRE', own, self.TTL)]
        if domains:
            commands += [('SADD', base + ':d', *sorted(domains)), ('EXPIRE', base + ':d', self.TTL)]
        # The union of the own and the others' target domains: one domain reached from two nodes counts once.
        commands += [('GET', base + ':pr'), ('SUNIONSTORE', base + ':u', base + ':d', base + ':pd'), ('EXPIRE', base + ':u', 60)]
        answers = self.call(commands)
        return answers[0] + int(answers[-3] or 0), answers[-2]

    def once(self, key):
        """True the first time for this key (SET NX): one notice per sender and hour, also after a restart."""
        return self.call([('SET', self.PREFIX + key + ':told', 1, 'NX', 'EX', self.TTL)])[0] == 'OK'


class RateWatch:
    """Recipients and target domains per sender (login or address of the client) in the running hour. With a store (Redis) the
    counts survive a restart; when the store does not answer they are kept in memory as before, so the limits still hold."""
    # 8g: on a cluster the store holds the counts of the other nodes too (see RedisCounts); without the store, or while the
    # master does not answer, each node counts only its own mail.

    def __init__(self, store=None):
        self.lock, self.windows, self.store = threading.Lock(), {}, store

    def _stored(self, key, recipients, now):
        """(recipients, domains) from the store, None when there is none or it does not answer."""
        if self.store is None:
            return None
        try:
            return self.store.count(f'{key}:{int(now // 3600)}', len(recipients), {rcpt.rpartition('@')[2] for rcpt in recipients})
        except (OSError, ValueError) as err:
            syslog.syslog(syslog.LOG_WARNING, f'efa-outbound: sending counts in memory, Redis: {err}')
            return None

    def add(self, who, recipients, limits, now=None, domain='', tenant=''):
        """Counts the mail, and names the limit it goes over: 'recipients', 'domains', 'sender-domain', 'tenant' or None.
        9j: the recipients of all senders of one sender domain, and of one tenant, count against their own limits too."""
        now = time.time() if now is None else now
        with self.lock:
            over = None
            for key, limit, name in (('domain:' + domain, limits.get('domain_recipients_hour'), 'sender-domain'),
                                     ('tenant:' + tenant, limits.get('tenant_recipients_hour'), 'tenant')):
                if not limit or key.endswith(':'):
                    continue
                stored = self._stored(key, recipients, now)
                if stored is not None:
                    if stored[0] > limit and over is None:
                        over = name
                    continue
                window = self.windows.get(key)
                if window is None or now - window['start'] >= 3600:
                    window = self.windows[key] = {'start': now, 'recipients': 0, 'domains': set(), 'told': False}
                window['recipients'] += len(recipients)
                if window['recipients'] > limit and over is None:
                    over = name
            if over:
                return over
            stored = self._stored('who:' + who, recipients, now)
            if stored is not None:
                if limits.get('recipients_hour') and stored[0] > limits['recipients_hour']:
                    return 'recipients'
                if limits.get('domains_hour') and stored[1] > limits['domains_hour']:
                    return 'domains'
                return None
            window = self.windows.get(who)
            if window is None or now - window['start'] >= 3600:
                window = self.windows[who] = {'start': now, 'recipients': 0, 'domains': set(), 'told': False}
            window['recipients'] += len(recipients)
            window['domains'] |= {rcpt.rpartition('@')[2] for rcpt in recipients}
            if len(self.windows) > 10000:  # old windows of senders that are gone
                self.windows = {key: value for key, value in self.windows.items() if now - value['start'] < 3600}
            if limits.get('recipients_hour') and window['recipients'] > limits['recipients_hour']:
                return 'recipients'
            if limits.get('domains_hour') and len(window['domains']) > limits['domains_hour']:
                return 'domains'
            return None

    def first_time(self, who):
        """True once per sender and hour: the notices go out only once."""
        if self.store is not None:
            try:
                return self.store.once(f'who:{who}:{int(time.time() // 3600)}')
            except (OSError, ValueError):
                pass
        with self.lock:
            window = self.windows.get(who)
            if window is None or window['told']:
                return False
            window['told'] = True
            return True


# A1: a sender over a limit is taken as a taken-over account: all its further mail waits in the hold queue until an admin
# releases the account (efactl hijack-release). The list survives a restart; efactl reads it, its release comes with the settings.
HELD_FILE = os.environ.get('EFA_HELD_FILE', '/var/lib/efa-outbound/held-senders.json')


class HeldSenders:
    def __init__(self, path=HELD_FILE):
        self.path, self.lock = path, threading.Lock()
        try:
            with open(path) as f:
                self.held = json.load(f)
        except (OSError, ValueError):
            self.held = {}

    def hold(self, who, reason, now=None):
        with self.lock:
            if who in self.held:
                return False
            self.held[who] = {'since': time.time() if now is None else now, 'reason': reason}
            self._save()
            return True

    def is_held(self, who, released):
        """Held, unless an admin released it after it was held; a release takes it off the list."""
        with self.lock:
            item = self.held.get(who)
            if item is None:
                return False
            if float(released.get(who, 0)) >= item['since']:
                del self.held[who]
                self._save()
                return False
            return True

    def _save(self):
        try:
            with open(self.path + '.tmp', 'w') as f:
                json.dump(self.held, f)
            os.replace(self.path + '.tmp', self.path)
        except OSError as err:  # a read-only folder keeps the list in memory
            syslog.syslog(syslog.LOG_ERR, f'efa-outbound: list of held accounts not saved: {err}')


def notice_mark(message_id):
    return hmac.new(NOTICE_KEY, message_id.encode(), hashlib.sha256).hexdigest()


def is_notice(message):
    # Postfix hands folded headers over with their line breaks.
    mark = ''.join(str(message.get(NOTICE_HEADER, '')).split())
    return bool(mark) and hmac.compare_digest(mark, notice_mark(''.join(str(message.get('Message-ID', '')).split())))


def send_mail(to, subject, text):
    """A notice of eFa-next, with the null sender and a mark that lets it pass this milter."""
    notice = email.message.EmailMessage()
    host = efa_host.own_hostname()
    notice['From'], notice['To'], notice['Subject'] = f'eFa-next <postmaster@{host}>', to, subject
    notice['Message-ID'] = email.utils.make_msgid(domain=host)
    notice[NOTICE_HEADER] = notice_mark(notice['Message-ID'])
    notice.set_content(text)
    with smtplib.SMTP('127.0.0.1', 25, timeout=30) as server:
        server.send_message(notice, from_addr='', to_addrs=[to])


def send_notice(sender, recipients, message_id, password):
    """The password of an encrypted mail to its sender, in a mail of its own. Without the subject: it may hold what DLP looks for."""
    send_mail(sender, 'Passwort / password',
              f'Ihre Nachricht {message_id} an {", ".join(recipients)} wurde als PDF verschlüsselt. '
              f'Geben Sie den Empfängern dieses Passwort auf einem anderen Weg, etwa per Telefon oder SMS:\n\n    {password}\n\n'
              f'Your message {message_id} to {", ".join(recipients)} was encrypted as PDF. '
              f'Give the recipients this password another way, by phone or text message for instance.\n')


def limit_text(who, limit, action):
    what = {'recipients': ('zu viele Empfänger', 'too many recipients'), 'domains': ('zu viele verschiedene Zieldomains', 'too many target domains')}[limit]
    done = {'log': ('nur protokolliert', 'logged only'), 'throttle': ('vorläufig gebremst', 'throttled for now'),
            'hold': ('zurückgehalten, bis ein Admin sie freigibt', 'held until an admin releases them'), 'reject': ('abgewiesen', 'rejected')}[action]
    return (f'Der Absender {who} hat in dieser Stunde {what[0]} angeschrieben. Weitere Mails werden {done[0]}. '
            f'Wurde das Konto übernommen? Passwort ändern und das Gerät prüfen.\n\n'
            f'The sender {who} wrote to {what[1]} in this hour. Further mail is {done[1]}. '
            f'Was the account taken over? Change the password and check the device.\n')


def add_disclaimer(message, text, html):
    """The mail with a disclaimer of text and optional HTML, or None if it has to stay as it is."""
    return with_disclaimer(message, {'id': '-', 'scope': 'global', 'format': 'html' if html else 'text', 'text': text, 'html': html})


def disclaimer_for(wanted, sender):
    """The one template for a sender (8k), the per-domain disclaimers of before as domain templates."""
    legacy = [{'id': f'domain-{domain}'[:40], 'scope': 'domain', 'target': domain, 'format': 'html' if item.get('html') else 'text',
               'text': item.get('text', ''), 'html': item.get('html', ''), 'priority': 100} for domain, item in wanted.get('domains', {}).items()]
    tenants, groups = wanted.get('tenant_of', {}), wanted.get('sender_groups', {})
    return efa_disclaimer.pick(wanted.get('disclaimers', []) + legacy, sender.lower(), lambda domain: tenants.get(domain, ''),
                               lambda address: groups.get(address, ()))


def with_disclaimer(message, template):
    """The mail with the template in it, or None if it stays as it is."""
    folder = os.path.join(DISCLAIMER_DIR, template['id'])

    def read_file(name):
        with open(os.path.join(folder, os.path.basename(name)), 'rb') as f:
            return f.read()
    try:
        if not efa_disclaimer.apply(message, template, read_file, efa_mime.sealed):
            return None
        return efa_mime.to_bytes(message)
    except (*efa_mime.BROKEN, efa_mime.Unwritable, OSError):  # a structure it cannot write, or a missing file: without it then
        return None


def run_milter():
    import Milter

    class Outbound(Milter.Base):
        def __init__(self):
            self.ip, self.headers, self.chunks, self.sender, self.skip, self.too_big, self.rcpts, self.login = '', [], [], '', True, False, [], ''

        def connect(self, hostname, family, hostaddr):
            self.ip = hostaddr[0] if hostaddr else ''
            return Milter.CONTINUE

        def envfrom(self, sender, *args):
            self.headers, self.chunks, self.too_big, self.rcpts, self.inbound_crypto = [], [], False, [], False
            self.sender = sender.strip('<>').lower()
            self.login = self.getsymval('{auth_authen}') or ''
            wanted = settings()
            self.skip = not (active(wanted) or self.sender.rpartition('@')[2] in wanted.get('domains', {}))
            return Milter.CONTINUE

        def eoh(self):
            # Now the recipients are known: mail to a domain this server does not take mail for is outgoing too.
            if not self.skip:
                wanted = settings()
                local = wanted.get('local_domains')
                foreign = local is not None and any(rcpt.rpartition('@')[2] not in local for rcpt in self.rcpts)
                leaving = foreign or outgoing(self.ip, bool(self.login), wanted.get('networks', []))
                # 15: incoming mail for a domain that decrypts at the gateway, before rspamd, so the filter sees the content.
                self.inbound_crypto = not leaving and any(rcpt.rpartition('@')[2] in (wanted.get('crypto') or {}).get('decrypt', []) for rcpt in self.rcpts)
                self.skip = not (leaving or self.inbound_crypto)
            return Milter.CONTINUE

        def envrcpt(self, to, *args):
            self.rcpts.append(to.strip('<>').lower())
            return Milter.CONTINUE

        def header(self, name, value):
            self.headers.append((name, value))
            return Milter.CONTINUE

        def body(self, chunk):
            if not self.skip and not self.too_big:
                self.chunks.append(chunk)
                if sum(len(item) for item in self.chunks) > MAX_MAIL:
                    self.too_big, self.chunks = True, []
            return Milter.CONTINUE

        def eom(self):
            if self.skip:
                return Milter.ACCEPT
            queue_id = self.getsymval('i') or '-'
            if self.too_big:
                syslog.syslog(syslog.LOG_WARNING, f'efa-outbound unchecked {queue_id} from={self.sender}: larger than {MAX_MAIL} bytes')
                return Milter.ACCEPT
            encrypt = False
            try:
                wanted = settings()
                raw = b''.join(f'{name}: {value}\r\n'.encode('utf-8', 'surrogateescape') for name, value in self.headers) + b'\r\n' + b''.join(self.chunks)
                message = email.message_from_bytes(raw, policy=email.policy.default)
                if is_notice(message):
                    return Milter.ACCEPT
                if getattr(self, 'inbound_crypto', False):
                    opened, done = crypto_inbound(raw, self.sender, self.rcpts, wanted.get('crypto') or {}, crypto_keys())
                    if opened:
                        efa_mime.hand_back(self, self.headers, opened)
                    if done:
                        self.addheader('X-eFa-Crypto', '; '.join(done))
                    return Milter.ACCEPT
                action, names, encrypt = dlp_verdict(mail_text(message), wanted.get('dlp', {}))
                limits, bulk = wanted.get('limits', {}), wanted.get('bulk', {})
                local = set(wanted.get('local_domains', []))
                # Only when all recipients are outside: the bulk transport sends every recipient of the mail to its own domain.
                is_bulk = all(rcpt.rpartition('@')[2] not in local for rcpt in self.rcpts) and bulk_wanted(self.sender, message, bulk)
                if is_bulk:
                    self.addheader('X-eFa-Bulk', 'yes')
                    missing = bulk_missing(self.sender, message, bulk)
                    if missing:
                        syslog.syslog(syslog.LOG_WARNING, f'efa-outbound bulk missing={",".join(missing)} from={self.sender} id={queue_id}')
                        self.addheader('X-eFa-Bulk-Missing', ', '.join(missing))
                        if bulk.get('missing') == 'hold':
                            action, names = max(action, 'hold', key=ACTIONS.index), names + ['bulk-requirements']
                who = self.login or self.ip
                if limits.get('auto_hold') and self.held.is_held(who, wanted.get('released', {})):
                    syslog.syslog(syslog.LOG_WARNING, f'efa-outbound held account who={who} from={self.sender} id={queue_id}')
                    self.quarantine('account held: possibly taken over (A1), an admin releases it')
                    return Milter.ACCEPT
                domain = self.sender.rpartition('@')[2]
                over = self.watch.add(who, self.rcpts, limits, domain=domain, tenant=str(wanted.get('tenants', {}).get(domain, ''))) \
                    if limits.get('action', 'off') != 'off' and not is_bulk else None
                if over:
                    syslog.syslog(syslog.LOG_WARNING, f'efa-outbound limit {limits["action"]} {over} who={who} from={self.sender} id={queue_id}')
                    if self.watch.first_time(who):
                        text = limit_text(who, over, limits['action'])
                        for to in {wanted.get('admin'), self.sender if self.login else None} - {None, ''}:
                            try:
                                send_mail(to, 'eFa-next: Versandgrenze / sending limit', text)
                            except (OSError, smtplib.SMTPException) as err:  # the limit holds without the notice
                                syslog.syslog(syslog.LOG_ERR, f'efa-outbound notice to {to} failed: {err}')
                    if limits.get('auto_hold') and self.held.hold(who, f'over the limit {over}'):
                        for to in {wanted.get('admin')} - {None, ''}:
                            try:
                                send_mail(to, 'eFa-next: Konto angehalten / account held',
                                          f'{who} went over the sending limit ({over}) and may be taken over. Its mail waits in the hold queue '
                                          f'until you release it: efactl hijack-release --who {who}\n')
                            except (OSError, smtplib.SMTPException) as err:
                                syslog.syslog(syslog.LOG_ERR, f'efa-outbound notice to {to} failed: {err}')
                        action, names = 'hold', names + ['account-held']
                    if limits['action'] == 'throttle':
                        self.setreply('451', '4.7.1', 'Sending limit reached, try again later')
                        return Milter.TEMPFAIL
                    action, names = max(action, limits['action'], key=ACTIONS.index), names + [f'limit-{over}']
                keyword = wanted.get('pdf', {}).get('keyword', '')
                if keyword_in(str(message.get('Subject', '')), keyword):
                    encrypt, names = True, names + ['subject']
                    action = max(action, 'encrypt', key=ACTIONS.index)
                if action != 'off':
                    syslog.syslog(syslog.LOG_WARNING, f'efa-outbound dlp {action} rules={",".join(names)} from={self.sender} id={queue_id}')
                if action == 'reject':
                    self.setreply('550', '5.7.1', 'Stopped by data loss prevention, ask your administrator')
                    return Milter.REJECT
                if encrypt and not efa_mime.sealed(message):
                    password, agreed = password_for(self.rcpts, settings(PASSWORDS, {}) if os.path.exists(PASSWORDS) else {})
                    message = encrypted_mail(message, password, agreed, keyword)
                    if not agreed:
                        send_notice(self.sender, self.rcpts, str(message.get('Message-ID', queue_id)), password)
                    if str(message.get('Subject', '')) != dict((k.lower(), v) for k, v in self.headers).get('subject', ''):
                        self.chgheader('Subject', 1, str(message.get('Subject', '')))
                    syslog.syslog(syslog.LOG_INFO, f'efa-outbound encrypted {queue_id} password={"agreed" if agreed else "to sender"}')
                if action != 'off':
                    self.addheader('X-eFa-DLP', f'{action}: {", ".join(names)}')
                template = disclaimer_for(wanted, self.sender)
                if template and efa_disclaimer.FIELD_RE.search((template.get('text') or '') + (template.get('html') or '')):
                    fields = settings(SIGNATURE_FIELDS, SIGNATURE_CACHE).get(self.sender, {}) if os.path.exists(SIGNATURE_FIELDS) else {}
                    template = efa_disclaimer.fill(template, fields)
                changed = with_disclaimer(message, template) if template else None
                if changed is None and encrypt:
                    changed = efa_mime.to_bytes(message)
                crypto = wanted.get('crypto') or {}
                if crypto.get('sign') or crypto.get('encrypt'):
                    # Never out without the signature or encryption the policy asks for: the handler below answers 451.
                    encrypt = True
                    plan, sealed = crypto_outbound(changed if changed is not None else raw, self.sender, self.rcpts, crypto, crypto_keys())
                    if plan['missing']:
                        self.setreply('550', '5.7.1', f"No key to encrypt the mail for {', '.join(plan['missing'][:3])}: ask the recipient for a certificate")
                        return Milter.REJECT
                    if sealed is not (changed if changed is not None else raw):
                        changed = sealed
                        self.addheader('X-eFa-Crypto', ' '.join(item for item in (f"signed {plan['sign']}" if plan['sign'] else '',
                                                                                  f"encrypted {plan['encrypt']}" if plan['encrypt'] else '') if item))
                if changed is not None:
                    efa_mime.hand_back(self, self.headers, changed)
                if action == 'hold':
                    self.quarantine(f'data loss prevention: {", ".join(names)}')
                else:
                    held = hold_wanted(wanted, self.sender, self.login, self.ip, self.rcpts, message)
                    if held:
                        subject = str(message.get('Subject', ''))
                        if held[0] == 'recall':
                            hold_note(queue_id, 'recall', self.sender, self.login, self.rcpts, subject, time.time() + held[1] * 60)
                            self.quarantine(f'recall window of {held[1]} minutes (P6)')
                        else:
                            try:
                                hold_note(queue_id, 'confirm', self.sender, self.login, held[1], subject, time.time() + held[2] * 3600)
                            except (OSError, ValueError) as err:
                                # Fail closed: an attachment to a new recipient never goes out unconfirmed.
                                syslog.syslog(syslog.LOG_ERR, f'efa-outbound confirm note of {queue_id} failed: {err}')
                                self.setreply('451', '4.7.1', 'The mail could not be held for confirmation, try again later')
                                return Milter.TEMPFAIL
                            self.quarantine('attachment to a new recipient, the sender confirms (P1)')
                        syslog.syslog(syslog.LOG_INFO, f'efa-outbound {held[0]} {queue_id} from={self.sender}')
                if privacy_wanted(wanted, self.sender, self.login, self.ip):
                    for name, index in private_deletions(self.headers):
                        self.chgheader(name, index, '')
            except Exception as err:
                if encrypt or strict(settings()):
                    # Never out unchecked or in clear text: the sending server tries again later.
                    syslog.syslog(syslog.LOG_ERR, f'efa-outbound could not check or encrypt {queue_id}: {err}')
                    self.setreply('451', '4.7.1', 'The mail could not be checked at the moment, try again later')
                    return Milter.TEMPFAIL
                # mail flow first: a mail it cannot handle goes on unchanged
                syslog.syslog(syslog.LOG_ERR, f'efa-outbound left unchanged {queue_id}: {err}')
            return Milter.ACCEPT

    watch = RateWatch(RedisCounts())
    Outbound.watch = watch
    Outbound.held = HeldSenders()
    Milter.factory = Outbound
    Milter.set_flags(Milter.ADDHDRS | Milter.CHGHDRS | Milter.CHGBODY | Milter.QUARANTINE)
    Milter.runmilter('efa-outbound', f'inet:{PORT}@127.0.0.1', timeout=120)
    # A connection that comes in while Python shuts down crashes pymilter: end without the shutdown.
    os._exit(0)


def self_test():
    import tempfile
    # 15: out signed and encrypted after the policy; in decrypted with the key of the recipient domain, the signer kept.
    import shutil
    if shutil.which('openssl'):
        folder = tempfile.mkdtemp()
        try:
            pem = os.path.join(folder, 'gw.pem')
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=gateway', '-keyout', pem + '.key',
                            '-out', pem + '.crt', '-addext', 'subjectAltName=email:a@own.example'], capture_output=True, check=True)
            with open(pem, 'wb') as f:
                f.write(open(pem + '.crt', 'rb').read() + open(pem + '.key', 'rb').read())
            keys = {'smime-own-@own.example': pem, 'smime-peer-@far.example': pem}
            policy = {'sign': {'own.example': 'smime'}, 'encrypt': {'far.example': {'mode': 'always', 'kind': 'smime'}}, 'harvest': True}
            raw = b'From: a@own.example\r\nTo: b@far.example\r\nSubject: Offer\r\nContent-Type: text/plain\r\n\r\nsecret price\r\n'
            plan, sealed = crypto_outbound(raw, 'a@own.example', ['b@far.example'], policy, keys)
            assert plan == {'sign': 'smime', 'encrypt': 'smime', 'missing': []} and b'secret price' not in sealed and b'Subject: Offer' in sealed
            assert crypto_outbound(raw, 'a@own.example', ['c@nokey.example'], {'encrypt': {'nokey.example': {'mode': 'always', 'kind': 'auto'}}}, keys)[0]['missing']
            global HARVEST
            saved, HARVEST = HARVEST, os.path.join(folder, 'harvest')
            try:
                opened, done = crypto_inbound(sealed, 'a@own.example', ['x@own.example'], policy, {'smime-own-@own.example': pem})
                assert done == ['decrypted', 'certificate of the sender kept'] and b'secret price' in opened
                assert os.path.exists(os.path.join(HARVEST, 'smime-peer-a@own.example.pem'))
            finally:
                HARVEST = saved
        finally:
            shutil.rmtree(folder, ignore_errors=True)
    # P1 and P6: an attachment to a recipient the sender never wrote to waits for the sender; recall only for logged in users.
    with_file = email.message.EmailMessage()
    with_file['From'], with_file['Subject'] = 'anna@own.example', 'Offer'
    with_file.set_content('see attached')
    with_file.add_attachment(b'%PDF-1.4', maintype='application', subtype='pdf', filename='offer.pdf')
    plain = email.message.EmailMessage()
    plain.set_content('hello')
    wanted = {'misdirect': {'own.example': 4}, 'recall': {'own.example': 2}, 'local_domains': ['own.example']}
    known = {'efa:bec:rel:anna@own.example|bob@partner.example'}
    exists = known.__contains__
    assert hold_wanted(wanted, 'anna@own.example', 'anna', '', ['bob@partner.example', 'new@far.example', 'x@own.example'], with_file, exists) == \
        ('confirm', ['new@far.example'], 4)
    assert hold_wanted(wanted, 'anna@own.example', 'anna', '', ['bob@partner.example'], with_file, exists) == ('recall', 2)
    assert hold_wanted(wanted, 'anna@own.example', '', '192.0.2.5', ['new@far.example'], plain, exists) is None, 'recall needs a login'

    def down(key):
        raise OSError('down')
    assert unknown_recipients('anna@own.example', ['bob@partner.example'], {'own.example'}, down) == ['bob@partner.example'], 'fail closed'
    with tempfile.TemporaryDirectory() as folder:
        note = hold_note('4ABC123DEF', 'recall', 'anna@own.example', 'anna', ['bob@partner.example'], 'Offer', 99.0, folder)
        assert json.load(open(os.path.join(folder, '4ABC123DEF.json')))['until'] == 99.0 and note['kind'] == 'recall'
        try:
            hold_note('../x', 'recall', '', '', [], '', 0, folder)
            raise AssertionError('a bad queue id')
        except ValueError:
            pass
    # A1: a held account stays held until a release that came after the hold.
    with tempfile.TemporaryDirectory() as folder:
        held = HeldSenders(folder + '/held.json')
        assert held.hold('anna', 'over the limit recipients', now=100) and not held.hold('anna', 'again', now=101)
        assert held.is_held('anna', {}) and held.is_held('anna', {'anna': 50})
        assert HeldSenders(folder + '/held.json').is_held('anna', {}), 'kept over a restart'
        assert not held.is_held('anna', {'anna': 100}) and not held.is_held('anna', {})
    # 9j: limits per sender domain and per tenant over all their senders.
    watch, limits = RateWatch(), {'domain_recipients_hour': 3, 'tenant_recipients_hour': 6}
    assert watch.add('a', ['x@1', 'y@2'], limits, now=0, domain='own.example', tenant='3') is None
    assert watch.add('b', ['z@3', 'w@4'], limits, now=1, domain='own.example', tenant='3') == 'sender-domain'
    assert watch.add('c', ['v@5', 'u@6'], limits, now=2, domain='other.example', tenant='3') is None
    assert watch.add('d', ['t@7'], limits, now=3, domain='third.example', tenant='3') == 'tenant'
    assert watch.add('e', ['s@8'] * 10, {}, now=4, domain='own.example', tenant='3') is None
    # M2: private headers go for the chosen senders, never one a DKIM signature covers.
    headers = [('Received', 'from pc1 [10.0.0.5]'), ('Received', 'from exch [10.0.0.2]'), ('X-Mailer', 'Outlook 16'), ('Subject', 'x'),
               ('DKIM-Signature', 'v=1; a=rsa-sha256; d=own.example; h=From:Subject:X-Mailer; b=x'), ('User-Agent', 'Thunderbird')]
    assert private_deletions(headers) == [('Received', 2), ('Received', 1), ('User-Agent', 1)]
    assert private_deletions([('X-Originating-IP', '[10.1.1.1]')]) == [('X-Originating-IP', 1)]
    wanted = {'privacy': {'all': False, 'domains': ['own.example'], 'logins': ['app'], 'networks': ['10.9.0.0/16']}}
    assert privacy_wanted(wanted, 'a@own.example', '', '') and privacy_wanted(wanted, 'a@x.example', 'app', '') and privacy_wanted(wanted, 'a@x.example', '', '10.9.1.1')
    assert not privacy_wanted(wanted, 'a@x.example', 'other', '192.0.2.1') and privacy_wanted({'privacy': {'all': True}}, 'a@x', '', '')
    assert active({'privacy': {'all': True}}) and not active({'privacy': {'all': False, 'domains': []}})
    assert outgoing('10.0.0.5', False, ['10.0.0.0/8']) and outgoing('203.0.113.1', True, []) and not outgoing('203.0.113.1', False, ['10.0.0.0/8'])
    assert not outgoing('bad', False, ['10.0.0.0/8'])
    assert cards('Karte 4111 1111 1111 1111 bitte') == {'4111111111111111'} and cards('5500-0000-0000-0004') == {'5500000000000004'}
    assert cards('4111 1111 1111 1111 12 29') == {'4111111111111111'}
    assert not cards('Order 4111 1111 1111 1112') and not cards('Tel 0043 1 234 567 890 12') and not cards('4444444444444444')
    assert ibans('IBAN: DE89 3704 0044 0532 0130 00.') == {'DE89370400440532013000'} and ibans('at611904300234573201') == {'AT611904300234573201'}
    assert ibans('an DE89 3704 0044 0532 0130 00 bitte') == {'DE89370400440532013000'} and ibans('AT61 1904 3002 3457 3201 BANK') == {'AT611904300234573201'}
    assert not ibans('DE89 3704 0044 0532 0130 01') and not ibans('DE89370400440532013000', {'DE89370400440532013000'})
    dlp = {'cards': 'hold', 'iban': 'log', 'rules': [{'name': 'secret', 'pattern': r'\bstreng geheim\b', 'action': 'reject'}]}
    assert dlp_verdict('nothing here', dlp) == ('off', [], False)
    assert dlp_verdict('IBAN DE89370400440532013000', dlp) == ('log', ['iban'], False)
    assert dlp_verdict('4111111111111111 and DE89370400440532013000', dlp) == ('hold', ['cards', 'iban'], False)
    assert dlp_verdict('Das ist STRENG GEHEIM', dlp) == ('reject', ['secret'], False)
    assert dlp_verdict('4111111111111111', {'cards': 'off'}) == ('off', [], False)
    assert dlp_verdict('4111111111111111 DE89370400440532013000', {'cards': 'encrypt', 'iban': 'hold'}) == ('hold', ['cards', 'iban'], True)
    assert at_svnr('1237010180') and not at_svnr('1238010180') and de_tax_id('86095742719') and not de_tax_id('86095742718')
    assert at_tax_number('121234561') and not at_tax_number('121234567')  # 1+4+1+4+3+8+5+3 = 29, check digit 1
    assert de_svnr('15070649C103') and not de_svnr('15070649C104')
    assert national_ids('SV-Nummer: 1237 010180') == {'1237010180'} and national_ids('Steuer-ID 86095742719') == {'86095742719'}
    assert not national_ids('Rechnung 1237 010180') and national_ids('Versicherungsnummer 15 070649 C 103') == {'15070649C103'}
    assert active({'pdf': {'keyword': '[secure]'}}) and not active({'dlp': {'cards': 'off'}}) and active({'dlp': {'ids': 'log'}})
    assert active({'limits': {'action': 'throttle'}}) and not active({'limits': {'action': 'off'}}) and active({'bulk': {'enabled': True}})
    news = email.message.EmailMessage()
    news['Precedence'] = 'bulk'
    bulk = {'enabled': True, 'auto': True, 'senders': ['news.example'], 'ready': {'own.example': [], 'news.example': ['dmarc']}}
    assert bulk_wanted('a@own.example', news, bulk) and bulk_wanted('x@news.example', email.message.EmailMessage(), bulk)
    assert not bulk_wanted('a@own.example', email.message.EmailMessage(), bulk) and not bulk_wanted('a@own.example', news, {**bulk, 'enabled': False})
    assert not bulk_wanted('a@own.example', news, {**bulk, 'auto': False})
    assert bulk_missing('a@own.example', news, bulk) == ['one-click-unsubscribe']
    news['List-Unsubscribe'], news['List-Unsubscribe-Post'] = '<https://own.example/u/1>', 'List-Unsubscribe=One-Click'
    assert bulk_missing('a@own.example', news, bulk) == [] and bulk_missing('x@news.example', news, bulk) == ['dmarc']
    assert bulk_missing('x@other.example', news, bulk) == ['not-checked']
    assert keyword_in('Offer [SECURE]', '[secure]') and without_keyword('Offer [SECURE] now', '[secure]') == 'Offer now'
    assert password_for(['a@x.example', 'b@x.example'], {'x.example': 'pw1'}) == ('pw1', True)
    assert password_for(['a@x.example', 'b@y.example'], {'x.example': 'pw1'})[1] is False
    assert password_for(['a@x.example'], {'a@x.example': 'pw2', 'x.example': 'pw1'}) == ('pw2', True)
    assert notice_mark('<a@b>') == notice_mark('<a@b>') != notice_mark('<c@b>')
    folded = email.message_from_bytes(f'Message-ID:\r\n <a@b.example>\r\n{NOTICE_HEADER}:\n {notice_mark("<a@b.example>")}\r\n\r\nx\r\n'.encode(),
                                      policy=email.policy.default)
    assert is_notice(folded) and not is_notice(email.message_from_bytes(b'Message-ID: <a@b.example>\r\n' + NOTICE_HEADER.encode() + b': 00\r\n\r\nx'))
    watch, limits = RateWatch(), {'recipients_hour': 5, 'domains_hour': 2}
    assert watch.add('anna', ['a@x.example', 'b@x.example'], limits, 0) is None and watch.add('anna', ['c@y.example'], limits, 10) is None
    assert watch.add('anna', ['d@z.example'], limits, 20) == 'domains' and watch.add('bert', ['a@x.example'] * 6, limits, 20) == 'recipients'
    assert watch.add('anna', ['d@z.example'], limits, 3700) is None, 'a new hour'
    assert watch.first_time('bert') and not watch.first_time('bert') and not watch.first_time('nobody')
    # A1: with a store the counts survive a new RateWatch (a restart); a store that does not answer falls back to memory.
    fake = efa_redis.Memory()
    limits = {'recipients_hour': 5, 'domains_hour': 2}
    assert RateWatch(RedisCounts(fake)).add('anna', ['a@x.example', 'b@x.example', 'c@y.example'], limits, 7200) is None
    assert RateWatch(RedisCounts(fake)).add('anna', ['d@x.example'] * 3, limits, 7300) == 'recipients', 'counted over a restart'
    assert RateWatch(RedisCounts(fake)).add('anna', ['e@z.example'], limits, 7400) == 'recipients'
    assert RateWatch(RedisCounts(fake)).add('anna', ['e@z.example'], limits, 10900) is None, 'a new hour'
    assert RateWatch(RedisCounts(fake)).add('bert', ['a@x.example', 'b@y.example', 'c@z.example'], limits, 7200) == 'domains'
    assert RedisCounts(fake).once('who:bert:2') and not RedisCounts(fake).once('who:bert:2')

    # 8g: what efa-cluster wrote for the other nodes counts too, and a domain reached from both nodes once.
    fake = efa_redis.Memory()
    fake([('SET', 'efa:rate:who:carl:3:pr', 3), ('SADD', 'efa:rate:who:carl:3:pd', 'x.example', 'q.example')])
    assert RateWatch(RedisCounts(fake)).add('carl', ['a@x.example'], limits, 3 * 3600 + 5) is None, 'x.example from both nodes: 2 domains'
    assert RateWatch(RedisCounts(fake)).add('carl', ['a@r.example'], limits, 3 * 3600 + 6) == 'domains'
    assert fake([('HGETALL', 'efa:rate:own:3'), ('GET', 'efa:rate:who:carl:3:r')]) == [['who:carl', '2'], '2'], 'own count stays own'
    assert RateWatch(RedisCounts(fake)).add('dora', ['a@x.example'], {'recipients_hour': 5}, 3 * 3600 + 5) is None
    fake([('SET', 'efa:rate:who:dora:3:pr', 5)])
    assert RateWatch(RedisCounts(fake)).add('dora', ['b@x.example'], {'recipients_hour': 6}, 3 * 3600 + 6) == 'recipients', '1 + 1 + 5 others'

    def down(_commands):
        raise OSError('connection refused')
    gone = RateWatch(RedisCounts(down))
    assert gone.add('anna', ['a@x.example'] * 6, limits, 0) == 'recipients', 'Redis down: counted in memory'
    assert gone.first_time('anna') and not gone.first_time('anna')
    assert 'too many target domains' in limit_text('anna', 'domains', 'hold')
    message = email.message.EmailMessage()
    message['From'], message['To'], message['Subject'] = 'anna@own.example', 'b@y.example', 'offer'
    message.set_content('Hello.')
    message.add_alternative('<html><body><p>Hello.</p></body></html>', subtype='html')
    message.add_attachment(b'data', maintype='application', subtype='pdf', filename='a.pdf')
    message.add_attachment('card 4111111111111111', subtype='plain', filename='list.txt')
    assert '4111111111111111' in mail_text(email.message_from_bytes(message.as_bytes(), policy=email.policy.default))
    text = 'Own Ltd, Vienna. This mail is confidential.'
    changed = email.message_from_bytes(add_disclaimer(email.message_from_bytes(message.as_bytes(), policy=email.policy.default), text, ''),
                                       policy=email.policy.default)
    assert changed.get_body(('plain',)).get_content().replace('\r\n', '\n').endswith('-- \nOwn Ltd, Vienna. This mail is confidential.\n')
    page = changed.get_body(('html',)).get_content()
    assert '<div class="efa-disclaimer"' in page and page.index('efa-disclaimer') < page.lower().index('</body>')
    assert [part.get_filename() for part in changed.iter_attachments()] == ['a.pdf', 'list.txt']
    assert 'Own Ltd' not in [part for part in changed.iter_attachments()][1].get_content()
    assert all(part['MIME-Version'] is None for part in changed.walk() if part.get_content_maintype() == 'text' and part.get_filename() is None)
    assert add_disclaimer(changed, text, '') is None, 'not twice'
    signed = email.message.EmailMessage()
    signed['Content-Type'] = 'multipart/signed; protocol="application/pkcs7-signature"; boundary="b"'
    assert add_disclaimer(signed, text, '') is None
    assert '&lt;b&gt;' in efa_disclaimer.html_text('<b>') and '<br>' in efa_disclaimer.html_text('a\nb')
    # 8k: group before domain before tenant before all; the old per-domain one as a domain template; pictures from the folder.
    wanted = {'domains': {'old.example': {'text': 'Old style'}}, 'tenant_of': {'own.example': 'acme'}, 'sender_groups': {'anna@own.example': ['sales']},
              'disclaimers': [{'id': 'all', 'scope': 'global', 'format': 'text', 'text': 'For all'},
                              {'id': 'acme', 'scope': 'tenant', 'target': 'acme', 'format': 'text', 'text': 'Acme'},
                              {'id': 'sales', 'scope': 'group', 'target': 'own.example', 'groups': ['sales'], 'format': 'html',
                               'html': '<p>Sales <img src="cid:logo"></p>', 'media': [{'cid': 'logo', 'file': 'logo.png', 'type': 'image/png'}]}]}
    assert [disclaimer_for(wanted, who)['id'] for who in ('Anna@own.example', 'bob@own.example', 'x@old.example', 'x@other.example')] == \
        ['sales', 'acme', 'domain-old.example', 'all']
    import tempfile
    global DISCLAIMER_DIR
    with tempfile.TemporaryDirectory() as folder:
        DISCLAIMER_DIR = folder
        os.makedirs(os.path.join(folder, 'sales'))
        with open(os.path.join(folder, 'sales', 'logo.png'), 'wb') as f:
            f.write(b'\x89PNG\r\n\x1a\nPIC')
        out = email.message_from_bytes(with_disclaimer(email.message_from_bytes(message.as_bytes(), policy=email.policy.default),
                                                       disclaimer_for(wanted, 'anna@own.example')), policy=email.policy.default)
        assert next(p for p in out.walk() if p.get_content_type() == 'image/png')['Content-ID'] == '<logo>'
        assert 'Sales' in out.get_body(('plain',)).get_content()
        os.remove(os.path.join(folder, 'sales', 'logo.png'))
        assert with_disclaimer(email.message_from_bytes(message.as_bytes(), policy=email.policy.default), disclaimer_for(wanted, 'anna@own.example')) is None, \
            'a missing picture: the mail goes on as it is'
    html_only = email.message.EmailMessage()
    html_only.set_content('<p>Hallo &amp; Gruß</p><script>x()</script>', subtype='html')
    assert body_text(html_only).strip() == 'Hallo & Gruß'
    if efa_pdf.available():
        sealed = encrypted_mail(email.message_from_bytes(message.as_bytes(), policy=email.policy.default), 'pw', True, '')
        assert [part.get_filename() for part in sealed.iter_attachments()] == ['message.pdf'] and 'vereinbarten' in sealed.get_body().get_content()
        assert b'/AESV3' in next(sealed.iter_attachments()).get_payload(decode=True) and sealed['Subject'] == 'offer'
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
    else:
        syslog.openlog('efa-outbound', 0, syslog.LOG_MAIL)
        run_milter()
