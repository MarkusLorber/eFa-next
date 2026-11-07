#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""eFa outbound: a milter on 127.0.0.1:8908 before rspamd for outgoing mail, from logged in users and from the relay networks.
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
import sys
import syslog
import threading
import time

# The copy next to this program first (a checkout in CI), then the installed one: insert(0) puts the last one in front.
for _folder in ('/usr/lib/eFa/python', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'lib', 'eFa', 'python')):
    if os.path.isdir(_folder) and _folder not in sys.path:
        sys.path.insert(0, _folder)
import efa_disclaimer  # noqa: E402
import efa_mime  # noqa: E402
import efa_pdf  # noqa: E402

PORT = 8908
DISCLAIMER_DIR = os.environ.get('EFA_DISCLAIMER_DIR', '/etc/eFa/disclaimers')
SETTINGS = os.environ.get('EFA_OUTBOUND_SETTINGS', '/etc/eFa/outbound.json')
MAX_MAIL = 30 * 1024 * 1024
# shortcut: DLP reads the first 2 MB of text of a mail; raise it if leaks hide behind long texts.
MAX_TEXT = 2 * 1024 * 1024
ACTIONS = ('off', 'log', 'encrypt', 'hold', 'reject')
PASSWORDS = os.path.join(os.environ.get('CREDENTIALS_DIRECTORY', '/nonexistent'), 'pdf-passwords')
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
        wanted.get('limits', {}).get('action', 'off') != 'off' or bool(wanted.get('bulk', {}).get('enabled'))


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


class RateWatch:
    """Recipients and target domains per sender (login or address of the client) in the running hour."""
    # shortcut: counts live in memory and start again with each hour and each restart; keep them in redis for several nodes (9).

    def __init__(self):
        self.lock, self.windows = threading.Lock(), {}

    def add(self, who, recipients, limits, now=None):
        """Counts the mail, and names the limit it goes over: 'recipients', 'domains' or None."""
        now = time.time() if now is None else now
        with self.lock:
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
        with self.lock:
            window = self.windows.get(who)
            if window is None or window['told']:
                return False
            window['told'] = True
            return True


def notice_mark(message_id):
    return hmac.new(NOTICE_KEY, message_id.encode(), hashlib.sha256).hexdigest()


def is_notice(message):
    # Postfix hands folded headers over with their line breaks.
    mark = ''.join(str(message.get(NOTICE_HEADER, '')).split())
    return bool(mark) and hmac.compare_digest(mark, notice_mark(''.join(str(message.get('Message-ID', '')).split())))


def send_mail(to, subject, text):
    """A notice of eFa, with the null sender and a mark that lets it pass this milter."""
    notice = email.message.EmailMessage()
    host = socket.getfqdn()
    notice['From'], notice['To'], notice['Subject'] = f'eFa <postmaster@{host}>', to, subject
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
            self.headers, self.chunks, self.too_big, self.rcpts = [], [], False, []
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
                self.skip = not (foreign or outgoing(self.ip, bool(self.login), wanted.get('networks', [])))
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
                over = self.watch.add(who, self.rcpts, limits) if limits.get('action', 'off') != 'off' and not is_bulk else None
                if over:
                    syslog.syslog(syslog.LOG_WARNING, f'efa-outbound limit {limits["action"]} {over} who={who} from={self.sender} id={queue_id}')
                    if self.watch.first_time(who):
                        text = limit_text(who, over, limits['action'])
                        for to in {wanted.get('admin'), self.sender if self.login else None} - {None, ''}:
                            try:
                                send_mail(to, 'eFa: Versandgrenze / sending limit', text)
                            except (OSError, smtplib.SMTPException) as err:  # the limit holds without the notice
                                syslog.syslog(syslog.LOG_ERR, f'efa-outbound notice to {to} failed: {err}')
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
                changed = with_disclaimer(message, template) if template else None
                if changed is None and encrypt:
                    changed = efa_mime.to_bytes(message)
                if changed is not None:
                    efa_mime.hand_back(self, self.headers, changed)
                if action == 'hold':
                    self.quarantine(f'data loss prevention: {", ".join(names)}')
            except Exception as err:
                if encrypt or strict(settings()):
                    # Never out unchecked or in clear text: the sending server tries again later.
                    syslog.syslog(syslog.LOG_ERR, f'efa-outbound could not check or encrypt {queue_id}: {err}')
                    self.setreply('451', '4.7.1', 'The mail could not be checked at the moment, try again later')
                    return Milter.TEMPFAIL
                # mail flow first: a mail it cannot handle goes on unchanged
                syslog.syslog(syslog.LOG_ERR, f'efa-outbound left unchanged {queue_id}: {err}')
            return Milter.ACCEPT

    watch = RateWatch()
    Outbound.watch = watch
    Milter.factory = Outbound
    Milter.set_flags(Milter.ADDHDRS | Milter.CHGHDRS | Milter.CHGBODY | Milter.QUARANTINE)
    Milter.runmilter('efa-outbound', f'inet:{PORT}@127.0.0.1', timeout=120)
    # A connection that comes in while Python shuts down crashes pymilter: end without the shutdown.
    os._exit(0)


def self_test():
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
