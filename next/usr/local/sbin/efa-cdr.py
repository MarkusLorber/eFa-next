#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""eFa-next content milter on 127.0.0.1:8907 after rspamd: content disarm and link rewriting, each switched on its own.
Content disarm: Office files lose their macros, PDF files their active content
(JavaScript, open and launch actions, embedded files), Office files with macros it cannot clean are replaced by a note.
The original mail is kept for the admin, who can still deliver it. Mail it cannot read passes unchanged: mail flow first."""
import base64
import email
import email.policy
import email.utils
import io
import json
import os
import re
import secrets
import subprocess
import sys
import syslog
import tempfile
import time
import zipfile
import zlib

# Installed, or next to this file in the source tree.
# The copy next to this program first (a checkout in CI), then the installed one: insert(0) puts the last one in front.
for _folder in ('/usr/lib/eFa/python', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'lib', 'eFa', 'python')):
    if os.path.isdir(_folder) and _folder not in sys.path:
        sys.path.insert(0, _folder)
from efa_links import link_target, link_token  # noqa: E402
import efa_bimi  # noqa: E402
import efa_host  # noqa: E402
from efa_mime import BROKEN, Unwritable, hand_back, mime_header_changes, to_bytes  # noqa: E402

PORT = 8907
# Written by efactl cdr-set and links-set, readable by this service only (root:efa-web 0640): it holds the key of the links.
SETTINGS = os.environ.get('EFA_CONTENT_SETTINGS', '/etc/efa-web/content.json')
LINK_RE = re.compile(r'https?://[^\s<>"\'\)\]]+', re.I)
HREF_RE = re.compile(r'''(href\s*=\s*)(["'])(https?://[^"']+)\2''', re.I)
MAX_URL = 2000
STORE = os.environ.get('EFA_CDR_STORE', '/var/lib/efa-cdr')
MAX_MAIL = 30 * 1024 * 1024
HEADER = 'X-eFa-CDR'
# Macro-enabled OOXML: the parts and content types to drop or turn into those of the plain format.
VBA_PARTS = re.compile(r'(^|/)(vbaProject\.bin|vbaData\.xml|_rels/vbaProject\.bin\.rels)$', re.I)
MACRO_TYPES = {
    'application/vnd.ms-word.document.macroEnabled.main+xml': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml',
    'application/vnd.ms-word.template.macroEnabledTemplate.main+xml': 'application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml',
    'application/vnd.ms-excel.sheet.macroEnabled.main+xml': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml',
    'application/vnd.ms-excel.template.macroEnabled.main+xml': 'application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml',
    'application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml': 'application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml',
}
RENAMED = {'docm': 'docx', 'dotm': 'dotx', 'xlsm': 'xlsx', 'xltm': 'xltx', 'pptm': 'pptx', 'potm': 'potx', 'ppsm': 'ppsx'}
OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
OLE_VBA = '_VBA_PROJECT'.encode('utf-16-le')
# The names of active PDF content; renamed to a name of the same length, so no offset in the file moves.
PDF_ACTIVE = re.compile(rb'/(JavaScript|JS|OpenAction|AA|Launch|EmbeddedFiles|EmbeddedFile|RichMedia|XFA|SubmitForm|ImportData)(?=[\s/<>\[\]()])')


class Uncleanable(ValueError):
    """An attachment with active content that cannot be cleaned: it is replaced, never let through."""


def clean_ooxml(data):
    """An OOXML file without its macro parts and with the content types of the plain format. None if it had no macros.
    Raises Uncleanable for a broken file with macro parts (found by scripts/fuzz.py)."""
    try:
        source = zipfile.ZipFile(io.BytesIO(data))
        names = source.namelist()
    # No zip Office could open either (found by scripts/fuzz.py).
    except (zipfile.BadZipFile, ValueError, NotImplementedError, RuntimeError, EOFError, OSError, zlib.error):
        return None
    if not any(VBA_PARTS.search(name) for name in names):
        return None
    try:
        return _clean_ooxml(source)
    except (zipfile.BadZipFile, zlib.error, EOFError, OSError, NotImplementedError, RuntimeError, ValueError) as err:
        raise Uncleanable(f'broken Office file with macros: {err}')


def _clean_ooxml(source):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as target:
        for info in source.infolist():
            if VBA_PARTS.search(info.filename):
                continue
            content = source.read(info.filename)
            if info.filename == '[Content_Types].xml':
                text = content.decode('utf-8', 'replace')
                for old, new in MACRO_TYPES.items():
                    text = text.replace(old, new)
                text = re.sub(r'<Default[^>]*vnd\.ms-office\.vbaProject[^>]*/>', '', text)
                text = re.sub(r'<Override[^>]*vbaProject[^>]*/>', '', text)
                content = text.encode('utf-8')
            elif info.filename.endswith('.rels'):
                content = re.sub(rb'<Relationship[^>]*vbaProject[^>]*/>', b'', content)
            target.writestr(info, content)
    return out.getvalue()


def ole_macros(data):
    return data[:8] == OLE_MAGIC and OLE_VBA in data


def pdf_active(data):
    return data[:5] == b'%PDF-' and bool(PDF_ACTIVE.search(data))


def clean_pdf(data, qpdf='qpdf'):
    """A PDF without active content: qpdf opens all object streams, the names are renamed, qpdf writes a clean file again.
    None if it had none, raises OSError if qpdf fails."""
    if data[:5] != b'%PDF-':
        return None
    with tempfile.TemporaryDirectory() as folder:
        source, open_copy, result = (os.path.join(folder, name) for name in ('in.pdf', 'open.pdf', 'out.pdf'))
        with open(source, 'wb') as f:
            f.write(data)
        done = subprocess.run([qpdf, '--qdf', '--object-streams=disable', '--stream-data=uncompress', source, open_copy], capture_output=True, timeout=60)
        # qpdf exits 3 for warnings, the file is written anyway.
        if done.returncode not in (0, 3):
            raise OSError(done.stderr.decode('utf-8', 'replace')[-200:])
        with open(open_copy, 'rb') as f:
            opened = f.read()
        if not PDF_ACTIVE.search(opened):
            return None
        with open(open_copy, 'wb') as f:
            f.write(PDF_ACTIVE.sub(lambda match: b'/' + match.group(1)[:-1] + b'_', opened))
        done = subprocess.run([qpdf, '--object-streams=generate', '--compress-streams=y', open_copy, result], capture_output=True, timeout=60)
        if done.returncode not in (0, 3):
            raise OSError(done.stderr.decode('utf-8', 'replace')[-200:])
        with open(result, 'rb') as f:
            return f.read()


def _replace(part, *args, **kwargs):
    """The cleaned content in place of the part. Raises Unwritable if the part takes none: never the original instead."""
    try:
        part.set_content(*args, **kwargs)
    except BROKEN as err:
        raise Unwritable(f'the attachment cannot be replaced: {err}')


def disarm(raw, qpdf='qpdf'):
    """The mail with clean attachments and what was done, or (None, []) if nothing had to change. Raises Unwritable for a mail
    the email library cannot read: its attachments cannot be checked, so the milter rejects it rather than let it pass."""
    try:
        message = email.message_from_bytes(raw, policy=email.policy.default)
        parts = list(message.walk())
    except BROKEN as err:
        raise Unwritable(f'the mail cannot be read: {err}')
    done = []
    for part in parts:
        if part.is_multipart() or part.get_content_disposition() not in ('attachment', 'inline') and not part.get_filename():
            continue
        if part.get_content_maintype() == 'multipart':
            # A multipart without its parts (broken boundary) still holds the data: it cannot be checked (found by scripts/fuzz.py).
            raise Unwritable('an attachment in a multipart part without parts')
        name = part.get_filename() or 'attachment'
        data = part.get_payload(decode=True) or b''
        ending = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
        cleaned, note = None, None
        try:
            if data[:2] == b'PK':
                cleaned = clean_ooxml(data)
            elif data[:5] == b'%PDF-' and (pdf_active(data) or b'/ObjStm' in data):
                cleaned = clean_pdf(data, qpdf)
        except (Uncleanable, OSError) as err:
            note = f'{name} replaced: active content that cannot be cleaned ({str(err)[:80]})'
            _replace(part, f'eFa-next removed the attachment {name}: it had active content that could not be cleaned. Ask your admin for the original.\n',
                     disposition='attachment', filename=name + '.removed.txt')
            done.append(note)
            continue
        if data[:2] == b'PK':
            if cleaned is not None:
                note = f'macros removed from {name}'
                if ending in RENAMED:
                    name = name[:-len(ending)] + RENAMED[ending]
        elif ole_macros(data):
            note = f'{name} replaced: an Office file with macros that cannot be cleaned'
            _replace(part, f'eFa-next removed the attachment {name}: it contained macros. Ask your admin for the original.\n',
                     disposition='attachment', filename=name + '.removed.txt')
            done.append(note)
            continue
        elif data[:5] == b'%PDF-' and (pdf_active(data) or b'/ObjStm' in data):
            if cleaned is not None:
                note = f'active content removed from {name}'
        if cleaned is not None:
            kind = part.get_content_type()
            if ending in RENAMED:
                kind = 'application/vnd.openxmlformats-officedocument.' + {'doc': 'wordprocessingml.document', 'dot': 'wordprocessingml.template',
                                                                         'xls': 'spreadsheetml.sheet', 'xlt': 'spreadsheetml.template',
                                                                         'ppt': 'presentationml.presentation', 'pot': 'presentationml.template',
                                                                         'pps': 'presentationml.slideshow'}[RENAMED[ending][:3]]
            main, sub = kind.split('/', 1)
            _replace(part, cleaned, maintype=main, subtype=sub, disposition='attachment', filename=name)
            done.append(note)
    if not done:
        return None, []
    return to_bytes(message), done


# 5v (e): active content in HTML mail: scripts, frames, plugins, forms, event handlers, script links and redirects. A mail client
# should not run them; this takes them out for the domains that ask for it, after rspamd checked DKIM and ARC of the original.
ACTIVE_BLOCKS = re.compile(r'<(script|iframe|object|embed|applet|frameset)\b.*?</\1\s*>', re.I | re.S)
ACTIVE_TAGS = re.compile(r'<\s*/?\s*(script|iframe|object|embed|applet|frame|frameset|base|form|input|button|select|textarea)\b[^>]*>', re.I)
EVENT_ATTRS = re.compile(r"""\s+on[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)""", re.I)
SCRIPT_LINKS = re.compile(r"""((?:href|src|action|formaction|xlink:href)\s*=\s*)(["']?)\s*(?:javascript|vbscript|data\s*:\s*text/html)[^"'\s>]*\2""", re.I)
META_REFRESH = re.compile(r"""<meta\b[^>]*http-equiv\s*=\s*["']?refresh[^>]*>""", re.I)


def html_disarmed(text):
    """HTML without active content, and whether something was taken out."""
    new = ACTIVE_BLOCKS.sub('', text)
    new = ACTIVE_TAGS.sub('', new)
    new = EVENT_ATTRS.sub('', new)
    new = SCRIPT_LINKS.sub(lambda m: m.group(1) + '"#"', new)
    new = META_REFRESH.sub('', new)
    return new, new != text


def disarm_html(raw):
    """The mail with its HTML parts disarmed, or None if there was nothing; signed or encrypted mail stays as it is."""
    message = email.message_from_bytes(raw, policy=email.policy.default)
    if message.get_content_type() in ('multipart/signed', 'multipart/encrypted', 'application/pkcs7-mime'):
        return None
    changed = False
    for part in message.walk():
        if part.get_content_type() != 'text/html' or part.get_content_disposition() == 'attachment':
            continue
        try:
            text = part.get_content()
        except (LookupError, ValueError):
            continue
        new, done = html_disarmed(text)
        if done:
            part.set_content(new, subtype='html', charset='utf-8')
            changed = True
    if not changed:
        return None
    message['X-eFa-HTML-Disarmed'] = 'scripts, forms and event handlers removed'
    return to_bytes(message)


def _host(url):
    found = re.match(r'https?://([^/?#:]+)', url, re.I)
    return found.group(1).lower() if found else ''


# M1: tracking protection of incoming mail. Tracking pixels (pictures of 1x1 or from known tracking hosts) go, and so do the
# tracking parameters of links (utm_*, fbclid, gclid, mc_eid ...). The lists are local; nothing is asked outside.
TRACK_PARAM = re.compile(r'^(utm_[a-z_]+|fbclid|gclid|gclsrc|dclid|gbraid|wbraid|msclkid|mc_eid|mc_cid|_hsenc|_hsmi|__hssc|__hstc|mkt_tok|yclid|'
                         r'igshid|oly_anon_id|oly_enc_id|vero_id|vero_conv|wickedid|_kx|ss_source|s_cid|trk_[a-z]+|ml_subscriber|ml_subscriber_hash)$', re.I)
TRACK_HOSTS = ('mailtrack.io', 'mixmax.com', 'yesware.com', 'bananatag.com', 'getnotify.com', 'streak.com', 'mailtag.io', 'superhuman.com',
               'track.hubspot.com', 'pixel.mailchimp.com', 'open.convertkit-mail.com', 'mandrillapp.com', 'sendgrid.net', 'mailjet.com',
               'emltrk.com', 'cmail19.com', 'cmail20.com', 'createsend1.com', 'list-manage.com', 'exacttarget.com', 'returnpath.net')
IMG_RE = re.compile(r'<img\b[^>]*>', re.I | re.S)
SRC_RE = re.compile(r'''\bsrc\s*=\s*["']?([^"'\s>]+)''', re.I)
TINY_RE = re.compile(r'''\b(?:width|height)\s*=\s*["']?[01](?:px)?["'\s/>]|(?:width|height)\s*:\s*[01]px''', re.I)


def untracked_url(url):
    """The link without its tracking parameters, and how many went."""
    head, sep, query = url.partition('?')
    if not sep:
        return url, 0
    query, hash_sep, fragment = query.partition('#')
    pairs = [pair for pair in query.split('&') if pair]
    kept = [pair for pair in pairs if not TRACK_PARAM.match(pair.split('=', 1)[0])]
    if len(kept) == len(pairs):
        return url, 0
    return head + ('?' + '&'.join(kept) if kept else '') + (hash_sep + fragment), len(pairs) - len(kept)


def is_pixel(tag, hosts):
    src = SRC_RE.search(tag)
    host = _host(src.group(1)) if src else ''
    return len(TINY_RE.findall(tag)) >= 2 or any(host == item or host.endswith('.' + item) for item in hosts)


def strip_tracking(raw, hosts=TRACK_HOSTS):
    """The mail without tracking pixels and tracking parameters: (mail, pixels, parameters), or (None, 0, 0) if there were none.
    Signed or encrypted mail stays as it is."""
    message = email.message_from_bytes(raw, policy=email.policy.default)
    if message.get_content_type() in ('multipart/signed', 'multipart/encrypted', 'application/pkcs7-mime'):
        return None, 0, 0
    pixels = params = 0

    def link(url):
        nonlocal params
        new, count = untracked_url(url)
        params += count
        return new
    for part in message.walk():
        kind = part.get_content_type()
        if part.is_multipart() or part.get_content_disposition() == 'attachment' or kind not in ('text/plain', 'text/html'):
            continue
        try:
            text = part.get_content()
        except (LookupError, ValueError):
            continue
        new = text
        if kind == 'text/html':
            before = len(IMG_RE.findall(new))
            new = IMG_RE.sub(lambda m: '' if is_pixel(m.group(0), hosts) else m.group(0), new)
            pixels += before - len(IMG_RE.findall(new))
            new = HREF_RE.sub(lambda m: m.group(1) + m.group(2) + link(m.group(3).replace('&amp;', '&')).replace('&', '&amp;') + m.group(2), new)
        else:
            new = LINK_RE.sub(lambda m: link(m.group(0)), new)
        if new != text:
            part.set_content(new, subtype=kind.split('/')[1], charset='utf-8')
    if not pixels and not params:
        return None, 0, 0
    return to_bytes(message), pixels, params


def rewrite_links(raw, base, key, exceptions, tenant=''):
    """Each http and https link in the text and HTML parts goes over the check of this server. Signed or encrypted parts stay as
    they are, and so do links to the exceptions and to this server itself. Returns the mail and the number of links, or (None, 0)."""
    message = email.message_from_bytes(raw, policy=email.policy.default)
    if message.get_content_type() in ('multipart/signed', 'multipart/encrypted', 'application/pkcs7-mime'):
        return None, 0
    own = _host(base)
    count = 0

    def keep(url):
        host = _host(url)
        return len(url) > MAX_URL or host == own or any(host == item or host.endswith('.' + item) for item in exceptions)

    def wrapped(url):
        nonlocal count
        if keep(url):
            return url
        count += 1
        return f'{base}/l/{link_token(url, key, tenant)}'
    for part in message.walk():
        kind = part.get_content_type()
        if part.is_multipart() or part.get_content_disposition() == 'attachment' or kind not in ('text/plain', 'text/html'):
            continue
        try:
            text = part.get_content()
        except (LookupError, ValueError):
            continue
        if kind == 'text/html':
            new = HREF_RE.sub(lambda m: m.group(1) + m.group(2) + wrapped(m.group(3).replace('&amp;', '&')).replace('&', '&amp;') + m.group(2), text)
        else:
            new = LINK_RE.sub(lambda m: wrapped(m.group(0)), text)
        if new != text:
            part.set_content(new, subtype=kind.split('/')[1], charset='utf-8')
    if not count:
        return None, 0
    return to_bytes(message), count


BANNER_TEXT = ('Caution: this mail comes from outside your organization. Do not open links or attachments unless you know the sender.')
DKIM_PASS = re.compile(r'\bdkim=pass\b', re.I)


def add_banner(raw, text, unsigned_only, exceptions, auth_results):
    """A warning at the top of the text and HTML parts of incoming mail. Mail with a valid DKIM signature is left alone unless
    unsigned_only is off, and so are signed or encrypted mails and senders of the exceptions. Returns the mail, or None."""
    message = email.message_from_bytes(raw, policy=email.policy.default)
    if message.get_content_type() in ('multipart/signed', 'multipart/encrypted', 'application/pkcs7-mime'):
        return None
    if unsigned_only and any(DKIM_PASS.search(value) for value in auth_results):
        return None
    sender = str(message.get('From', '')).lower()
    if any(sender.rstrip('>').endswith('@' + domain) or sender.rstrip('>').endswith('.' + domain) for domain in exceptions):
        return None
    changed = False
    for part in message.walk():
        kind = part.get_content_type()
        if part.is_multipart() or part.get_content_disposition() == 'attachment' or kind not in ('text/plain', 'text/html'):
            continue
        try:
            body = part.get_content()
        except (LookupError, ValueError):
            continue
        if kind == 'text/plain':
            body = f'[{text}]\n\n' + body
        else:
            note = ('<div style="border:1px solid #c0a000;background:#fff8d6;color:#3f444a;padding:8px 12px;margin:0 0 12px;'
                    f'font:13px sans-serif">{html_escape(text)}</div>')
            found = re.search(r'<body[^>]*>', body, re.I)
            body = body[:found.end()] + note + body[found.end():] if found else note + body
        part.set_content(body, subtype=kind.split('/')[1], charset='utf-8')
        changed = True
    return to_bytes(message) if changed else None


# 6/8h: the journal of the archive handover. A report around each mail with its envelope (sender, all recipients with the BCC
# ones, time, queue id) and the mail itself as message/rfc822, sent after the verdict of rspamd and before a quarantine hold,
# through the port of Postfix without filters, so the journal never waits for a release and is never filtered itself.
JOURNAL_PORT = 10031


def journal_report(raw, sender, rcpts, queue_id, to, host, now=None):
    report = email.message.EmailMessage()
    stamp = email.utils.formatdate(now, localtime=True)
    report['From'], report['To'] = f'eFa-next journal <postmaster@{host}>', to
    subject = ' '.join(str(email.message_from_bytes(raw.split(b'\r\n\r\n', 1)[0] + b'\r\n\r\n', policy=email.policy.default).get('Subject', '')).split())
    report['Subject'] = f'Journal: {subject[:200]}'
    report['Date'], report['Message-ID'] = stamp, email.utils.make_msgid(domain=host)
    report['X-eFa-Journal-Sender'] = sender or '<>'
    report['X-eFa-Journal-Recipients'] = ', '.join(rcpts)
    report['X-eFa-Journal-Queue-ID'] = queue_id
    report.set_content(f'Sender: {sender or "<>"}\nRecipients: {", ".join(rcpts)}\nReceived: {stamp}\nQueue-ID: {queue_id}\n')
    # As an embedded message (RFC 2046: never base64); parsed with compat32, so its headers are written back as they came.
    report.add_attachment(email.message_from_bytes(raw, policy=email.policy.compat32))
    return report


def journal_targets(journal, sender, rcpts):
    """The journal addresses a mail goes to: by the domains of its recipients (in) and of its sender (out)."""
    found = {journal.get('in', {}).get(rcpt.rpartition('@')[2].lower()) for rcpt in rcpts}
    found.add(journal.get('out', {}).get(sender.rpartition('@')[2].lower()))
    return sorted(found - {None, ''})


def journal_send(report, to):
    import smtplib
    with smtplib.SMTP('127.0.0.1', JOURNAL_PORT, timeout=30) as server:
        server.send_message(report, from_addr='', to_addrs=[to])


def html_escape(text):
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


def settings(path=SETTINGS, cache={}):
    """The switches and the link key, read again only when the file changed."""
    try:
        stamp = os.stat(path).st_mtime_ns
    except OSError:
        return {}
    if cache.get('stamp') != stamp:
        with open(path) as f:
            cache.update(stamp=stamp, value=json.load(f))
    return cache['value']


def store_original(raw, sender, rcpts, done, folder=STORE):
    """The original, for the admin: efactl cdr-list shows it, cdr-release delivers it unchanged."""
    os.makedirs(folder, mode=0o700, exist_ok=True)
    key = time.strftime('%Y%m%d%H%M%S-') + secrets.token_hex(6)
    fd = os.open(os.path.join(folder, key + '.eml'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw)
    fd = os.open(os.path.join(folder, key + '.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump({'sender': sender, 'rcpts': rcpts, 'done': done, 'ts': time.strftime('%Y-%m-%d %H:%M:%S')}, f)
    return key


def run_milter():
    import Milter

    class Disarm(Milter.Base):
        def __init__(self):
            self.chunks, self.headers, self.sender, self.rcpts, self.skip, self.too_big = [], [], '', [], False, False

        def envfrom(self, sender, *args):
            self.chunks, self.headers, self.rcpts, self.too_big = [], [], [], False
            self.sender = sender.strip('<>')
            # Own users and internal servers send out: nothing to disarm. The journal (6/8h) still needs their mail.
            self.skip = bool(self.getsymval('{auth_authen}'))
            self.collect = not self.skip or bool(settings().get('journal'))
            return Milter.CONTINUE

        def envrcpt(self, rcpt, *args):
            self.rcpts.append(rcpt.strip('<>'))
            return Milter.CONTINUE

        def header(self, name, value):
            self.headers.append((name, value))
            return Milter.CONTINUE

        def body(self, chunk):
            if self.collect and not self.too_big:
                self.chunks.append(chunk)
                if sum(len(item) for item in self.chunks) > MAX_MAIL:
                    self.skip, self.too_big, self.chunks = True, True, []
            return Milter.CONTINUE

        def eom(self):
            raw = b''.join(f'{name}: {value}\r\n'.encode('utf-8', 'surrogateescape') for name, value in self.headers) + b'\r\n' + b''.join(self.chunks)
            journal = settings().get('journal') or {}
            targets = journal_targets(journal, self.sender, self.rcpts) if journal else []
            if targets:
                queue_id = self.getsymval('i') or '-'
                original = raw if not self.too_big else raw + b'[larger than the limit of the content milter: the body is not in this journal report]\r\n'
                try:
                    for to in targets:
                        journal_send(journal_report(original, self.sender, self.rcpts, queue_id, to, efa_host.own_hostname()), to)
                except (OSError, *BROKEN) as err:
                    # Fail closed: a mail without its journal report does not go on; the sending server tries again.
                    syslog.syslog(syslog.LOG_ERR, f'journal report of {queue_id} not sent: {err}')
                    self.setreply('451', '4.7.1', 'The mail could not be archived at the moment, try again later')
                    return Milter.TEMPFAIL
            if self.skip:
                return Milter.ACCEPT
            try:
                wanted = settings()
                clean, done, key = None, [], None
                if wanted.get('cdr'):
                    try:
                        clean, done = disarm(raw)
                    except Exception:  # with content disarm on, a mail it cannot check never passes as it is
                        # Unreadable, or active content found and the clean mail cannot be written: never the original instead.
                        syslog.syslog(syslog.LOG_ERR, f'rejected for {",".join(self.rcpts)}: the mail cannot be read or the disarmed one written')
                        self.setreply('550', '5.7.1', 'The attachments of this mail could not be checked or cleaned')
                        return Milter.REJECT
                    if clean is not None:
                        key = store_original(raw, self.sender, self.rcpts, done)
                html = wanted.get('html_disarm') or {}
                if html.get('all') or any(rcpt.rpartition('@')[2].lower() in html.get('domains', []) for rcpt in self.rcpts):
                    disarmed = disarm_html(clean or raw)
                    if disarmed is not None:
                        clean = disarmed
                        done.append('active HTML removed')
                tracking = wanted.get('tracking') or {}
                sender_domain = self.sender.rpartition('@')[2].lower()
                if (tracking.get('all') or any(rcpt.rpartition('@')[2].lower() in tracking.get('domains', []) for rcpt in self.rcpts)) and \
                        self.sender.lower() not in tracking.get('exceptions', []) and sender_domain not in tracking.get('exceptions', []):
                    # M1: before the link check, so the wrapped links carry no tracking parameters either.
                    untracked, pixels, params = strip_tracking(clean or raw, TRACK_HOSTS + tuple(tracking.get('hosts', [])))
                    if untracked is not None:
                        clean = untracked
                        done.append(f'tracking removed: {pixels} pixels, {params} link parameters')
                links = wanted.get('links') or {}
                if links.get('enabled'):
                    # Item 4: the tenant of the first recipient that has one, for the hints of the warning page.
                    tenant = next((links.get('tenants', {}).get(rcpt.rpartition('@')[2].lower(), '') for rcpt in self.rcpts
                                   if links.get('tenants', {}).get(rcpt.rpartition('@')[2].lower())), '')
                    rewritten, count = rewrite_links(clean or raw, links['base'], bytes.fromhex(links['key']), links.get('exceptions', []), tenant)
                    if rewritten is not None:
                        clean = rewritten
                        done.append(f'{count} links go over the link check')
                banner = wanted.get('banner') or {}
                if banner.get('enabled'):
                    results = [value for name, value in self.headers if name.lower() == 'authentication-results']
                    warned = add_banner(clean or raw, banner.get('text') or BANNER_TEXT, banner.get('unsigned_only', True),
                                        banner.get('exceptions', []), results)
                    if warned is not None:
                        clean = warned
                        done.append('warning banner added')
                bimi = wanted.get('bimi') or {}
                if bimi.get('enabled'):
                    self.bimi_headers()
                if clean is None:
                    return Milter.ACCEPT
                hand_back(self, self.headers, clean)
                self.addheader(HEADER, '; '.join(done) + (f'; original {key}' if key else ''))
                syslog.syslog(syslog.LOG_INFO, f'changed for {",".join(self.rcpts)}: {"; ".join(done)}' + (f' (original {key})' if key else ''))
            except Exception as err:  # mail flow first: a mail it cannot handle goes on unchanged
                syslog.syslog(syslog.LOG_ERR, f'left unchanged: {err}')
            return Milter.ACCEPT

    def bimi_headers(self):
        """5w: the BIMI headers of the sender never come through; with a passed check eFa-next sets its own."""
        names = [name for name, _value in self.headers]
        for header in ('BIMI-Location', 'BIMI-Indicator'):
            for index in range(sum(1 for name in names if name.lower() == header.lower()), 0, -1):
                self.chgheader(header, index, '')
        sender = next((value for name, value in self.headers if name.lower() == 'from'), '')
        domain = email.utils.parseaddr(sender)[1].rpartition('@')[2].lower()
        selector = next((value for name, value in self.headers if name.lower() == 'bimi-selector'), '')
        selector = (re.search(r'\bs=([A-Za-z0-9_-]+)', selector) or [None, ''])[1]
        if not domain:
            return
        results = [value for name, value in self.headers if name.lower() == 'authentication-results']
        result, reason, headers = efa_bimi.check(domain, selector, results)
        for name, value in headers:
            self.addheader(name, value)
        note = f'bimi={result} header.d={domain} header.selector={selector or "default"}' + (' policy.authority=none' if result == 'pass' else f' ({reason})')
        self.addheader('Authentication-Results', f'{efa_host.own_hostname()}; {note}')
    Disarm.bimi_headers = bimi_headers
    Milter.factory = Disarm
    Milter.set_flags(Milter.ADDHDRS | Milter.CHGHDRS | Milter.CHGBODY)
    Milter.runmilter('efa-cdr', f'inet:{PORT}@127.0.0.1', timeout=120)
    # A connection that comes in while Python shuts down crashes pymilter: end without the shutdown.
    os._exit(0)


def test_pdf(objects):
    """A small PDF with a correct cross-reference table, for the self-test."""
    out, offsets = bytearray(b'%PDF-1.4\n'), []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b'%d 0 obj\n' % number + body + b'\nendobj\n'
    xref = len(out)
    out += b'xref\n0 %d\n0000000000 65535 f \n' % (len(objects) + 1) + b''.join(b'%010d 00000 n \n' % offset for offset in offsets)
    out += b'trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n' % (len(objects) + 1, xref)
    return bytes(out)


def self_test():
    # 6/8h: the journal names the envelope with the BCC recipients and holds the mail; in by the recipients, out by the sender.
    journal = {'in': {'own.example': 'in@archive.example'}, 'out': {'own.example': 'out@archive.example'}}
    assert journal_targets(journal, 'a@far.example', ['b@own.example', 'c@far.example']) == ['in@archive.example']
    assert journal_targets(journal, 'b@own.example', ['b2@own.example']) == ['in@archive.example', 'out@archive.example']
    report = journal_report(b'From: a@far.example\r\nSubject: Hi\r\n\r\nbody\r\n', 'a@far.example', ['b@own.example', 'hidden@own.example'], 'ABC123',
                            'in@archive.example', 'mx.own.example', 0)
    assert report['X-eFa-Journal-Recipients'] == 'b@own.example, hidden@own.example' and report['Subject'] == 'Journal: Hi'
    attached = [part for part in report.iter_attachments()][0]
    assert attached.get_content_type() == 'message/rfc822' and b'Subject: Hi' in report.as_bytes() and b'body' in report.as_bytes()
    # M1: pixels and tracking parameters go, real pictures and other parameters stay.
    assert untracked_url('https://shop.example/a?id=7&utm_source=nl&fbclid=x#top') == ('https://shop.example/a?id=7#top', 2)
    assert untracked_url('https://shop.example/a?utm_medium=mail') == ('https://shop.example/a', 1) and untracked_url('https://x.example/') == ('https://x.example/', 0)
    tracked = email.message.EmailMessage()
    tracked['From'], tracked['To'], tracked['Subject'] = 'news@shop.example', 'a@own.example', 'Offer'
    tracked.set_content('See https://shop.example/?utm_campaign=x')
    tracked.add_alternative('<p><img src="https://shop.example/logo.png" width="120" height="40">'
                            '<img src="https://t.shop.example/o.gif" width="1" height="1"><img src="https://mailtrack.io/trace/x.png">'
                            '<a href="https://shop.example/p?gclid=1&amp;sku=9">buy</a></p>', subtype='html')
    out, pixels, params = strip_tracking(tracked.as_bytes())
    html = email.message_from_bytes(out, policy=email.policy.default).get_body(('html',)).get_content()
    assert (pixels, params) == (2, 2) and 'logo.png' in html and 'o.gif' not in html and 'mailtrack' not in html and 'href="https://shop.example/p?sku=9"' in html
    assert strip_tracking(b'From: a@x.example\r\nSubject: plain\r\n\r\nno links\r\n') == (None, 0, 0)
    # 5v (e): active HTML goes, the text and harmless links stay.
    html = ('<html><head><meta http-equiv="refresh" content="0;url=https://evil.example/"><script>alert(1)</script></head>'
            '<body onload="x()"><p>Hello</p><a href="javascript:steal()">pay</a> <a href="https://shop.example/">shop</a>'
            '<form action="https://evil.example/"><input name="pw"></form><iframe src="https://x.example/"></iframe></body></html>')
    new, done = html_disarmed(html)
    assert done and 'script' not in new and 'onload' not in new and 'javascript' not in new and '<form' not in new and '<input' not in new
    assert 'iframe' not in new and 'refresh' not in new and '<p>Hello</p>' in new and 'href="https://shop.example/"' in new and 'href="#"' in new
    assert html_disarmed('<p>plain</p>') == ('<p>plain</p>', False)
    mail = email.message.EmailMessage()
    mail['From'], mail['To'], mail['Subject'] = 'a@x.example', 'b@y.example', 's'
    mail.set_content('text')
    mail.add_alternative(html, subtype='html')
    out = email.message_from_bytes(disarm_html(mail.as_bytes()), policy=email.policy.default)
    assert out['X-eFa-HTML-Disarmed'] and 'alert' not in out.get_body(('html',)).get_content() and disarm_html(b'Subject: x\r\n\r\nplain') is None
    def ooxml(parts):
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as z:
            for name, data in parts.items():
                z.writestr(name, data)
        return out.getvalue()
    types = ('<Types><Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
             '<Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>')
    rels = '<Relationships><Relationship Id="r1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/></Relationships>'
    docm = ooxml({'[Content_Types].xml': types, 'word/document.xml': '<w/>', 'word/vbaProject.bin': b'\x00VBA', 'word/_rels/document.xml.rels': rels})
    clean = zipfile.ZipFile(io.BytesIO(clean_ooxml(docm)))
    assert sorted(clean.namelist()) == ['[Content_Types].xml', 'word/_rels/document.xml.rels', 'word/document.xml']
    assert b'macroEnabled' not in clean.read('[Content_Types].xml') and b'vbaProject' not in clean.read('[Content_Types].xml')
    assert b'vbaProject' not in clean.read('word/_rels/document.xml.rels') and clean_ooxml(ooxml({'word/document.xml': '<w/>'})) is None
    assert clean_ooxml(b'PK broken') is None
    assert ole_macros(OLE_MAGIC + b'\x00' * 10 + OLE_VBA) and not ole_macros(OLE_MAGIC + b'\x00' * 10)
    assert pdf_active(b'%PDF-1.4\n1 0 obj << /OpenAction 2 0 R >>') and not pdf_active(b'%PDF-1.4\n1 0 obj << /OpenActions >>')
    assert PDF_ACTIVE.sub(lambda m: b'/' + m.group(1)[:-1] + b'_', b'<< /JS (x) /AA << >> /JavaScript 3 0 R >>') == b'<< /J_ (x) /A_ << >> /JavaScrip_ 3 0 R >>'

    message = email.message.EmailMessage()
    message['From'], message['To'], message['Subject'] = 'a@x.example', 'b@y.example', 'cdr'
    message.set_content('Report attached.')
    message.add_attachment(docm, maintype='application', subtype='vnd.ms-word.document.macroEnabled.12', filename='report.docm')
    message.add_attachment(OLE_MAGIC + b'\x00' * 10 + OLE_VBA, maintype='application', subtype='msword', filename='old.doc')
    message.add_attachment(b'plain text', maintype='text', subtype='plain', filename='notes.txt')
    clean, done = disarm(message.as_bytes())
    assert done == ['macros removed from report.docm', 'old.doc replaced: an Office file with macros that cannot be cleaned'], done
    parsed = email.message_from_bytes(clean, policy=email.policy.default)
    names = [part.get_filename() for part in parsed.iter_attachments()]
    assert names == ['report.docx', 'old.doc.removed.txt', 'notes.txt'], names
    report = next(part for part in parsed.iter_attachments() if part.get_filename() == 'report.docx')
    assert report.get_content_type().endswith('wordprocessingml.document') and 'word/vbaProject.bin' not in zipfile.ZipFile(io.BytesIO(report.get_content())).namelist()
    plain = email.message.EmailMessage()
    plain['From'], plain['To'] = 'a@x.example', 'b@y.example'
    plain.set_content('no attachments')
    assert disarm(plain.as_bytes()) == (None, [])
    broken = email.message.EmailMessage()
    broken['From'], broken['To'], broken['Subject'] = 'a@x.example', 'b@y.example', 'x'
    broken.set_content('see attached')
    macro_zip = io.BytesIO()
    with zipfile.ZipFile(macro_zip, 'w', zipfile.ZIP_DEFLATED) as target:
        target.writestr('word/vbaProject.bin', b'macro' * 200)
        target.writestr('word/document.xml', b'<w:document/>')
    damaged = bytearray(macro_zip.getvalue())
    second = damaged.find(b'PK\x03\x04', 4)
    damaged[second + 2:second + 4] = b'XX'  # the local header of the document; the central directory still names both
    broken.add_attachment(bytes(damaged), maintype='application', subtype='octet-stream', filename='a.docm')
    out, notes = disarm(broken.as_bytes())
    assert out is not None and 'cannot be cleaned' in notes[0] and b'macro' * 5 not in out, notes
    # A multipart part with a broken boundary that holds a macro file (scripts/fuzz.py, seed 6004): rejected, never passed on.
    hidden = (b'From: a@x.example\r\nTo: b@y.example\r\nSubject: x\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n'
              b'--b\r\nContent-Type: multipart/mixed; boundary="==\r\nContent-Transfer-Encoding: base64\r\n'
              b'Content-Disposition: attachment; filename="a.docm"\r\n\r\n' + base64.encodebytes(docm).replace(b'\n', b'\r\n') + b'--b--\r\n')
    try:
        disarm(hidden)
        raise AssertionError('a hidden attachment must not pass')
    except Unwritable:
        pass
    pdf_mail = email.message.EmailMessage()
    pdf_mail.set_content('x')
    pdf_mail.add_attachment(b'%PDF-1.4 /OpenAction 1 0 R /JavaScript (x)', maintype='application', subtype='pdf', filename='a.pdf')
    out, notes = disarm(pdf_mail.as_bytes(), qpdf='false')
    assert out is not None and 'a.pdf replaced' in notes[0] and b'/JavaScript' not in out, notes
    secret = b'k' * 32
    token = link_token('https://shop.example/a?b=1&c=2', secret)
    assert link_target(token, secret) == 'https://shop.example/a?b=1&c=2' and link_target(token, b'x' * 32) is None and link_target('bad', secret) is None
    assert link_target(token[:-2] + 'AA', secret) is None
    linked = email.message.EmailMessage()
    linked['From'], linked['To'], linked['Subject'] = 'a@x.example', 'b@y.example', 'links'
    linked.set_content('See https://shop.example/a and https://own.example/x and https://sub.partner.example/y.')
    linked.add_alternative('<p><a href="https://shop.example/a?b=1&amp;c=2">shop</a> <a href=\'http://evil.example/\'>x</a> <a href="mailto:a@b">m</a></p>',
                           subtype='html')
    out, count = rewrite_links(linked.as_bytes(), 'https://mx.own.example', secret, ['own.example', 'partner.example'])
    assert count == 3, count
    parsed = email.message_from_bytes(out, policy=email.policy.default)
    plain = parsed.get_body(('plain',)).get_content()
    page = parsed.get_body(('html',)).get_content()
    assert 'https://own.example/x' in plain and 'https://sub.partner.example/y' in plain and 'https://shop.example/a ' not in plain
    target = re.search(r'https://mx\.own\.example/l/([\w.-]+)', page).group(1).replace('&amp;', '&')
    assert link_target(target, secret) == 'https://shop.example/a?b=1&c=2' and 'mailto:a@b' in page and 'evil.example' not in page
    one = email.message.EmailMessage()
    one['From'] = 'a@x.example'
    one.set_content('Go to https://shop.example/a now.')
    out_one, _count = rewrite_links(one.as_bytes(), 'https://mx.own.example', secret, [])
    changed = dict(mime_header_changes([('Content-Type', 'text/plain; charset="utf-8"'), ('Content-Transfer-Encoding', '7bit'), ('MIME-Version', '1.0')],
                                       email.message_from_bytes(out_one, policy=email.policy.default)))
    assert 'Content-Transfer-Encoding' in changed and changed['Content-Transfer-Encoding'] != '7bit', changed
    external = email.message.EmailMessage()
    external['From'], external['Subject'] = 'Someone <x@outside.example>', 'hi'
    external.set_content('Hello.')
    external.add_alternative('<html><body><p>Hello.</p></body></html>', subtype='html')
    warned = email.message_from_bytes(add_banner(external.as_bytes(), BANNER_TEXT, True, [], ['mx.own; dkim=none']), policy=email.policy.default)
    assert warned.get_body(('plain',)).get_content().startswith('[Caution') and '<body><div style=' in warned.get_body(('html',)).get_content()
    assert add_banner(external.as_bytes(), BANNER_TEXT, True, [], ['mx.own; dkim=pass header.d=outside.example']) is None
    assert add_banner(external.as_bytes(), BANNER_TEXT, False, [], ['mx.own; dkim=pass']) is not None
    assert add_banner(external.as_bytes(), BANNER_TEXT, False, ['outside.example'], []) is None
    signed = email.message.EmailMessage()
    signed['Content-Type'] = 'multipart/signed; protocol="application/pkcs7-signature"; boundary="b"'
    assert rewrite_links(signed.as_bytes(), 'https://mx.own.example', secret, []) == (None, 0)
    with tempfile.TemporaryDirectory() as folder:
        key = store_original(b'raw', 'a@x.example', ['b@y.example'], ['x'], folder)
        assert oct(os.stat(os.path.join(folder, key + '.eml')).st_mode)[-3:] == '600'
        assert json.load(open(os.path.join(folder, key + '.json')))['rcpts'] == ['b@y.example']
    if subprocess.run(['sh', '-c', 'command -v qpdf'], capture_output=True).returncode == 0:
        pdf = test_pdf([b'<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >>',
                        b'<< /Type /Pages /Kids [] /Count 0 >>'])
        cleaned = clean_pdf(pdf)
        # Cleaned once, nothing is left for a second run.
        assert cleaned and cleaned[:5] == b'%PDF-' and clean_pdf(cleaned) is None
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
    else:
        syslog.openlog('efa-cdr', 0, syslog.LOG_MAIL)
        run_milter()
