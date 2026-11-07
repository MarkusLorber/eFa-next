# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Disclaimers of outgoing mail (8k): templates for all domains, a tenant, a domain or groups of senders in a domain, as text
or as HTML with embedded pictures, both with attachments. The most specific template that fits the sender wins (group, then
domain, then tenant, then all domains), so a mail gets exactly one.

The milter (efa-outbound) only reads files: the templates in outbound.json, their pictures and attachments below
/etc/eFa/disclaimers/<id>/, and which groups a sender is in (sender_groups in outbound.json), written by efactl. The mail flow never
waits for LDAP or the database.
"""
import html as html_lib
import re
import time
from email.message import EmailMessage

LEVELS = {'group': 3, 'domain': 2, 'tenant': 1, 'global': 0}
FORMATS = ('html', 'text')
# What a disclaimer may carry: pictures for the HTML and files to attach. No active content (SVG is left out: it can hold script).
MEDIA_TYPES = {'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'gif': 'image/gif'}
ATTACHMENT_TYPES = {**MEDIA_TYPES, 'pdf': 'application/pdf', 'vcf': 'text/vcard'}
MAGIC = {'image/png': b'\x89PNG\r\n\x1a\n', 'image/jpeg': b'\xff\xd8\xff', 'image/gif': b'GIF8', 'application/pdf': b'%PDF-'}
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TEMPLATE_BYTES = 5 * 1024 * 1024
ID_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,39}$')
UNSAFE_HTML = re.compile(r'<\s*(script|iframe|object|embed|form|base|meta|link|style)\b|\bon\w+\s*=|javascript:|vbscript:|data:(?!image/(png|jpeg|gif))'
                         r'|\bsrc\s*=\s*["\']?\s*(https?:|//)|\burl\s*\(', re.I)


def html_problem(html):
    """None for HTML that may go into a disclaimer: no script, frames, forms, event handlers or outside resources. Links
    (href) to https are fine; pictures come with the template (src="cid:...")."""
    if UNSAFE_HTML.search(html or ''):
        return 'HTML without scripts, frames, forms, styles from outside, event handlers or pictures from the internet (src="cid:..." only).'
    links = re.findall(r'\bhref\s*=\s*["\']?\s*([^"\'\s>]*)', html or '', re.I)
    if any(not link.lower().startswith(('https://', 'mailto:', 'tel:', '#')) for link in links):
        return 'Links: https://, mailto: or tel: only.'
    return None


def file_problem(name, data, kinds):
    """None for a file of an allowed type whose content matches its ending."""
    ending = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
    kind = kinds.get(ending)
    if not kind or not re.match(r'^[\w.() -]{1,80}$', name) or '/' in name or name.startswith('.'):
        return f'{name}: allowed are {", ".join(sorted(kinds))} with a plain file name.'
    if len(data) > MAX_FILE_BYTES:
        return f'{name}: larger than {MAX_FILE_BYTES // 1024 // 1024} MB.'
    if kind in MAGIC and not data.startswith(MAGIC[kind]):
        return f'{name}: the content is no {ending.upper()}.'
    if kind == 'text/vcard' and not data.lstrip().upper().startswith(b'BEGIN:VCARD'):
        return f'{name}: the content is no vCard.'
    return None


MAX_ZIP_FILES = 50
MAX_RATIO = 100
DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')


def template_problem(template):
    """None for the fields of a template that the milter can use."""
    if not ID_RE.match(template.get('id') or ''):
        return 'Id: small letters, digits and dashes, up to 40.'
    if template.get('scope') not in LEVELS:
        return 'Scope: global, tenant, domain or group.'
    if template['scope'] != 'global' and not template.get('target'):
        return 'A tenant, domain or group template needs its tenant or domain (target).'
    if template['scope'] == 'group' and not template.get('groups'):
        return 'A group template needs one or more groups.'
    if template.get('format') not in FORMATS:
        return 'Format: html or text.'
    if template['format'] == 'html' and not (template.get('html') or '').strip():
        return 'An HTML template needs its HTML.'
    if template['format'] == 'text' and not (template.get('text') or '').strip():
        return 'A text template needs its text.'
    if len(template.get('text') or '') > 5000 or len(template.get('html') or '') > 100000:
        return 'Text up to 5000 characters, HTML up to 100000.'
    if template['format'] == 'html':
        problem = html_problem(template['html'])
        if problem:
            return problem
        cids = set(re.findall(r'src\s*=\s*["\']?cid:([^"\'\s>]+)', template['html'], re.I))
        if cids - {item['cid'] for item in template.get('media') or []}:
            return 'The HTML names pictures (cid:) that are not in media/: ' + ', '.join(sorted(cids - {item['cid'] for item in template.get('media') or []}))
    if not str(template.get('priority', 100)).isdigit() or int(template.get('priority', 100)) > 9999:
        return 'Priority: a number up to 9999.'
    if any(template.get(key) and not DATE_RE.match(template[key]) for key in ('valid_from', 'valid_until')):
        return 'Valid from and until: YYYY-MM-DD.'
    return None


def read_zip(data):
    """A template and its files from a ZIP: manifest.json, body.html and/or body.txt, media/ (pictures, named in the HTML as
    cid:<file name>) and attachments/. Raises ValueError with the reason; nothing of a bad ZIP is used."""
    import json
    import efa_zip
    # The shared safe reader (A4): member count, unpacked size, ZIP bombs, traversal, absolute paths, links and encryption.
    members = efa_zip.safe_unzip(data, max_files=MAX_ZIP_FILES, max_total=MAX_TEMPLATE_BYTES, max_ratio=MAX_RATIO)
    found = {}
    for name, content in members.items():
        folder, _, base = name.rpartition('/')
        if folder not in ('', 'media', 'attachments') or (folder == '' and base not in ('manifest.json', 'body.html', 'body.txt')):
            raise ValueError(f'{name}: only manifest.json, body.html, body.txt, media/ and attachments/.')
        found[name] = content
    try:
        manifest = json.loads(found.pop('manifest.json').decode('utf-8'))
    except KeyError:
        raise ValueError('manifest.json is missing.') from None
    except (UnicodeDecodeError, ValueError):
        raise ValueError('manifest.json is no JSON in UTF-8.') from None
    if not isinstance(manifest, dict):
        raise ValueError('manifest.json: an object.')
    try:
        html = found.pop('body.html', b'').decode('utf-8')
        text = found.pop('body.txt', b'').decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError('body.html and body.txt: UTF-8.') from None
    groups = manifest.get('groups') or []
    template = {'id': str(manifest.get('id') or manifest.get('name') or '').strip().lower(), 'name': str(manifest.get('name') or '')[:80],
                'scope': manifest.get('scope'), 'target': str(manifest.get('target') or '').strip().lower(),
                'groups': [str(item).strip() for item in groups] if isinstance(groups, list) else [], 'format': manifest.get('format'),
                'html': html, 'text': text.strip(), 'priority': manifest.get('priority', 100), 'enabled': manifest.get('enabled', True) is not False,
                'valid_from': str(manifest.get('valid_from') or ''), 'valid_until': str(manifest.get('valid_until') or ''), 'media': [], 'attachments': []}
    files = {}
    for name, content in sorted(found.items()):
        folder, base = name.split('/', 1)
        problem = file_problem(base, content, MEDIA_TYPES if folder == 'media' else ATTACHMENT_TYPES)
        if problem:
            raise ValueError(problem)
        if base in files:
            raise ValueError(f'{base}: twice.')
        files[base] = content
        kind = (MEDIA_TYPES if folder == 'media' else ATTACHMENT_TYPES)[base.rsplit('.', 1)[1].lower()]
        if folder == 'media':
            # The HTML names a picture as cid:logo.png or cid:logo.
            stem = base.rsplit('.', 1)[0]
            cid = stem if re.search(r'cid:' + re.escape(stem) + r'(?![\w.-])', html) else base
            template['media'].append({'cid': cid, 'file': base, 'type': kind})
        else:
            template['attachments'].append({'file': base, 'type': kind})
    problem = template_problem(template)
    if problem:
        raise ValueError(problem)
    return template, files


def write_zip(template, read_file):
    """The ZIP of a template, as read_zip takes it."""
    import io
    import json
    import zipfile
    out = io.BytesIO()
    keys = ('id', 'name', 'scope', 'target', 'groups', 'format', 'priority', 'enabled', 'valid_from', 'valid_until')
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('manifest.json', json.dumps({key: template.get(key) for key in keys if template.get(key) not in (None, '', [])}, indent=1))
        if template.get('html'):
            archive.writestr('body.html', template['html'])
        if template.get('text'):
            archive.writestr('body.txt', template['text'])
        for item in template.get('media') or []:
            archive.writestr('media/' + item['file'], read_file(item['file']))
        for item in template.get('attachments') or []:
            archive.writestr('attachments/' + item['file'], read_file(item['file']))
    return out.getvalue()


def active(template, now):
    if not template.get('enabled', True):
        return False
    return (not template.get('valid_from') or template['valid_from'] <= now) and (not template.get('valid_until') or now <= template['valid_until'])


def fits(template, sender, tenant_of, groups_of):
    """Whether a template is meant for this sender: its domain, the tenant of its domain, or a group it is in (in that domain)."""
    domain = sender.rpartition('@')[2].lower()
    scope, target = template['scope'], (template.get('target') or '').lower()
    if scope == 'global':
        return True
    if scope == 'tenant':
        return bool(target) and tenant_of(domain) == target
    if scope == 'domain':
        return domain == target
    if scope == 'group':
        return domain == target and bool(set(template.get('groups') or []) & set(groups_of(sender.lower())))
    return False


def pick(templates, sender, tenant_of=lambda domain: '', groups_of=lambda sender: (), now=None):
    """The one template for a sender: the most specific level, then the lowest priority number, then the name."""
    now = time.strftime('%Y-%m-%d') if now is None else now
    found = [item for item in templates if active(item, now) and fits(item, sender, tenant_of, groups_of)]
    return min(found, key=lambda item: (-LEVELS[item['scope']], int(item.get('priority', 100)), item.get('id', ''))) if found else None


def html_text(text):
    return '<br>'.join(html_lib.escape(line) for line in text.splitlines())


def text_of(html):
    """A text version of the HTML of a disclaimer for the text part of a mail."""
    text = re.sub(r'(?is)<br\s*/?>|</p>|</div>|</tr>|</h\d>', '\n', html)
    text = re.sub(r'(?is)<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', lambda m: f'{m.group(2)} ({m.group(1)})' if m.group(1) not in m.group(2) else m.group(2), text)
    text = html_lib.unescape(re.sub(r'(?s)<[^>]+>', '', text))
    return '\n'.join(line.strip() for line in text.splitlines()).strip()


def marker_of(template):
    return ' '.join((template.get('text') or text_of(template.get('html') or '')).split())[:60]


def apply(message, template, read_file, sealed=lambda message: False):
    """Puts the template into the mail (an EmailMessage with the default policy). Returns False when the mail stays as it is:
    signed or encrypted, or holding the disclaimer already (a reply quoting it). read_file(name) gives the bytes of a picture
    or an attachment of the template."""
    if sealed(message):
        return False
    html = template.get('html') if template.get('format') == 'html' else ''
    text = template.get('text') or text_of(html)
    block_html = html or html_text(text)
    marker = marker_of(template)
    parts = {'plain': None, 'html': None}
    for part in message.walk():
        key = {'text/plain': 'plain', 'text/html': 'html'}.get(part.get_content_type())
        if part.is_multipart() or key is None or parts[key] is not None or part.get_content_disposition() == 'attachment':
            continue
        try:
            body = part.get_content()
        except (LookupError, ValueError):
            continue
        if marker and marker in ' '.join(re.sub(r'<[^>]+>', ' ', body).split()):
            return False
        parts[key] = (part, body)
    if not any(parts.values()):
        return False
    if parts['plain']:
        part, body = parts['plain']
        part.set_content(body.rstrip('\n') + '\n\n-- \n' + text + '\n', charset='utf-8')
    if parts['html']:
        part, body = parts['html']
        block = f'<div class="efa-disclaimer" style="margin-top:16px;font-size:12px;color:#646563">{block_html}</div>'
        found = list(re.finditer(r'</body>', body, re.I))
        part.set_content(body[:found[-1].start()] + block + body[found[-1].start():] if found else body + block, subtype='html', charset='utf-8')
        media = template.get('media') or [] if html else []
        if media:
            # The pictures next to the HTML: a multipart/related around it, or the one it is in already.
            if part.get_content_type() == 'text/html':
                part.make_related()
                holder = part
            else:
                holder = part
            for item in media:
                maintype, subtype = item['type'].split('/')
                holder.add_related(read_file(item['file']), maintype=maintype, subtype=subtype, cid=f"<{item['cid']}>",
                                   filename=item['file'])
    for item in template.get('attachments') or []:
        if not message.is_multipart() or message.get_content_type() != 'multipart/mixed':
            message.make_mixed()
        maintype, subtype = item['type'].split('/')
        message.add_attachment(read_file(item['file']), maintype=maintype, subtype=subtype, filename=item.get('name') or item['file'])
    for part in message.walk():
        if part is not message and 'MIME-Version' in part:
            del part['MIME-Version']  # set_content and make_* add it, it belongs only at the top
    return True


def self_test():
    import email
    import email.policy
    templates = [{'id': 'all', 'scope': 'global', 'format': 'text', 'text': 'Global text'},
                 {'id': 'acme', 'scope': 'tenant', 'target': 'acme', 'format': 'text', 'text': 'Tenant text'},
                 {'id': 'dom', 'scope': 'domain', 'target': 'a.example', 'format': 'html', 'html': '<p>Domain <b>HTML</b> <img src="cid:logo"></p>',
                  'media': [{'cid': 'logo', 'file': 'logo.png', 'type': 'image/png'}], 'attachments': [{'file': 'card.vcf', 'type': 'text/vcard'}]},
                 {'id': 'sales', 'scope': 'group', 'target': 'a.example', 'groups': ['sales'], 'format': 'text', 'text': 'Sales text', 'priority': 5},
                 {'id': 'sales2', 'scope': 'group', 'target': 'a.example', 'groups': ['sales'], 'format': 'text', 'text': 'Second', 'priority': 9},
                 {'id': 'old', 'scope': 'domain', 'target': 'b.example', 'format': 'text', 'text': 'Old', 'valid_until': '2026-01-01'}]
    tenant_of = {'a.example': 'acme', 'b.example': 'acme', 'c.example': ''}.get
    groups_of = {'anna@a.example': ['sales']}.get
    groups = lambda sender: groups_of(sender) or ()
    assert pick(templates, 'anna@a.example', tenant_of, groups, '2026-11-07')['id'] == 'sales', 'group before domain, lower priority first'
    assert pick(templates, 'bob@a.example', tenant_of, groups, '2026-11-07')['id'] == 'dom'
    assert pick(templates, 'x@b.example', tenant_of, groups, '2026-11-07')['id'] == 'acme', 'a template that ran out is not used'
    assert pick(templates, 'x@c.example', tenant_of, groups, '2026-11-07')['id'] == 'all'
    assert pick([], 'x@c.example') is None
    assert html_problem('<p><a href="https://x.example">x</a><img src="cid:logo"></p>') is None
    for bad in ('<script>x</script>', '<img src="https://t.example/p.gif">', '<a href="javascript:x">', '<p onclick="x">', '<a href="http://x">',
                '<style>@import url(x)</style>', '<div style="background:url(https://x)">'):
        assert html_problem(bad), bad
    assert file_problem('logo.png', b'\x89PNG\r\n\x1a\nrest', MEDIA_TYPES) is None and file_problem('logo.png', b'GIF8', MEDIA_TYPES)
    assert file_problem('x.svg', b'<svg/>', ATTACHMENT_TYPES) and file_problem('../x.pdf', b'%PDF-', ATTACHMENT_TYPES)
    assert file_problem('card.vcf', b'BEGIN:VCARD\r\nEND:VCARD', ATTACHMENT_TYPES) is None
    assert text_of('<p>Hi <a href="https://x.example">site</a><br>Ä&amp;Ö</p>') == 'Hi site (https://x.example)\nÄ&Ö'
    files = {'logo.png': b'\x89PNG\r\n\x1a\nPIC', 'card.vcf': b'BEGIN:VCARD\r\nFN:A\r\nEND:VCARD\r\n'}
    # Text only: the text at the end, the HTML version in an HTML part.
    plain = email.message_from_bytes(b'From: bob@a.example\r\nSubject: t\r\n\r\nHello\r\n', policy=email.policy.default)
    assert apply(plain, templates[0], files.get) and plain.get_content().endswith('-- \nGlobal text\n')
    assert not apply(plain, templates[0], files.get), 'not twice'
    # HTML with a picture and an attachment, into a mail with text and HTML.
    alt = EmailMessage(policy=email.policy.default)
    alt['From'], alt['Subject'] = 'bob@a.example', 'Grüße'
    alt.set_content('Hallo Grüße')
    alt.add_alternative('<html><body><p>Hallo</p></body></html>', subtype='html')
    assert apply(alt, templates[2], files.get)
    out = email.message_from_bytes(alt.as_bytes(), policy=email.policy.default)
    assert out.get_content_type() == 'multipart/mixed' and [p.get_content_type() for p in out.walk()][:6] == [
        'multipart/mixed', 'multipart/alternative', 'text/plain', 'multipart/related', 'text/html', 'image/png'], [p.get_content_type() for p in out.walk()]
    text_part = next(p for p in out.walk() if p.get_content_type() == 'text/plain')
    html_part = next(p for p in out.walk() if p.get_content_type() == 'text/html')
    image = next(p for p in out.walk() if p.get_content_type() == 'image/png')
    assert 'Domain HTML' in text_part.get_content() and 'Grüße' in text_part.get_content(), 'a text version for the text part, umlauts kept'
    assert 'efa-disclaimer' in html_part.get_content() and html_part.get_content().index('efa-disclaimer') < html_part.get_content().index('</body>')
    assert image['Content-ID'] == '<logo>' and image.get_content() == files['logo.png']
    card = next(p for p in out.walk() if p.get_filename() == 'card.vcf')
    assert card.get_content_disposition() == 'attachment' and b'FN:A' in card.get_payload(decode=True)
    assert not apply(out, templates[2], files.get), 'not twice'
    # Signed mail stays as it is.
    assert not apply(email.message_from_bytes(b'Subject: s\r\n\r\nx', policy=email.policy.default), templates[0], files.get, sealed=lambda m: True)
    # ZIP: what write_zip makes, read_zip takes back; bad ones are refused whole.
    import io
    import zipfile
    data = write_zip(templates[2], files.get)
    again, got = read_zip(data)
    assert again['html'] == templates[2]['html'] and again['media'] == templates[2]['media'] and got == files, again
    assert again['attachments'] == [{'file': 'card.vcf', 'type': 'text/vcard'}]

    def zipped(entries, link=None):
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, content in entries.items():
                archive.writestr(name, content)
            if link:
                info = zipfile.ZipInfo(link)
                info.external_attr = 0o120777 << 16
                archive.writestr(info, 'body.txt')
        return out.getvalue()
    manifest = b'{"id": "t1", "scope": "domain", "target": "a.example", "format": "text"}'
    assert read_zip(zipped({'manifest.json': manifest, 'body.txt': 'Hi'}))[0]['text'] == 'Hi'
    for bad, why in ((zipped({'manifest.json': manifest, 'body.txt': 'Hi', '../x.txt': 'x'}), 'path'),
                     (zipped({'manifest.json': manifest, 'body.txt': 'Hi', 'media/x.svg': '<svg/>'}), 'svg'),
                     (zipped({'manifest.json': manifest, 'body.txt': 'Hi', 'media/x.png': 'GIF8'}), 'magic'),
                     (zipped({'manifest.json': manifest, 'body.txt': 'Hi'}, link='attachments/l.pdf'), 'link'),
                     (zipped({'manifest.json': manifest, 'body.txt': 'Hi', 'attachments/big.pdf': b'%PDF-' + b'0' * (6 * 1024 * 1024)}), 'size'),
                     (zipped({'manifest.json': manifest.replace(b'"text"', b'"html"'), 'body.html': '<p onclick="x">'}), 'html'),
                     (zipped({'manifest.json': manifest.replace(b'"text"', b'"html"'), 'body.html': '<img src="cid:nothere.png">'}), 'cid'),
                     (zipped({'manifest.json': b'[1]', 'body.txt': 'x'}), 'manifest'), (zipped({'body.txt': 'x'}), 'no manifest'),
                     (zipped({'manifest.json': manifest, 'body.txt': 'Hi', 'other/x.pdf': '%PDF-'}), 'folder'), (b'PK no zip', 'zip'),
                     (zipped({'manifest.json': manifest.replace(b'a.example', b''), 'body.txt': 'Hi'}), 'target')):
        try:
            read_zip(bad)
        except ValueError:
            continue
        raise AssertionError(f'a bad ZIP was taken: {why}')
    print('self-test ok')


if __name__ == '__main__':
    import sys
    if '--self-test' in sys.argv:
        self_test()
