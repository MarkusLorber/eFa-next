# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""G7-21: the mail flow picture of the dashboard (draft 2, compact): what the code does with a mail, as data.

The stages and branches are data (STAGES, BRANCHES): id, label in English and German, the switch that makes a stage optional,
the counter it shows and the mail search a click opens. The layout is computed from that data, in a wide form (two lanes,
1200 x 352) and a tall one for phones; the page shows one by the width of the screen. Each stage has an icon from a theme
folder (/usr/share/eFa/flow/<theme>/<icon>.svg, own files of the package), referenced as an image of this server, never
inlined. A new theme is a new folder, no code. Only counters that exist are shown (dash-stats, the queues); no claim of
MTA-STS for outgoing mail. Standard library only."""
import html
import re

THEME_DIR = '/usr/share/eFa/flow'
THEME_RE = re.compile(r'^[a-z0-9][a-z0-9_-]{0,31}$')
# lane: in (port 25) or out (port 587 and the relay networks). flag: the switch of an optional stage (dashed while off).
STAGES = (
    {'id': 'internet-in', 'lane': 'in', 'icon': 'internet', 'en': 'Internet', 'de': 'Internet'},
    {'id': 'postscreen', 'lane': 'in', 'icon': 'postscreen', 'en': 'Postscreen', 'de': 'Postscreen',
     'note_en': 'blocklists, protocol checks', 'note_de': 'Blocklisten, Protokollprüfung'},
    {'id': 'smtp', 'lane': 'in', 'icon': 'smtp', 'en': 'SMTP rules', 'de': 'SMTP-Regeln', 'note_en': 'HELO, relay, recipients',
     'note_de': 'HELO, Relay, Empfänger'},
    {'id': 'rspamd', 'lane': 'in', 'icon': 'rspamd', 'en': 'Spam & virus', 'de': 'Spam & Virus', 'counter': 'processed', 'search': '',
     'note_en': 'greylisting, SPF/DKIM/DMARC, ClamAV', 'note_de': 'Greylisting, SPF/DKIM/DMARC, ClamAV'},
    {'id': 'cdr', 'lane': 'in', 'icon': 'cdr', 'en': 'Content disarm', 'de': 'Entschärfung', 'flag': 'cdr', 'note_en': 'macros, PDF, links',
     'note_de': 'Makros, PDF, Links'},
    {'id': 'deliver', 'lane': 'in', 'icon': 'deliver', 'en': 'Delivery', 'de': 'Zustellung', 'counter': 'delivered', 'search': 'result:no_action',
     'note_en': 'TLS, DANE where on', 'note_de': 'TLS, DANE wenn an'},
    {'id': 'users', 'lane': 'out', 'icon': 'users', 'en': 'Users, relays', 'de': 'Benutzer, Relays', 'note_en': 'port 587 with login',
     'note_de': 'Port 587 mit Anmeldung'},
    {'id': 'outbound', 'lane': 'out', 'icon': 'outbound', 'en': 'Outbound checks', 'de': 'Ausgangsprüfung', 'flag': 'outbound',
     'note_en': 'disclaimer, DLP, limits', 'note_de': 'Disclaimer, DLP, Grenzen'},
    {'id': 'sign', 'lane': 'out', 'icon': 'sign', 'en': 'rspamd + DKIM', 'de': 'rspamd + DKIM', 'note_en': 'check, sign', 'note_de': 'prüfen, signieren'},
    {'id': 'internet-out', 'lane': 'out', 'icon': 'internet', 'en': 'Internet', 'de': 'Internet', 'counter': 'outgoing',
     'note_en': 'waiting in the queue', 'note_de': 'warten in der Queue'},
)
BRANCHES = (
    {'id': 'rejected', 'from': 'rspamd', 'icon': 'rejected', 'en': 'Rejected', 'de': 'Abgelehnt', 'counter': 'rejected', 'search': 'result:reject'},
    {'id': 'uq', 'from': 'rspamd', 'icon': 'uq', 'en': 'User quarantine', 'de': 'Benutzer-Quarantäne', 'flag': 'uq', 'search': 'result:discard'},
    {'id': 'hold', 'from': 'rspamd', 'icon': 'hold', 'en': 'Admin hold', 'de': 'Admin-Halt', 'flag': 'hold', 'counter': 'hold', 'page': 'queue'},
)
ICONS = sorted({item['icon'] for item in STAGES + BRANCHES})
BOX_W, BOX_H, ICON = 150, 66, 28


def counters(stats):
    """The numbers the picture shows, from dash-stats only: today's mails, the queues. None where a reader may not see them."""
    today = (stats or {}).get('today') or {}
    queues = ((stats or {}).get('queues') or {}).get('counts') or {}
    found = {}
    if today:
        found.update(processed=today.get('processed', 0), delivered=today.get('clean', 0) + today.get('spam', 0),
                     rejected=today.get('high_spam', 0) + today.get('viruses', 0) + today.get('blocked_files', 0))
    if queues:
        found.update(hold=sum((queues.get('hold') or {}).values()),
                     outgoing=sum((queues.get(name) or {}).get('out', 0) for name in ('active', 'deferred', 'incoming')))
    return found


def layout(tall=False):
    """{id: (x, y)} of every stage and branch, and the size of the picture, from the data alone."""
    places = {}
    lanes = {lane: [stage for stage in STAGES if stage['lane'] == lane] for lane in ('in', 'out')}
    if not tall:
        width, height = 1200, 352
        for lane, top in (('in', 20), ('out', 266)):
            items = lanes[lane]
            step = (width - 40 - BOX_W) / max(len(items) - 1, 1)
            for i, stage in enumerate(items):
                places[stage['id']] = (round(20 + i * step), top)
        for i, branch in enumerate(BRANCHES):
            fx, _fy = places[branch['from']]
            places[branch['id']] = (round(fx - BOX_W + i * (BOX_W + 14)), 143)
        return places, width, height
    # Phones: one column per lane, the branches beside the stage they leave.
    width, y = 360, 10
    for stage in lanes['in']:
        places[stage['id']] = (10, y)
        if stage['id'] == BRANCHES[0]['from']:
            for i, branch in enumerate(BRANCHES):
                places[branch['id']] = (200, y + i * (BOX_H + 8))
            y += max(BOX_H + 18, len(BRANCHES) * (BOX_H + 8))
        else:
            y += BOX_H + 18
    y += 20
    for stage in lanes['out']:
        places[stage['id']] = (10, y)
        y += BOX_H + 18
    return places, width, y


def _fit(text, size, room, wide=0.56):
    """SVG attributes that squeeze a text into room units when its estimated width (size * wide per character) is larger."""
    return f' textLength="{room}" lengthAdjust="spacingAndGlyphs"' if len(text) * size * wide > room else ''


def _lines(note, size=11, room=BOX_W - 54):
    """A note in at most two lines, split after a comma where the first line still fits."""
    words, first = note.split(', '), ''
    for i in range(len(words), 0, -1):
        first = ', '.join(words[:i]) + (',' if i < len(words) else '')
        if len(first) * size * 0.52 <= room or i == 1:
            rest = ', '.join(words[i:])
            return [first] + ([rest] if rest else [])
    return [note]


def _box(item, x, y, flags, numbers, theme, lang, link):
    label = item['de'] if lang == 'de' and item.get('de') else item['en']
    note = item.get('note_de' if lang == 'de' else 'note_en', '')
    off = bool(item.get('flag')) and not flags.get(item['flag'])
    number = numbers.get(item.get('counter')) if item.get('counter') else None
    state = (' – ' + ('aus' if lang == 'de' else 'off')) if off else ''
    title = f'{label}{state}' + (f': {note}' if note else '') + (f' ({number})' if number is not None else '')
    room = BOX_W - 54  # from the text start (after the icon) to 8 units before the right edge
    shape = (f'<rect x="{x}" y="{y}" width="{BOX_W}" height="{BOX_H}" rx="10" class="fl-box{" fl-off" if off else ""}"/>'
             f'<image href="/flow-icon/{theme}/{item["icon"]}.svg" x="{x + 10}" y="{y + 10}" width="{ICON}" height="{ICON}"/>'
             f'<text x="{x + 46}" y="{y + 24}" class="fl-label"{_fit(label, 14, room)}>{html.escape(label)}</text>'
             + (''.join(f'<text x="{x + 46}" y="{y + 41 + 13 * i}" class="fl-note"{_fit(line, 11, room, 0.52)}>{html.escape(line)}</text>'
                        for i, line in enumerate(_lines(note))) if note and number is None else '')
             + (f'<text x="{x + 46}" y="{y + 50}" class="fl-num">{number}</text>' if number is not None else '')
             + f'<title>{html.escape(title)}</title>')
    target = link(item)
    return f'<a href="{html.escape(target)}" class="fl-item">{shape}</a>' if target else f'<g class="fl-item">{shape}</g>'


def _arrows(places, tall):
    """The lines between the stages of a lane and from a stage to its branches."""
    lines = []
    for lane in ('in', 'out'):
        items = [stage['id'] for stage in STAGES if stage['lane'] == lane]
        for a, b in zip(items, items[1:]):
            (ax, ay), (bx, by) = places[a], places[b]
            if tall:
                lines.append(f'<path class="fl-line" d="M{ax + BOX_W // 2} {ay + BOX_H} L{bx + BOX_W // 2} {by}"/>')
            else:
                lines.append(f'<path class="fl-line" d="M{ax + BOX_W} {ay + BOX_H // 2} L{bx} {by + BOX_H // 2}"/>')
    for branch in BRANCHES:
        (fx, fy), (bx, by) = places[branch['from']], places[branch['id']]
        if tall:
            lines.append(f'<path class="fl-line fl-branch" d="M{fx + BOX_W} {fy + BOX_H // 2} L{bx} {by + BOX_H // 2}"/>')
        else:
            lines.append(f'<path class="fl-line fl-branch" d="M{fx + BOX_W // 2} {fy + BOX_H} L{bx + BOX_W // 2} {by}"/>')
    return ''.join(lines)


STYLE = ('<style>.flowpic{--fl-line:#9aa093;--fl-box:#f4f5f1;--fl-ink:#2f312d;--fl-soft:#6b6e66;--fl-edge:#c9ccc4}'
         '@media (prefers-color-scheme: dark){.flowpic{--fl-line:#6a6e66;--fl-box:#2b2d2a;--fl-ink:#e6e7e3;--fl-soft:#a9aca4;--fl-edge:#50534d}}'
         '.flowpic svg{width:100%;height:auto;display:block}.flowpic .tall{display:none}'
         '@media (max-width:760px){.flowpic .wide{display:none}.flowpic .tall{display:block;max-width:360px;margin:0 auto}}'
         '.flowpic .fl-box{fill:var(--fl-box);stroke:var(--fl-edge);stroke-width:1.5}.flowpic .fl-off{fill:none;stroke-dasharray:6 5}'
         '.flowpic .fl-label{font:600 14px system-ui,sans-serif;fill:var(--fl-ink)}.flowpic .fl-note{font:11px system-ui,sans-serif;fill:var(--fl-soft)}'
         '.flowpic .fl-num{font:700 16px system-ui,sans-serif;fill:var(--fl-ink)}'
         '.flowpic .fl-line{fill:none;stroke:var(--fl-line);stroke-width:2.5;marker-end:url(#fl-head)}.flowpic .fl-branch{stroke-dasharray:4 4}'
         '.flowpic a.fl-item:focus .fl-box,.flowpic a.fl-item:hover .fl-box{stroke:var(--fl-ink);stroke-width:2.5}'
         '.flowpic .fl-lane{font:600 12px system-ui,sans-serif;fill:var(--fl-soft);letter-spacing:.04em}</style>')


def render(flow, stats, lang='en', link=None, theme='default'):
    """The picture as HTML: a wide and a tall SVG (the page shows one by width), the stages linked to the mail search."""
    flags = (flow or {}).get('flags') or {}
    theme = theme if THEME_RE.match(theme or '') else 'default'
    numbers = counters(stats)
    link = link or (lambda item: '')
    lanes = {'in': 'EINGEHEND, PORT 25' if lang == 'de' else 'INCOMING, PORT 25',
             'out': 'AUSGEHEND, PORT 587 UND RELAYS' if lang == 'de' else 'OUTGOING, PORT 587 AND RELAYS'}
    parts = []
    for tall in (False, True):
        places, width, height = layout(tall)
        body = [_arrows(places, tall)]
        for item in STAGES + BRANCHES:
            body.append(_box(item, *places[item['id']], flags, numbers, theme, lang, link))
        if not tall:
            body.append(f'<text x="20" y="14" class="fl-lane">{lanes["in"]}</text><text x="20" y="260" class="fl-lane">{lanes["out"]}</text>')
        summary = (f"Mailfluss: {numbers.get('processed', '–')} Mails heute geprüft" if lang == 'de'
                   else f"Mail flow: {numbers.get('processed', '–')} mails checked today")
        parts.append(f'<svg class="{"tall" if tall else "wide"}" viewBox="0 0 {width} {height}" role="img" aria-label="{html.escape(summary)}">'
                     '<defs><marker id="fl-head" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
                     '<path d="M0 0L10 5L0 10z" fill="var(--fl-line)"/></marker></defs>' + ''.join(body) + '</svg>')
    return f'<div class="flowpic">{STYLE}{"".join(parts)}</div>'


def themes(folder=THEME_DIR):
    """The theme folders that hold every icon; default first."""
    import os
    try:
        names = sorted(name for name in os.listdir(folder) if THEME_RE.match(name)
                       and all(os.path.isfile(os.path.join(folder, name, icon + '.svg')) for icon in ICONS))
    except OSError:
        return ['default']
    return sorted(names, key=lambda name: name != 'default') or ['default']


def self_test():
    import os
    import tempfile
    stats = {'today': {'processed': 120, 'clean': 80, 'spam': 15, 'high_spam': 10, 'viruses': 2, 'blocked_files': 1},
             'queues': {'counts': {'deferred': {'in': 1, 'out': 4}, 'hold': {'in': 3, 'out': 0}}}}
    assert counters(stats) == {'processed': 120, 'delivered': 95, 'rejected': 13, 'hold': 3, 'outgoing': 4}
    assert counters({'today': {'processed': 1}}) == {'processed': 1, 'delivered': 0, 'rejected': 0} and counters(None) == {}
    for tall in (False, True):
        places, width, height = layout(tall)
        assert set(places) == {item['id'] for item in STAGES + BRANCHES}
        boxes = sorted(places.values())
        # No two boxes overlap, and all lie in the picture.
        for (ax, ay), (bx, by) in zip(boxes, boxes[1:]):
            assert abs(ax - bx) >= BOX_W or abs(ay - by) >= BOX_H, (tall, ax, ay, bx, by)
        assert all(0 <= x and x + BOX_W <= width and 0 <= y and y + BOX_H <= height for x, y in boxes), (tall, width, height)
    assert layout()[1:] == (1200, 352)
    picture = render({'flags': {'cdr': False, 'outbound': True, 'uq': True, 'hold': False}}, stats, 'de',
                     lambda item: '/p/log?text=' + item['search'] if 'search' in item else '', theme='../x')
    assert picture.count('<svg') == 2 and 'Spam &amp; Virus' in picture and '>120<' in picture and '>13<' in picture
    assert picture.count('class="fl-box fl-off"') == 4, 'CDR and the admin hold dashed, in both forms'
    # Every text fits its box: a long label or note line is squeezed (textLength), a note breaks after a comma into two lines.
    assert _lines('blocklists, protocol checks') == ['blocklists,', 'protocol checks'] and _lines('check, sign') == ['check, sign']
    assert 'textLength="96"' in picture and 'Benutzer-Quarant' in picture and _fit('Internet', 14, 96) == ''
    assert '/flow-icon/default/cdr.svg' in picture and '../x' not in picture and '<script' not in picture and 'MTA-STS' not in picture
    assert 'href="/p/log?text=result:reject"' in picture and 'href="/p/log?text=result:no_action"' in picture
    with tempfile.TemporaryDirectory() as folder:
        for name, icons in (('default', ICONS), ('dark', ICONS), ('half', ICONS[:2]), ('Bad', ICONS)):
            os.makedirs(os.path.join(folder, name))
            for icon in icons:
                open(os.path.join(folder, name, icon + '.svg'), 'w').close()
        assert themes(folder) == ['default', 'dark'], 'only complete themes, default first'
    assert themes('/nonexistent') == ['default']
    print('efa_flow self-test ok')


if __name__ == '__main__':
    self_test()
