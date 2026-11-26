# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A mail as PDF: its header lines and text on A4 pages, its attachments embedded as files. Encrypted with qpdf, AES-256."""
import functools
import os
import shutil
import struct
import subprocess
import tempfile
import textwrap
import unicodedata
import zlib

LINE_CHARS = 95
# Only for tests: a qpdf that fails, to see that mail never leaves in clear text.
QPDF = os.environ.get('EFA_QPDF', 'qpdf')
LINES_PER_PAGE = 64


# PDF-1: text the standard font cannot show (Polish, Czech, Greek, Cyrillic ...) is set in DejaVu Sans (package dejavu-sans-fonts),
# embedded only into a PDF that needs it; a PDF in Western European letters stays as small as before. Without the font such
# letters become '?', as before.
FONT_FILES = {b'U1': ('/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf', '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'),
              b'U2': ('/usr/share/fonts/dejavu-sans-fonts/DejaVuSans-Bold.ttf', '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'),
              # G7-24: Chinese, Japanese and Korean from Droid Sans Fallback (package google-droid-sans-fonts, TrueType, EL9 and EL10).
              b'U3': ('/usr/share/fonts/google-droid-sans-fonts/DroidSansFallbackFull.ttf', '/usr/share/fonts/google-droid-sans-fonts/DroidSansFallback.ttf',
                      '/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf')}
UNICODE_OF = {b'F1': b'U1', b'F2': b'U2'}
# A letter the DejaVu font lacks (Chinese, Japanese, Korean) is set in this one, regular for bold too.
FALLBACK = b'U3'
# G7-24: only the glyphs a PDF uses are embedded (P7-17); these tables are of no use in a PDF.
DROP_TABLES = {b'GSUB', b'GPOS', b'GDEF', b'kern', b'DSIG', b'hdmx', b'VDMX', b'LTSH', b'vhea', b'vmtx', b'morx', b'feat', b'JSTF', b'BASE'}


def _text(value):
    return value.encode('cp1252', 'replace').replace(b'\\', b'\\\\').replace(b'(', b'\\(').replace(b')', b'\\)')


def _wide(value):
    return any(unicodedata.east_asian_width(char) in ('W', 'F') for char in value)


def _fits(value):
    try:
        value.encode('cp1252')
        return True
    except UnicodeEncodeError:
        return False


@functools.lru_cache(maxsize=4)
def _font(name):
    """The TrueType font for U1/U2: {data, units, cmap {code point: glyph}, widths [advance], bbox, ascent, descent}; None if missing."""
    path = next((item for item in FONT_FILES[name] if os.path.exists(item)), None)
    if not path:
        return None
    try:
        with open(path, 'rb') as f:
            data = f.read()
        tables = {}
        for index in range(struct.unpack('>H', data[4:6])[0]):
            tag, _sum, offset, length = struct.unpack('>4sIII', data[12 + 16 * index:28 + 16 * index])
            tables[tag] = offset
        head, hhea, hmtx, cmap = tables[b'head'], tables[b'hhea'], tables[b'hmtx'], tables[b'cmap']
        units = struct.unpack('>H', data[head + 18:head + 20])[0]
        bbox = struct.unpack('>4h', data[head + 36:head + 44])
        ascent, descent = struct.unpack('>2h', data[hhea + 4:hhea + 8])
        metrics = struct.unpack('>H', data[hhea + 34:hhea + 36])[0]
        widths = [struct.unpack('>H', data[hmtx + 4 * index:hmtx + 4 * index + 2])[0] for index in range(metrics)]
        mapping = {}
        subtables = struct.unpack('>H', data[cmap + 2:cmap + 4])[0]
        found = {}
        for index in range(subtables):
            platform, encoding, offset = struct.unpack('>HHI', data[cmap + 4 + 8 * index:cmap + 12 + 8 * index])
            found[(platform, encoding)] = cmap + offset
        if (3, 10) in found and struct.unpack('>H', data[found[(3, 10)]:found[(3, 10)] + 2])[0] == 12:
            at = found[(3, 10)]
            for group in range(struct.unpack('>I', data[at + 12:at + 16])[0]):
                start, end, glyph = struct.unpack('>3I', data[at + 16 + 12 * group:at + 28 + 12 * group])
                for code in range(start, min(end, start + 65536) + 1):
                    mapping[code] = glyph + code - start
        else:
            at = found[(3, 1)]
            count = struct.unpack('>H', data[at + 6:at + 8])[0] // 2
            ends = struct.unpack(f'>{count}H', data[at + 14:at + 14 + 2 * count])
            starts_at = at + 16 + 2 * count
            starts = struct.unpack(f'>{count}H', data[starts_at:starts_at + 2 * count])
            deltas = struct.unpack(f'>{count}h', data[starts_at + 2 * count:starts_at + 4 * count])
            ranges_at = starts_at + 4 * count
            ranges = struct.unpack(f'>{count}H', data[ranges_at:ranges_at + 2 * count])
            for segment in range(count):
                for code in range(starts[segment], ends[segment] + 1):
                    if code == 0xFFFF:
                        continue
                    if ranges[segment] == 0:
                        glyph = (code + deltas[segment]) & 0xFFFF
                    else:
                        where = ranges_at + 2 * segment + ranges[segment] + 2 * (code - starts[segment])
                        glyph = struct.unpack('>H', data[where:where + 2])[0]
                        glyph = (glyph + deltas[segment]) & 0xFFFF if glyph else 0
                    if glyph:
                        mapping[code] = glyph
        return {'data': data, 'units': units, 'cmap': mapping, 'widths': widths, 'bbox': bbox, 'ascent': ascent, 'descent': descent,
                'name': os.path.basename(path)[:-4].encode()}
    except (OSError, KeyError, struct.error, ValueError):
        return None


def _show(font, size, value, used):
    """Font selection and show operator for one run of text: WinAnsi with the standard font where it fits, else glyph ids of the
    embedded fonts (used collects them per font for _assemble). G7-24: right-to-left text (Arabic, Hebrew) in visual order,
    Arabic in its joined forms; a letter DejaVu lacks (Chinese, Japanese, Korean) from the fallback font."""
    if _fits(value) or _font(UNICODE_OF[font]) is None:
        return b'/%s %s Tf (%s) Tj' % (font, str(size).encode(), _text(value))
    value = visual(value)
    name, fallback = UNICODE_OF[font], _font(FALLBACK)
    runs = []
    for char in value:
        which = name if ord(char) in _font(name)['cmap'] or not fallback or ord(char) not in fallback['cmap'] else FALLBACK
        if runs and runs[-1][0] == which:
            runs[-1][1].append(char)
        else:
            runs.append((which, [char]))
    out = []
    for which, chars in runs:
        cmap = _font(which)['cmap']
        # A letter no font here has (google-droid-sans-fonts not installed) becomes '?', as before PDF-1.
        glyphs = [cmap.get(ord(char)) or cmap.get(ord('?'), 0) for char in chars]
        for char, glyph in zip(chars, glyphs):
            used.setdefault(which, {})[glyph] = char if ord(char) in cmap else '?'
        out.append(b'/%s %s Tf <%s> Tj' % (which, str(size).encode(), ''.join('%04x' % glyph for glyph in glyphs).encode()))
    return b' '.join(out)


# G7-24: right to left. A short form of the bidirectional algorithm (UAX 9) for one line: the direction of its first strong
# letter, neutrals between letters of one direction take it, numbers stay left to right; runs reversed level by level, brackets
# mirrored in right-to-left runs. Arabic letters take their joined forms from the presentation forms of Unicode (stdlib names).
MIRROR = dict(zip('()[]{}<>«»', ')(][}{><»«'))
_FORMS = {}


def _forms(char):
    """(isolated, final, initial, medial) of an Arabic letter, None where Unicode has no such form."""
    if char not in _FORMS:
        found = [None] * 4
        try:
            name = unicodedata.name(char)
        except ValueError:
            name = ''
        if name.startswith('ARABIC LETTER '):
            for index, form in enumerate(('ISOLATED', 'FINAL', 'INITIAL', 'MEDIAL')):
                try:
                    found[index] = unicodedata.lookup(f'{name} {form} FORM')
                except KeyError:
                    pass
        _FORMS[char] = tuple(found)
    return _FORMS[char]


LAM_ALEF = {'\u0622': ('\ufef5', '\ufef6'), '\u0623': ('\ufef7', '\ufef8'), '\u0625': ('\ufef9', '\ufefa'), '\u0627': ('\ufefb', '\ufefc')}


def shape(text):
    """Arabic letters in their isolated, final, initial or medial form, lam with alef as one ligature (logical order kept)."""
    if not any('\u0600' <= char <= '\u06ff' for char in text):
        return text
    chars = list(text)
    letters = [i for i, char in enumerate(chars) if unicodedata.category(char) != 'Mn']

    def joins_left(i):  # this letter connects to the letter after it
        forms = _forms(chars[i])
        return forms[2] is not None and forms[3] is not None

    def joins_right(i):  # this letter connects to the letter before it
        return _forms(chars[i])[1] is not None
    out = list(chars)
    skip = set()
    for pos, i in enumerate(letters):
        if i in skip:
            continue
        before = letters[pos - 1] if pos > 0 else None
        after = letters[pos + 1] if pos + 1 < len(letters) else None
        connect_before = before is not None and before not in skip and joins_left(before) and joins_right(i)
        if chars[i] == '\u0644' and after is not None and chars[after] in LAM_ALEF:
            out[i] = LAM_ALEF[chars[after]][1 if connect_before else 0]
            out[after] = ''
            skip.add(after)
            continue
        forms = _forms(chars[i])
        if forms[0] is None:
            continue
        connect_after = after is not None and joins_left(i) and joins_right(after)
        form = (forms[3] if connect_before and connect_after else forms[1] if connect_before else forms[2] if connect_after else forms[0])
        out[i] = form or chars[i]
    return ''.join(out)


def _strong(char):
    kind = unicodedata.bidirectional(char)
    return 'R' if kind in ('R', 'AL') else 'L' if kind in ('L', 'EN', 'AN') else None


def visual(text):
    """The line in the order it is drawn, left to right. Unchanged without right-to-left letters."""
    if not any(_strong(char) == 'R' for char in text):
        return text
    text = shape(text)
    base = next((_strong(char) for char in text if _strong(char)), 'L')
    kinds = [_strong(char) for char in text]
    # Neutrals: the direction of both sides when they agree, else the base direction.
    for i, kind in enumerate(kinds):
        if kind is None:
            left = next((kinds[j] for j in range(i - 1, -1, -1) if kinds[j]), base)
            right = next((_strong(text[j]) for j in range(i + 1, len(text)) if _strong(text[j])), base)
            kinds[i] = left if left == right else base
    if base == 'R':
        levels = [1 if kind == 'R' else 2 for kind in kinds]
    else:
        levels = [1 if kind == 'R' else 0 for kind in kinds]
    chars = [MIRROR.get(char, char) if level % 2 else char for char, level in zip(text, levels)]
    for level in range(max(levels), 0, -1):
        i = 0
        while i < len(chars):
            if levels[i] >= level:
                j = i
                while j < len(chars) and levels[j] >= level:
                    j += 1
                chars[i:j], levels[i:j] = chars[i:j][::-1], levels[i:j][::-1]
                i = j
            else:
                i += 1
    return ''.join(chars)


def _subset(font, glyphs):
    """The TrueType file with only these glyphs (and the parts of composite glyphs they use), the others empty; glyph ids stay,
    so CIDToGIDMap Identity still holds. Tables a PDF does not use are left out."""
    data = font['data']
    tables = {}
    for index in range(struct.unpack('>H', data[4:6])[0]):
        tag, _sum, offset, length = struct.unpack('>4sIII', data[12 + 16 * index:28 + 16 * index])
        tables[tag] = data[offset:offset + length]
    head, maxp = bytearray(tables[b'head']), tables[b'maxp']
    count = struct.unpack('>H', maxp[4:6])[0]
    long_loca = struct.unpack('>h', head[50:52])[0] == 1
    loca = tables[b'loca']
    offsets = (struct.unpack(f'>{count + 1}I', loca[:4 * (count + 1)]) if long_loca
               else [value * 2 for value in struct.unpack(f'>{count + 1}H', loca[:2 * (count + 1)])])
    glyf = tables[b'glyf']
    keep, todo = {0}, [glyph for glyph in glyphs if 0 <= glyph < count]
    while todo:
        glyph = todo.pop()
        if glyph in keep and glyph != 0:
            continue
        keep.add(glyph)
        start, end = offsets[glyph], offsets[glyph + 1]
        if end - start >= 10 and struct.unpack('>h', glyf[start:start + 2])[0] < 0:
            at = start + 10
            while True:
                flags, part = struct.unpack('>HH', glyf[at:at + 4])
                if part not in keep:
                    todo.append(part)
                at += 4 + (4 if flags & 1 else 2) + (8 if flags & 0x80 else 4 if flags & 0x40 else 2 if flags & 0x8 else 0)
                if not flags & 0x20:
                    break
    new_glyf, new_loca = bytearray(), []
    for glyph in range(count):
        new_loca.append(len(new_glyf))
        if glyph in keep:
            new_glyf += glyf[offsets[glyph]:offsets[glyph + 1]]
            new_glyf += b'\0' * (-len(new_glyf) % 4)
    new_loca.append(len(new_glyf))
    head[50:52] = struct.pack('>h', 1)
    head[8:12] = b'\0\0\0\0'
    tables.update({b'glyf': bytes(new_glyf), b'loca': struct.pack(f'>{count + 1}I', *new_loca), b'head': bytes(head)})
    for tag in DROP_TABLES:
        tables.pop(tag, None)

    def checksum(blob):
        blob += b'\0' * (-len(blob) % 4)
        return sum(struct.unpack(f'>{len(blob) // 4}I', blob)) & 0xFFFFFFFF
    tags = sorted(tables)
    power = 1 << (len(tags).bit_length() - 1)
    out = bytearray(struct.pack('>IHHHH', 0x00010000, len(tags), power * 16, power.bit_length() - 1, len(tags) * 16 - power * 16))
    offset = 12 + 16 * len(tags)
    body = bytearray()
    for tag in tags:
        blob = tables[tag]
        out += struct.pack('>4sIII', tag, checksum(blob), offset + len(body), len(blob))
        body += blob + b'\0' * (-len(blob) % 4)
    whole = bytes(out + body)
    adjust = (0xB1B0AFBA - checksum(whole)) & 0xFFFFFFFF
    at = offset + sum(len(tables[tag]) + (-len(tables[tag]) % 4) for tag in tags[:tags.index(b'head')])
    return whole[:at + 8] + struct.pack('>I', adjust) + whole[at + 12:]


def _string(value):
    """A PDF text string (document info, file names): literal where WinAnsi fits, else UTF-16BE with its byte order mark."""
    if _fits(value):
        return b'(' + _text(value) + b')'
    return b'<feff' + value.encode('utf-16-be').hex().encode() + b'>'


def _unicode_font(add, name, glyphs):
    """The objects of a Type0 font with the whole TrueType file embedded, widths and ToUnicode for the glyphs used."""
    font = _font(name)
    scale = 1000.0 / font['units']
    data = _subset(font, set(glyphs))
    packed = zlib.compress(data)
    file_ = add(b'<< /Length %d /Length1 %d /Filter /FlateDecode >>\nstream\n' % (len(packed), len(data)) + packed + b'\nendstream')
    bbox = b' '.join(b'%d' % round(value * scale) for value in font['bbox'])
    descriptor = add(b'<< /Type /FontDescriptor /FontName /%s /Flags 32 /FontBBox [%s] /ItalicAngle 0 /Ascent %d /Descent %d '
                     b'/CapHeight %d /StemV 80 /FontFile2 %d 0 R >>' % (font['name'], bbox, round(font['ascent'] * scale),
                                                                       round(font['descent'] * scale), round(font['ascent'] * scale), file_))
    widths = font['widths']
    w = b' '.join(b'%d [%d]' % (glyph, round(widths[min(glyph, len(widths) - 1)] * scale)) for glyph in sorted(glyphs))
    cid = add(b'<< /Type /Font /Subtype /CIDFontType2 /BaseFont /%s /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) '
              b'/Supplement 0 >> /FontDescriptor %d 0 R /W [%s] /CIDToGIDMap /Identity >>' % (font['name'], descriptor, w))
    pairs = [(glyph, char) for glyph, char in sorted(glyphs.items()) if glyph]
    chunks = [pairs[index:index + 100] for index in range(0, len(pairs), 100)]
    cmap = (b'/CIDInit /ProcSet findresource begin 12 dict begin begincmap /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) '
            b'/Supplement 0 >> def /CMapName /Adobe-Identity-UCS def /CMapType 2 def 1 begincodespacerange <0000> <ffff> endcodespacerange\n'
            + b''.join(b'%d beginbfchar\n' % len(chunk) + b''.join(b'<%04x> <%s>\n' % (glyph, char.encode('utf-16-be').hex().encode())
                                                                     for glyph, char in chunk) + b'endbfchar\n' for chunk in chunks)
            + b'endcmap CMapName currentdict /CMap defineresource pop end end')
    packed = zlib.compress(cmap)
    unicode_map = add(b'<< /Length %d /Filter /FlateDecode >>\nstream\n' % len(packed) + packed + b'\nendstream')
    return add(b'<< /Type /Font /Subtype /Type0 /BaseFont /%s /Encoding /Identity-H /DescendantFonts [%d 0 R] /ToUnicode %d 0 R >>'
               % (font['name'], cid, unicode_map))


def build(lines, attachments=(), info=None):
    """The PDF bytes: lines of text, attachments as (file name, bytes) embedded; info: {'Title': ..., ...} for the document."""
    wrapped = []
    for line in lines:
        # G7-24: Chinese, Japanese and Korean letters are about twice as wide.
        wrapped += textwrap.wrap(line.expandtabs(4), LINE_CHARS // 2 if _wide(line) else LINE_CHARS, replace_whitespace=False, drop_whitespace=False) or ['']
    pages = [wrapped[i:i + LINES_PER_PAGE] for i in range(0, len(wrapped), LINES_PER_PAGE)] or [[]]
    used = {}
    streams = [b'BT /F1 10 Tf 12 TL 50 800 Td\n' + b''.join(_show(b'F1', 10, line, used) + b' T*\n' for line in page) + b'ET' for page in pages]
    return _assemble(streams, attachments, info, used)


def _assemble(streams, attachments=(), info=None, used=None):
    """The PDF around page contents: A4 pages with Helvetica (F1) and Helvetica-Bold (F2), DejaVu Sans (U1, U2) only where used,
    embedded files, document info."""
    objects = []

    def add(body):
        objects.append(body)
        return len(objects)

    catalog = add(None)
    tree = add(None)
    fonts = [add(b'<< /Type /Font /Subtype /Type1 /BaseFont /%s /Encoding /WinAnsiEncoding >>' % name) for name in (b'Helvetica', b'Helvetica-Bold')]
    extra = b''.join(b' /%s %d 0 R' % (name, _unicode_font(add, name, glyphs)) for name, glyphs in sorted((used or {}).items()))
    kids = []
    for stream in streams:
        packed = zlib.compress(stream)
        content = add(b'<< /Length %d /Filter /FlateDecode >>\nstream\n' % len(packed) + packed + b'\nendstream')
        kids.append(add(b'<< /Type /Page /Parent %d 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 %d 0 R /F2 %d 0 R%s >> >> '
                        b'/Contents %d 0 R >>' % (tree, fonts[0], fonts[1], extra, content)))
    objects[tree - 1] = b'<< /Type /Pages /Count %d /Kids [%s] >>' % (len(kids), b' '.join(b'%d 0 R' % kid for kid in kids))
    names = []
    for name, data in attachments:
        packed = zlib.compress(data)
        stream = add(b'<< /Type /EmbeddedFile /Length %d /Filter /FlateDecode /Params << /Size %d >> >>\nstream\n' % (len(packed), len(data))
                     + packed + b'\nendstream')
        spec = add(b'<< /Type /Filespec /F (' + _text(name) + b') /UF ' + _string(name) + b' /EF << /F %d 0 R >> >>' % stream)
        names.append(_string('%03d %s' % (len(names), name)) + b' %d 0 R' % spec)
    files = b' /Names << /EmbeddedFiles << /Names [%s] >> >> /PageMode /UseAttachments' % b' '.join(names) if names else b''
    objects[catalog - 1] = b'<< /Type /Catalog /Pages %d 0 R%s >>' % (tree, files)
    meta = add(b'<< ' + b' '.join(b'/' + key.encode() + b' ' + _string(str(value)) for key, value in info.items()) + b' >>') if info else None
    out = bytearray(b'%PDF-1.7\n%\xe2\xe3\xcf\xd3\n')
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b'%d 0 obj\n' % number + body + b'\nendobj\n'
    xref = len(out)
    out += b'xref\n0 %d\n0000000000 65535 f \n' % (len(objects) + 1) + b''.join(b'%010d 00000 n \n' % offset for offset in offsets)
    trailer_info = b' /Info %d 0 R' % meta if meta else b''
    out += b'trailer\n<< /Size %d /Root %d 0 R%s >>\nstartxref\n%d\n%%%%EOF\n' % (len(objects) + 1, catalog, trailer_info, xref)
    return bytes(out)


def page_streams(pdf):
    """The uncompressed contents of the pages (and other streams) of a PDF made here: for tests."""
    found = []
    for part in pdf.split(b'stream\n')[1:]:
        body = part.split(b'\nendstream', 1)[0]
        try:
            found.append(zlib.decompress(body))
        except zlib.error:
            pass
    return found


# 5y and Q5b: reports with a head and foot on every page, headings, text and tables with a colored status mark.
MARGIN, TOP, BOTTOM, WIDTH = 50, 790, 60, 495
STATUS_COLORS = {'ok': (0.753, 0.812, 0.282), 'warning': (0.788, 0.541, 0.0), 'error': (0.722, 0.227, 0.227), 'na': (0.392, 0.396, 0.388)}
GRAY = (0.392, 0.396, 0.388)


def _fit(text, size, width):
    """Lines of at most width points; Helvetica is about half its size wide per letter (wider letters fit, as the guess is low)."""
    # DejaVu Sans (PDF-1) is wider than Helvetica.
    chars = max(int(width / (size * (1.0 if _wide(str(text)) else 0.52 if _fits(str(text)) or _font(b'U1') is None else 0.6))), 8)
    return textwrap.wrap(str(text), chars) or ['']


def report(title, blocks, info=None, footer=''):
    """A report as PDF bytes. blocks: ('h', text), ('p', text) or ('table', [(header, width), ...], rows) with rows of cells,
    where a row may end with a status ('ok', 'warning', 'error', 'na') drawn as a colored mark in front of the first cell.
    Every page gets the title on top and "page X / Y" with footer at the bottom."""
    pages, ops, used = [], [], {}
    y = TOP - 30

    def new_page():
        nonlocal ops, y
        ops = []
        pages.append(ops)
        y = TOP - 30

    def text(x, line, size=10, bold=False, color=(0, 0, 0)):
        ops.append(b'%.3f %.3f %.3f rg BT %.1f %.1f Td %s ET' % (*color, x, y, _show(b'F2' if bold else b'F1', size, line, used)))

    def room(height):
        if y - height < BOTTOM:
            new_page()

    new_page()
    for block in blocks:
        if block[0] == 'h':
            room(30)
            y -= 8
            text(MARGIN, block[1], 13, True)
            y -= 20
        elif block[0] == 'p':
            for line in _fit(block[1], 10, WIDTH):
                room(14)
                text(MARGIN, line)
                y -= 14
            y -= 4
        elif block[0] == 'table':
            columns, rows = block[1], block[2]

            def header():
                nonlocal y
                x = MARGIN
                for name, width in columns:
                    text(x, name, 9, True, GRAY)
                    x += width
                ops.append(b'%.3f %.3f %.3f RG 0.5 w %d %.1f m %d %.1f l S' % (*GRAY, MARGIN, y - 4, MARGIN + WIDTH, y - 4))
                y -= 16
            room(40)
            header()
            for row in rows:
                status = row[-1] if len(row) > len(columns) else None
                cells = [_fit(cell, 9, width - 14 if index == 0 else width - 6) for index, (cell, (_name, width)) in enumerate(zip(row, columns))]
                height = max(len(lines) for lines in cells) * 11 + 5
                if y - height < BOTTOM:
                    new_page()
                    header()
                if status:
                    ops.append(b'%.3f %.3f %.3f rg %d %.1f 8 8 re f' % (*STATUS_COLORS.get(status, GRAY), MARGIN, y - 1))
                x = MARGIN
                for index, ((_name, width), lines) in enumerate(zip(columns, cells)):
                    keep = y
                    for line in lines:
                        text(x + (14 if index == 0 else 0), line, 9)
                        y -= 11
                    y = keep
                    x += width
                y -= height
            y -= 6
    streams = []
    for number, page in enumerate(pages, 1):
        y = TOP + 18
        ops = page
        text(MARGIN, title, 9, True, GRAY)
        ops.append(b'%.3f %.3f %.3f RG 0.5 w %d %d m %d %d l S' % (*GRAY, MARGIN, TOP + 12, MARGIN + WIDTH, TOP + 12))
        y = 30
        text(MARGIN, footer, 8, False, GRAY)
        mark = f'page {number} / {len(pages)}'
        text(MARGIN + WIDTH - len(mark) * 4.2, mark, 8, False, GRAY)
        streams.append(b'\n'.join(page))
    return _assemble(streams, (), info, used)


def available():
    return shutil.which(QPDF) is not None


def encrypt(pdf, password):
    """The PDF encrypted with AES-256. The password goes to qpdf in a file of its own, not on the command line."""
    with tempfile.TemporaryDirectory() as folder:
        plain, sealed, args = (os.path.join(folder, name) for name in ('in.pdf', 'out.pdf', 'args'))
        with open(plain, 'wb') as f:
            f.write(pdf)
        fd = os.open(args, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write('\n'.join(['--encrypt', password, os.urandom(24).hex(), '256', '--', plain, sealed]) + '\n')
        done = subprocess.run([QPDF, '@' + args], capture_output=True, text=True, timeout=120)
        if done.returncode not in (0, 3):  # 3: done, with warnings
            raise RuntimeError(f'qpdf failed: {done.stderr.strip()[:200]}')
        with open(sealed, 'rb') as f:
            return f.read()


def self_test():
    pdf = build(['From: anna@own.example', 'Subject: Offer (draft) \\ test', '', 'Grüße ' * 40, 'x'] * 30, [('a.txt', b'hello')])
    assert pdf.startswith(b'%PDF-1.7') and pdf.rstrip().endswith(b'%%EOF') and b'/EmbeddedFiles' in pdf and b'/Count 4 ' in pdf, pdf[:200]
    assert b'Offer \\(draft\\) \\\\ test' in zlib.decompress(pdf.split(b'stream\n', 1)[1].split(b'\nendstream', 1)[0])
    start = int(pdf.rsplit(b'startxref\n', 1)[1].split(b'\n', 1)[0])
    assert pdf[start:start + 4] == b'xref'
    if available():
        sealed = encrypt(pdf, 'test password')
        assert b'/Encrypt' in sealed and b'/AESV3' in sealed and b'Offer' not in sealed
        with tempfile.NamedTemporaryFile(suffix='.pdf') as f:
            f.write(sealed)
            f.flush()
            done = subprocess.run(['qpdf', '--password=test password', '--check', f.name], capture_output=True)
            wrong = subprocess.run(['qpdf', '--password=wrong', '--check', f.name], capture_output=True)
        assert done.returncode in (0, 3) and b'No syntax or stream encoding errors' in done.stdout, (done.stdout[-300:], done.stderr[-300:])
        assert wrong.returncode == 2 and b'invalid password' in wrong.stderr, wrong.stderr[-300:]
    global QPDF
    if shutil.which('false'):
        QPDF, kept = 'false', QPDF
        try:
            encrypt(pdf, 'x')
            raise AssertionError('a failing qpdf must raise')
        except RuntimeError:
            pass
        finally:
            QPDF = kept
    # Reports: head and foot with the page count, umlauts in WinAnsi, a table that runs over pages, colored marks.
    rows = [(f'C-{number}', 'Prüfung Größe ' * (number % 3 + 1), 'Grüße, über das Maß', ('ok', 'warning', 'error', 'na')[number % 4])
            for number in range(120)]
    pdf = report('Härtungsbericht mx.example', [('h', 'Übersicht'), ('p', 'Ein Absatz mit Umlauten: äöü ÄÖÜ ß. ' * 8),
                                                 ('table', [('ID', 60), ('Prüfung', 260), ('Hinweis', 175)], rows)],
                 info={'Title': 'Härtungsbericht', 'Producer': 'eFa-next', 'Creator': 'eFa-next'}, footer='eFa-next')
    text = b''.join(page_streams(pdf))
    pages = int(pdf.split(b'/Count ', 1)[1].split(b' ', 1)[0])
    assert pages >= 3 and b'page 1 / %d' % pages in text and b'page %d / %d' % (pages, pages) in text, pages
    assert b'\xdcbersicht' in text and b'Gr\xfc\xdfe' in text and b'C-119' in text, 'WinAnsi umlauts and every row'
    assert b'0.753 0.812 0.282 rg' in text and b'0.722 0.227 0.227 rg' in text and b'/F2' in text, 'status colors and bold'
    assert b'/Producer (eFa-next)' in pdf and b'/Title (H\xe4rtungsbericht)' in pdf
    if shutil.which('qpdf'):
        with tempfile.NamedTemporaryFile(suffix='.pdf') as f:
            f.write(pdf)
            f.flush()
            done = subprocess.run(['qpdf', '--check', f.name], capture_output=True)
        assert done.returncode == 0 and b'No syntax or stream encoding errors' in done.stdout, done.stdout[-300:]
    # PDF-1: letters outside WinAnsi in DejaVu Sans, embedded only then; without the font they stay '?' as before.
    if _font(b'U1') is not None:
        plain = build(['Grüße'])
        assert b'/U1' not in plain and b'FontFile2' not in plain, 'a Western European PDF embeds no font'
        mixed = report('Bericht Łódź', [('p', 'Žluťoučký kůň, Ελληνικά, Кириллица')], info={'Title': 'Łódź'})
        text = b''.join(page_streams(mixed))
        assert b'/FontFile2' in mixed and b'/Identity-H' in mixed and b'/ToUnicode' in mixed and b'/U1 10 Tf <' in text, 'embedded'
        assert b'/U2 9 Tf <' in text and b'%04x' % _font(b'U1')['cmap'][ord('Ł')] in text, 'bold title and the glyph of the letter'
        assert b'<feff' + 'Łódź'.encode('utf-16-be').hex().encode() + b'>' in mixed, 'title as UTF-16'
        if shutil.which('qpdf'):
            with tempfile.NamedTemporaryFile(suffix='.pdf') as f:
                f.write(mixed)
                f.flush()
                done = subprocess.run(['qpdf', '--check', f.name], capture_output=True)
            assert done.returncode == 0 and b'No syntax or stream encoding errors' in done.stdout, done.stdout[-300:]
        if shutil.which('pdftotext'):
            with tempfile.NamedTemporaryFile(suffix='.pdf') as f:
                f.write(mixed)
                f.flush()
                done = subprocess.run(['pdftotext', f.name, '-'], capture_output=True)
            assert 'Žluťoučký kůň' in done.stdout.decode() and 'Кириллица' in done.stdout.decode(), done.stdout[:300]
    # G7-24: only the glyphs used are embedded; Chinese, Japanese and Korean from the fallback font; Arabic and Hebrew right to left.
    assert visual('abc') == 'abc' and visual('שלום world') == 'world םולש', visual('שלום world')
    assert visual('Total: שלום (2)') == 'Total: םולש (2)', visual('Total: שלום (2)')
    assert shape('\u0628\u0628\u0628') == '\ufe91\ufe92\ufe90' and shape('\u0644\u0627') == '\ufefb', [hex(ord(c)) for c in shape('\u0644\u0627')]
    assert shape('\u0627\u0628') == '\ufe8d\ufe8f', 'alef does not join to the left'
    if _font(b'U1') is not None:
        small = report('x', [('p', 'Łódź')])
        assert len(small) < 60000, f'a subset, not the whole DejaVu font: {len(small)} bytes'
        rtl = report('x', [('p', 'مرحبا بالعالم'), ('p', 'שלום עולם')])
        assert b'%04x' % _font(b'U1')['cmap'][ord('\ufee3')] in b''.join(page_streams(rtl)), 'meem in its initial form'
        if shutil.which('qpdf'):
            for blob in (small, rtl):
                with tempfile.NamedTemporaryFile(suffix='.pdf') as f:
                    f.write(blob)
                    f.flush()
                    done = subprocess.run(['qpdf', '--check', f.name], capture_output=True)
                assert done.returncode == 0, done.stdout[-300:]
    if _font(b'U1') is not None and _font(FALLBACK) is not None:
        cjk = report('报告', [('p', '中文测试 日本語のテスト 한국어 시험 and Latin')])
        text = b''.join(page_streams(cjk))
        assert b'/U3 10 Tf <' in text and b'/U1 10 Tf <' in text and len(cjk) < 200000, len(cjk)
        if shutil.which('pdftotext'):
            with tempfile.NamedTemporaryFile(suffix='.pdf') as f:
                f.write(cjk)
                f.flush()
                done = subprocess.run(['pdftotext', f.name, '-'], capture_output=True)
            assert '中文测试' in done.stdout.decode() and '한국어' in done.stdout.decode(), done.stdout[:300]
    print('self-test ok')


if __name__ == '__main__':
    self_test()
