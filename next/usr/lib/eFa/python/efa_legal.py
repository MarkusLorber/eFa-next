# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The legal texts of eFa-next (5y): LICENSE, DISCLAIMER.md and THIRD-PARTY-NOTICES.md, their digest, and a PDF of each and of
all, made at build time with efa_pdf and installed in FOLDER. A new digest asks for a new confirmation: on the console by
typing ja or yes (or --accept-legal=<digest> unattended), in the web interface with a checkbox before any admin page."""
import hashlib
import json
import os
import sys

NAMES = ('LICENSE', 'DISCLAIMER.md', 'THIRD-PARTY-NOTICES.md')
FOLDER = '/usr/share/eFa/legal'
ACCEPTED = '/etc/eFa/legal-accepted.json'
PDF_NAMES = {'LICENSE': 'license.pdf', 'DISCLAIMER.md': 'disclaimer.pdf', 'THIRD-PARTY-NOTICES.md': 'third-party-notices.pdf'}
ALL_PDF = 'legal-all.pdf'
SUMMARY = {
    'en': ('eFa-next is free software under the GNU Affero General Public License 3.0 or later (LICENSE). It is a mail filter server '
           'for qualified administrators of businesses and organisations, not for consumers. It comes without any warranty; to the '
           'maximum extent permitted by applicable law, its authors, contributors and sponsors are not liable for any damage '
           '(DISCLAIMER.md). Third-party components keep their own licenses (THIRD-PARTY-NOTICES.md).'),
    'de': ('eFa-next ist freie Software unter der GNU Affero General Public License 3.0 oder neuer (LICENSE). Es ist ein Mailfilter-Server '
           'für fachkundige Administratoren von Unternehmen und Organisationen, nicht für Verbraucher. Es gibt keine Gewährleistung; soweit '
           'gesetzlich zulässig, haften Autoren, Mitwirkende und Sponsoren für keine Schäden (DISCLAIMER.md). Komponenten Dritter behalten '
           'ihre eigenen Lizenzen (THIRD-PARTY-NOTICES.md).'),
}
# The digest a person can check with standard tools, in the folder with the three texts: the same 16 hex digits as digest().
SHELL_DIGEST = ("for f in LICENSE DISCLAIMER.md THIRD-PARTY-NOTICES.md; do printf '%s\\0' \"$f\"; cat \"$f\"; printf '\\0'; done "
                "| sha256sum | cut -c1-16")
CONFIRM = {'en': 'I am a qualified administrator and do not use eFa-next as a consumer. I have read the legal texts and accept them.',
           'de': 'Ich bin fachkundiger Administrator und nutze eFa-next nicht als Verbraucher. Ich habe die Rechtstexte gelesen und akzeptiere sie.'}


def digest(texts):
    """The first 16 hex digits of SHA-256 over the names and texts: what a confirmation is for."""
    found = hashlib.sha256()
    for name in NAMES:
        found.update(name.encode() + b'\0' + texts[name].encode('utf-8') + b'\0')
    return found.hexdigest()[:16]


# The terms an admin accepts: LICENSE and DISCLAIMER.md. THIRD-PARTY-NOTICES.md lists the licenses of the parts and changes with
# them; owner, 2026-11-13: after an update no new confirmation while the terms are the same and they were accepted before.
TERMS = ('LICENSE', 'DISCLAIMER.md')
# The digests of the released versions (all three texts) with the digest of their terms, for a confirmation of before that has
# no terms field: 6.0.0.4 to 6.0.0.6 have the same LICENSE and DISCLAIMER.md.
RELEASED_TERMS = {'225a332075533ba5': '76490f1b9f53d68d', '01d90ce54b3223db': '76490f1b9f53d68d', 'c1628493503b5b70': '76490f1b9f53d68d',
                  '2b48d76e88e9c049': '76490f1b9f53d68d'}


def terms_digest(texts):
    """The first 16 hex digits of SHA-256 over the names and texts of the terms only (as digest(), without the notices)."""
    found = hashlib.sha256()
    for name in TERMS:
        found.update(name.encode() + b'\0' + texts[name].encode('utf-8') + b'\0')
    return found.hexdigest()[:16]


def carry_over(record, now_digest, now_terms):
    """The confirmation for the installed texts made from one of before, or None: only when it was a real confirmation (a digest,
    when and who) and its terms are the same as now. A confirmation of other terms, or none, asks again."""
    if not isinstance(record, dict) or not all(record.get(key) for key in ('digest', 'when', 'who')) or not now_digest or not now_terms:
        return None
    if record['digest'] == now_digest:
        return None  # holds already
    if (record.get('terms') or RELEASED_TERMS.get(record['digest'])) != now_terms:
        return None
    return {**record, 'digest': now_digest, 'terms': now_terms, 'carried_from': record['digest']}


def read_texts(folder):
    with_texts = {}
    for name in NAMES:
        with open(os.path.join(folder, name), encoding='utf-8') as f:
            with_texts[name] = f.read()
    return with_texts


def find_texts(*folders):
    """The texts from the first folder that has all three: the installed ones, or a checkout next to a program."""
    for folder in folders:
        if all(os.path.exists(os.path.join(folder, name)) for name in NAMES):
            return read_texts(folder)
    return None


def current(folder=None):
    """The digest of the installed texts, or None without them."""
    try:
        with open(os.path.join(folder or FOLDER, 'digest.txt')) as f:
            return f.read().strip() or None
    except OSError:
        return None


def accepted(path=None, now_digest=None):
    """The confirmation that holds for the installed texts, or None."""
    now_digest = now_digest or current()
    try:
        with open(path or ACCEPTED) as f:
            found = json.load(f)
    except (OSError, ValueError):
        return None
    return found if now_digest and found.get('digest') == now_digest else None


def _pdf_lib(here):
    sys.path.insert(0, here)
    import efa_pdf
    return efa_pdf


def pdf(title, text, version, the_digest, lib):
    """One PDF: eFa-next, the version and the digest on top, then the text. No date in it: the same source, the same PDF."""
    head = [f'eFa-next {version}: {title}', f'Version {version} - SHA-256 (16) der Rechtstexte / of the legal texts: {the_digest}', '']
    return lib.build(head + text.replace('\r\n', '\n').split('\n'),
                     info={'Title': f'eFa-next {version} {title}', 'Producer': 'eFa-next', 'Creator': 'eFa-next'})


def build(top, out, version):
    """At build time: the texts, digest.txt, the summary and a PDF of each and of all into out (FOLDER in the package)."""
    texts = read_texts(top)
    the_digest = digest(texts)
    lib = _pdf_lib(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(out, exist_ok=True)
    for name, text in texts.items():
        with open(os.path.join(out, name), 'w', encoding='utf-8') as f:
            f.write(text)
        with open(os.path.join(out, PDF_NAMES[name]), 'wb') as f:
            f.write(pdf(name, text, version, the_digest, lib))
    joined = '\n'.join([SUMMARY['de'], '', SUMMARY['en']] + [f'\n\n==== {name} ====\n\n{texts[name]}' for name in NAMES])
    with open(os.path.join(out, ALL_PDF), 'wb') as f:
        f.write(pdf('Rechtstexte / Legal texts', joined, version, the_digest, lib))
    with open(os.path.join(out, 'digest.txt'), 'w') as f:
        f.write(the_digest + '\n')
    with open(os.path.join(out, 'summary.json'), 'w', encoding='utf-8') as f:
        json.dump({'digest': the_digest, 'version': version, 'summary': SUMMARY, 'confirm': CONFIRM}, f, ensure_ascii=False, indent=1)
    return the_digest


def console_confirm(texts_digest, folder, given=None, ask=input, say=print):
    """True when the person at the console typed ja or yes, or --accept-legal names this digest; else nothing may change."""
    if given is not None:
        if given == texts_digest:
            return True
        say(f'--accept-legal={given} does not match the legal texts ({texts_digest}). Nothing was changed.')
        return False
    say(SUMMARY['de'] + '\n\n' + SUMMARY['en'] + '\n')
    say('Texte / Texts: ' + ', '.join(os.path.join(folder, name) for name in NAMES))
    if os.path.exists(os.path.join(FOLDER, ALL_PDF)):
        say(f'PDF: {os.path.join(FOLDER, ALL_PDF)}')
    say(f'Digest of these texts / Prüfsumme dieser Texte: {texts_digest}\n'
        f'  (the first 16 hex digits of SHA-256 over the name and text of each file; in {folder}: {SHELL_DIGEST})\n'
        f'Unattended, after reading them / ohne Rückfrage, nach dem Lesen: --accept-legal={texts_digest}\n')
    say(CONFIRM['de'] + '\n' + CONFIRM['en'])
    try:
        answer = ask('Zum Bestätigen ja eintippen / type yes to confirm: ').strip().lower()
    except EOFError:
        answer = ''
    if answer in ('ja', 'yes'):
        return True
    say('Nicht bestätigt, nichts wurde geändert. / Not confirmed, nothing was changed.')
    return False


def self_test():
    import subprocess
    import tempfile
    here = os.path.dirname(os.path.abspath(__file__))
    with tempfile.TemporaryDirectory() as tmp:
        for name in NAMES:
            with open(os.path.join(tmp, name), 'w', encoding='utf-8') as f:
                f.write(f'{name}\nÄrger & (Klammern) \\ Backslash\n')
        out = os.path.join(tmp, 'out')
        first = build(tmp, out, '9.9.9')
        assert current(out) == first and len(first) == 16
        again = os.path.join(tmp, 'again')
        assert build(tmp, again, '9.9.9') == first
        assert all(open(os.path.join(out, item), 'rb').read() == open(os.path.join(again, item), 'rb').read() for item in os.listdir(out)), \
            'the same texts, the same files'
        lib = _pdf_lib(here)
        page = b''.join(lib.page_streams(open(os.path.join(out, ALL_PDF), 'rb').read()))
        assert first.encode() in page and b'9.9.9' in page and b'\xc4rger' in page, 'version, digest and umlauts in the PDF'
        if subprocess.run(['sh', '-c', 'command -v qpdf'], capture_output=True).returncode == 0:
            for item in (*PDF_NAMES.values(), ALL_PDF):
                assert subprocess.run(['qpdf', '--check', os.path.join(out, item)], capture_output=True).returncode == 0, item
        with open(os.path.join(tmp, 'DISCLAIMER.md'), 'a', encoding='utf-8') as f:
            f.write('changed\n')
        assert digest(read_texts(tmp)) != first, 'a changed text, a new digest'
        path = os.path.join(tmp, 'accepted.json')
        with open(path, 'w') as f:
            json.dump({'digest': first, 'who': 'console'}, f)
        assert accepted(path, first)['who'] == 'console' and accepted(path, '0' * 16) is None and accepted(path + 'x', first) is None
        said = []
        assert console_confirm(first, tmp, ask=lambda prompt: ' Ja ', say=said.append) and any('Rechtstexte' in line for line in said)
        assert not console_confirm(first, tmp, ask=lambda prompt: 'j', say=said.append)
        assert not console_confirm(first, tmp, ask=lambda prompt: (_ for _ in ()).throw(EOFError()), say=said.append), 'no console: no'
        assert console_confirm(first, tmp, given=first, say=said.append) and not console_confirm(first, tmp, given='abc', say=said.append)
        # Owner, 2026-11-13: a confirmation of the same terms carries over (the notices changed); other terms or none: asked again.
        texts = read_texts(tmp)
        terms = terms_digest(texts)
        before = {'digest': '0123456789abcdef', 'terms': terms, 'when': '2026-11-01 10:00:00 +0100', 'who': 'admin (web)'}
        moved = carry_over(before, digest(texts), terms)
        assert moved['digest'] == digest(texts) and moved['carried_from'] == '0123456789abcdef' and moved['who'] == 'admin (web)'
        assert carry_over({**before, 'terms': 'f' * 16}, digest(texts), terms) is None, 'other terms: ask again'
        assert carry_over(None, digest(texts), terms) is None and carry_over({'digest': 'x' * 16}, digest(texts), terms) is None, 'none: ask'
        assert carry_over({**before, 'digest': digest(texts)}, digest(texts), terms) is None, 'holds already'
        assert carry_over({k: v for k, v in before.items() if k != 'terms'}, digest(texts), terms) is None, 'unknown digest without terms'
        legacy = {'digest': 'c1628493503b5b70', 'when': '2026-11-05 09:00:00 +0100', 'who': 'console (root)'}
        assert carry_over(legacy, '2b48d76e88e9c049', '76490f1b9f53d68d')['carried_from'] == 'c1628493503b5b70', '6.0.0.5.2 to 6.0.0.6'
        assert carry_over(legacy, '2b48d76e88e9c049', 'f' * 16) is None, 'changed terms after 6.0.0.5.2: ask'
        joined = os.path.join(here, '..', '..', '..', '..', '..')
        if all(os.path.exists(os.path.join(joined, name)) for name in NAMES):
            source = read_texts(joined)
            assert RELEASED_TERMS.get(digest(source), terms_digest(source)) == terms_digest(source), \
                'the texts of this tree: their terms digest in RELEASED_TERMS is right'
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
