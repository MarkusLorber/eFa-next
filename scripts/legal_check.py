# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The legal texts of eFa-next as they must be (rules L1 to L15), called by scripts/license_check.py; L10 (the SPDX, copyright
and author lines of every source file) stays there.

Each rule only reads the files. A wrong legal text is never changed here: it is reported, and only the owner changes it.
"""
import ast
import hashlib
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DISCLAIMER = 'DISCLAIMER.md'
COPYRIGHT = 'Copyright (C) 2026 Markus Lorber and eFa-next contributors'
AUTHOR = 'Author: Markus Lorber, Lukasz Galusinski'
# DISCLAIMER.md holds both languages, each a "## " part; intended use and liability are "### " sections, the severability
# clause is a bold paragraph at the end of the liability section.
LANGUAGES = {'en': 'English', 'de': 'Deutsch'}
SECTIONS = {'en': ('Intended use', 'Warranty and liability', 'Severability'),
            'de': ('Bestimmungsgemäßer Gebrauch', 'Gewährleistung und Haftung', 'Salvatorische Klausel')}
QUALIFIER = {'en': re.compile(r'to the maximum extent permitted by (applicable )?law', re.I), 'de': re.compile(r'soweit gesetzlich zulässig', re.I)}
EXCLUSION = {'en': re.compile(r'\b(liable|liability|warrant(y|ies)|without any promise)\b', re.I),
             'de': re.compile(r'\b(haften|haftet|Haftung|Gewährleistung|ohne jede Zusage)\b', re.I)}
PARTIES = {'en': ('Markus Lorber', 'IT-World ITW GmbH', r'\bauthors?\b', r'\bcontributors?\b', r'\bsponsors?\b'),
           'de': ('Markus Lorber', 'IT-World ITW GmbH', r'\bAutor(en)?\b', r'\bMitwirkende\b', r'\bSponsor(en)?\b')}
# What liability may never exclude (intent, gross negligence, injury to life, body or health, product liability). Named only
# in a sentence that keeps it ("unaffected", "unberührt").
NOT_EXCLUDABLE = re.compile(r'\b(intent|intentional|wil?lful|gross(ly)? neglig\w*|personal injur\w*|injur\w* to (life|body|health)|'
                            r'product liability|Vorsatz|vorsätzlich\w*|grob\w* fahrlässig\w*|grobe\w* Fahrlässigkeit|Personenschä\w*|'
                            r'Verletzung des Lebens|Produkthaftung\w*|PHG|ProdHaftG)\b', re.I)
KEPT = re.compile(r'\b(unaffected|not affected|not excluded|remains?|unberührt|nicht ausgeschlossen|bleibt|bleiben)\b', re.I)
BAN = re.compile(r'\b(verboten|untersagt|nicht gestattet|prohibited|forbidden)\b', re.I)
AGPL_KEPT = {'en': re.compile(r'rights under the AGPL are not affected', re.I), 'de': re.compile(r'Rechte nach der AGPL bleiben (davon )?unberührt', re.I)}
AGPL_SECTIONS = {'en': re.compile(r'sections 15 and 16 of the GNU Affero General Public License'),
                 'de': re.compile(r'Abschnitte 15 und 16 der GNU Affero General Public License')}
NO_RIGHTS = {'en': 'IT-World ITW GmbH sponsors the project and holds no rights to the code',
             'de': 'Die IT-World ITW GmbH unterstützt das Projekt als Sponsor und hat keine Rechte am Code'}
# L9: SHA-256 of the words of the license texts (whitespace joined to one space; LICENSE has its paragraphs on one line each).
# The AGPL-3.0 of the FSF as published 2007 (http:// links) and as published now (https:// links), word for word.
AGPL_WORDS = {'0a7e77a9ebe3fa59cc00696f2180ffc7e0834b7445213b59eb4232c1a1b75746', '2cd0fb7883a3b3553dedbb0bad171646d46f51e2642951aae7c59cb5cec86c46'}
# The license file of eFa 5 byte for byte, as it came from eFa 5 (it holds the GPL-3.0 and the licenses of eFa 5 components).
EFA_GPL_FILE = '5580dfd8ae5a25568130654a50697fc16d914c265fcfd090c32132ebceb1d278'
# L12: the RPM a spec file requires, named as in THIRD-PARTY-NOTICES.md where the names differ.
NOTICE_NAMES = {'mariadb-server': 'mariadb', 'clamd': 'clamav', 'clamav-update': 'clamav', 'fail2ban-server': 'fail2ban',
                'fail2ban-firewalld': 'fail2ban', 'dnf-utils': 'yum-utils', 'openssh-server': 'openssh', 'python3-flask': 'flask',
                'python3-waitress': 'waitress', 'python3-pymysql': 'pymysql', 'python3-pymilter': 'pymilter',
                'python3-certbot-nginx': 'certbot', 'bind-utils': 'bind utilities (dig)', 'gnupg2': 'gnupg',
                'python3-cryptography': 'cryptography'}
# L15: what exists only at the site that builds eFa-next. Its services by name are internal names of scripts/name_check.py
# (salted hashes, so this file does not name them; that CI step fails on them); their ports and mail disclaimer text here.
# No path of this repository may hold them.
ITW_ONLY = re.compile(r'(?<![\w.-])(8899|8901|8902)(?![\w.-])')
ITW_ONLY_PATHS = ()
# The mail disclaimer of ITW: a line that names IT-World or ITW together with what such a disclaimer holds (company register,
# court, VAT number, managing director, "confidential"). A neutral example without the company (as in the setup wizard) is fine,
# as is a placeholder register number (FN 000000x, ATU00000000). Mail addresses at it-world domains are never in the tree; the
# sponsor link https://it-world.eu is.
ITW_NAME = re.compile(r'IT-?World|\bITW\b', re.I)
MAIL_DISCLAIMER = re.compile(r'Firmenbuch|Handelsgericht|\bFN (?!0+\s?[a-z]\b)\d+\s?[a-z]\b|\bATU(?!0{8}\b)\d{8}\b|\bUID\b|'
                             r'Geschäftsführ|registered office|Sitz der Gesellschaft|confidential|vertraulich', re.I)
ITW_MAIL = re.compile(r'[\w.+-]+@(?:[\w-]+\.)*it-world\.[a-z]+', re.I)
SELF = ('scripts/legal_check.py', 'tests/test_legal_check.py')
# Findings in the texts as they are, waiting for the owner (only the owner changes legal texts). Shown on every run, not
# counted as failures; a new finding fails. Take an entry out when its text is fixed.
OPEN = set()


def parts(text):
    """{'en': ..., 'de': ...}: the "## English" and "## Deutsch" parts of the disclaimer."""
    found, lang = {}, None
    for line in text.split('\n'):
        head = re.match(r'## (\S.*)$', line)
        if head:
            lang = next((key for key, name in LANGUAGES.items() if head.group(1).strip() == name), None)
            continue
        if lang:
            found[lang] = found.get(lang, '') + line + '\n'
    return found


def sections(text):
    """The sections of one language: "### Heading" and a paragraph starting with "**Heading.**", each with its text."""
    found, name = {}, None
    for paragraph in re.split(r'\n\s*\n', text):
        head = re.match(r'### (.+)$', paragraph.strip())
        bold = re.match(r'\*\*([^*]+?)\.\*\*\s*(.*)$', paragraph.strip(), re.S)
        if head:
            name = head.group(1).strip()
            found[name] = ''
        elif bold:
            name = bold.group(1).strip()
            found[name] = bold.group(2) + '\n\n'
        elif name and paragraph.strip():
            found[name] += paragraph.strip() + '\n\n'
    return found


def paragraphs(text):
    return [' '.join(item.split()) for item in re.split(r'\n\s*\n', text) if item.strip()]


def sentences(text):
    return [item for item in re.split(r'(?<=[.;!?])\s+', ' '.join(text.split())) if item]


def unqualified(text, lang):
    """The paragraphs that exclude warranty or liability without the qualifier of the law; a sentence that keeps a liability
    ("remains unaffected") excludes nothing."""
    found = []
    for item in paragraphs(text):
        rest = ' '.join(part for part in sentences(item) if not (NOT_EXCLUDABLE.search(part) and KEPT.search(part)))
        if not item.startswith('#') and EXCLUSION[lang].search(rest) and not QUALIFIER[lang].search(rest):
            found.append(item)
    return found


def disclaimer_problems(text):
    """L1 to L4 and L6 to L8 on the text of DISCLAIMER.md."""
    found = []
    by_lang = parts(text)
    for lang, name in LANGUAGES.items():
        if lang not in by_lang:
            found.append(f'L1 {DISCLAIMER}: no "## {name}" part')
            continue
        body, have = by_lang[lang], sections(by_lang[lang])
        found += [f'L1 {DISCLAIMER} ({lang}): no section "{item}"' for item in SECTIONS[lang] if not have.get(item, '').strip()]
        found += [f'L2 {DISCLAIMER} ({lang}): no "{QUALIFIER[lang].pattern}": {item[:80]}' for item in unqualified(body, lang)]
        # The parties in the exclusion of liability itself (the paragraph that names Markus Lorber).
        liable = ' '.join(item for item in paragraphs(have.get(SECTIONS[lang][1], '')) if 'Markus Lorber' in item and EXCLUSION[lang].search(item))
        found += [f'L3 {DISCLAIMER} ({lang}): the liability does not name {party.strip(chr(92) + "b")}' for party in PARTIES[lang]
                  if not re.search(party, liable)]
        found += [f'L4 {DISCLAIMER} ({lang}): excludes what the law keeps: {item[:80]}' for item in sentences(body)
                  if NOT_EXCLUDABLE.search(item) and not KEPT.search(item)]
        if NO_RIGHTS[lang] not in ' '.join(body.split()):
            found.append(f'L5 {DISCLAIMER} ({lang}): no "{NO_RIGHTS[lang]}"')
        if not AGPL_KEPT[lang].search(' '.join(have.get(SECTIONS[lang][0], '').split())):
            found.append(f'L6 {DISCLAIMER} ({lang}): the intended use does not say that the rights under the AGPL stay unaffected')
        found += [f'L6 {DISCLAIMER} ({lang}): a ban instead of a use statement: {item[:80]}' for item in sentences(body) if BAN.search(item)]
        if not AGPL_SECTIONS[lang].search(' '.join(body.split())):
            found.append(f'L7 {DISCLAIMER} ({lang}): no reference to sections 15 and 16 of the AGPL')
    if len(by_lang) == 2:
        names = {lang: set(re.findall(r'Markus Lorber|IT-World ITW GmbH|eFa-next|`[^`]+`|\b\d+\b|\b[A-Z]{3,}\b', body)) for lang, body in by_lang.items()}
        if names['en'] != names['de']:
            found.append(f'L8 {DISCLAIMER}: English and German name different things: '
                         f'only en {sorted(names["en"] - names["de"])}, only de {sorted(names["de"] - names["en"])}')
        if [len(sections(by_lang[lang])) for lang in LANGUAGES] != [len(SECTIONS[lang]) for lang in LANGUAGES]:
            found.append(f'L8 {DISCLAIMER}: English and German have other sections than {SECTIONS["en"]} / {SECTIONS["de"]}')
    return found


def word_hash(text):
    return hashlib.sha256(' '.join(text.split()).encode('utf-8')).hexdigest()


def license_problems(license_text, gpl_bytes):
    """L9: LICENSE is the AGPL-3.0 word for word, LICENSES/GPL-3.0.txt the license file of eFa 5 byte for byte."""
    found = []
    if word_hash(license_text) not in AGPL_WORDS:
        found.append('L9 LICENSE: not the unmodified text of the GNU AGPL-3.0')
    if hashlib.sha256(gpl_bytes).hexdigest() != EFA_GPL_FILE:
        found.append('L9 LICENSES/GPL-3.0.txt: not the unmodified license file of eFa 5')
    return found


def notice_problems(notice):
    """L10: NOTICE names the copyright and the author as every source file does."""
    return [f'L10 NOTICE: no "{line}"' for line in (COPYRIGHT, AUTHOR) if line not in notice]


def efa_files_problems(licenses_md):
    """L11: no file holds code from eFa."""
    body = re.search(r'^## Files with code from eFa\s*\n(.*?)(?=^## |\Z)', licenses_md, re.S | re.M)
    if not body:
        return ['L11 LICENSES.md: no section "Files with code from eFa"']
    return [] if body.group(1).strip().rstrip('.') == 'None' else ['L11 LICENSES.md: files with code from eFa are listed, not "None"']


def requires(spec):
    """The packages a spec file requires, without versions, macros and the own packages."""
    names = []
    for line in spec.split('\n'):
        found = re.match(r'Requires:\s*(.+)$', line)
        if found:
            names += [item for item in re.split(r'[\s,]+', re.sub(r'\s*[<>=]+\s*\S+', '', found.group(1)))
                      if item and '%' not in item and not item.startswith('eFa')]
    return names


def notice_rows(notices):
    """{component in lower case: license cell} of the tables of THIRD-PARTY-NOTICES.md that have a License column."""
    rows = {}
    column = None
    for line in notices.split('\n'):
        cells = [item.strip() for item in line.strip().strip('|').split('|')] if line.startswith('|') else None
        if not cells:
            column = None
            continue
        if column is None:
            column = next((i for i, item in enumerate(cells) if item.lower().startswith('license')), -1)
            continue
        if column < 0 or set(cells[0]) <= set('- '):
            continue
        for name in cells[0].split(','):
            rows[name.strip().lower()] = cells[column] if column < len(cells) else ''
    return rows


def sbom_problems(specs, notices):
    """L12: every package the RPMs require (where the SBOM of build/sbom.py starts, its closure is read on the build host) has
    a row with a license in THIRD-PARTY-NOTICES.md. The SBOM itself fails at build time on a component without a license."""
    rows = notice_rows(notices)
    found = []
    for name in sorted(set(item for spec in specs for item in requires(spec)), key=str.lower):
        row = NOTICE_NAMES.get(name.lower(), name.lower())
        if row not in rows:
            found.append(f'L12 THIRD-PARTY-NOTICES.md: {name} (Requires in rpm/) has no row')
        elif not rows[row].strip():
            found.append(f'L12 THIRD-PARTY-NOTICES.md: {name} has no license')
    return found


def constant(source, name):
    """The value of a top level NAME = <literal> in Python source: only its lines are parsed (all of efactl takes seconds)."""
    found = re.search(r'^' + re.escape(name) + r' = .*?(?=^[A-Za-z_#@])', source + '\nEND', re.S | re.M)
    return ast.literal_eval(found.group(0).split(' = ', 1)[1].strip()) if found else None


def short_problems(texts):
    """L2 on the short forms: README License section, the setup, the RBL confirmation, the summary of the web interface and
    of efa-migrate, the footer of the web interface. texts: {label: (text, lang)}."""
    return [f'L2 {label}: excludes liability without "{"to the maximum extent permitted by law" if lang == "en" else "soweit gesetzlich zulässig"}"'
            for label, (text, lang) in texts.items() if unqualified(text, lang)]


def reference_problems(refs):
    """L13: refs {label: text}; each must name DISCLAIMER.md (which holds the severability clause, L1)."""
    return [f'L13 {label}: no reference to DISCLAIMER.md' for label, text in refs.items() if 'DISCLAIMER' not in text]


def digest_problems(legal_names, build_source, sources):
    """L14: the confirmed digest is efa_legal.digest() over LICENSE, DISCLAIMER.md and THIRD-PARTY-NOTICES.md, made from the
    files at build time (build/build-rpms.py calls efa_legal.build); no program holds a digest of its own."""
    found = []
    if 'DISCLAIMER.md' not in (legal_names or ()):
        found.append('L14 efa_legal.NAMES: DISCLAIMER.md is not in the digest')
    if 'efa_legal.build(' not in build_source:
        found.append('L14 build/build-rpms.py: does not make the digest from the texts (efa_legal.build)')
    for label, source in sources.items():
        found += [f'L14 {label}:{number}: a fixed legal digest' for number, line in enumerate(source.split('\n'), 1)
                  if re.search(r'legal', line, re.I) and re.search(r'[\'"][0-9a-f]{16}[\'"]', line)]
    return found


def rights_problems(path, text):
    """L5: IT-World ITW GmbH never in a copyright line, never as employer or rights holder."""
    found = []
    for number, line in enumerate(text.split('\n'), 1):
        if 'IT-World' not in line:
            continue
        if re.search(r'copyright|\(C\)|©', line, re.I):
            found.append(f'L5 {path}:{number}: IT-World in a copyright line')
        elif re.search(r'employer|Arbeitgeber|rights holder|Rechteinhaber|holds the rights|hält die Rechte', line, re.I) and \
                not re.search(r'\b(not|no|kein\w*|nicht)\b', line, re.I):
            found.append(f'L5 {path}:{number}: IT-World as employer or rights holder')
    return found


def internal_problems(path, text):
    """L15: no ITW-only service, port or mail disclaimer in the public tree."""
    if path.startswith(ITW_ONLY_PATHS) and ITW_ONLY_PATHS:
        return []
    return [f'L15 {path}:{number}: ITW-internal: {line.strip()[:80]}' for number, line in enumerate(text.split('\n'), 1)
            if ITW_ONLY.search(line) or ITW_MAIL.search(line) or (ITW_NAME.search(line) and MAIL_DISCLAIMER.search(line))]


def read(path, mode='r'):
    with open(os.path.join(ROOT, path), mode, **({} if 'b' in mode else {'encoding': 'utf-8'})) as f:
        return f.read()


def tree():
    """(path, text) of every text file of the repository but .git and the files of this check."""
    for top, dirs, names in os.walk(ROOT):
        dirs[:] = sorted(item for item in dirs if item not in ('.git', '__pycache__'))
        for name in sorted(names):
            path = os.path.relpath(os.path.join(top, name), ROOT).replace(os.sep, '/')
            if path in SELF:
                continue
            try:
                with open(os.path.join(top, name), encoding='utf-8') as f:
                    yield path, f.read()
            except (UnicodeDecodeError, OSError):
                continue


def problems():
    """All findings of L1 to L15 (but L10 of the source files) in the repository."""
    found = []
    try:
        disclaimer = read(DISCLAIMER)
    except OSError:
        return [f'L1 {DISCLAIMER}: missing']
    found += disclaimer_problems(disclaimer)
    found += license_problems(read('LICENSE'), read('LICENSES/GPL-3.0.txt', 'rb'))
    found += notice_problems(read('NOTICE'))
    found += efa_files_problems(read('LICENSES.md'))
    specs = [read(os.path.join('rpm', name)) for name in sorted(os.listdir(os.path.join(ROOT, 'rpm'))) if name.endswith('.spec')]
    found += sbom_problems(specs, read('THIRD-PARTY-NOTICES.md'))
    readme = re.search(r'^## License\s*\n(.*?)(?=^## |\Z)', read('README.md'), re.S | re.M)
    readme = readme.group(1) if readme else ''
    efactl, web, init = read('next/usr/sbin/efactl'), read('next/usr/local/sbin/efa-web.py'), read('next/usr/local/sbin/efa-init.py')
    legal, migrate = read('next/usr/lib/eFa/python/efa_legal.py'), read('migration/efa-migrate')
    rbl = constant(efactl, 'RBL_TERMS_TEXT') or ''
    summary = constant(legal, 'SUMMARY') or {}
    footer = ' '.join(re.findall(r"_\('([^']*(?:warranty|liab)[^']*)'\)", web, re.I))
    found += short_problems({'README.md License': (readme, 'en'), 'efa-init.py DISCLAIMER_SHORT': (constant(init, 'DISCLAIMER_SHORT') or '', 'en'),
                             'efactl RBL_TERMS_TEXT': (rbl, 'en'), 'efa_legal.SUMMARY en': (summary.get('en', ''), 'en'),
                             'efa_legal.SUMMARY de': (summary.get('de', ''), 'de'), 'efa-web.py footer': (footer, 'en')})
    found += reference_problems({'README.md License': readme, 'efa-init.py (setup)': init,
                                 'web interface legal page (efa_legal.NAMES)': ' '.join(constant(legal, 'NAMES') or ()),
                                 'efa-migrate': migrate if 'efa_legal.console_confirm' in migrate else '',
                                 'RBL confirmation (efactl RBL_TERMS_TEXT, docs/rbl.md)': rbl + read('docs/rbl.md')})
    found += digest_problems(constant(legal, 'NAMES'), read('build/build-rpms.py'),
                             {'efa-init.py': init, 'efa-migrate': migrate, 'efa-web.py': web, 'efactl': efactl})
    for path, text in tree():
        found += rights_problems(path, text) + internal_problems(path, text)
    return found
