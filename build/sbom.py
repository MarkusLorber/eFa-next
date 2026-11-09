#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""A CycloneDX 1.5 SBOM (JSON) of the built RPMs: eFa-next and eFa-next-base and every package they need, also transitively, with
version and license as the RPM database of the build host has them. Sorted and with the time of SOURCE_DATE_EPOCH, so
the same packages on the same host give the same file.

    build/sbom.py RPM... --out FILE
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import uuid

QF = '%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{LICENSE}\\t%{URL}\\t%{VENDOR}\\n'


def rpm(args):
    done = subprocess.run(['rpm'] + args, capture_output=True, text=True)
    return done.stdout.splitlines()


def needed(requires):
    """The capabilities worth resolving: no rpmlib() features, no conditions."""
    return sorted({line.split()[0] for line in requires if line and not line.startswith(('rpmlib(', '(')) and line.split()[0]})


def closure(rpm_files, query='-qp'):
    """Names of all installed packages the RPMs need, transitively. query -q: installed package names instead of files."""
    seen, queue = set(), needed(rpm([query, '--requires'] + rpm_files))
    while queue:
        names = {line.strip() for line in rpm(['-q', '--whatprovides', '--qf', '%{NAME}\\n'] + queue) if line and ' ' not in line}
        new = sorted(names - seen)
        seen |= names
        queue = needed(rpm(['-q', '--requires'] + new)) if new else []
    return sorted(seen)


def closure_parents(rpm_files, parents, query='-qp'):
    """SBOM-2: like closure, one capability at a time (slow), noting in parents the first package that needed each.
    query -q: rpm_files are the names of installed packages instead of files."""
    seen, queue = set(), [(cap, 'eFa-next') for cap in needed(rpm([query, '--requires'] + rpm_files))]
    while queue:
        new = []
        for cap, by in queue:
            for name in {line.strip() for line in rpm(['-q', '--whatprovides', '--qf', '%{NAME}\\n', cap]) if line and ' ' not in line} - seen:
                seen.add(name)
                new.append(name)
                parents[name] = by
        queue = [(cap, name) for name in sorted(new) for cap in needed(rpm(['-q', '--requires', name]))]
    return sorted(seen)


# SBOM-2: eFa-next itself has no Perl (owner's rule: none in its code or its own requirements). Perl only through these packages
# of the distribution or vendor, which need it themselves and cannot be replaced; a chain through any other package fails.
PERL_VIA = {
    'mariadb-server': 'needs the client package mariadb (Perl helper scripts in it); efactl uses mysqldump, mysql and mysqlcheck from it',
    'rspamd': 'the package of rspamd.com needs perl-interpreter for its script rspamd_stats',
}


def perl_problems(parents):
    """The chains to perl* packages the runtime of eFa-next pulls in other than through PERL_VIA."""
    chains = [why(name, parents) for name in sorted(parents) if name.startswith('perl')]
    return [chain for chain in chains if not set(chain.split(' > ')) & set(PERL_VIA)]


def why(name, parents):
    """SBOM-2: the chain of packages from eFa-next to name, such as eFa-next > mariadb-server > perl-interpreter."""
    chain = [name]
    while chain[-1] in parents and chain[-1] != 'eFa-next' and len(chain) < 50:
        chain.append(parents[chain[-1]])
    return ' > '.join(reversed(chain))

# SBOM-1: the older Fedora license names of EL9 packages as SPDX. Names that do not say which license exactly (BSD, Public
# Domain, GFDL ...) become a LicenseRef, so the expression stays valid without guessing. Longer names first.
LEGACY_SPDX = [
    ('BSD with advertising', 'BSD-4-Clause'), ('Artistic 2.0', 'Artistic-2.0'), ('ASL 2.0', 'Apache-2.0'),
    ('Public Domain', 'LicenseRef-Public-Domain'), ('Public domain', 'LicenseRef-Public-Domain'),
    ('GPL+', 'GPL-1.0-or-later'), ('GPLv2+', 'GPL-2.0-or-later'), ('GPLv2', 'GPL-2.0-only'), ('GPLv3+', 'GPL-3.0-or-later'),
    ('GPLv3', 'GPL-3.0-only'), ('LGPLv2+', 'LGPL-2.0-or-later'), ('LGPLv2', 'LGPL-2.0-only'), ('LGPLv3+', 'LGPL-3.0-or-later'),
    ('LGPLv3', 'LGPL-3.0-only'), ('MPLv2.0', 'MPL-2.0'), ('Artistic', 'Artistic-1.0-Perl'), ('Boost', 'BSL-1.0'), ('zlib', 'Zlib'),
    ('Sleepycat', 'Sleepycat'), ('FSFAP', 'FSFAP'), ('IBM', 'IPL-1.0'), ('Python', 'LicenseRef-Python'), ('RSA', 'RSA-MD'),
    ('OpenLDAP', 'OLDAP-2.8'), ('OFL', 'LicenseRef-OFL'), ('BSD', 'LicenseRef-BSD'), ('UCD', 'LicenseRef-UCD'), ('HSRL', 'LicenseRef-HSRL'), ('AFL', 'LicenseRef-AFL'), ('GFDL', 'LicenseRef-GFDL'),
]
SPDX_IDS = {spdx for _, spdx in LEGACY_SPDX} | {'MIT', 'ISC', 'Apache-2.0', 'EPL-2.0', 'IPL-1.0', 'AGPL-3.0-or-later', 'GPL-2.0-or-later', 'GPL-3.0-or-later',
                                                'LGPL-2.1-or-later', 'LGPL-2.1-only', 'BSD-2-Clause', 'BSD-3-Clause', 'MIT-0', 'OFL-1.1', 'PSF-2.0',
                                                'Unicode-DFS-2016', 'curl', 'OpenSSL', 'Zlib', 'BSL-1.0', 'MPL-1.1', 'CC0-1.0', 'Unlicense', 'X11',
                                                'GPL-2.0-only', 'LGPL-3.0-or-later', 'Artistic-2.0', 'Python-2.0', 'Python-2.0.1', 'HPND',
                                                'GCC-exception-2.0', 'GCC-exception-3.1', 'Autoconf-exception-generic', 'Bison-exception-2.2',
                                                'LLVM-exception', 'Classpath-exception-2.0', 'SunPro', 'FSFUL', 'Sendmail', 'TTWL', '0BSD',
                                                'Unicode-3.0', 'CMU-Mach', 'OLDAP-2.8', 'GNU-compiler-exception', 'Texinfo-exception',
                                                'Autoconf-exception-generic-3.0'}
SPDX_EXCEPTIONS = {'GCC-exception-2.0', 'GCC-exception-3.1', 'Autoconf-exception-generic', 'Bison-exception-2.2', 'LLVM-exception',
                   'Classpath-exception-2.0', 'GNU-compiler-exception', 'Texinfo-exception', 'Autoconf-exception-generic-3.0'}


def spdx_like(token):
    """An id of the SPDX list this file does not name: with a dash, and none of the older Fedora names."""
    return bool(re.fullmatch(r'[A-Za-z0-9]+(-[A-Za-z0-9.+]+)+', token)) and not token.startswith(('GPLv', 'LGPLv', 'ASL', 'MPLv'))


def spdx_valid(expression):
    """True for an SPDX license expression of known ids or LicenseRef-, with AND, OR, WITH and parentheses."""
    tokens = re.findall(r'\(|\)|[^\s()]+', expression)
    pos, depth, want_id = 0, 0, True
    while pos < len(tokens):
        token = tokens[pos]
        if want_id:
            if token == '(':
                depth += 1
            elif token in SPDX_IDS - SPDX_EXCEPTIONS or re.fullmatch(r'LicenseRef-[A-Za-z0-9.-]+', token) or spdx_like(token):
                if pos + 1 < len(tokens) and tokens[pos + 1] == 'WITH':
                    if pos + 2 >= len(tokens) or tokens[pos + 2] not in SPDX_EXCEPTIONS:
                        return False
                    pos += 2
                want_id = False
            else:
                return False
        elif token == ')':
            depth -= 1
            if depth < 0:
                return False
        elif token in ('AND', 'OR'):
            want_id = True
        else:
            return False
        pos += 1
    return depth == 0 and not want_id


def legacy_to_spdx(text):
    """The SPDX expression of an older RPM license text, or None when a part of it has no clear SPDX form."""
    if 'exception' in text.lower():
        return None
    out = ' ' + text.replace('(', ' ( ').replace(')', ' ) ') + ' '
    for old, new in LEGACY_SPDX:
        out = re.sub(r'(?<=\s)' + re.escape(old) + r'(?=\s)', new, out)
    out = re.sub(r'(?<=\s)and(?=\s)', 'AND', out)
    out = re.sub(r'(?<=\s)or(?=\s)', 'OR', out)
    out = re.sub(r'\(\s+', '(', re.sub(r'\s+\)', ')', ' '.join(out.split())))
    return out if spdx_valid(out) else None


def license_entry(text):
    """An SPDX expression as such, an older RPM license name (GPLv2+, "and") as its SPDX form; what has none stays a name."""
    if spdx_valid(' '.join(text.split())):
        return {'expression': text}
    converted = legacy_to_spdx(text)
    return {'expression': converted} if converted else {'license': {'name': text}}


# Packages whose repository sets no vendor: the namespace of their purl by name.
NAMESPACES = {'rspamd': 'rspamd'}


def component(fields, kind='library', namespace=None, scope=None):
    name, epoch, version, release, arch, license_, url, vendor = (fields + [''] * 8)[:8]
    full = f'{version}-{release}'
    namespace = namespace or (vendor.split()[0].lower() if vendor and vendor != '(none)' else NAMESPACES.get(name, 'unknown'))
    purl = f'pkg:rpm/{namespace}/{name}@{full}?arch={arch}' + (f'&epoch={epoch}' if epoch not in ('', '0', '(none)') else '')
    item = {'type': kind, 'bom-ref': purl, 'name': name, 'version': full, 'purl': purl,
            'licenses': [license_entry(license_)] if license_ and license_ != '(none)' else []}
    if scope:
        item['scope'] = scope
    if namespace == 'efa-next':
        item.update(author='Markus Lorber, Lukasz Galusinski', supplier={'name': 'Markus Lorber'})
    if url and url != '(none)':
        item['externalReferences'] = [{'type': 'website', 'url': url}]
    return item


def sbom(rpm_files, stamp):
    own = [component(line.split('\t'), 'application', 'efa-next') for line in rpm(['-qp', '--qf', QF] + rpm_files)]
    names = [name for name in closure(rpm_files) if name not in {item['name'] for item in own}]
    deps = [component(line.split('\t')) for line in rpm(['-q', '--qf', QF] + names)] if names else []
    # Weak dependencies (Suggests, Recommends) that are installed here, such as qpdf for the PDF encryption.
    weak = needed(rpm(['-qp', '--suggests'] + rpm_files) + rpm(['-qp', '--recommends'] + rpm_files))
    weak_names = sorted({line.strip() for line in rpm(['-q', '--whatprovides', '--qf', '%{NAME}\\n'] + weak) if line and ' ' not in line} - set(names)) if weak else []
    deps += [component(line.split('\t'), scope='optional') for line in rpm(['-q', '--qf', QF] + weak_names)] if weak_names else []
    when = datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    main = next((item for item in own if item['name'] == 'eFa-next'), own[0])
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.5',
            # The same content gives the same serial number.
            'serialNumber': 'urn:uuid:' + str(uuid.uuid5(uuid.NAMESPACE_URL, 'efa-next:' + ','.join(item['purl'] for item in own + deps))),
            'version': 1,
            'metadata': {'timestamp': when, 'component': main, 'tools': {'components': [{'type': 'application', 'name': 'eFa-next build/sbom.py'}]}},
            'components': sorted(own + deps, key=lambda item: item['purl']),
            'dependencies': [{'ref': item['purl'], 'dependsOn': [dep['purl'] for dep in deps]} for item in own]}


OWN_LICENSE = 'AGPL-3.0-or-later'


def license_problems(bom):
    """Every component names its license; the own ones (eFa-next, eFa-next-base) the AGPL-3.0-or-later."""
    found = []
    for item in bom['components']:
        if not item.get('licenses'):
            found.append(f"{item['name']}: no license")
        elif item['purl'].startswith('pkg:rpm/efa-next/') and item['licenses'] != [{'expression': OWN_LICENSE}]:
            found.append(f"{item['name']}: not {OWN_LICENSE}")
    return found


def sbom_problems(bom):
    """SBOM-1: an own check of the CycloneDX 1.5 fields this file writes: required fields and types, purls, unique refs,
    valid license expressions, dependencies that name known components."""
    found = []
    for key, kind in (('bomFormat', str), ('specVersion', str), ('serialNumber', str), ('version', int), ('metadata', dict), ('components', list),
                      ('dependencies', list)):
        if not isinstance(bom.get(key), kind):
            found.append(f'{key}: missing or not a {kind.__name__}')
    if found:
        return found
    if bom['bomFormat'] != 'CycloneDX' or bom['specVersion'] != '1.5':
        found.append('not CycloneDX 1.5')
    if not re.fullmatch(r'urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', bom['serialNumber']):
        found.append('serialNumber is no urn:uuid')
    if not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', bom['metadata'].get('timestamp', '')):
        found.append('metadata.timestamp is no date-time')
    refs = set()
    main = bom['metadata'].get('component') or {}
    # The metadata component is mostly the same object as its entry in components: by position, not by identity.
    listed = len(bom['components'])
    for index, item in enumerate(bom['components'] + [main]):
        name = item.get('name', '?')
        if item.get('type') not in ('application', 'library', 'framework', 'operating-system', 'file'):
            found.append(f'{name}: type')
        if not item.get('name') or not item.get('version'):
            found.append(f'{name}: name or version missing')
        if not re.fullmatch(r'pkg:[a-z]+/[a-z0-9._-]+/[^/@\s]+@[^?\s]+(\?\S*)?', item.get('purl', '')) or '/unknown/' in item.get('purl', ''):
            found.append(f"{name}: purl {item.get('purl')}")
        for entry in item.get('licenses', []):
            if 'expression' in entry and not spdx_valid(entry['expression']):
                found.append(f"{name}: no valid SPDX expression: {entry['expression']}")
            elif 'license' in entry and not (entry['license'].get('name') or entry['license'].get('id')):
                found.append(f'{name}: empty license')
        if index < listed:
            if item.get('bom-ref') in refs:
                found.append(f'{name}: bom-ref twice')
            refs.add(item.get('bom-ref'))
    for dep in bom['dependencies']:
        for ref in [dep.get('ref')] + dep.get('dependsOn', []):
            if ref not in refs:
                found.append(f'dependency on an unknown component: {ref}')
    return found


SCHEMA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'third-party', 'cyclonedx-1.5')
SCHEMA_FILES = ('bom-1.5.schema.json', 'spdx.schema.json', 'jsf-0.82.schema.json')


def schema_files(folder=SCHEMA_DIR):
    """The official schema files as pinned by SHA256SUMS in the repository; ValueError for a missing or changed one."""
    import hashlib
    with open(os.path.join(folder, 'SHA256SUMS')) as f:
        pinned = {name: digest for digest, name in (line.split() for line in f if line.strip())}
    found = {}
    for name in SCHEMA_FILES:
        with open(os.path.join(folder, name), 'rb') as f:
            data = f.read()
        if hashlib.sha256(data).hexdigest() != pinned.get(name):
            raise ValueError(f'{name} does not match SHA256SUMS')
        found[name] = json.loads(data)
    return found


def schema_problems(bom, folder=SCHEMA_DIR):
    """SBOM-1: the check against the official CycloneDX 1.5 JSON schema (python3-jsonschema), offline with the pinned files."""
    try:
        import jsonschema
    except ImportError:
        return ['python3-jsonschema is missing: dnf install python3-jsonschema (the official schema check)']
    try:
        schemas = schema_files(folder)
    except (OSError, ValueError) as err:
        return [f'schema files: {err}']
    store = {schema['$id']: schema for schema in schemas.values()}
    store.update({name: schema for name, schema in schemas.items()})
    main = schemas['bom-1.5.schema.json']
    resolver = jsonschema.RefResolver(base_uri=main['$id'], referrer=main, store=store)
    validator = jsonschema.Draft7Validator(main, resolver=resolver)
    return [f"schema: {'/'.join(str(part) for part in error.path)}: {error.message[:200]}" for error in validator.iter_errors(bom)][:50]


def own_component():
    return component(['eFa-next', '(none)', '6', '1', 'noarch', 'AGPL-3.0-or-later', '', '(none)'], 'application', 'efa-next')


def self_test():
    chains = {'perl-Carp': 'perl-interpreter', 'perl-interpreter': 'git', 'git': 'eFa-next', 'python3': 'eFa-next'}
    assert perl_problems(chains) == ['eFa-next > git > perl-interpreter > perl-Carp', 'eFa-next > git > perl-interpreter']
    assert perl_problems({'python3': 'eFa-next'}) == []
    assert perl_problems({'perl-DBI': 'mariadb', 'mariadb': 'mariadb-server', 'mariadb-server': 'eFa-next', 'perl-interpreter': 'rspamd',
                          'rspamd': 'eFa-next'}) == [], 'Perl only through the packages named in PERL_VIA'
    item = component(['postfix', '2', '3.5.25', '1.el9', 'x86_64', 'IPL-1.0 OR EPL-2.0', 'http://www.postfix.org', 'AlmaLinux'])
    assert item['purl'] == 'pkg:rpm/almalinux/postfix@3.5.25-1.el9?arch=x86_64&epoch=2' and item['licenses'] == [{'expression': 'IPL-1.0 OR EPL-2.0'}]
    assert component(['x', '0', '1', '1', 'noarch', '(none)', '(none)', '(none)'])['purl'] == 'pkg:rpm/unknown/x@1-1?arch=noarch'
    assert component(['eFa', '(none)', '6', '1', 'noarch', 'AGPL-3.0-or-later', '', '(none)'], 'application', 'efa-next')['purl'] == 'pkg:rpm/efa-next/eFa@6-1?arch=noarch'
    assert license_entry('Apache-2.0') == {'expression': 'Apache-2.0'} and license_entry('LGPL-2.1-or-later WITH GCC-exception-2.0 AND MIT')['expression']
    assert license_entry('GPLv2+') == {'expression': 'GPL-2.0-or-later'} and license_entry('(MIT OR Apache-2.0)') == {'expression': '(MIT OR Apache-2.0)'}
    assert license_entry('(IBM and GPLv2+) or (EPL-2.0 and GPLv2+)') == {'expression': '(IPL-1.0 AND GPL-2.0-or-later) OR (EPL-2.0 AND GPL-2.0-or-later)'}
    assert license_entry('BSD') == {'expression': 'LicenseRef-BSD'} and license_entry('ASL 2.0 or BSD') == {'expression': 'Apache-2.0 OR LicenseRef-BSD'}
    assert license_entry('GPLv2 and GPLv2+ and LGPLv2+ and BSD with advertising and Public Domain')['expression'] == \
        'GPL-2.0-only AND GPL-2.0-or-later AND LGPL-2.0-or-later AND BSD-4-Clause AND LicenseRef-Public-Domain'
    assert license_entry('GPLv2+ and LGPLv2+ with exceptions') == {'license': {'name': 'GPLv2+ and LGPLv2+ with exceptions'}}
    assert license_entry('Licensed only for approved usage, see COPYING for details.')['license']
    assert not spdx_valid('MIT AND') and not spdx_valid('(MIT') and not spdx_valid('MIT WITH Apache-2.0') and spdx_valid('GPL-2.0-or-later WITH GCC-exception-2.0')
    assert component(['rspamd', '0', '4.2.3', '1.el9', 'x86_64', 'Apache-2.0', '', '(none)'])['purl'] == 'pkg:rpm/rspamd/rspamd@4.2.3-1.el9?arch=x86_64'
    good = {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'serialNumber': 'urn:uuid:' + str(uuid.uuid5(uuid.NAMESPACE_URL, 'x')), 'version': 1,
            'metadata': {'timestamp': '2026-01-01T00:00:00Z', 'component': own_component()}, 'components': [own_component(), item],
            'dependencies': [{'ref': own_component()['purl'], 'dependsOn': [item['purl']]}]}
    assert sbom_problems(good) == [], sbom_problems(good)
    # Two own packages, one needing the other, and the main one in the metadata as the same object as in the components.
    base = component(['eFa-next-base', '(none)', '6.0.0.5', '1.el9', 'noarch', 'AGPL-3.0-or-later', '', '(none)'], 'application', 'efa-next')
    top = component(['eFa-next', '(none)', '6.0.0.5', '1.el9', 'noarch', 'AGPL-3.0-or-later', '', '(none)'], 'application', 'efa-next')
    pair = {**good, 'metadata': {**good['metadata'], 'component': top}, 'components': [base, top, item],
            'dependencies': [{'ref': top['purl'], 'dependsOn': [base['purl'], item['purl']]}, {'ref': base['purl'], 'dependsOn': [item['purl']]}]}
    assert sbom_problems(pair) == [], sbom_problems(pair)
    assert sbom_problems({**good, 'components': [own_component(), item, item]}) == ['postfix: bom-ref twice']
    assert sbom_problems({**good, 'dependencies': [{'ref': 'pkg:rpm/x/y@1', 'dependsOn': []}]}) == ['dependency on an unknown component: pkg:rpm/x/y@1']
    assert sbom_problems({**good, 'components': [own_component(), component(['x', '0', '1', '1', 'noarch', 'MIT', '', '(none)'])]})
    assert needed(['rpmlib(PayloadIsZstd) <= 5.4.18-1', 'python3', 'eFa-base = 1:6.0.0.3-1', '(a or b)', '']) == ['eFa-base', 'python3']
    own = component(['eFa', '(none)', '6', '1', 'noarch', 'AGPL-3.0-or-later', '', '(none)'], 'application', 'efa-next')
    assert license_problems({'components': [own, item]}) == [] and own['author'] == 'Markus Lorber, Lukasz Galusinski' and 'author' not in item
    assert license_problems({'components': [component(['x', '0', '1', '1', 'noarch', '(none)', '(none)', '(none)'])]}) == ['x: no license']
    assert license_problems({'components': [component(['eFa', '0', '6', '1', 'noarch', 'GPL-3.0-or-later', '', ''], 'application', 'efa-next')]})
    assert why('perl-Carp', {'perl-Carp': 'perl-interpreter', 'perl-interpreter': 'mariadb-server', 'mariadb-server': 'eFa-next'}) == \
        'eFa-next > mariadb-server > perl-interpreter > perl-Carp'
    assert set(schema_files()) == set(SCHEMA_FILES), 'the pinned schema files are there and match'
    try:
        import jsonschema  # noqa: F401
        assert schema_problems(good) == [], schema_problems(good)
        assert schema_problems({**good, 'specVersion': 15}) and schema_problems({**good, 'components': [{'name': 'x'}]})
    except ImportError:
        print('self-test: python3-jsonschema missing, the official schema check was not run')
    print('self-test ok')


def main():
    if '--self-test' in sys.argv:
        self_test()
        return 0
    if '--closure-installed' in sys.argv:
        # build.bash source: what the installed eFa-next needs at runtime, never removed with the build tools.
        print('\n'.join(closure(['eFa-next', 'eFa-next-base'], '-q')))
        return 0
    if '--perl-check' in sys.argv:
        # build/sbom.py --perl-check: the installed eFa-next and eFa-next-base and all they need, with no Perl in it.
        parents = {}
        closure_parents(['eFa-next', 'eFa-next-base'], parents, '-q')
        problems = perl_problems(parents)
        print(f'{len(parents)} packages needed at runtime, ' + (f'{len(problems)} with Perl:' if problems else 'no Perl'))
        print('\n'.join(problems))
        return 1 if problems or not parents else 0
    if '--why' in sys.argv:
        # build/sbom.py --why NAME RPM...: why the built RPMs pull in a package (NAME may end in *), on the build host.
        position = sys.argv.index('--why')
        target, files, parents = sys.argv[position + 1], sorted(sys.argv[position + 2:]), {}
        closure_parents(files, parents)
        prefix = target.rstrip('*')
        for name in sorted(item for item in parents if item == target or (target.endswith('*') and item.startswith(prefix))):
            print(why(name, parents))
        return 0
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('rpms', nargs='+')
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    data = sbom(sorted(args.rpms), int(os.environ.get('SOURCE_DATE_EPOCH', '1767225600')))
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.write('\n')
    print(f'sbom: {len(data["components"])} components in {args.out}')
    problems = license_problems(data) + sbom_problems(data) + schema_problems(data)
    for problem in problems:
        print(f'sbom: {problem}', file=sys.stderr)
    if problems:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
