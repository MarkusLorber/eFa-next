#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""A CycloneDX 1.5 SBOM (JSON) of the built RPMs: eFa and eFa-base and every package they need, also transitively, with
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


def closure(rpm_files):
    """Names of all installed packages the RPMs need, transitively."""
    seen, queue = set(), needed(rpm(['-qp', '--requires'] + rpm_files))
    while queue:
        names = {line.strip() for line in rpm(['-q', '--whatprovides', '--qf', '%{NAME}\\n'] + queue) if line and ' ' not in line}
        new = sorted(names - seen)
        seen |= names
        queue = needed(rpm(['-q', '--requires'] + new)) if new else []
    return sorted(seen)


SPDX_EXPRESSION = re.compile(r'[A-Za-z0-9.+-]+(\s+(AND|OR|WITH)\s+[A-Za-z0-9.+-]+)*')


def license_entry(text):
    """An SPDX expression as such; the older RPM license names (GPLv2+, "and") as a name."""
    plain = text.replace('(', ' ').replace(')', ' ').strip()
    if SPDX_EXPRESSION.fullmatch(' '.join(plain.split())) and not re.search(r'GPLv|\s(and|or)\s|\bBSD\b(?!-)', text):
        return {'expression': text}
    return {'license': {'name': text}}


def component(fields, kind='library', namespace=None, scope=None):
    name, epoch, version, release, arch, license_, url, vendor = (fields + [''] * 8)[:8]
    full = f'{version}-{release}'
    namespace = namespace or (vendor.split()[0].lower() if vendor and vendor != '(none)' else 'unknown')
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
    main = next((item for item in own if item['name'] == 'eFa'), own[0])
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.5',
            # The same content gives the same serial number.
            'serialNumber': 'urn:uuid:' + str(uuid.uuid5(uuid.NAMESPACE_URL, 'efa-next:' + ','.join(item['purl'] for item in own + deps))),
            'version': 1,
            'metadata': {'timestamp': when, 'component': main, 'tools': {'components': [{'type': 'application', 'name': 'eFa-next build/sbom.py'}]}},
            'components': sorted(own + deps, key=lambda item: item['purl']),
            'dependencies': [{'ref': item['purl'], 'dependsOn': [dep['purl'] for dep in deps]} for item in own]}


OWN_LICENSE = 'AGPL-3.0-or-later'


def license_problems(bom):
    """Every component names its license; the own ones (eFa, eFa-base) the AGPL-3.0-or-later."""
    found = []
    for item in bom['components']:
        if not item.get('licenses'):
            found.append(f"{item['name']}: no license")
        elif item['purl'].startswith('pkg:rpm/efa-next/') and item['licenses'] != [{'expression': OWN_LICENSE}]:
            found.append(f"{item['name']}: not {OWN_LICENSE}")
    return found


def self_test():
    item = component(['postfix', '2', '3.5.25', '1.el9', 'x86_64', 'IPL-1.0 OR EPL-2.0', 'http://www.postfix.org', 'AlmaLinux'])
    assert item['purl'] == 'pkg:rpm/almalinux/postfix@3.5.25-1.el9?arch=x86_64&epoch=2' and item['licenses'] == [{'expression': 'IPL-1.0 OR EPL-2.0'}]
    assert component(['x', '0', '1', '1', 'noarch', '(none)', '(none)', '(none)'])['purl'] == 'pkg:rpm/unknown/x@1-1?arch=noarch'
    assert component(['eFa', '(none)', '6', '1', 'noarch', 'AGPL-3.0-or-later', '', '(none)'], 'application', 'efa-next')['purl'] == 'pkg:rpm/efa-next/eFa@6-1?arch=noarch'
    assert license_entry('Apache-2.0') == {'expression': 'Apache-2.0'} and license_entry('LGPL-2.1-or-later WITH GCC-exception-2.0 AND MIT')['expression']
    assert license_entry('GPLv2+') == {'license': {'name': 'GPLv2+'}} and 'license' in license_entry('(IBM and GPLv2+) or (EPL-2.0 and GPLv2+)')
    assert 'license' in license_entry('BSD') and license_entry('(MIT OR Apache-2.0)') == {'expression': '(MIT OR Apache-2.0)'}
    assert needed(['rpmlib(PayloadIsZstd) <= 5.4.18-1', 'python3', 'eFa-base = 1:6.0.0.3-1', '(a or b)', '']) == ['eFa-base', 'python3']
    own = component(['eFa', '(none)', '6', '1', 'noarch', 'AGPL-3.0-or-later', '', '(none)'], 'application', 'efa-next')
    assert license_problems({'components': [own, item]}) == [] and own['author'] == 'Markus Lorber, Lukasz Galusinski' and 'author' not in item
    assert license_problems({'components': [component(['x', '0', '1', '1', 'noarch', '(none)', '(none)', '(none)'])]}) == ['x: no license']
    assert license_problems({'components': [component(['eFa', '0', '6', '1', 'noarch', 'GPL-3.0-or-later', '', ''], 'application', 'efa-next')]})
    print('self-test ok')


def main():
    if '--self-test' in sys.argv:
        self_test()
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
    for problem in license_problems(data):
        print(f'sbom: {problem}', file=sys.stderr)
    if license_problems(data):
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
