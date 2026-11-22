#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The compliance file of a release: which technical requirements of a standard eFa-next covers, how far, and the evidence
to check each claim (docs/compliance/README.md).

    compliance_build.py --version 6.0.0.6.7 [--out DIR] [--ci-log unit-tests.log --self-tests ok] [--commit SHA] [--date D]
    compliance_build.py --check            the references only, nothing written

Source: next/usr/share/eFa/compliance/controls.json (it ships in the RPM for efactl compliance-verify). Written:
eFa-next-<version>.compliance.json, .compliance.md and .compliance.de.md. It fails when a covered or partial control has no
evidence besides a document, when a reference does not resolve (test, self-test, hardening check, security standard, efactl
command, file, Wazuh rule), when a test it names did not pass in the CI log given, or when the file does not match
compliance/compliance.schema.json. A hardening check that no control names is a warning.
"""
import argparse
import ast
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = 'next/usr/share/eFa/compliance/controls.json'
SCHEMA = 'compliance/compliance.schema.json'
EFACTL = 'next/usr/sbin/efactl'
STATUSES = ('covered', 'partial', 'not-covered', 'out-of-scope')
# Hans 2026-11-19: not legally binding, open to independent checks; warranty and liability only by reference to DISCLAIMER.md
# (its wording "to the maximum extent permitted by law"), no exclusion of its own (scripts/legal_check.py L16).
NOTICE = {
    'en': ('Not a legally binding statement. This file lists which technical requirements of the standards eFa-next covers, how '
           'far, and how each claim can be checked. It is no certification, no confirmation of conformity by a third party and '
           'no legal advice. Warranty and liability: DISCLAIMER.md applies, to the maximum extent permitted by law. The operator '
           'stays responsible for the conformity of their organisation. Anyone can have this information verified independently '
           'at any time by auditors of their own choice, with: the SHA-256 of this file in the signed SHA256SUMS of the release, '
           '"efactl compliance-verify" on an installed host, and the open source code (AGPL-3.0).'),
    'de': ('Keine rechtlich verbindliche Aussage. Diese Datei listet, welche technischen Anforderungen der Standards eFa-next '
           'abdeckt, in welchem Umfang und wie jede Angabe geprüft werden kann. Sie ist keine Zertifizierung, keine '
           'Konformitätsbestätigung durch Dritte und keine Rechtsberatung. Gewährleistung und Haftung: Es gilt DISCLAIMER.md, '
           'soweit gesetzlich zulässig. Der Betreiber bleibt für die Konformität seiner Organisation verantwortlich. Eine '
           'unabhängige Überprüfung durch eigene Prüfer oder Auditoren ist jederzeit möglich, mit: der SHA-256-Prüfsumme dieser '
           'Datei in der signierten SHA256SUMS des Release, "efactl compliance-verify" auf einem installierten Host und dem '
           'offenen Quellcode (AGPL-3.0).'),
}
# Short words in the notice that legal_check (L16) and the website look for.
NOTICE_MARKS = {'en': ('Not a legally binding statement', 'DISCLAIMER.md', 'to the maximum extent permitted by law', 'verified independently'),
                'de': ('Keine rechtlich verbindliche Aussage', 'DISCLAIMER.md', 'soweit gesetzlich zulässig', 'unabhängige Überprüfung')}
WORDS = {
    'en': {'title': 'eFa-next {version}: compliance file', 'version': 'Version', 'commit': 'Commit', 'date': 'Date',
           'summary': 'Coverage per standard', 'standard': 'Standard', 'control': 'Control', 'status': 'Status', 'owner': 'Owner',
           'scope': 'Scope', 'limits': 'Limits', 'evidence': 'Evidence', 'applies': 'Applies', 'ci': 'CI of this release',
           'verify': 'Verify', 'verify_text': 'sha256sum -c SHA256SUMS (after gpg --verify SHA256SUMS.asc), then on a host: '
                                              'efactl compliance-verify [--standard ID].',
           'covered': 'covered', 'partial': 'partial', 'not-covered': 'not covered', 'out-of-scope': 'out of scope',
           'efa-next': 'eFa-next', 'os': 'operating system', 'operator': 'operator', 'shared': 'shared', 'texts': ''},
    'de': {'title': 'eFa-next {version}: Compliance-Datei', 'version': 'Version', 'commit': 'Commit', 'date': 'Datum',
           'summary': 'Abdeckung je Standard', 'standard': 'Standard', 'control': 'Anforderung', 'status': 'Status',
           'owner': 'Zuständig', 'scope': 'Umfang', 'limits': 'Grenzen', 'evidence': 'Nachweis', 'applies': 'Gilt',
           'ci': 'CI dieses Release', 'verify': 'Prüfen',
           'verify_text': 'sha256sum -c SHA256SUMS (nach gpg --verify SHA256SUMS.asc), dann auf einem Host: '
                          'efactl compliance-verify [--standard ID].',
           'covered': 'abgedeckt', 'partial': 'teilweise', 'not-covered': 'nicht abgedeckt', 'out-of-scope': 'außerhalb des Umfangs',
           'efa-next': 'eFa-next', 'os': 'Betriebssystem', 'operator': 'Betreiber', 'shared': 'geteilt',
           'texts': 'Die Texte der Anforderungen sind englisch, wie die Standards selbst.'},
}


def read(path):
    with open(os.path.join(ROOT, path), encoding='utf-8') as f:
        return f.read()


def load(path=SOURCE):
    return json.loads(read(path))


def strong(item):
    """Evidence that is more than a document: a test, a check, a command, code or a rule."""
    return item['type'] != 'file' or not item['ref'].startswith('docs/') and not item['ref'].endswith('.md')


def _command_blocks(efactl):
    """{command: its line in COMMANDS up to the next one}."""
    found = {}
    for match in re.finditer(r"^    '([a-z0-9-]+)': \{'func'(.*?)(?=^    '[a-z0-9-]+': \{'func'|^\}$)", efactl, re.M | re.S):
        found[match.group(1)] = match.group(2)
    return found


def hardening_titles(efactl):
    start = efactl.index('def hardening_checks(f):')
    body = efactl[start:efactl.index('\ndef ', start + 10)]
    return set(re.findall(r"\(\s*'[^':]+:[^']*',\s*'([^'{]+)',", body))


def _tests(root):
    """{module.Class.test} of tests/ (by the syntax tree, without running them)."""
    found = set()
    for name in os.listdir(os.path.join(root, 'tests')):
        if name.startswith('test_') and name.endswith('.py'):
            tree = ast.parse(read(os.path.join('tests', name)))
            for node in tree.body:
                if isinstance(node, ast.ClassDef):
                    found |= {f'{name[:-3]}.{node.name}.{item.name}' for item in node.body
                              if isinstance(item, ast.FunctionDef) and item.name.startswith('test')}
    return found


def static_problems(doc, root=ROOT):
    """(errors, warnings) of the source: evidence for every claim, every reference resolves."""
    errors, warnings = [], []
    efactl = read(EFACTL)
    commands = _command_blocks(efactl)
    titles = hardening_titles(efactl)
    tests = _tests(root)
    standards = set(json.loads(read('next/usr/share/eFa/standards.json'))['standards'])
    rules = set(re.findall(r'<rule id="(\d+)"', read('next/usr/share/eFa/wazuh/efa-next_rules.xml')))
    ci = read('scripts/ci.sh')
    used = set()
    seen_standards = set()
    for standard in doc['standards']:
        if standard['id'] in seen_standards:
            errors.append(f"{standard['id']}: the standard twice")
        seen_standards.add(standard['id'])
        seen = set()
        for control in standard['controls']:
            where = f"{standard['id']} {control['id']}"
            if control['id'] in seen:
                errors.append(f'{where}: the control twice')
            seen.add(control['id'])
            if control['status'] not in STATUSES:
                errors.append(f"{where}: status {control['status']}")
            if control['status'] in ('covered', 'partial') and not any(strong(item) for item in control['evidence']):
                errors.append(f"{where}: {control['status']} without evidence (a document alone is no evidence)")
            for item in control['evidence']:
                kind, ref = item['type'], item['ref']
                problem = None
                if kind == 'test':
                    problem = None if ref in tests else 'no such test'
                elif kind == 'selftest':
                    problem = None if os.path.exists(os.path.join(root, ref)) and f' {ref} ' in ci.replace('\n', ' ') else 'not a self-test of scripts/ci.sh'
                elif kind == 'hardening':
                    used.add(ref)
                    problem = None if ref in titles else 'no such hardening check'
                elif kind == 'standard':
                    problem = None if ref in standards else 'no such security standard (standards.json)'
                elif kind == 'command':
                    block = commands.get(ref)
                    problem = 'no such efactl command' if block is None else None if "'writes': False" in block else 'not a read-only command'
                elif kind == 'file':
                    problem = None if os.path.exists(os.path.join(root, ref)) else 'no such file'
                elif kind == 'wazuh-rule':
                    problem = None if ref in rules else 'no such Wazuh rule'
                else:
                    problem = 'unknown evidence type'
                if problem:
                    errors.append(f'{where}: {kind} {ref}: {problem}')
    warnings += [f'hardening check named by no control: {title}' for title in sorted(titles - used)]
    return errors, warnings


HEADER = re.compile(r'^(test\w*) \(([\w.]+)\)', re.M)
SUMMARY = re.compile(r'^(?:FAIL|ERROR): (test\w*) \(([\w.]+)\)', re.M)


def _test_id(name, where):
    return where if where.endswith('.' + name) else f'{where}.{name}'


def passed_tests(log):
    """module.Class.test of every test that passed in a verbose unittest log (Python 3.9: (module.Class), 3.11+: (module.Class.test)).
    Output of a test (a warning, a print) can stand between its name and its "ok": the part up to the next test counts."""
    failed = {_test_id(name, where) for name, where in SUMMARY.findall(log)}
    headers = list(HEADER.finditer(log))
    found = set()
    for i, header in enumerate(headers):
        part = log[header.end():headers[i + 1].start() if i + 1 < len(headers) else len(log)].split('\n=====', 1)[0]
        test = _test_id(header.group(1), header.group(2))
        if test in failed or re.search(r'(?:^|\.\.\. )(?:skipped|expected failure|FAIL|ERROR)\b', part, re.M):
            continue
        if re.search(r'(?:^|\.\.\. )ok$', part, re.M):
            found.add(test)
    return found


def ci_problems(doc, log, self_tests):
    """Every test the file names passed in this CI run; every self-test it names ran green."""
    passed = passed_tests(log)
    errors = []
    for standard in doc['standards']:
        for control in standard['controls']:
            for item in control['evidence']:
                if item['type'] == 'test' and item['ref'] not in passed:
                    errors.append(f"{standard['id']} {control['id']}: test {item['ref']} did not pass in this CI run")
                elif item['type'] == 'selftest' and self_tests != 'ok':
                    errors.append(f"{standard['id']} {control['id']}: self-test {item['ref']}: the self-tests of this run did not pass")
    return errors


def counts(standard):
    return {status: sum(1 for control in standard['controls'] if control['status'] == status) for status in STATUSES}


def source_sha256():
    """SHA-256 of the shipped controls.json: efactl compliance-verify writes the same into its result, so a result on a host
    is tied to the compliance file of its release."""
    with open(os.path.join(ROOT, SOURCE), 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def release(doc, version, commit, date, ci=None):
    found = {'format': 'efa-next-compliance', 'schema': 1, 'product': 'eFa-next', 'version': version, 'commit': commit, 'date': date,
             'source_sha256': source_sha256(), 'notice': {'legally_binding': False, **NOTICE}, 'disclaimer': 'DISCLAIMER.md'}
    if ci:
        found['ci'] = ci
    found['summary'] = {standard['id']: counts(standard) for standard in doc['standards']}
    found['standards'] = doc['standards']
    return found


def schema_problems(data, schema_path=SCHEMA):
    try:
        import jsonschema
    except ImportError:
        return ['python3-jsonschema is missing: dnf install python3-jsonschema (the schema check)']
    validator = jsonschema.Draft7Validator(json.loads(read(schema_path)))
    return [f"schema: {'/'.join(str(part) for part in error.path)}: {error.message[:200]}" for error in validator.iter_errors(data)][:50]


OSCAL_DIR = 'third-party/oscal-1.1.2'
OSCAL_SCHEMA = 'oscal_component_schema.json'
OSCAL_NS = 'https://efa-next.eu/ns/oscal'
# Official OSCAL control ids only where the catalog is certain: NIST SP 800-53 Rev. 5 (ac-11). Every other standard gets ids of
# the eFa-next namespace (efa-<standard>-<control>), with the id of the standard as the label prop: no made-up official ids.
OSCAL_CATALOGS = {'nist-800-53': 'https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json'}
OSCAL_STATUS = {'covered': 'implemented', 'partial': 'partial', 'out-of-scope': 'not-applicable'}  # not-covered: no OSCAL status


def _uuid(*parts):
    """A fixed UUID (v5) per item: the same file builds the same export."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, OSCAL_NS + '/' + '/'.join(parts)))


def oscal_control_id(standard, control):
    if standard in OSCAL_CATALOGS and re.fullmatch(r'[A-Z]{2}-\d+(\(\d+\))?', control):
        return control.lower().replace('(', '.').replace(')', '')
    return 'efa-' + re.sub(r'[^a-z0-9]+', '-', f'{standard}-{control}'.lower()).strip('-')


def oscal(data):
    """The compliance file as an OSCAL 1.1.2 component-definition: one component eFa-next, one control-implementation per standard."""
    prop = lambda name, value: {'name': name, 'ns': OSCAL_NS, 'value': str(value)}  # noqa: E731
    implementations = []
    for standard in data['standards']:
        requirements = []
        for control in standard['controls']:
            props = [prop('coverage', control['status']), prop('owner', control['owner']), prop('label', control['id'])]
            if control['status'] in OSCAL_STATUS:
                props.append({'name': 'implementation-status', 'value': OSCAL_STATUS[control['status']]})
            props += [prop('evidence', evidence_text(item)) for item in control['evidence']]
            item = {'uuid': _uuid(data['version'], standard['id'], control['id']), 'control-id': oscal_control_id(standard['id'], control['id']),
                    'description': f"{control['title']}: {control['scope']}", 'props': props}
            if control['limits']:
                item['remarks'] = control['limits']
            requirements.append(item)
        implementations.append({'uuid': _uuid(data['version'], standard['id']),
                                'source': OSCAL_CATALOGS.get(standard['id'], f'{OSCAL_NS}/{standard["id"]}'),
                                'description': f"{standard['title']} ({standard['version']}). {standard['applies']}",
                                'props': [prop('standard', standard['id'])], 'implemented-requirements': requirements})
    return {'component-definition': {
        'uuid': _uuid(data['version']),
        'metadata': {'title': f"eFa-next {data['version']}: compliance file", 'last-modified': data['date'] + 'T00:00:00Z',
                     'version': data['version'], 'oscal-version': '1.1.2',
                     'props': [prop('commit', data['commit']), prop('source-sha256', data['source_sha256']), prop('legally-binding', 'false')],
                     'remarks': NOTICE['en'] + '\n\n' + NOTICE['de']},
        'components': [{'uuid': _uuid(data['version'], 'component'), 'type': 'software', 'title': 'eFa-next',
                        'description': 'Self-hosted open source mail security gateway (AGPL-3.0).', 'purpose': 'Mail filtering gateway',
                        'props': [prop('version', data['version'])],
                        'links': [{'href': 'https://github.com/MarkusLorber/eFa-next', 'rel': 'homepage'}],
                        'control-implementations': implementations}]}}


def oscal_problems(document):
    """The check against the official OSCAL schema, pinned by SHA256SUMS. Python re has no \\p{L} or \\p{N}: those two classes
    of the schema are read as [^\\W\\d_] and \\d (letters and digits of any script, as the schema means them)."""
    try:
        import jsonschema
    except ImportError:
        return ['python3-jsonschema is missing: dnf install python3-jsonschema (the OSCAL schema check)']
    with open(os.path.join(ROOT, OSCAL_DIR, OSCAL_SCHEMA), 'rb') as f:
        raw = f.read()
    pinned = dict(line.split()[::-1] for line in read(f'{OSCAL_DIR}/SHA256SUMS').split('\n') if line.strip())
    if hashlib.sha256(raw).hexdigest() != pinned.get(OSCAL_SCHEMA):
        return [f'{OSCAL_DIR}/{OSCAL_SCHEMA}: does not match its SHA256SUMS']
    schema = json.loads(raw.decode('utf-8').replace('\\\\p{L}', '[^\\\\W\\\\d_]').replace('\\\\p{N}', '\\\\d'))
    # The schema names its definitions by "$id": "#name" and refers to them as "#name"; python3-jsonschema 3.2 (EL9) cannot
    # resolve such anchors, so they become JSON pointers to the same definitions.
    anchors = {item['$id']: f'#/definitions/{key}' for key, item in schema['definitions'].items() if str(item.get('$id', '')).startswith('#')}

    def pointers(node):
        if isinstance(node, dict):
            return {key: anchors.get(value, value) if key == '$ref' else pointers(value) for key, value in node.items() if key != '$id' or node is schema}
        return [pointers(item) for item in node] if isinstance(node, list) else node
    schema = pointers(schema)
    validator = jsonschema.Draft7Validator(schema)
    return [f"oscal: {'/'.join(str(part) for part in error.path)}: {error.message[:200]}" for error in validator.iter_errors(document)][:50]


def evidence_text(item):
    if item['type'] == 'command':
        text = f"efactl {item['ref']}"
        return text + (f": {item['key']} = {json.dumps(item['equals'], ensure_ascii=False)}" if 'key' in item else '')
    return f"{item['type']}: {item['ref']}"


def cell(text):
    return str(text).replace('|', '/').replace('\n', ' ')


def markdown(data, lang='en'):
    w = WORDS[lang]
    lines = [f"# {w['title'].format(version=data['version'])}", '', f"> **{data['notice'][lang]}**", '',
             f"{w['version']}: {data['version']} · {w['commit']}: `{data['commit']}` · {w['date']}: {data['date']}", '',
             f"{w['verify']}: `{w['verify_text']}`", '']
    if data.get('ci'):
        lines += [f"{w['ci']}: {data['ci'].get('unit_tests', '')}, self-tests {data['ci'].get('self_tests', '')}.", '']
    if w['texts']:
        lines += [w['texts'], '']
    lines += [f"## {w['summary']}", '', f"| {w['standard']} | {w['covered']} | {w['partial']} | {w['not-covered']} | {w['out-of-scope']} |",
              '| --- | --- | --- | --- | --- |']
    for standard in data['standards']:
        c = data['summary'][standard['id']]
        lines.append(f"| {cell(standard['title'])} | {c['covered']} | {c['partial']} | {c['not-covered']} | {c['out-of-scope']} |")
    for standard in data['standards']:
        lines += ['', f"## {standard['title']}", '', f"{w['version']}: {cell(standard['version'])}. {w['applies']}: {standard['applies']}", '',
                  f"| {w['control']} | {w['status']} | {w['owner']} | {w['scope']} | {w['limits']} | {w['evidence']} |",
                  '| --- | --- | --- | --- | --- | --- |']
        for control in standard['controls']:
            evidence = '<br>'.join(cell(evidence_text(item)) for item in control['evidence']) or '–'
            lines.append(f"| **{cell(control['id'])}** {cell(control['title'])} | {w[control['status']]} | {w[control['owner']]} | "
                         f"{cell(control['scope'])} | {cell(control['limits']) or '–'} | {evidence} |")
    return '\n'.join(lines) + '\n'


def git_commit():
    """The commit of the tree: compliance/COMMIT as git archive fills it in (export-subst; CI has no .git), else git."""
    try:
        text = read('compliance/COMMIT').strip()
        if re.fullmatch(r'[0-9a-f]{40}', text):
            return text
    except OSError:
        pass
    try:
        return subprocess.run(['git', '-C', ROOT, 'rev-parse', 'HEAD'], capture_output=True, text=True, check=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ''


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--version')
    parser.add_argument('--out', default=os.path.join(ROOT, 'compliance'))
    parser.add_argument('--ci-log', help='the verbose unit-test log of this CI run')
    parser.add_argument('--self-tests', choices=('ok', 'failed'))
    parser.add_argument('--commit', default=os.environ.get('EFA_COMMIT') or '')
    parser.add_argument('--date', default=datetime.datetime.now(datetime.timezone.utc).date().isoformat())
    parser.add_argument('--check', action='store_true', help='check the references only, write nothing')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    doc = load()
    errors, warnings = static_problems(doc)
    ci = None
    if args.ci_log:
        with open(args.ci_log, encoding='utf-8', errors='replace') as f:
            log = f.read()
        errors += ci_problems(doc, log, args.self_tests)
        ran = re.search(r'Ran (\d+) tests?', log)
        ci = {'unit_tests': f'Ran {ran.group(1)} tests' if ran else 'unknown', 'self_tests': 'ok',
              'tests_referenced': len({item['ref'] for s in doc['standards'] for c in s['controls'] for item in c['evidence'] if item['type'] == 'test'})}
    data = None
    if not args.check:
        if not args.version or not re.fullmatch(r'\d+(\.\d+){3,5}', args.version):
            errors.append('--version: the release version, such as 6.0.0.6.7')
        else:
            commit = args.commit or git_commit()
            data = release(doc, args.version, commit, args.date, ci if not errors else None)
            errors += schema_problems(data)
            errors += oscal_problems(oscal(data))
    for item in warnings:
        print(f'compliance: warning: {item}')
    for item in errors:
        print(f'compliance: {item}')
    if errors:
        print(f'compliance: FAILED, {len(errors)} problems')
        return 1
    if data is not None:
        os.makedirs(args.out, exist_ok=True)
        base = os.path.join(args.out, f'eFa-next-{args.version}.compliance')
        with open(base + '.json', 'w', encoding='utf-8', newline='\n') as f:
            json.dump(data, f, indent=1, ensure_ascii=False)
            f.write('\n')
        for lang, suffix in (('en', '.md'), ('de', '.de.md')):
            with open(base + suffix, 'w', encoding='utf-8', newline='\n') as f:
                f.write(markdown(data, lang))
        with open(base + '.oscal.json', 'w', encoding='utf-8', newline='\n') as f:
            json.dump(oscal(data), f, indent=1, ensure_ascii=False)
            f.write('\n')
        totals = {status: sum(c[status] for c in data['summary'].values()) for status in STATUSES}
        print(f"compliance: {base}.json/.md/.de.md/.oscal.json: {len(data['standards'])} standards, "
              + ', '.join(f'{status} {number}' for status, number in totals.items()))
    else:
        print('compliance: references ok')
    return 0


def self_test():
    doc = {'standards': [{'id': 'x', 'title': 'X', 'version': '1', 'applies': 'a', 'controls': [
        {'id': '1', 'title': 't', 'status': 'covered', 'owner': 'efa-next', 'scope': 's', 'limits': '', 'evidence': [{'type': 'file', 'ref': 'docs/WAZUH.md'}]},
        {'id': '2', 'title': 't', 'status': 'partial', 'owner': 'shared', 'scope': 's', 'limits': '',
         'evidence': [{'type': 'test', 'ref': 'test_nope.A.test_b'}, {'type': 'command', 'ref': 'admin-idle-set'}, {'type': 'wazuh-rule', 'ref': '1'}]},
        {'id': '2', 'title': 't', 'status': 'out-of-scope', 'owner': 'operator', 'scope': 's', 'limits': '', 'evidence': []}]}]}
    errors, _warnings = static_problems(doc)
    text = '\n'.join(errors)
    assert 'x 1: covered without evidence' in text and 'test_nope.A.test_b: no such test' in text, text
    assert 'admin-idle-set: not a read-only command' in text and 'wazuh-rule 1: no such Wazuh rule' in text and 'the control twice' in text, text
    log = ('test_a (test_m.C) ... ok\ntest_b (test_m.C.test_b) ... ok\ntest_c (test_m.C)\nA doc line ... ok\ntest_d (test_m.C) ... FAIL\n'
           'test_e (test_m.C) ... skipped \'no\'\ntest_f (test_m.C) ... /x.py:1: ResourceWarning: unclosed\n  text = open(x)\nok\n'
           'test_g (test_m.C) ... warning\nok\n\n======\nFAIL: test_g (test_m.C)\n')
    assert passed_tests(log) == {'test_m.C.test_a', 'test_m.C.test_b', 'test_m.C.test_c', 'test_m.C.test_f'}, passed_tests(log)
    one = {'standards': [{'id': 'x', 'controls': [{'id': '1', 'evidence': [{'type': 'test', 'ref': 'test_m.C.test_e'}, {'type': 'selftest', 'ref': 'p'}]}]}]}
    assert len(ci_problems(one, log, 'failed')) == 2 and ci_problems({'standards': []}, '', None) == []
    for lang in ('en', 'de'):
        assert all(mark in NOTICE[lang] for mark in NOTICE_MARKS[lang]), lang
    page = markdown(release(load(), '6.0.0.6.7', '0' * 40, '2026-11-19'), 'de')
    assert page.count('Keine rechtlich verbindliche Aussage') == 1 and ' | abgedeckt | ' in page, page[:400]
    print('self-test ok')
    return 0


if __name__ == '__main__':
    sys.exit(main())
