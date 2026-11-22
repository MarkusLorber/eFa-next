# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The compliance file of a release (scripts/compliance_build.py): every claim has evidence beyond a document, every reference
resolves, the file matches compliance/compliance.schema.json, the notice (not legally binding, independent checks, DISCLAIMER.md)
is in the JSON and both Markdown files, and efactl compliance-verify turns the evidence into results on a host."""
import copy
import json
import os
import shutil
import sys
import tempfile
import unittest

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(TOP, 'scripts'))
import compliance_build  # noqa: E402
import compliance_diff  # noqa: E402


class Build(unittest.TestCase):
    def setUp(self):
        self.doc = compliance_build.load()

    def test_references_resolve(self):
        errors, _warnings = compliance_build.static_problems(self.doc)
        self.assertEqual(errors, [])

    def test_release_file_is_valid(self):
        try:
            import jsonschema  # noqa: F401
        except ImportError:
            self.skipTest('python3-jsonschema missing')
        data = compliance_build.release(self.doc, '6.0.0.6.7', 'a' * 40, '2026-11-19', {'unit_tests': 'Ran 1 tests', 'self_tests': 'ok'})
        self.assertEqual(compliance_build.schema_problems(data), [])
        self.assertIs(data['notice']['legally_binding'], False)
        self.assertTrue(compliance_build.schema_problems({**data, 'commit': 'abc'}))
        broken = copy.deepcopy(data)
        broken['standards'][0]['controls'][0]['status'] = 'certified'
        self.assertTrue(compliance_build.schema_problems(broken), 'no status beyond the four')

    def test_oscal_export_is_valid(self):
        """The OSCAL component-definition against the pinned official schema; official ids only for NIST SP 800-53."""
        try:
            import jsonschema  # noqa: F401
        except ImportError:
            self.skipTest('python3-jsonschema missing')
        data = compliance_build.release(self.doc, '6.0.0.6.7', 'a' * 40, '2026-11-19')
        document = compliance_build.oscal(data)
        self.assertEqual(compliance_build.oscal_problems(document), [])
        implementations = document['component-definition']['components'][0]['control-implementations']
        ids = {impl['props'][0]['value']: [r['control-id'] for r in impl['implemented-requirements']] for impl in implementations}
        self.assertIn('ac-11', ids['nist-800-53'])
        self.assertTrue(all(i.startswith('efa-') for std, found in ids.items() if std != 'nist-800-53' for i in found))
        self.assertIn(compliance_build.NOTICE['de'], document['component-definition']['metadata']['remarks'])
        broken = copy.deepcopy(document)
        broken['component-definition']['components'][0]['type'] = ''
        self.assertTrue(compliance_build.oscal_problems(broken), 'an invalid export is found')
        self.assertEqual(compliance_build.oscal(data), document, 'the same file builds the same export')

    def test_claims_without_evidence_fail(self):
        doc = copy.deepcopy(self.doc)
        control = doc['standards'][0]['controls'][0]
        control.update(status='covered', evidence=[{'type': 'file', 'ref': 'docs/WAZUH.md'}])
        doc['standards'][0]['controls'].append({**control, 'id': 'X-1', 'evidence': [{'type': 'command', 'ref': 'no-such-command'}]})
        errors, _warnings = compliance_build.static_problems(doc)
        self.assertTrue(any('without evidence' in item for item in errors), errors)
        self.assertTrue(any('no-such-command: no such efactl command' in item for item in errors), errors)

    def test_a_test_must_have_passed_in_the_ci_log(self):
        ref = next(item['ref'] for s in self.doc['standards'] for c in s['controls'] for item in c['evidence'] if item['type'] == 'test')
        module, cls, name = ref.split('.')
        self.assertEqual(compliance_build.ci_problems({'standards': [{'id': 'x', 'controls': [{'id': '1', 'evidence': [{'type': 'test', 'ref': ref}]}]}]},
                                                      f'{name} ({module}.{cls}) ... ok\n', 'ok'), [])
        self.assertTrue(compliance_build.ci_problems(self.doc, f'{name} ({module}.{cls}) ... FAIL\n', 'ok'))

    def test_notice_in_both_markdown_files(self):
        data = compliance_build.release(self.doc, '6.0.0.6.7', 'a' * 40, '2026-11-19')
        for lang in ('en', 'de'):
            page = compliance_build.markdown(data, lang)
            head = page[:1500]
            for mark in compliance_build.NOTICE_MARKS[lang]:
                self.assertIn(mark, head, f'{lang}: "{mark}" near the top')
        self.assertNotRegex(json.dumps(self.doc).lower(), r'\bcertified\b|\bcompliant with\b|\berfüllt\b')

    def test_legal_rule_l16(self):
        import legal_check
        self.assertEqual(legal_check.compliance_notice_problems(), [])
        saved = dict(compliance_build.NOTICE)
        try:
            compliance_build.NOTICE['de'] = saved['de'].replace('soweit gesetzlich zulässig', 'immer')
            self.assertTrue(any(item.startswith('L16 compliance notice de') for item in legal_check.compliance_notice_problems()))
        finally:
            compliance_build.NOTICE.update(saved)

    def test_writes_the_three_files(self):
        out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out, True)
        code = compliance_build.main(['--version', '6.0.0.6.7', '--out', out, '--commit', 'b' * 40, '--date', '2026-11-19'])
        try:
            import jsonschema  # noqa: F401
        except ImportError:
            self.assertEqual(code, 1, 'without the schema check nothing is written')
            return
        self.assertEqual(code, 0)
        self.assertEqual(sorted(os.listdir(out)), ['eFa-next-6.0.0.6.7.compliance.de.md', 'eFa-next-6.0.0.6.7.compliance.json',
                                                   'eFa-next-6.0.0.6.7.compliance.md', 'eFa-next-6.0.0.6.7.compliance.oscal.json'])


class Diff(unittest.TestCase):
    def test_first_and_next_release(self):
        data = compliance_build.release(compliance_build.load(), '6.0.0.6.7', 'a' * 40, '2026-11-19')
        self.assertIn('First release with a compliance file', compliance_diff.markdown(None, data))
        later = copy.deepcopy(data)
        later['version'] = '6.0.0.6.8'
        later['standards'][0]['controls'][0]['status'] = 'not-covered'
        self.assertIn('status ', compliance_diff.markdown(data, later))


class Verify(unittest.TestCase):
    """efactl compliance_evaluate with the facts of a host given here (the real ones need an installed host)."""

    @classmethod
    def setUpClass(cls):
        if not hasattr(os, 'geteuid'):
            raise unittest.SkipTest('efactl runs on Linux only')
        from test_cluster_sync_2fa import load_efactl
        cls.efactl = load_efactl()

    def test_results(self):
        doc = {'standards': [{'id': 'x', 'controls': [
            {'id': 'ok', 'title': 't', 'status': 'covered', 'owner': 'efa-next', 'evidence': [
                {'type': 'hardening', 'ref': 'A'}, {'type': 'command', 'ref': 'admin-idle-status', 'key': 'at_most_15', 'equals': True},
                {'type': 'test', 'ref': 'test_m.C.test_a'}, {'type': 'wazuh-rule', 'ref': '108011'}, {'type': 'file', 'ref': 'next/usr/x'}]},
            {'id': 'bad', 'title': 't', 'status': 'partial', 'owner': 'shared', 'evidence': [
                {'type': 'standard', 'ref': 'bsi-03108'}, {'type': 'command', 'ref': 'admin-idle-status', 'key': 'at_most_15', 'equals': False}]},
            {'id': 'ci', 'title': 't', 'status': 'covered', 'owner': 'efa-next', 'evidence': [{'type': 'test', 'ref': 'test_m.C.test_a'}]},
            {'id': 'org', 'title': 't', 'status': 'out-of-scope', 'owner': 'operator', 'evidence': []}]}]}
        facts = {'hardening': {'A': 'pass'}, 'standards': {'bsi-03108': 'needs'}, 'run': lambda ref: ('ok', {'at_most_15': True}),
                 'exists': lambda path: path == '/usr/x', 'rules': {'108011'}}
        results, summary = self.efactl.compliance_evaluate(doc, facts)
        self.assertEqual([item['result'] for item in results], ['pass', 'fail', 'not-applicable', 'operator'])
        self.assertEqual(summary['x'], {'pass': 1, 'fail': 1, 'not-applicable': 1, 'operator': 1})
        self.assertEqual(results[0]['checks'][2]['result'], 'release', 'tests were checked by the CI of the release')

    def test_commands_with_arguments_are_not_run(self):
        self.assertEqual(self.efactl._compliance_command('gdpr-export', {}), ('release', None))
        self.assertEqual(self.efactl._compliance_command('compliance-verify', {}), ('release', None))
        self.assertEqual(self.efactl.COMMAND_PERMISSIONS['compliance-verify'], 'audit.view')
        self.assertFalse(self.efactl.COMMANDS['compliance-verify']['writes'])

    def signed(self, result=None):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        key = ed25519.Ed25519PrivateKey.generate()
        result = result or {'format': 'efa-next-compliance-result', 'host': 'mx.example', 'checked': '2026-11-19T18:00:00Z', 'version': '6.0.0.6.7',
                            'source_sha256': 'a' * 64, 'standard': 'all', 'summary': {'x': {'pass': 1}}, 'results': []}
        return key, self.efactl.compliance_result_zip(result, key)

    def test_signed_result_round_trip_and_tamper(self):
        import base64
        import io
        import zipfile
        key, found = self.signed()
        data = base64.b64decode(found['zip'])
        result, fingerprint = self.efactl.compliance_result_check(data, found['fingerprint'])
        self.assertEqual((result['host'], fingerprint, result['signer']['fingerprint']), ('mx.example', found['fingerprint'], found['fingerprint']))
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        self.assertEqual(sorted(files), ['README.txt', 'result.json', 'result.json.sig', 'signer.pub.pem'])

        def rezip(**changed):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as archive:
                for name, body in {**files, **changed}.items():
                    archive.writestr(name, body)
            return buffer.getvalue()
        with self.assertRaises(self.efactl.EfaError):
            self.efactl.compliance_result_check(rezip(**{'result.json': files['result.json'].replace(b'"pass": 1', b'"pass": 2')}))
        other_key, other = self.signed()
        with zipfile.ZipFile(io.BytesIO(base64.b64decode(other['zip']))) as archive:
            other_pem = archive.read('signer.pub.pem')
        with self.assertRaises(self.efactl.EfaError, msg='another key in the zip'):
            self.efactl.compliance_result_check(rezip(**{'signer.pub.pem': other_pem, 'result.json.sig': other_key.sign(files['result.json'])}))
        with self.assertRaises(self.efactl.EfaError, msg='expected fingerprint'):
            self.efactl.compliance_result_check(data, other['fingerprint'])
        with self.assertRaises(self.efactl.EfaError):
            self.efactl.compliance_result_check(b'not a zip')
        # The documented check with OpenSSL alone.
        import shutil
        import subprocess
        if shutil.which('openssl'):
            folder = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, folder, True)
            for name, body in files.items():
                with open(os.path.join(folder, name), 'wb') as f:
                    f.write(body)
            done = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', 'signer.pub.pem', '-rawin', '-in', 'result.json',
                                   '-sigfile', 'result.json.sig'], cwd=folder, capture_output=True, text=True)
            self.assertIn('Signature Verified Successfully', done.stdout + done.stderr)

    def test_signed_only_for_the_whole_system(self):
        import argparse
        from unittest import mock
        for grants, allowed in (({'audit.view': None}, True), ({'audit.view': {'tenants': {3}, 'domains': set()}}, False), ({}, False)):
            with mock.patch.object(self.efactl, 'identity_now', {'username': 'u', 'role': 'admin', 'grants': grants}), \
                    mock.patch.object(self.efactl, 'COMPLIANCE_FILE', '/nonexistent/controls.json'):
                with self.assertRaises(self.efactl.EfaError) as caught:
                    self.efactl.compliance_verify(argparse.Namespace(standard='', signed=True))
                self.assertEqual('missing or unreadable' in str(caught.exception), allowed, grants)

    def test_check_is_console_only(self):
        import argparse
        from unittest import mock
        with mock.patch.object(self.efactl, '_web_call', lambda: True):
            with self.assertRaises(self.efactl.EfaError):
                self.efactl.compliance_verify_check(argparse.Namespace(file='/etc/shadow', fingerprint=''))

    def test_web_route(self):
        import base64
        from test_bec_page import load_web
        web = load_web()
        self.assertEqual(web.ROUTE_RIGHTS['compliance_zip'], 'efactl')
        calls = []

        def fake(*args, **kwargs):
            calls.append(args)
            return (True, {'name': 'r.zip', 'zip': base64.b64encode(b'PK').decode()}) if args[0] == 'compliance-verify' else (True, {'active': True})
        web.efactl = fake
        client = web.app.test_client()
        https = {'base_url': 'https://localhost'}
        with client.session_transaction(**https) as sess:
            sess.update(admin=True, csrf='token', sid='cz', lang='en')
        web.active_sessions['cz'] = __import__('time').time() + 600
        self.assertEqual(client.post('/compliance-result.zip', data={'csrf': 'wrong'}, **https).status_code, 403)
        reply = client.post('/compliance-result.zip', data={'csrf': 'token', 'standard': 'pci-dss'}, **https)
        self.assertEqual((reply.status_code, reply.mimetype, reply.data), (200, 'application/zip', b'PK'))
        self.assertIn(('compliance-verify', '--signed', '--standard=pci-dss'), calls)

    def test_shipped_source_is_the_one_checked(self):
        self.assertEqual(self.efactl.COMPLIANCE_FILE, '/' + compliance_build.SOURCE[len('next/'):])


if __name__ == '__main__':
    unittest.main()
