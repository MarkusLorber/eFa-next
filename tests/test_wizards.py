# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The guided wizards: their texts and help, the efactl calls they end in against the schema, and the frame in efa-web
(wizard first, the manual switch kept in My settings, values from the configuration, rights, the background test)."""
import importlib.machinery
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'python'))
import efa_help  # noqa: E402
import efa_i18n  # noqa: E402
import efa_nav  # noqa: E402
import efa_harden  # noqa: E402
import efa_wizard  # noqa: E402

EFACTL = os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl')
WEB = os.path.join(ROOT, 'next', 'usr', 'local', 'sbin', 'efa-web.py')
DE = os.path.join(ROOT, 'next', 'usr', 'share', 'eFa', 'locale', 'de.po')
SCHEMA = json.loads(subprocess.run([sys.executable, '-B', EFACTL, 'schema'], capture_output=True, text=True, check=True).stdout)


def load_web():
    """efa-web as a module, with its files below a folder of the test and efactl replaced by a fake."""
    folder = tempfile.mkdtemp(prefix='efa-wizard-test-')
    before = os.environ.get('EFA_ETC')
    os.environ['EFA_ETC'] = folder
    loader = importlib.machinery.SourceFileLoader('efa_web_wizards', WEB)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    web = importlib.util.module_from_spec(spec)
    try:
        loader.exec_module(web)
    finally:
        if before is None:
            os.environ.pop('EFA_ETC', None)
        else:
            os.environ['EFA_ETC'] = before
    web.efa_legal.FOLDER, web.efa_legal.ACCEPTED = folder + '/legal', folder + '/accepted.json'
    web.READ_CACHE_SECONDS.clear()
    web.app.secret_key = b'wizard-test'
    return web


class WizardTextTests(unittest.TestCase):
    def test_self_test(self):
        self.assertEqual(efa_wizard.self_test(), 'efa_wizard self-test ok')

    def test_every_wizard_step_and_field_has_help(self):
        missing = [f'{name}.{key}' for name, wizard in efa_wizard.WIZARDS.items()
                   for key in [''] + ['step:' + step['id'] for step in wizard['steps']] + [field['name'] for field in efa_wizard.fields(name)]
                   if not efa_help.WIZARD.get(name, {}).get(key)]
        self.assertEqual(missing, [], 'wizard steps or fields without a help text in efa_help.WIZARD')
        known = {name: {''} | {'step:' + step['id'] for step in wizard['steps']} | {field['name'] for field in efa_wizard.fields(name)}
                 for name, wizard in efa_wizard.WIZARDS.items()}
        unknown = [f'{name}.{key}' for name, texts in efa_help.WIZARD.items() for key in texts if key not in known.get(name, set())]
        self.assertEqual(unknown, [], 'help texts of wizard fields that do not exist')

    def test_every_text_is_german(self):
        with open(DE, encoding='utf-8') as f:
            de = efa_i18n.po_entries(f.read())
        wanted = efa_wizard.all_texts() + [text for texts in efa_help.WIZARD.values() for text in texts.values()]
        with open(WEB, encoding='utf-8') as f:
            source = f.read()
        start = source.index('{#- Guided wizards')
        wanted += re.findall(r"_\('([^']+)'\)", source[start:source.index("{% if not wizard %}", start)])
        wanted += ['New disclaimer', 'New archive target', efa_help.CARD['archive-test']]
        self.assertEqual(sorted({text for text in wanted if not de.get(text)}), [], 'wizard texts without German translation in de.po')

    def test_wizards_on_pages_with_their_command(self):
        for name, wizard in efa_wizard.WIZARDS.items():
            self.assertIn(wizard['page'], efa_nav.PAGES, name)
            self.assertIn(wizard['command'], efa_nav.PAGES[wizard['page']]['commands'], name)
            self.assertNotEqual(wizard['page'], 'dash', 'no wizard on the dashboard')


class WizardCallTests(unittest.TestCase):
    """Each wizard ends in one call of an efactl command, with arguments and values its schema knows."""
    samples = {
        'disclaimer': {'id': efa_wizard.NEW, 'new_id': 'main', 'scope': 'domain', 'domain': 'a.example', 'name': 'Main', 'format': 'html',
                       'text': 'Line one\nLine two', 'html': '<p>Hi</p>', 'enabled': 'on'},
        'archive': {'target': efa_wizard.NEW, 'name': 'mailstore', 'template': 'mailstore', 'address': 'journal@archive.example', 'host': 'archive.example',
                    'port': '25', 'format': 'journal', 'direction': 'both', 'all': efa_wizard.CHOSEN, 'domains': 'a.example,b.example', 'tls': 'verify'},
        'dkim': {'domain': 'a.example', 'kind': 'both', 'bits': '3072'},
        'route': {'domain': 'a.example', 'destination': 'mail.a.example:25'},
    }

    def test_arguments_are_in_the_schema(self):
        for name, values in self.samples.items():
            args = efa_wizard.call(name, values)
            command = SCHEMA[args[0]]
            known = {arg['name']: arg for arg in command['args']}
            for item in args[1:]:
                key, _sep, value = item[2:].partition('=')
                self.assertIn(key, known, f'{name}: --{key}')
                if known[key].get('choices') and value:
                    self.assertIn(value, [choice['value'] for choice in known[key]['choices']], f'{name}: --{key}={value}')
            self.assertTrue(all(arg['name'] in [item[2:].partition('=')[0] for item in args[1:]] for arg in command['args'] if arg.get('required')), name)

    def test_values(self):
        self.assertEqual(efa_wizard.call('archive', self.samples['archive']),
                         ['archive-set', '--name=mailstore', '--template=mailstore', '--address=journal@archive.example', '--host=archive.example', '--port=25',
                          '--direction=both', '--domains=a.example,b.example', '--tls=verify', '--format=journal'])
        self.assertEqual(efa_wizard.call('archive', {**self.samples['archive'], 'all': efa_wizard.ALL})[7], '--domains=', 'all domains: empty')
        self.assertIn('--text=Line one\nLine two', efa_wizard.call('disclaimer', self.samples['disclaimer']))
        self.assertIn('--html=', efa_wizard.call('disclaimer', {**self.samples['disclaimer'], 'format': 'text'}), 'text only sends no HTML')
        self.assertEqual(efa_wizard.call('route', self.samples['route']), ['transport-set', '--domain=a.example', '--action=add', '--destination=mail.a.example:25'])

    def test_archive_tls_choices_are_those_of_efactl(self):
        field = next(item for item in efa_wizard.fields('archive') if item['name'] == 'tls')
        self.assertEqual([value for value, _text in field['choices']], [item['value'] for item in next(arg for arg in SCHEMA['archive-set']['args'] if arg['name'] == 'tls')['choices']])
        self.assertEqual(efa_wizard.NEW_VALUES['archive']['tls'], 'verify', 'a new archive: TLS with a checked certificate')


class WizardWebTests(unittest.TestCase):
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

    def setUp(self):
        web = self.web
        self.calls, self.prefs = [], {'manual': []}
        self.schema = {name: SCHEMA[name] for name in ('settings', 'tenant-list', 'archive-status', 'archive-set', 'archive-test', 'archive-remove',
                                                       'disclaimer-status', 'disclaimer-template-set', 'disclaimer-export', 'my-settings', 'my-settings-set',
                                                       'dkim-check', 'dkim-create', 'transport-set')}
        self.outputs = {
            'settings': {'transports': {'a.example': 'mail.a.example'}},
            'tenant-list': {'tenants': [{'name': 't1', 'domains': ['b.example']}]},
            'archive-status': {'targets': [{'name': 'ms', 'template': 'mailstore', 'address': 'j@archive.example', 'host': 'archive.example', 'port': 2525,
                                            'direction': 'in', 'tls': 'encrypt', 'domains': ['a.example'], 'format': 'journal', 'waiting': 0}]},
            'disclaimer-status': {'templates': [], 'domains': []},
            'dkim-check': {'keys': [{'domain': 'a.example', 'selector': 'efa-rsa', 'type': 'rsa', 'state': 'active'}]},
            'dkim-create': {'domain': 'a.example', 'keys': [{'type': 'ed25519', 'selector': 'efa-ed25519', 'dns_record': 'efa-ed25519._domainkey IN TXT "v=DKIM1; k=ed25519; p=AAA"'}]},
            'archive-test': {'host': 'archive.example', 'port': 2525, 'connect': True, 'starttls': True, 'verified': False, 'error': 'Certificate not valid'},
            'session-check': {'active': True},
        }

        def fake(*args, secrets_in=None, who=None):
            self.calls.append(args)
            if args[0] == 'schema':
                return True, self.schema
            if args[0] == 'my-settings':
                return True, dict(self.prefs)
            if args[0] == 'my-settings-set':
                page, _sep, state = args[1].partition('=')[2].partition(':')
                self.prefs['manual'] = sorted({item for item in self.prefs['manual'] if item != page} | ({page} if state == 'on' else set()))
                return True, dict(self.prefs)
            return True, self.outputs.get(args[0], {'done': True})

        web.efactl = fake
        web.wizard_drafts.clear()
        self.client = self.login()

    def login(self, sid='wiz'):
        client = self.web.app.test_client()
        with client.session_transaction(**self.https) as sess:
            sess.update(admin=True, csrf='token', sid=sid, lang='en', view='standard')
        self.web.active_sessions[sid] = time.time() + 600
        self.web.session_checked[sid] = time.time()
        return client

    def page(self, slug, **args):
        reply = self.client.get(f'/p/{slug}', query_string=args, **self.https)
        self.assertEqual(reply.status_code, 200)
        return reply.get_data(as_text=True)

    def step(self, wizard, step, go='next', **fields):
        return self.client.post(f'/wizard/{wizard}', data={'csrf': 'token', 'step': step, 'go': go, **fields}, **self.https)

    def test_wizard_first_and_the_manual_switch_is_kept(self):
        found = self.page('archive')
        self.assertIn('id="wizard"', found)
        self.assertNotIn('id="archive-set"', found, 'the manual cards wait behind the switch')
        self.assertLess(found.index('<h1>'), found.index('class="wizmode"'), 'the switch sits under the title')
        reply = self.client.post('/wizard-mode', data={'csrf': 'token', 'page': 'archive', 'mode': 'manual'}, **self.https)
        self.assertEqual((reply.status_code, reply.headers['Location']), (303, '/p/archive'))
        self.assertIn(('my-settings-set', '--manual=archive:on'), self.calls)
        found = self.page('archive')
        self.assertIn('id="archive-set"', found)
        self.assertNotIn('id="wizard"', found)
        self.assertIn('value="manual" class="cur"', found)
        # Kept on the server: a new login of the same user starts in the manual view.
        self.client = self.login('wiz2')
        self.assertIn('id="archive-set"', self.page('archive'))
        self.assertIn('id="wizard"', self.page('disclaimer'), 'per page')
        self.client.post('/wizard-mode', data={'csrf': 'token', 'page': 'archive', 'mode': 'wizard'}, **self.https)
        self.assertIn(('my-settings-set', '--manual=archive:off'), self.calls)
        self.assertIn('id="wizard"', self.page('archive'))
        self.assertEqual(self.client.post('/wizard-mode', data={'csrf': 'token', 'page': 'dash', 'mode': 'manual'}, **self.https).status_code, 400)
        self.assertEqual(self.client.post('/wizard-mode', data={'page': 'archive', 'mode': 'manual'}, **self.https).status_code, 403, 'the form token')

    def test_wizard_reads_less(self):
        self.page('archive')
        self.assertNotIn(('archive-remove',), self.calls)
        self.assertEqual({call[0] for call in self.calls} - {'schema', 'my-settings', 'settings', 'tenant-list', 'archive-status'}, set())

    def test_prefilled_from_the_configuration_then_applied(self):
        reply = self.step('archive', 'pick', target='ms', template='mailstore')
        self.assertEqual((reply.status_code, reply.headers['Location']), (303, '/p/archive?w=where#wizard'))
        found = self.page('archive', w='where')
        self.assertIn('value="archive.example"', found)
        self.assertIn('value="2525"', found, 'the port set now, not the default 25')
        self.step('archive', 'where', address='j@archive.example', host='archive.example', port='2525', format='journal')
        found = self.page('archive', w='which')
        self.assertIn('value="in" checked', found)
        self.step('archive', 'which', direction='both', all=efa_wizard.CHOSEN, domains=['a.example', 'b.example'])
        self.step('archive', 'tls', tls='verify')
        summary = self.page('archive', w='summary')
        self.assertIn('<b>Required, certificate checked</b>', summary)
        self.assertNotIn(('archive-set',), [call[:1] for call in self.calls], 'nothing before Apply')
        reply = self.step('archive', 'summary', go='apply')
        self.assertEqual(reply.headers['Location'], '/p/archive?w=summary#wizard')
        self.assertIn(('archive-set', '--name=ms', '--template=mailstore', '--address=j@archive.example', '--host=archive.example', '--port=2525',
                       '--direction=both', '--domains=a.example,b.example', '--tls=verify', '--format=journal'), self.calls)
        done = self.page('archive', w='summary')
        self.assertIn('Done.', done)
        self.assertIn('value="manual">Open the manual view', done)

    def test_back_keeps_the_values(self):
        self.step('archive', 'pick', target=efa_wizard.NEW, template='piler')
        reply = self.step('archive', 'where', go='back', name='pil', address='x@archive.example', host='h.example', port='25', format='copy')
        self.assertEqual(reply.headers['Location'], '/p/archive?w=pick#wizard')
        found = self.page('archive', w='where')
        self.assertIn('value="h.example"', found)
        self.assertIn('value="restart"', found, 'Start again on every step after the first')
        self.assertIn('value="piler" checked', self.page('archive', w='pick'))
        self.step('archive', 'where', go='restart')
        self.assertIn('value="mailstore" checked', self.page('archive', w='pick'), 'Start again forgets the draft')

    def test_values_outside_the_choices_are_refused(self):
        self.step('archive', 'pick', target='ms', template='mailstore')
        self.step('archive', 'which', direction='both', all=efa_wizard.CHOSEN, domains=['evil.example'])
        self.assertIn('Choose a value from the list.', self.page('archive', w='which'))
        self.step('archive', 'tls', tls='none')
        self.assertIn('Choose a value from the list.', self.page('archive', w='tls'))
        self.step('archive', 'summary', go='apply')
        applied = next(call for call in self.calls if call[0] == 'archive-set')
        self.assertIn('--tls=encrypt', applied, 'a refused value never gets into the draft')
        self.assertIn('--domains=a.example', applied)

    def test_a_choice_that_opens_a_field_shows_the_step_again(self):
        self.step('disclaimer', 'pick', id=efa_wizard.NEW)
        reply = self.step('disclaimer', 'scope', new_id='main', scope='domain')
        self.assertEqual(reply.headers['Location'], '/p/disclaimer?w=scope#wizard')
        found = self.page('disclaimer', w='scope')
        self.assertIn('name="domain"', found)
        self.assertNotIn('class="err"', found, 'no error for the field that was not there yet')
        reply = self.step('disclaimer', 'scope', new_id='main', scope='domain', domain='b.example')
        self.assertEqual(reply.headers['Location'], '/p/disclaimer?w=text#wizard')

    def test_a_later_step_starts_at_the_beginning_without_its_object(self):
        found = self.page('archive', w='summary')
        self.assertIn('name="step" value="pick"', found)

    def test_connection_test_in_the_background(self):
        self.step('archive', 'pick', target='ms', template='mailstore')
        reply = self.step('archive', 'tls', go='test', tls='verify')
        self.assertEqual(reply.headers['Location'], '/p/archive?w=tls#wizard')
        for _wait in range(50):
            if self.client.get('/wizard/archive/test', **self.https).get_json()['state'] == 'done':
                break
            time.sleep(0.05)
        self.assertIn(('archive-test', '--host=archive.example', '--port=2525'), self.calls)
        found = self.page('archive', w='tls')
        self.assertIn('Certificate not valid', found)
        self.assertEqual(self.client.get('/wizard.js', **self.https).mimetype, 'text/javascript')

    def test_one_connection_test_at_a_time(self):
        self.step('archive', 'pick', target='ms', template='mailstore')
        self.web.wizard_drafts[('wiz', 'archive')]['test'] = {'state': 'running'}
        before = len([call for call in self.calls if call[0] == 'archive-test'])
        self.step('archive', 'tls', go='test', tls='verify')
        self.step('archive', 'tls', go='test', tls='verify')
        time.sleep(0.2)
        self.assertEqual(len([call for call in self.calls if call[0] == 'archive-test']), before, 'no new thread while one runs')

    def test_rights_of_the_login(self):
        del self.schema['archive-set']
        found = self.page('archive')
        self.assertNotIn('id="wizard"', found)
        self.assertNotIn('class="wizmode"', found, 'no switch without the wizard')
        self.assertEqual(self.step('archive', 'pick', target='ms', template='mailstore').status_code, 403)
        del self.schema['archive-test']
        self.schema['archive-set'] = SCHEMA['archive-set']
        self.step('archive', 'pick', target='ms', template='mailstore')
        self.assertNotIn('value="test"', self.page('archive', w='tls'), 'the test only with its command')

    def test_drafts_belong_to_their_session(self):
        self.step('archive', 'pick', target='ms', template='mailstore')
        self.client = self.login('other')
        self.assertIn('name="step" value="pick"', self.page('archive', w='where'))

    def test_disclaimer_preview_runs_nothing(self):
        self.step('disclaimer', 'pick', id=efa_wizard.NEW)
        self.step('disclaimer', 'scope', new_id='main', scope='global')
        self.step('disclaimer', 'text', name='Main', format='html', text='Hello', html='<p onclick="x()">Hi</p><script>alert(1)</script>')
        found = self.page('disclaimer', w='preview')
        self.assertIn('<iframe sandbox=""', found)
        self.assertIn('srcdoc="&lt;p onclick=&#34;x()&#34;&gt;Hi&lt;/p&gt;&lt;script&gt;', found)
        self.assertNotIn('<script>alert', found)
        self.step('disclaimer', 'preview', enabled='on')
        self.step('disclaimer', 'summary', go='apply')
        call = next(call for call in self.calls if call[0] == 'disclaimer-template-set')
        self.assertEqual(call[:6], ('disclaimer-template-set', '--id=main', '--name=Main', '--scope=global', '--target=', '--format=html'))

    def test_dkim_shows_the_record(self):
        self.step('dkim', 'domain', domain='a.example')
        self.assertIn('rsa (efa-rsa)', self.page('dkim', w='key'))
        self.step('dkim', 'key', kind='both', bits='2048')
        self.step('dkim', 'summary', go='apply')
        self.assertIn(('dkim-create', '--domain=a.example', '--kind=both', '--bits=2048'), self.calls)
        self.assertIn('k=ed25519; p=AAA', self.page('dkim'))

    def test_an_error_of_efactl_stays_on_the_summary(self):
        self.outputs['transport-set'] = None
        original = self.web.efactl

        def failing(*args, **kwargs):
            if args[0] == 'transport-set':
                self.calls.append(args)
                return False, {'error': 'Invalid destination host.'}
            return original(*args, **kwargs)

        self.web.efactl = failing
        self.step('route', 'domain', domain='c.example')
        self.step('route', 'server', destination='bad host')
        self.step('route', 'summary', go='apply')
        found = self.page('flow', w='summary')
        self.assertIn('Invalid destination host.', found)
        self.assertIn('value="apply"', found)



class HardeningWizardTests(unittest.TestCase):
    """HARD-W: the hardening wizard on the page Security standards: super admins only, the password and the 2FA code as on the
    manual card, a preview before Apply, and exactly one call of standards-set."""
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

    def setUp(self):
        web = self.web
        self.calls, self.prefs = [], {'manual': []}
        self.schema = {name: SCHEMA[name] for name in ('settings', 'tenant-list', 'my-settings', 'my-settings-set', 'standards-status', 'standards-show',
                                                       'standards-check', 'standards-set', 'standards-preview', 'standards-rollback', 'os-harden-status',
                                                       'os-harden-set')}
        harden = {'items': [{'id': key, 'on': key in ('chronyd', 'ssh-profile')} for key in efa_harden.OS_ITEMS],
                  'efa': [{'id': key, 'on': key == 'tls-min'} for key in efa_harden.EFA_ITEMS],
                  'hints': [{'id': key, 'text': text, 'on': None} for key, text in efa_harden.HINTS.items()],
                  'foreign': ['tcp 0.0.0.0:36787 other-runner']}
        self.outputs = {
            'settings': {}, 'tenant-list': {'tenants': []},
            'standards-status': {'selected': ['rfc9325'], 'port25_tls': 'off', 'port25_mode': 'off', 'port25_without_tls_7d': 3, 'port25_sessions_7d': 40,
                                 'standards': [{'id': sid, 'title': f'Title {sid}', 'version': '2026'} for sid in efa_harden.known()], 'rollback': False},
            'standards-show': {'checked': '2026-11-11', 'standards': {'bsi-02102-2': {'status': 'not', 'rows': [
                {'setting': 'certificate web', 'status': 'not', 'now': 'rsa 2048 bits', 'wanted': 'RSA from 3000'}]}}},
            'os-harden-status': harden,
            'standards-preview': {'selected': ['bsi-02102-2', 'rfc9325'], 'changes': [{'setting': 'TLS profile', 'now': 'rfc9325', 'then': 'bsi', 'because': 'x'}],
                                  'warnings': ['eFa-next keeps the groups X25519']},
            'standards-set': {'applied': True, 'selected': ['bsi-02102-2', 'rfc9325'], 'changed': ['TLS profile'],
                              'check': {'bsi-02102-2': {'title': 'BSI TR-02102-2 (TLS)', 'status': 'not'}}},
            'session-check': {'active': True},
        }

        def fake(*args, secrets_in=None, who=None):
            self.calls.append(args)
            if args[0] == 'schema':
                return True, self.schema
            if args[0] == 'my-settings':
                return True, dict(self.prefs)
            if args[0] == 'my-settings-set':
                page, _sep, state = args[1].partition('=')[2].partition(':')
                self.prefs['manual'] = sorted({item for item in self.prefs['manual'] if item != page} | ({page} if state == 'on' else set()))
                return True, dict(self.prefs)
            return True, self.outputs.get(args[0], {'done': True})

        web.efactl = fake
        web.wizard_drafts.clear()
        web.read_cache.clear()
        web.login_failures.clear()
        folder = tempfile.mkdtemp(prefix='efa-harden-web-')
        web.PASSWORD_FILE = folder + '/admin.pw'
        with open(web.PASSWORD_FILE, 'w') as f:
            f.write('stored')
        web.password_ok = lambda stored, password: stored == 'stored' and password == 'Right-Pass-2026'
        web.admin_second_factor = lambda code: code == '123456'
        self.client = self.login()

    def login(self, sid='hard'):
        client = self.web.app.test_client()
        with client.session_transaction(**self.https) as sess:
            sess.update(admin=True, csrf='token', sid=sid, lang='en', view='standard')
        self.web.active_sessions[sid] = time.time() + 600
        self.web.session_checked[sid] = time.time()
        return client

    def page(self, **args):
        reply = self.client.get('/p/standards', query_string=args, **self.https)
        self.assertEqual(reply.status_code, 200)
        return reply.get_data(as_text=True)

    def step(self, step, go='next', **fields):
        return self.client.post('/wizard/hardening', data={'csrf': 'token', 'step': step, 'go': go, **fields}, **self.https)

    def walk(self):
        self.step('standards', select=['bsi-02102-2', 'rfc9325'])
        self.step('port25', port25='off')
        os_items = {f'os_{key}': 'on' if key in ('auditd', 'sshd-cis') else 'keep' for key in efa_harden.OS_ITEMS}
        self.step('os', **os_items)
        self.step('efa', **{f'efa_{key}': 'keep' for key in efa_harden.EFA_ITEMS})
        return os_items

    def applied(self):
        return [call for call in self.calls if call[0] == 'standards-set']

    def test_only_with_standards_set_in_the_schema(self):
        found = self.page()
        self.assertIn('id="wizard"', found)
        self.assertIn('name="select" value="cis-el"', found)
        self.assertIn('name="select" value="rfc9325" checked', found, 'prefilled from standards-status')
        self.assertNotIn('name="select" value="bsi-02102-2" checked', found)
        self.assertEqual({call[0] for call in self.calls} - {'schema', 'my-settings', 'settings', 'tenant-list', 'standards-status', 'standards-show'}, set(),
                         'the page reads only standards-status and standards-show')
        # Any login but a super admin: efactl leaves standards-set out of its schema (SUPER_COMMANDS).
        del self.schema['standards-set']
        found = self.page()
        self.assertNotIn('id="wizard"', found)
        self.assertEqual(self.step('standards', select=['rfc9325']).status_code, 403)

    def test_steps_preview_and_apply_with_the_password(self):
        os_items = self.walk()
        self.assertIn(('os-harden-status',), self.calls, 'read before the step, not by the page')
        args = efa_wizard.harden_args({'select': 'bsi-02102-2,rfc9325', 'port25': 'off', **os_items})
        self.assertIn(('standards-preview', *args), self.calls)
        found = self.page(w='preview')
        self.assertIn('eFa-next keeps the groups X25519', found)
        self.assertIn('certificate web', found, 'what this wizard does not change')
        self.assertIn('name="ack"', found, 'the tick box: there are warnings')
        self.assertNotIn('The preview shows no pictures', found, 'not the preview block of the disclaimer wizard')
        self.assertLess(found.index('eFa-next keeps the groups X25519'), found.index('name="ack"'), 'the tick box after the warnings')
        self.step('preview', ack='')
        self.assertIn('Tick the box to go on.', self.page(w='preview'))
        self.step('preview', ack='yes')
        summary = self.page(w='summary')
        self.assertIn('name="reauth"', summary)
        self.assertIn('name="reauth_code"', summary)
        self.step('summary', go='apply')
        self.assertIn(self.web.REAUTH_FAILED, self.page(w='summary'))
        self.step('summary', go='apply', reauth='wrong', reauth_code='123456')
        self.assertIn(self.web.REAUTH_FAILED, self.page(w='summary'))
        self.assertEqual(self.applied(), [], 'nothing applied without the right password and 2FA code')
        self.step('summary', go='apply', reauth='Right-Pass-2026', reauth_code='123456')
        self.assertEqual(self.applied(), [('standards-set', *args, '--apply=yes', '--confirm=yes')])
        self.assertNotIn('Right-Pass-2026', json.dumps(list(self.web.wizard_drafts.values()), default=str), 'never in the draft')
        done = self.page(w='summary')
        self.assertIn('Done.', done)
        self.assertIn('BSI TR-02102-2 (TLS)', done)
        self.assertIn('value="manual">Open the manual view', done)

    def test_os_step_shows_state_hints_and_foreign_services(self):
        self.step('standards', select=['cis-el'])
        self.step('port25', port25='off')
        found = self.page(w='os')
        self.assertIn('tcp 0.0.0.0:36787 other-runner', found)
        self.assertIn('SELinux enforcing', found)
        self.assertIn('name="os_auditd" value="on" checked', found, 'cis-el asks for it')
        self.assertIn('name="os_crypto-future" value="keep" checked', found, 'FUTURE only on purpose')

    def test_a_changed_draft_needs_its_preview(self):
        self.walk()
        self.step('preview', ack='yes')
        self.step('efa', go='back', **{f'efa_{key}': 'on' if key == 'audit-mode' else 'keep' for key in efa_harden.EFA_ITEMS})
        self.step('summary', go='apply', reauth='Right-Pass-2026', reauth_code='123456')
        self.assertEqual(self.applied(), [])
        self.assertIn('Open the preview first.', self.page(w='summary'))

    def test_start_again_drops_the_preview(self):
        self.walk()
        self.step('preview', ack='yes')
        self.step('summary', go='restart')
        self.assertIn('name="select" value="rfc9325" checked', self.page(), 'back to step 1, prefilled again')
        self.step('summary', go='apply', reauth='Right-Pass-2026', reauth_code='123456')
        self.assertEqual(self.applied(), [], 'nothing applied after Start again')

    def test_manual_switch_kept(self):
        self.client.post('/wizard-mode', data={'csrf': 'token', 'page': 'standards', 'mode': 'manual'}, **self.https)
        found = self.page()
        self.assertIn('id="standards-set"', found)
        self.assertNotIn('id="wizard"', found)

    def test_link_on_the_security_page(self):
        self.schema['firewall-show'] = SCHEMA['firewall-show']
        reply = self.client.get('/p/sec', **self.https)
        self.assertIn('/p/standards#wizard', reply.get_data(as_text=True))


if __name__ == '__main__':
    unittest.main()
