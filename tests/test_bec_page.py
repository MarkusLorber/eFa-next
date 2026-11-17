# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""6.0.0.6.x (Hans): the page Impersonation & BEC by task. The state once, the VIPs as a list with Remove per row and one add form,
the protected domains (partners to edit, own ones read only), the scores grouped and folded. No function and no field of the
commands is lost, the forms send what efactl expects, every text has its German translation."""
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
sys.dont_write_bytecode = True
import efa_a11y  # noqa: E402
import efa_i18n  # noqa: E402

EFACTL = os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl')
WEB = os.path.join(ROOT, 'next', 'usr', 'local', 'sbin', 'efa-web.py')
DE = os.path.join(ROOT, 'next', 'usr', 'share', 'eFa', 'locale', 'de.po')
SCHEMA = json.loads(subprocess.run([sys.executable, '-B', EFACTL, 'schema'], capture_output=True, text=True, check=True).stdout)
OWN = [f'own{i}.example' for i in range(15)]


def load_web():
    folder = tempfile.mkdtemp(prefix='efa-bec-test-')
    before = os.environ.get('EFA_ETC')
    os.environ['EFA_ETC'] = folder
    loader = importlib.machinery.SourceFileLoader('efa_web_bec', WEB)
    web = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    try:
        loader.exec_module(web)
    finally:
        if before is None:
            os.environ.pop('EFA_ETC', None)
        else:
            os.environ['EFA_ETC'] = before
    web.efa_legal.FOLDER, web.efa_legal.ACCEPTED = folder + '/legal', folder + '/accepted.json'
    web.READ_CACHE_SECONDS.clear()
    web.app.secret_key = b'bec-test'
    return web


class BecPage(unittest.TestCase):
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

    def setUp(self):
        self.calls = []
        self.schema = {name: SCHEMA[name] for name in ('settings', 'bec-status', 'bec-set', 'bec-vip-set', 'bec-partner-set')}
        self.status = {'enabled': True, 'vips': [{'name': 'Jane Doe', 'address': 'jane@own0.example'}], 'partners': ['bank.example'],
                       'relation_days': 365, 'style_min': 5, 'young_days': 30, 'pattern_min': 20, 'own_domains': OWN,
                       'scores': {'vip': 6.0, 'lookalike': 5.0, 'first_contact': 1.0, 'style': 3.0, 'language': 3.0, 'young_domain': 0.0, 'pattern': 0.0}}

        def fake(*args, secrets_in=None, who=None):
            self.calls.append(args)
            if args[0] == 'schema':
                return True, self.schema
            if args[0] == 'bec-status':
                return True, self.status
            if args[0] == 'session-check':
                return True, {'active': True}
            return True, {}
        self.web.efactl = fake

    def page(self, lang='en', view='standard'):
        client = self.web.app.test_client()
        with client.session_transaction(**self.https) as sess:
            sess.update(admin=True, csrf='token', sid='bec', lang=lang, view=view)
        self.web.active_sessions['bec'] = time.time() + 600
        self.web.session_checked['bec'] = time.time()
        reply = client.get('/p/bec', **self.https)
        self.assertEqual(reply.status_code, 200)
        return client, reply.get_data(as_text=True)

    def test_one_card_per_task_and_the_state_once(self):
        for view in ('standard', 'expert'):
            _client, html = self.page(view=view)
            self.assertEqual(re.findall(r'<(?:div|details) class="card[^"]*" id="([a-z-]+)"', html), ['bec-set', 'bec-vip-set', 'bec-partner-set', 'bec-scores'])
            # Before, each of the three forms repeated the whole state (VIPs, partners, days, scores, own domains).
            self.assertNotIn('<th>relation days</th>', html)
            self.assertEqual(html.count('own0.example'), 2, 'the own domains once, plus the address of the VIP')
            self.assertNotIn('name="action" value="add" checked', html, 'no add/remove pick: a button per row instead')
            self.assertIn('<details class="card fold becadv" id="bec-scores">', html, 'the scores folded')

    def test_every_field_of_the_commands_is_on_the_page(self):
        _client, html = self.page()
        for name in ('bec-set', 'bec-vip-set', 'bec-partner-set'):
            form = html[html.index(f'action="/run/{name}"'):]
            for arg in SCHEMA[name]['args']:
                self.assertIn(f'name="{arg["name"]}"', form[:form.index('</form>')], f'{name}.{arg["name"]}')
        # The current values, never a default: the switch, every score, the days and the young days chosen.
        scores = html[html.index('id="bec-scores"'):]
        for arg, value in (('score_vip', '6.0'), ('score_lookalike', '5.0'), ('score_first_contact', '1.0'), ('score_style', '3.0'),
                           ('score_language', '3.0'), ('score_young_domain', '0.0'), ('score_pattern', '0.0'), ('relation_days', '365')):
            self.assertRegex(scores, f'name="{arg}" value="{re.escape(value)}"')
        self.assertIn('<option value="30" selected>', scores)
        self.assertIn('name="mode" value="on"', scores, 'Apply keeps the switch as it is')
        self.assertIn('class="badge on" aria-pressed="true"', html, 'one switch, in the head of the first card')

    def test_remove_and_add_send_what_efactl_expects(self):
        client, html = self.page()
        self.assertIn('data-confirm="Remove VIP Jane Doe?"', html)
        self.assertIn('data-confirm="Remove partner domain bank.example?"', html)
        client.post('/run/bec-vip-set', data={'csrf': 'token', 'action': 'remove', 'name': 'Jane Doe', 'address': ''}, **self.https)
        client.post('/run/bec-vip-set', data={'csrf': 'token', 'action': 'add', 'name': 'John Roe', 'address': 'john@own1.example'}, **self.https)
        client.post('/run/bec-partner-set', data={'csrf': 'token', 'action': 'remove', 'domain': 'bank.example'}, **self.https)
        sent = [call for call in self.calls if call[0] in ('bec-vip-set', 'bec-partner-set')]
        self.assertEqual(sent[0][:3], ('bec-vip-set', '--action=remove', '--name=Jane Doe'))
        self.assertIn('--address=john@own1.example', sent[1])
        self.assertEqual(sent[2], ('bec-partner-set', '--action=remove', '--domain=bank.example'))

    def test_off_says_so_and_empty_lists_invite(self):
        self.status = {**self.status, 'enabled': False, 'vips': [], 'partners': []}
        _client, html = self.page()
        self.assertIn('Off: none of these checks runs. On is recommended.', html)
        self.assertIn('No VIP yet.', html)
        self.assertIn('name="mode" value="off"', html[html.index('id="bec-scores"'):])

    def test_without_the_right_to_change_only_the_lists(self):
        self.schema = {name: SCHEMA[name] for name in ('settings', 'bec-status')}
        _client, html = self.page(view='expert')
        self.assertIn('Jane Doe', html)
        self.assertIn('bank.example', html)
        self.assertNotIn('action="/run/bec-', html)

    def test_german_and_accessible(self):
        _client, html = self.page(lang='de', view='expert')
        self.assertIn('Geschützte Domains', html)
        self.assertIn('Bewertungen und Zeiträume', html)
        self.assertEqual(efa_a11y.page_problems(html), [])
        with open(WEB, encoding='utf-8') as f:
            source = f.read()
        block = source[source.index('{% macro bec_view() %}'):source.index('{% set ns = namespace(hidden=0) %}')]
        self.assertIn('Content and behaviour', block)
        with open(DE, encoding='utf-8') as f:
            de = efa_i18n.po_entries(f.read())
        missing = [text for text in re.findall(r"_\('([^']+)'\)", block) if not de.get(text)]
        missing += [text for text in ('BEC settings saved.', 'VIPs saved.', 'Partner domains saved.') if not de.get(text)]
        self.assertEqual(missing, [])


if __name__ == '__main__':
    unittest.main()
