# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The page Mail routing by importance (Hans 2026-11-15): the domains first and in both views, held accounts on top, lists shown
and forms folded; every command and field of before is still there, with the current values; German texts."""
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
import efa_nav  # noqa: E402

EFACTL = os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl')
WEB = os.path.join(ROOT, 'next', 'usr', 'local', 'sbin', 'efa-web.py')
DE = os.path.join(ROOT, 'next', 'usr', 'share', 'eFa', 'locale', 'de.po')
SCHEMA = json.loads(subprocess.run([sys.executable, '-B', EFACTL, 'schema'], capture_output=True, text=True, check=True).stdout)
DOMAINS = [f'd{number:02}.example' for number in range(30)]


def load_web():
    folder = tempfile.mkdtemp(prefix='efa-flow-test-')
    before = os.environ.get('EFA_ETC')
    os.environ['EFA_ETC'] = folder
    loader = importlib.machinery.SourceFileLoader('efa_web_flow', WEB)
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
    web.app.secret_key = b'flow-test'
    return web


class MailRoutingPage(unittest.TestCase):
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

    def setUp(self):
        self.prefs = {'manual': ['flow']}
        self.held = [{'who': 'acc@d01.example', 'since': '2026-11-15 21:04', 'reason': 'over the limit'}]
        names = set(efa_nav.PAGES['flow']['commands']) | {'settings', 'tenant-list', 'my-settings', 'my-settings-set'}
        self.schema = {name: SCHEMA[name] for name in names if name in SCHEMA}
        transports = {domain: 'mail.example' for domain in DOMAINS}
        transports['lab.example'] = '[192.0.2.9]:25'
        self.outputs = {
            'settings': {'transports': transports, 'message_size_limit_mb': 42, 'recipient_verification': 'on', 'smarthost': 'relay.example'},
            'relay-networks-list': {'networks': [{'network': '127.0.0.0/8', 'family': 'IPv4', 'description': 'system', 'state': 'active', 'locked': True},
                                                 {'network': '192.0.2.0/24', 'family': 'IPv4', 'description': 'office', 'state': 'active', 'locked': False}],
                                    'added': [], 'removed': [], 'pending': False, 'warnings': [], 'unknown': []},
            'submitter-list': {'submitters': [{'name': 'exchange', 'tenant': '', 'kind': 'ip', 'value': '192.0.2.1/32', 'domains': ['d01.example']}],
                               'limits': {'recipients_hour': 321, 'domains_hour': 0, 'domain_recipients_hour': 0, 'tenant_recipients_hour': 0,
                                          'action': 'hold', 'auto_hold': True}},
            'header-privacy-status': {'all': False, 'domains': ['d02.example'], 'submitters': [], 'removed': ['Received']},
            'tls-partner-list': {'partners': [{'domain': 'bank.example', 'out': 'verify', 'in': True}]},
            'session-check': {'active': True},
        }
        self.calls = []

        def fake(*args, secrets_in=None, who=None):
            self.calls.append(args)
            if args[0] == 'schema':
                return True, self.schema
            if args[0] == 'my-settings':
                return True, dict(self.prefs)
            if args[0] == 'hijack-list':
                return True, {'held': list(self.held), 'auto_hold': True}
            return True, self.outputs.get(args[0], {'done': True})

        self.web.efactl = fake
        self.web.READ_CACHE_SECONDS.clear()
        if hasattr(self.web, 'read_cache'):
            self.web.read_cache.clear()

    def page(self, view='expert', lang='en', **args):
        client = self.web.app.test_client()
        sid = f'flow{time.time()}'
        with client.session_transaction(**self.https) as sess:
            sess.update(admin=True, csrf='token', sid=sid, lang=lang, view=view)
        self.web.active_sessions[sid] = time.time() + 600
        self.web.session_checked[sid] = time.time()
        reply = client.get('/p/flow', query_string=args, **self.https)
        self.assertEqual(reply.status_code, 200)
        return reply.get_data(as_text=True)

    def test_order_by_importance(self):
        html = self.page()
        marks = ['class="flow-facts"', 'id="hijack-list"', 'id="transport-set"', 'class="wizmode"', 'id="relay-networks-list"', 'id="smarthost-set"',
                 'id="submitter-list"', 'id="outbound-limits"', 'id="message-size-set"', 'id="recipient-verification-set"',
                 'id="header-privacy-status"', 'id="tls-partner-list"']
        places = [html.index(mark) for mark in marks]
        self.assertEqual(places, sorted(places), 'domains first, held accounts above them, then relay, submitters, limits, the rest folded')
        self.assertNotIn('<h2>Current domains</h2>', html, 'the list is not shown twice')
        self.assertIn('<details class="section"><summary>Header privacy</summary>', html, 'rarely needed: folded')

    def test_domains_grouped_with_count_search_and_fold(self):
        html = self.page()
        self.assertIn('<span class="cnt">31</span>', html)
        self.assertIn('data-filter="#flow-domains"', html)
        self.assertLess(html.index('&rarr; mail.example'), html.index('&rarr; [192.0.2.9]:25'), 'the biggest group first')
        self.assertIn('Show all 30', html, 'beyond 12 folded')
        for domain in DOMAINS:
            self.assertIn(f'data-item="{domain} mail.example"', html)
        self.assertEqual(html.count('action="/run/transport-set" class="fx"'), 31, 'a remove button per domain')
        self.assertIn('<input type="hidden" name="action" value="remove">', html)
        add = html[html.index('id="transport-add"'):]
        add = add[:add.index('</details>')]
        self.assertIn('name="action" value="add"', add)
        self.assertIn('name="domain"', add)
        self.assertIn('name="destination"', add)

    def test_domains_also_in_the_wizard_view(self):
        self.prefs['manual'] = []
        html = self.page()
        self.assertIn('id="wizard"', html)
        self.assertIn('data-item="d00.example mail.example"', html)
        self.assertLess(html.index('id="transport-set"'), html.index('id="wizard"'))
        self.assertNotIn('class="fx"', html, 'the wizard view only lists, the wizard adds')
        self.assertIn('id="hijack-list"', html, 'held accounts are read in the wizard view too')
        self.assertIn(('hijack-list',), self.calls)

    def test_click_on_a_domain_fills_the_form(self):
        html = self.page(domain='d03.example', destination='mail.example')
        add = html[html.index('id="transport-add"'):]
        self.assertTrue(add.startswith('id="transport-add" open'))
        self.assertIn('value="d03.example"', add[:add.index('</details>')])
        self.assertIn('href="/p/flow?domain=d03.example&amp;destination=mail.example#transport-add"', html)

    def test_every_command_and_field_is_still_there(self):
        html = self.page()
        for name, command in self.schema.items():
            # relay-networks-set: efactl only; apply and discard show while changes wait (test_relay_pending), as before.
            if not command['writes'] or name in ('my-settings-set', 'relay-networks-set', 'relay-networks-apply', 'relay-networks-discard'):
                continue
            self.assertIn(f'action="/run/{name}"', html, name)
            forms = re.findall(rf'<form method="post" action="/run/{re.escape(name)}"[^>]*>(.*?)</form>', html, re.S)
            fields = set(re.findall(r'name="([a-z_]+)"', ''.join(forms)))
            for arg in command['args']:
                self.assertIn(arg['name'], fields, f'{name}: {arg["name"]}')

    def test_relay_pending(self):
        self.outputs['relay-networks-list'] = {**self.outputs['relay-networks-list'], 'added': ['198.51.100.0/24'], 'pending': True}
        html = self.page()
        self.assertIn('Added: 198.51.100.0/24', html)
        self.assertIn('action="/run/relay-networks-apply"', html)
        self.assertIn('action="/run/relay-networks-discard"', html)
        self.assertIn('class="fact bad" href="#relay-networks-list"', html)

    def test_current_values(self):
        html = self.page()
        self.assertIn('id="message-size-set-megabytes" name="megabytes" value="42"', html)
        self.assertIn('id="smarthost-set-host" name="host" value="relay.example"', html)
        self.assertIn('id="outbound-limits-set-recipients_hour" name="recipients_hour" value="321"', html)
        self.assertRegex(html, r'id="recipient-verification-set-mode" name="mode" value="on"\s*checked')
        self.assertIn('<b class="mono">relay.example</b>', html)

    def test_held_accounts(self):
        html = self.page()
        top = html[html.index('id="hijack-list"'):html.index('id="transport-set"')]
        self.assertIn('acc@d01.example', top)
        self.assertIn('name="who" value="acc@d01.example"', top)
        self.held = []
        html = self.page()
        self.assertIn('<p class="h flow-line" id="hijack-list">Held accounts: none</p>', html)
        self.assertNotIn('class="card att-card"', html)

    def test_standard_view_and_read_only(self):
        html = self.page(view='standard')
        self.assertNotIn('id="tls-partner-list"', html)
        self.assertIn('expert-note', html)
        self.schema = {name: command for name, command in self.schema.items() if not command['writes'] or name == 'my-settings-set'}
        html = self.page()
        self.assertIn('data-item="d00.example mail.example"', html)
        self.assertNotIn('/run/transport-set', html)
        self.assertNotIn('class="ffold"', html)

    def test_german(self):
        html = self.page(lang='de')
        for text in ('Domains und ihre Mailserver', 'Domain oder Mailserver suchen', 'Angehaltene Konten', 'Domain hinzufügen oder ihren Mailserver ändern',
                     'Immer erlaubt (System):', 'Grenzen ändern'):
            self.assertIn(text, html)
        with open(DE, encoding='utf-8') as f:
            po = f.read()
        self.assertIn('msgid "Saved. The lists below show the new state."\nmsgstr "Gespeichert. Die Listen unten zeigen den neuen Stand."', po)


if __name__ == '__main__':
    unittest.main()
