# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""6.0.0.6.x (Hans): the menu by use, important pages and cards on top, every card once in the admin interface, My account only in
the user menu at the top right, and old links and bookmarks still open the page that has the card now."""
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
import efa_nav  # noqa: E402

EFACTL = os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl')
WEB = os.path.join(ROOT, 'next', 'usr', 'local', 'sbin', 'efa-web.py')
DE = os.path.join(ROOT, 'next', 'usr', 'share', 'eFa', 'locale', 'de.po')
SCHEMA = json.loads(subprocess.run([sys.executable, '-B', EFACTL, 'schema'], capture_output=True, text=True, check=True).stdout)
# The menu of before (6.0.0.6.3): its pages and commands, so nothing gets lost on the way.
BEFORE_SLUGS = {'dash', 'flow', 'held', 'quar', 'queue', 'log', 'privacy', 'spam', 'rbl', 'ipblock', 'senders', 'rules', 'bec', 'dkim', 'dlp', 'bulk',
                'archive', 'pdfmail', 'disclaimer', 'domset', 'tenants', 'account', 'users', 'groups', 'standards', 'sec', 'report', 'export', 'wazuh',
                'dnsshare', 'net', 'bak', 'cluster', 'maint'}


def load_web():
    folder = tempfile.mkdtemp(prefix='efa-menu-test-')
    before = os.environ.get('EFA_ETC')
    os.environ['EFA_ETC'] = folder
    loader = importlib.machinery.SourceFileLoader('efa_web_menu', WEB)
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
    web.app.secret_key = b'menu-test'
    return web


class Menu(unittest.TestCase):
    def test_groups_in_order_of_use(self):
        self.assertEqual([group for group, _pages in efa_nav.NAV],
                         ['Daily', 'Protection', 'Domains & routing', 'Outgoing mail & archive', 'Users & access', 'Security & privacy',
                          'Monitoring & reports', 'System'])
        daily = [page['slug'] for page in dict(efa_nav.NAV)['Daily']]
        self.assertEqual(daily, ['dash', 'log', 'quar', 'held', 'queue'])
        self.assertEqual(dict(efa_nav.NAV)['System'][0]['slug'], 'maint', 'updates first under System')

    def test_every_card_once_for_admins(self):
        seen = [name for _group, pages in efa_nav.ADMIN_NAV for page in pages for name in page['commands']]
        self.assertEqual([name for name in set(seen) if seen.count(name) > 1], [])
        # The portal keeps its own cards on its page.
        self.assertIn('totp-setup', efa_nav.PAGES['held']['commands'])
        self.assertNotIn('totp-setup', efa_nav.ADMIN_PAGES['held']['commands'])
        self.assertIn('uq-list', efa_nav.ADMIN_PAGES['held']['commands'])

    def test_no_command_and_no_note_lost(self):
        commands = {name for _group, pages in efa_nav.NAV for page in pages for name in page['commands']}
        for name in ('blocklist-show', 'wazuh-install', 'dns-share-add', 'firewall-set', 'firewall-probe-set', 'trap-set', 'audit-search',
                     'history-undo', 'privacy-evidence', 'api-status', 'hardening-report', 'tls-port25-set', 'crypto-policy-set', 'session-end'):
            self.assertIn(name, commands)
        notes = {key for _group, pages in efa_nav.NAV for page in pages for key in page.get('notes', {})}
        for key in ('blocklist-set', 'wazuh-config', 'dns-share-add', 'firewall-set', 'firewall-test', 'own-yara-set', 'floor-check', 'pyzor-set'):
            self.assertIn(key, notes)

    def test_old_pages_and_cards_lead_on(self):
        self.assertTrue(BEFORE_SLUGS <= set(efa_nav.PAGES) | set(efa_nav.MOVED))
        self.assertEqual({efa_nav.MOVED[slug] for slug in ('ipblock', 'wazuh', 'dnsshare')}, {'rbl', 'export', 'net'})
        for (_old, card), new in efa_nav.MOVED_CARDS.items():
            self.assertIn(card, efa_nav.PAGES[new]['commands'])
        self.assertEqual(efa_nav.MOVED_CARDS[('sec', 'firewall-set')], 'firewall')
        self.assertEqual(efa_nav.MOVED_CARDS[('spam', 'attachment-set')], 'files')
        self.assertEqual(efa_nav.MOVED_CARDS[('users', 'audit-search')], 'privacy')

    def test_important_cards_first(self):
        self.assertEqual(efa_nav.PAGES['sec']['sections'][0][0], 'State of this server')
        self.assertEqual(efa_nav.PAGES['users']['sections'][0][0], 'Users')
        self.assertEqual(efa_nav.PAGES['net']['sections'][-1][0], 'DNS resolver for other networks')

    def test_tui_reads_the_admin_menu(self):
        with open(os.path.join(ROOT, 'next', 'usr', 'local', 'sbin', 'efa-tui'), encoding='utf-8') as f:
            self.assertIn('from efa_nav import ADMIN_NAV as NAV', f.read())

    def test_german_texts(self):
        with open(DE, encoding='utf-8') as f:
            de = efa_i18n.po_entries(f.read())
        texts = [group for group, _pages in efa_nav.NAV] + [page['title'] for _group, pages in efa_nav.NAV for page in pages]
        texts += [section[0] for _group, pages in efa_nav.NAV for page in pages for section in page['sections'] if section[0]]
        self.assertEqual([text for text in texts if not de.get(text)], [])


class Pages(unittest.TestCase):
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

    def setUp(self):
        self.calls = []
        self.totp = {'account': '@admin', 'active': True, 'recovery_codes_left': 2, 'required_for_my_role': True, 'policy': 'super'}
        sid = self.web.session_sha('menu')[:12]
        self.outputs = {
            'schema': SCHEMA, 'session-check': {'active': True},
            'account-show': {'username': 'admin', 'email': 'admin@example.org', 'email_pending': '', 'name': 'Jane Doe', 'phone': ''},
            'passkey-status': {'rp_id': 'mx.example.org', 'policy': {}, 'my_keys': [], 'my_mode': 'optional'},
            'session-list': {'sessions': [{'id': sid, 'user': 'admin (main)', 'client': '192.0.2.5', 'browser': 'Firefox', 'started': '2026-11-15 10:00',
                                           'last_seen': '2026-11-15 11:00'},
                                          {'id': 'a1b2c3d4e5f6', 'user': 'admin (main)', 'client': '192.0.2.9', 'browser': 'Safari', 'started': '2026-11-14 10:00',
                                           'last_seen': '2026-11-14 11:00'}]}}

        def fake(*args, secrets_in=None, who=None):
            self.calls.append(args)
            if args[0] == 'totp-status':
                return True, self.totp
            return True, self.outputs.get(args[0], {})
        self.web.efactl = fake

    def page(self, slug, lang='en', view='standard'):
        client = self.web.app.test_client()
        with client.session_transaction(**self.https) as sess:
            sess.update(admin=True, csrf='token', sid='menu', lang=lang, view=view)
        self.web.active_sessions['menu'] = time.time() + 600
        self.web.session_checked['menu'] = time.time()
        reply = client.get(f'/p/{slug}', **self.https)
        return client, reply

    def side(self, html):
        return html[html.index('<details class="navmenu"'):html.index('</aside>')]

    def test_my_account_only_at_the_top_right(self):
        _client, reply = self.page('rules')
        html = reply.get_data(as_text=True)
        self.assertNotIn('href="/p/account"', self.side(html))
        self.assertIn('class="account" href="/p/account"', html, 'the user menu has it')
        self.assertIn('href="/p/firewall"', self.side(html))
        self.assertNotIn('href="/p/ipblock"', self.side(html))

    def test_account_overview_groups_and_folds(self):
        _client, reply = self.page('account')
        html = reply.get_data(as_text=True)
        self.assertEqual(reply.status_code, 200)
        self.assertLess(html.index('id="account-overview"'), html.index('<summary>Login &amp; security</summary>'))
        self.assertLess(html.index('<summary>Login &amp; security</summary>'), html.index('<summary>Personal data</summary>'))
        self.assertLess(html.index('<summary>Personal data</summary>'), html.index('<summary>Settings &amp; sessions</summary>'))
        self.assertIn('Jane Doe', html)
        self.assertIn('Few recovery codes left: make new ones.', html)
        # 2FA on: the new app, the confirm and new codes in one fold; switching off folded at the end of the group.
        self.assertIn('<details class="card fold accfold" id="totp-fold">', html)
        self.assertIn('id="totp-disable-fold"', html)
        self.assertEqual(html.count('id="totp-setup"'), 1)
        # Sessions: a button per row, never for this browser; no session id to type.
        self.assertIn('This browser', html)
        self.assertIn('name="session" value="a1b2c3d4e5f6"', html)
        self.assertNotIn('id="session-end"', html)
        self.assertNotIn('More on this page in the expert view', html)

    def test_account_without_2fa_shows_the_setup_open(self):
        self.totp = {**self.totp, 'active': False, 'recovery_codes_left': 0}
        _client, reply = self.page('account')
        html = reply.get_data(as_text=True)
        self.assertIn('Your role needs 2FA: set it up now.', html)
        self.assertIn('<div class="card totpfirst" id="totp-setup">', html)
        first = html[html.index('id="totp-setup"'):html.index('</details>', html.index('id="totp-setup"'))]
        self.assertIn('name="reauth"', first, 'a first setup asks the password once')
        self.assertNotIn('name="reauth_code"', first, 'no 2FA code field while 2FA is off')
        self.assertNotIn('id="totp-fold"', html)
        self.assertNotIn('action="/run/totp-disable"', html, 'nothing to switch off')
        self.assertIn('>Show the QR code</button>', html)
        self.assertEqual(html.count('id="totp-confirm"'), 1, 'the first code only once, folded in the setup card')

    def test_end_session_sends_its_id(self):
        client, _reply = self.page('account')
        client.post('/run/session-end', data={'csrf': 'token', 'session': 'a1b2c3d4e5f6'}, **self.https)
        self.assertIn(('session-end', '--session=a1b2c3d4e5f6'), [call[:2] for call in self.calls])

    def test_old_addresses(self):
        client, _reply = self.page('rules')
        for old, new in (('ipblock', 'rbl'), ('wazuh', 'export'), ('dnsshare', 'net'), ('fwtest', 'firewall'), ('virus', 'files')):
            reply = client.get(f'/p/{old}', **self.https)
            self.assertEqual((reply.status_code, reply.headers['Location']), (301, f'/p/{new}'))
        html = client.get('/p/sec', **self.https).get_data(as_text=True)
        self.assertIn('/p/firewall#firewall-set', html, 'a bookmark of a moved card goes on (copy.js)')

    def test_notice_of_a_moved_card_links_its_page(self):
        self.assertEqual(self.web.card_page('sec', 'firewall-show'), 'firewall')
        self.assertEqual(self.web.card_page('spam', 'lookalike-status'), 'files')
        self.assertEqual(self.web.card_page('sec', 'floor-status'), 'sec')

    def test_german_and_accessible(self):
        for slug in ('account', 'files', 'rbl', 'firewall', 'privacy'):
            _client, reply = self.page(slug, lang='de', view='expert')
            html = reply.get_data(as_text=True)
            self.assertEqual(reply.status_code, 200, slug)
        # The new parts of My account (overview, folds, sessions). The radio pills of the generic forms (here: the language of
        # My settings) are known to this checker from before, they are not part of this change.
        _client, reply = self.page('account', lang='de', view='expert')
        self.assertEqual([item for item in efa_a11y.page_problems(reply.get_data(as_text=True)) if item != 'field without a label: language'], [])
        self.assertIn('Täglich', html)
        self.assertIn('Sicherheit &amp; Datenschutz', html)
        _client, reply = self.page('account', lang='de')
        html = reply.get_data(as_text=True)
        for text in ('Anmeldung &amp; Sicherheit', 'Persönliche Daten', 'Einstellungen &amp; Sitzungen', 'Dieser Browser', 'Sitzung beenden'):
            self.assertIn(text, html)
        with open(WEB, encoding='utf-8') as f:
            source = f.read()
        block = source[source.index('{% macro account_overview() %}'):source.index('{% macro bec_view() %}')]
        with open(DE, encoding='utf-8') as f:
            de = efa_i18n.po_entries(f.read())
        self.assertEqual([text for text in re.findall(r"_\('([^']+)'\)", block) if not de.get(text)], [])


if __name__ == '__main__':
    unittest.main()
