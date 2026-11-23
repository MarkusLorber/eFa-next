# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The break-glass admin (Hans 2026-11-18): ten one-time codes of 128 bits, only their scrypt hashes kept (0600, written whole,
under /var/lib: not in backups, exports or the cluster snapshot), each used once; SSH with a code from the admin networks
only, nothing global changed; the PAM guard leaves every other user's stack as it was; sudo with a fresh code; the codes
never in a log or the audit; every try raises the alarm; super admins only, with the password and 2FA again."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'next', 'usr', 'lib', 'eFa', 'python'))
import efa_breakglass as bg  # noqa: E402
from test_threat import load_efactl  # noqa: E402


class Codes(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder, True)

    def test_codes_are_long_and_single_use(self):
        codes, state = bg.issue({}, 'efa-bg-abcd1234', now=100)
        self.assertEqual(len(codes), 10)
        self.assertEqual(len(set(codes)), 10)
        self.assertTrue(all(len(bg.normal(code)) == 26 for code in codes), '128 bits in base32')
        bg.write_state(state, self.folder)
        text = open(bg.state_file(self.folder)).read()
        for code in codes:
            self.assertNotIn(bg.normal(code), text, 'only hashes are kept')
        self.assertTrue(bg.use_code(codes[3].lower(), self.folder, now=200), 'case and dashes do not matter')
        self.assertFalse(bg.use_code(codes[3], self.folder), 'never twice')
        self.assertFalse(bg.use_code('AAAA-BBBB', self.folder))
        self.assertFalse(bg.use_code('', self.folder))
        state = bg.read_state(self.folder)
        self.assertEqual((len(state['codes']), state['last_use']), (9, 200))
        self.assertEqual(os.stat(bg.state_file(self.folder)).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.folder).st_mode & 0o777, 0o700)
        self.assertEqual(sorted(os.listdir(self.folder)), ['state.json', 'state.lock'], 'written whole: no temp file left')

    def test_new_codes_end_the_old_ones(self):
        old, state = bg.issue({}, 'efa-bg-abcd1234')
        bg.write_state(state, self.folder)
        new, state = bg.issue(bg.read_state(self.folder), 'efa-bg-abcd1234')
        bg.write_state(state, self.folder)
        self.assertFalse(any(bg.use_code(code, self.folder) for code in old))
        self.assertTrue(bg.use_code(new[0], self.folder))

    def test_two_at_once_cannot_both_use_a_code(self):
        codes, state = bg.issue({}, 'efa-bg-abcd1234')
        bg.write_state(state, self.folder)
        results = []
        threads = [threading.Thread(target=lambda: results.append(bg.use_code(codes[0], self.folder))) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(results.count(True), 1)


class Files(unittest.TestCase):
    def test_sshd_only_this_user_and_only_from_admin_networks(self):
        text = bg.sshd_text('efa-bg-abcd1234', ['192.0.2.0/24', '2001:db8::/48'])
        self.assertIn('Match User efa-bg-abcd1234 Address 192.0.2.0/24,2001:db8::/48\n    AuthenticationMethods keyboard-interactive', text)
        self.assertIn('Match User efa-bg-abcd1234\n    AuthenticationMethods publickey\n    PubkeyAuthentication yes\n    AuthorizedKeysFile none', text)
        self.assertTrue(text.rstrip().endswith('Match all'))
        outside = [line for line in text.split('\n') if line and not line.startswith(('    ', '#', 'Match'))]
        self.assertEqual(outside, [], 'nothing global')
        self.assertNotIn('Address', bg.sshd_text('efa-bg-abcd1234', []), 'no admin networks: no SSH for it at all')
        with self.assertRaises(ValueError):
            bg.sshd_text('root', ['192.0.2.0/24'])

    def test_pam_guard_leaves_other_users_alone(self):
        sshd = '#%PAM-1.0\nauth       substack     password-auth\nauth       include      postlogin\naccount    include      password-auth\n'
        guarded = bg.with_guard(sshd, 'efa-bg-abcd1234')
        lines = [line for line in guarded.split('\n') if line.startswith('auth')]
        jump = int(re.search(r'success=(\d+)', lines[0]).group(1))
        self.assertIn('pam_succeed_if.so quiet user != efa-bg-abcd1234', lines[0])
        self.assertEqual(lines[1 + jump:], ['auth       substack     password-auth', 'auth       include      postlogin'],
                         'every other user jumps exactly over the lines of the break-glass user to the stack of before')
        own = lines[1:1 + jump]
        self.assertTrue(all('pam_faillock' in line or 'pam_exec' in line for line in own), own)
        self.assertIn('success=done', own[-1], 'a right code ends the auth part for this user')
        self.assertIn('[default=die]', own[2], 'a wrong one ends it too, failed')
        self.assertEqual(bg.without_guard(guarded), sshd, 'removed without a trace')
        self.assertEqual(bg.with_guard(guarded, 'efa-bg-abcd1234'), guarded, 'once only')
        self.assertEqual(len(bg.guard_lines('efa-bg-abcd1234')), bg.GUARD_LEN)
        self.assertNotIn('substack', '\n'.join(bg.guard_lines('efa-bg-abcd1234')), 'a substack cannot jump')

    def test_code_check_and_counters(self):
        ssh, tty = '\n'.join(bg.guard_lines('efa-bg-abcd1234')), '\n'.join(bg.guard_lines('efa-bg-abcd1234', tty=True))
        self.assertIn('pam_exec.so quiet expose_authtok /usr/libexec/eFa/breakglass-code', ssh, 'the code on stdin, no log=')
        self.assertNotIn('log=', ssh)
        self.assertIn('deny=5 unlock_time=900 fail_interval=900', ssh)
        self.assertNotIn('faillock-efa-bg-tty', ssh)
        self.assertIn('dir=/var/run/faillock-efa-bg-tty', tty, 'the console has a counter of its own')

    def test_sudo_needs_a_code(self):
        text = bg.sudoers_text('efa-bg-abcd1234')
        self.assertIn('efa-bg-abcd1234 ALL=(ALL) ALL', text)
        self.assertIn('timestamp_timeout=0', text)
        self.assertNotIn('NOPASSWD', text)

    def test_admin_networks(self):
        self.assertTrue(bg.in_networks('192.0.2.7', ['192.0.2.0/24']))
        self.assertTrue(bg.in_networks('[2001:db8::5]', ['2001:db8::/48']))
        self.assertFalse(bg.in_networks('198.51.100.1', ['192.0.2.0/24']))
        self.assertFalse(bg.in_networks('tty1', ['192.0.2.0/24']))
        self.assertFalse(bg.in_networks('192.0.2.7', []))


class Commands(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def test_not_replicated_and_not_in_backups(self):
        self.assertIn('breakglass-issue', self.efactl.CLUSTER_LOCAL)
        self.assertIn('breakglass-alarm', self.efactl.CLUSTER_LOCAL)
        self.assertTrue(bg.STATE_DIR.startswith('/var/lib/'), 'not /etc: no backup, export or snapshot carries it')
        for path in self.efactl.BACKUP_PATHS:
            self.assertFalse(bg.STATE_DIR.startswith(path), path)
        self.assertNotIn('breakglass', ' '.join(self.efactl.SNAP_TABLES))

    def test_gates(self):
        editor = {'username': 'a', 'role': 'custom', 'grants': {'settings.edit'}}
        for name in ('breakglass-issue', 'breakglass-remove', 'breakglass-status', 'breakglass-alarm'):
            self.assertIn(name, self.efactl.SUPER_COMMANDS)
            self.assertFalse(self.efactl.command_allowed(editor, name, True), name)
        with mock.patch.dict(os.environ, {'SUDO_USER': 'efa-web'}):
            with self.assertRaises(self.efactl.EfaError):
                self.efactl.breakglass_alarm(types.SimpleNamespace(event='login-ok', source='x', service='sshd'))

    def test_issue_gives_the_pdf_and_keeps_no_code(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder, True)
        audited = []
        with mock.patch.object(bg, 'STATE_DIR', folder), mock.patch.object(self.efactl, '_breakglass_install', lambda user: None), \
                mock.patch.object(self.efactl, '_breakglass_sshd', lambda state: (bg.write_state({**state, 'networks': []}, folder), {**state, 'networks': []})[1]), \
                mock.patch.object(self.efactl, '_audit', audited.append), mock.patch.object(bg, 'read_state', lambda folder_=None: _read(folder)):
            answer = self.efactl.breakglass_issue(types.SimpleNamespace(confirm='yes'))
        import base64
        pdf = base64.b64decode(answer['pdf'])
        self.assertTrue(pdf.startswith(b'%PDF'))
        self.assertTrue(re.fullmatch(r'efa-bg-[a-z0-9]{8}', answer['user']))
        self.assertNotIn('codes', answer, 'the codes only inside the PDF')
        self.assertTrue(audited and 'PDF' in audited[0] and not re.search(r'[A-Z2-7]{4}-[A-Z2-7]{4}', audited[0]), 'the audit without a code')
        with mock.patch.object(self.efactl, '_confirm', side_effect=self.efactl.EfaError('Type yes')):
            with self.assertRaises(self.efactl.EfaError):
                self.efactl.breakglass_issue(types.SimpleNamespace(confirm=''))

    def test_web_gates(self):
        from test_bec_page import load_web
        web = load_web()
        for name in ('breakglass-issue', 'breakglass-remove'):
            self.assertIn(name, web.REAUTH_COMMANDS)
        self.assertIn('breakglass-alarm', web.NOT_CALLABLE)
        self.assertIn('breakglass-issue', web.PDF_COMMANDS)
        source = open(web.__file__, encoding='utf-8').read()
        self.assertIn("'Cache-Control': 'no-store'", source)


class Part2(unittest.TestCase):
    """The web login with a code (no TOTP for this user only), its alarm and lock, the banner, the self check, the notice,
    and what a package update may do to the files (found and put back, a second run changes nothing)."""

    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.codes, state = bg.issue({}, 'efa-bg-abcd1234')
        bg.write_state({**state, 'networks': ['192.0.2.0/24']}, self.folder)
        self.raised = []
        lib = types.SimpleNamespace(**{name: getattr(bg, name) for name in dir(bg) if not name.startswith('__')})
        lib.STATE_DIR = self.folder
        lib.read_state = lambda folder=None: bg.read_state(self.folder)
        lib.write_state = lambda state, folder=None: bg.write_state(state, self.folder)
        lib.use_code = lambda code, folder=None, now=None: bg.use_code(code, self.folder, now)
        for patch in (mock.patch.object(self.efactl, '_breakglass', lambda: lib),
                      mock.patch.object(self.efactl, '_breakglass_raise', lambda event, source, service: self.raised.append(event))):
            patch.start()
            self.addCleanup(patch.stop)

    def login(self, code, user='efa-bg-abcd1234', source='192.0.2.9'):
        with mock.patch.object(self.efactl, '_secrets', lambda count, prompt: [code]):
            return self.efactl.breakglass_login(types.SimpleNamespace(user=user, source=source))

    def test_only_from_the_admin_networks_and_nothing_counted_from_outside(self):
        for _ in range(8):
            with self.assertRaises(self.efactl.EfaError):
                self.login(self.codes[0], source='198.51.100.7')
        state = bg.read_state(self.folder)
        self.assertEqual(state.get('web_failures', []), [], 'outsiders cannot lock the account')
        self.assertEqual(len(state['codes']), 10, 'no code used from outside')
        self.assertEqual(self.raised, ['refused-network'], 'one alarm per source in 10 minutes')
        self.assertEqual(state['refused_count'], 8, 'but every try counted')
        with self.assertRaises(self.efactl.EfaError):
            self.login(self.codes[0], source='203.0.113.5')
        self.assertEqual(self.raised, ['refused-network', 'refused-network'], 'another source: its own alarm')
        self.assertTrue(self.login(self.codes[0])['ok'], 'from the admin network the code still works')

    def test_no_admin_networks_web_login_off(self):
        bg.write_state({**bg.read_state(self.folder), 'networks': []}, self.folder)
        with self.assertRaises(self.efactl.EfaError):
            self.login(self.codes[0])
        with mock.patch.object(self.efactl, 'breakglass_problems', lambda: []):
            status = self.efactl.breakglass_status(None)
        self.assertIn('off', status['web'])
        self.assertIn('console', status['web'], 'the console stays the way in')

    def test_cluster_needs_its_break_glass_admin_first(self):
        bg.write_state({}, self.folder)
        with self.assertRaises(self.efactl.EfaError) as caught:
            self.efactl.cluster_init(types.SimpleNamespace(name='node-b', mode='ha', confirm='yes'))
        self.assertIn('break-glass admin', str(caught.exception))
        with self.assertRaises(self.efactl.EfaError) as caught:
            self.efactl.cluster_activate(types.SimpleNamespace(confirm='yes', understood='yes'))
        self.assertIn('break-glass admin', str(caught.exception))

    def test_join_keeps_the_break_glass_admin(self):
        with mock.patch.object(self.efactl, 'cluster_local_accounts', lambda: []):
            preview = self.efactl.join_preview_of({'files': [], 'unchanged_files': 0, 'postconf': [], 'units': {}, 'tables': []}, 'node-b',
                                                  postconf_now={}, active=lambda unit: False)
        self.assertEqual(preview['breakglass_kept'], 'efa-bg-abcd1234')

    def test_web_login_with_a_code_once(self):
        answer = self.login(self.codes[0])
        self.assertEqual((answer['ok'], answer['codes_left']), (True, 9))
        with self.assertRaises(self.efactl.EfaError):
            self.login(self.codes[0])
        self.assertEqual(self.raised, ['web-ok', 'web-failed'], 'an alarm for every try, right or wrong')
        with self.assertRaises(self.efactl.EfaError):
            self.login(self.codes[1], user='efa-bg-zzzz9999')

    def test_web_lock_after_wrong_codes(self):
        for _ in range(self.efactl.BREAKGLASS_WEB_TRIES):
            with self.assertRaises(self.efactl.EfaError):
                self.login('AAAA-BBBB-CCCC')
        with self.assertRaises(self.efactl.EfaError):
            self.login(self.codes[2])
        self.assertEqual(self.raised[-1], 'locked-out', 'locked: even a right code waits, and the lock raises its own alarm')
        self.assertEqual(len(bg.read_state(self.folder)['codes']), 10, 'the code was not used up by a locked try')

    def test_files_found_changed_and_put_back(self):
        sshd = '#%PAM-1.0\nauth       substack     password-auth\naccount    include      password-auth\n'
        files = {f'/etc/pam.d/{service}': bg.with_guard(sshd, 'efa-bg-abcd1234', tty) for service, tty in self.efactl.BREAKGLASS_PAM.items()}
        files[bg.SSHD_FILE] = bg.sshd_text('efa-bg-abcd1234', ['192.0.2.0/24'])
        files[bg.SUDOERS] = bg.sudoers_text('efa-bg-abcd1234')
        files['/etc/pam.d/system-auth'] = 'auth required pam_unix.so\n'
        with mock.patch.object(self.efactl, '_read_text', lambda path: files.get(path)), mock.patch.object(os.path, 'exists', lambda path: False):
            self.assertEqual(self.efactl.breakglass_problems(), [])
            files['/etc/pam.d/sudo'] = sshd  # a package update wrote it anew
            files['/etc/pam.d/sshd'] = files['/etc/pam.d/sshd'].replace('[success=4 ', '[success=3 ')  # the jump no longer fits
            files['/etc/pam.d/password-auth'] = bg.GUARD_MARK + '\n'
            problems = self.efactl.breakglass_problems()
        self.assertEqual(len([p for p in problems if '/etc/pam.d/sudo:' in p]), 1)
        self.assertEqual(len([p for p in problems if '/etc/pam.d/sshd:' in p]), 1, 'a jump that does not fit the lines')
        self.assertTrue(any('authselect' in p for p in problems))
        healed = bg.with_guard(sshd, 'efa-bg-abcd1234')
        self.assertEqual(bg.with_guard(healed, 'efa-bg-abcd1234'), healed, 'putting back twice: byte for byte the same')

    def test_rpmnew_is_reported(self):
        sshd = '#%PAM-1.0\nauth       substack     password-auth\n'
        files = {f'/etc/pam.d/{service}': bg.with_guard(sshd, 'efa-bg-abcd1234', tty) for service, tty in self.efactl.BREAKGLASS_PAM.items()}
        files[bg.SSHD_FILE], files[bg.SUDOERS] = bg.sshd_text('efa-bg-abcd1234', ['192.0.2.0/24']), bg.sudoers_text('efa-bg-abcd1234')
        with mock.patch.object(self.efactl, '_read_text', lambda path: files.get(path)), \
                mock.patch.object(os.path, 'exists', lambda path: path == '/etc/pam.d/sshd.rpmnew'):
            self.assertEqual([p for p in self.efactl.breakglass_problems() if '.rpmnew' in p], [
                '/etc/pam.d/sshd.rpmnew: a package brought a new version; merge it, then efactl breakglass-heal'])
        self.assertIn('/etc/pam.d', self.efactl.OS_CHECK_DIRS)

    def test_self_check_names_the_exception(self):
        with mock.patch.object(self.efactl, 'breakglass_problems', lambda: []), mock.patch.object(self.efactl, '_breakglass_networks', lambda: []):
            status = self.efactl.security_status(None)
        self.assertIn('break-glass admin efa-bg-abcd1234: one-time codes (10 left, last use never)', status['exceptions'][0])
        self.assertIn('faillock 5 tries / 15 min', status['exceptions'][0])

    def test_web_login_and_banner(self):
        from test_bec_page import SCHEMA, load_web
        web = load_web()
        calls = []

        def fake(*args, secrets_in=None, who=None):
            calls.append((args, secrets_in))
            if args[0] == 'breakglass-login':
                return (True, {'ok': True, 'user': 'efa-bg-abcd1234', 'codes_left': 9}) if secrets_in == ['GOOD'] else (False, {'error': 'Wrong'})
            if args[0] == 'schema':
                return True, dict(SCHEMA)
            if args[0] == 'session-check':
                return True, {'active': True}
            return True, {}
        web.efactl = fake
        web.efactl_read = fake
        https = {'base_url': 'https://localhost'}
        client = web.app.test_client()
        client.get('/login', **https)
        with client.session_transaction(**https) as sess:
            sess['csrf'] = 'token'
        reply = client.post('/login', data={'csrf': 'token', 'username': 'efa-bg-abcd1234', 'password': 'BAD'}, **https)
        self.assertNotEqual(reply.status_code, 302, 'a wrong code: no login')
        reply = client.post('/login', data={'csrf': 'token', 'username': 'efa-bg-abcd1234', 'password': 'GOOD', 'code': '123456'}, **https)
        self.assertEqual(reply.status_code, 302)
        asked = [args for args, secret in calls if args[0] == 'breakglass-login']
        self.assertTrue(asked and all('--user=efa-bg-abcd1234' in args for args in asked))
        self.assertFalse([args for args, _s in calls if args[0] in ('user-verify', 'admin-2fa-verify')], 'no TOTP for this user')
        self.assertFalse(any('GOOD' in ' '.join(args) for args, _s in calls), 'the code never in the command line')
        with client.session_transaction(**https) as sess:
            self.assertEqual((sess.get('breakglass'), sess.get('role')), ('efa-bg-abcd1234', 'super'))
            sid = sess['sid']
        import time as _time
        web.active_sessions[sid] = _time.time() + 600
        web.session_checked[sid] = _time.time()
        page = client.get('/p/sec', **https).get_data(as_text=True)
        self.assertIn('id="breakglass-banner"', page)
        self.assertIn('One-time codes left: 9', page)
        self.assertIn('#breakglass-issue', page, 'the offer of new codes')


class SameAnswer(unittest.TestCase):
    """A wrong break-glass code, a try from outside and an unknown user get the same answer: text, status, and at least the
    same time (the name never leaks)."""

    def test_failed_logins_look_alike(self):
        from test_bec_page import load_web
        import time as clock
        web = load_web()

        def fake(*args, secrets_in=None, who=None):
            if args[0] in ('breakglass-login', 'user-verify'):
                return False, {'error': 'Wrong password or 2FA code.'}
            return True, {}
        web.efactl = fake
        web.efactl_read = fake
        https = {'base_url': 'https://localhost'}
        answers = []
        for name in ('efa-bg-abcd1234', 'anna', 'nobody-here'):
            client = web.app.test_client()
            client.get('/login', **https)
            with client.session_transaction(**https) as sess:
                sess['csrf'] = 'token'
            start = clock.monotonic()
            reply = client.post('/login', data={'csrf': 'token', 'username': name, 'password': 'x'}, **https)
            took = clock.monotonic() - start
            body = reply.get_data(as_text=True)
            answers.append((reply.status_code, re.findall(r'<p class="err"[^>]*>([^<]*)</p>', body)))
            self.assertGreaterEqual(took, web.LOGIN_FAIL_SECONDS * 0.95, name)
        self.assertEqual(len(set(map(str, answers))), 1, answers)


class NodeAlarm(unittest.TestCase):
    def test_master_notes_only_known_events_cleaned(self):
        from test_cluster_rates import load
        etc = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, etc, True)
        service = load('next/usr/local/sbin/efa-cluster.py', 'efa_cluster_service_bg', etc)
        self.assertEqual(service.node_alarm_text('node-a', {'event': 'login-ok', 'source': '192.0.2.9;rm -rf', 'service': 'sshd<b>'}),
                         'node node-a: break-glass admin login-ok (sshdb from 192.0.2.9rm-rf)')
        self.assertIsNone(service.node_alarm_text('node-a', {'event': 'anything'}))
        handler = open(service.__file__, encoding='utf-8').read()
        self.assertIn("problem = take_job(body, 'alarm')", handler, 'a job with id and expiry, no replay')


class ExistingCluster(unittest.TestCase):
    """A cluster of 6.0.0.6.6 (node-a and node-b, live) updated to 6.0.0.6.7 without break-glass admins: nothing stops (sync,
    journal, resync, rollouts, mode); each host shows the red notice with the way to make it; a NEW init or a NEW node (also a
    rejoin, which goes through join and confirmation again) needs it first."""

    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def test_only_init_and_activate_ask_for_it(self):
        source = open(self.efactl.__file__, encoding='utf-8').read()
        callers = [m.group(1) for m in re.finditer(r'\ndef ([a-z_]+)\(', source)]
        using = sorted(name for name in callers if '_breakglass_first()' in source.split(f'\ndef {name}(')[1].split('\ndef ')[0])
        self.assertEqual(using, ['cluster_activate', 'cluster_init'])

    def test_resync_of_a_member_without_break_glass(self):
        fake = types.SimpleNamespace(call=lambda *a, **kw: {'seq': 7, 'files': [], 'postconf': {}, 'services': {}, 'sql': '', 'units': {}},
                                     read_state=lambda etc: {'role': 'client'}, write_state=lambda state, etc: None)
        with mock.patch.object(self.efactl, '_cluster_parts', lambda: (fake, '/b', {'role': 'client', 'master': {'host': 'node-b', 'port': 8460}})), \
                mock.patch.object(self.efactl, 'snapshot_apply', lambda snapshot, files_only=False: {'files': 0}), \
                mock.patch.object(self.efactl, '_breakglass', lambda: types.SimpleNamespace(read_state=lambda: {})):
            self.assertEqual(self.efactl.cluster_resync(None)['journal_from'], 7, 'a member without break-glass admin keeps syncing')

    def test_red_notice_on_a_host_of_a_cluster_without_it(self):
        etc = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, etc, True)
        os.makedirs(etc + '/eFa/cluster')
        open(etc + '/eFa/cluster/cluster.json', 'w').close()
        with mock.patch.object(self.efactl, 'ETC', etc), mock.patch.object(self.efactl, '_breakglass', lambda: types.SimpleNamespace(read_state=lambda: {})), \
                mock.patch.object(self.efactl, '_system_notices_rest', lambda: []), mock.patch.object(self.efactl, 'BREAKGLASS_ALARMS', etc + '/none'):
            notices = self.efactl._system_notices()
        self.assertTrue(any('Break-glass admin missing' in item[0] and item[1:3] == ['sec', 'breakglass-issue'] for item in notices), notices)
        with mock.patch.object(self.efactl, 'ETC', etc), mock.patch.object(self.efactl, '_breakglass', lambda: types.SimpleNamespace(read_state=lambda: {'user': 'efa-bg-abcd1234'})), \
                mock.patch.object(self.efactl, '_system_notices_rest', lambda: []), mock.patch.object(self.efactl, 'BREAKGLASS_ALARMS', etc + '/none'):
            self.assertFalse(any('missing' in item[0] for item in self.efactl._system_notices()))

    def test_master_sees_the_nodes_without_it(self):
        from test_bec_page import SCHEMA, load_web
        import efa_nav
        web = load_web()
        names = {name for section in efa_nav.PAGES['cluster']['sections'] for name in section[1]}
        schema = {name: SCHEMA[name] for name in names if name in SCHEMA}
        status = {'cluster-status': {'role': 'master', 'name': 'node-b', 'breakglass': False,
                                     'nodes': [{'node': 'node-a', 'reachable': True, 'breakglass': False}, {'node': 'node-c', 'reachable': True, 'breakglass': True}]}}

        def fake(*args, secrets_in=None, who=None):
            if args[0] == 'schema':
                return True, schema
            if args[0] == 'session-check':
                return True, {'active': True}
            return True, status.get(args[0], {})
        web.efactl = fake
        web.efactl_read = fake
        https = {'base_url': 'https://localhost'}
        client = web.app.test_client()
        import time as clock
        with client.session_transaction(**https) as sess:
            sess.update(admin=True, csrf='t', sid='eb', lang='en', view='standard')
        web.active_sessions['eb'] = clock.time() + 600
        web.session_checked['eb'] = clock.time()
        html = client.get('/p/cluster', **https).get_data(as_text=True)
        self.assertIn('Break-glass admin missing on this host.', html)
        self.assertIn('<span class="b">node-a</span>', html, 'the node without it, in red; node-c has one')
        self.assertIn('/p/sec?view=expert&amp;next=cluster#breakglass-issue', html)
        # The link list of the page check of the CI (scripts/page_times.py, only on Forgejo): checked where it is.
        tool = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'scripts', 'page_times.py')
        if os.path.exists(tool):
            sys.path.insert(0, os.path.dirname(tool))
            import page_times
            self.assertIn('/p/sec?view=expert&amp;next=cluster#breakglass-issue', page_times.CROSS_PAGE_LINKS)


def _read(folder):
    try:
        with open(os.path.join(folder, 'state.json')) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


if __name__ == '__main__':
    unittest.main()
