# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""N6: taking dangerous mail back out of the mailboxes over IMAP, against a real Dovecot. The test starts its own Dovecot
(foreground, own configuration and folders in a temporary directory, 127.0.0.1 and a free port, TLS only, a master user
'efa-retro' with the separator '*', mailboxes as Maildir), delivers mails over IMAP APPEND, and runs retro-imap-set and
retro-run of efactl as the console gives them. Only the database rows of retro-run (the hashes of the delivered mails and the
mail log) are given by the test, and the certificate of the test server is trusted for this test only.

Without dovecot the test is skipped; the CI (Dovecot is installed for the submitter logins) runs it with
EFA_CI_RETRO_IMAP=yes and then fails when it is missing. The Dovecot of the host is not touched."""

import hashlib
import imaplib
import ipaddress
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_write_commands as writes  # noqa: E402

efactl, EfaError = writes.efactl, writes.EfaError
DOVECOT = shutil.which('dovecot') or ('/usr/sbin/dovecot' if os.path.exists('/usr/sbin/dovecot') else None)
REQUIRED = os.environ.get('EFA_CI_RETRO_IMAP') == 'yes'
MASTER, MASTER_PASSWORD = 'efa-retro', 'master-' + hashlib.sha256(os.urandom(16)).hexdigest()[:16]
USERS = {'anna@own.example': 'pw-anna', 'bert@own.example': 'pw-bert'}
EVIL_LINK = 'https://evil.example/login'
SYSTEM_CONTEXT = ssl.create_default_context  # the trust store of the system, before the test trusts its own certificate

CONFIG = '''base_dir = {tmp}/run
state_dir = {tmp}/state
log_path = {tmp}/dovecot.log
info_log_path = {tmp}/dovecot.log
protocols = imap
listen = 127.0.0.1
ssl = required
ssl_cert = <{tmp}/cert.pem
ssl_key = <{tmp}/key.pem
disable_plaintext_auth = yes
auth_mechanisms = plain login
auth_master_user_separator = *
mail_location = maildir:{tmp}/mail/%u
mail_uid = {uid}
mail_gid = {gid}
first_valid_uid = 1
default_internal_user = {internal}
default_login_user = {login_user}
service imap-login {{
  inet_listener imap {{
    port = 0
  }}
  inet_listener imaps {{
    port = {port}
    ssl = yes
  }}
}}
service anvil {{
  chroot =
}}
service imap-login {{
  chroot =
}}
passdb {{
  driver = passwd-file
  master = yes
  args = scheme=PLAIN {tmp}/master.passwd
}}
passdb {{
  driver = passwd-file
  args = scheme=PLAIN {tmp}/users.passwd
}}
userdb {{
  driver = static
  args = uid={uid} gid={gid} home={tmp}/mail/%u
}}
namespace inbox {{
  inbox = yes
  separator = /
  mailbox Junk {{
    auto = create
    special_use = \\Junk
  }}
}}
'''


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def make_certificate(folder):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    with open(folder + '/cert.pem', 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(folder + '/key.pem', 'wb') as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def mail(message_id, subject, body):
    return (f'From: Mallory <m@far.example>\r\nTo: anna@own.example\r\nSubject: {subject}\r\nMessage-ID: <{message_id}>\r\n'
            f'Date: Thu, 12 Nov 2026 08:00:00 +0000\r\n\r\n{body}\r\n').encode()


def selinux_enforcing():
    return bool(shutil.which('getenforce')) and subprocess.run(['getenforce'], capture_output=True, text=True).stdout.strip() == 'Enforcing'


# Only in the CI step retro-imap (EFA_CI_RETRO_IMAP=yes): a Dovecot of its own in a temporary folder, never in unit-tests.
@unittest.skipUnless(REQUIRED, 'only in the CI step retro-imap (EFA_CI_RETRO_IMAP=yes)')
class RetroImapDovecotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not REQUIRED:
            raise unittest.SkipTest('only in the CI step retro-imap (EFA_CI_RETRO_IMAP=yes)')
        if DOVECOT is None:
            raise AssertionError('EFA_CI_RETRO_IMAP=yes but dovecot is missing')
        cls.tmp = tempfile.mkdtemp(prefix='efa-retro-imap-')
        os.chmod(cls.tmp, 0o755)
        for folder in ('run', 'state', 'mail'):
            os.makedirs(f'{cls.tmp}/{folder}')
        make_certificate(cls.tmp)
        with open(cls.tmp + '/users.passwd', 'w') as f:
            f.write(''.join(f'{user}:{password}\n' for user, password in USERS.items()))
        with open(cls.tmp + '/master.passwd', 'w') as f:
            f.write(f'{MASTER}:{MASTER_PASSWORD}\n')
        cls.port = free_port()
        internal = 'dovecot' if _user_exists('dovecot') else 'nobody'
        login_user = 'dovenull' if _user_exists('dovenull') else internal
        # Dovecot never gives mail to uid 0: the mailboxes belong to its own internal user.
        import pwd
        owner = pwd.getpwnam(internal)
        os.chown(cls.tmp + '/mail', owner.pw_uid, owner.pw_gid)
        with open(cls.tmp + '/dovecot.conf', 'w') as f:
            f.write(CONFIG.format(tmp=cls.tmp, port=cls.port, uid=owner.pw_uid, gid=owner.pw_gid, internal=internal, login_user=login_user))
        for name in ('users.passwd', 'master.passwd', 'key.pem'):
            os.chmod(f'{cls.tmp}/{name}', 0o644)
        command = [DOVECOT, '-F', '-c', cls.tmp + '/dovecot.conf']
        # SELinux enforcing: started as itself, Dovecot moves into dovecot_t, which may not read its config in /tmp (tmp_t).
        # runcon starts it unconfined instead: unconfined_service_t under system_r (the CI unit runs in initrc_t, which may not
        # write tmp_t either), the own type of a login shell (unconfined_t) otherwise. The policy of the host stays as it is.
        if selinux_enforcing():
            with open('/proc/self/attr/current') as f:
                own = f.read().strip('\x00\n ').split(':')
            kind = 'unconfined_service_t' if len(own) < 3 or own[1] == 'system_r' else own[2]
            command = ['runcon', '-t', kind] + command
        cls.server = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        cls.trusted = ssl.create_default_context(cafile=cls.tmp + '/cert.pem')
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1', cls.port), timeout=1):
                    break
            except OSError:
                if cls.server.poll() is not None:
                    raise AssertionError('dovecot did not start: ' + cls.server.stdout.read().decode() + _read(cls.tmp + '/dovecot.log'))
                time.sleep(0.1)
        else:
            raise AssertionError('dovecot does not listen: ' + _read(cls.tmp + '/dovecot.log'))

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        try:
            cls.server.wait(10)
        except subprocess.TimeoutExpired:
            cls.server.kill()
        cls.server.stdout.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.harness = writes.WriteCommandTests('test_every_listed_command_is_covered')
        self.harness.setUp()
        self.notified, self.events = [], []
        self.feed = self.harness.tmp + '/efa-feed-url.map'
        self.rows = {'delivered_iocs': [], 'maillog': {}}
        self.patches = [
            mock.patch.object(efactl, '_admin_query', self.query),
            mock.patch.object(efactl, '_admins_notify', lambda subject, text: self.notified.append(text)),
            mock.patch.object(efactl, '_event', lambda *a, **k: self.events.append(a)),
            mock.patch.object(efactl, '_audit', lambda text: None),
            mock.patch.object(efactl, '_reload_rspamd', lambda: None),
            mock.patch.object(efactl, 'FEED_MAPS', {'url': self.feed}),
            # Only the certificate of the test server is trusted, and only here; retro_pull checks name and chain as always.
            mock.patch.object(efactl.ssl, 'create_default_context', lambda *a, **k: self.trusted),
        ]
        for patch in self.patches:
            patch.start()
        for user in USERS:
            with self.connect(user, USERS[user]) as conn:
                conn.select('INBOX')
                conn.store('1:*', '+FLAGS', '\\Deleted') if conn.search(None, 'ALL')[1][0] else None
                conn.expunge()
                conn.select('Junk')
                conn.store('1:*', '+FLAGS', '\\Deleted') if conn.search(None, 'ALL')[1][0] else None
                conn.expunge()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.harness.tearDown()

    def query(self, sql, params=(), *args, **kwargs):
        sql = ' '.join(sql.split())
        if sql.startswith('DELETE FROM delivered_iocs'):
            return []
        if sql.startswith('SELECT maillog_id, kind, h FROM delivered_iocs'):
            return list(self.rows['delivered_iocs'])
        if sql.startswith('SELECT CAST(ts AS CHAR) AS ts, message_id, sender, rcpt, subject FROM maillog'):
            found = self.rows['maillog'].get(params[0])
            return [found] if found else []
        raise AssertionError('unexpected statement: ' + sql)

    def connect(self, login, password):
        conn = imaplib.IMAP4_SSL('127.0.0.1', self.port, ssl_context=self.trusted, timeout=10)
        try:
            conn.login(login, password)
        except imaplib.IMAP4.error:
            conn.shutdown()
            raise
        return conn

    def deliver(self, user, message):
        with self.connect(user, USERS[user]) as conn:
            self.assertEqual(conn.append('INBOX', None, None, message)[0], 'OK')

    def folder(self, user, name):
        """The Message-IDs in a folder of a mailbox."""
        with self.connect(user, USERS[user]) as conn:
            conn.select(name, readonly=True)
            numbers = conn.search(None, 'ALL')[1][0].split()
            found = []
            for number in numbers:
                header = conn.fetch(number, '(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])')[1][0][1].decode()
                found.append(header.split('<', 1)[1].split('>', 1)[0])
            return sorted(found)

    def switch_on(self, *extra):
        with mock.patch.object(efactl, '_secrets', lambda count, prompt: [MASTER_PASSWORD]):
            self.harness.run_cmd('retro-set', '--mode', 'on')
            self.harness.run_cmd('retro-imap-set', '--mode', 'on', '--host', '127.0.0.1', '--port', str(self.port),
                                 '--login', '{user}*{master}', '--master', MASTER, *extra)

    def dangerous_mail_delivered(self, rcpt='anna@own.example'):
        for user in USERS:
            self.deliver(user, mail('evil-1@far.example', 'Konto gesperrt', f'Bitte hier: {EVIL_LINK}'))
            self.deliver(user, mail('fine-1@far.example', 'Hallo', 'nichts Böses'.encode('ascii', 'replace').decode()))
        self.rows['maillog'][41] = {'ts': '2026-11-12 08:00:01', 'message_id': 'evil-1@far.example', 'sender': 'm@far.example',
                                    'rcpt': rcpt, 'subject': 'Konto gesperrt'}
        self.rows['delivered_iocs'] = [{'maillog_id': 41, 'kind': 'url', 'h': hashlib.sha256(EVIL_LINK.encode()).hexdigest()}]

    def feed_names(self, entry):
        with open(self.feed, 'w') as f:
            f.write(entry + '\n')

    def test_the_master_login_works_at_all(self):
        with self.connect(f'anna@own.example*{MASTER}', MASTER_PASSWORD) as conn:
            self.assertEqual(conn.select('INBOX')[0], 'OK')
        with self.assertRaises(imaplib.IMAP4.error):
            with self.connect(f'anna@own.example*{MASTER}', 'wrong'):
                pass

    def test_moved_to_junk_after_the_feed_names_the_link(self):
        self.switch_on('--action', 'move', '--folder', 'Junk')
        self.dangerous_mail_delivered('anna@own.example, bert@own.example')
        self.feed_names('https://other.example/')
        self.assertEqual(efactl.retro_run(None)['hits'], 0)
        self.assertEqual(self.folder('anna@own.example', 'INBOX'), ['evil-1@far.example', 'fine-1@far.example'])
        self.feed_names(EVIL_LINK)
        self.assertEqual(efactl.retro_run(None), {'checked': 1, 'hits': 1, 'new': 1})
        for user in USERS:
            with self.subTest(user=user):
                self.assertEqual(self.folder(user, 'INBOX'), ['fine-1@far.example'])
                self.assertEqual(self.folder(user, 'Junk'), ['evil-1@far.example'])
        self.assertIn('taken back: anna@own.example: 1 moved to Junk; bert@own.example: 1 moved to Junk', self.notified[0])
        # Each mail is handled once: a second run takes nothing more and tells nobody again.
        self.assertEqual(efactl.retro_run(None)['new'], 0)
        self.assertEqual(len(self.notified), 1)

    def test_delete(self):
        self.switch_on('--action', 'delete')
        self.dangerous_mail_delivered('bert@own.example')
        self.feed_names(EVIL_LINK)
        efactl.retro_run(None)
        self.assertEqual(self.folder('bert@own.example', 'INBOX'), ['fine-1@far.example'])
        self.assertEqual(self.folder('bert@own.example', 'Junk'), [])
        # Only the recipients of the log entry: anna's copy stays.
        self.assertEqual(self.folder('anna@own.example', 'INBOX'), ['evil-1@far.example', 'fine-1@far.example'])

    def test_wrong_master_password_leaves_the_mail_and_says_so(self):
        self.switch_on()
        efactl._json_write(efactl.RETRO_IMAP_SECRET, {'password': 'wrong'})
        self.dangerous_mail_delivered()
        self.feed_names(EVIL_LINK)
        efactl.retro_run(None)
        self.assertIn('not taken back: error', self.notified[0])
        self.assertEqual(self.folder('anna@own.example', 'INBOX'), ['evil-1@far.example', 'fine-1@far.example'])

    def test_an_untrusted_certificate_is_refused(self):
        self.switch_on()
        self.dangerous_mail_delivered()
        self.feed_names(EVIL_LINK)
        with mock.patch.object(efactl.ssl, 'create_default_context', SYSTEM_CONTEXT):
            efactl.retro_run(None)
        self.assertIn('not taken back: error', self.notified[0])
        self.assertEqual(self.folder('anna@own.example', 'INBOX'), ['evil-1@far.example', 'fine-1@far.example'])

    def test_a_message_id_with_quotes_finds_nothing_else(self):
        self.switch_on()
        self.dangerous_mail_delivered()
        self.rows['maillog'][41]['message_id'] = 'evil-1@far.example" OR ALL "'
        self.feed_names(EVIL_LINK)
        efactl.retro_run(None)
        self.assertEqual(self.folder('anna@own.example', 'INBOX'), ['evil-1@far.example', 'fine-1@far.example'])

    def test_settings_are_checked(self):
        with mock.patch.object(efactl, '_secrets', lambda count, prompt: ['']):
            self.harness.refused('retro-imap-set', '--mode', 'on', '--host', '127.0.0.1', '--login', '{user}*{master}')
        with mock.patch.object(efactl, '_secrets', lambda count, prompt: ['x']):
            for words in (('--host', 'bad host'), ('--port', '99999'), ('--login', 'fixed'), ('--action', 'archive'), ('--folder', '../x;')):
                with self.subTest(words=words):
                    self.harness.refused('retro-imap-set', '--mode', 'on', '--host', '127.0.0.1', *words)
        self.switch_on()
        self.assertEqual(os.stat(efactl.RETRO_IMAP_SECRET).st_mode & 0o777, 0o600)
        self.assertNotIn(MASTER_PASSWORD, efactl._json_read(efactl.RETRO_FILE, {}).__repr__())


def _user_exists(name):
    try:
        import pwd
        pwd.getpwnam(name)
        return True
    except (KeyError, ImportError, AttributeError):
        return False


def _read(path):
    try:
        with open(path) as f:
            return f.read()[-3000:]
    except OSError:
        return ''


if __name__ == '__main__':
    unittest.main()
