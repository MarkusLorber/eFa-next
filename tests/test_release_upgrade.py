# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The release upgrade to EL10: preflight, leapp report (fixture), start confirmation, super admins only, the fixed steps of
efactl release-upgrade, Postfix hash maps and network drivers. leapp itself is never run: its report is a fixture."""

import importlib.machinery
import importlib.util
import json
import os
import re
import sys
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
for name in ('grp', 'pwd', 'fcntl', 'syslog', 'termios', 'resource'):
    sys.modules.setdefault(name, __import__(name) if importlib.util.find_spec(name) else types.ModuleType(name))
for folder in ('next/usr/lib/eFa/python', 'src/eFa/root/usr/lib/eFa/python', 'src/eFa-base/root/usr/lib/eFa/python'):
    if os.path.join(ROOT, folder) not in sys.path:
        sys.path.insert(0, os.path.join(ROOT, folder))
_loader = importlib.machinery.SourceFileLoader('efactl_ru', os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'))
efactl = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_ru', _loader))
_loader.exec_module(efactl)

import efa_release_upgrade as ru  # noqa: E402

V3 = 'processor : 0\nflags : fpu avx avx2 bmi1 bmi2 f16c fma abm movbe xsave\n'
FACTS = {'os_release': 'NAME="AlmaLinux"\nID="almalinux"\nVERSION_ID="9.8"\n', 'efa_version': '6.0.0.6', 'el10_repo': True, 'cpuinfo': V3,
         'free_root': 60 * 1024 ** 3, 'free_boot': 2 * 1024 ** 3, 'pending': [], 'ifcfg': [], 'time_synced': True, 'queue': 15,
         'cluster_role': 'none', 'net_drivers': {'ens33': 'vmxnet3'}, 'postconf_n': 'mynetworks = 127.0.0.0/8\n'}
# The structure of a real leapp-report.json of a preupgrade run (AlmaLinux 9 to 10), shortened, plus one inhibitor.
LEAPP_REPORT = {'leapp_run_id': 'x', 'entries': [
    {'title': 'Leapp detected loaded kernel drivers which are no longer maintained in RHEL 10.', 'severity': 'high',
     'groups': ['kernel', 'drivers'], 'key': 'k1', 'summary': '- e1000'},
    {'title': 'SElinux relabeling will be scheduled', 'severity': 'info', 'groups': ['selinux'], 'key': 'k2'},
    {'title': 'MariaDB (mariadb-server) has been detected on your system', 'severity': 'medium', 'groups': ['services'], 'key': 'k3'},
    {'title': 'Packages not signed by the distribution vendor found on the system', 'severity': 'high', 'groups': ['sanity'],
     'key': 'k4', 'summary': '- eFa-next\n- eFa-next-base\n- rspamd'},
    {'title': 'Missing required answers in the answer file', 'severity': 'high', 'groups': ['inhibitor'], 'key': 'k5',
     'detail': {'remediations': [{'type': 'command', 'context': ['leapp', 'answer']}, {'type': 'hint', 'context': 'answer it'}]}}]}


def parse(words):
    return efactl.build_parser(words).parse_args(words)


class Preflight(unittest.TestCase):
    def test_ready(self):
        self.assertTrue(ru.preflight(FACTS)['ready'])

    def test_each_required_check_blocks(self):
        for key, value in (('os_release', 'VERSION_ID="10.0"\n'), ('efa_version', '6.0.0.5.1'), ('el10_repo', 'HTTP Error 404'),
                           ('cpuinfo', 'flags : fpu sse2\n'), ('free_root', 4 * 1024 ** 3), ('free_boot', 399 * 1024 ** 2),
                           ('pending', [{'package': 'bash'}]), ('pending', 'dnf failed'), ('ifcfg', ['ifcfg-ens33']), ('time_synced', False)):
            found = ru.preflight({**FACTS, key: value})
            self.assertFalse(found['ready'], key)
            self.assertTrue(found['reasons'], key)

    def test_missing_el10_repo_is_the_reason(self):
        found = ru.preflight({**FACTS, 'el10_repo': 'HTTP Error 404: Not Found'})
        self.assertEqual(len(found['reasons']), 1)
        self.assertIn('eFa-next repository for EL10', found['reasons'][0])

    def test_boot_space(self):
        # 555 MB free (as on a real EL9 host) and 576 MB (leapp passed) only warn; leapp's own /boot inhibitor decides.
        for mb in (555, 576):
            found = ru.preflight({**FACTS, 'free_boot': mb * 1024 ** 2})
            self.assertTrue(found['ready'], mb)
            self.assertTrue(any('/boot' in text for text in found['warnings']), mb)
        self.assertFalse(ru.preflight({**FACTS, 'free_boot': 399 * 1024 ** 2})['ready'])
        self.assertFalse([t for t in ru.preflight({**FACTS, 'free_boot': 600 * 1024 ** 2})['warnings'] if '/boot' in t])
        report = {'entries': [{'title': 'Not enough space on /boot', 'groups': ['inhibitor', 'boot'], 'severity': 'high'}]}
        self.assertFalse(ru.leapp_report(report)['ok'])

    def test_dropped_driver_warns(self):
        found = ru.preflight({**FACTS, 'net_drivers': {'enp0s3': 'e1000', 'eth1': 'e1000e'}})
        self.assertTrue(found['ready'])
        self.assertEqual(len(found['warnings']), 1)
        self.assertIn('enp0s3 (e1000)', found['warnings'][0])

    def test_hash_maps_warn_and_switch(self):
        postconf_n = ('alias_maps = hash:/etc/aliases\nalias_database = hash:/etc/aliases\ntransport_maps = hash:/etc/postfix/transport\n'
                      'smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache\n'
                      'smtpd_helo_restrictions = permit_mynetworks, check_helo_access hash:/etc/postfix/helo_access\n'
                      'relay_domains = $mydestination\n')
        found = ru.preflight({**FACTS, 'postconf_n': postconf_n})
        self.assertTrue(found['ready'])
        self.assertTrue(any('Berkeley DB' in text for text in found['warnings']))
        change = ru.lmdb_changes(postconf_n)
        self.assertEqual(change['parameters']['transport_maps'], 'lmdb:/etc/postfix/transport')
        self.assertEqual(change['parameters']['smtp_tls_session_cache_database'], 'lmdb:${data_directory}/smtp_scache')
        self.assertNotIn('relay_domains', change['parameters'])
        self.assertEqual(change['postmap'], ['/etc/postfix/helo_access', '/etc/postfix/transport'])
        self.assertEqual(change['postalias'], ['/etc/aliases'])
        self.assertEqual(ru.bdb_maps('mynetworks = 10.0.0.0/8\nx = cidr:/etc/postfix/a.cidr\n'), {})


class LeappReport(unittest.TestCase):
    def test_fixture(self):
        found = ru.leapp_report(json.loads(json.dumps(LEAPP_REPORT)))
        self.assertEqual([item['key'] for item in found['inhibitors']], ['k5'])
        self.assertEqual([item['key'] for item in found['high_risk']], ['k1', 'k4'])
        self.assertFalse(found['ok'])
        self.assertEqual(found['unknown_inhibitors'][0]['title'], 'Missing required answers in the answer file')

    def test_without_inhibitor(self):
        report = {'entries': [entry for entry in LEAPP_REPORT['entries'] if entry['key'] != 'k5']}
        self.assertTrue(ru.leapp_report(report)['ok'])
        self.assertTrue(ru.leapp_report({})['ok'])

    def test_old_flags_style(self):
        self.assertFalse(ru.leapp_report({'entries': [{'title': 't', 'flags': ['inhibitor']}]})['ok'])


class Confirmation(unittest.TestCase):
    STATE = {'state': 'ready', 'preupgrade': {'ok': True, 'time': 1000.0}}

    def test_start_needs_snapshot_hostname_and_report(self):
        self.assertIsNone(ru.start_problem('yes', ' MX1.Example.ORG ', 'mx1.example.org', self.STATE, 2000))
        self.assertIn('snapshot', ru.start_problem('', 'mx1.example.org', 'mx1.example.org', self.STATE, 2000))
        self.assertIn('host name', ru.start_problem('yes', 'mx2.example.org', 'mx1.example.org', self.STATE, 2000))
        self.assertIn('preupgrade', ru.start_problem('yes', 'mx1.example.org', 'mx1.example.org', {}, 2000))
        self.assertIn('older', ru.start_problem('yes', 'mx1.example.org', 'mx1.example.org', self.STATE, 1000 + 25 * 3600))

    def test_abort_only_before_leapp_upgrade(self):
        self.assertIsNone(ru.abort_problem({'state': 'starting'}))
        for state in ('upgrading', 'rebooting', 'finishing'):
            self.assertTrue(ru.abort_problem({'state': state}))

    def test_web_asks_password_and_2fa(self):
        with open(os.path.join(ROOT, 'next', 'usr', 'local', 'sbin', 'efa-web.py'), encoding='utf-8') as f:
            text = f.read()
        reauth = re.search(r"^REAUTH_COMMANDS = \{(.*?)\}", text, re.M | re.S).group(1)
        self.assertIn("'release-upgrade'", reauth)
        self.assertIn("'release-upgrade'", re.search(r"^DANGER = \{(.*?)\}", text, re.M).group(1))
        # 403, not 404, for logins and tokens without super admin rights.
        self.assertRegex(text, r"if name in SUPER_COMMANDS and name not in commands:\n\s+return jsonify\(error=[^)]*\), 403")


class SuperAdminsOnly(unittest.TestCase):
    def identity(self, role):
        return {'role': role, 'grants': {name: None for name in efactl.PERMISSIONS}}

    def test_only_super(self):
        for name in ('release-upgrade', 'release-upgrade-status'):
            writes = efactl.COMMANDS[name]['writes']
            self.assertTrue(efactl.command_allowed(None, name, writes))
            self.assertTrue(efactl.command_allowed(self.identity('super'), name, writes))
            # Every permission, but not a super admin: still not allowed.
            for role in ('admin', 'user'):
                self.assertFalse(efactl.command_allowed(self.identity(role), name, writes), role)

    def test_schema_hides_it(self):
        efactl.identity_now = self.identity('admin')
        try:
            self.assertNotIn('release-upgrade', efactl.schema(None))
        finally:
            efactl.identity_now = None


class FixedSteps(unittest.TestCase):
    def test_extra_parameters_are_refused(self):
        self.assertEqual(parse(['release-upgrade', '--action=preflight']).action, 'preflight')
        for words in (['release-upgrade', '--action=start', '--extra=x'], ['release-upgrade', '--action=start', '--', 'rm'],
                      ['release-upgrade-status', '--action=start']):
            with self.assertRaises(SystemExit):
                parse(words)

    def test_only_known_steps(self):
        cmd = efactl.COMMANDS['release-upgrade']
        self.assertIsNone(efactl.arg_choice_problem(cmd, parse(['release-upgrade', '--action=abort']), 'release-upgrade'))
        for value in ('upgrade', 'start;reboot', 'leapp upgrade'):
            args = parse(['release-upgrade', f'--action={value}'])
            self.assertTrue(efactl.arg_choice_problem(cmd, args, 'release-upgrade'), value)
        self.assertEqual({item['value'] for item in cmd['args'][0]['choices']}, set(ru.ACTIONS))

    def test_background_parts_not_from_the_web(self):
        self.assertIn('release-upgrade-run', efactl.CLI_ONLY)
        self.assertIn('release-upgrade-finish', efactl.CLI_ONLY)
        self.assertNotIn('release-upgrade-run', efactl.COMMANDS)


OS_RELEASE = {
    'almalinux': 'NAME="AlmaLinux"\nID="almalinux"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.8"\n',
    'rhel': 'NAME="Red Hat Enterprise Linux"\nID="rhel"\nID_LIKE="fedora"\nVERSION_ID="9.6"\n',
    'rocky': 'NAME="Rocky Linux"\nID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.6"\n',
    'centos': 'NAME="CentOS Stream"\nID="centos"\nID_LIKE="rhel fedora"\nVERSION_ID="9"\n',
}


class Distribution(unittest.TestCase):
    """S23: the upgrade never changes the distribution; only AlmaLinux 9 to 10 is open today."""
    def test_almalinux_only(self):
        self.assertTrue(ru.preflight({**FACTS, 'os_release': OS_RELEASE['almalinux']})['ready'])
        for name in ('rhel', 'rocky', 'centos'):
            found = ru.preflight({**FACTS, 'os_release': OS_RELEASE[name], 'rhel_registered': True})
            self.assertFalse(found['ready'], name)
            self.assertTrue(any(reason.startswith('Distribution') for reason in found['reasons']), name)

    def test_rhel_reasons(self):
        self.assertEqual(ru.distribution_problem('rhel', True), 'RHEL 9 → 10: noch nicht getestet')
        saved = ru.RHEL_ENABLED
        ru.RHEL_ENABLED = True
        try:
            self.assertIsNone(ru.distribution_problem('rhel', True))
            self.assertIn('registered', ru.distribution_problem('rhel', False))
            self.assertIn('registered', ru.distribution_problem('rhel', None))
        finally:
            ru.RHEL_ENABLED = saved
        self.assertNotIn('leapp-data-almalinux', ru.upgrade_packages('rhel')[1])
        with self.assertRaises(ValueError):
            ru.upgrade_packages('rocky')

    def test_never_a_change_of_distribution(self):
        before = {'os_id': 'rhel'}
        found = ru.post_checks({'os_release': 'ID="almalinux"\nVERSION_ID="10.1"\n'}, before)
        same = [item for item in found['checks'] if item['name'] == 'Same distribution'][0]
        self.assertFalse(same['ok'])
        self.assertFalse(found['ok'])


class ElevateSignature(unittest.TestCase):
    """S22: the release package of ELevate only with a good signature of the pinned key."""
    def test_refused(self):
        self.assertIsNone(ru.rpm_signature_problem('x.rpm: digests signatures OK\n', 'RSA/SHA256, Key ID 429785e181b961a5'))
        # Changed after signing, unsigned, or signed by another (imported) key: refused.
        self.assertTrue(ru.rpm_signature_problem('x.rpm: DIGESTS SIGNATURES NOT OK\n', 'Key ID 429785e181b961a5'))
        self.assertTrue(ru.rpm_signature_problem('x.rpm: digests OK\n', '(none) (none)'))
        self.assertTrue(ru.rpm_signature_problem('x.rpm: digests signatures OK\n', 'RSA/SHA256, Key ID 21ea45ab2f86d6a1'))

    def test_shipped_key_is_the_pinned_one(self):
        with open(os.path.join(ROOT, 'next', 'usr', 'share', 'eFa', 'keys', 'RPM-GPG-KEY-ELevate')) as f:
            text = f.read()
        self.assertTrue(text.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----'))
        self.assertEqual(ru.ELEVATE_FINGERPRINT, '74E7F249EE698A4DACFB48C8429785E181B961A5')
        self.assertEqual(ru.ELEVATE_KEY, '/usr/share/eFa/keys/RPM-GPG-KEY-ELevate')


class OsCheck(unittest.TestCase):
    """PKG-2/PKG-4: the check after a package update names failed tests, stopped services and .rpmnew files."""
    def test_findings(self):
        self.assertEqual(efactl.os_check_findings({}, [], []), [])
        found = efactl.os_check_findings({'nginx': 'nginx: [emerg] unknown directive "http3"\n'}, ['unbound'], ['/etc/postfix/main.cf.rpmnew'])
        self.assertEqual(len(found), 3)
        self.assertIn('nginx: configuration test failed: nginx: [emerg] unknown directive "http3"', found[0])
        self.assertEqual(found[1], 'unbound is not running')
        self.assertTrue(found[2].startswith('/etc/postfix/main.cf.rpmnew:'))

    def test_watches_all_mail_services(self):
        for name in ('postfix', 'rspamd', 'redis', 'nginx', 'mariadb', 'unbound', 'fail2ban', 'firewalld'):
            self.assertIn(name, efactl.OS_CHECK_SERVICES)
        self.assertIn('os-check-run', efactl.BACKGROUND_JOBS)


class TestRepositoryHook(unittest.TestCase):
    """EFA_EL10_TEST_REPO (a rehearsal before the EL10 repository exists): the test repository, its vendor file without signature check, and a warning."""
    def test_hook(self):
        import importlib
        self.assertEqual(ru.EL10_TEST_REPO, '')
        self.assertIn('gpgcheck=1', ru.vendor_files()['efa-next.repo'])
        marker = types.SimpleNamespace(st_uid=0, st_mode=0o100600)
        # Without the marker file the variable is ignored, and preflight says why.
        with mock.patch.dict(os.environ, {'EFA_EL10_TEST_REPO': 'http://127.0.0.1:8099/el10/'}), \
                mock.patch('os.stat', side_effect=FileNotFoundError('marker')):
            test = importlib.reload(ru)
            try:
                self.assertEqual(test.EL10_TEST_REPO, '')
                self.assertIn('gpgcheck=1', test.vendor_files()['efa-next.repo'])
                self.assertTrue(any('ignored' in text for text in test.preflight(FACTS)['warnings']))
            finally:
                os.environ.pop('EFA_EL10_TEST_REPO', None)
                importlib.reload(ru)
        with mock.patch.dict(os.environ, {'EFA_EL10_TEST_REPO': 'http://127.0.0.1:8099/el10/'}), \
                mock.patch('os.stat', return_value=marker):
            test = importlib.reload(ru)
            try:
                self.assertEqual(test.EL10_PROBE, 'http://127.0.0.1:8099/el10/repodata/repomd.xml')
                repo = test.vendor_files()['efa-next.repo']
                self.assertIn('gpgcheck=0', repo)
                self.assertIn('TEST', repo)
                self.assertTrue(any('TEST: unsigned test builds' in text for text in test.preflight(FACTS)['warnings']))
                self.assertTrue(test.preflight(FACTS)['ready'])
            finally:
                os.environ.pop('EFA_EL10_TEST_REPO', None)
                importlib.reload(ru)
        self.assertEqual(ru.EL10_TEST_REPO, '')

    @unittest.skipUnless(os.name == 'posix', 'efactl-runner needs a Unix host (fork, Unix sockets)')
    def test_web_path_never_passes_it(self):
        """efactl-runner, the way of the web interface to efactl, gives each call a fixed environment: not this variable."""
        loader = importlib.machinery.SourceFileLoader('runner_env', os.path.join(ROOT, 'next', 'usr', 'local', 'sbin', 'efactl-runner.py'))
        runner = importlib.util.module_from_spec(importlib.util.spec_from_loader('runner_env', loader))
        loader.exec_module(runner)
        user = types.SimpleNamespace(pw_uid=990, pw_gid=990)
        with mock.patch.dict(os.environ, {'EFA_EL10_TEST_REPO': 'http://127.0.0.1:8099/el10/'}), \
                mock.patch.object(runner.pwd, 'getpwnam', return_value=user, create=True):
            env = runner.sudo_env('efa-web', ['release-upgrade', '--action=preflight'])
        self.assertNotIn('EFA_EL10_TEST_REPO', env)
        self.assertTrue(all(not key.startswith('EFA_') for key in env))


class VendorFiles(unittest.TestCase):
    def test_efa_next_and_rspamd(self):
        files = ru.vendor_files()
        self.assertEqual(files['efa-next.sigs'].split(), [ru.KEY_ID])
        self.assertEqual(files['rspamd.sigs'].split(), list(ru.RSPAMD_KEY_IDS))
        for name in ('efa-next', 'rspamd'):
            mapping = json.loads(files[f'{name}_map.json'])
            self.assertEqual(mapping['mapping'][0]['target_major_version'], '10')
            self.assertIn('gpgcheck=1', files[f'{name}.repo'])


if __name__ == '__main__':
    unittest.main()
