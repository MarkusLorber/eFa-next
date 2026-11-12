# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""S28: every step of the release upgrade through the real code of efactl, against a temporary /etc and state folder. Faked
is only the boundary to the system: the programs efactl starts (subprocess), the platform layer (systemd, dnf, leapp, the
facts of the host), the network (the EL10 repository) and the SMTP server. The functions of efactl and efa_release_upgrade
run as they are, so a call that cannot work (a keyword twice, a wrong name) fails here."""

import argparse
import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest

# The real sleep: the tests replace time.sleep of efactl, which is the one of the time module.
REAL_SLEEP = time.sleep
from unittest import mock

sys.dont_write_bytecode = True
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
for name in ('grp', 'pwd', 'syslog', 'termios', 'resource'):
    sys.modules.setdefault(name, __import__(name) if importlib.util.find_spec(name) else types.ModuleType(name))
# Windows (a test run by hand): tarfile asks pwd and grp for the owner names.
for name, call in (('pwd', 'getpwuid'), ('grp', 'getgrgid')):
    if not hasattr(sys.modules[name], call):
        setattr(sys.modules[name], call, lambda uid: ('root',))
if 'fcntl' not in sys.modules:
    try:
        import fcntl  # noqa: F401
    except ImportError:  # Windows: the lock of the step is a no-op here
        sys.modules['fcntl'] = types.SimpleNamespace(flock=lambda *args: None, LOCK_EX=2, LOCK_NB=4)
for folder in ('next/usr/lib/eFa/python', 'src/eFa/root/usr/lib/eFa/python', 'src/eFa-base/root/usr/lib/eFa/python'):
    if os.path.join(ROOT, folder) not in sys.path:
        sys.path.insert(0, os.path.join(ROOT, folder))

import efa_platform_el9  # noqa: E402  (the path above first)


def leapp_log(vendor, sections):
    """A leapp log as leapp 0.24 writes it: the vendors it took and its dnf transaction check."""
    lines = [f'2026-11-10 09:38:11.817 DEBUG    PID: 8261 leapp.workflow.FactsCollection.vendor_repo_signature_scanner: Vendor efa-next '
             + ('found in active list, processing file efa-next.sigs' if vendor else 'not in active list, skipping')]
    for section, names in sections:
        lines.append(f'{section}:')
        lines += [f' {name}   noarch  6.0.0.6-1.el10  efa-next-el10  1 M' for name in names]
    lines += ['', 'Transaction Summary', 'Downloading Packages:', 'Check completed.']
    return ''.join(f'2026-11-10 09:40:42.421 DEBUG    PID: 21243 leapp.workflow.TargetTransactionCheck.dnf_transaction_check: {line}\n'
                   if not line.startswith('2026') else line + '\n' for line in lines)


GOOD_LEAPP = leapp_log(True, [('Installing', ['valkey']), ('Upgrading', ['eFa-next', 'eFa-next-base', 'postfix']), ('Removing', ['redis'])])
# The first rehearsal: the vendor efa-next not taken, eFa-next and what it needs removed.
BAD_LEAPP = leapp_log(False, [('Upgrading', ['postfix']), ('Removing', ['nginx', 'redis']),
                              ('Removing dependent packages', ['certbot', 'eFa-next', 'eFa-next-base', 'python3-pymilter'])])

V3 = 'processor : 0\nflags : fpu avx avx2 bmi1 bmi2 f16c fma abm movbe xsave\n'
UNITS = ['postfix', 'rspamd', 'clamd@scan', 'mariadb', 'redis', 'unbound', 'nginx', 'efa-web', 'efactl-runner', 'efa-maillog',
         'efa-milter-health', 'chronyd', 'firewalld']


def host_facts(major):
    """What the platform layer reports of an AlmaLinux host before (9) and after (10) the upgrade."""
    release = f'el{major}'
    return {'os_release': f'NAME="AlmaLinux"\nID="almalinux"\nVERSION_ID="{major}.1"\n', 'kernel': f'6.12.0-55.{release}.x86_64',
            'cpuinfo': V3, 'free_root': 60 * 1024 ** 3, 'free_boot': 2 * 1024 ** 3, 'ifcfg': ['readme-ifcfg-rh.txt'], 'time_synced': True,
            'packages': [f'bash-5.2-1.{release}.x86_64', f'postfix-3.8-1.{release}.x86_64'] + (
                ['kernel-core-5.14.0-687.66.1.el9_8.x86_64', 'kernel-core-6.12.0-55.el10.x86_64', 'leapp-0.20.0-2.el9.noarch']
                if major == 10 else []), 'dnf_check': '', 'selinux': 'Enforcing',
            'avc': 0, 'net_drivers': {'ens192': 'vmxnet3'}, 'addresses': ['ens192 192.0.2.10/24'], 'routes': ['default via 192.0.2.1 dev ens192'],
            'firewall': {'public': {'services': ['smtp', 'ssh'], 'ports': [], 'interfaces': ['ens192'], 'sources': [], 'rich_rules': []}},
            'nft_tables': {'inet test_block': 'table inet test_block {\n tcp dport 25 counter packets 3 bytes 180 reject\n}'},
            'active': list(UNITS)}


class FakePlatform:
    def __init__(self):
        self.major, self.calls, self.removed, self.leapp_busy = 9, [], set(), [False]
        # The Wazuh agent of the operator per release ({} for none), as release_facts reports it.
        self.wazuh = {}
        self.leapp = {'preupgrade': GOOD_LEAPP, 'upgrade': GOOD_LEAPP}

    def __getattr__(self, name):
        # service_start_background, service_stop, service_enable, service_disable, reboot, package_install: recorded.
        return lambda *args, **kwargs: self.calls.append((name,) + args)

    def release_facts(self, avc_since=('boot',)):
        facts = host_facts(self.major)
        return {**facts, 'packages': [item for item in facts['packages'] if item not in self.removed], 'wazuh': self.wazuh.get(self.major, {})}

    def release_package_unchanged(self, paths):
        return set()

    def release_service_states(self, names, prefix):
        return {'efa-web': ('notify', 'active'), 'postfix': ('forking', 'active')}

    def release_leftover_facts(self, names):
        return {}, set()

    def release_remove_packages(self, names):
        self.calls.append(('release_remove_packages', tuple(names)))
        return True, ''

    def release_leapp_busy(self):
        # leapp_resume.service: still running for the first answers, then done (the last answer stays).
        return self.leapp_busy.pop(0) if len(self.leapp_busy) > 1 else self.leapp_busy[0]

    def service_is_active(self, name):
        return True

    def release_prepare(self, release_rpm, packages):
        self.calls.append(('release_prepare', release_rpm, tuple(packages)))
        return True, ''

    def release_recover_script(self, *args, **kwargs):
        return efa_platform_el9.EL9().release_recover_script(*args, **kwargs)

    def release_leapp(self, args, log_path):
        self.calls.append(('leapp',) + tuple(args))
        # leapp takes the vendor efa-next only while its EL9 repository is on.
        with open(self.repo) as f:
            self.calls.append(('repo while leapp', 'enabled=1' in f.read()))
        # What leapp reads of its customisation during the run.
        seen = {}
        for name in ('to_install', 'to_keep', 'epel.repo'):
            with open(self.leapp_files[name]) as f:
                seen[name] = f.read()
        self.calls.append(('leapp files', seen))
        with open(self.log.format(args[0]), 'w') as f:
            f.write(self.leapp[args[0]])
        if args == ['preupgrade']:
            with open(self.report, 'w') as f:
                json.dump({'entries': [{'title': 'Packages not signed by the distribution vendor found on the system',
                                        'severity': 'high', 'groups': ['sanity'], 'key': 'k4'}]}, f)
        return 0

    def release_enforce(self):
        return 'Enforcing'

    def path(self, name):
        return {'redis_dir': self.tmp + '/valkey', 'redis_cli': '/usr/bin/valkey-cli'}[name]

    def account(self, name):
        return 'root'

    def release_key_fingerprints(self, key_path):
        return [self.fingerprint]

    def release_signature(self, path, key_path):
        # What rpm -K says of a package signed by the ELevate key.
        return f'{os.path.basename(path)}: digests signatures OK\n', 'RSA/SHA256, Key ID 429785e181b961a5'

    def release_cleanup(self, packages):
        self.calls.append(('release_cleanup', tuple(packages)))
        self.removed |= {item for item in host_facts(10)['packages'] if item in packages or item.split('-0.')[0] in packages}
        return True, ''


class FakeRun:
    """The programs efactl starts, answered as on a set-up host; gpg runs for real. Anything else fails the test."""
    def __init__(self, etc):
        self.etc, self.calls = etc, []
        self.postconf = {'smtpd_client_restrictions': 'permit_mynetworks', 'config_directory': etc + '/postfix', 'myhostname': 'mx.example.org'}
        # The version of an installed wazuh-agent, '' for none (rpm -q).
        self.wazuh = ''

    def __getattr__(self, name):
        return getattr(subprocess, name)

    def run(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        name, ok = os.path.basename(cmd[0]), subprocess.CompletedProcess(cmd, 0, '', '')
        if name == 'gpg':
            return subprocess.run(cmd, **kwargs)
        if name == 'postconf' and cmd[1:2] == ['-h']:
            return subprocess.CompletedProcess(cmd, 0, ''.join(self.postconf.get(item, '') + '\n' for item in cmd[2:]), '')
        if name == 'postconf' and cmd[1:2] == ['-e']:
            key, _, value = cmd[2].partition(' = ')
            self.postconf[key] = value
            return ok
        if name == 'postconf' and cmd[1:2] == ['-n']:
            return subprocess.CompletedProcess(cmd, 0, ''.join(f'{key} = {value}\n' for key, value in sorted(self.postconf.items())), '')
        if name == 'postconf' and cmd[1:2] == ['-P']:
            return subprocess.CompletedProcess(cmd, 0, 'submission/inet/syslog_name = postfix/submission\n', '')
        if name == 'postconf' and cmd[1:2] == ['-m']:
            return subprocess.CompletedProcess(cmd, 0, 'cidr\nhash\nlmdb\n', '')
        if name == 'postconf' and cmd[1:2] == ['-M']:
            return subprocess.CompletedProcess(cmd, 0, 'smtp      unix  -       -       n       -       -       smtp\n', '')
        if name == 'postconf' and cmd[1:2] == ['-X']:
            for key in cmd[2:]:
                self.postconf.pop(key, None)
            return ok
        if name == 'rpm' and 'wazuh-agent' in cmd:
            return subprocess.CompletedProcess(cmd, 0 if self.wazuh else 1, self.wazuh, '')
        if name in ('dnf', 'postqueue', 'postfix', 'systemctl', 'mariadb-upgrade', 'mysqlcheck', 'postmap', 'postalias', 'sftp', 'mysqldump',
                    'nginx', 'postsuper'):
            return ok
        raise AssertionError(f'unexpected program: {cmd}')


class FakeSMTP:
    """Postfix with rspamd and ClamAV in front: a clean mail is taken, GTUBE and EICAR rejected."""
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def ehlo(self, *args):
        return 250, b'ok'

    def has_extn(self, name):
        return False

    def mail(self, sender):
        return 250, b'2.1.0 Ok'

    def rcpt(self, recipient):
        return 250, b'2.1.5 Ok'

    def rset(self):
        return 250, b'2.0.0 Ok'

    def data(self, raw):
        if b'GTUBE' in raw or b'EICAR' in raw:
            return 554, b'5.7.1 Spam message rejected'
        return 250, b'2.0.0 Ok: queued as 4AbCdE'


class Reply:
    status = 200

    def read(self, size=-1):
        return b''

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


@unittest.skipUnless(os.name == 'posix' and shutil.which('gpg'), 'the backup test of start needs gpg on a Unix host')
class ReleaseUpgradeFlow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='efa-ru-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        etc = self.etc = self.tmp + '/etc'
        env = {'EFA_ETC': etc, 'EFA_BACKUP_DIR': self.tmp + '/backup', 'EFA_RU_DIR': self.tmp + '/ru', 'EFA_RU_LOG': self.tmp + '/ru.log'}
        with mock.patch.dict(os.environ, env):
            loader = importlib.machinery.SourceFileLoader('efactl_flow', os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'))
            self.efactl = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_flow', loader))
            loader.exec_module(self.efactl)
        for path, text in (('eFa-Version', '6.0.0.6\n'), ('postfix/main.cf', 'myhostname = mx.example.org\n'),
                           ('postfix/transport', 'example.org smtp:[192.0.2.20]\n'), ('eFa/backup-password', 'a backup password 1234\n'),
                           ('cron.d/eFa-Monitor.cron', '* * * * * root /usr/sbin/efa-monitor\n')):
            os.makedirs(os.path.dirname(f'{etc}/{path}'), exist_ok=True)
            with open(f'{etc}/{path}', 'w') as f:
                f.write(text)
        os.makedirs(self.tmp + '/backup')
        with open(f'{etc}/eFa/backup-targets.json', 'w') as f:
            json.dump({'offsite': {'kind': 'sftp', 'host': 'backup.example.org', 'user': 'efa', 'key_file': etc + '/eFa/k', 'path': '/b',
                                   'keep_days': 7}}, f)
        self.platform, self.run = FakePlatform(), FakeRun(etc)
        lib = self.efactl._ru_lib()
        self.platform.report, self.platform.tmp, self.platform.fingerprint = self.tmp + '/leapp-report.json', self.tmp, lib.ELEVATE_FINGERPRINT
        self.platform.log, self.platform.repo = self.tmp + '/leapp-{}.log', etc + '/yum.repos.d/efa-next.repo'
        self.net = self.tmp + '/net'
        # What leapp leaves on disk after the upgrade.
        self.leftovers = [self.tmp + '/leapp-left/etc-leapp/files', self.tmp + '/leapp-left/var-lib-leapp', self.tmp + '/leapp-left/tmp_leapp_py3']
        for path in self.leftovers:
            os.makedirs(path + '/sub')
        self.dnf_conf = etc + '/dnf.conf'
        with open(self.dnf_conf, 'w') as f:
            f.write('[main]\ngpgcheck=1\nexclude=clamd-[2-9]*,python3-leapp,leapp-upgrade-el9toel10,snactor,leapp,python3-pymilter-[2-9]*\n')
        # leapp's files as its packages ship them (leapp-upgrade-el9toel10, leapp-data-almalinux).
        self.shipped = {'to_install': '### List of packages (each on new line) to be added to the upgrade transaction\n',
                        'to_keep': '### List of packages (each on new line) to be kept in the upgrade transaction\n',
                        'epel.repo': '[el10-epel]\nmetalink=https://mirrors.fedoraproject.org/metalink?repo=epel-10&arch=$basearch\ngpgcheck=1\n',
                        'upgrade_paths.json': json.dumps({'almalinux': {'default': {'9': ['10.0', '10.1', '10.2']}}})}
        self.platform.leapp_files = {name: f'{self.tmp}/leapp/{name}' for name in self.shipped}
        os.makedirs(self.tmp + '/leapp')
        for name, text in self.shipped.items():
            with open(self.platform.leapp_files[name], 'w') as f:
                f.write(text)
        os.makedirs(self.tmp + '/valkey')
        os.makedirs(etc + '/yum.repos.d')
        with open(etc + '/yum.repos.d/efa-next.repo', 'w') as f:
            f.write('[efa-next]\nname=eFa-next EL9\nbaseurl=https://repo.efa-next.eu/el9/\nenabled=0\n')
        for patch in (mock.patch.object(self.efactl, '_platform', lambda: self.platform), mock.patch.object(self.efactl, 'subprocess', self.run),
                      mock.patch.object(self.efactl.urllib.request, 'urlopen', lambda *args, **kwargs: Reply()),
                      mock.patch.object(self.efactl.smtplib, 'SMTP', FakeSMTP), mock.patch.object(self.efactl, 'BACKUP_PATHS', (etc + '/postfix',)), mock.patch.object(self.efactl, 'BACKUP_DATA_PATHS', ()),
                      mock.patch.object(self.efactl, 'RU_FINISH_TRIES', 1), mock.patch.object(self.efactl, 'RU_FINISH_WAIT', 0),
                      mock.patch.object(lib, 'LEAPP_REPORT', self.platform.report), mock.patch.object(lib, 'VENDORS_DIR', self.tmp + '/vendors.d'),
                      # Never the files of the host that runs the test: the repositories and the settings below the temp root.
                      mock.patch.object(lib, 'REPO_FILES', (etc + '/yum.repos.d/efa-next.repo',)),
                      mock.patch.object(lib, 'LEAPP_LOG', self.platform.log), mock.patch.object(lib, 'RECOVER_DIR', self.net),
                      mock.patch.object(lib, 'RECOVER_UNIT_FILE', self.net + '-unit/' + lib.RECOVER_UNIT),
                      mock.patch.object(lib, 'RECOVER_MOTD', self.net + '-motd'),
                      mock.patch.object(lib, 'LEAPP_TRANSACTION_DIR', self.tmp + '/leapp'),
                      mock.patch.object(lib, 'LEAPP_LEFTOVERS', tuple(self.leftovers)),
                      mock.patch.object(lib, 'LEAPP_ETC', self.tmp + '/leapp-left/etc-leapp'),
                      mock.patch.object(lib, 'DNF_CONF', self.dnf_conf), mock.patch.object(lib, 'RPMNEW_DIR', self.tmp + '/ru/rpmnew'),
                      mock.patch.object(lib, 'RPMNEW_MANAGED', (etc + '/postfix/main.cf', etc + '/chrony.conf')),
                      mock.patch.object(self.efactl, 'RU_LEAPP_WAIT', 0), mock.patch.object(self.efactl.time, 'sleep', lambda seconds: None),
                      mock.patch.object(lib, 'LEAPP_EPEL_REPO', self.platform.leapp_files['epel.repo']),
                      mock.patch.object(lib, 'LEAPP_UPGRADE_PATHS', self.platform.leapp_files['upgrade_paths.json']),
                      mock.patch.object(lib, 'CONFIG_DIRS', (etc + '/postfix', etc + '/rspamd/local.d')),
                      mock.patch.object(self.efactl, 'RU_REDIS_DUMP', self.tmp + '/redis/dump.rdb')):
            patch.start()
            self.addCleanup(patch.stop)

    def step(self, action, **confirm):
        """What the web interface or the console does, then what efa-release-upgrade.service does."""
        args = argparse.Namespace(action=action, snapshot=confirm.get('snapshot', ''), hostname=confirm.get('hostname', ''))
        answer = self.efactl.release_upgrade(args)
        if action in ('preflight', 'preupgrade', 'start'):
            self.assertIn(('service_start_background', self.efactl.RU_UNIT), self.platform.calls)
            self.assertEqual(self.efactl.release_upgrade_status(None)['state'], 'queued')
            self.efactl.release_upgrade_run(None)
        return answer

    def state(self):
        return self.efactl.release_upgrade_status(None)

    def test_save_takes_state_as_a_change(self):
        record = {}
        self.efactl._ru_save(record, state='preflight', request=None)
        self.assertEqual(record['state'], 'preflight')

    def test_whole_upgrade(self):
        lib = self.efactl._ru_lib()
        self.assertEqual(self.state()['state'], 'idle')
        self.step('preflight')
        self.assertEqual(self.state()['state'], 'ready', self.state())
        self.step('preupgrade')
        state = self.state()
        self.assertEqual(state['state'], 'ready', state)
        self.assertEqual([item['key'] for item in state['preupgrade']['high_risk']], ['k4'])
        self.assertTrue(os.path.exists(self.tmp + '/vendors.d/efa-next_map.json'))
        self.assertIn(('leapp', 'preupgrade'), self.platform.calls)
        self.assertEqual(state['preupgrade']['removal'], [])
        self.assertEqual([call for call in self.platform.calls if call[0] == 'repo while leapp'], [('repo while leapp', True)])
        # During leapp: nginx, sendmail-milter and pytz kept against the PES removals, eFa-next taken from the EL10 repository,
        # EPEL of the target release 10.2. After it: the files as leapp shipped them.
        seen = [call[1] for call in self.platform.calls if call[0] == 'leapp files'][0]
        self.assertTrue(seen['to_keep'].startswith(self.shipped['to_keep']))
        self.assertTrue(seen['to_keep'].endswith('nginx\nsendmail-milter\npython3-pytz\nwazuh-agent\n'), seen['to_keep'])
        self.assertTrue(seen['to_install'].endswith('eFa-next\neFa-next-base\npython3-pymilter\ncertbot\npython3-certbot-nginx\n'))
        self.assertIn('metalink?repo=epel-10.2&arch=', seen['epel.repo'])
        for name in ('to_install', 'to_keep', 'epel.repo'):
            with open(self.platform.leapp_files[name]) as f:
                self.assertEqual(f.read(), self.shipped[name], name)
        with open(self.platform.repo) as f:
            self.assertIn('enabled=0', f.read())
        with self.assertRaises(self.efactl.EfaError):
            self.step('start', snapshot='yes', hostname='wrong.example.org')
        self.step('start', snapshot='yes', hostname=self.efactl.own_hostname())
        state = self.state()
        self.assertEqual(state['state'], 'rebooting', state)
        self.assertIn(('leapp', 'upgrade'), self.platform.calls)
        self.assertIn(('reboot',), self.platform.calls)
        self.assertIn(('service_enable', self.efactl.RU_FINISH_UNIT), self.platform.calls)
        self.assertIn(('service_enable', lib.RECOVER_UNIT), self.platform.calls)
        self.assertTrue(os.path.exists(self.net + '/recover.sh') and os.path.exists(lib.RECOVER_UNIT_FILE))
        with open(self.platform.repo) as f:
            self.assertIn('enabled=0', f.read())
        # Maintenance: new mail 421, the restriction of before kept, the service monitor off, a backup that left the host.
        self.assertTrue(os.path.exists(self.efactl.RU_MAINTENANCE_MAP))
        self.assertTrue(self.run.postconf['smtpd_client_restrictions'].startswith('check_client_access cidr:'))
        self.assertFalse(os.path.exists(self.etc + '/cron.d/eFa-Monitor.cron'))
        self.assertTrue(any(call[0] == 'sftp' for call in self.run.calls))
        self.assertTrue(state['backup']['backup'].endswith('.gpg'))
        # The first boot into EL10: leapp_resume still runs at first, the stock main.cf of EL10 lies beside the managed one.
        self.platform.major = 10
        self.platform.leapp_busy[:] = [True, False]
        with open(self.etc + '/postfix/main.cf.rpmnew', 'w') as f:
            f.write('# stock EL10\n')
        with mock.patch.object(self.efactl, 'RU_LEAPP_WAIT', 60):
            self.efactl.release_upgrade_finish(None)
        cleanup = [call[1] for call in self.platform.calls if call[0] == 'release_cleanup'][0]
        self.assertIn('leapp', cleanup)
        self.assertIn('kernel-core-5.14.0-687.66.1.el9_8.x86_64', cleanup)
        self.assertNotIn('kernel-core-6.12.0-55.el10.x86_64', cleanup)
        with open(self.dnf_conf) as f:
            self.assertEqual(f.read(), '[main]\ngpgcheck=1\nexclude=clamd-[2-9]*,python3-pymilter-[2-9]*\n')
        self.assertFalse(os.path.exists(self.etc + '/postfix/main.cf.rpmnew'))
        kept = [os.path.join(root, name) for root, _dirs, names in os.walk(self.tmp + '/ru/rpmnew') for name in names]
        self.assertEqual([path.endswith('/postfix/main.cf.rpmnew') for path in kept], [True])
        self.assertEqual(os.stat(self.tmp + '/ru/rpmnew').st_mode & 0o777, 0o700)
        # All checks passed: what leapp left is gone, its folder in /etc too.
        self.assertFalse([path for path in self.leftovers if os.path.exists(path)])
        self.assertFalse(os.path.exists(self.tmp + '/leapp-left/etc-leapp'))
        state = self.state()
        self.assertEqual(state['state'], 'done', state['result']['failed'])
        self.assertEqual(self.run.postconf['smtpd_client_restrictions'], 'permit_mynetworks')
        self.assertFalse(os.path.exists(self.efactl.RU_MAINTENANCE_MAP))
        with open(self.etc + '/yum.repos.d/efa-next.repo') as f:
            self.assertIn('repo.efa-next.eu/el10/', f.read())
        self.assertTrue(os.path.exists(self.etc + '/cron.d/eFa-Monitor.cron'))
        self.assertEqual(self.efactl.release_upgrade_finish(None), {'release_upgrade': 'nothing to do'})
        self.assertFalse(os.path.exists(self.net) or os.path.exists(lib.RECOVER_UNIT_FILE))
        self.assertIn(('service_disable', lib.RECOVER_UNIT), self.platform.calls)

    def test_preupgrade_stops_when_leapp_would_remove_efa_next(self):
        self.platform.leapp['preupgrade'] = BAD_LEAPP
        self.step('preflight')
        self.step('preupgrade')
        state = self.state()
        self.assertEqual(state['state'], 'inhibited', state)
        self.assertTrue(any('vendor efa-next not active' in text for text in state['warnings']), state['warnings'])
        self.assertTrue(any('remove eFa-next,' in text for text in state['warnings']), state['warnings'])
        self.assertTrue(any('remove python3-pymilter' in text for text in state['warnings']), state['warnings'])
        with self.assertRaises(self.efactl.EfaError):
            self.efactl.release_upgrade(argparse.Namespace(action='start', snapshot='yes', hostname=self.efactl.own_hostname()))
        self.assertNotIn(('leapp', 'upgrade'), self.platform.calls)

    def test_no_reboot_when_leapp_upgrade_would_remove_efa_next(self):
        lib = self.efactl._ru_lib()
        self.step('preflight')
        self.step('preupgrade')
        self.platform.leapp['upgrade'] = BAD_LEAPP
        with self.assertRaises(self.efactl.EfaError):
            self.step('start', snapshot='yes', hostname=self.efactl.own_hostname())
        state = self.state()
        self.assertEqual(state['state'], 'failed', state)
        self.assertIn('no reboot', state['error'])
        self.assertNotIn(('reboot',), self.platform.calls)
        # Maintenance stays on, and so does the safety net for a reboot by hand.
        self.assertTrue(os.path.exists(self.efactl.RU_MAINTENANCE_MAP))
        self.assertTrue(os.path.exists(self.efactl.RU_FINISH_MARK) and os.path.exists(self.net + '/recover.sh'))
        with open(self.platform.repo) as f:
            self.assertIn('enabled=0', f.read())

    def test_safety_net_puts_efa_next_back(self):
        """recover.sh of the safety net as the first EL10 boot runs it: efactl missing, dnf installs it, the checks run;
        dnf fails: maintenance stays, a note on the console."""
        lib = self.efactl._ru_lib()
        bin_dir, efactl = self.tmp + '/bin', self.tmp + '/sbin/efactl'
        os.makedirs(bin_dir)
        os.makedirs(os.path.dirname(efactl))
        with open(self.tmp + '/os-release', 'w') as f:
            f.write('ID="almalinux"\nVERSION_ID="10.2"\n')
        with open(bin_dir + '/dnf', 'w') as f:
            f.write(f'#!/bin/sh\necho "$@" > {self.tmp}/dnf-args\n[ -e {self.tmp}/dnf-fails ] && exit 1\n'
                    f'printf \'#!/bin/sh\\necho "$@" > {self.tmp}/finish-ran\\n\' > {efactl}\nchmod 755 {efactl}\n')
        with open(bin_dir + '/systemctl', 'w') as f:
            f.write(f'#!/bin/sh\necho "$@" >> {self.tmp}/systemctl-args\nexit 0\n')
        for name in ('dnf', 'systemctl'):
            os.chmod(f'{bin_dir}/{name}', 0o755)
        mark = self.tmp + '/finish-pending'
        open(mark, 'w').close()
        script = self.tmp + '/recover.sh'
        with open(script, 'w') as f:
            f.write(efa_platform_el9.EL9().release_recover_script(self.tmp + '/recover.log', mark, self.net + '/repos', lib.RECOVER_MOTD,
                                                                  efactl=efactl, os_release=self.tmp + '/os-release'))
        env = {**os.environ, 'PATH': bin_dir + ':' + os.environ['PATH']}
        done = subprocess.run(['sh', script], env=env, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertFalse(os.path.exists(self.tmp + '/finish-ran'))
        with open(self.tmp + '/systemctl-args') as f:
            self.assertEqual(f.read().splitlines(), ['daemon-reload', 'start --no-block efa-release-upgrade-finish.service'])
        with open(self.tmp + '/dnf-args') as f:
            self.assertIn(f'reposdir=/etc/yum.repos.d,{self.net}/repos install eFa-next eFa-next-base', f.read())
        # efactl is there now: nothing to do.
        self.assertEqual(subprocess.run(['sh', script], env=env, capture_output=True).returncode, 0)
        os.remove(efactl)
        open(self.tmp + '/dnf-fails', 'w').close()
        done = subprocess.run(['sh', script], env=env, capture_output=True, text=True)
        self.assertEqual(done.returncode, 1)
        with open(lib.RECOVER_MOTD) as f:
            self.assertIn('Maintenance stays on (new mail gets 421)', f.read())
        with open(self.tmp + '/recover.log') as f:
            self.assertIn('FAILED: eFa-next could not be installed again', f.read())

    def test_wazuh_agent_of_the_operator_is_carried_over(self):
        """An agent eFa-next did not install, off as on a clone: start takes it over before the settings are kept, the finish finds
        it taken over; ossec.conf stays byte for byte and no call reaches the agent."""
        conf = self.tmp + '/ossec.conf'
        foreign = ('<ossec_config>\n  <client>\n    <server>\n      <address>wazuh.operator.example</address>\n    </server>\n'
                   '    <enrollment>\n      <groups>mail</groups>\n    </enrollment>\n  </client>\n</ossec_config>\n')
        with open(conf, 'w') as f:
            f.write(foreign)
        self.run.wazuh = '4.14.7-1'
        with mock.patch.object(self.efactl, 'WAZUH_CONF', conf), mock.patch.object(self.efactl, 'WAZUH_REAL_CONF', conf):
            self.step('preflight')
            self.step('preupgrade')
            self.step('start', snapshot='yes', hostname=self.efactl.own_hostname())
            with open(self.efactl.RU_LOG) as f:
                self.assertIn('Wazuh agent taken over: manager wazuh.operator.example, groups mail, active response on; config unchanged', f.read())
            self.platform.major = 10
            self.efactl.release_upgrade_finish(None)
        state = self.state()
        self.assertEqual(state['state'], 'done', state.get('result', {}).get('failed'))
        self.assertIn({'step': 'Wazuh agent', 'ok': True, 'detail': 'already managed by eFa-next'},
                      state['after_upgrade'])
        with open(conf) as f:
            self.assertEqual(f.read(), foreign)
        with open(self.efactl.WAZUH_FILE) as f:
            self.assertTrue(json.load(f)['managed'])
        self.assertEqual([call for call in self.run.calls if 'wazuh-agent' in call and call[0] != 'rpm'], [])

    def test_wazuh_agent_stays_as_it_was(self):
        """The agent of an operator, off and masked as on a clone, and one that runs: the same package, files and state after
        the upgrade pass; an agent that runs after the upgrade although it was off fails the check, maintenance stays on."""
        for before_state, after_state, result in ((('masked', 'inactive'), ('masked', 'inactive'), 'done'),
                                                  (('enabled', 'active'), ('enabled', 'active'), 'done'),
                                                  (('masked', 'inactive'), ('enabled', 'active'), 'checks_failed')):
            with self.subTest(before=before_state, after=after_state):
                self.setUp()
                agent = {'version': '4.14.10-1', 'ossec_conf': 'a' * 64, 'client_keys': 'b' * 64, 'runs': True}
                self.platform.wazuh = {9: {**agent, 'enabled': before_state[0], 'active': before_state[1]},
                                       10: {**agent, 'enabled': after_state[0], 'active': after_state[1]}}
                self.step('preflight')
                checks = {item['name']: item for item in self.state()['preflight']['checks']}
                self.assertIn('stays exactly as it is', checks['Wazuh agent']['detail'])
                self.step('preupgrade')
                self.step('start', snapshot='yes', hostname=self.efactl.own_hostname())
                self.platform.major = 10
                self.efactl.release_upgrade_finish(None)
                state = self.state()
                self.assertEqual(state['state'], result, state.get('result', {}).get('failed'))
                if result != 'done':
                    self.assertTrue(any(item.startswith('Wazuh agent unchanged') for item in state['result']['failed']))
                    self.assertTrue(os.path.exists(self.efactl.RU_MAINTENANCE_MAP))
                self.assertEqual([call for call in self.platform.calls if 'wazuh-agent' in call], [], 'nothing reaches the agent')
                self.assertEqual([call for call in self.run.calls if 'wazuh-agent' in call and call[0] != 'rpm'], [])

    def test_leapp_may_not_touch_the_wazuh_agent(self):
        """If leapp would update, reinstall or remove the agent, preupgrade stops: its scripts would stop or unmask it."""
        self.platform.wazuh = {9: {'version': '4.14.10-1', 'enabled': 'masked', 'active': 'inactive', 'ossec_conf': 'a' * 64, 'client_keys': ''}}
        self.platform.leapp['preupgrade'] = leapp_log(True, [('Upgrading', ['eFa-next', 'eFa-next-base', 'wazuh-agent'])])
        self.step('preflight')
        self.step('preupgrade')
        state = self.state()
        self.assertEqual(state['state'], 'inhibited', state)
        self.assertTrue(any('leapp would change wazuh-agent (Upgrading)' in text for text in state['warnings']), state['warnings'])

    def test_finish_keeps_maintenance_on_a_failed_check(self):
        self.step('preflight')
        self.step('preupgrade')
        self.step('start', snapshot='yes', hostname=self.efactl.own_hostname())
        self.platform.major = 9  # leapp did not reach EL10
        self.efactl.release_upgrade_finish(None)
        state = self.state()
        self.assertEqual(state['state'], 'checks_failed')
        self.assertTrue(any(item.startswith('Enterprise Linux 10') for item in state['result']['failed']))
        self.assertTrue(os.path.exists(self.efactl.RU_MAINTENANCE_MAP))

    def test_blocked_without_the_el10_repository(self):
        def no_repo(*args, **kwargs):
            raise OSError('HTTP Error 404: Not Found')
        with mock.patch.object(self.efactl.urllib.request, 'urlopen', no_repo):
            self.step('preflight')
        state = self.state()
        self.assertEqual(state['state'], 'blocked')
        self.assertTrue(any('repository for EL10' in item for item in state['warnings']))
        # preupgrade runs the preflight again and stops there: no ELevate installed.
        with mock.patch.object(self.efactl.urllib.request, 'urlopen', no_repo):
            self.step('preupgrade')
        self.assertEqual(self.state()['state'], 'blocked')
        self.assertFalse([call for call in self.platform.calls if call[0] == 'release_prepare'])

    def test_no_selinux_and_no_removal_while_leapp_runs(self):
        """leapp_resume.service still running at the end of the wait: SELinux stays, leapp stays, the checks fail, 421 stays."""
        self.step('preflight')
        self.step('preupgrade')
        self.step('start', snapshot='yes', hostname=self.efactl.own_hostname())
        self.platform.major = 10
        self.platform.leapp_busy[:] = [True]
        self.efactl.release_upgrade_finish(None)
        state = self.state()
        self.assertEqual(state['state'], 'checks_failed')
        self.assertIn({'step': 'leapp ended its own phase', 'ok': False}, [{key: item[key] for key in ('step', 'ok')} for item in state['after_upgrade']])
        self.assertFalse([call for call in self.platform.calls if call[0] in ('release_enforce', 'release_cleanup')])
        self.assertTrue(os.path.exists(self.efactl.RU_MAINTENANCE_MAP))
        # Checks failed: leapp's leftovers stay for the next try and the analysis.
        self.assertTrue(all(os.path.exists(path) for path in self.leftovers))

    def test_drain_does_not_wait_for_deferred_mail(self):
        """Mail that is deferred (its next try comes later) stays queued; the drain waits only for mail on its way."""
        rows = [{'queue': 'deferred'}, {'queue': 'deferred'}, {'queue': 'hold'}]
        waited, real_sleep = [], REAL_SLEEP

        def nap(seconds):
            # Only the waits of the drain (15 s) count; the backup waits a second for a free name when two starts share
            # one second, and that wait is real.
            if seconds == 15:
                waited.append(seconds)
                rows[:] = [row for row in rows if row['queue'] != 'active']
            else:
                real_sleep(seconds)
        self.step('preflight')
        self.step('preupgrade')
        with mock.patch.object(self.efactl, '_queue_rows', lambda: rows), mock.patch.object(self.efactl, 'RU_DRAIN_SECONDS', 900), \
                mock.patch.object(self.efactl.time, 'sleep', nap):
            self.step('start', snapshot='yes', hostname=self.efactl.own_hostname())
        self.assertEqual(self.state()['state'], 'rebooting')
        self.assertEqual(waited, [])
        with open(self.efactl.RU_LOG) as f:
            self.assertIn('3 mails stay in the queue over the upgrade (2 deferred', f.read())
        # Mail on its way is waited for.
        rows[:] = [{'queue': 'active'}]
        with mock.patch.object(self.efactl, '_queue_rows', lambda: rows), mock.patch.object(self.efactl.time, 'sleep', nap):
            self.efactl._ru_save(self.efactl._ru_state(), state='ready')
            self.step('start', snapshot='yes', hostname=self.efactl.own_hostname())
        self.assertEqual(waited, [15])

    def test_teaming_blocks_the_upgrade(self):
        """EL10 has no teamd: a host with a team connection would boot without network. Preflight stops, nothing installed."""
        facts = {**host_facts(9), 'team': ['team0']}
        with mock.patch.object(self.platform, 'release_facts', lambda avc_since=('boot',): facts):
            self.step('preflight')
            self.assertEqual(self.state()['state'], 'blocked')
            self.assertTrue(any('No network teaming' in text and 'bond' in text for text in self.state()['warnings']))
            self.step('preupgrade')
        self.assertEqual(self.state()['state'], 'blocked')
        self.assertFalse([call for call in self.platform.calls if call[0] in ('release_prepare', 'leapp')])

    def test_leapp_error_is_no_pass(self):
        # leapp preupgrade that ends with an error (a broken vendor map) and no inhibitor: not ready, start refused.
        self.step('preflight')
        with mock.patch.object(self.platform, 'release_leapp', lambda args, log: 1):
            with open(self.platform.report, 'w') as f:
                f.write('{"entries": []}')
            self.step('preupgrade')
        state = self.state()
        self.assertEqual(state['state'], 'inhibited')
        self.assertTrue(any('ended with exit 1' in text for text in state['warnings']))
        with self.assertRaises(self.efactl.EfaError):
            self.efactl.release_upgrade(argparse.Namespace(action='start', snapshot='yes', hostname=self.efactl.own_hostname()))

    def test_abort(self):
        args = argparse.Namespace(action='preflight', snapshot='', hostname='')
        self.efactl.release_upgrade(args)
        self.assertEqual(self.efactl.release_upgrade(argparse.Namespace(action='abort', snapshot='', hostname='')), {'release_upgrade': 'aborted'})
        self.assertEqual(self.state()['state'], 'aborted')
        self.assertIn(('service_stop', self.efactl.RU_UNIT), self.platform.calls)
        # The maintenance mode of the admin stays: the upgrade had not set one.
        self.assertTrue(os.path.exists(self.etc + '/cron.d/eFa-Monitor.cron'))
        self.efactl._ru_save(self.efactl._ru_state(), state='upgrading')
        with self.assertRaises(self.efactl.EfaError):
            self.efactl.release_upgrade(argparse.Namespace(action='abort', snapshot='', hostname=''))

    def test_a_fault_never_leaves_a_step_running(self):
        def broken(*args, **kwargs):
            raise KeyError('addresses')
        self.efactl.release_upgrade(argparse.Namespace(action='preflight', snapshot='', hostname=''))
        with mock.patch.object(self.platform, 'release_facts', broken):
            with self.assertRaises(self.efactl.EfaError):
                self.efactl.release_upgrade_run(None)
        self.assertEqual(self.state()['state'], 'failed')
        self.step('preflight')
        self.assertEqual(self.state()['state'], 'ready')


if __name__ == '__main__':
    unittest.main()
