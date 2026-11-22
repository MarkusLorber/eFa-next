# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""6.0.0.6.7 (Hans): the update policy of a cluster. Set only on the master (eFa-next mode, days, time; the operating system
off, security or all), the nodes refuse local changes; every install goes through the staged rollout, one node after the
other with its health window (after its reboot), the master last; dnf-automatic is off on every member; a lease that
expires; a node without its master for 48 h + n x 6 h installs security updates alone, not while a peer updates; the
hooks of the admin and the wrapper of the dnf transaction run only when root alone can change them."""
import json
import os
import shutil
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'next', 'usr', 'lib', 'eFa', 'python'))
import efa_update_hooks as hooks  # noqa: E402
from test_threat import load_efactl  # noqa: E402

HOUR = 3600


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder, True)
        e = self.efactl
        for name, value in (('UPDATE_POLICY_FILE', 'update-policy.json'), ('UPDATE_FILE', 'autoupdate.json'), ('UPDATE_LEASE', 'lease.json'),
                            ('UPDATE_POLICY_PUBLISHED', 'published.json'), ('UPDATE_FALLBACK_FILE', 'fallback.json'),
                            ('SYNC_RECEIVED', 'received.json'), ('UPDATE_PENDING_FILE', 'pending.json')):
            patcher = mock.patch.object(e, name, os.path.join(self.folder, value))
            patcher.start()
            self.addCleanup(patcher.stop)
        for name in ('_audit', '_event', '_admins_notify', '_admin_notify'):
            patcher = mock.patch.object(e, name, lambda *a, **kw: None)
            patcher.start()
            self.addCleanup(patcher.stop)

    def role(self, role):
        return mock.patch.object(self.efactl, 'cluster_role', lambda: role)


class ClientsRefuse(Base):
    def test_the_policy_is_shared_and_refused_on_a_node(self):
        e = self.efactl
        self.assertTrue(e.cluster_replicated('autoupdate-set'), 'the master hands it on')
        self.assertFalse(e.cluster_replicated('update-staged-run'), 'a step of the rollout stays on its node')
        args = types.SimpleNamespace(mode='auto', days='sun', time='03:00', os='security')
        with self.role('client'), mock.patch.object(e, '_os_update_apply', lambda: []), mock.patch.object(e, 'autoupdate_status', lambda _a: {}):
            with self.assertRaises(e.EfaError) as caught:
                e.autoupdate_set(args)
            self.assertIn('Managed by', str(caught.exception))
            with mock.patch.dict(os.environ, {'EFA_CLUSTER_REPLAY': '1'}):
                e.autoupdate_set(args)  # the journal of the master
        self.assertEqual(e._update_policy()['os'], 'security')

    def test_a_node_refuses_the_update_buttons(self):
        e = self.efactl
        with self.role('client'), mock.patch.object(e, 'acting_client', ''):
            for call, args in ((e.update_system, types.SimpleNamespace(confirm='yes', reboot='off', reboot_confirm='', dry_run='')),
                               (e.update_install, types.SimpleNamespace(confirm='yes')),
                               (e.update_staged_run, types.SimpleNamespace(job='r-abcdef', os='security', efa='no'))):
                with self.assertRaises(e.EfaError, msg=call.__name__):
                    call(args)

    def test_the_master_starts_a_step_of_its_rollout(self):
        e = self.efactl
        started = []
        with self.role('client'), mock.patch.object(e, 'acting_client', 'cluster-master'), \
                mock.patch.object(e, '_system_start', lambda *a: started.append(a) or {'update': 'started'}):
            e.update_staged_run(types.SimpleNamespace(job='r-abcdef', os='security', efa='no'))
        self.assertEqual(started, [('auto', False, 'security', 'no', 'r-abcdef')])
        self.assertEqual(json.load(open(e.UPDATE_LEASE))['job'], 'r-abcdef')


class Rollout(Base):
    def status(self, job, state='done', version='6.0.0.7'):
        return {'version': version, 'down': [], 'status': 'ok', 'update': {'job': job, 'state': state}}

    def test_one_node_at_a_time_the_master_last(self):
        e = self.efactl
        nodes = {'n1': {}, 'n2': {}, 'n3': {}}
        state = {'job': 'r-1', 'version': '6.0.0.7', 'order': ['n1', 'n2', 'n3'], 'index': 0, 'started': None}
        # A node that updates and reboots: no answer for a while, then done; the health window (1 h) starts then.
        answers = {}
        installs, now = [], 0
        while True:
            action, target = e.cluster_update_next(state, nodes, {name: answers.get(name) for name in nodes}, now, 1)
            if action == 'install':
                self.assertEqual([name for name in installs if answers.get(name) is None or answers[name]['update']['state'] != 'done'], [],
                                 'a node starts only when the one before is done')
                installs.append(target)
                state['started'] = now
                answers[target] = None  # rebooting
            elif action == 'wait' and answers.get(target) is None and now - state['started'] >= HOUR:
                answers[target] = self.status('r-1')  # back after its reboot
                done_at = now
            elif action == 'wait' and answers.get(target):
                self.assertLess(now - done_at, HOUR + 600, 'the window counts from the end of the step')
            elif action in ('self', 'done', 'stop'):
                break
            now += 600
        self.assertEqual((action, installs), ('self', ['n1', 'n2', 'n3']), 'the master goes last')

    def test_a_failed_step_or_no_answer_stops_it(self):
        e = self.efactl
        nodes = {'n1': {}, 'n2': {}}
        state = {'job': 'r-1', 'version': None, 'order': ['n1', 'n2'], 'index': 0, 'started': 0}
        self.assertEqual(e.cluster_update_next(dict(state), nodes, {'n1': self.status('r-1', 'failed')}, 60, 1)[0], 'stop')
        self.assertEqual(e.cluster_update_next(dict(state), nodes, {'n1': None}, 3 * HOUR - 60, 1)[0], 'wait')
        self.assertEqual(e.cluster_update_next(dict(state), nodes, {'n1': None}, 3 * HOUR + 60, 1)[0], 'stop')
        self.assertEqual(e.cluster_update_next(dict(state), nodes, {'n1': self.status('r-0')}, 60, 1)[0], 'wait', 'an older job is not this one')

    def test_os_off_installs_only_releases(self):
        e = self.efactl
        policy = {'mode': 'auto', 'days': ['sun'], 'time': '03:00', 'os': 'off'}
        update = {'latest': '6.0.0.7'}
        with mock.patch.object(e, '_update_available', lambda u: True):
            self.assertEqual(e._rollout_due({}, update, policy, lambda: [5, 3], 0, True), {'os': 'off', 'efa': True})
        with mock.patch.object(e, '_update_available', lambda u: False):
            self.assertIsNone(e._rollout_due({}, update, policy, lambda: [5, 3], 0, True), 'packages wait while the policy is off')
            self.assertEqual(e._rollout_due({}, update, {**policy, 'os': 'security'}, lambda: [0, 2], 0, True), {'os': 'security', 'efa': False})
            self.assertIsNone(e._rollout_due({}, update, {**policy, 'os': 'security'}, lambda: [0, 0], 0, True), 'nothing to install')
            self.assertIsNone(e._rollout_due({}, update, {**policy, 'os': 'all'}, lambda: [1], 0, False), 'only in the maintenance window')
            self.assertIsNone(e._rollout_due({'since': 0}, update, {**policy, 'os': 'all'}, lambda: [1], 10 * HOUR, True), 'once a day')


class Lease(Base):
    def test_a_second_job_waits_and_a_dead_lease_expires(self):
        e = self.efactl
        e._update_lease_take('r-1', now=1000)
        with self.assertRaises(e.EfaError):
            e._update_lease_take('r-2', now=1000 + HOUR)
        e._update_lease_take('r-1', now=1000 + HOUR)  # the same job again (its post-boot) is fine
        e._update_lease_take('r-2', now=1000 + HOUR + e.UPDATE_LEASE_SECONDS + 1)
        self.assertGreater(e.UPDATE_LEASE_SECONDS, (4 + 1) * HOUR, 'longer than the master waits for a node')
        e._update_lease_drop('r-1')
        self.assertTrue(os.path.exists(e.UPDATE_LEASE), 'only its own job drops it')
        e._update_lease_drop('r-2')
        self.assertFalse(os.path.exists(e.UPDATE_LEASE))


class Fallback(Base):
    def test_offsets_per_node(self):
        e = self.efactl
        self.assertFalse(e.fallback_due(None, 100 * HOUR, 0, None))
        self.assertFalse(e.fallback_due(0, 48 * HOUR - 1, 0, None))
        self.assertTrue(e.fallback_due(0, 48 * HOUR, 0, None))
        self.assertFalse(e.fallback_due(0, 53 * HOUR, 1, None), 'the second node 6 h later')
        self.assertTrue(e.fallback_due(0, 54 * HOUR, 1, None))
        self.assertFalse(e.fallback_due(0, 60 * HOUR, 0, 50 * HOUR), 'once a day')

    def fake_cluster(self, busy):
        calls = []

        def call(base, host, port, path, timeout=10, expected=None):
            calls.append((host, path, expected))
            return {'busy': host in busy}
        return types.SimpleNamespace(call=call), calls

    def run_step(self, busy, now):
        e = self.efactl
        json.dump({'nodes': ['node-a', 'node-c'], 'peers': {'node-a': {'host': 'h1', 'port': 8460, 'fingerprint': 'f1'},
                                                         'node-c': {'host': 'h3', 'port': 8460, 'fingerprint': 'f3'}}}, open(e.SYNC_RECEIVED, 'w'))
        json.dump({'mode': 'notify', 'days': ['sun'], 'time': '03:00', 'os': 'security'}, open(e.UPDATE_POLICY_FILE, 'w'))
        cluster, calls = self.fake_cluster(busy)
        started = []
        with self.role('client'), mock.patch.object(e, '_master_down_since', lambda: 0), \
                mock.patch.object(e, '_cluster_parts', lambda: (cluster, '/b', {'name': 'node-c', 'master': {'name': 'node-b'}})), \
                mock.patch.object(e, '_system_start', lambda *a: started.append(a) or {'update': 'started'}):
            result = e.update_fallback_step(now=now)
        return result, started, calls

    def test_the_second_node_waits_and_skips_while_a_peer_updates(self):
        result, started, _calls = self.run_step(set(), 50 * HOUR)
        self.assertEqual((result, started), (None, []), 'node-c is the second node: 54 h')
        result, started, calls = self.run_step({'h1'}, 55 * HOUR)
        self.assertEqual((result, started), ({'skipped': ['node-a']}, []))
        self.assertEqual(calls, [('h1', '/v1/busy', 'f1')], 'only the peer, with its own certificate; not itself')
        result, started, _calls = self.run_step(set(), 55 * HOUR)
        self.assertEqual(len(started), 1)
        self.assertEqual(started[0][:4], ('auto', False, 'security', 'no'), 'security updates only, never an eFa-next release')
        self.assertTrue(started[0][4].startswith('fallback-'))


class Policy(Base):
    def test_first_read_takes_the_values_of_before(self):
        e = self.efactl
        json.dump({'mode': 'auto', 'days': ['sat'], 'time': '02:00', 'latest': '6.0.0.6'}, open(e.UPDATE_FILE, 'w'))
        platform = types.SimpleNamespace(service_is_enabled=lambda name: name == 'dnf-automatic.timer')
        with mock.patch.object(e, '_platform', lambda: platform):
            self.assertEqual(e._update_policy(), {'mode': 'auto', 'days': ['sat'], 'time': '02:00', 'os': 'security'})
        self.assertTrue(os.path.exists(e.UPDATE_POLICY_FILE))
        self.assertEqual(e._update_state()['mode'], 'auto')

    def test_dnf_automatic_off_on_every_member(self):
        e = self.efactl
        json.dump({'mode': 'auto', 'days': ['sun'], 'time': '03:00', 'os': 'all'}, open(e.UPDATE_POLICY_FILE, 'w'))
        off, conf = [], []
        platform = types.SimpleNamespace(service_is_enabled=lambda name: True, service_disable=lambda name, stop=False: off.append(name),
                                         configure_auto_updates=lambda upgrade_type: conf.append(upgrade_type) or True)
        with mock.patch.object(e, '_platform', lambda: platform):
            with self.role('client'):
                e._os_update_apply()
            self.assertEqual(off, list(e.DNF_AUTOMATIC_TIMERS))
            with self.role('none'), mock.patch.object(e.os.path, 'exists', lambda path: True):
                e._os_update_apply()
        self.assertEqual(conf, ['default'], 'a host alone: dnf-automatic with all updates')

    def test_the_master_publishes_its_policy_once(self):
        e = self.efactl
        json.dump({'mode': 'auto', 'days': ['sun'], 'time': '03:00', 'os': 'off'}, open(e.UPDATE_POLICY_FILE, 'w'))
        entries = []
        cluster = types.SimpleNamespace(journal_append=lambda base, items: entries.extend(items))
        with mock.patch.object(e, '_cluster_parts', lambda: (cluster, '/b', {})):
            self.assertTrue(e._policy_publish())
            self.assertFalse(e._policy_publish())
        self.assertEqual(entries[0]['command'], 'autoupdate-set')
        self.assertEqual(entries[0]['args'], {'mode': 'auto', 'days': 'sun', 'time': '03:00', 'os': 'off'})

    def test_join_preview_shows_the_policy(self):
        e = self.efactl
        with mock.patch.object(e, 'cluster_local_accounts', lambda: []), mock.patch.object(e, '_breakglass', lambda: types.SimpleNamespace(read_state=lambda: {})):
            preview = e.join_preview_of({'files': [{'path': 'eFa/update-policy.json', 'change': 'replaced'}], 'unchanged_files': 0, 'postconf': [],
                                         'units': {}, 'tables': []}, 'node-b', postconf_now={}, active=lambda unit: unit == 'dnf-automatic.timer',
                                        policy_now={'mode': 'notify', 'days': ['sun'], 'time': '03:00', 'os': 'security'})
        self.assertEqual(preview['updates'], {'now': {'mode': 'notify', 'days': ['sun'], 'time': '03:00', 'os': 'security'}, 'replaced': True,
                                              'dnf_automatic_off': True})


class DnfCallSites(unittest.TestCase):
    """EVERY dnf transaction of efactl goes through _dnf_transaction (or _dnf_command inside update-system-run): the hooks and
    the wrapper. Only calls that change no package (check-update, a download) may call dnf directly."""
    READ_ONLY = ('check-update', "'download'", '--downloadonly', 'updateinfo', 'repoquery', 'repolist', 'makecache')

    def test_no_dnf_transaction_bypasses_the_runner(self):
        import re
        source = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'next', 'usr', 'sbin', 'efactl'), encoding='utf-8').read()
        bypass, seen = [], 0
        for found in re.finditer(r"\[\s*'dnf'", source):
            line_start = source.rfind('\n', 0, found.start()) + 1
            statement = source[line_start:source.find(']', found.start()) + 1]
            seen += 1
            if '_dnf_transaction(' in statement or '_dnf_command(' in statement or any(word in statement for word in self.READ_ONLY):
                continue
            bypass.append(f'line {source.count(chr(10), 0, found.start()) + 1}: {statement.strip()[:100]}')
        self.assertEqual(bypass, [], 'a dnf transaction outside the runner')
        self.assertGreaterEqual(seen, 10, 'the scan found the call sites')
        for name in ('package_install', 'package_downgrade', 'package_upgrade_files'):
            self.assertNotIn(f'.{name}(', source, f'{name} of the platform layer runs dnf without the hooks')
        for name in ('release_prepare', 'release_cleanup'):
            calls = re.findall(rf'\.{name}\(([^\n]*)', source)
            self.assertTrue(calls and all('run=_dnf_run_for(' in call for call in calls), f'{name} without the runner')
        self.assertNotIn("Popen(['dnf'", source)

    def test_the_runner_wraps_vetoes_and_nests(self):
        efactl = load_efactl()
        ran, phases = [], []
        hooks_lib = types.SimpleNamespace(wrapper=lambda folder: None,
                                          run_phase=lambda folder, phase, env: phases.append((phase, env['EFA_UPDATE_KIND'])) or {'ok': True, 'ran': [], 'failed': [], 'refused': []})
        with mock.patch.object(efactl, '_lib', lambda name: hooks_lib), \
                mock.patch.object(efactl.subprocess, 'run', lambda command, **kw: ran.append((command, kw.get('pass_fds'))) or types.SimpleNamespace(returncode=0, stdout='', stderr='')):
            with efactl._update_hooks('efa'):
                efactl._dnf_transaction(['dnf', '-y', 'upgrade', 'eFa-next'], 'efa')
                efactl._dnf_transaction(['dnf', '-y', 'downgrade', 'eFa-next'], 'efa')
            self.assertEqual(phases, [('pre', 'efa'), ('post', 'efa')], 'the hooks once around the whole install')
            phases.clear()
            efactl._dnf_install(['pyzor'], 'pyzor')
            self.assertEqual(phases, [('pre', 'pyzor'), ('post', 'pyzor')])
            efactl._HOOKS_NOW.update(depth=0, wrapper=7)
            self.assertEqual(efactl._dnf_command(['dnf', '-y', 'install', 'x']), (['/proc/self/fd/7', 'dnf', '-y', 'install', 'x'], {'pass_fds': (7,)}))
            efactl._HOOKS_NOW.update(depth=0, wrapper=None)
        self.assertEqual(ran[0], (['dnf', '-y', 'upgrade', 'eFa-next'], None))
        veto = types.SimpleNamespace(wrapper=lambda folder: None,
                                     run_phase=lambda folder, phase, env: {'ok': phase != 'pre', 'ran': ['10-veto'], 'failed': [('10-veto', 'exit 1')], 'refused': []})
        ran.clear()
        with mock.patch.object(efactl, '_lib', lambda name: veto), mock.patch.object(efactl.subprocess, 'run', lambda *a, **kw: ran.append(a)), \
                mock.patch.object(efactl, '_hook_alarm', lambda text: None), mock.patch.object(efactl, '_update_blocker', lambda: None), \
                mock.patch.object(efactl, '_maintenance', lambda mode: None):
            with self.assertRaises(efactl.EfaError):
                efactl._dnf_install(['pyzor'], 'pyzor')
            self.assertTrue(efactl._update_install({'latest': '6.0.0.7'}).startswith('Not installed: Not done: a pre hook said no'),
                            'the automatic install of a release on a host alone (update-run, auto) too')
        self.assertEqual(ran, [], 'no dnf after a veto')
        self.assertEqual(efactl._HOOKS_NOW, {'depth': 0, 'wrapper': None})


@unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0 and sys.platform.startswith('linux'), 'owner checks need root on Linux')
class Hooks(unittest.TestCase):
    def setUp(self):
        self.top = tempfile.mkdtemp(dir='/root')  # every folder above it belongs to root and is not writable by others
        self.addCleanup(shutil.rmtree, self.top, True)
        self.dir = os.path.join(self.top, 'update-hooks.d')
        os.makedirs(self.dir + '/pre.d', mode=0o755)
        os.makedirs(self.dir + '/post.d', mode=0o755)
        os.chmod(self.top, 0o755)

    def program(self, path, text, mode=0o755):
        with open(path, 'w') as f:
            f.write('#!/bin/sh\n' + text + '\n')
        os.chmod(path, mode)
        return path

    def test_the_wrapper_runs_the_dnf_command_line(self):
        out = os.path.join(self.top, 'args')
        self.program(self.dir + '/wrapper', f'echo "$@" > {out}')
        fd, problem = hooks.wrapper(self.dir)
        self.assertIsNone(problem)
        try:
            self.assertEqual(hooks.run_fd(fd, ['dnf', '-y', 'upgrade', '--security'])[0], 0)
        finally:
            os.close(fd)
        self.assertEqual(open(out).read().strip(), 'dnf -y upgrade --security')

    def test_a_failing_pre_hook_says_no_a_post_hook_only_reports(self):
        self.program(self.dir + '/pre.d/10-ok', 'exit 0')
        self.program(self.dir + '/pre.d/20-veto', 'echo busy; exit 3')
        result = hooks.run_phase(self.dir, 'pre')
        self.assertEqual((result['ok'], result['ran']), (False, ['10-ok', '20-veto']))
        self.assertIn('exit 3', result['failed'][0][1])
        self.program(self.dir + '/post.d/10-slow', 'sleep 5')
        result = hooks.run_phase(self.dir, 'post', timeout=1)
        self.assertEqual((result['ok'], result['failed'][0][1][:8]), (False, 'exit 124'), 'a timeout is a failure')

    def test_refused_wrong_owner_mode_symlink_or_folder(self):
        self.program(self.dir + '/pre.d/10-other', 'exit 0')
        os.chown(self.dir + '/pre.d/10-other', 65534, 65534)
        self.program(self.dir + '/pre.d/20-group', 'exit 0', mode=0o775)
        self.program(self.dir + '/pre.d/30-noexec', 'exit 0', mode=0o644)
        target = self.program(os.path.join(self.top, 'elsewhere'), 'exit 0')
        os.symlink(target, self.dir + '/pre.d/40-link')
        result = hooks.run_phase(self.dir, 'pre')
        self.assertEqual(result['ran'], [], 'none of them runs')
        reasons = dict(result['refused'])
        self.assertIn('root:root', reasons['10-other'])
        self.assertIn('writable', reasons['20-group'])
        self.assertIn('not executable', reasons['30-noexec'])
        self.assertIn('symlink', reasons['40-link'])
        self.assertTrue(result['ok'], 'a refused hook is left out, the caller raises the alarm')
        for name in os.listdir(self.dir + '/pre.d'):
            os.remove(self.dir + '/pre.d/' + name)
        self.program(self.dir + '/pre.d/10-fine', 'exit 0')
        os.chmod(self.dir + '/pre.d', 0o777)
        self.assertIn('writable by group or others', dict(hooks.run_phase(self.dir, 'pre')['refused'])['10-fine'])
        os.chmod(self.dir + '/pre.d', 0o755)
        os.chmod(self.top, 0o757)
        self.assertIn('writable', dict(hooks.run_phase(self.dir, 'pre')['refused'])['10-fine'], 'a folder above it too')

    def test_a_bad_wrapper_refuses_the_update(self):
        efactl = load_efactl()
        self.program(self.dir + '/wrapper', 'exit 0', mode=0o777)
        fd, problem = hooks.wrapper(self.dir)
        self.assertIsNone(fd)
        self.assertIn('writable', problem)
        work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, work, True)
        alarms, backups = [], []
        patches = [mock.patch.object(efactl, name, value) for name, value in (
            ('UPDATE_HOOKS_DIR', self.dir), ('UPDATE_LOCK', work + '/lock'), ('UPDATE_SYSTEM_FILE', work + '/system.json'),
            ('UPDATE_LEASE', work + '/lease.json'), ('UPDATE_FILE', work + '/auto.json'), ('UPDATE_POLICY_FILE', work + '/policy.json'),
            ('_progress_begin', lambda *a, **kw: {}), ('_progress_end', lambda *a, **kw: None), ('_progress_step', lambda *a, **kw: None),
            ('_system_log', lambda text: None), ('_admin_notify', lambda *a: None), ('_hook_alarm', alarms.append),
            ('backup_now', lambda _a: backups.append(1)), ('_update_available', lambda state: False))]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        args = types.SimpleNamespace(reboot='auto', dry_run='no', os='security', efa='no', job='r-abcdef')
        result = efactl.update_system_run(args)
        self.assertIn('wrapper failed its check', result['result'])
        self.assertEqual((len(alarms), backups), (1, []), 'an alarm, and nothing ran: no fall back to plain dnf')
        os.remove(self.dir + '/wrapper')
        self.program(self.dir + '/pre.d/10-veto', 'exit 1')
        result = efactl.update_system_run(args)
        self.assertIn('a pre hook said no', result['result'])
        self.assertEqual(backups, [], 'itw-safe-update can veto an update')


if __name__ == '__main__':
    unittest.main()
