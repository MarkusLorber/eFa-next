# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""A Wazuh agent that eFa-next did not install (the agent of the operator, with its own manager): the take-over reads its
ossec.conf and changes nothing, neither the file nor the running agent; giving it back removes only what eFa-next wrote; a
later setting through eFa-next keeps what the agent had. The upgrade, the migration and the release upgrade take it over
the same way. The hint names the exact command, and that command works."""
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(TOP, 'src', 'eFa-base', 'root', 'usr', 'lib', 'eFa', 'python'))
sys.path.insert(0, os.path.join(TOP, 'next', 'usr', 'lib', 'eFa', 'python'))

# The agent of an operator: its own manager, enrollment with name and groups, active response on, a block of its own.
FOREIGN = """<ossec_config>
  <client>
    <server>
      <address>wazuh.operator.example</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <enrollment>
      <enabled>yes</enabled>
      <agent_name>mx-02</agent_name>
      <groups>mail,linux</groups>
      <authorization_pass_path>etc/authd.pass</authorization_pass_path>
    </enrollment>
  </client>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/operator.log</location>
  </localfile>
</ossec_config>
"""
AGENT_PROGRAMS = ('systemctl', 'wazuh-control', 'agent-auth', 'service')


def load_efactl():
    for name in ('grp', 'pwd', 'fcntl', 'syslog', 'termios', 'resource'):
        sys.modules.setdefault(name, __import__(name) if importlib.util.find_spec(name) else types.ModuleType(name))
    loader = importlib.machinery.SourceFileLoader('efactl_wazuh', os.path.join(TOP, 'next', 'usr', 'sbin', 'efactl'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_wazuh', loader))
    loader.exec_module(module)
    return module


class Agent(unittest.TestCase):
    active = True

    def setUp(self):
        self.efactl = load_efactl()
        self.tmp = tempfile.mkdtemp(prefix='efa-wazuh-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.conf = self.tmp + '/ossec.conf'
        with open(self.conf, 'w') as f:
            f.write(FOREIGN)
        self.calls = []

        def run(cmd, *args, **kwargs):
            self.calls.append(list(cmd))
            if cmd[0] == 'rpm':
                return subprocess.CompletedProcess(cmd, 0, '4.14.7-1', '')
            if cmd[:2] == ['systemctl', 'is-active']:
                return subprocess.CompletedProcess(cmd, 0 if self.active else 3, '', '')
            return subprocess.CompletedProcess(cmd, 0, '', '')
        fake = types.SimpleNamespace(**{name: getattr(subprocess, name) for name in dir(subprocess) if not name.startswith('_')})
        fake.run = run
        # The test file counts as the real ossec.conf, so the decisions about the agent run as on a host (owner change aside).
        for patch in (mock.patch.object(self.efactl, 'subprocess', fake), mock.patch.object(self.efactl, 'WAZUH_CONF', self.conf),
                      mock.patch.object(self.efactl, 'WAZUH_REAL_CONF', self.conf), mock.patch.object(self.efactl.shutil, 'chown', lambda *a, **k: None),
                      mock.patch.object(self.efactl, 'WAZUH_FILE', self.tmp + '/wazuh.json'),
                      mock.patch.object(self.efactl, 'WAZUH_AUTHD_PASS', self.tmp + '/authd.pass'),
                      mock.patch.object(self.efactl, 'EVENTS_MARKER', self.tmp + '/events-on'),
                      mock.patch.object(self.efactl, '_audit', lambda text: None)):
            patch.start()
            self.addCleanup(patch.stop)

    def cli(self, line, stdin=''):
        """The words as the console gives them to efactl, through its own parser."""
        words = line.split()[1:]
        args = self.efactl.build_parser(words).parse_args(words)
        with mock.patch.object(sys, 'stdin', io.StringIO(stdin)):
            return args.func(args)

    def agent_calls(self):
        return [call for call in self.calls if call[0] in AGENT_PROGRAMS and call[:2] != ['systemctl', 'is-active']]

    def state(self):
        with open(self.tmp + '/wazuh.json') as f:
            return json.load(f)

    def text(self):
        with open(self.conf) as f:
            return f.read()

    def hinted_command(self):
        with self.assertRaises(self.efactl.EfaError) as caught:
            self.efactl._wazuh_guard()
        found = re.search(r'efactl wazuh-config [^(]*?--confirm yes', str(caught.exception))
        self.assertTrue(found, str(caught.exception))
        return found.group(0)

    def test_hint_names_the_command_and_it_takes_over_without_a_change(self):
        command = self.hinted_command()
        self.assertEqual(command, 'efactl wazuh-config --adopt yes --confirm yes')
        answer = self.cli(command)
        self.assertEqual(answer['wazuh'], 'taken over')
        self.assertEqual(list(answer)[0], 'manager', 'the manager address first')
        self.assertEqual(answer['manager'], 'wazuh.operator.example')
        self.assertEqual(self.text(), FOREIGN, 'ossec.conf byte for byte')
        self.assertEqual(self.agent_calls(), [], 'the agent is neither started, stopped, restarted nor enrolled')
        state = self.state()
        self.assertEqual((state['managed'], state['adopted'], state['agent_name'], state['groups'], state['active_response']),
                         (True, True, 'mx-02', 'mail,linux', True))
        self.assertTrue(answer['backup'].startswith(self.conf + '.efa-'))
        with open(answer['backup']) as f:
            self.assertEqual(f.read(), FOREIGN)

    def test_without_confirmation_nothing(self):
        with self.assertRaises(self.efactl.EfaError) as caught:
            self.cli('efactl wazuh-config --adopt yes')
        self.assertEqual(str(caught.exception), 'Add --confirm yes to confirm.')
        self.assertFalse(os.path.exists(self.tmp + '/wazuh.json'))
        with mock.patch.dict(os.environ, {'SUDO_USER': 'efa-web'}), self.assertRaises(self.efactl.EfaError) as caught:
            self.cli('efactl wazuh-config --adopt yes')
        self.assertEqual(str(caught.exception), "Type 'yes' to confirm.", 'the web interface has a field for it')

    def test_give_back_round_trip(self):
        self.cli('efactl wazuh-config --adopt yes --confirm yes')
        self.cli('efactl wazuh-config --events on', stdin='\n\n')
        self.assertIn(self.efactl.WAZUH_BEGIN, self.text())
        answer = self.cli('efactl wazuh-config --adopt no --confirm yes')
        self.assertEqual((answer['wazuh'], answer['efa_block_removed']), ('given back', True))
        self.assertEqual(self.text(), FOREIGN, 'only the block of eFa-next goes')
        self.assertFalse(self.state()['managed'])
        self.assertTrue(self.efactl.wazuh_foreign('4.14.7-1', self.state()))
        self.assertEqual([call for call in self.agent_calls() if call[1:2] != ['restart']], [], 'give back touches no agent')

    def test_a_later_setting_keeps_the_values_of_the_agent(self):
        self.cli('efactl wazuh-config --adopt yes --confirm yes')
        self.calls.clear()
        self.cli('efactl wazuh-config --events on', stdin='\n\n')
        text = self.text()
        for kept in ('<address>wazuh.operator.example</address>', '<agent_name>mx-02</agent_name>', '<groups>mail,linux</groups>',
                     '<authorization_pass_path>etc/authd.pass</authorization_pass_path>', '<location>/var/log/operator.log</location>'):
            self.assertIn(kept, text)
        self.assertNotIn('<disabled>yes</disabled>', text, 'its active response stays on unless the admin turns it off')
        self.assertTrue(any(name.startswith('ossec.conf.efa-') for name in os.listdir(self.tmp)), 'a copy before the write')
        restarts = [call for call in self.agent_calls()]
        self.assertEqual(restarts, [['systemctl', 'restart', 'wazuh-agent']] if self.active else [], 'never switched on, restarted only if it runs')
        self.cli('efactl wazuh-config --active_response off', stdin='\n\n')
        self.assertIn('<disabled>yes</disabled>', self.text(), 'off when the admin sets it off')

    def test_ctrl_c_at_the_password_prompt(self):
        """Ctrl+C at the prompt of a setting: aborted with 130, no traceback, nothing written."""
        self.cli('efactl wazuh-config --adopt yes --confirm yes')
        before = (self.text(), self.state())
        words = ['wazuh-config', '--events', 'on']
        args = self.efactl.build_parser(words).parse_args(words)
        tty = types.SimpleNamespace(isatty=lambda: True, readline=lambda *a: '')
        with mock.patch.object(sys, 'stdin', tty), mock.patch.object(self.efactl.getpass, 'getpass', side_effect=KeyboardInterrupt), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as out, self.assertRaises(SystemExit) as caught:
            args.func(args)
        self.assertEqual(caught.exception.code, 130)
        self.assertEqual(json.loads(out.getvalue()), {'error': 'aborted, nothing changed'})
        self.assertEqual((self.text(), self.state()), before)

    def test_unreadable_config_is_reported_not_taken_over(self):
        with open(self.conf, 'w') as f:
            f.write('<ossec_config>\n</ossec_config>\n')
        answer = self.efactl.wazuh_take_over()
        self.assertEqual(answer['wazuh'], 'not taken over')
        self.assertIn('stays as it is', answer['report'])
        self.assertFalse(os.path.exists(self.tmp + '/wazuh.json'))
        self.assertEqual(self.agent_calls(), [])

    def test_take_over_once(self):
        first = self.efactl.wazuh_take_over()
        self.assertIn('Wazuh agent taken over: manager wazuh.operator.example, groups mail,linux, active response on; config unchanged', first['report'])
        self.assertEqual(self.efactl.wazuh_take_over()['wazuh'], 'already managed by eFa-next')
        self.assertEqual(self.text(), FOREIGN)
        self.assertEqual(self.agent_calls(), [])


class InactiveAgent(Agent):
    """The agent of a clone, off and disabled: it stays off."""
    active = False


class Paths(unittest.TestCase):
    def test_upgrade_step(self):
        import efa_configure
        self.assertIn('wazuh-take-over', efa_configure.plan('eFa', 'upgrade')[1])
        self.assertNotIn('wazuh-take-over', efa_configure.plan('eFa', 'first-install')[1])
        said, ran, files = [], [], {}
        report = {'report': 'Wazuh agent taken over: manager m.example, groups none, active response on; config unchanged'}

        def step(answer):
            # The path of efactl comes from the platform (EL9/EL10); off EL the test names it, the step itself stays as it is.
            with mock.patch.object(efa_configure, 'P', lambda name: '/usr/sbin'),                     mock.patch.object(efa_configure.c, 'run', lambda cmd, check=True: ran.append(cmd) or answer), \
                    mock.patch.object(efa_configure.c, 'read_text', lambda path, default=None: files.get(path, default)), \
                    mock.patch.object(efa_configure.c, 'info', said.append):
                efa_configure.step_wazuh_take_over()
        # No agent: nothing is called.
        step(None)
        self.assertEqual((ran, said), ([], []))
        # An agent eFa-next does not manage: efactl takes it over and the report goes to the log of the upgrade.
        files[efa_configure.WAZUH_OSSEC] = FOREIGN
        step(subprocess.CompletedProcess([], 0, json.dumps(report), ''))
        self.assertEqual(ran[-1][1:], ['wazuh-take-over'])
        self.assertEqual(said, [report['report']])
        # Whatever efactl answers, the upgrade goes on.
        step(subprocess.CompletedProcess([], 1, 'not json', 'boom'))
        self.assertIn('gave no answer', said[-1])
        # Managed already: nothing is called.
        files[efa_configure.WAZUH_SETTINGS] = '{"managed": true}'
        ran.clear()
        step(None)
        self.assertEqual(ran, [])

    def test_migration_takes_over_and_reports(self):
        with open(os.path.join(TOP, 'migration', 'efa-migrate'), encoding='utf-8') as f:
            source = f.read()
        body = source[source.index('def restore_settings('):source.index('\ndef ', source.index('def restore_settings(') + 10)]
        self.assertIn("'wazuh-take-over'", body)
        self.assertIn('warnings.append(report)', body)
        self.assertLess(body.index("'wazuh-take-over'"), body.index('settings_steps(plan, target'))

    def test_release_upgrade_compares_the_agent(self):
        import efa_release_upgrade
        self.assertIn('/var/ossec/etc/ossec.conf', efa_release_upgrade.CONFIG_DIRS)
        self.assertIn('/etc/eFa/wazuh.json', efa_release_upgrade.CONFIG_DIRS)


if __name__ == '__main__':
    unittest.main()
