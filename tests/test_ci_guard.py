# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""scripts/ci_guard.py: the main.cf of before around a live step of the CI, put back by the next run when a step was stopped."""

import importlib.util
import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('ci_guard', os.path.join(HERE, '..', 'scripts', 'ci_guard.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class CiGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='efa-ci-guard-')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.main_cf, self.folder = self.tmp + '/main.cf', self.tmp + '/restore'
        self.write('clean\n')
        self.calls = []
        self.check_ok = True

    def write(self, text):
        with open(self.main_cf, 'w') as f:
            f.write(text)

    def read(self):
        with open(self.main_cf) as f:
            return f.read()

    def run_fake(self, cmd, **kwargs):
        self.calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0 if self.check_ok or cmd[1] != 'check' else 1, '', '')

    def test_a_step_that_ends_leaves_nothing(self):
        saved = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, saved)
        guard.begin('step', self.main_cf, self.folder)
        self.write('changed\n')
        self.write('clean\n')
        guard.end('step', self.folder)
        self.assertEqual(guard.restore(self.main_cf, self.folder, self.run_fake), [])
        self.assertEqual(self.calls, [])

    def test_a_stopped_step_is_put_back_by_the_next_run(self):
        saved = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, saved)
        guard.begin('first', self.main_cf, self.folder)
        self.write('first change\n')
        time.sleep(0.02)
        guard.begin('second', self.main_cf, self.folder)
        self.write('first and second change\n')
        done = guard.restore(self.main_cf, self.folder, self.run_fake)
        self.assertEqual(self.read(), 'clean\n', 'the oldest marker holds the main.cf of before all steps')
        self.assertEqual(done, ['main.cf of first put back', 'marker second.main.cf dropped'])
        self.assertEqual(self.calls, [['postfix', 'check'], ['postfix', 'reload']])
        self.assertEqual(os.listdir(self.folder), [])

    def test_a_failed_check_keeps_main_cf_and_the_markers(self):
        saved = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, saved)
        guard.begin('step', self.main_cf, self.folder)
        self.write('changed\n')
        self.check_ok = False
        with self.assertRaisesRegex(SystemExit, 'did not pass postfix check'):
            guard.restore(self.main_cf, self.folder, self.run_fake)
        self.assertEqual(self.read(), 'changed\n')
        self.assertEqual(os.listdir(self.folder), ['step.main.cf'])
        self.assertNotIn(['postfix', 'reload'], self.calls)

    @unittest.skipUnless(hasattr(signal, 'SIGTERM') and os.name == 'posix', 'signals of a Unix host')
    def test_sigterm_runs_the_finally_of_a_step(self):
        script = (f"import importlib.util, os, signal\n"
                  f"spec = importlib.util.spec_from_file_location('g', {os.path.join(HERE, '..', 'scripts', 'ci_guard.py')!r})\n"
                  f"g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)\n"
                  f"g.begin('step', {self.main_cf!r}, {self.folder!r})\n"
                  f"try:\n    os.kill(os.getpid(), signal.SIGTERM)\nfinally:\n    open({self.tmp + '/finally'!r}, 'w').close()\n"
                  f"    g.end('step', {self.folder!r})\n")
        done = subprocess.run(['python3', '-I', '-c', script], capture_output=True, text=True)
        self.assertEqual(done.returncode, 143, done.stderr)
        self.assertTrue(os.path.exists(self.tmp + '/finally'))
        self.assertEqual(os.listdir(self.folder), [])


if __name__ == '__main__':
    unittest.main()
