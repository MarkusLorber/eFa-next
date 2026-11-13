# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The restore of the fresh test (scripts/ci.sh fresh_restore): a timer job that the restore stopped with TERM is no failure
of the host. Its failed state is reset for the service of every efa-* timer, before the restore starts them again."""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CI = os.path.join(TOP, 'scripts', 'ci.sh')


def restore_body():
    text = open(CI, encoding='utf-8').read()
    return text[text.index('fresh_restore() {'):text.index('\n}\n', text.index('fresh_restore() {'))]


class RestoreResetsTimerJobs(unittest.TestCase):
    def test_order(self):
        body = restore_body()
        loop = body.index("list-unit-files --no-legend --plain 'efa-*.timer'")
        self.assertLess(loop, body.index('    sc start $('), 'reset before the start, so a new failure still shows')
        self.assertLess(body.index('    sc start $('), body.index('efactl status'))

    @unittest.skipUnless(os.name == 'posix' and shutil.which('sh'), 'needs sh on a Unix host')
    def test_every_timer_service(self):
        loop = re.search(r"\n    for timer in .*?\n    done\n", restore_body(), flags=re.S).group(0)
        with tempfile.TemporaryDirectory() as tmp:
            calls = os.path.join(tmp, 'calls')
            fake = os.path.join(tmp, 'systemctl')
            with open(fake, 'w') as f:
                f.write('#!/bin/sh\n'
                        'if [ "$1" = list-unit-files ]; then printf "efa-firewall-guard.timer enabled\\nefa-os-check.timer enabled\\n"; exit 0; fi\n'
                        f'echo "$@" >> {calls}\n')
            os.chmod(fake, 0o755)
            done = subprocess.run(['sh', '-c', loop], env={**os.environ, 'PATH': tmp + os.pathsep + os.environ['PATH']},
                                  capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            with open(calls) as f:
                self.assertEqual(f.read().splitlines(), ['reset-failed efa-firewall-guard.service', 'reset-failed efa-os-check.service'])


if __name__ == '__main__':
    unittest.main()
