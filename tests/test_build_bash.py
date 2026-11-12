# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""build/build.bash on EL9 and EL10: which releases and distributions it takes (check_os, with an os-release fixture), the
repositories it picks per major version, and that these are the ones the platform layer names (one source of truth)."""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
BUILD = os.path.join(ROOT, 'build', 'build.bash')
sys.path.insert(0, os.path.join(ROOT, 'src', 'eFa-base', 'root', 'usr', 'lib', 'eFa', 'python'))


def head_and(function):
    """The variables at the top of build.bash (up to the work folder) and one of its functions, as a script of its own."""
    with open(BUILD, encoding='utf-8') as f:
        text = f.read()
    head = text[text.index('ACTION='):text.index('WORK_DIR=""')]
    body = re.search(r'^%s\(\) \{.*?^\}' % function, text, re.M | re.S).group(0)
    return head + '\n' + body + '\n'


@unittest.skipUnless(shutil.which('bash'), 'needs bash')
class CheckOs(unittest.TestCase):
    def run_check(self, os_id, version):
        with tempfile.TemporaryDirectory() as tmp:
            release = os.path.join(tmp, 'os-release')
            with open(release, 'w', newline='\n') as f:
                f.write(f'NAME="test"\nID="{os_id}"\nVERSION_ID="{version}"\n')
            # SELinux as on an installed host: getenforce says Enforcing.
            fake = os.path.join(tmp, 'getenforce')
            with open(fake, 'w', newline='\n') as f:
                f.write('#!/bin/sh\necho Enforcing\n')
            os.chmod(fake, 0o755)
            script = head_and('check_os') + 'check_os && echo "major=$EL_MAJOR repo=$REPO_URL rspamd=$RSPAMD_REPO_URL release=$RELEASE_URL"\n'
            env = dict(os.environ, EFA_OS_RELEASE=release.replace('\\', '/'), PATH=tmp + os.pathsep + os.environ.get('PATH', ''))
            done = subprocess.run(['bash', '-c', script], capture_output=True, text=True, env=env)
            return done.returncode, done.stdout.strip()

    def test_matrix(self):
        for os_id, version in (('almalinux', '9.8'), ('rocky', '9.6'), ('rhel', '9.6'), ('centos', '9'), ('almalinux', '10.2')):
            code, out = self.run_check(os_id, version)
            self.assertEqual(code, 0, (os_id, version, out))
        for os_id, version, reason in (('almalinux', '8.10', 'unsupported version'), ('almalinux', '11.0', 'unsupported version'),
                                       ('rhel', '10.1', 'RHEL 10: not tested yet'), ('rocky', '10.0', 'rocky 10: not supported'),
                                       ('centos', '10', 'centos 10: not supported'), ('debian', '12', 'unsupported OS')):
            code, out = self.run_check(os_id, version)
            self.assertNotEqual(code, 0, (os_id, version))
            self.assertIn(reason, out, (os_id, version))

    def test_repositories_per_release(self):
        _code, el9 = self.run_check('almalinux', '9.8')
        self.assertIn('repo=https://repo.efa-next.eu/el9/latest', el9)
        self.assertIn('rspamd=https://rspamd.com/rpm-stable/centos-9/', el9)
        self.assertIn('release=https://github.com/', el9)
        _code, el10 = self.run_check('almalinux', '10.2')
        self.assertIn('repo=https://repo.efa-next.eu/el10/latest', el10)
        self.assertIn('rspamd=https://rspamd.com/rpm-stable/centos-10/', el10)
        # The GitHub releases carry EL9 packages only.
        self.assertTrue(el10.endswith('release='), el10)


class SameAsThePlatform(unittest.TestCase):
    def test_rspamd_repository(self):
        with open(BUILD, encoding='utf-8') as f:
            text = f.read()
        template = re.search(r'^RSPAMD_REPO_URL="(.*)"$', text, re.M).group(1)
        try:
            import efa_platform_el10
            import efa_platform_el9
        except ImportError as err:  # efa_common needs pwd/grp: a Unix host
            self.skipTest(str(err))
        for platform, major in ((efa_platform_el9.EL9, '9'), (efa_platform_el10.EL10, '10')):
            base = platform.REPOSITORIES['rspamd'].rsplit('/', 1)[0] + '/'
            self.assertTrue(template.replace('$EL_MAJOR', major).startswith(base), (platform.name, base, template))


if __name__ == '__main__':
    unittest.main()
