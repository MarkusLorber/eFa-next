# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski

"""Hans 2026-11-20: the public GitHub commit carries only the allowlisted paths, never release or CI tooling, plans or
internal notes, and a kept file that names internal infrastructure stops the release (scripts/publish/public-tree.sh).
The script lives only on Forgejo: on GitHub this test is skipped."""

import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
SCRIPT = os.path.join(ROOT, 'scripts', 'publish', 'public-tree.sh')


@unittest.skipUnless(os.path.exists(SCRIPT) and shutil.which('git') and shutil.which('sh'), 'public-tree.sh is not in this tree')
class PublicTree(unittest.TestCase):
    def repo(self, files):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder, True)
        git = lambda *args: subprocess.run(['git', '-C', folder, *args], capture_output=True, text=True, check=True).stdout  # noqa: E731
        git('init', '-q')
        for path, text in files.items():
            os.makedirs(os.path.dirname(os.path.join(folder, path)) or folder, exist_ok=True)
            with open(os.path.join(folder, path), 'w') as f:
                f.write(text)
        git('add', '-A')
        git('-c', 'user.name=t', '-c', 'user.email=t@example.org', 'commit', '-q', '-m', 't')
        return folder, git

    def checks(self):
        # public-tree.sh runs name_check and legal_check of the commit against the public tree.
        found = {}
        for name in ('name_check', 'legal_check'):
            with open(os.path.join(ROOT, 'scripts', name + '.py'), encoding='utf-8') as f:
                found['scripts/' + name + '.py'] = f.read()
        return found

    def test_only_the_allowlist_goes_public(self):
        folder, git = self.repo({**self.checks(), 'next/a.py': 'x', 'README.md': 'r', 'README.de.md': 'd', 'LICENSE': 'l', 'docs/manual/a.md': 'm',
                                 'docs/plan-x.md': 'p', 'scripts/publish/x.sh': 'p', 'scripts/i18n_extract.py': 'i',
                                 '.forgejo/ci.yml': 'c', '.github/workflows/w.yml': 'w', '.github/FUNDING.yml': 'f', 'notes.txt': 'n'})
        done = subprocess.run(['sh', SCRIPT, folder, 'HEAD'], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        kept = git('ls-tree', '-r', '--name-only', done.stdout.strip()).split()
        self.assertEqual(sorted(kept), ['LICENSE', 'README.de.md', 'README.md', 'docs/manual/a.md', 'next/a.py', 'scripts/i18n_extract.py'])

    def test_internal_infrastructure_stops_it(self):
        # Generic examples only: the internal names themselves are known to name_check as salted hashes.
        # Put together here, so this file itself never matches the patterns of public-tree.sh.
        for text in ('sftp -P ' + '7777 host', 'HOST_' + 'FPR: x', 'SHA' + '256:' + 'A' * 43, 'cd domains/x/public' + '_html', 'install eF' + 'a now'):
            folder, _git = self.repo({**self.checks(), 'next/a.py': text})
            done = subprocess.run(['sh', SCRIPT, folder, 'HEAD'], capture_output=True, text=True)
            self.assertNotEqual(done.returncode, 0, text)
            self.assertIn('next/a.py', done.stderr, text)


if __name__ == '__main__':
    unittest.main()
