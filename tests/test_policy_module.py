# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""NGINX-PID: when the SELinux module of eFa-next is loaded anew (install, update, the first EL10 boot of the release upgrade),
a pid file of nginx made before the rule gets the type of nginx again (restorecon -F), before nginx starts again.
What the policy holds decides whether the module is loaded, never the stamp alone: a downgrade, a restore with an old stamp
or a semodule -r leave a stamp that no longer says what is loaded."""
import bz2
import hashlib
import subprocess
import unittest

from efa_testlib import RootTestCase, c

POLICY = "usr/share/selinux/packages/eFa/efa.pp"
STORE = "var/lib/selinux/targeted/active/modules/400/efa/hll"
STAMP = "var/lib/eFa/selinux-efa.sha256"


class PolicyModule(RootTestCase):
    def test_new_module_relabels_the_pid_file_of_nginx(self):
        self.write(POLICY, "module 1.4.0")
        self.write("run/nginx.pid", "")
        self.assertTrue(c.platform().apply_policy_module("/" + POLICY))
        self.assertIn(["semodule", "-i", self.path(POLICY)], self.runner.calls)
        self.assertIn(["restorecon", "-F", self.path("run/nginx.pid")], self.runner.calls)

    def test_no_pid_file_no_restorecon_and_a_loaded_module_stays(self):
        self.write(POLICY, "module 1.4.0")
        self.assertTrue(c.platform().apply_policy_module("/" + POLICY))
        self.assertFalse([call for call in self.runner.calls if call[0] == "restorecon"])
        self.runner.calls.clear()
        self.runner_semodule_lists_efa()
        self.write(STORE, "module 1.4.0")
        self.assertFalse(c.platform().apply_policy_module("/" + POLICY), "the same module is not loaded twice")
        self.assertNotIn(["semodule", "-i", self.path(POLICY)], self.runner.calls)

    def test_a_stale_stamp_never_hides_another_loaded_module(self):
        # The stamp of 1.4.0 (a restore brought it back), the policy holds the module of an older release.
        self.write(POLICY, "module 1.4.0")
        self.write(STAMP, hashlib.sha256(b"module 1.4.0").hexdigest() + "\n")
        self.write(STORE, "module 1.3.2")
        self.runner_semodule_lists_efa()
        self.assertTrue(c.platform().apply_policy_module("/" + POLICY))
        self.assertIn(["semodule", "-i", self.path(POLICY)], self.runner.calls)

    def test_a_removed_module_is_loaded_again_whatever_the_stamp_says(self):
        self.write(POLICY, "module 1.4.0")
        self.write(STAMP, hashlib.sha256(b"module 1.4.0").hexdigest() + "\n")
        self.assertTrue(c.platform().apply_policy_module("/" + POLICY), "semodule -r efa: not listed, loaded again")

    def test_a_packed_store_counts_and_the_stamp_is_written(self):
        self.write(POLICY, "module 1.4.0")
        self.runner_semodule_lists_efa()
        path = self.path(STORE)
        import os
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(bz2.compress(b"module 1.4.0"))
        self.assertFalse(c.platform().apply_policy_module("/" + POLICY))
        with open(self.path(STAMP)) as fh:
            self.assertEqual(fh.read().strip(), hashlib.sha256(b"module 1.4.0").hexdigest())

    def runner_semodule_lists_efa(self):
        original = self.runner._semodule
        self.runner._semodule = lambda cmd, inp: original(cmd, inp) if cmd[1] != "-l" else subprocess.CompletedProcess(cmd, 0, "efa\n", "")


if __name__ == "__main__":
    unittest.main()
