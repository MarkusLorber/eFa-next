# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The SELinux module of eFa-next: every type it uses is required, and module_request (the kernel loading a module, here
IPv6 on hosts without it) is never allowed, only hidden from the log for the domains a test showed doing it."""
import os
import re
import unittest

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TE = os.path.join(TOP, 'src', 'eFa-base', 'selinux', 'efa.te')
# freshclam (antivirus_t) on each update, fail2ban (fail2ban_t) at boot, both on hosts without IPv6.
QUIET_MODULE_REQUEST = {'antivirus_t', 'fail2ban_t'}


class SelinuxPolicyTests(unittest.TestCase):
    def setUp(self):
        with open(TE, encoding='utf-8') as f:
            self.text = re.sub(r'#.*', '', f.read())
        self.required = set(re.findall(r'\btype\s+(\w+)\s*;', self.text.split('require', 1)[1].split('}', 1)[0]))
        self.rules = re.findall(r'^\s*(allow|dontaudit)\s+(\w+)\s+(\w+):(\w+)\s+([\w{} ]+);', self.text, flags=re.M)

    def test_version(self):
        self.assertRegex(self.text, r'module efa \d+\.\d+\.\d+;')

    def test_types_required(self):
        for _kind, source, target, _cls, _perm in self.rules:
            self.assertIn(source, self.required, source)
            self.assertIn(target, self.required, target)

    def test_nginx_pid_gets_the_type_of_nginx(self):
        """NGINX-PID: nginx -t of efactl or of an admin creates /run/nginx.pid; it must get httpd_var_run_t, not var_run_t."""
        found = set(re.findall(r'^\s*type_transition\s+(\w+)\s+var_run_t:file\s+httpd_var_run_t\s+"nginx\.pid"\s*;', self.text, flags=re.M))
        self.assertEqual(found, {'unconfined_service_t', 'unconfined_t'})
        for name in ('unconfined_service_t', 'unconfined_t', 'var_run_t', 'httpd_var_run_t'):
            self.assertIn(name, self.required, name)

    def test_module_request_only_quiet(self):
        quiet = {source for kind, source, _t, cls, perm in self.rules if cls == 'system' and 'module_request' in perm and kind == 'dontaudit'}
        allowed = [source for kind, source, _t, cls, perm in self.rules if cls == 'system' and 'module_request' in perm and kind == 'allow']
        self.assertEqual(allowed, [], 'module_request is never allowed')
        self.assertEqual(quiet, QUIET_MODULE_REQUEST)


if __name__ == '__main__':
    unittest.main()
