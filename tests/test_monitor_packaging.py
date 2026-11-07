# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Tests for the service monitor and static checks of the package files."""

import os
import re
import unittest

from efa_testlib import TOP, RootTestCase, c

import efa_monitor

SETTINGS = 'SERVICES="postfix clamd@scan"\nMAX_RESTARTS=2\nCOUNTER_MINUTES=10\n'


class MonitorTests(RootTestCase):
    def setUp(self):
        super().setUp()
        self.write("etc/sysconfig/eFa-Monitor", SETTINGS)
        c.write_kv("/etc/eFa/eFa-Config", {"ADMINEMAIL": "admin@example.org"}, 0o640)

    def restarts(self):
        return [cmd[2] for cmd in self.runner.calls if cmd[:2] == ["systemctl", "restart"]]

    def mails(self):
        return [inp for cmd, inp in zip(self.runner.calls, self.runner.inputs)
                if cmd[0].endswith("sendmail")]

    def test_restart_limit_and_one_mail(self):
        self.runner.active.add("postfix")
        for minute in range(5):
            self.runner.active.discard("clamd@scan")  # stays down
            efa_monitor.check(now=1000 + 60 * minute)
        self.assertEqual(self.restarts(), ["clamd@scan", "clamd@scan"])
        self.assertEqual(len(self.mails()), 1)
        self.assertIn("To: admin@example.org", self.mails()[0])

    def test_counter_expires(self):
        self.runner.active.add("postfix")
        for now in (0, 60, 120):
            self.runner.active.discard("clamd@scan")
            efa_monitor.check(now=now)
        self.runner.active.discard("clamd@scan")
        efa_monitor.check(now=601)
        self.assertEqual(len(self.restarts()), 3)

    def test_enable_disable(self):
        efa_monitor.enable()
        self.assertIn("* * * * * root /usr/sbin/efa-monitor",
                      self.read("etc/cron.d/eFa-Monitor.cron"))
        efa_monitor.disable()
        self.assertFalse(os.path.exists(self.path("etc/cron.d/eFa-Monitor.cron")))

    def test_reboot_check(self):
        self.assertTrue(efa_monitor.reboot_check())
        self.assertTrue(os.path.exists(self.path("var/lib/eFa/reboot-due")))


class PackagingTests(unittest.TestCase):
    def files(self):
        skip = {"dist", "__pycache__"}
        for top in ("build", "rpm", "src", "tests"):
            for folder, dirs, names in os.walk(os.path.join(TOP, top)):
                dirs[:] = [d for d in dirs if d not in skip]
                for name in names:
                    if not name.endswith((".pyc",)):
                        yield os.path.join(folder, name)

    def test_spdx_headers_and_no_attribution(self):
        words = ["cla" + "ude", "anthr" + "opic"]  # split so this file passes too
        banned = re.compile(r"\b(%s)\b|generated (by|with) (an )?ai" % "|".join(words), re.I)
        for path in self.files():
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("SPDX-License-Identifier: AGPL-3.0-or-later", text[:300], path)
            self.assertIn("Copyright (C) 2026 Markus Lorber and eFa-next contributors", text[:400], path)
            self.assertIn("Author: Markus Lorber, Lukasz Galusinski", text[:400], path)
            self.assertIsNone(banned.search(text), path)

    def test_specs(self):
        for name in ("eFa-base", "eFa"):
            with open(os.path.join(TOP, "rpm", name + ".spec"), encoding="utf-8") as fh:
                spec = fh.read()
            self.assertIn("%global _buildhost localhost", spec)
            self.assertIn("/etc/MailScanner/MailScanner.conf", spec.split("%posttrans")[0])
            self.assertRegex(spec, r"Version:\s+6\.0\.0\.\d+")
            self.assertNotRegex(spec, r"Requires:\s*(httpd|php|perl)")
        # Both packages carry the same version, or the dependency eFa-base = %{version} breaks.
        versions = set()
        for name in ("eFa-base", "eFa"):
            with open(os.path.join(TOP, "rpm", name + ".spec"), encoding="utf-8") as fh:
                versions.add(re.search(r"Version:\s+(\S+)", fh.read()).group(1))
        self.assertEqual(len(versions), 1, versions)
        with open(os.path.join(TOP, "rpm", "eFa.spec"), encoding="utf-8") as fh:
            self.assertIn("Requires:       eFa-base = 1:%{version}-%{release}", fh.read())

    def test_mail_services_hardened(self):
        # A2: the services that parse untrusted mail carry the lockdown drop-in; the root orchestrators do not get it.
        units = os.path.join(TOP, "next/usr/lib/systemd/system")
        for name in ("efa-cdr", "efa-maillog", "efa-milter-health", "efa-outbound", "efa-sasl", "efa-portal"):
            path = os.path.join(units, name + ".service.d", "hardening.conf")
            self.assertTrue(os.path.exists(path), path)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            for directive in ("CapabilityBoundingSet=", "SystemCallFilter=@system-service", "RestrictAddressFamilies=", "NoNewPrivileges=yes"):
                self.assertIn(directive, text, name)
        for name in ("efactl-runner", "efa-portal-helper", "efa-init", "efa-cluster", "efa-autoupdate"):
            self.assertFalse(os.path.exists(os.path.join(units, name + ".service.d", "hardening.conf")), name)

    def test_no_firewall_reload_anywhere(self):
        for path in self.files():
            if "tests" in path.split(os.sep):
                continue
            with open(path, encoding="utf-8") as fh:
                self.assertNotIn("--reload", fh.read(), path)

    def test_logrotate_covers_all_files(self):
        with open(os.path.join(TOP, "src/eFa-base/root/etc/logrotate.d/eFa"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("/var/log/eFa/* {", text)
        self.assertIn("olddir /var/log/eFa-archive", text)
        for word in ("monthly", "rotate 4", "compress"):
            self.assertIn(word, text)


if __name__ == "__main__":
    unittest.main()
