# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Tests for efa_common, the service steps and the package hooks."""

import unittest

from efa_testlib import RootTestCase, c

import efa_configure
import efa_services as s


class CommonTests(RootTestCase):
    def test_kv_roundtrip_and_mode(self):
        c.write_kv("/etc/eFa/eFa-Config", {"HOSTNAME": "mx", "ADMINEMAIL": "a@b.example"}, 0o640)
        self.assertEqual(self.read("etc/eFa/eFa-Config"), "HOSTNAME:mx\nADMINEMAIL:a@b.example\n")
        self.assertEqual(self.mode("etc/eFa/eFa-Config"), 0o640)
        self.assertEqual(c.read_kv("/etc/eFa/eFa-Config")["HOSTNAME"], "mx")

    def test_kv_rejects_line_breaks(self):
        with self.assertRaises(c.StepError):
            c.write_kv("/etc/eFa/x", {"A": "1\nB:2"}, 0o600)

    def test_write_file_reports_change(self):
        self.assertTrue(c.write_file("/etc/x.conf", "a\n"))
        self.assertFalse(c.write_file("/etc/x.conf", "a\n"))

    def test_set_directives(self):
        text = c.set_directives("Example\nFoo 1\nFoo 2\n#Bar 3\nTCPSocket 1\n",
                                {"Foo": "9", "Bar": "4"}, disable=("Example", "TCPSocket"))
        self.assertEqual(text, "#Example\nFoo 9\n#Bar 3\n#TCPSocket 1\nBar 4\n")

    def test_set_ini(self):
        text = c.set_ini("[a]\nx = 1\n[b]\ny = 2\n", "a", {"x": "5", "z": "6"})
        self.assertEqual(text, "[a]\nx = 5\nz = 6\n[b]\ny = 2\n")

    def test_validation(self):
        self.assertTrue(c.valid_domain("example.com"))
        self.assertFalse(c.valid_domain("bad_domain.com"))
        self.assertEqual(c.netmask_prefix("255.255.255.0"), 24)
        self.assertEqual(c.netmask_prefix("64", 6), 64)
        self.assertFalse(c.valid_email("a@b.example\nBcc:x"))


class StepTests(RootTestCase):
    def run_all(self):
        return c.run_steps(s.INSTALL_STEPS, s.INSTALL_ORDER)

    def test_all_steps_pass_and_are_idempotent(self):
        self.assertEqual(self.run_all(), [])
        first = self.snapshot()
        calls = len(self.runner.calls)
        self.assertEqual(self.run_all(), [])
        self.assertEqual(self.snapshot(), first)
        second = self.runner.calls[calls:]
        self.assertFalse([cmd for cmd in second if cmd[:2] == ["postconf", "-e"]])
        self.assertFalse([cmd for cmd in second
                          if any(a.startswith("--add-service=") for a in cmd)])

    def test_postfix_parameters(self):
        s.step_postfix()
        pf = self.runner.explicit
        self.assertEqual(pf["smtpd_milters"], "inet:127.0.0.1:11332, inet:127.0.0.1:8999")
        self.assertEqual(pf["milter_default_action"], "accept")
        self.assertEqual(pf["mynetworks"], "127.0.0.0/8 [::1]/128")
        self.assertEqual(pf["transport_maps"], "hash:/etc/postfix/transport")
        self.assertEqual(pf["disable_vrfy_command"], "yes")
        self.assertEqual(pf["unverified_recipient_reject_code"], "550")
        self.assertEqual(pf["mydestination"], "")
        for name in ("header_checks", "milter_header_checks", "helo_access",
                     "recipient_canonical", "transport"):
            self.assertEqual(self.read("etc/postfix/" + name), "")
        self.assertEqual(self.runner.master_params["submission/inet/smtpd_sasl_auth_enable"], "yes")

    def test_postfix_keeps_efactl_values(self):
        self.runner.explicit["mynetworks"] = "10.0.0.0/8"
        self.runner.explicit["message_size_limit"] = "1000"
        s.step_postfix()
        self.assertEqual(self.runner.explicit["mynetworks"], "10.0.0.0/8")
        self.assertEqual(self.runner.explicit["message_size_limit"], "1000")

    def test_clamav(self):
        self.runner.users.add("_rspamd")
        s.step_clamav()
        text = self.read("etc/clamd.d/scan.conf")
        self.assertIn("#Example", text)
        self.assertIn("#TCPSocket 3310", text)
        self.assertIn("LocalSocket /run/clamd.scan/clamd.sock", text)
        self.assertIn(["usermod", "-a", "-G", "virusgroup", "_rspamd"], self.runner.calls)

    def test_firewall_never_reloads(self):
        self.runner.active.add("firewalld")
        self.run_all()
        s.step_firewall()
        for cmd in self.runner.calls:
            self.assertNotIn("--reload", cmd)
            self.assertNotIn("--complete-reload", cmd)
        added = [cmd for cmd in self.runner.calls if cmd[0] == "firewall-cmd"
                 and any(a.startswith("--add-service=") for a in cmd)]
        self.assertTrue(any("--permanent" in cmd for cmd in added))
        self.assertTrue(any("--permanent" not in cmd for cmd in added))

    def test_unbound_and_fail2ban(self):
        s.step_unbound()
        s.step_fail2ban()
        conf = self.read("etc/unbound/unbound.conf")
        self.assertIn('include: "/etc/unbound/conf.d/*.conf"', conf)
        self.assertIn("interface: 127.0.0.1", conf)
        self.assertIn("After=network-online.target",
                      self.read("etc/systemd/system/unbound.service.d/efa-network.conf"))
        jails = self.read("etc/fail2ban/jail.d/efa.local")
        self.assertIn("[sshd]", jails)
        self.assertIn("[postfix-sasl]", jails)

    def test_failed_step_is_reported(self):
        self.runner.fail.add("postconf")
        self.assertIn("postfix", self.run_all())


class HookTests(RootTestCase):
    def test_first_install_writes_version(self):
        self.write("usr/sbin/efa-apply", "")
        self.assertEqual(efa_configure.package_hook("eFa-base", "first-install", "6.0.0.3"), 0)
        self.assertFalse(c.read_text("/etc/eFa-Version", ""))  # eFa not done yet
        self.assertEqual(efa_configure.package_hook("eFa", "first-install", "6.0.0.3"), 0)
        self.assertEqual(self.read("etc/eFa-Version"), "eFa-6.0.0.3\n")
        self.assertEqual(self.mode("etc/sudoers.d/efa-init"), 0o440)
        self.assertIn(["systemctl", "enable", "--quiet", "--now", "efa-reboot-check.timer"],
                      self.runner.calls)

    def test_failed_install_writes_no_version(self):
        self.runner.fail.add("postconf")
        self.assertEqual(efa_configure.package_hook("eFa-base", "first-install", "6.0.0.3"), 1)
        self.assertEqual(c.read_text("/etc/eFa-Version", ""), "")

    def test_upgrade_changes_no_settings(self):
        self.runner.active.update({"efa-web.service", "efa-init.service"})
        self.assertEqual(efa_configure.package_hook("eFa-base", "upgrade", "6.0.0.3"), 0)
        self.assertFalse([cmd for cmd in self.runner.calls if cmd[0] == "postconf"])
        restarted = [cmd[-1] for cmd in self.runner.calls if cmd[:2] == ["systemctl", "try-restart"]]
        self.assertEqual(restarted, ["efa-web.service"])

    def test_no_wizard_access_when_configured(self):
        c.write_kv("/etc/eFa/eFa-Config", {"CONFIGURED": "YES"}, 0o640)
        efa_configure.package_hook("eFa", "first-install", "6.0.0.3")
        self.assertEqual(c.read_text("/etc/sudoers.d/efa-init", ""), "")


if __name__ == "__main__":
    unittest.main()
