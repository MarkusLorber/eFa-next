# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Tests for efa-apply (first-run settings) and efa-firstboot."""

import io
import os
import unittest
from unittest import mock

from efa_testlib import RootTestCase, c

import efa_apply
import efa_firstboot

SECRETS = {"ROOTPASSWORD": "Root-Secret-4711",
           "CLIPASSWORD": "Cli-Secret-0815",
           "WEBADMINPASSWORD": "Web-Secret-1234"}
ANSWERS = {
    "HOSTNAME": "mx1", "DOMAINNAME": "example.org", "ADMINEMAIL": "admin@example.org",
    "ORGNAME": "Example Org", "MAILSERVER": "10.0.0.25", "INTERFACE": "eth0",
    "IPV4ADDRESS": "192.0.2.10", "IPV4NETMASK": "255.255.255.0",
    "IPV4GATEWAY": "192.0.2.1", "IPV6ADDRESS": "auto", "RECURSION": "NO",
    "DNSIP1": "192.0.2.53", "DNSIP2": "", "IPV6DNS": "no", "TZONE": "Europe/Berlin",
    "ISUTC": "yes", "CLIUSERNAME": "efaadmin", "VMTOOLS": "YES",
}


def answer_text(extra=None):
    data = dict(ANSWERS, **SECRETS)
    data.update(extra or {})
    return "".join("%s:%s\n" % kv for kv in data.items())


class ApplyTests(RootTestCase):
    def setUp(self):
        super().setUp()
        self.runner.groups["efa-web"] = []

    def apply(self, argv, text=None):
        stdin = io.StringIO(text if text is not None else answer_text())
        out = io.StringIO()
        with mock.patch("sys.stdin", stdin), mock.patch("sys.stdout", out):
            code = efa_apply.main(argv, stdin_is_tty=False)
        return code, out.getvalue()

    def test_mail_server_dns_zone(self):
        code, out = self.apply(["--transport"], answer_text() + "MAILSERVER:mail.corp.example\nMAILSERVERDNS:10.0.0.53\n")
        self.assertEqual(code, 0, out + self.all_logs())
        self.assertIn(["efactl", "dns-zone-set", "--zone", "corp.example", "--action", "add", "--servers", "10.0.0.53"],
                      self.runner.calls)
        self.assertIn("[mail.corp.example]", self.read("etc/postfix/transport"))

    def test_all_steps(self):
        code, out = self.apply(["--all"])
        self.assertEqual(code, 0, out + self.all_logs())
        cfg = c.read_kv("/etc/eFa/eFa-Config")
        self.assertEqual(cfg["CONFIGURED"], "YES")
        self.assertEqual(cfg["HOSTNAME"], "mx1")
        self.assertEqual(cfg["ISUTC"], "YES")
        self.assertEqual(self.mode("etc/eFa/eFa-Config"), 0o640)
        self.assertEqual(self.mode("etc/eFa/MySQL-Config"), 0o600)
        self.assertRegex(self.read("etc/eFa/MySQL-Config"), r"^MYSQLROOTPWD:[A-Za-z0-9]{32}\n$")
        self.assertRegex(self.read("etc/efa-web/admin.pw"), r"^pbkdf2_sha256\$600000\$")
        self.assertEqual(self.mode("etc/efa-web/admin.pw"), 0o640)
        self.assertIn("example.org smtp:[10.0.0.25]", self.read("etc/postfix/transport"))
        self.assertIn("192.0.2.10 mx1.example.org mx1", self.read("etc/hosts"))
        self.assertIn("forward-addr: 192.0.2.53", self.read("etc/unbound/efa-forward.conf"))
        self.assertIn("nameserver 127.0.0.1", self.read("etc/resolv.conf"))
        self.assertIn("protocols =\n", self.read("etc/dovecot/local.conf"))
        self.assertIn("PermitRootLogin no", self.read("etc/ssh/sshd_config.d/00-efa-root.conf"))
        self.assertFalse(os.path.exists(self.path("etc/ssh/ssh_host_ed25519_key")))
        self.assertTrue(os.path.exists(self.path("var/lib/eFa/setup-reboot")))
        self.assertTrue(os.path.exists(self.path("var/lib/eFa/firstboot-pending")))
        self.assertIn(["systemctl", "disable", "--quiet", "efa-init"], self.runner.calls)
        self.assertIn(["efactl", "maillog-setup"], self.runner.calls)
        self.assertIn(["nmcli", "connection", "modify", "1111-2222", "connection.autoconnect",
                       "yes", "ipv4.method", "manual", "ipv4.addresses", "192.0.2.10/24",
                       "ipv4.gateway", "192.0.2.1", "ipv6.method", "auto", "ipv6.addresses",
                       "", "ipv6.gateway", ""], self.runner.calls)

    def test_secrets_never_leak(self):
        code, out = self.apply(["--all", "--verbose"])
        self.assertEqual(code, 0)
        db_pw = c.read_kv("/etc/eFa/MySQL-Config")["MYSQLROOTPWD"]
        argv = "\n".join(" ".join(cmd) for cmd in self.runner.calls)
        files = b"".join(v for k, v in self.snapshot().items() if "MySQL-Config" not in k)
        for secret in list(SECRETS.values()) + [db_pw]:
            self.assertNotIn(secret, argv)
            self.assertNotIn(secret, self.all_logs())
            self.assertNotIn(secret, out)
            self.assertNotIn(secret.encode(), files)
        # passwords went to chpasswd on stdin
        piped = [inp for cmd, inp in zip(self.runner.calls, self.runner.inputs)
                 if cmd[0] == "chpasswd"]
        self.assertEqual(piped, ["root:%s\n" % SECRETS["ROOTPASSWORD"],
                                 "efaadmin:%s\n" % SECRETS["CLIPASSWORD"]])

    def test_single_steps_use_staged_answers(self):
        self.assertEqual(self.apply(["--hostname"])[0], 0)
        code, out = self.apply(["--transport"], text="")
        self.assertEqual(code, 0, out)
        self.assertIn("example.org smtp:[10.0.0.25]", self.read("etc/postfix/transport"))

    def test_rejects_injection(self):
        for bad in ({"HOSTNAME": "mx1 evil"}, {"DOMAINNAME": "example.org;rm"},
                    {"TZONE": "../../etc/passwd"}, {"MAILSERVER": "a b"}):
            code, _ = self.apply(["--hostname"], answer_text(bad))
            self.assertEqual(code, 2, bad)
        self.assertNotIn("evil", c.read_text("/etc/hosts", ""))

    def test_short_password_refused(self):
        # The minimum matches the wizard (12); a shorter password is refused on the passwords step.
        self.assertEqual(efa_apply.MIN_PASSWORD, 12)
        code, _ = self.apply(["--passwords"], answer_text({"WEBADMINPASSWORD": "short-11chr", "CLIPASSWORD": "short-11chr", "ROOTPASSWORD": "short-11chr"}))
        self.assertEqual(code, 2)

    def test_refuses_when_configured_via_sudo(self):
        c.write_kv("/etc/eFa/eFa-Config", {"CONFIGURED": "YES"}, 0o640)
        with mock.patch.dict(os.environ, {"SUDO_USER": "efa-init"}):
            self.assertEqual(self.apply(["--all"])[0], 3)

    def test_stops_at_first_failure(self):
        self.runner.fail.add("hostnamectl")
        code, out = self.apply(["--all"])
        self.assertEqual(code, 1)
        self.assertIn("FAILED hostname", out)
        self.assertNotIn("CONFIGURED", c.read_text("/etc/eFa/eFa-Config", ""))

    def test_transport_is_idempotent(self):
        self.apply(["--transport"])
        self.apply(["--transport"])
        self.assertEqual(self.read("etc/postfix/transport").count("example.org"), 1)

    def test_answers_file_must_be_private(self):
        path = self.path("answers")
        self.write("answers", answer_text())
        os.chmod(path, 0o644)
        self.assertEqual(self.apply(["--answers", path, "--hostname"])[0], 2)
        os.chmod(path, 0o600)
        self.assertEqual(self.apply(["--answers", path, "--hostname"])[0], 0)


class FirstBootTests(RootTestCase):
    def test_first_boot_cleans_up(self):
        self.write("var/lib/eFa/firstboot-pending", "")
        self.write("etc/sudoers.d/efa-init", "rule")
        self.write("var/lib/eFa/setup/kickstart.conf", "ROOTPASSWORD:x")
        with mock.patch.object(efa_firstboot, "wait_for_network", return_value=True), \
                mock.patch.object(efa_firstboot, "internet_reachable", return_value=False):
            self.assertEqual(efa_firstboot.first_boot(), 0)
        for rel in ("etc/sudoers.d/efa-init", "var/lib/eFa/setup", "var/lib/eFa/firstboot-pending"):
            self.assertFalse(os.path.exists(self.path(rel)), rel)
        self.assertIn("efa-monitor", self.read("etc/cron.d/eFa-Monitor.cron"))
        self.assertIn(["freshclam"], self.runner.calls)
        self.assertIn(["efactl", "cdr-set", "--mode", "on"], self.runner.calls)
        self.assertIn("no internet access", self.all_logs())

    def test_setup_reboot(self):
        self.write("var/lib/eFa/setup-reboot", "")
        self.runner.active.add("efa-init")
        efa_firstboot.setup_reboot(delay=0, sleep=lambda _: None)
        self.assertIn(["systemctl", "stop", "efa-init"], self.runner.calls)
        self.assertEqual(self.runner.calls[-1], ["systemctl", "reboot"])
        self.assertFalse(os.path.exists(self.path("var/lib/eFa/setup-reboot")))


if __name__ == "__main__":
    unittest.main()
