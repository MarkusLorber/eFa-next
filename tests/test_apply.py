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
        self.assertIn(["efactl", "dns-zone-set", "--zone", "corp.example", "--action", "add", "--servers", "10.0.0.53", "--dnssec", "off"],
                      self.runner.calls)
        self.assertIn("[mail.corp.example]", self.read("etc/postfix/transport"))

    def test_all_steps(self):
        code, out = self.apply(["--all"])
        self.assertEqual(code, 0, out + self.all_logs())
        cfg = c.read_kv("/etc/eFa/eFa-Config")
        self.assertEqual(cfg["CONFIGURED"], "YES")
        self.assertEqual(cfg["HOSTNAME"], "mx1")
        self.assertEqual(cfg["ISUTC"], "YES")
        self.assertEqual(self.read("etc/efa-web/language"), "en\n", "the login page speaks the language of the setup")
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
        # S30: no ROOTSSH in the answers: root login through SSH stays as it is.
        self.assertFalse(any(call[1:2] == ["ssh-root-set"] for call in self.runner.calls if call[0] == "efactl"))
        self.assertFalse(os.path.exists(self.path("etc/ssh/ssh_host_ed25519_key")))
        self.assertTrue(os.path.exists(self.path("var/lib/eFa/setup-reboot")))
        self.assertTrue(os.path.exists(self.path("var/lib/eFa/firstboot-pending")))
        self.assertIn(["systemctl", "disable", "--quiet", "efa-init"], self.runner.calls)
        self.assertIn(["efactl", "maillog-setup"], self.runner.calls)
        self.assertIn(["nmcli", "connection", "modify", "1111-2222", "connection.autoconnect",
                       "yes", "ipv4.method", "manual", "ipv4.addresses", "192.0.2.10/24",
                       "ipv4.gateway", "192.0.2.1", "ipv6.method", "auto", "ipv6.addresses",
                       "", "ipv6.gateway", ""], self.runner.calls)

    def test_root_ssh_only_by_choice(self):
        code, out = self.apply(["--passwords"], answer_text({"ROOTSSH": "key-only"}))
        self.assertEqual(code, 0, out + self.all_logs())
        self.assertIn(["efactl", "ssh-root-set", "--mode=key-only", "--confirm=yes"], self.runner.calls)
        code, out = self.apply(["--passwords"], answer_text({"ROOTSSH": "maybe"}))
        self.assertNotEqual(code, 0)

    def test_root_ssh_status(self):
        self.runner.sshd_t = "permitrootlogin yes\n"
        code, out = self.apply(["--root-ssh-status"], "")
        self.assertEqual((code, out), (0, "ROOTSSH on\n"))

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

    def test_setup_variant(self):
        guided = ("SETUPVARIANT:guided\nEULINK:no\nNOTICEACCEPTED:0123456789abcdef/1762600000\nEULINKCONFIRM:fedcba9876543210/1762600000\n"
                  "FRAMEWORKS:nis2,iso27001\nSETUPLANG:de\n")
        totp = "TOTPSECRET:GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\nTOTPSTEP:59000000\nTOTPRECOVERY:" + ",".join(["a" * 64] * 10) + "\n"
        code, out = self.apply(["--variant"], answer_text() + guided)
        self.assertEqual(code, 2, out)  # guided without the 2FA of the main admin: refused
        code, out = self.apply(["--variant"], answer_text() + guided + totp)
        self.assertEqual(code, 0, out + self.all_logs())
        self.assertIn(["efactl", "totp-import"], self.runner.calls)
        self.assertIn(["efactl", "setup-variant-apply", "--variant", "guided", "--eulink", "no", "--notice", "0123456789abcdef/1762600000",
                       "--lang", "de", "--console_user", "efaadmin", "--noeu", "fedcba9876543210/1762600000", "--frameworks", "nis2,iso27001"],
                      self.runner.calls)
        self.assertNotIn("GEZDGNBV", "\n".join(" ".join(cmd) for cmd in self.runner.calls))
        self.assertEqual(self.runner.calls[-1], ["efactl", "floor-check", "--mode", "apply"])
        self.assertEqual(self.apply(["--variant"], answer_text() + "NOTICEACCEPTED:nothex/1\n")[0], 2)

    def test_hosts_keeps_localhost(self):
        """Without localhost in /etc/hosts the name went to DNS and Postfix (inet_interfaces=localhost) got a foreign address."""
        self.write("etc/hosts", "192.0.2.99 other.example\n")
        code, out = self.apply(["--hostname"])
        self.assertEqual(code, 0, out)
        hosts = self.read("etc/hosts")
        self.assertIn("127.0.0.1 localhost localhost.localdomain\n", hosts)
        self.assertIn("192.0.2.99 other.example", hosts)
        self.assertEqual(self.apply(["--hostname"])[0], 0)
        self.assertEqual(self.read("etc/hosts").count("localhost.localdomain"), 1)

    def test_hosts_localhost_only_on_loopback(self):
        """A line with a foreign address that also names localhost: the localhost names go, its other names stay, a backup."""
        before = ("127.0.0.1   mx1.example.org mx1 localhost localhost.localdomain localhost4 localhost4.localdomain4\n"
                  "192.0.2.1   mx1.example.org   mx1 localhost localhost.localdomain localhost4 localhost4.localdomain4\n"
                  "192.0.2.7 localhost6 # only localhost\n"
                  "::1             localhost\n")
        text, moved = efa_apply.hosts_localhost_only_loopback(before)
        self.assertEqual(text, "127.0.0.1   mx1.example.org mx1 localhost localhost.localdomain localhost4 localhost4.localdomain4\n"
                               "192.0.2.1 mx1.example.org mx1\n::1             localhost\n")
        self.assertEqual(len(moved), 2)
        self.assertEqual(efa_apply.hosts_localhost_only_loopback(text), (text, []))
        self.write("etc/hosts", before)
        self.assertEqual(self.apply(["--hostname"])[0], 0)
        self.assertNotIn("192.0.2.1   mx1.example.org   mx1 localhost", self.read("etc/hosts"))
        self.assertEqual(self.read("etc/hosts.efa-bak"), before)

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

    def test_time_sync_servers_checked(self):
        """--time-sync takes 1 to 4 host names or addresses; anything else is refused before a command runs."""
        self.assertEqual(efa_apply.ntp_server_list("0.pool.ntp.org, 192.0.2.123 2001:db8::1"), ["0.pool.ntp.org", "192.0.2.123", "2001:db8::1"])
        self.assertEqual(efa_apply.ntp_server_list(""), [])
        for wrong in ("a;id", "$(id)", "a.example b.example c.example d.example e.example", "-x"):
            self.assertIsNone(efa_apply.ntp_server_list(wrong), wrong)
            calls = len(self.runner.calls)
            self.assertEqual(self.apply(["--time-sync=" + wrong])[0], 2, wrong)
            self.assertEqual(len(self.runner.calls), calls, wrong)

    def test_time_sync_sets_sources_and_steps_the_clock(self):
        """A dry run: the chrony sources replaced, chronyd restarted, burst, makestep, waitsync; one line for the wizard."""
        self.write("etc/chrony.conf", "pool 2.almalinux.pool.ntp.org iburst\nsourcedir /run/chrony-dhcp\ndriftfile /var/lib/chrony/drift\n")
        code, out = self.apply(["--time-sync", "ntp.example.org,192.0.2.123"])
        self.assertEqual(code, 0, out + self.all_logs())
        conf = self.read("etc/chrony.conf")
        self.assertIn("server ntp.example.org iburst\nserver 192.0.2.123 iburst\n", conf)
        self.assertNotIn("pool 2.almalinux", conf)
        self.assertIn("driftfile /var/lib/chrony/drift", conf)
        chrony = [call for call in self.runner.calls if call[0] == "chronyc"]
        self.assertIn(["chronyc", "-a", "makestep"], chrony)
        self.assertLess(chrony.index(["chronyc", "-a", "burst", "4/4"]), chrony.index(["chronyc", "-a", "makestep"]))
        self.assertTrue(out.startswith("TIMESYNC yes"), out)
        self.runner.fail.add("chronyc")
        code, out = self.apply(["--time-sync", ""])
        self.assertEqual((code, out.split()[:2]), (1, ["TIMESYNC", "no"]), "not synchronized: the wizard says why")
        self.assertIn("server ntp.example.org iburst", self.read("etc/chrony.conf"), "empty: the sources stay")

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
        self.assertIn(["efactl", "bec-set", "--mode", "on", "--score_pattern", "2"], self.runner.calls)
        self.assertIn("no internet access", self.all_logs())

    def test_first_boot_starts_the_web_interface_after_the_wizard(self):
        """WEB-RESTART: efa-web skips its start while the wizard holds port 8080; with the wizard gone, first boot starts it."""
        self.write("var/lib/eFa/firstboot-pending", "")
        self.write("usr/lib/systemd/system/efa-web.service", "[Service]\n")
        self.runner.enabled.add("efa-web.service")
        with mock.patch.object(efa_firstboot, "wait_for_network", return_value=True), \
                mock.patch.object(efa_firstboot, "internet_reachable", return_value=False):
            self.assertEqual(efa_firstboot.first_boot(), 0)
        self.assertIn(["systemctl", "start", "efa-web.service"], self.runner.calls)

    def test_setup_reboot(self):
        self.write("var/lib/eFa/setup-reboot", "")
        self.runner.active.add("efa-init")
        efa_firstboot.setup_reboot(delay=0, sleep=lambda _: None)
        self.assertIn(["systemctl", "stop", "efa-init"], self.runner.calls)
        self.assertEqual(self.runner.calls[-1], ["systemctl", "reboot"])
        self.assertFalse(os.path.exists(self.path("var/lib/eFa/setup-reboot")))


if __name__ == "__main__":
    unittest.main()
