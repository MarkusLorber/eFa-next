# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Test helpers: a temporary target root and a fake command runner.

No test needs root or runs a real system command. Every command the code
under test runs is recorded by FakeRunner.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOP = os.path.dirname(HERE)
for pkg in ("eFa-base", "eFa"):
    path = os.path.join(TOP, "src", pkg, "root", "usr", "lib", "eFa", "python")
    if path not in sys.path:
        sys.path.insert(0, path)
sys.dont_write_bytecode = True

import efa_common as c  # noqa: E402
import efa_platform_el9  # noqa: E402

SEED_FILES = {
    "etc/os-release": 'ID="almalinux"\nVERSION_ID="9.5"\nID_LIKE="rhel centos fedora"\n',
    "etc/postfix/main.cf": "# stock main.cf\n",
    "etc/clamd.d/scan.conf": "Example\n#LocalSocket /run/clamd.scan/clamd.sock\n"
                             "TCPSocket 3310\nUser clamscan\n",
    "etc/freshclam.conf": "Example\nDatabaseOwner clamupdate\n",
    "etc/dnf/automatic.conf": "[commands]\nupgrade_type = default\n"
                              "apply_updates = no\n\n[emitters]\nemit_via = motd\n",
    "etc/hosts": "127.0.0.1 localhost localhost.localdomain\n",
    "etc/ssh/ssh_host_ed25519_key": "old",
    "etc/ssh/ssh_host_ed25519_key.pub": "old",
    "usr/share/zoneinfo/Europe/Berlin": "TZif",
    "usr/share/selinux/packages/eFa/efa.pp": "policy",
    "sys/class/net/eth0/address": "00:11:22:33:44:55\n",
    "proc/net/if_inet6": "",
}
UNITS = ("sshd", "crond", "chronyd", "NetworkManager", "postfix", "dovecot", "mariadb",
         "redis", "rspamd", "nginx", "unbound", "clamav-freshclam", "clamd@",
         "fail2ban", "firewalld", "efa-init", "efa-web", "efa-firstboot",
         "efa-setup-reboot", "efa-kickstart", "efa-reboot-check")


def _cp(cmd, code=0, out="", err=""):
    return subprocess.CompletedProcess(cmd, code, out, err)


class FakeRunner:
    """Records commands and emulates the few whose output matters."""

    def __init__(self):
        self.calls = []
        self.inputs = []
        self.explicit = {}            # postconf -n
        self.master = {}              # postconf -M
        self.master_params = {}       # postconf -P
        self.active = set()           # active systemd units
        self.enabled = set()          # enabled systemd units (systemctl is-enabled)
        self.fail = set()             # program names that fail
        self.query_ok = set()         # firewall services already open
        self.users = set()
        self.groups = {"virusgroup": [], "postfix": [], "efa-web": [], "wheel": []}

    def __call__(self, cmd, input_text):
        self.calls.append(list(cmd))
        self.inputs.append(input_text)
        name = os.path.basename(cmd[0])
        if name in self.fail:
            return _cp(cmd, 1, "", "forced failure")
        handler = getattr(self, "_" + name.replace("-", "_"), None)
        return handler(cmd, input_text) if handler else _cp(cmd)

    def programs(self):
        return [os.path.basename(call[0]) for call in self.calls]

    def _postconf(self, cmd, _):
        args = cmd[1:]
        if args == ["-n"]:
            return _cp(cmd, 0, "".join("%s = %s\n" % kv for kv in sorted(self.explicit.items())))
        if args[0] == "-h":
            value = self.explicit.get(args[1], "hash" if args[1] == "default_database_type" else "")
            return _cp(cmd, 0, value + "\n")
        if args[0] == "-e":
            for item in args[1:]:
                key, value = item.split("=", 1)
                self.explicit[key] = value
            return _cp(cmd)
        if args[0] == "-M":
            if "=" in args[1]:
                key, value = args[1].split("=", 1)
                self.master[key] = value
                return _cp(cmd)
            return _cp(cmd, 0, self.master.get(args[1], ""))
        if args[0] == "-P":
            if "=" in args[1]:
                key, value = args[1].split("=", 1)
                self.master_params[key] = value
                return _cp(cmd)
            return _cp(cmd, 0, "".join("%s = %s\n" % kv for kv in sorted(
                self.master_params.items()) if kv[0].startswith(args[1] + "/")))
        return _cp(cmd)

    def _systemctl(self, cmd, _):
        if cmd[1] == "is-active":
            return _cp(cmd, 0, "active\n") if cmd[2] in self.active else _cp(cmd, 3, "inactive\n")
        if cmd[1] == "is-enabled":
            return _cp(cmd, 0, "enabled\n") if cmd[2] in self.enabled else _cp(cmd, 1, "disabled\n")
        if cmd[1] in ("start", "restart"):
            self.active.add(cmd[-1])
        return _cp(cmd)

    def _openssl(self, cmd, _):
        if cmd[1] == "req":
            for flag in ("-keyout", "-out"):
                with open(cmd[cmd.index(flag) + 1], "w") as fh:
                    fh.write("PEM")
            return _cp(cmd)
        return _cp(cmd, 1)

    def _getent(self, cmd, _):
        if cmd[1] == "passwd":
            return _cp(cmd, 0 if cmd[2] in self.users else 2)
        if cmd[2] in self.groups:
            return _cp(cmd, 0, "%s:x:1:%s\n" % (cmd[2], ",".join(self.groups[cmd[2]])))
        return _cp(cmd, 2)

    def _firewall_cmd(self, cmd, _):
        if any(a.startswith("--query-service=") for a in cmd):
            key = (cmd[0], "--permanent" in cmd, cmd[-1].split("=")[1])
            return _cp(cmd, 0 if key in self.query_ok else 1)
        if any(a.startswith("--add-service=") for a in cmd):
            self.query_ok.add((cmd[0], "--permanent" in cmd, cmd[-1].split("=")[1]))
        return _cp(cmd)

    _firewall_offline_cmd = _firewall_cmd

    def _nmcli(self, cmd, _):
        if cmd[1:3] == ["-t", "-f"]:
            return _cp(cmd, 0, "1111-2222:eth0\n")
        return _cp(cmd)

    def _semodule(self, cmd, _):
        return _cp(cmd, 0, "") if cmd[1] == "-l" else _cp(cmd)

    def _systemd_detect_virt(self, cmd, _):
        return _cp(cmd, 0, "kvm\n") if "--vm" in cmd else _cp(cmd, 1, "none\n")

    def _rpm(self, cmd, _):
        return _cp(cmd, 1)

    def _needs_restarting(self, cmd, _):
        return _cp(cmd, 1, "Reboot is required to fully utilize these updates.\n")


class RootTestCase(unittest.TestCase):
    """Each test gets a fresh temporary root and a fresh fake runner."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="efa-test-")
        self.addCleanup(shutil.rmtree, self.root, True)
        for rel, text in SEED_FILES.items():
            self.write(rel, text)
        for unit in UNITS:
            self.write("usr/lib/systemd/system/%s.service" % unit, "[Unit]\n")
        self.write("usr/lib/systemd/system/efa-reboot-check.timer", "[Timer]\n")
        self.write("usr/lib/systemd/system/efa-setup-reboot.path", "[Path]\n")
        self.runner = FakeRunner()
        c.env.reset()
        c.env.root = self.root
        c.env.runner = self.runner
        c.env.platform = efa_platform_el9.EL9()
        self.addCleanup(c.env.reset)

    def path(self, rel):
        return os.path.join(self.root, rel.lstrip("/"))

    def write(self, rel, text):
        target = self.path(rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(text)

    def read(self, rel):
        with open(self.path(rel), encoding="utf-8") as fh:
            return fh.read()

    def mode(self, rel):
        return os.stat(self.path(rel)).st_mode & 0o7777

    def snapshot(self):
        """Content of every file below the root, for idempotency checks."""
        result = {}
        for folder, _, files in os.walk(self.root):
            for name in files:
                full = os.path.join(folder, name)
                rel = os.path.relpath(full, self.root)
                if rel.startswith("var/log/"):
                    continue
                with open(full, "rb") as fh:
                    result[rel] = fh.read()
        return result

    def all_logs(self):
        text = ""
        log_dir = self.path("var/log/eFa")
        if os.path.isdir(log_dir):
            for name in os.listdir(log_dir):
                with open(os.path.join(log_dir, name), encoding="utf-8") as fh:
                    text += fh.read()
        return text
