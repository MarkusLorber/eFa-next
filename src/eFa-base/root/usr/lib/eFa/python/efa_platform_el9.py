# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Platform layer for EL9 (AlmaLinux, Rocky Linux, RHEL 9).

systemd, dnf / dnf-automatic, firewalld, NetworkManager, shadow-utils and
SELinux. Only this module knows these tools.
"""

import hashlib
import os
import re
import time

import efa_common as c
from efa_common import StepError, rp
from efa_platform import Platform

UNIT_DIRS = ("/etc/systemd/system", "/usr/lib/systemd/system")
LIVE_STATES = ("active", "activating", "reloading")
CRYPT_PREFIXES = ("$6$", "$5$", "$y$", "$2b$", "$gy$")


def rpm_verify_content_changed(line):
    """One line of rpm -V: True when the content differs (S size, 5 digest, L link target) or the file is missing."""
    flags = line.split()[0]
    return flags == "missing" or any(flag in flags[:9] for flag in "S5L")


class EL9(Platform):
    name = "el9"
    root_group = "root"

    PATHS = {
        "efa_etc": "/etc/eFa",
        "efa_config": "/etc/eFa/eFa-Config",
        "mysql_config": "/etc/eFa/MySQL-Config",
        "version_file": "/etc/eFa-next-Version",
        # The name up to 6.0.0.5.x, kept as a symlink to version_file: their updaters and scripts read it.
        "version_link": "/etc/eFa-Version",
        "log_dir": "/var/log/eFa",
        "state_dir": "/var/lib/eFa",
        "setup_dir": "/var/lib/eFa/setup",
        "hostname_file": "/etc/hostname",
        "hosts_file": "/etc/hosts",
        "resolv_conf": "/etc/resolv.conf",
        "zoneinfo_dir": "/usr/share/zoneinfo",
        "localtime": "/etc/localtime",
        "chrony_conf": "/etc/chrony.conf",
        "postfix_dir": "/etc/postfix",
        "cert_file": "/etc/pki/tls/certs/efa.crt",
        "key_file": "/etc/pki/tls/private/efa.key",
        "sasl_conf": "/etc/dovecot/local.conf",
        "clamd_conf": "/etc/clamd.d/scan.conf",
        "clamd_socket": "/run/clamd.scan/clamd.sock",
        "clamd_log": "/var/log/clamd.scan",
        "clamav_db_dir": "/var/lib/clamav",
        "freshclam_conf": "/etc/freshclam.conf",
        "mariadb_conf": "/etc/my.cnf.d/efa.cnf",
        "unbound_conf": "/etc/unbound/unbound.conf",
        "unbound_conf_d": "/etc/unbound/conf.d",
        "unbound_local_d": "/etc/unbound/local.d",
        "unbound_forward": "/etc/unbound/efa-forward.conf",
        "unbound_root_key": "/var/lib/unbound/root.key",
        "unbound_pidfile": "/run/unbound/unbound.pid",
        "fail2ban_jail": "/etc/fail2ban/jail.d/efa.local",
        "ssh_dir": "/etc/ssh",
        "sshd_dropin": "/etc/ssh/sshd_config.d/40-efa.conf",
        # Before the 01-permitrootlogin.conf of Anaconda: sshd keeps the first value; the same file as the switch ssh-root-set.
        "sshd_root_dropin": "/etc/ssh/sshd_config.d/00-efa-root.conf",
        "ssh_banner": "/etc/issue.net",
        "sudoers_file": "/etc/sudoers.d/efa-init",
        "cron_dir": "/etc/cron.d",
        "monitor_settings": "/etc/sysconfig/eFa-Monitor",
        "monitor_cron": "/etc/cron.d/eFa-Monitor.cron",
        "policy_module": "/usr/share/selinux/packages/eFa/efa.pp",
        "efa_web_dir": "/etc/efa-web",
        "web_admin_pw": "/etc/efa-web/admin.pw",
        "sendmail": "/usr/sbin/sendmail",
        "efa_sbin": "/usr/sbin",
        "unit_dir": "/usr/lib/systemd/system",
        "nm_dns_conf": "/etc/NetworkManager/conf.d/90-efa-dns.conf",
        "dnf_automatic_conf": "/etc/dnf/automatic.conf",
        "redis_conf": "/etc/redis/redis.conf",
        "redis_dir": "/var/lib/redis",
        "redis_cli": "/usr/bin/redis-cli",
    }
    # What differs between the releases of Enterprise Linux (efa_platform_el10 overrides it): where rspamd and ClamAV come
    # from, the versions the repositories bring, and whether the system crypto policy still accepts SHA-1 signatures.
    REPOSITORIES = {"rspamd": "https://rspamd.com/rpm-stable/centos-9/$basearch", "clamav": "epel-release (EPEL 9)",
                    "nginx": "module stream nginx:1.26"}
    VERSIONS = {"python": "3.9", "nginx": "1.26", "mariadb": "10.5", "postfix": "3.5"}
    SHA1_SIGNATURES = True
    SERVICES = {
        "mta": "postfix", "db": "mariadb", "redis": "redis", "spam": "rspamd",
        "web": "nginx", "av": "clamd@scan", "avupdate": "clamav-freshclam",
        "dns": "unbound", "ban": "fail2ban", "firewall": "firewalld",
        "ssh": "sshd", "cron": "crond", "time": "chronyd", "sasl": "dovecot",
        "network": "NetworkManager", "wizard": "efa-init",
        "firstboot": "efa-firstboot.service",
        "setup_reboot": "efa-setup-reboot.path",
    }
    # eFa-next oneshot units: never restarted or enabled as plain services.
    # A package update can run inside efa-autoupdate.service: a restart would kill it.
    EFA_ONESHOTS = ("efa-firstboot.service", "efa-kickstart.service",
                    "efa-setup-reboot.service", "efa-reboot-check.service",
                    "efa-autoupdate.service", "efa-dkim-rotation.service",
                    "efa-firewall-guard.service", "efa-mailreport.service",
                    "efa-post-boot.service", "efa-sanesecurity.service",
                    "efa-events.service", "efa-cve-watch.service", "efa-outbound-hold.service",
                    "efa-time-sync.service", "efa-release-upgrade.service", "efa-release-upgrade-finish.service",
                    "efa-os-check.service")
    ACCOUNTS = {
        "clamav_user": "clamscan", "av_group": "virusgroup",
        "postfix_group": "postfix", "web_group": "efa-web",
        "rspamd_user": "_rspamd", "wizard_user": "efa-init",
        "admin_group": "wheel", "redis_user": "redis",
    }
    FIREWALL_SERVICES = {
        "ssh": "ssh", "smtp": "smtp", "submission": "smtp-submission",
        "http": "http", "https": "https",
    }
    UNNEEDED_SERVICES = ("avahi-daemon", "cups", "rpcbind", "bluetooth",
                         "ModemManager")
    GUEST_TOOLS = {
        "vmware": ("open-vm-tools", "vmtoolsd"),
        "kvm": ("qemu-guest-agent", "qemu-guest-agent"),
        "qemu": ("qemu-guest-agent", "qemu-guest-agent"),
        "microsoft": ("hyperv-daemons", "hypervkvpd"),
    }

    def __init__(self):
        self._running = None
        self._mac = None

    # ------------------------------------------------ service manager
    def manager_running(self):
        if self._running is None:
            if not c.env.live:
                self._running = True
            else:
                chroot = c.run(["systemd-detect-virt", "--chroot"],
                               check=False).returncode == 0
                self._running = os.path.isdir("/run/systemd/system") and not chroot
        return self._running

    # Logical unit names of eFa-next that are called otherwise on this release (EL10: valkey for redis).
    UNIT_ALIASES = {}

    @staticmethod
    def _unit(name):
        return name if "." in name else name + ".service"

    def service_exists(self, name):
        name = self.UNIT_ALIASES.get(name, name)
        unit = self._unit(name)
        names = [unit]
        if "@" in unit:
            names.append(unit.split("@", 1)[0] + "@" + unit[unit.rfind("."):])
        return any(os.path.exists(rp(os.path.join(d, n)))
                   for d in UNIT_DIRS for n in names)

    def service_enable(self, name, start=False):
        name = self.UNIT_ALIASES.get(name, name)
        cmd = ["systemctl", "enable", "--quiet"]
        if start and self.manager_running():
            cmd.append("--now")
        c.run(cmd + [name])

    def service_disable(self, name, stop=False):
        name = self.UNIT_ALIASES.get(name, name)
        cmd = ["systemctl", "disable", "--quiet"]
        if stop and self.manager_running():
            cmd.append("--now")
        c.run(cmd + [name])

    def service_is_active(self, name):
        name = self.UNIT_ALIASES.get(name, name)
        if not self.manager_running():
            return False
        res = c.run(["systemctl", "is-active", name], check=False)
        return res.stdout.strip() in LIVE_STATES

    def kernel_settings(self, values):
        path = rp("/etc/sysctl.d/90-efa.conf")
        if values is None:
            if os.path.exists(path):
                os.remove(path)
            return
        c.write_file(path, "# eFa-next: kernel settings (CIS AlmaLinux 9), efactl kernel-hardening-set\n" +
                     "".join("%s = %s\n" % item for item in sorted(values.items())))
        c.run(["sysctl", "-q", "-p", path], check=False)

    def kernel_settings_active(self):
        return os.path.exists(rp("/etc/sysctl.d/90-efa.conf"))

    def kernel_values(self, names):
        found = {}
        for name in names:
            try:
                with open("/proc/sys/" + name.replace(".", "/")) as f:
                    found[name] = f.read().strip()
            except OSError:
                pass
        return found

    def service_is_enabled(self, name):
        name = self.UNIT_ALIASES.get(name, name)
        res = c.run(["systemctl", "is-enabled", name], check=False)
        return res.stdout.strip() == "enabled"

    def service_start(self, name):
        name = self.UNIT_ALIASES.get(name, name)
        if not self.manager_running():
            raise StepError("cannot start %s: systemd is not running" % name)
        c.run(["systemctl", "start", name])

    def service_stop(self, name):
        name = self.UNIT_ALIASES.get(name, name)
        if self.manager_running():
            c.run(["systemctl", "stop", name])

    def service_restart(self, name, check=True):
        name = self.UNIT_ALIASES.get(name, name)
        if not self.manager_running():
            if check:
                raise StepError("cannot restart %s: systemd is not running" % name)
            return None
        return c.run(["systemctl", "restart", name], check=check)

    def service_start_background(self, name):
        """Start without waiting for it (a oneshot from a package script); a failure is only logged."""
        name = self.UNIT_ALIASES.get(name, name)
        if self.manager_running():
            c.run(["systemctl", "start", "--no-block", name], check=False)

    def service_try_restart(self, name):
        name = self.UNIT_ALIASES.get(name, name)
        if self.manager_running():
            c.run(["systemctl", "try-restart", name])

    def service_reload_if_active(self, name):
        name = self.UNIT_ALIASES.get(name, name)
        if self.service_is_active(name):
            c.run(["systemctl", "try-reload-or-restart", name])

    def service_manager_reload(self):
        if self.manager_running():
            c.run(["systemctl", "daemon-reload"])

    def _dropin(self, name, filename, content):
        path = "/etc/systemd/system/%s.d/%s" % (self._unit(name), filename)
        changed = c.write_file(path, content)
        if changed:
            self.service_manager_reload()
        return changed

    def service_set_open_files(self, name, limit):
        name = self.UNIT_ALIASES.get(name, name)
        header = "# SPDX-License-Identifier: AGPL-3.0-or-later\n" \
                 "# Copyright (C) 2026 Markus Lorber and eFa-next contributors\n" \
                 "# Author: Markus Lorber, Lukasz Galusinski\n"
        return self._dropin(name, "efa-limits.conf",
                            header + "[Service]\nLimitNOFILE=%d\n" % limit)

    # 5v (h): only what these services keep working with: no new privileges by exec, the system read-only below /usr and /boot,
    # no home folders, an own /tmp, no kernel tunables, modules or control groups, no SUID files, no realtime.
    HARDENING = ("[Service]\nNoNewPrivileges=yes\nProtectSystem=full\nProtectHome=yes\nPrivateTmp=yes\nProtectKernelTunables=yes\n"
                 "ProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectControlGroups=yes\nRestrictSUIDSGID=yes\nRestrictRealtime=yes\n"
                 "LockPersonality=yes\nRestrictNamespaces=yes\n")

    def service_hardening(self, name, on):
        name = self.UNIT_ALIASES.get(name, name)
        path = "/etc/systemd/system/%s.d/efa-hardening.conf" % self._unit(name)
        if not on:
            if os.path.exists(path):
                os.remove(path)
                self.service_manager_reload()
                return True
            return False
        header = "# SPDX-License-Identifier: AGPL-3.0-or-later\n" \
                 "# Copyright (C) 2026 Markus Lorber and eFa-next contributors\n" \
                 "# Author: Markus Lorber, Lukasz Galusinski\n"
        return self._dropin(name, "efa-hardening.conf", header + self.HARDENING)

    def service_start_after_network(self, name):
        name = self.UNIT_ALIASES.get(name, name)
        header = "# SPDX-License-Identifier: AGPL-3.0-or-later\n" \
                 "# Copyright (C) 2026 Markus Lorber and eFa-next contributors\n" \
                 "# Author: Markus Lorber, Lukasz Galusinski\n"
        return self._dropin(name, "efa-network.conf", header +
                            "[Unit]\nWants=network-online.target\n"
                            "After=network-online.target\n")

    def efa_units(self):
        timers, services = [], []
        folder = rp(self.PATHS["unit_dir"])
        try:
            names = sorted(os.listdir(folder))
        except FileNotFoundError:
            names = []
        for name in names:
            if not name.lower().startswith("efa-") or "@" in name:
                continue
            if name.endswith(".timer"):
                timers.append(name)
            elif name.endswith(".service"):
                services.append(name)
        return timers, services

    # ------------------------------------------------ packages and updates
    def package_installed(self, package):
        return c.run(["rpm", "-q", "--quiet", package], check=False).returncode == 0

    def repo_key_import(self, path):
        c.run(["rpm", "--import", path])

    def repo_refresh(self, repo):
        c.run(["dnf", "-q", "clean", "metadata", "--repo", repo], check=False)
        res = c.run(["dnf", "-q", "-y", "makecache", "--repo", repo], check=False)
        return res.returncode == 0, (res.stdout + res.stderr)[-300:]

    def package_install(self, packages):
        c.run(["dnf", "-y", "install"] + list(packages))

    def package_fetch(self, packages, folder):
        c.run(["dnf", "-y", "-q", "install", "--downloadonly", "--downloaddir=" + folder] + list(packages))
        return sorted(os.path.join(folder, name) for name in os.listdir(folder) if name.endswith(".rpm"))

    def package_signature_ok(self, path):
        # dnf does not check local packages by default: rpm checks them against the imported keys.
        res = c.run(["rpm", "-K", path], check=False)
        return res.returncode == 0 and "signatures ok" in res.stdout.lower()

    def package_upgrade_files(self, paths):
        res = c.run(["dnf", "-y", "--disablerepo=*", "upgrade"] + list(paths), check=False)
        return res.returncode == 0, (res.stderr or res.stdout)[-200:]

    def package_scripts(self, path):
        return c.run(["rpm", "-qp", "--scripts", "--triggers", path], check=False).stdout

    def package_downgrade(self, files):
        res = c.run(["dnf", "-y", "downgrade"] + list(files), check=False)
        return res.returncode == 0, (res.stderr or res.stdout)[-300:]

    def configure_auto_updates(self):
        path = self.PATHS["dnf_automatic_conf"]
        text = c.read_text(path)
        new = c.set_ini(text, "commands", {"upgrade_type": "security",
                                           "download_updates": "yes",
                                           "apply_updates": "yes"})
        new = c.set_ini(new, "emitters", {"emit_via": "stdio"})
        changed = c.write_file(path, new)
        self.service_enable("dnf-automatic.timer", start=True)
        return changed

    def reboot_required(self):
        res = c.run(["needs-restarting", "-r"], check=False)
        if res.returncode == 1:
            return True, res.stdout.strip()
        if res.returncode == 0:
            return False, ""
        raise StepError("needs-restarting failed with exit code %d" % res.returncode)

    OVAL_SOURCES = {
        "almalinux": "https://security.almalinux.org/oval/org.almalinux.alsa-9.xml.bz2",
        "rocky": "https://dl.rockylinux.org/pub/oval/org.rockylinux.rlsa-9.xml.bz2",
        "rhel": "https://access.redhat.com/security/data/oval/v2/RHEL9/rhel-9.oval.xml.bz2",
    }

    def oval_source(self):
        lines = c.read_text("/etc/os-release", "").splitlines()
        ident = next((line.split("=", 1)[1].strip().strip('"') for line in lines if line.startswith("ID=")), "")
        return self.OVAL_SOURCES.get(ident)

    def package_versions(self):
        res = c.run(["rpm", "-qa", "--qf", "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE}\\n"], check=False)
        found = {}
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) == 4:
                found.setdefault(parts[0], []).append(tuple(parts[1:]))
        return found

    def version_older(self, installed, fixed):
        import rpm
        return rpm.labelCompare(tuple(installed), tuple(fixed)) < 0

    def security_updates(self):
        # One line per CVE: "CVE-2026-1234 Important/Sec. openssl-1:3.0.7-28.el9_4.x86_64". Advisories without CVE come by their name.
        found = {}
        for flag in ("--with-cve", ""):
            res = c.run(["dnf", "-q", "updateinfo", "list", "--security"] + ([flag] if flag else []), check=False)
            if res.returncode != 0:
                raise StepError("dnf updateinfo failed: %s" % (res.stderr or "")[-200:])
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) != 3:
                    continue
                ident, severity, nevra = parts
                name = nevra.rsplit("-", 2)[0]
                item = found.setdefault(name, {"package": name, "severity": severity.split("/")[0], "ids": []})
                if ident not in item["ids"]:
                    item["ids"].append(ident)
        return sorted(found.values(), key=lambda item: item["package"])

    def listening(self, with_packages=True):
        res = c.run(["ss", "-H", "-ltnup"], check=False)
        found, packages = [], {}
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            proto, local = parts[0], parts[4]
            address, _, port = local.rpartition(":")
            match = re.search(r'\(\("([^"]+)",pid=(\d+)', line)
            process, pid = (match.group(1), match.group(2)) if match else ("", "")
            package = ""
            if pid and with_packages:
                try:
                    exe = os.readlink("/proc/%s/exe" % pid)
                except OSError:
                    exe = ""
                if exe and exe not in packages:
                    q = c.run(["rpm", "-qf", "--qf", "%{NAME}", exe], check=False)
                    packages[exe] = q.stdout.strip() if q.returncode == 0 else ""
                package = packages.get(exe, "")
            found.append({"proto": proto, "address": address.strip("[]"), "port": int(port) if port.isdigit() else 0,
                          "process": process, "package": package, "unit": self._unit_of(pid)})
        return found

    def _unit_of(self, pid):
        """The systemd unit of a process (the last part of its cgroup), or "" for none or a process that is gone."""
        try:
            with open("/proc/%s/cgroup" % pid) as f:
                path = f.read().strip().splitlines()[-1].rpartition(":")[2]
        except (OSError, IndexError, ValueError):
            return ""
        name = path.rstrip("/").rpartition("/")[2]
        return name if name.endswith((".service", ".scope")) else ""

    def append_only(self, path, on):
        c.run(["chattr", "+a" if on else "-a", path])

    AUDIT_RULES = "/etc/audit/rules.d/efa.rules"

    def audit_rules(self, text):
        if text is None:
            if os.path.exists(self.AUDIT_RULES):
                os.remove(self.AUDIT_RULES)
        else:
            with open(self.AUDIT_RULES, "w") as f:
                f.write(text)
            os.chmod(self.AUDIT_RULES, 0o640)
        c.run(["augenrules", "--load"])

    def audit_rules_present(self):
        return os.path.exists(self.AUDIT_RULES)

    def file_labels(self, path):
        c.run(["restorecon", "-R", path], check=False)

    def package_verify(self, path):
        res = c.run(["rpm", "-Vf", path], check=False)
        return (res.stdout + res.stderr).strip()[:2000]

    def journal_window(self, since, until, idents):
        cmd = ["journalctl", "--no-pager", "-o", "short-iso", "--since", "@%d" % int(since), "--until", "@%d" % int(until)]
        for ident in idents:
            cmd += ["-t", ident]
        return c.run(cmd, check=False).stdout.splitlines()[-200:]

    def process_counts(self, groups):
        counts = dict.fromkeys(groups, 0)
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open("/proc/%s/comm" % pid) as f:
                    name = f.read().strip()
                with open("/proc/%s/cmdline" % pid, "rb") as f:
                    words = f.read().decode("utf-8", "replace").split("\0")
            except OSError:
                continue
            for label, names in groups.items():
                if name in names or any(os.path.basename(word) in names for word in words[:2]):
                    counts[label] += 1
                    break
        return counts

    TCP_KEYS = {"TcpExt": ("SyncookiesSent", "ListenDrops", "ListenOverflows"), "Tcp": ("PassiveOpens",)}

    @staticmethod
    def parse_proc_net(text, keys):
        """/proc/net/netstat and /proc/net/snmp: pairs of lines, names then values, each pair led by its table name."""
        found = {}
        lines = text.splitlines()
        for head, values in zip(lines[::2], lines[1::2]):
            names, numbers = head.split(), values.split()
            for key in keys.get(names[0].rstrip(":"), ()) if names else ():
                if key in names[1:] and len(numbers) == len(names):
                    found[key] = int(numbers[names.index(key)])
        return found

    def tcp_counters(self):
        found = self.parse_proc_net(c.read_text("/proc/net/netstat", ""), self.TCP_KEYS)
        found.update(self.parse_proc_net(c.read_text("/proc/net/snmp", ""), self.TCP_KEYS))
        return found

    def memory_used_percent(self):
        memory = {}
        for line in c.read_text("/proc/meminfo", "").splitlines():
            name, _sep, rest = line.partition(":")
            if name in ("MemTotal", "MemAvailable") and rest.split():
                memory[name] = int(rest.split()[0])
        return round(100 * (1 - memory["MemAvailable"] / memory["MemTotal"]), 1)

    CONNECTION_KEYS = ("ipv4.method", "ipv4.addresses", "ipv4.gateway", "ipv4.dns", "ipv4.route-metric", "ipv4.route-table",
                       "ipv4.routing-rules", "connection.zone", "ipv4.never-default")

    def interfaces(self):
        res = c.run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"])
        found = []
        for line in res.stdout.splitlines():
            device, kind, state, connection = (line.split(":") + ["", "", "", ""])[:4]
            if kind in ("ethernet", "vlan"):
                found.append({"device": device, "type": kind, "state": state, "connection": connection})
        return found

    def main_interface(self):
        res = c.run(["ip", "-o", "route", "show", "default"], check=False)
        match = re.search(r"\bdev\s+(\S+)", res.stdout)
        return match.group(1) if match else ""

    def connection_settings(self, connection):
        res = c.run(["nmcli", "-t", "-f", ",".join(self.CONNECTION_KEYS), "connection", "show", connection])
        return dict(line.split(":", 1) for line in res.stdout.splitlines() if ":" in line)

    def connection_ensure(self, device, vlan=None):
        name = "efa-%s" % (device if vlan is None else "%s.%d" % (device, vlan))
        known = c.run(["nmcli", "-t", "-f", "NAME", "connection", "show"]).stdout.split()
        if name in known:
            return name, False
        if vlan is None:
            c.run(["nmcli", "connection", "add", "type", "ethernet", "ifname", device, "con-name", name, "ipv4.method", "disabled", "ipv6.method", "ignore"])
        else:
            c.run(["nmcli", "connection", "add", "type", "vlan", "dev", device, "id", str(vlan), "ifname", "%s.%d" % (device, vlan),
                   "con-name", name, "ipv4.method", "disabled", "ipv6.method", "ignore"])
        return name, True

    def connection_apply(self, connection, settings):
        pairs = []
        for key in self.CONNECTION_KEYS:
            if key in settings:
                pairs += [key, settings[key]]
        c.run(["nmcli", "connection", "modify", connection] + pairs)
        # NetworkManager tells firewalld the zone of the interface itself: no firewall reload.
        c.run(["nmcli", "connection", "up", connection])

    def connection_delete(self, connection):
        c.run(["nmcli", "connection", "delete", connection], check=False)

    NO_AUTO_FILE = "/etc/NetworkManager/conf.d/50-efa-no-auto-default.conf"

    def no_auto_profiles(self):
        # Only interfaces that come later: a profile that exists stays as it is.
        changed = c.write_file(self.NO_AUTO_FILE, "# eFa-next: a new interface gets no automatic DHCP profile, it stays unused until it has a role.\n"
                                                  "[main]\nno-auto-default=*\n")
        if changed:
            c.run(["nmcli", "general", "reload", "conf"], check=False)
        return changed

    def ethernet_devices(self):
        net = rp("/sys/class/net")
        try:
            devices = sorted(name for name in os.listdir(net) if os.path.exists(os.path.join(net, name, "device")))
            with open(rp("/proc/net/route")) as f:
                main = {line.split()[0] for line in f.read().splitlines()[1:] if line.split()[1:2] == ["00000000"]}
        except OSError:
            return [], set()
        return devices, main

    def auto_profiles(self):
        res = c.run(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show"], check=False)
        found = []
        for line in res.stdout.splitlines():
            name, _, device = line.rpartition(":")
            if re.fullmatch(r"Wired connection \d+", name):
                found.append({"name": name, "device": device})
        return found

    def zone_services(self, zone, services):
        for tool in (["firewall-cmd", "--permanent"], ["firewall-cmd"]):
            current = c.run(tool + ["--zone=" + zone, "--list-services"]).stdout.split()
            for name in current:
                if name not in services:
                    c.run(tool + ["--zone=" + zone, "--remove-service=" + name])
            for name in services:
                if name not in current:
                    c.run(tool + ["--zone=" + zone, "--add-service=" + name])

    def zone_service_list(self, zone):
        return c.run(["firewall-cmd", "--permanent", "--zone=" + zone, "--list-services"]).stdout.split()

    def schedule(self, name, seconds, argv):
        # A fixed time, not --on-active: a daemon-reload, as by a package update, would start a relative timer again.
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() + seconds))
        c.run(["systemd-run", "--unit=" + name, "--collect", "--on-calendar=" + when, "--timer-property=AccuracySec=1s"] + list(argv))

    def unschedule(self, name):
        c.run(["systemctl", "stop", name + ".timer"], check=False)

    def reboot(self):
        c.run(["systemctl", "reboot"])

    def guest_tools(self):
        res = c.run(["systemd-detect-virt", "--vm"], check=False)
        return self.GUEST_TOOLS.get(res.stdout.strip())

    # ------------------------------------------------ firewall
    def run_later(self, unit, seconds, command):
        c.run(["systemctl", "stop", unit + ".timer"], check=False)
        c.run(["systemd-run", "--unit=" + unit, "--collect", "--on-active=%d" % seconds, "--timer-property=AccuracySec=10s"] + list(command), check=False)

    def nft_apply(self, script):
        done = c.run(["nft", "-f", "-"], input_text=script, check=False)
        return done.returncode == 0, (done.stderr or "")[-300:]

    def nft_has_table(self, family, name):
        return c.run(["nft", "list", "table", family, name], check=False).returncode == 0

    def firewall_allow(self, logical_names):
        changed = False
        names = [self.FIREWALL_SERVICES[n] for n in logical_names]
        online = self.service_is_active("firewalld")
        if online:
            tools = (["firewall-cmd", "--permanent"], ["firewall-cmd"])
        else:
            tools = (["firewall-offline-cmd"],)
        for tool in tools:
            for svc in names:
                query = c.run(tool + ["--query-service=" + svc], check=False)
                if query.returncode != 0:
                    c.run(tool + ["--add-service=" + svc])
                    changed = True
        # No full firewall reload: permanent and runtime are changed separately.
        self.service_enable("firewalld", start=True)
        return changed

    # ------------------------------------------------ users and groups
    def user_exists(self, name):
        return c.run(["getent", "passwd", name], check=False).returncode == 0

    def group_members(self, group):
        res = c.run(["getent", "group", group], check=False)
        if res.returncode != 0:
            return None
        fields = res.stdout.strip().split(":")
        return [m for m in fields[3].split(",") if m] if len(fields) > 3 else []

    def user_add(self, name, groups, comment):
        c.run(["useradd", "-m", "-G", ",".join(groups), "-c", comment, name])

    def user_add_to_group(self, name, group):
        c.run(["usermod", "-a", "-G", group, name])

    def set_password(self, user, password):
        if any(ch in password for ch in "\r\n\0"):
            raise c.InputError("password contains a line break")
        if password.startswith(CRYPT_PREFIXES):
            cmd = ["chpasswd", "-e"]
        else:
            cmd = ["chpasswd", "-c", "SHA512"]
        c.run(cmd, input_text="%s:%s\n" % (user, password), secret=True)

    # ------------------------------------------------ host and network
    def set_hostname(self, fqdn):
        changed = c.write_file(self.PATHS["hostname_file"], fqdn + "\n")
        if self.manager_running():
            c.run(["hostnamectl", "set-hostname", fqdn])
        return changed

    def set_timezone(self, zone, hardware_clock_utc):
        if self.manager_running():
            c.run(["timedatectl", "set-timezone", zone])
            c.run(["timedatectl", "set-local-rtc",
                   "0" if hardware_clock_utc else "1"])
            return
        link = rp(self.PATHS["localtime"])
        tmp = link + ".efa-new"
        if os.path.lexists(tmp):
            os.unlink(tmp)
        os.symlink("../usr/share/zoneinfo/" + zone, tmp)
        os.replace(tmp, link)

    def interface_exists(self, iface):
        return os.path.exists(rp("/sys/class/net/" + iface))

    def _connection_for(self, iface):
        res = c.run(["nmcli", "-t", "-f", "UUID,DEVICE", "connection", "show"])
        uuids = []
        for line in res.stdout.splitlines():
            uuid, _, device = line.partition(":")
            if device == iface:
                return uuid
            uuids.append(uuid)
        for uuid in uuids:
            res = c.run(["nmcli", "-g", "connection.interface-name",
                         "connection", "show", uuid], check=False)
            if res.stdout.strip() == iface:
                return uuid
        return None

    def configure_interface(self, iface, ipv4, ipv6):
        uuid = self._connection_for(iface)
        if uuid is None:
            name = "efa-" + iface
            c.run(["nmcli", "connection", "add", "type", "ethernet",
                   "ifname", iface, "con-name", name])
            uuid = c.run(["nmcli", "-g", "connection.uuid", "connection",
                          "show", name]).stdout.strip()
        args = ["connection.autoconnect", "yes"]
        if ipv4 is None:
            args += ["ipv4.method", "auto", "ipv4.addresses", "", "ipv4.gateway", ""]
        else:
            addr, prefix, gateway = ipv4
            args += ["ipv4.method", "manual", "ipv4.addresses",
                     "%s/%d" % (addr, prefix), "ipv4.gateway", gateway]
        if ipv6 == "disabled":
            args += ["ipv6.method", "disabled", "ipv6.addresses", "", "ipv6.gateway", ""]
        elif ipv6 is None:
            args += ["ipv6.method", "auto", "ipv6.addresses", "", "ipv6.gateway", ""]
        else:
            addr, prefix, gateway = ipv6
            args += ["ipv6.method", "manual", "ipv6.addresses",
                     "%s/%d" % (addr, prefix), "ipv6.gateway", gateway]
        # Not activated now: the wizard is reached over the old address.
        # The new settings apply at the reboot that ends the setup.
        c.run(["nmcli", "connection", "modify", uuid] + args)

    def firewall_rich_rule(self, rule, add):
        zones = [line.split()[0] for line in c.run(["firewall-cmd", "--get-active-zones"]).stdout.splitlines()
                 if line.strip() and not line.startswith((" ", "\t"))]
        for zone in zones:
            for tool in (["firewall-cmd", "--permanent"], ["firewall-cmd"]):
                there = c.run(tool + ["--zone=" + zone, "--query-rich-rule=" + rule], check=False).returncode == 0
                if add and not there:
                    c.run(tool + ["--zone=" + zone, "--add-rich-rule=" + rule])
                elif not add and there:
                    c.run(tool + ["--zone=" + zone, "--remove-rich-rule=" + rule])
        return zones

    def use_local_resolver(self, secondary=None):
        header = "# SPDX-License-Identifier: AGPL-3.0-or-later\n" \
                 "# Copyright (C) 2026 Markus Lorber and eFa-next contributors\n" \
                 "# Author: Markus Lorber, Lukasz Galusinski\n"
        changed = c.write_file(self.PATHS["nm_dns_conf"], header +
                               "# eFa-next: the local Unbound resolver serves DNS.\n"
                               "[main]\ndns=none\n")
        if changed:
            self.service_reload_if_active("NetworkManager")
        changed |= c.write_file(self.PATHS["resolv_conf"],
                                "# eFa-next: local resolver (Unbound)\n"
                                "nameserver 127.0.0.1\n" + ("nameserver %s\n" % secondary if secondary else "") +
                                "options edns0 trust-ad\n")
        return changed

    def has_default_route(self):
        for line in c.read_text("/proc/net/route", "").splitlines()[1:]:
            fields = line.split()
            if len(fields) > 1 and fields[1] == "00000000":
                return True
        for line in c.read_text("/proc/net/ipv6_route", "").splitlines():
            fields = line.split()
            if len(fields) >= 10 and fields[0] == "0" * 32 \
                    and fields[1] == "00" and fields[9] != "lo":
                return True
        return False

    def ipv6_available(self):
        # From the kernel's own switches, without opening an IPv6 socket: that would load the module, and from a confined
        # program SELinux denies it (net-pf-10).
        if "ipv6.disable=1" in c.read_text("/proc/cmdline", "").split():
            return False
        if not os.path.isdir(rp("/proc/sys/net/ipv6")):
            return False
        return c.read_text("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1").strip() == "0"

    # ------------------------------------------------ time
    NTP_MARK = "# eFa-next: the time sources of the setup wizard"

    def ntp_servers(self):
        found = []
        for line in c.read_text(self.PATHS["chrony_conf"], "").splitlines():
            fields = line.split()
            if len(fields) > 1 and fields[0] in ("server", "pool"):
                found.append(fields[1])
        return found

    def set_ntp_servers(self, servers):
        path = self.PATHS["chrony_conf"]
        old = c.read_text(path, "")
        keep = [line for line in old.splitlines() if line != self.NTP_MARK and line.split()[:1] not in (["server"], ["pool"])]
        new = "\n".join([self.NTP_MARK] + ["server %s iburst" % server for server in servers] + keep) + "\n"
        if new == old:
            return False
        c.write_file(path, new, 0o644)
        self.service_restart(self.service("time"))
        return True

    def _clock_offset(self):
        # chronyc -c tracking: reference id, name, stratum, reference time, offset of the system clock in seconds, ...
        result = c.run(["chronyc", "-c", "tracking"], check=False)
        try:
            return float(result.stdout.split(",")[4])
        except (IndexError, ValueError, AttributeError):
            return None

    def time_sync(self):
        self.service_enable(self.service("time"), start=True)
        before = self._clock_offset()
        # A new VM is often minutes off: measure at once, then set the clock in one step instead of slewing for hours.
        c.run(["chronyc", "-a", "burst", "4/4"], check=False)
        c.run(["chronyc", "waitsync", "10", "0", "0", "2"], check=False)
        c.run(["chronyc", "-a", "makestep"], check=False)
        synced = c.run(["chronyc", "waitsync", "15", "1", "0", "2"], check=False).returncode == 0
        return before, self._clock_offset(), synced

    # ------------------------------------------------ Postfix lookup tables
    # Berkeley DB (hash) on EL9; EL10 has no Berkeley DB in Postfix and uses lmdb. A host whose default_database_type is set
    # otherwise (lmdb with postfix-lmdb on EL9) keeps its own: EL9 stays on hash until hosts are switched on purpose.
    MAP_TYPE = "hash"
    MAP_TYPES = ("hash", "btree", "lmdb", "cdb")

    def map_type(self):
        found = (c.run(["postconf", "-h", "default_database_type"], check=False).stdout or "").strip()
        return found if found in self.MAP_TYPES else self.MAP_TYPE

    # ------------------------------------------------ release upgrade (ELevate)
    def release_facts(self, avc_since=("boot",)):
        def text(path):
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    return fh.read()
            except OSError:
                return ""

        def out(cmd):
            return (c.run(cmd, check=False).stdout or "").strip()

        def free(path):
            try:
                found = os.statvfs(path)
                return found.f_bavail * found.f_frsize
            except OSError:
                return 0
        try:
            scripts = os.listdir("/etc/sysconfig/network-scripts")
        except OSError:
            scripts = []
        addresses = sorted(line.split()[1] + " " + line.split()[3]
                           for line in out(["ip", "-o", "addr", "show", "scope", "global"]).splitlines()
                           if len(line.split()) > 3 and "/" in line.split()[3])
        routes = sorted(re.sub(r"\s+(expires \S+|proto \S+|metric \d+|pref \S+)", "", line).strip()
                        for line in (out(["ip", "route", "show", "default"]) + "\n" + out(["ip", "-6", "route", "show", "default"])).splitlines()
                        if line.strip())
        firewall = {}
        for line in out(["firewall-cmd", "--get-active-zones"]).splitlines():
            if line and not line.startswith(" "):
                zone = line.split()[0]
                firewall[zone] = {what: sorted(out(["firewall-cmd", "--zone=" + zone, "--list-" + what]).split())
                                  for what in ("services", "ports", "interfaces", "sources")}
                firewall[zone]["rich_rules"] = sorted(out(["firewall-cmd", "--zone=" + zone, "--list-rich-rules"]).splitlines())
                # firewalld 2 (EL10) lists the default zone as "public (default)" also without an interface or a source; such a
                # zone takes no traffic, and firewalld 1 (EL9) does not list it: the same zones on both sides.
                if not firewall[zone]["interfaces"] and not firewall[zone]["sources"]:
                    del firewall[zone]
        tables = {}
        for line in out(["nft", "list", "tables"]).splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[2] != "firewalld":
                tables[parts[1] + " " + parts[2]] = out(["nft", "list", "table", parts[1], parts[2]])
        drivers = {}
        for name in sorted(os.listdir("/sys/class/net")) if os.path.isdir("/sys/class/net") else []:
            link = "/sys/class/net/%s/device/driver" % name
            if os.path.islink(link):
                drivers[name] = os.path.basename(os.readlink(link))
        avc = c.run(["ausearch", "-m", "avc", "-ts"] + list(avc_since), check=False).stdout or ""
        # Network teaming (teamd): EL10 has none. The connections of NetworkManager and the links of the kernel.
        team = {line.rsplit(":", 1)[0] for line in out(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"]).splitlines()
                if line.rsplit(":", 1)[-1] in ("team", "team-slave")}
        team |= {line.split(":")[1].strip().split("@")[0] for line in out(["ip", "-d", "-o", "link", "show"]).splitlines()
                 if re.search(r"\b(team|team_slave)\b", line) and len(line.split(":")) > 2}
        # The Wazuh agent of the operator: what the release upgrade must carry over as it is.
        wazuh = {}
        if c.run(["rpm", "-q", "wazuh-agent"], check=False).returncode == 0:
            def digest(path):
                try:
                    with open(path, "rb") as fh:
                        return hashlib.sha256(fh.read()).hexdigest()
                except OSError:
                    return ""
            wazuh = {"version": out(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", "wazuh-agent"]),
                     "enabled": out(["systemctl", "is-enabled", "wazuh-agent"]) or "unknown",
                     "active": out(["systemctl", "is-active", "wazuh-agent"]) or "unknown",
                     "ossec_conf": digest("/var/ossec/etc/ossec.conf"), "client_keys": digest("/var/ossec/etc/client.keys")}
            # The program itself still runs (its libraries on this release): -V prints the version and ends, it starts nothing.
            done = c.run(["/var/ossec/bin/wazuh-agentd", "-V"], check=False)
            wazuh["runs"] = done.returncode == 0 and "Wazuh" in (done.stdout or "") + (done.stderr or "")
        third_party = sorted(line for line in out(["dnf", "-q", "repoquery", "--installed", "--qf", "%{name} %{from_repo}\n"]).splitlines()
                             if len(line.split()) == 2)
        return {"os_release": text("/etc/os-release"), "kernel": os.uname().release, "cpuinfo": text("/proc/cpuinfo"),
                "wazuh": wazuh, "installed_from": third_party,
                "free_root": free("/"), "free_boot": free("/boot"), "ifcfg": scripts,
                "time_synced": out(["timedatectl", "show", "-p", "NTPSynchronized", "--value"]) == "yes",
                "packages": out(["rpm", "-qa", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n"]).splitlines(),
                "dnf_check": out(["dnf", "-q", "check"]), "selinux": out(["getenforce"]),
                "enabled_units": sorted(line.split()[0] for line in out(["systemctl", "list-unit-files", "efa-*", "--state=enabled",
                                                                         "--no-legend", "--plain"]).splitlines() if line.split()),
                "avc": avc.count("type=AVC"), "net_drivers": drivers, "team": sorted(team), "addresses": addresses, "routes": routes, "firewall": firewall, "nft_tables": tables,
                "active": [line.split()[0][:-len(".service")] for line in out(["systemctl", "list-units", "--type=service", "--state=active",
                                                                               "--no-legend", "--plain"]).splitlines()
                           if line.split() and line.split()[0].endswith(".service")]}

    def release_key_fingerprints(self, key_path):
        """The fingerprints in a key file, read without importing it."""
        out = c.run(["gpg", "--show-keys", "--with-colons", key_path], check=False).stdout or ""
        return [line.split(":")[9].upper() for line in out.splitlines() if line.startswith("fpr:")]

    def release_signature(self, path, key_path):
        """S22: the key imported into rpm, then (rpm -K of the package, its signature) for the caller to judge."""
        c.run(["rpm", "--import", key_path])
        checksig = c.run(["rpm", "-K", path], check=False)
        signature = c.run(["rpm", "-qp", "--qf", "%{RSAHEADER:pgpsig} %{SIGPGP:pgpsig}", path], check=False)
        return (checksig.stdout or "") + (checksig.stderr or ""), signature.stdout or ""

    def release_prepare(self, release_rpm, packages):
        """release_rpm: a local package already checked by release_signature, or None (the tool comes from the enabled
        repositories). dnf checks the local package against the imported keys once more."""
        if release_rpm and not self.package_installed("elevate-release"):
            done = c.run(["dnf", "-y", "--setopt=localpkg_gpgcheck=1", "install", release_rpm], check=False)
            if done.returncode != 0:
                return False, (done.stderr or done.stdout or "")[-500:]
        done = c.run(["dnf", "-y", "install"] + list(packages), check=False)
        return done.returncode == 0, (done.stderr or done.stdout or "")[-500:]

    def release_cleanup(self, packages):
        """After the upgrade: the upgrade tool and its repository go. (ok, last lines of the output)."""
        installed = [name for name in packages if self.package_installed(name)]
        if not installed:
            return True, ""
        # leapp's names are on the exclude= line of dnf.conf: without --disableexcludes dnf skips them and still ends with 0.
        done = c.run(["dnf", "-y", "--disableexcludes=main", "remove"] + installed, check=False)
        left = [name for name in installed if self.package_installed(name)]
        output = (done.stderr or done.stdout or "")[-500:]
        return done.returncode == 0 and not left, ("still installed: " + ", ".join(left) + " " if left else "") + output

    def release_package_unchanged(self, paths):
        """The paths that are files of an installed package with the content it ships: rpm -V reports neither size (S),
        digest (5) nor link target (L), and the file is there. Mode, owner, group or time alone (an eFa 5 host, a copy)
        change no setting."""
        paths = list(paths)
        if not paths:
            return set()
        owned = {}
        for path, line in zip(paths, (c.run(["rpm", "-qf", "--qf", "%{NAME}\\n"] + paths, check=False).stdout or "").splitlines()):
            if " " not in line.strip():
                owned.setdefault(line.strip(), []).append(path)
        unchanged = set()
        for name, files in owned.items():
            changed = {line.split()[-1] for line in (c.run(["rpm", "-V", name], check=False).stdout or "").splitlines()
                       if line.split() and rpm_verify_content_changed(line)}
            unchanged |= {path for path in files if path not in changed}
        return unchanged

    def release_leapp_busy(self):
        """Whether leapp still runs its own phase after the upgrade (leapp_resume.service, or a leapp process)."""
        state = (c.run(["systemctl", "show", "-p", "ActiveState", "--value", "leapp_resume.service"], check=False).stdout or "").strip()
        return state in ("active", "activating", "reloading") or c.run(["pgrep", "-f", "leapp3? upgrade --resume"], check=False).returncode == 0

    def release_service_states(self, names, prefix):
        listed = (c.run(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--plain"], check=False).stdout or "")
        units = [line.split()[0] for line in listed.splitlines() if line.split() and line.split()[0].endswith(".service")
                 and "@" not in line.split()[0] and (line.split()[0].startswith(prefix) or line.split()[0][:-8] in names)]
        # Instances of templates (clamd@scan) are not listed as such: asked one by one.
        units += [name + ".service" for name in names if "@" in name
                  and (c.run(["systemctl", "is-enabled", name + ".service"], check=False).stdout or "").strip() == "enabled"]
        if not units:
            return {}
        shown = c.run(["systemctl", "show", "-p", "Id", "-p", "Type", "-p", "ActiveState"] + sorted(set(units)), check=False).stdout or ""
        states = {}
        for block in shown.split("\n\n"):
            item = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
            if item.get("Id", "").endswith(".service"):
                states[item["Id"][:-8]] = (item.get("Type", ""), item.get("ActiveState", ""))
        return states

    def release_leftover_facts(self, names):
        names = sorted(set(names))
        if not names:
            return {}, set()
        needed = {}
        for name in names:
            done = c.run(["dnf", "-q", "repoquery", "--installed", "--whatrequires", name, "--qf", "%{name}\n"], check=False)
            needed[name] = sorted({line.strip() for line in (done.stdout or "").splitlines() if line.strip() and line.strip() != name})
        users = c.run(["dnf", "-q", "repoquery", "--userinstalled", "--qf", "%{name}\n"], check=False).stdout or ""
        return needed, {line.strip() for line in users.splitlines() if line.strip()}

    def release_remove_packages(self, names):
        names = sorted(set(names))
        if not names:
            return True, ""
        # rpm -e removes exactly these and refuses when another package still needs one of them.
        done = c.run(["rpm", "-e"] + names, check=False)
        left = [name for name in names if self.package_installed(name)]
        return done.returncode == 0 and not left, (("still installed: " + ", ".join(left) + " ") if left else "") + (done.stderr or done.stdout or "")[-300:]

    def release_enforce(self):
        """SELinux back to enforcing, now and after the next boot (leapp sets it to permissive for the upgrade)."""
        path = "/etc/selinux/config"
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            fixed = re.sub(r"(?m)^SELINUX=\w+", "SELINUX=enforcing", text)
            if fixed != text:
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(fixed)
        except OSError:
            pass
        c.run(["setenforce", "1"], check=False)
        return (c.run(["getenforce"], check=False).stdout or "").strip()

    def release_recover_script(self, log, finish_mark, repo_dir, motd, efactl="/usr/sbin/efactl", os_release="/etc/os-release"):
        """The safety net of the release upgrade, run at the first EL10 boot (efa_release_upgrade.recover_files): without
        efactl it installs eFa-next again from the EL10 repository in repo_dir and runs the checks; else maintenance stays."""
        return f'''#!/bin/sh
# eFa-next release upgrade, safety net: written by efactl release-upgrade start, part of no package.
# First EL10 boot without efactl (leapp removed eFa-next): install it again from the EL10 repository, then run the checks.
LOG={log}
say() {{ echo "$(date '+%F %T') recover: $*" >> "$LOG"; echo "recover: $*"; }}
mkdir -p "$(dirname "$LOG")"
[ -e {finish_mark} ] || exit 0
[ -x {efactl} ] && {{ say "efactl is there: nothing to do"; exit 0; }}
. {os_release}
case "$VERSION_ID" in
    10|10.*) ;;
    *) say "not on EL10 ($VERSION_ID): nothing done"; exit 0 ;;
esac
say "eFa-next is missing after the upgrade: installing it from the EL10 repository"
if dnf -y --setopt=reposdir=/etc/yum.repos.d,{repo_dir} install eFa-next eFa-next-base >> "$LOG" 2>&1 && [ -x {efactl} ]; then
    systemctl daemon-reload
    say "eFa-next is installed again: the checks run once leapp has ended its own phase"
    # Not run from here: the unit waits for leapp_resume.service, this script runs before it.
    systemctl start --no-block efa-release-upgrade-finish.service
    exit 0
fi
say "FAILED: eFa-next could not be installed again. Maintenance stays on: new mail gets 421. The way back is the VM snapshot."
mkdir -p "$(dirname {motd})"
printf '%s\\n' "eFa-next release upgrade: eFa-next is missing and could not be installed again." \\
    "Maintenance stays on (new mail gets 421). See $LOG. The way back is the VM snapshot." > {motd}
exit 1
'''

    def release_leapp(self, args, log_path):
        done = c.run(["leapp"] + list(args), check=False)
        with open(log_path, "a", encoding="utf-8") as log:
            log.write((done.stdout or "") + (done.stderr or ""))
        return done.returncode

    # ------------------------------------------------ SELinux
    def mac_enabled(self):
        if self._mac is None:
            self._mac = c.have("selinuxenabled") and c.run(
                ["selinuxenabled"], check=False).returncode == 0
        return self._mac

    def apply_policy_module(self, path):
        if not self.mac_enabled():
            c.info("SELinux is not enabled; policy module skipped")
            return False
        with open(rp(path), "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        stamp = self.PATHS["state_dir"] + "/selinux-efa.sha256"
        listed = c.run(["semodule", "-l"]).stdout.split()
        # What is loaded decides, not the stamp: a downgrade, a restore with an old stamp or a semodule -r leave the stamp
        # saying 1.4.0 while another module (or none) is in the policy. The stamp is only written as a record.
        if "efa" in listed and self.loaded_policy_digest("efa") == digest:
            if c.read_text(stamp, "").strip() != digest:
                c.write_file(stamp, digest + "\n")
            return False
        c.run(["semodule", "-i", rp(path)])
        c.write_file(stamp, digest + "\n")
        # NGINX-PID: a pid file of nginx made before the rule (var_run_t) gets the type of nginx, before nginx starts again.
        if os.path.exists(rp("/run/nginx.pid")) and c.have("restorecon"):
            c.run(["restorecon", "-F", rp("/run/nginx.pid")], check=False)
        return True

    def loaded_policy_digest(self, name):
        """SHA-256 of the module package as the policy holds it (libsemanage keeps the installed .pp as hll in its store,
        bzip2 packed when compression is on), the highest priority first; None when it is not in the store. On EL9 a
        module has no version any more (CIL drops the one of policy_module), so its content is compared."""
        kind = "targeted"
        for line in c.read_text("/etc/selinux/config", "").splitlines():
            if line.startswith("SELINUXTYPE="):
                kind = line.split("=", 1)[1].strip() or kind
        store = rp("/var/lib/selinux/%s/active/modules" % kind)
        try:
            priorities = sorted((entry for entry in os.listdir(store) if entry.isdigit()), key=int, reverse=True)
        except OSError:
            return None
        for priority in priorities:
            hll = os.path.join(store, priority, name, "hll")
            if os.path.isfile(hll):
                with open(hll, "rb") as fh:
                    data = fh.read()
                if data[:3] == b"BZh":
                    import bz2
                    try:
                        data = bz2.decompress(data)
                    except (OSError, ValueError):
                        return None
                return hashlib.sha256(data).hexdigest()
        return None

    def restore_context(self, path):
        if c.env.live and self.mac_enabled() and c.have("restorecon"):
            c.run(["restorecon", path], check=False)
