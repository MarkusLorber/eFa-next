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


class EL9(Platform):
    name = "el9"
    root_group = "root"

    PATHS = {
        "efa_etc": "/etc/eFa",
        "efa_config": "/etc/eFa/eFa-Config",
        "mysql_config": "/etc/eFa/MySQL-Config",
        "version_file": "/etc/eFa-Version",
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
    }
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
                    "efa-time-sync.service")
    ACCOUNTS = {
        "clamav_user": "clamscan", "av_group": "virusgroup",
        "postfix_group": "postfix", "web_group": "efa-web",
        "rspamd_user": "_rspamd", "wizard_user": "efa-init",
        "admin_group": "wheel",
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

    @staticmethod
    def _unit(name):
        return name if "." in name else name + ".service"

    def service_exists(self, name):
        unit = self._unit(name)
        names = [unit]
        if "@" in unit:
            names.append(unit.split("@", 1)[0] + "@" + unit[unit.rfind("."):])
        return any(os.path.exists(rp(os.path.join(d, n)))
                   for d in UNIT_DIRS for n in names)

    def service_enable(self, name, start=False):
        cmd = ["systemctl", "enable", "--quiet"]
        if start and self.manager_running():
            cmd.append("--now")
        c.run(cmd + [name])

    def service_disable(self, name, stop=False):
        cmd = ["systemctl", "disable", "--quiet"]
        if stop and self.manager_running():
            cmd.append("--now")
        c.run(cmd + [name])

    def service_is_active(self, name):
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

    def service_is_enabled(self, name):
        res = c.run(["systemctl", "is-enabled", name], check=False)
        return res.stdout.strip() == "enabled"

    def service_start(self, name):
        if not self.manager_running():
            raise StepError("cannot start %s: systemd is not running" % name)
        c.run(["systemctl", "start", name])

    def service_stop(self, name):
        if self.manager_running():
            c.run(["systemctl", "stop", name])

    def service_restart(self, name, check=True):
        if not self.manager_running():
            if check:
                raise StepError("cannot restart %s: systemd is not running" % name)
            return None
        return c.run(["systemctl", "restart", name], check=check)

    def service_start_background(self, name):
        """Start without waiting for it (a oneshot from a package script); a failure is only logged."""
        if self.manager_running():
            c.run(["systemctl", "start", "--no-block", name], check=False)

    def service_try_restart(self, name):
        if self.manager_running():
            c.run(["systemctl", "try-restart", name])

    def service_reload_if_active(self, name):
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

    def listening(self):
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
            if pid:
                try:
                    exe = os.readlink("/proc/%s/exe" % pid)
                except OSError:
                    exe = ""
                if exe and exe not in packages:
                    q = c.run(["rpm", "-qf", "--qf", "%{NAME}", exe], check=False)
                    packages[exe] = q.stdout.strip() if q.returncode == 0 else ""
                package = packages.get(exe, "")
            found.append({"proto": proto, "address": address.strip("[]"), "port": int(port) if port.isdigit() else 0,
                          "process": process, "package": package})
        return found

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

    def use_local_resolver(self):
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
                                "nameserver 127.0.0.1\noptions edns0 trust-ad\n")
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
        if c.read_text(stamp, "").strip() == digest and "efa" in listed:
            return False
        c.run(["semodule", "-i", rp(path)])
        c.write_file(stamp, digest + "\n")
        return True

    def restore_context(self, path):
        if c.env.live and self.mac_enabled() and c.have("restorecon"):
            c.run(["restorecon", path], check=False)
