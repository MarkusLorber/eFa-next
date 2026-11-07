# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Configuration steps for the services of an eFa-next host.

Each step can run alone, is safe to repeat and raises StepError on failure.
The steps are platform-neutral: paths, service names, accounts and OS
commands come from the platform layer (efa_common.platform()).
"""

import os

import efa_common as c
from efa_common import P, StepError, rp

HEADER = ("# SPDX-License-Identifier: AGPL-3.0-or-later\n"
          "# Copyright (C) 2026 Markus Lorber and eFa-next contributors\n"
          "# Author: Markus Lorber, Lukasz Galusinski\n")

# ======================================================================= Postfix

MILTERS = "inet:127.0.0.1:11332, inet:127.0.0.1:8999"
# Must equal the default that efactl uses for message_size_limit (open point).
MESSAGE_SIZE_LIMIT = "26214400"
HASH_MAPS = ("transport", "helo_access", "recipient_canonical")
REGEXP_MAPS = ("header_checks", "milter_header_checks")


def postfix_file(name):
    return P("postfix_dir") + "/" + name


def postfix_fixed(db):
    """Parameters the eFa setup always enforces."""
    pf = postfix_file
    return {
        "inet_interfaces": "all",
        "inet_protocols": "all",
        "mydestination": "",
        "local_recipient_maps": "",
        "local_transport": "error:local mail delivery is disabled",
        "relay_domains": "%s:%s" % (db, pf("transport")),
        "transport_maps": "%s:%s" % (db, pf("transport")),
        "smtpd_relay_restrictions":
            "permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination",
        "smtpd_helo_required": "yes",
        "smtpd_helo_restrictions": "permit_mynetworks, check_helo_access %s:%s, "
                                   "reject_invalid_helo_hostname" % (db, pf("helo_access")),
        "smtpd_data_restrictions": "reject_unauth_pipelining",
        "header_checks": "regexp:" + pf("header_checks"),
        "recipient_canonical_maps": "%s:%s" % (db, pf("recipient_canonical")),
        "milter_default_action": "accept",
        "milter_protocol": "6",
        "unverified_recipient_reject_code": "550",
        "disable_vrfy_command": "yes",
        "enable_long_queue_ids": "yes",
        "smtpd_banner": "$myhostname ESMTP",
        "biff": "no",
        "append_dot_mydomain": "no",
        "smtpd_tls_security_level": "may",
        "smtpd_tls_cert_file": P("cert_file"),
        "smtpd_tls_key_file": P("key_file"),
        "smtpd_tls_loglevel": "1",
        "smtpd_tls_received_header": "yes",
        # TLS 1.2 or newer as BSI TR-03108 asks (a new install; an upgrade keeps the old value, efactl tls-min-set).
        "smtpd_tls_protocols": TLS_MIN,
        "smtpd_tls_mandatory_protocols": TLS_MIN,
        "smtpd_tls_auth_only": "yes",
        "smtpd_tls_session_cache_database": "btree:${data_directory}/smtpd_scache",
        "smtp_tls_security_level": "may",
        "smtp_tls_loglevel": "1",
        "smtp_tls_protocols": TLS_MIN,
        "smtp_tls_mandatory_protocols": TLS_MIN,
        "smtp_tls_session_cache_database": "btree:${data_directory}/smtp_scache",
        "smtpd_sasl_auth_enable": "no",
        "smtpd_sasl_type": "dovecot",
        "smtpd_sasl_path": "private/auth",
        "smtpd_sasl_security_options": "noanonymous",
        "smtpd_client_connection_count_limit": "20",
        "smtpd_client_connection_rate_limit": "60",
        "smtpd_client_auth_rate_limit": "10",
        "smtpd_error_sleep_time": "1s",
        "smtpd_soft_error_limit": "10",
        "smtpd_hard_error_limit": "20",
    }


def efactl_defaults():
    """Parameters that efactl edits later: set only while still unset."""
    return {
        "mynetworks": "127.0.0.0/8 [::1]/128",
        "message_size_limit": MESSAGE_SIZE_LIMIT,
        "smtpd_recipient_restrictions":
            "permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, "
            "reject_non_fqdn_recipient, reject_unknown_recipient_domain",
        "smtpd_milters": MILTERS,
        "milter_header_checks": "regexp:" + postfix_file("milter_header_checks"),
        "efa_submission_restrictions": "permit_sasl_authenticated, reject",
    }


# The form every Postfix knows: ">=TLSv1.2" needs 3.6, EL9 ships 3.5, which rejects it and then has no TLS.
TLS_MIN = "!SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
# Kernel settings of a new install (CIS AlmaLinux 9); efactl kernel-hardening-set for an upgraded one.
KERNEL_SETTINGS = {"net.ipv4.conf.all.accept_redirects": "0", "net.ipv4.conf.default.accept_redirects": "0",
                   "net.ipv6.conf.all.accept_redirects": "0", "net.ipv4.conf.all.send_redirects": "0",
                   "net.ipv4.conf.default.send_redirects": "0", "fs.suid_dumpable": "0"}

SUBMISSION = ("submission/inet", "submission inet n - n - - smtpd")
SUBMISSION_OPTIONS = {
    "syslog_name": "postfix/submission",
    "smtpd_tls_security_level": "encrypt",
    "smtpd_sasl_auth_enable": "yes",
    "smtpd_tls_auth_only": "yes",
    # efactl puts the submitter checks (8g) into this parameter of main.cf.
    "smtpd_relay_restrictions": "$efa_submission_restrictions",
    "smtpd_recipient_restrictions": "$efa_submission_restrictions",
    "milter_macro_daemon_name": "ORIGINATING",
}


def _parse_assignments(text):
    values = {}
    for line in text.splitlines():
        name, sep, value = line.partition("=")
        if sep:
            values[name.strip()] = value.strip()
    return values


class Postconf:
    """Small wrapper around postconf(1), the documented Postfix interface."""

    def __init__(self):
        self.explicit = _parse_assignments(c.run(["postconf", "-n"]).stdout)
        self.changed = False

    def get(self, name):
        if name in self.explicit:
            return self.explicit[name]
        return c.run(["postconf", "-h", name]).stdout.strip()

    def set(self, values, only_if_unset=False):
        todo = []
        for name, value in values.items():
            if only_if_unset and name in self.explicit:
                continue
            if self.explicit.get(name) != value:
                todo.append("%s=%s" % (name, value))
                self.explicit[name] = value
        if todo:
            c.run(["postconf", "-e"] + todo)
            self.changed = True

    def set_service(self, service, entry, options):
        current = c.run(["postconf", "-M", service], check=False).stdout.split()
        if current != entry.split():
            c.run(["postconf", "-M", "%s=%s" % (service, entry)])
            self.changed = True
        have = _parse_assignments(c.run(["postconf", "-P", service], check=False).stdout)
        for name, value in options.items():
            key = "%s/%s" % (service, name)
            if have.get(key) != value:
                c.run(["postconf", "-P", "%s=%s" % (key, value)])
                self.changed = True


def postmap(pc, name):
    db = pc.get("default_database_type") or "hash"
    c.run(["postmap", "%s:%s" % (db, rp(postfix_file(name)))])


def step_postfix():
    if not os.path.exists(rp(postfix_file("main.cf"))):
        raise StepError("Postfix is not installed: main.cf is missing")
    # First: postconf -n stops with an error if the stock "localhost" does not
    # resolve to a local address, and postconf -e does not check it.
    if c.run(["postconf", "-n"], check=False).returncode != 0:
        c.run(["postconf", "-e", "inet_interfaces=all"])
    pc = Postconf()
    db = pc.get("default_database_type") or "hash"
    for name in HASH_MAPS + REGEXP_MAPS:
        c.ensure_file(postfix_file(name), "")
    if not os.path.exists(rp(P("cert_file"))):
        # Placeholder until the setup makes one for the real host name.
        c.ensure_certificate(c.current_fqdn())
    pc.set(postfix_fixed(db))
    pc.set(efactl_defaults(), only_if_unset=True)
    pc.set_service(SUBMISSION[0], SUBMISSION[1], SUBMISSION_OPTIONS)
    for name in HASH_MAPS:
        postmap(pc, name)
    c.run(["postfix", "check"])
    mta = c.platform().service("mta")
    c.platform().service_enable(mta)
    if pc.changed:
        c.platform().service_reload_if_active(mta)


# ======================================================================= ClamAV

def clamd_settings():
    pl = c.platform()
    return {
        "LocalSocket": P("clamd_socket"),
        "LocalSocketGroup": pl.account("av_group"),
        "LocalSocketMode": "660",
        "FixStaleSocket": "yes",
        "User": pl.account("clamav_user"),
        "LogFile": P("clamd_log"),
        "LogTime": "yes",
        "LogSyslog": "no",
        "LogFileMaxSize": "20M",
        "LogRotate": "yes",
        "MaxThreads": "10",
        "StreamMaxLength": "64M",
        "MaxScanSize": "256M",
        "MaxFileSize": "64M",
        "MaxRecursion": "16",
        "MaxFiles": "10000",
        "ScanMail": "yes",
        "ScanArchive": "yes",
        "PhishingSignatures": "yes",
    }


def step_clamav():
    pl = c.platform()
    conf = P("clamd_conf")
    text = c.read_text(conf)
    changed = c.write_file(conf, c.set_directives(
        text, clamd_settings(), disable=("Example", "TCPSocket", "TCPAddr")))
    fresh = P("freshclam_conf")
    text = c.read_text(fresh)
    c.write_file(fresh, c.set_directives(
        text, {"NotifyClamd": conf}, disable=("Example",)))
    c.ensure_file(P("clamd_log"), "", 0o640, pl.account("clamav_user"),
                  pl.account("clamav_user"))
    # rspamd talks to clamd over the local socket.
    members = pl.group_members(pl.account("av_group"))
    rspamd = pl.account("rspamd_user")
    if members is not None and rspamd not in members and pl.user_exists(rspamd):
        pl.user_add_to_group(rspamd, pl.account("av_group"))
    pl.service_enable(pl.service("avupdate"), start=True)
    pl.service_enable(pl.service("av"))
    if changed:
        pl.service_try_restart(pl.service("av"))


# ======================================================================= MariaDB

MARIADB_CONF = HEADER + """\
# eFa: local database for eFa-next.
[mysqld]
bind-address = 127.0.0.1
skip-name-resolve
max_connections = 100
innodb_buffer_pool_size = 256M
key_buffer_size = 16M
tmp_table_size = 32M
max_heap_table_size = 32M
performance_schema = OFF
"""


def step_mariadb():
    pl = c.platform()
    db = pl.service("db")
    changed = c.write_file(P("mariadb_conf"), MARIADB_CONF)
    changed |= pl.service_set_open_files(db, 16384)
    pl.service_enable(db)
    if changed:
        pl.service_try_restart(db)


# ======================================================================= Unbound

def render_unbound(ipv6):
    interfaces = ["127.0.0.1"] + (["::1"] if c.platform().ipv6_available() else [])
    lines = [HEADER.rstrip("\n"), "# eFa: local resolver for this host only.", "server:"]
    lines += ["    interface: %s" % i for i in interfaces]
    lines += [
        "    access-control: 127.0.0.0/8 allow",
        "    access-control: ::1/128 allow",
        # Without these three, Unbound uses its built-in chroot.
        "    chroot: \"\"",
        "    username: \"unbound\"",
        "    directory: \"%s\"" % os.path.dirname(P("unbound_conf")),
        "    do-ip4: yes",
        "    do-ip6: %s" % ("yes" if ipv6 else "no"),
        "    use-syslog: yes",
        "    pidfile: \"%s\"" % P("unbound_pidfile"),
        "    hide-identity: yes",
        "    hide-version: yes",
        "    harden-glue: yes",
        "    harden-dnssec-stripped: yes",
        "    qname-minimisation: yes",
        "    prefetch: yes",
        "    auto-trust-anchor-file: \"%s\"" % P("unbound_root_key"),
        "    include: \"%s/*.conf\"" % P("unbound_local_d"),
        "",
        "remote-control:",
        "    control-enable: no",
        "",
        "# Forwarding chosen in the setup (empty for full recursion).",
        "include: \"%s\"" % P("unbound_forward"),
        "# Zones managed by efactl.",
        "include: \"%s/*.conf\"" % P("unbound_conf_d"),
    ]
    return "\n".join(lines) + "\n"


def render_forward(servers):
    if not servers:
        return HEADER + "# eFa: full recursion, no forwarders.\n"
    lines = [HEADER.rstrip("\n"), "forward-zone:", "    name: \".\""]
    lines += ["    forward-addr: %s" % s for s in servers]
    return "\n".join(lines) + "\n"


def _check_unbound(tmp):
    if c.have("unbound-checkconf") and os.path.exists(rp(P("unbound_root_key"))):
        c.run(["unbound-checkconf", tmp])


def write_unbound(ipv6):
    for folder in ("unbound_conf_d", "unbound_local_d"):
        os.makedirs(rp(P(folder)), exist_ok=True)
    c.ensure_file(P("unbound_forward"), render_forward(None))
    return c.write_file(P("unbound_conf"), render_unbound(ipv6), validate=_check_unbound)


def step_unbound():
    pl = c.platform()
    dns = pl.service("dns")
    ipv6 = c.read_kv(P("efa_config")).get("IPV6DNS", "NO") == "YES"
    changed = write_unbound(ipv6)
    changed |= pl.service_start_after_network(dns)
    pl.service_enable(dns)
    if changed:
        pl.service_try_restart(dns)


# ======================================================================= System

BANNER = ("Authorized access only. Activity on this system is logged and may "
          "be monitored.\n")


def sshd_hardening():
    return HEADER + """\
# eFa: SSH hardening. Files in this folder are read in name order and the
# first value wins, so this file comes before the vendor defaults.
PermitRootLogin prohibit-password
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
Banner %s
""" % P("ssh_banner")


def write_sshd_dropin(path, content):
    """Write an sshd drop-in, check the full configuration, roll back on error."""
    old = c.read_text(path, "\0missing")
    changed = c.write_file(path, content)
    if not changed:
        return False
    res = c.run(["sshd", "-t"], check=False)
    if res.returncode != 0:
        if old == "\0missing":
            c.remove(path)
        else:
            c.write_file(path, old)
        raise StepError("sshd rejected the new configuration %s" % path)
    c.platform().service_reload_if_active(c.platform().service("ssh"))
    return True


NEEDED_SERVICES = ("ssh", "cron", "time", "network", "mta", "db", "redis",
                   "spam", "web", "dns", "avupdate", "av", "ban", "firewall")


def step_dirs():
    c.ensure_dir(P("efa_etc"), 0o755)
    c.ensure_dir(P("log_dir"), 0o750)
    c.ensure_dir(P("state_dir"), 0o750)
    c.ensure_dir(P("state_dir") + "/install-state", 0o750)
    for name in ("efa_config", "mysql_config"):
        if os.path.exists(rp(P(name))):
            c.set_owner_mode(P(name), 0o640 if name == "efa_config" else 0o600)


def step_system():
    pl = c.platform()
    c.write_file(P("ssh_banner"), BANNER)
    write_sshd_dropin(P("sshd_dropin"), sshd_hardening())
    missing = []
    for logical in NEEDED_SERVICES:
        name = pl.service(logical)
        if pl.service_exists(name):
            pl.service_enable(name)
        else:
            missing.append(name)
    for name in pl.UNNEEDED_SERVICES:
        if pl.service_exists(name):
            pl.service_disable(name, stop=True)
    pl.kernel_settings(KERNEL_SETTINGS)
    if missing:
        raise StepError("services not installed: %s" % ", ".join(missing))


# ======================================================================= Fail2Ban

def fail2ban_jails():
    return HEADER + """\
# eFa: default jails. Bans go through the firewall (fail2ban-firewalld).
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
backend = systemd

[postfix-sasl]
enabled = true
backend = systemd
"""


def step_fail2ban():
    pl = c.platform()
    ban = pl.service("ban")
    changed = c.write_file(P("fail2ban_jail"), fail2ban_jails())
    pl.service_enable(ban, start=True)
    if changed:
        pl.service_try_restart(ban)


# ======================================================================= updates

def step_auto_updates():
    c.platform().configure_auto_updates()


# ======================================================================= firewall

FIREWALL_OPEN = ("ssh", "smtp", "submission", "http", "https")


def step_firewall():
    c.platform().firewall_allow(FIREWALL_OPEN)


# ======================================================================= SELinux

def step_selinux():
    """Install the eFa policy module (no-op where the platform has none)."""
    c.platform().apply_policy_module(P("policy_module"))


# ======================================================================= table

INSTALL_STEPS = {
    "dirs": step_dirs,
    "selinux": step_selinux,
    "system": step_system,
    "postfix": step_postfix,
    "clamav": step_clamav,
    "mariadb": step_mariadb,
    "unbound": step_unbound,
    "fail2ban": step_fail2ban,
    "dnf-automatic": step_auto_updates,
    "firewalld": step_firewall,
}
INSTALL_ORDER = list(INSTALL_STEPS)
# An upgrade does not change settings: only these steps run.
UPGRADE_ORDER = ["dirs", "selinux"]
