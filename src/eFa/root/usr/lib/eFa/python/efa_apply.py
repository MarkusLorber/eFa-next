# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""efa-apply: apply the first-run settings of eFa-next (root program).

The web wizard (efa-init.py) calls it through one sudo rule:

    sudo -n /usr/sbin/efa-apply [--verbose] [--answers FILE|-] --all
    sudo -n /usr/sbin/efa-apply [--verbose] [--answers FILE|-] --hostname --dns ...

Answers are KEY:value lines, read from --answers FILE (mode 0600 or
stricter) or from stdin (the default when stdin is not a terminal).
Passwords are only accepted this way: never on the command line. Non-secret
answers are kept between calls in the setup folder, so single steps can run
in separate calls. Steps run in the documented order and stop at the first
failure. One line per step goes to stdout: "OK step" or "FAILED step: why".

Exit codes: 0 ok, 1 a step failed, 2 bad usage or input, 3 refused.
"""

import argparse
import base64
import hashlib
import os
import re
import secrets
import stat
import sys

import efa_common as c
import efa_services as s
from efa_common import P, InputError, StepError, rp

SETTING_KEYS = (
    "HOSTNAME", "DOMAINNAME", "ADMINEMAIL", "ORGNAME", "MAILSERVER",
    "INTERFACE", "IPV4ADDRESS", "IPV4NETMASK", "IPV4GATEWAY", "IPV6ADDRESS",
    "IPV6MASK", "IPV6GATEWAY", "IPV6DNS", "DNSIP1", "DNSIP2", "RECURSION",
    "TZONE", "ISUTC", "CLIUSERNAME", "VMTOOLS", "MAILSERVERDNS", "LEGALACCEPTED",
    "SETUPVARIANT", "EULINK", "EULINKCONFIRM", "FRAMEWORKS", "FRAMEWORKNOTE", "NOTICEACCEPTED", "SETUPLANG")
# The 2FA of the main admin from the guided setup: secret, last step, hashes of the recovery codes. Never kept in a file here.
SECRET_KEYS = ("ROOTPASSWORD", "CLIPASSWORD", "WEBADMINPASSWORD", "TOTPSECRET", "TOTPSTEP", "TOTPRECOVERY",
               "CONSOLETOTPSECRET", "CONSOLETOTPSTEP", "CONSOLETOTPRECOVERY")
CONFIRMED_RE = re.compile(r"^[0-9a-f]{16}/\d{9,11}$")
AUTO_VALUES = ("", "auto", "dhcp", "automatic")
PBKDF2_ITERATIONS = 600000
MIN_PASSWORD = 12

STEP_ORDER = ("mariadb", "hostname", "dns", "network", "sshkeys", "timezone",
              "transport", "sasl", "dbpasswords", "autoupdates", "passwords",
              "cert", "webadmin", "variant", "vmtools", "finish")


# ===================================================================== input

def _check_value(key, value):
    """Validate one answer. Return the normalised value or raise InputError."""
    if c.CONTROL_RE.search(value):
        raise InputError("%s contains control characters" % key)
    upper = value.upper()
    if key in ("RECURSION", "IPV6DNS", "ISUTC", "VMTOOLS"):
        if upper not in c.YES_NO:
            raise InputError("%s must be YES or NO" % key)
        return upper
    ok = True
    if key == "HOSTNAME":
        ok = c.valid_label(value)
    elif key == "DOMAINNAME":
        ok = c.valid_domain(value)
        value = value.lower()
    elif key == "ADMINEMAIL":
        ok = c.valid_email(value)
    elif key == "ORGNAME":
        ok = len(value) <= 128
    elif key == "LEGALACCEPTED":
        ok = bool(re.match(r"^[0-9a-f]{16}$", value))
    elif key == "SETUPVARIANT":
        ok = value in ("guided", "manual")
    elif key == "EULINK":
        ok = value in ("yes", "no")
    elif key == "SETUPLANG":
        ok = value in ("en", "de")
    elif key in ("NOTICEACCEPTED", "EULINKCONFIRM"):
        ok = value == "" or bool(CONFIRMED_RE.match(value))
    elif key == "FRAMEWORKS":
        ok = bool(re.match(r"^[a-z0-9,-]{0,400}$", value))
    elif key == "FRAMEWORKNOTE":
        ok = bool(re.match(r"^[\w .,;:()/&+'-]{0,200}$", value))
    elif key == "MAILSERVER":
        ok = c.valid_label(value) or c.valid_domain(value) or c.ip_version(value) > 0
    elif key == "INTERFACE":
        ok = bool(re.match(r"^[A-Za-z0-9_.-]{1,15}$", value))
    elif key == "IPV4ADDRESS":
        ok = value.lower() in AUTO_VALUES or c.ip_version(value) == 4
    elif key == "IPV6ADDRESS":
        ok = value.lower() in AUTO_VALUES + ("disabled",) or c.ip_version(value) == 6
    elif key in ("IPV4GATEWAY",):
        ok = value == "" or c.ip_version(value) == 4
    elif key in ("IPV6GATEWAY",):
        ok = value == "" or c.ip_version(value) == 6
    elif key in ("DNSIP1", "DNSIP2", "MAILSERVERDNS"):
        ok = value == "" or c.ip_version(value) > 0
    elif key == "IPV4NETMASK":
        ok = value == "" or _prefix_ok(value, 4)
    elif key == "IPV6MASK":
        ok = value == "" or _prefix_ok(value, 6)
    elif key == "TZONE":
        ok = bool(re.match(r"^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$", value)) \
            and os.path.isfile(rp(P("zoneinfo_dir") + "/" + value))
    elif key == "CLIUSERNAME":
        ok = bool(c.USER_RE.match(value)) and value != "root"
    if not ok:
        raise InputError("invalid value for %s" % key)
    return value


def _prefix_ok(value, version):
    try:
        c.netmask_prefix(value, version)
        return True
    except InputError:
        return False


def parse_answers(text):
    """Return (settings, secret) dicts from KEY:value text."""
    settings, secret = {}, {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            raise InputError("answer line without ':'")
        key, value = line.split(":", 1)
        key = key.strip()
        if key in SECRET_KEYS:
            if not value or any(ch in value for ch in "\r\n\0"):
                raise InputError("%s is empty or invalid" % key)
            secret[key] = value
        elif key in SETTING_KEYS:
            settings[key] = _check_value(key, value.strip())
        else:
            c.warn("ignored unknown answer key %s" % key)
    return settings, secret


def read_answers(source):
    if source == "-":
        return sys.stdin.read()
    fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, encoding="utf-8") as fh:
        info = os.fstat(fh.fileno())
        if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise InputError("answers file must not be readable by group or others")
        return fh.read()


def staging_file():
    return P("setup_dir") + "/settings"


def merged_settings(answers):
    """Saved settings, then staged answers, then the new answers."""
    cfg = c.read_kv(P("efa_config"))
    cfg.update(c.read_kv(staging_file()))
    cfg.update(answers)
    return cfg


def save_staging(answers):
    if not answers:
        return
    data = c.read_kv(staging_file())
    data.update(answers)
    c.ensure_dir(P("setup_dir"), 0o700)
    c.write_kv(staging_file(), data, 0o600)


def need(cfg, key):
    value = cfg.get(key, "")
    if value == "":
        raise InputError("%s is required for this step" % key)
    return value


LOCALHOST_NAME = re.compile(r"^localhost[46]?(\.localdomain[46]?)?$")


def hosts_localhost_only_loopback(text):
    """The localhost names off every line whose address is not loopback (127.0.0.0/8, ::1); the other names of a line stay.
    A line left without names goes. Returns the text and the lines as they were before."""
    out, moved = [], []
    for line in text.splitlines():
        body, hash_, comment = line.partition("#")
        fields = body.split()
        if len(fields) < 2 or fields[0].startswith("127.") or fields[0] == "::1":
            out.append(line)
            continue
        names = [name for name in fields[1:] if not LOCALHOST_NAME.match(name)]
        if len(names) == len(fields) - 1:
            out.append(line)
            continue
        moved.append(line.strip())
        if names:
            out.append(" ".join([fields[0]] + names) + ((" " + hash_ + comment) if hash_ else ""))
    return "\n".join(out) + "\n", moved


# ===================================================================== steps

def firstboot_marker():
    return P("state_dir") + "/firstboot-pending"


def reboot_marker():
    return P("state_dir") + "/setup-reboot"


class Steps:
    def __init__(self, cfg, secret):
        self.cfg = cfg
        self.secret = secret
        self.pl = c.platform()

    def fqdn(self):
        return "%s.%s" % (need(self.cfg, "HOSTNAME"), need(self.cfg, "DOMAINNAME"))

    # -- start MariaDB
    def mariadb(self):
        db = self.pl.service("db")
        self.pl.service_enable(db)
        self.pl.service_start(db)

    # -- host name and hosts file
    def hostname(self):
        fqdn = self.fqdn()
        short = need(self.cfg, "HOSTNAME")
        self.pl.set_hostname(fqdn)
        block = []
        for key in ("IPV4ADDRESS", "IPV6ADDRESS"):
            addr = self.cfg.get(key, "")
            if c.ip_version(addr):
                block.append("%s %s %s" % (addr, fqdn, short))
        hosts = P("hosts_file")
        text = c.read_text(hosts, "127.0.0.1 localhost localhost.localdomain\n"
                                  "::1 localhost localhost.localdomain\n")
        # Without localhost here the name goes to DNS, and Postfix with inet_interfaces=localhost may get a foreign address.
        if not re.search(r"^\s*127\.0\.0\.1\s+(.*\s)?localhost(\s|$)", text, re.M):
            text = "127.0.0.1 localhost localhost.localdomain\n" + text
        text, moved = hosts_localhost_only_loopback(text)
        if moved:
            c.write_file(hosts + ".efa-bak", c.read_text(hosts, ""))
            c.log("hosts: localhost names taken off addresses that are not loopback, before: %s" % " | ".join(moved))
        c.write_file(hosts, c.replace_block(text, block))
        pc = s.Postconf()
        pc.set({"myhostname": fqdn, "mydomain": need(self.cfg, "DOMAINNAME"),
                "myorigin": "$myhostname"})

    # -- DNS: Unbound as local resolver
    def dns(self):
        recursion = self.cfg.get("RECURSION", "YES")
        servers = []
        if recursion == "NO":
            servers = [v for v in (self.cfg.get("DNSIP1"), self.cfg.get("DNSIP2")) if v]
            if not servers:
                raise InputError("DNSIP1 is required when RECURSION is NO")
        changed = s.write_unbound(self.cfg.get("IPV6DNS", "NO") == "YES")
        changed |= c.write_file(P("unbound_forward"), s.render_forward(servers))
        dns = self.pl.service("dns")
        self.pl.service_enable(dns)
        if self.pl.manager_running():
            if changed or not self.pl.service_is_active(dns):
                self.pl.service_restart(dns)
        self.pl.use_local_resolver()

    # -- IP configuration
    def network(self):
        iface = need(self.cfg, "INTERFACE")
        if not self.pl.interface_exists(iface):
            raise InputError("network interface %s does not exist" % iface)
        v4 = self.cfg.get("IPV4ADDRESS", "")
        ipv4 = None
        if v4.lower() not in AUTO_VALUES:
            ipv4 = (v4, c.netmask_prefix(need(self.cfg, "IPV4NETMASK"), 4),
                    self.cfg.get("IPV4GATEWAY", ""))
        v6 = self.cfg.get("IPV6ADDRESS", "")
        if v6.lower() == "disabled":
            ipv6 = "disabled"
        elif v6.lower() in AUTO_VALUES:
            ipv6 = None
        else:
            ipv6 = (v6, c.netmask_prefix(need(self.cfg, "IPV6MASK"), 6),
                    self.cfg.get("IPV6GATEWAY", ""))
        self.pl.configure_interface(iface, ipv4, ipv6)

    # -- new SSH host keys
    def sshkeys(self):
        folder = rp(P("ssh_dir"))
        for name in os.listdir(folder):
            if name.startswith("ssh_host_") and "key" in name:
                os.unlink(os.path.join(folder, name))
        c.run(["ssh-keygen", "-A"])
        self.pl.service_try_restart(self.pl.service("ssh"))

    # -- time zone
    def timezone(self):
        zone = need(self.cfg, "TZONE")
        self.pl.set_timezone(zone, self.cfg.get("ISUTC", "YES") == "YES")

    # -- Postfix transport for the domain
    def transport(self):
        domain = need(self.cfg, "DOMAINNAME")
        server = need(self.cfg, "MAILSERVER")
        nexthop = "[ipv6:%s]" % server if c.ip_version(server) == 6 else "[%s]" % server
        entry = "%s smtp:%s" % (domain, nexthop)
        path = s.postfix_file("transport")
        lines, found = [], False
        for line in c.read_text(path, "").splitlines():
            fields = line.split()
            if fields and fields[0].lower() == domain:
                if not found:
                    lines.append(entry)
                    found = True
                continue
            lines.append(line)
        if not found:
            lines.append(entry)
        changed = c.write_file(path, "\n".join(lines) + "\n")
        # A name only an internal DNS server knows: its zone goes there, or mail to it bounces.
        dns = self.cfg.get("MAILSERVERDNS", "")
        if dns and "." in server and not c.ip_version(server):
            # The zone of an internal mail server is mostly unsigned below a signed public domain: without DNSSEC, as before.
            c.run([c.which("efactl"), "dns-zone-set", "--zone", server.split(".", 1)[1],
                   "--action", "add", "--servers", dns, "--dnssec", "off"])
        pc = s.Postconf()
        s.postmap(pc, "transport")
        if changed:
            self.pl.service_reload_if_active(self.pl.service("mta"))

    # -- SASL for the submission port
    def sasl(self):
        # The logins of port 587 are checked by efa-sasl (efactl submission-pam-set below). Dovecot only where it is still
        # installed, with only the socket for Postfix: no IMAP, no POP3.
        if not self.pl.service_exists(self.pl.service("sasl")):
            c.run([c.which("efactl"), "submission-pam-set", "--mode", "off"])
            c.run([c.which("efactl"), "content-reason-set", "--mode", "on"])
            self.pl.service_reload_if_active(self.pl.service("mta"))
            return
        conf = s.HEADER + (
            "# eFa-next: Dovecot serves only the SASL socket for the submission port.\n"
            "protocols =\n"
            "listen = *\n"
            "auth_mechanisms = plain login\n"
            "service auth {\n"
            "  unix_listener /var/spool/postfix/private/auth {\n"
            "    mode = 0660\n"
            "    user = postfix\n"
            "    group = postfix\n"
            "  }\n"
            "}\n")
        changed = c.write_file(P("sasl_conf"), conf)
        sasl = self.pl.service("sasl")
        self.pl.service_enable(sasl)
        if changed:
            self.pl.service_try_restart(sasl)
        # A new install: system accounts may not log in on port 587, only submitters (efactl submitter-set).
        c.run([c.which("efactl"), "submission-pam-set", "--mode", "off"])
        # Privacy defaults of a new install (Q7): a reason before the content of a mail is shown.
        c.run([c.which("efactl"), "content-reason-set", "--mode", "on"])
        self.pl.service_reload_if_active(self.pl.service("mta"))

    # -- new random database root password
    def dbpasswords(self):
        def mysql(sql, cnf=None, check=True):
            cmd = ["mysql"] + (["--defaults-extra-file=" + cnf] if cnf else [])
            return c.run(cmd + ["--protocol=socket", "-u", "root", "--batch"],
                         input_text=sql, check=check, secret=True)

        cnf = None
        try:
            if mysql("SELECT 1;\n", check=False).returncode != 0:
                old = c.read_kv(P("mysql_config")).get("MYSQLROOTPWD", "")
                if not old:
                    raise StepError("cannot log in to MariaDB as root")
                cnf = P("state_dir") + "/.efa-mysql.cnf"
                quoted = old.replace("\\", "\\\\").replace('"', '\\"')
                c.write_file(cnf, '[client]\npassword="%s"\n' % quoted, 0o600)
                cnf = rp(cnf)
            new = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789")
                          for _ in range(32))
            mysql("ALTER USER 'root'@'localhost' IDENTIFIED VIA unix_socket "
                  "OR mysql_native_password USING PASSWORD('%s');\n"
                  "DROP USER IF EXISTS ''@'localhost';\n"
                  "DROP DATABASE IF EXISTS test;\n"
                  "FLUSH PRIVILEGES;\n" % new, cnf)
        finally:
            if cnf:
                os.unlink(cnf)
        data = c.read_kv(P("mysql_config"))
        data["MYSQLROOTPWD"] = new
        c.write_kv(P("mysql_config"), data, 0o600)

    # -- automatic OS updates
    def autoupdates(self):
        s.step_auto_updates()

    # -- root and console user passwords, remove default access
    def passwords(self):
        root_pw = self.secret.get("ROOTPASSWORD")
        cli_pw = self.secret.get("CLIPASSWORD")
        user = self.cfg.get("CLIUSERNAME", "")
        if not root_pw and not cli_pw:
            raise InputError("ROOTPASSWORD or CLIPASSWORD is required")
        if cli_pw and not user:
            raise InputError("CLIUSERNAME is required with CLIPASSWORD")
        for pw in (root_pw, cli_pw):
            if pw and not pw.startswith("$") and len(pw) < MIN_PASSWORD:
                raise InputError("passwords need at least %d characters" % MIN_PASSWORD)
        admin = self.pl.account("admin_group")
        if user:
            if self.pl.user_exists(user):
                self.pl.user_add_to_group(user, admin)
            else:
                self.pl.user_add(user, [admin], "eFa-next console user")
        if root_pw:
            self.pl.set_password("root", root_pw)
        if cli_pw:
            self.pl.set_password(user, cli_pw)
            # A console user with sudo exists: no direct root login by SSH.
            s.write_sshd_dropin(P("sshd_root_dropin"), s.HEADER +
                                "# eFa-next: log in as the console user and use sudo.\n"
                                "PermitRootLogin no\n")

    # -- self-signed web certificate
    def cert(self):
        static = [self.cfg.get(key, "") for key in ("IPV4ADDRESS", "IPV6ADDRESS")]
        if c.ensure_certificate(self.fqdn(), ips=[ip for ip in static if ip and ip.lower() not in AUTO_VALUES and ip.lower() != "disabled"]):
            for logical in ("web", "mta"):
                self.pl.service_reload_if_active(self.pl.service(logical))

    # -- web admin password hash, then the mail log setup
    def webadmin(self):
        pw = self.secret.get("WEBADMINPASSWORD")
        if not pw:
            raise InputError("WEBADMINPASSWORD is required")
        if pw.startswith("pbkdf2_sha256$") and pw.count("$") == 3:
            line = pw
        else:
            if len(pw) < MIN_PASSWORD:
                raise InputError("passwords need at least %d characters" % MIN_PASSWORD)
            line = hash_web_password(pw)
        group = self.pl.account("web_group")
        if not os.path.isdir(rp(P("efa_web_dir"))):
            c.ensure_dir(P("efa_web_dir"), 0o750, "root", group)
        c.write_file(P("web_admin_pw"), line + "\n", 0o640, "root", group)
        language = self.cfg.get("SETUPLANG", "en")
        c.write_file(P("efa_web_dir") + "/language", (language if language in ("en", "de") else "en") + "\n", 0o640, "root", group)
        c.run([c.which("efactl"), "maillog-setup"])

    # -- setup variant of the wizard (6.0.0.5), then the security minimum of postfix, nginx and dovecot
    def variant(self):
        efactl = c.which("efactl")
        variant = self.cfg.get("SETUPVARIANT", "")
        if variant:
            if variant == "guided":
                totp = [self.secret.get(key, "") for key in ("TOTPSECRET", "TOTPSTEP", "TOTPRECOVERY")]
                if not all(totp):
                    raise InputError("the guided setup needs the 2FA of the main admin")
                c.run([efactl, "totp-import"], input_text="".join(item + "\n" for item in totp), secret=True)
                # The own 2FA of the console admin (SSH), never the one of the main admin; before the switch of its login shell.
                console = [self.secret.get(key, "") for key in ("CONSOLETOTPSECRET", "CONSOLETOTPSTEP", "CONSOLETOTPRECOVERY")]
                if all(console) and self.cfg.get("CLIUSERNAME"):
                    c.run([efactl, "totp-import", "--console_user", self.cfg["CLIUSERNAME"]],
                          input_text="".join(item + "\n" for item in console), secret=True)
            if not self.cfg.get("NOTICEACCEPTED"):
                raise InputError("NOTICEACCEPTED is required with SETUPVARIANT")
            args = [efactl, "setup-variant-apply", "--variant", variant, "--eulink", need(self.cfg, "EULINK"),
                    "--notice", self.cfg["NOTICEACCEPTED"], "--lang", self.cfg.get("SETUPLANG", "en"),
                    "--console_user", self.cfg.get("CLIUSERNAME", "")]
            for key, option in (("EULINKCONFIRM", "--noeu"), ("FRAMEWORKS", "--frameworks"), ("FRAMEWORKNOTE", "--note")):
                if self.cfg.get(key):
                    args += [option, self.cfg[key]]
            c.run(args)
            # The language of the wizard stays the language of the main admin in the web interface (My settings).
            c.run([efactl, "my-settings-set", "--language", self.cfg.get("SETUPLANG", "en")], check=False)
        c.run([efactl, "floor-check", "--mode", "apply"])

    # -- hypervisor guest tools (wizard question)
    def vmtools(self):
        if self.cfg.get("VMTOOLS", "NO") != "YES":
            return
        tools = self.pl.guest_tools()
        if tools is None:
            c.info("no known hypervisor; no guest tools needed")
            return
        package, service = tools
        if not self.pl.package_installed(package):
            self.pl.package_install([package])
        self.pl.service_enable(service, start=True)

    # -- finish: settings file, services, stop wizard, reboot marker
    def finish(self):
        for key in ("HOSTNAME", "DOMAINNAME", "ADMINEMAIL"):
            need(self.cfg, key)
        data = c.read_kv(P("efa_config"))
        for key in SETTING_KEYS:
            if key in self.cfg:
                data[key] = self.cfg[key]
        data["CONFIGURED"] = "YES"
        c.write_kv(P("efa_config"), data, 0o640)
        if self.cfg.get("LEGALACCEPTED"):
            # 5y: the legal texts were confirmed in the setup wizard; efactl notes it once the system is set up.
            c.run([c.which("efactl"), "legal-accept", "--digest", self.cfg["LEGALACCEPTED"], "--confirm", "yes"])
        pl = self.pl
        for logical in s.NEEDED_SERVICES:
            if pl.service_exists(pl.service(logical)):
                pl.service_enable(pl.service(logical))
        wizard = pl.service("wizard")
        _, units = pl.efa_units()
        for unit in units:
            if unit.split(".")[0] != wizard and unit not in pl.EFA_ONESHOTS:
                pl.service_enable(unit)
        if pl.service_exists(wizard):
            # Disabled now, stopped by the reboot job, so that the wizard
            # (which runs this program) can still show its last page.
            pl.service_disable(wizard)
        pl.service_enable(pl.service("firstboot"))
        c.ensure_dir(P("state_dir"), 0o750)
        c.touch(firstboot_marker())
        # An unattended install must not apply its settings a second time.
        c.remove(P("setup_dir") + "/kickstart.conf")
        pl.service_enable(pl.service("setup_reboot"), start=True)
        c.touch(reboot_marker())


def hash_web_password(password, salt=None):
    """PBKDF2-SHA256 hash as 'pbkdf2_sha256$iterations$salt$hash' (base64)."""
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                 PBKDF2_ITERATIONS)
    return "pbkdf2_sha256$%d$%s$%s" % (
        PBKDF2_ITERATIONS, base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode())


# ===================================================================== time

def ntp_server_list(text):
    """The servers of a comma or space list: 1 to 4 host names or IP addresses; None if one is not."""
    servers = [part for part in re.split(r"[,\s]+", text or "") if part]
    if len(servers) > 4 or not all(c.ip_version(server) or c.valid_fqdn(server) for server in servers):
        return None
    return servers


def time_sync(text):
    """--time-sync: the time servers (empty: the present ones), then the clock now. One line for the wizard:
    TIMESYNC yes|no OFFSET_BEFORE OFFSET_AFTER (seconds, - if unknown)."""
    servers = ntp_server_list(text)
    if servers is None:
        print("efa-apply: time servers: 1 to 4 host names or IP addresses", file=sys.stderr)
        return 2
    try:
        pl = c.platform()
        if c.read_kv(P("efa_config")).get("CONFIGURED") == "YES" and os.environ.get("SUDO_USER"):
            print("efa-apply: this host is already configured", file=sys.stderr)
            return 3
        if servers:
            pl.set_ntp_servers(servers)
        before, after, synced = pl.time_sync()
    except (StepError, OSError) as exc:
        print("efa-apply: %s" % exc, file=sys.stderr)
        return 1
    shown = lambda value: "-" if value is None else "%.3f" % value
    c.info("time sync: servers %s, offset before %s s, after %s s, synchronized %s"
           % (",".join(servers) or "kept", shown(before), shown(after), synced))
    print("TIMESYNC %s %s %s" % ("yes" if synced else "no", shown(before), shown(after)))
    return 0 if synced else 1


# ===================================================================== main

def main(argv=None, stdin_is_tty=None):
    ap = argparse.ArgumentParser(prog="efa-apply",
                                 description="Apply the eFa-next first-run settings.")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--answers", metavar="FILE",
                    help="KEY:value answers from FILE, or '-' for stdin")
    ap.add_argument("--all", action="store_true", help="run every step")
    ap.add_argument("--time-sync", metavar="SERVERS",
                    help="use these time servers (comma list, empty: keep them) and set the clock now")
    for name in STEP_ORDER:
        ap.add_argument("--" + name, action="store_true", dest="step_" + name)
    args = ap.parse_args(argv)
    c.env.verbose = args.verbose
    c.env.program = "efa-apply"
    c.env.log_file = "eFa-apply.log"
    if c.env.live and os.geteuid() != 0:
        print("efa-apply: must run as root", file=sys.stderr)
        return 3
    if args.time_sync is not None:
        return time_sync(args.time_sync)
    names = [n for n in STEP_ORDER if args.all or getattr(args, "step_" + n)]
    if not names:
        ap.error("choose --all or at least one step")
    try:
        c.platform()
        if c.read_kv(P("efa_config")).get("CONFIGURED") == "YES" \
                and os.environ.get("SUDO_USER"):
            print("efa-apply: this host is already configured", file=sys.stderr)
            return 3
        source = args.answers
        if source is None:
            tty = sys.stdin.isatty() if stdin_is_tty is None else stdin_is_tty
            source = None if tty else "-"
        settings, secret = parse_answers(read_answers(source)) if source else ({}, {})
        save_staging(settings)
        cfg = merged_settings(settings)
    except (StepError, OSError) as exc:
        print("efa-apply: %s" % exc, file=sys.stderr)
        return 2
    steps = Steps(cfg, secret)
    for name in names:
        c.info("step %s: start" % name)
        try:
            getattr(steps, name)()
        except Exception as exc:  # report and stop at the first failure
            c.error("step %s failed: %s" % (name, exc))
            print("FAILED %s: %s" % (name, exc))
            return 2 if isinstance(exc, InputError) else 1
        c.info("step %s: ok" % name)
        print("OK %s" % name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
