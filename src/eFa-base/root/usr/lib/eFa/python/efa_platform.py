# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Platform layer: the one place for everything that depends on the OS.

The configuration steps are platform-neutral. They take paths, service
names, account names and OS commands from a Platform object. Today there is
one implementation, efa_platform_el9.EL9 (AlmaLinux / Rocky / RHEL 9).

A port to another OS adds one module with a subclass that fills PATHS,
SERVICES, ACCOUNTS and FIREWALL_SERVICES and implements every method below
that raises NotImplementedError. See IMPLEMENTATION-NOTES.md.
"""


class Platform:
    """Interface of the platform layer. All paths are absolute target paths."""

    name = "generic"
    root_group = "root"

    # logical name -> path. Keys every platform must define:
    # efa_etc, efa_config, mysql_config, version_file, log_dir, state_dir,
    # setup_dir, hostname_file, hosts_file, resolv_conf, zoneinfo_dir,
    # postfix_dir, cert_file, key_file, sasl_conf, sasldb, clamd_conf,
    # clamd_socket, clamd_log, freshclam_conf, mariadb_conf, unbound_conf,
    # unbound_conf_d, unbound_local_d, unbound_forward, unbound_root_key,
    # fail2ban_jail, sshd_dropin, sshd_root_dropin, ssh_dir, ssh_banner,
    # sudoers_file, cron_dir, monitor_settings, monitor_cron, policy_module,
    # efa_web_dir, web_admin_pw, sendmail, efa_sbin.
    PATHS = {}
    # logical service -> OS service name (mta, db, redis, spam, web, av,
    # avupdate, dns, ban, firewall, ssh, cron, time, network, wizard,
    # firstboot, setup_reboot)
    SERVICES = {}
    # logical account -> OS user or group name (clamav_user, av_group,
    # postfix_group, web_group, rspamd_user, wizard_user, admin_group)
    ACCOUNTS = {}
    # logical port name -> firewall service name (ssh, smtp, submission,
    # http, https)
    FIREWALL_SERVICES = {}
    # eFa-next oneshot jobs that are never restarted or enabled as plain services
    EFA_ONESHOTS = ()
    # services that the setup turns off if they exist
    UNNEEDED_SERVICES = ()

    def path(self, name):
        return self.PATHS[name]

    def service(self, logical):
        return self.SERVICES[logical]

    def account(self, logical):
        return self.ACCOUNTS[logical]

    # ------------------------------------------------ service manager
    def manager_running(self):
        """True if the service manager can start and stop services now
        (False e.g. in an installer chroot)."""
        raise NotImplementedError

    def service_exists(self, name):
        raise NotImplementedError

    def service_enable(self, name, start=False):
        raise NotImplementedError

    def service_disable(self, name, stop=False):
        raise NotImplementedError

    def service_is_active(self, name):
        """True if running or starting."""
        raise NotImplementedError

    def service_is_enabled(self, name):
        """True if it starts at boot (a timer: if it is armed at boot)."""
        raise NotImplementedError

    def service_start(self, name):
        raise NotImplementedError

    def service_stop(self, name):
        raise NotImplementedError

    def service_restart(self, name, check=True):
        raise NotImplementedError

    def service_try_restart(self, name):
        """Restart only if it is running."""
        raise NotImplementedError

    def service_reload_if_active(self, name):
        raise NotImplementedError

    def service_manager_reload(self):
        """Make the service manager re-read its unit or rc files."""
        raise NotImplementedError

    def service_set_open_files(self, name, limit):
        """Raise the open file limit of a service. True if changed."""
        raise NotImplementedError

    def service_hardening(self, name, on):
        """5v (h): the sandbox settings of the service manager for a third-party service, or none. True if changed."""
        raise NotImplementedError

    def service_start_after_network(self, name):
        """Order a service after the network is up. True if changed."""
        raise NotImplementedError

    def efa_units(self):
        """Return (scheduled_jobs, services) shipped by the eFa packages."""
        raise NotImplementedError

    # ------------------------------------------------ packages and updates
    def package_installed(self, package):
        raise NotImplementedError

    def package_install(self, packages):
        raise NotImplementedError

    def package_fetch(self, packages, folder):
        """Download these packages and what they need from the repositories into the folder; installs nothing. Returns the files."""
        raise NotImplementedError

    def package_signature_ok(self, path):
        """True if a package file carries a valid signature of an imported key."""
        raise NotImplementedError

    def package_upgrade_files(self, paths):
        """Install or upgrade these package files, without any repository. (ok, the last lines of the output)."""
        raise NotImplementedError

    def package_scripts(self, path):
        """The install scripts and triggers of a package file, as text."""
        raise NotImplementedError

    def package_downgrade(self, files):
        """Install these package files although they are older. Returns (ok, last part of the output)."""
        raise NotImplementedError

    def kernel_settings(self, values):
        """Writes the kernel settings of eFa-next for every boot and applies them now; None removes them (the system defaults
        apply from the next boot)."""
        raise NotImplementedError

    def kernel_settings_active(self):
        """Whether the kernel settings of eFa-next are written for every boot."""
        raise NotImplementedError

    def configure_auto_updates(self):
        """Automatic security updates of the OS. True if changed."""
        raise NotImplementedError

    def reboot_required(self):
        """Return (True/False, reason text)."""
        raise NotImplementedError

    def security_updates(self):
        """Pending security updates: [{'package', 'severity', 'ids'}], ids are CVE or advisory names. Reads only."""
        raise NotImplementedError

    def listening(self):
        """Sockets that listen: [{'proto', 'address', 'port', 'process', 'package'}]. Reads only."""
        raise NotImplementedError

    def oval_source(self):
        """The URL of the open OVAL security data of this distribution, or None. (FreeBSD later: VuXML.)"""
        raise NotImplementedError

    def package_versions(self):
        """Installed packages: {name: [(epoch, version, release), ...]}. Reads only."""
        raise NotImplementedError

    def version_older(self, installed, fixed):
        """True if the (epoch, version, release) installed is older than the fixed one."""
        raise NotImplementedError

    def append_only(self, path, on):
        """Only appending to the file is possible while on (chattr +a); off again for the rotation."""
        raise NotImplementedError

    def audit_rules(self, text):
        """The eFa-next rules of the audit daemon: written and loaded without a reboot, or removed when text is None."""
        raise NotImplementedError

    def audit_rules_present(self):
        raise NotImplementedError

    def file_labels(self, path):
        """The security labels of the system for new files below path, so services may read them (SELinux on EL9)."""
        raise NotImplementedError

    def process_counts(self, groups):
        """Running processes per group: groups maps a label to process names or command line words. {label: count}."""
        raise NotImplementedError

    def package_verify(self, path):
        """What the package manager says of a file against its package (rpm -V on EL9): '' when unchanged. Reads only."""
        raise NotImplementedError

    def journal_window(self, since, until, idents):
        """The log lines of these programs between two times (seconds since 1970): [line]. Reads only."""
        raise NotImplementedError

    # ------------------------------------------------ network interfaces
    def interfaces(self):
        """Ethernet and VLAN devices: [{'device', 'type', 'state', 'connection'}]."""
        raise NotImplementedError

    def main_interface(self):
        """The device of the default route: eFa-next never changes it through the interface pages."""
        raise NotImplementedError

    def connection_settings(self, connection):
        """{setting: value} of a connection, the keys of CONNECTION_KEYS."""
        raise NotImplementedError

    def connection_ensure(self, device, vlan=None):
        """The connection eFa-next manages for a device (or a VLAN on it), made if missing. Returns its name and whether it was made."""
        raise NotImplementedError

    def connection_apply(self, connection, settings):
        """Write the settings and bring the connection up: only that interface changes."""
        raise NotImplementedError

    def connection_delete(self, connection):
        raise NotImplementedError

    def no_auto_profiles(self):
        """A new interface gets no automatic DHCP profile: it stays unused until an admin gives it a role. Returns True if changed."""
        raise NotImplementedError

    def ethernet_devices(self):
        """(network devices with hardware, devices of the default route), read without starting a program."""
        raise NotImplementedError

    def auto_profiles(self):
        """The profiles the network service made by itself for an interface: [{'name', 'device'}]."""
        raise NotImplementedError

    def zone_services(self, zone, services):
        """The firewall zone offers exactly these services, runtime and permanent, without a reload."""
        raise NotImplementedError

    def zone_service_list(self, zone):
        """The services the firewall zone offers, permanent: what zone_services sets back on the way back."""
        raise NotImplementedError

    def schedule(self, name, seconds, argv):
        """Run argv once after so many seconds, as a job of the system: the way back of a change."""
        raise NotImplementedError

    def unschedule(self, name):
        raise NotImplementedError

    def reboot(self):
        raise NotImplementedError

    def guest_tools(self):
        """Return (package, service) for the hypervisor in use, or None."""
        raise NotImplementedError

    # ------------------------------------------------ firewall
    def firewall_allow(self, logical_names):
        """Enable the firewall and open the given ports permanently and in
        the running firewall, without a full reload. True if changed."""
        raise NotImplementedError

    def run_later(self, unit, seconds, command):
        """Run a command once, in seconds, as a unit of its own that a later call with the same name replaces."""
        raise NotImplementedError

    def nft_apply(self, script):
        """Load an nftables script in one transaction (all of it or nothing). Returns (ok, error text)."""
        raise NotImplementedError

    def nft_has_table(self, family, name):
        """True when the nftables table exists."""
        raise NotImplementedError

    # ------------------------------------------------ users and groups
    def user_exists(self, name):
        raise NotImplementedError

    def group_members(self, group):
        """Members of a group, or None if the group does not exist."""
        raise NotImplementedError

    def user_add(self, name, groups, comment):
        raise NotImplementedError

    def user_add_to_group(self, name, group):
        raise NotImplementedError

    def set_password(self, user, password):
        """Set a password (plain text or a crypt hash) via stdin only."""
        raise NotImplementedError

    # ------------------------------------------------ host and network
    def set_hostname(self, fqdn):
        raise NotImplementedError

    def set_timezone(self, zone, hardware_clock_utc):
        raise NotImplementedError

    def interface_exists(self, iface):
        raise NotImplementedError

    def configure_interface(self, iface, ipv4, ipv6):
        """ipv4/ipv6: None for automatic, 'disabled' (IPv6 only), or a
        tuple (address, prefix, gateway or '')."""
        raise NotImplementedError

    def use_local_resolver(self):
        """Point the system resolver at 127.0.0.1. True if changed."""
        raise NotImplementedError

    def has_default_route(self):
        raise NotImplementedError

    def ipv6_available(self):
        raise NotImplementedError

    def service_start_background(self, name):
        raise NotImplementedError

    # ------------------------------------------------ time
    def ntp_servers(self):
        """The time sources (server and pool lines)."""
        raise NotImplementedError

    def set_ntp_servers(self, servers):
        """Use these time sources instead of the present ones. True if changed."""
        raise NotImplementedError

    def time_sync(self):
        """Set the clock from the time sources now: (offset before, offset after in seconds or None, synchronized)."""
        raise NotImplementedError

    # ------------------------------------------------ mandatory access control
    def mac_enabled(self):
        """True if a mandatory access control system (SELinux) is active."""
        raise NotImplementedError

    def apply_policy_module(self, path):
        """Install the eFa-next policy module if it changed. No-op without MAC."""
        raise NotImplementedError

    def restore_context(self, path):
        """Restore the default security label of a path. No-op without MAC."""
        raise NotImplementedError


def detect():
    """Return the Platform object for the running OS."""
    import efa_common
    osrel = {}
    try:
        with open(efa_common.rp("/etc/os-release"), encoding="utf-8") as fh:
            for line in fh:
                key, sep, value = line.strip().partition("=")
                if sep:
                    osrel[key] = value.strip().strip('"')
    except OSError:
        pass
    ids = [osrel.get("ID", "")] + osrel.get("ID_LIKE", "").split()
    major = osrel.get("VERSION_ID", "").split(".")[0]
    if major == "9" and ({"rhel", "centos", "fedora"} & set(ids)):
        import efa_platform_el9
        return efa_platform_el9.EL9()
    raise efa_common.StepError("unsupported operating system: %s %s"
                               % (osrel.get("ID", "?"), osrel.get("VERSION_ID", "?")))
