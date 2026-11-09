<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Markus Lorber and eFa-next contributors -->
<!-- Author: Markus Lorber, Lukasz Galusinski -->
# eFa-next 6.0.0.3 clean-room build: implementation notes

Written only from `cleanroom/SPEC-6.0.0.3.md` and the public documentation
of the OS and the services. No eFa source was read. The integration into
this repository changed the few lines listed at the end.

Scope as decided in the spec: the two RPM specs with their package scripts,
`build/build.bash`, the program that applies the first-run settings, the
settings files, the after-first-boot step, the service configuration steps,
the service monitor, the small parts and one build script. Not built: the
web wizard (`efa-init.py` stays), the console wizard (dropped), eFa-Expand
(left out), translations (English only).

## Files (31)

The source tree under `src/<package>/root/` is laid out like the target
file system.

| File | What it does |
| --- | --- |
| `build/build.bash` | Installer for a fresh EL9 host (section 2). |
| `build/build-rpms.py` | Builds both RPMs and `SHA256SUMS`; neutral build host. |
| `rpm/eFa-base.spec` | Base package: OS requirements, configuration steps, monitor, logrotate, SELinux module; `%pre` / `%posttrans` logic. |
| `rpm/eFa.spec` | Main package: setup programs, units, backup cron, plus the existing eFa-next programs from `next/`. |
| **eFa-base** | |
| `usr/lib/eFa/python/efa_common.py` | Shared helpers: target root, command runner (no shell, secrets only on stdin), atomic writes with final mode before rename, `KEY:value` files, text edits, input checks, certificate, step runner. |
| `usr/lib/eFa/python/efa_platform.py` | Platform layer interface plus OS detection. |
| `usr/lib/eFa/python/efa_platform_el9.py` | EL9 implementation: systemd, dnf / dnf-automatic, firewalld, NetworkManager, shadow-utils, SELinux, all paths and names. |
| `usr/lib/eFa/python/efa_services.py` | Platform-neutral steps: dirs, selinux, system, postfix, clamav, mariadb, unbound, fail2ban, dnf-automatic, firewalld. |
| `usr/lib/eFa/python/efa_configure.py` | `efa-configure` CLI: single steps, `all`, `--list`, `-v`, and `--package-hook` for the package scripts. |
| `usr/lib/eFa/python/efa_monitor.py` | `efa-monitor`: service monitor, `--enable` / `--disable` (cron file), `--reboot-check`. |
| `usr/sbin/efa-configure`, `usr/sbin/efa-monitor` | Small wrappers (`python3 -Is`). |
| `usr/lib/systemd/system/efa-reboot-check.{service,timer}` | Daily check whether a reboot is due. |
| `etc/sysconfig/eFa-Monitor` | Monitor settings: services, restart limit, counter lifetime. |
| `etc/logrotate.d/eFa` | Rotates every file in `/var/log/eFa`. |
| `selinux/efa.te`, `selinux/README.md` | Placeholder module (no rules) and how to build the rules from `ausearch`. |
| **eFa** | |
| `usr/lib/eFa/python/efa_apply.py` | `efa-apply`: applies the first-run settings, one switch per step, `--all`, `--verbose`. |
| `usr/lib/eFa/python/efa_firstboot.py` | `efa-firstboot`: after-first-boot step, and `--setup-reboot`. |
| `usr/sbin/efa-apply`, `usr/libexec/eFa/efa-firstboot` | Wrappers. |
| `usr/lib/systemd/system/efa-firstboot.service` | Runs once at boot while `/var/lib/eFa/firstboot-pending` exists. |
| `usr/lib/systemd/system/efa-setup-reboot.{path,service}` | Marker `/var/lib/eFa/setup-reboot` -> stop the wizard, reboot. |
| `usr/lib/systemd/system/efa-kickstart.service` | Unattended install: applies `/var/lib/eFa/setup/kickstart.conf` at boot. |
| `etc/cron.d/eFa-Backup.cron` | Daily `efactl backup-now`, skipped if `/etc/eFa/eFa-Backup.disabled` exists. |
| **tests** | |
| `tests/efa_testlib.py` | Temporary root and a fake command runner. |
| `tests/test_configure.py`, `tests/test_apply.py`, `tests/test_monitor_packaging.py` | 35 self-tests. |

Installed paths: modules in `/usr/lib/eFa/python/`, programs in
`/usr/sbin/` and `/usr/libexec/eFa/`, units in `/usr/lib/systemd/system/`.

## Spec sections and files

| Spec | Implementation |
| --- | --- |
| 1 Packages | `rpm/*.spec`. `%pre` stops an upgrade before any file change if `/etc/MailScanner/MailScanner.conf` exists and records a first install in `/var/lib/rpm-state/<pkg>/`. `%posttrans` runs `efa-configure --package-hook <pkg> first-install|upgrade`: all steps on a first install, only `dirs` and `selinux` on an upgrade (no settings change). Every failed step is listed and the scriptlet exits non-zero. Each package writes its result to `/var/lib/eFa/install-state/<pkg>`; `/etc/eFa-Version` is written only when every installed package passed. Both reload systemd, enable every `efa-*.timer` (and `efa-setup-reboot.path`) and `try-restart` running `efa-*` services except the wizard and the oneshots. |
| 2 Installer | `build/build.bash` with actions `production` (default) and `kickstart`, optional RPM folder; log `/var/log/eFa/eFa-install.log`; stops at the first failed step. Checks OS and SELinux, enables EPEL, CRB, the rspamd repository and the newest nginx module stream, updates the OS, downloads `SHA256SUMS` and the two RPMs named in it from the latest release, verifies them, installs them and checks that `/etc/eFa-Version` exists. |
| 3 Applying | `efa_apply.py`. Steps in spec order: mariadb, hostname, dns, network, sshkeys, timezone, transport, sasl, dbpasswords, autoupdates, passwords, cert, webadmin, (vmtools), finish. Sudo rule `/etc/sudoers.d/efa-init` (0440, checked with `visudo`), made by the eFa-next first-install hook only while not configured. |
| 3 Settings files | `/etc/eFa/eFa-Config` (0640 root, `KEY:value`, all listed keys, `CONFIGURED:YES` at finish; other existing keys kept). `/etc/eFa/MySQL-Config` (0600 root, `MYSQLROOTPWD`). |
| 3 After first boot | `efa_firstboot.py` + `efa-firstboot.service`. |
| 4 Services | `efa_services.py` (one function per step), run by `efa-configure`. |
| 5 Monitor | `efa_monitor.py`, `/etc/sysconfig/eFa-Monitor`, `/etc/cron.d/eFa-Monitor.cron` (path kept). Kept separate from `efa-milter-health`: I cannot see that program, so a merge would not be simpler. |
| 6 Small parts | `eFa-Backup.cron`, `logrotate.d/eFa`, `selinux/`, `build-rpms.py`. `eFa-settings.inc` not needed; eFa-Expand left out. |

## Interpretations and decisions

1. **Interface of the applying program.** The spec gives the shape, not
   the names. Chosen: `/usr/sbin/efa-apply` with `--mariadb --hostname
   --dns --network --sshkeys --timezone --transport --sasl --dbpasswords
   --autoupdates --passwords --cert --webadmin --vmtools --finish`,
   `--all`, `--verbose`. Answers are `KEY:value` lines on stdin (or
   `--answers FILE`, mode 0600). Secret keys: `ROOTPASSWORD`,
   `CLIPASSWORD`, `WEBADMINPASSWORD`. Output: one `OK step` /
   `FAILED step: reason` line per step. Exit 0 ok, 1 step failed, 2 bad
   input, 3 refused. **`efa-init.py` must be checked against this and one
   side adapted** (open point).
2. Non-secret answers are staged in `/var/lib/eFa/setup/settings` (0600)
   so the wizard can call steps one by one. `finish` writes the settings
   file. With `--all`, the run stops at the first failed step, so a broken
   setup never reaches `finish`.
3. Static or automatic addressing: `IPV4ADDRESS` / `IPV6ADDRESS` empty,
   `auto` or `dhcp` mean automatic; `IPV6ADDRESS:disabled` turns IPv6 off.
   Netmask as prefix or dotted. `IPV6DNS` is read as YES/NO (Unbound uses
   IPv6). `RECURSION:NO` forwards to `DNSIP1` / `DNSIP2`.
4. The hypervisor-tools question has no applying step in the spec; added
   `--vmtools` (key `VMTOOLS:YES`): installs and enables the guest agent
   for the detected hypervisor.
5. "Remove default access": a new root password replaces any image
   default, and once a console user (in `wheel`) has a password, SSH root
   login is turned off (`39-efa-root.conf`). Before that, the base SSH
   hardening allows root only with keys.
6. "Make new random database passwords": only the MariaDB root password
   (the only key the spec names). root keeps socket login as OS root, so a
   failed save cannot lock root out. Anonymous users and the `test`
   database are removed. Other database users are left to
   `efactl maillog-setup`.
7. Web admin hash format: `pbkdf2_sha256$600000$<salt b64>$<hash b64>`.
   A value that already has this form is stored as is. **Must match the
   check in `efa-web.py`** (open point).
8. Wizard user and unit: `efa-init` / `efa-init.service`; web group
   `efa-web`. Names live only in the EL9 platform module. **Check against
   the eFa-next units** (open point).
9. Stopping the wizard: `efa-apply` runs inside the wizard's service, so
   `finish` only disables the wizard and writes the reboot marker; the path
   unit starts a separate job that waits 20 s (last page), stops the
   wizard and reboots. `efa-apply` refuses to run via sudo once
   `CONFIGURED:YES`.
10. Certificate: `/etc/pki/tls/certs/efa.crt` and
    `/etc/pki/tls/private/efa.key` (0600). The Postfix step makes a
    placeholder if none exists, so Postfix starts before the setup; the
    `cert` step remakes it when the host name differs. **nginx config of
    eFa-next must use the same paths** (open point).
11. Postfix: settings `efactl` edits later (`mynetworks`,
    `message_size_limit`, `smtpd_recipient_restrictions`, `smtpd_milters`,
    `milter_header_checks`) are set only while not yet in `main.cf`, so a
    repeated step keeps the admin's values; `relayhost` is not touched.
    `message_size_limit` default 26214400 is a guess: **use the value of
    `efactl`** (open point, one constant in `efa_services.py`). Map type is
    taken from `default_database_type`. Separate empty files
    `header_checks` and `milter_header_checks` (regexp), `helo_access`,
    `recipient_canonical`. SASL: Cyrus with sasldb (`/etc/sasl2/sasldb2`,
    root:postfix 0640), AUTH only on the submission port with TLS.
12. ClamAV logs to `/var/log/clamd.scan` and rotates it itself
    (`LogFileMaxSize`, `LogRotate`) to avoid a second logrotate entry for
    a file the package may already rotate. rspamd's user joins
    `virusgroup` for the socket.
13. Unbound: eFa-next owns `/etc/unbound/unbound.conf`; forwarding goes to
    `/etc/unbound/efa-forward.conf`, so `/etc/unbound/conf.d/` stays only
    for `efactl` zones. `::1` is used only if the host has IPv6.
14. Logrotate: the old file listed one file. Now `/var/log/eFa/*`;
    rotated copies go to `/var/log/eFa-archive/`, so the wildcard never
    rotates a rotated copy, and new log files are covered without a list.
    Logs in subfolders of `/var/log/eFa` are not covered.
15. Monitor: on with the first boot (`efa-monitor --enable` writes the
    cron file); off during setup. The cron file is a `%ghost` of eFa-base,
    so an upgrade never turns the monitor back on. "Activating" counts as
    running. One mail when the monitor gives up.
16. Reboot check: daily timer; writes `/var/lib/eFa/reboot-due` with the
    reason from `needs-restarting -r`, removes it when no longer due. No
    automatic reboot.
17. Version file content: `eFa-6.0.0.3`. **Check what `efactl` expects**
    (open point).
18. Unattended install: the kickstart `%post` writes the settings to
    `/root/eFa-kickstart.conf` (or `$EFA_KICKSTART_CONFIG`) and runs
    `build.bash kickstart`. The file moves to
    `/var/lib/eFa/setup/kickstart.conf` (0600) and `efa-kickstart.service`
    applies it at the next boot (the chroot has no running systemd);
    `finish` deletes it and triggers the reboot. On a running host the
    installer schedules the reboot itself.
19. MailScanner check: done only on upgrade, as the spec says. A first
    install on an eFa 5 host is not blocked (open point).
20. Firewall: `ssh`, `smtp`, `smtp-submission`, `http`, `https`,
    permanent and runtime separately, or `firewall-offline-cmd` when
    firewalld is not running. No reload anywhere (a test checks this).
21. clamav-unofficial-sigs: not included (license open, as the spec says).
22. `next/`: the existing eFa-next programs are not part of this build.
    `build-rpms.py --next-dir DIR` adds them; their files under `/etc` are
    marked `%config(noreplace)`; folders they need are not owned by the
    package.

## Platform layer and the FreeBSD plan

All OS-specific code is in `efa_platform_el9.py` behind the interface in
`efa_platform.py`. The steps (`efa_services`, `efa_apply`,
`efa_firstboot`, `efa_monitor`, `efa_configure`) only use Postfix,
MariaDB, OpenSSL, OpenSSH, sudo and ClamAV tools that are the same on
both systems, plus the layer. They use no shell and no GNU-only flags.
The RPM specs and `build.bash` are EL9 packaging and stay EL9-only.

A FreeBSD port adds `efa_platform_freebsd.py` with one `FreeBSD(Platform)`
class, a branch in `efa_platform.detect()`, and its own packaging (pkg
and an installer). The class provides:

- data: `PATHS` (e.g. `/usr/local/etc/postfix`, `/usr/local/etc/eFa`,
  `/var/log/eFa`, `/usr/local/etc/clamd.conf`), `SERVICES` (rc names),
  `ACCOUNTS` (`clamav`, `wheel`, ...), `FIREWALL_SERVICES` (ports for pf),
  `EFA_ONESHOTS`, `UNNEEDED_SERVICES`, `root_group = "wheel"`;
- service manager: `manager_running`, `service_exists`, `service_enable`
  / `service_disable` (`sysrc`), `service_is_active`, `service_start`,
  `service_stop`, `service_restart`, `service_try_restart`,
  `service_reload_if_active`, `service_manager_reload`,
  `service_set_open_files` (login class or rc variable),
  `service_start_after_network` (rc ordering), `efa_units`;
- packages and updates: `package_installed`, `package_install`,
  `configure_auto_updates` (periodic security updates with pkg),
  `reboot_required`, `reboot`, `guest_tools`;
- firewall: `firewall_allow` (pf anchor, `pfctl -a ... -f`, no full reload);
- users: `user_exists`, `group_members`, `user_add`, `user_add_to_group`,
  `set_password` (`pw usermod -H 0`, password on stdin);
- host and network: `set_hostname`, `set_timezone`, `interface_exists`,
  `configure_interface` (`rc.conf` `ifconfig_<if>`), `use_local_resolver`
  (`resolvconf.conf`), `has_default_route`, `ipv6_available`;
- access control: `mac_enabled` returns False, `apply_policy_module` and
  `restore_context` do nothing.

Scheduled jobs: cron files are the same format; the systemd timers
(`efa-reboot-check`, setup reboot path unit, first-boot unit) would become
`periodic` scripts or rc scripts on FreeBSD.

## Self-tests

From the folder that holds this file, on any Linux, without root:

    python3 -B -m unittest discover -s tests -v

The tests use a temporary folder as root and a fake command runner, so no
command runs and no host file changes. Result at handover:
**35 tests, all passed** (Python 3.13). They cover: settings files and
their modes, text edits, input checks; all install steps on a test root,
twice (second run changes no file and no Postfix setting, adds no
firewall rule); Postfix parameters and that `efactl` values are kept;
no firewall reload; first install writes the version file only if every
step passed; upgrade changes no settings and restarts only running eFa-next
services, not the wizard; `efa-apply --all` end to end; passwords and the
generated database password never appear in any command line, log,
output or file other than `MySQL-Config`; input injection is refused;
refusal once configured; staged answers; first boot cleanup and the
reboot job; monitor limit, single mail and counter expiry; SPDX headers;
spec checks.

## Not verified here

No EL9 host, `rpmbuild` or `checkmodule` was available. Not run for
real: the RPM build, the package scripts, `build.bash`, and every OS
command. The source archive creation of `build-rpms.py` was tried. Before
release: build both RPMs on EL9, run acceptance tests 2 to 6 of the spec,
and fill `efa.te` from `ausearch` as described in `selinux/README.md`.

## Open points

- Interface between `efa-init.py` and `efa-apply` (names, answer keys,
  output) - item 1.
- Web admin hash format vs. `efa-web.py` - item 7.
- Wizard user/unit name, `efa-web` group, certificate paths in nginx -
  items 8 and 10.
- `message_size_limit` default of `efactl` - item 11.
- Content of `/etc/eFa-Version` expected by `efactl` - item 17.
- Block a first install on an eFa 5 host too? - item 19.
- SELinux rules: only from a test in enforcing mode.
- clamav-unofficial-sigs: license question from the spec.

## Integration into eFa-next (2026-11-05)

The open points above were closed on the eFa-next side:

| Open point | Result |
| --- | --- |
| Interface of `efa-apply` | `efa-init.py` calls `efa-apply --verbose --answers - --all` and hands the answers over on stdin. English only, no language page. |
| Web admin hash | `efa-web.py` checks both forms: `pbkdf2_sha256$...` from `efa-apply` and the Werkzeug form from `efactl admin-password`. |
| Wizard user and unit | `efa-init.service` runs as `efa-init`, group `efa-web` for the session key. `efa-web-config.sh` creates the user. |
| Certificate paths | A new install uses `/etc/pki/tls/certs/efa.crt` and `/etc/pki/tls/private/efa.key` in nginx too. Hosts with `/etc/nginx/ssl` keep it. Both are in the backup. |
| `message_size_limit` | `efactl` has no default of its own, it only reads Postfix. The value 26214400 stays. |
| Version file | `eFa-6.0.0.3` works with the version check of `efactl`. |
| First install on an eFa 5 host | Blocked too, decided by the owner. |
| clamd socket | `rspamd-config.sh` uses `/run/clamd.scan/clamd.sock`, and hosts upgraded keep what they have. |

`next/usr/lib/eFa/setup/efa-next-setup` holds the steps of the eFa-next programs. `eFa.spec` runs it before its own package hook, so a failure there leaves the version file unwritten.

Changes in the clean-room files, none of them taken from eFa 5:

| File | Change | Why |
| --- | --- | --- |
| `rpm/eFa-base.spec`, `rpm/eFa.spec` | `Epoch: 1`, `Requires: eFa-base = 1:...` | Without the epoch of 1:6.0.0.2, 6.0.0.3 counts as a downgrade. |
| Both specs | `%pre` blocks every install on an eFa 5 host | Owner decision, item 19 |
| `rpm/eFa-base.spec` | `dovecot`, `rsyslog` instead of `cyrus-sasl*` | Owner decision: Dovecot stays, SASL only. The mail report reads the log of rsyslog. |
| `rpm/eFa.spec` | Python, certbot, dig, gpg, tar requirements, `Obsoletes: clamav-unofficial-sigs`, call of `efa-next-setup` | Needed by `next/` |
| `efa_services.py`, `efa_apply.py`, `efa_platform_el9.py` | SASL through Dovecot: `smtpd_sasl_type=dovecot`, `/etc/dovecot/local.conf` with `protocols =` | Owner decision |
| `efa_platform_el9.py` | All oneshot units of `next/` in `EFA_ONESHOTS`, later also `efa-events.service` | Bug: an update inside `efa-autoupdate.service` would have restarted, and so killed, itself. |
| `etc/sysconfig/eFa-Monitor` | No `fail2ban`, no `firewalld` | Bug: the monitor would have restarted a fail2ban the admin turned off, and firewalld at any time, against the rule on firewall changes. |
| `efa_monitor.py` | `MAILTO=""` in the cron file | Bug: warnings on stderr would have become mail to root, on a host without local delivery. |
| `build/build-rpms.py` | `usr/local/sbin/` in `EXEC_DIRS` | Bug: the programs of `next/` lost their execute bit. |
| `efa_services.py` | `postconf -e inet_interfaces=all` before the first `postconf -n` | Bug: on a stock `main.cf`, `postconf -n` stops if `localhost` resolves to a foreign address. |
| `efa_services.py` | Unbound: `chroot: ""`, `username`, `directory`, remote control off | Bug: the built-in chroot broke the check, and remote control needs keys a fresh host does not have. Nothing uses it. |
| `efa_apply.py` | Answer `MAILSERVERDNS`: the `transport` step calls `efactl dns-zone-set` for the zone of the mail server | Without it, a name only an internal DNS server knows makes Postfix bounce mail. |
| `tests/` | Scope and expectations follow the above | |
