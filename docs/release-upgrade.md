# Release upgrade from AlmaLinux 9 to 10

eFa-next upgrades the operating system of a running host from Enterprise Linux 9 to 10 with
[ELevate](https://wiki.almalinux.org/elevate/) (leapp). Page **Maintenance & update**, section **Release-Upgrade**
(expert view). Only super admins see it; the API answers 403 to every other login and token.

**There is no rollback.** The only way back is a VM snapshot taken right before the start. Mail is not accepted for about 30 to
60 minutes (new mail gets `421` and the sending servers try again later), and the host reboots several times.

## Steps

Each step is one fixed action of `efactl release-upgrade --action=<step>`; nothing else is taken. The long steps run in
`efa-release-upgrade.service` (one at a time, with a lock), state in `/var/lib/eFa/release-upgrade/`, log in
`/var/log/eFa/release-upgrade.log`. `efactl release-upgrade-status` (the status card) shows the state, the warnings and the log.

1. **preflight** shows a Wazuh agent with its version and state (it stays exactly as it is, see
   [EL10-PORT.md](EL10-PORT.md)) and lists packages from other repositories, then checks, and changes nothing:
   - Enterprise Linux 9 and eFa-next 6.0.0.6 or newer
   - the distribution: AlmaLinux 9 goes to AlmaLinux 10. The distribution never changes. RHEL 9 (to RHEL 10 with the leapp
     of Red Hat, on a registered system) stays blocked until it is tested; Rocky Linux and others are not supported.
   - the eFa-next repository for EL10 is reachable. Until eFa-next publishes packages for EL10 this check fails, and the
     upgrade cannot start: that is expected.
   - a CPU with x86-64-v3 (AlmaLinux 10 is built for it; for older CPUs only the x86_64_v2 variant of AlmaLinux 10 fits, which
     ELevate does not install)
   - 5 GB free on `/` and at least 400 MB free on `/boot` (below 600 MB a warning: leapp checks `/boot` itself in
     preupgrade, and its inhibitor decides)
   - no pending updates, network connections as NetworkManager keyfiles (no `ifcfg` files), the clock synchronised
   - shown as warnings: mails in the queue, the cluster role (upgrade one node at a time), network cards whose driver EL10 no
     longer maintains (such as `e1000`: switch the virtual NIC to virtio or vmxnet3 first), Postfix maps of type `hash:` or
     `btree:` (they are switched to `lmdb:` after the upgrade)
2. **preupgrade** runs the preflight again, installs ELevate (`elevate-release`, `leapp-upgrade`, `leapp-data-almalinux`;
   the release package only with a valid signature of the ELevate key that ships with eFa-next, fingerprint
   `74E7 F249 EE69 8A4D ACFB 48C8 4297 85E1 81B9 61A5`),
   writes the leapp vendor files for the eFa-next and the rspamd repository to `/etc/leapp/files/vendors.d/`
   (`efa-next.repo`, `efa-next_map.json`, `efa-next.sigs`, and the same for `rspamd`) and runs `leapp preupgrade`. Every
   inhibitor in `leapp-report.json` stops the upgrade; the high risks are shown.
   leapp takes the eFa-next repository only while `/etc/yum.repos.d/efa-next.repo` is enabled: it is switched on for the leapp
   run and off again after (a host without the file gets it as in [install.md](install.md)). The upgrade also stops when the
   leapp log does not say `Vendor efa-next found in active list`, when its dnf transaction check would remove eFa-next or a
   package it needs (nginx, postfix, rspamd, MariaDB, ClamAV, Unbound, pymilter, certbot, flask, waitress, PyMySQL; Redis
   only with Valkey in its place), when eFa-next is not in the upgrade, or when the report counts eFa-next among third-party
   packages that may be removed. Without this check leapp would remove eFa-next and boot into EL10 without it.
   For the leapp run efactl also keeps nginx, sendmail-milter and python3-pytz (leapp's package data drops them although
   EL10 has them), asks leapp for eFa-next, eFa-next-base, pymilter and certbot from the target repositories, and uses EPEL
   of the target release (10.2, not the newest 10.x), all through leapp's own files (`/etc/leapp/transaction/to_keep`,
   `to_install`, `vendors.d/epel.repo`), which are put back as shipped after the run. See [EL10-PORT.md](EL10-PORT.md).
3. **start** needs your password and 2FA code, the snapshot box and the host name typed in, and a preupgrade without inhibitor
   from the last 24 hours. Then:
   - an encrypted backup (a backup password must be set), uploaded to every external backup target, its SHA-256 compared with
     the uploaded one and a test extract; if any of it fails, nothing else happens. Without a backup: type
     `without backup, snapshot only` (or `ohne Backup, nur Snapshot`) into the last field (`--no_backup`); then this backup is
     left out, the audit log names who started so and on which host, and the VM snapshot is the only way back. Every start
     asks again; the default stays the backup. The check "Backup works" after the first EL10 boot stays.
   - maintenance mode: new mail gets `421`, mail on its way (active, incoming) drains for up to 15 minutes; deferred mail is not waited for, it stays in the queue with what is left and goes out after the upgrade
   - the state before (addresses, routes, firewall zones and ports, other nft tables such as a mail block, counts of domains,
     users and quarantine, DKIM keys, Perl packages) is kept for the checks after the upgrade
   - a safety net outside the packages: `/etc/efa-release-upgrade/` and `efa-release-upgrade-recover.service`. If eFa-next
     is missing at the first EL10 boot, it installs `eFa-next` and `eFa-next-base` again from the EL10 repository and runs
     the checks; if that fails, maintenance stays on and the console login says so. It is removed after the checks.
   - `leapp upgrade`, then the reboot. If `leapp upgrade` fails, mail is accepted again and nothing reboots. If its
     transaction check would remove eFa-next (as above), nothing reboots either and maintenance stays on: do not reboot,
     go back to the VM snapshot (leapp has already set up the upgrade for the next boot).
4. **abort** stops a step and lifts the maintenance mode, but only before `leapp upgrade` has started.

## After the first boot into EL10

`efa-release-upgrade-finish.service` runs once, after leapp has ended its own phase (`leapp_resume.service`; the unit is
ordered after it and also waits up to 30 minutes for it): `mariadb-upgrade`, the Postfix maps from `hash:`/`btree:` to
`lmdb:` (`postmap`/`postalias` again), the `.rpmnew`/`.rpmsave` files beside the files eFa-next writes itself moved to
`/var/lib/eFa/release-upgrade/rpmnew/<time>/` for a comparison by hand, SELinux enforcing again, leapp's names taken off the
`exclude=` line of `/etc/dnf/dnf.conf` (the pins of eFa-next stay), and ELevate, leapp and the el9 kernels removed (never the
running kernel; only with an el10 kernel installed). If leapp still runs after the wait, SELinux and leapp stay and the
checks fail. Then it checks: AlmaLinux 10 and an el10 kernel, no el9 packages left, `dnf check`, SELinux enforcing without denials since then, time synchronised, the same addresses,
routes, firewall zones and ports and other nft tables as before, Postfix, rspamd, ClamAV, MariaDB, Valkey or Redis, Unbound,
nginx and the eFa-next services running, a clean test mail accepted while GTUBE and EICAR are rejected, the same DKIM keys,
`mysqlcheck`, the same counts, a new backup, no Perl package that was not there before (except `perl-locale`, which EL10
split off perl-POSIX), `nginx -t`, and the same settings:
`postconf -n` and `-P` (table types aside), the text files below rspamd local.d and override.d, nginx and unbound conf.d,
fail2ban jail.d, the ClamAV daemon, the SSH profile, /etc/postfix and /etc/efa-web, and the enabled eFa-next units, as
exported before `leapp upgrade`. Any difference fails the check.

Only when every check passes, the maintenance mode is lifted and mail is accepted again, and what leapp left on disk
(`/etc/leapp/files`, `/var/lib/leapp`, `/root/tmp_leapp_py3`; its logs in `/var/log/leapp` stay) is removed. Otherwise new mail keeps getting
`421`, the dashboard and the admin mail name the failed checks, and the log has the details.
