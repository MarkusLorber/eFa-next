# FreeBSD port (target: 6.0.0.5)

eFa-next is to run on FreeBSD from 6.0.0.5, as a fresh install (no migration from eFa 5 there). This page lists what stands in the way today. Rule from now on: no new code calls an OS tool or an EL9 path directly; it goes through the platform layer (`efa_platform.py`, with `efa_platform_el9.py` and later `efa_platform_freebsd.py`), which grows where something is missing.

## The check

`scripts/os_lint.py`, run by `scripts/ci.sh`, counts direct calls outside the platform layer per file: `systemctl`, `dnf`/`rpm`/`yum`, `firewall-cmd`/`nft`/`ipset`, SELinux tools, `augenrules`/`auditctl`, `systemd-run`, `journalctl`, `logrotate`, `/etc/sysconfig`, `/proc`. A file with more than its count in `scripts/os-calls-baseline.json` fails the check. When a call moves into the platform layer, run `scripts/os_lint.py --write-baseline` so the lower count holds.

## What calls the OS directly today (baseline 2026-11-05: 125 lines in 8 files)

| File | Calls | What it is |
|---|---|---|
| `next/usr/sbin/efactl` | systemctl 45, dnf/rpm 16, firewalld 9, systemd-run 4, journalctl 2, SELinux 1, /etc/sysconfig 1 | Service control, updates and the package check, the firewall and its guard, background jobs, the event collector, the SELinux context of the Wazuh files. The largest part of the port: efactl does not use the platform layer yet. |
| `migration/efa-migrate` | systemctl 12, dnf/rpm 11, /etc/sysconfig 4, /proc 1 | Migration from eFa 5, EL9 only by design: not needed on FreeBSD. |
| `next/usr/lib/eFa/setup/rspamd-config.sh` | systemctl 6 | First install. |
| `next/usr/local/sbin/efa-web.py` | /proc 4 | Load card: `/proc/stat`, `/proc/meminfo`, `/proc/diskstats`, `/proc/net/dev`. FreeBSD: `sysctl` values through the platform layer. |
| `next/usr/lib/eFa/setup/efa-next-setup` | /etc/sysconfig 2, systemctl 1 | Upgrade hook of the RPM. FreeBSD: a pkg hook. |
| `next/usr/local/sbin/efa-milter-health.py` | systemctl 2, /etc/sysconfig 1 | Health service. |
| `next/usr/lib/eFa/setup/nginx-config.sh` | SELinux 1, systemctl 1 | First install. |
| `next/usr/share/eFa/wazuh/sca-efa-next.yml` | systemctl 1 | A check of the SCA policy: an EL policy; FreeBSD gets its own. |

## Also to do for FreeBSD

- **Paths**: Postfix, rspamd, nginx, Unbound, Redis, MariaDB, ClamAV live under `/usr/local/etc/` on FreeBSD. efactl has them as constants (`ETC + '/postfix/...'`, `RSPAMD_DIR`); they move into the platform layer as logical names (`efa_platform.path()` exists for that).
- **Services**: systemd units and timers (`next/usr/lib/systemd/system/`) become rc.d scripts and cron entries; the platform layer already has `service_*` methods for this.
- **Firewall**: firewalld and the guard become pf; the platform layer has `firewall_allow`, the guard and the update check need more.
- **Packages and updates**: dnf, rpm and dnf-automatic become pkg; the package-script check of the system update (firewall reloads) needs its pkg version.
- **Users and groups** (`useradd`, `usermod`): through the platform layer (`user_add` exists).
- **Backups**: the archive stores absolute paths today. To restore an EL9 backup on FreeBSD, paths must be stored as logical names (for example `postfix:main.cf`) and mapped back by the platform layer on restore.
- **Shell scripts**: the setup scripts already start with `#!/bin/sh` and pass `sh -n`; `build/build.bash` is EL9 only and stays bash.
- **Python**: standard library only; `grp`, `pwd`, `fcntl`, `curses` exist on FreeBSD. No Linux-only module is used outside the files above.
- **TUI** (5k): curses, to be tested on FreeBSD.
- **Content disarm** (3): the milter needs qpdf (`pkg install qpdf`) and pymilter (`py311-pymilter`); `package_fetch` and `package_scripts` of the platform layer become pkg fetch and the scripts of a pkg file. The unit `efa-cdr` with DynamicUser and StateDirectory becomes an rc.d script with an own user and `/var/db/efa-cdr`.
- **auditd rules** (5f): FreeBSD has audit(4) with `audit_control` instead of augenrules; `audit_rules` of the platform layer writes those.
- **Append only** (5f): `chattr +a` becomes `chflags sappnd`.
