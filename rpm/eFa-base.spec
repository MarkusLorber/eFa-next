# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
#
# eFa-next-base: OS packages, service configuration, monitor, SELinux module.
# Build with build/build-rpms.py.

# Keep the build host name out of the package header.
%global _buildhost localhost
# The file list is explicit; do not let rpmbuild add byte-compiled files.
%global __brp_python_bytecompile %{nil}

Name:           eFa-next-base
# Epoch 1 as in eFa-base 1:6.0.0.2: without it, 6.0.0.3 counts as a downgrade.
Epoch:          1
Version:        6.0.0.6.8
Release:        1%{?dist}
Summary:        eFa-next base: service configuration for the mail filter
License:        AGPL-3.0-or-later
URL:            https://github.com/MarkusLorber/eFa-next
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch
# Until 6.0.0.4 the package was called eFa-base; the epoch belongs in the version, else 1:6.0.0.4 is not older.
Provides:       eFa-base = 1:%{version}-%{release}
Obsoletes:      eFa-base < 1:6.0.0.4.1

BuildRequires:  checkpolicy
BuildRequires:  policycoreutils

Requires:       python3
Requires:       systemd
Requires:       postfix
Requires:       rsyslog
Requires:       mariadb-server
%if 0%{?rhel} >= 10
Requires:       valkey
# The Postfix tables of EL10 are lmdb (no Berkeley DB): only a weak dependency of postfix, so without it (install_weak_deps
# off, or after a dnf remove with autoremove) every postmap of the setup failed.
Requires:       postfix-lmdb
# The domain of clamd and freshclam (antivirus_t) is in the extra modules of the policy (CRB) in EL10: without them ClamAV runs
# unconfined. Weak: a host without CRB still installs and updates, the module of eFa-next loads either way (1.4.1).
Recommends:     selinux-policy-targeted-extra
%else
Requires:       redis
%endif
# 4.3.0: fixes of crashes of the workers and of the milter, ARC and Authentication-Results (CVE-4); the major lock stays in rspamd.repo.
# 4.3.1 (EFA-2026-009): DMARC reject kept for a malformed SPF domain, DKIM results not hidden by one bad signature, a clamd reply
# without a verdict is a scan failure, worker crashes in lua_tcp, timers and html/mime fixed.
Requires:       rspamd
# rspamd 4.3.1 at least (EFA-2026-009, before EFA-2026-005). Its packages also provide a plain "rspamd" without a version, which meets any
# "rspamd >= x": only the arch-bound name carries the version, so dnf really takes 4.3.1 along with this update.
Requires:       (rspamd(x86-64) >= 4.3.1 or rspamd(aarch-64) >= 4.3.1)
Requires:       nginx
Requires:       clamav
Requires:       clamd
Requires:       clamav-update
Requires:       unbound
Requires:       fail2ban-server
Requires:       fail2ban-firewalld
Requires:       firewalld
Requires:       dnf-automatic
Requires:       dnf-utils
Requires:       cronie
Requires:       logrotate
Requires:       openssl
Requires:       openssh-server
Requires:       sudo
Requires:       NetworkManager
Requires:       chrony
Requires:       policycoreutils
Requires:       selinux-policy-targeted

%description
Base package of eFa-next, an email filter appliance. It pulls in the
needed OS packages and configures Postfix, ClamAV, MariaDB, Unbound,
SSH, Fail2Ban, dnf-automatic and firewalld. It also holds the service
monitor, log rotation and the SELinux module.

%prep
%setup -q

%build
checkmodule -M -m -o selinux/efa.mod selinux/efa.te
semodule_package -o selinux/efa.pp -m selinux/efa.mod

%install
cp -a root/. %{buildroot}/
install -D -m 0644 selinux/efa.pp %{buildroot}/usr/share/selinux/packages/eFa/efa.pp
install -d -m 0755 %{buildroot}/etc/eFa
install -d -m 0750 %{buildroot}/var/log/eFa
install -d -m 0750 %{buildroot}/var/lib/eFa
install -d -m 0755 %{buildroot}/etc/cron.d
touch %{buildroot}/etc/cron.d/eFa-Monitor.cron

%pre
# Stop before any file changes on an eFa 5 system, first install too (use efa-migrate).
if [ -e /etc/MailScanner/MailScanner.conf ]; then
    echo "eFa-base: /etc/MailScanner/MailScanner.conf exists: this is an eFa 5 system." >&2
    echo "eFa-base: upgrade stopped, nothing was changed. Use efa-migrate." >&2
    exit 1
fi
mkdir -p /var/lib/rpm-state/eFa-base
# First install unless eFa-next 6 or later is set up here (its version file is written only when every step passed):
# replacing the packages eFa and eFa-base of 6.0.0.4 (Obsoletes) is an upgrade, an eFa 5 host is a first install.
# Also a reinstall after a first install whose setup failed: without the version file the setup has not finished yet.
# A set-up host is never a first install, also when the version file is gone: the first-install steps would replace
# its nginx, rspamd and Postfix settings.
if ! grep -Eqs '^eFa-([6-9]|[1-9][0-9])\.' /etc/eFa-next-Version /etc/eFa-Version && ! grep -Eqs '^[[:space:]]*CONFIGURED[[:space:]]*:[[:space:]]*YES' /etc/eFa/eFa-Config; then
    touch /var/lib/rpm-state/eFa-base/first-install
fi
exit 0

%posttrans
mode=upgrade
if [ -e /var/lib/rpm-state/eFa-base/first-install ]; then
    mode=first-install
fi
rm -f /var/lib/rpm-state/eFa-base/first-install
# The user of rspamd before anything configures it: rspamd 4.3.0 (el9) no longer creates it, so its own chown failed and the
# service did not start on a new host. Its folders then go to it as its package would have done.
systemd-sysusers /usr/lib/sysusers.d/efa-rspamd.conf >/dev/null 2>&1 || :
for dir in /var/lib/rspamd /var/log/rspamd; do
    [ -d "$dir" ] && [ "$(stat -c %U "$dir")" != _rspamd ] && chown -R _rspamd:_rspamd "$dir"
done
# Bytecode of eFa-next programs next to /usr/sbin and /usr/local/sbin belongs to no package (a program loaded as a module):
# only files of eFa-next go, the folder only when it is empty then.
for cache in /usr/sbin/__pycache__ /usr/local/sbin/__pycache__; do
    [ -d "$cache" ] || continue
    find "$cache" -maxdepth 1 -type f -name 'efa*.pyc' -delete
    rmdir "$cache" 2>/dev/null || :
done
# The bytecode of every module, checked by the hash of its source: the build clamps all times to SOURCE_DATE_EPOCH, so a
# changed module of the same size kept its old bytecode by time and size, and an upgrade ran old code.
python3 -m compileall -q -f --invalidation-mode checked-hash /usr/lib/eFa/python >/dev/null 2>&1 || :
/usr/sbin/efa-configure --package-hook eFa-base "$mode" --package-version %{version}

%preun
if [ "$1" -eq 0 ]; then
    rm -rf /usr/lib/eFa/python/__pycache__
    systemctl --no-reload disable --now efa-reboot-check.timer >/dev/null 2>&1 || :
fi

%postun
if [ "$1" -eq 0 ]; then
    semodule -r efa >/dev/null 2>&1 || :
    systemctl daemon-reload >/dev/null 2>&1 || :
fi

%files
%dir /usr/lib/eFa
%dir /usr/lib/eFa/python
/usr/lib/eFa/python/efa_common.py
/usr/lib/eFa/python/efa_configure.py
/usr/lib/eFa/python/efa_monitor.py
/usr/lib/eFa/python/efa_platform.py
/usr/lib/eFa/python/efa_platform_el9.py
/usr/lib/eFa/python/efa_platform_el10.py
/usr/lib/eFa/python/efa_services.py
%attr(0755,root,root) /usr/sbin/efa-configure
%attr(0755,root,root) /usr/sbin/efa-monitor
/usr/lib/systemd/system/efa-reboot-check.service
/usr/lib/systemd/system/efa-time-sync.service
/usr/lib/systemd/system/efa-reboot-check.timer
%config(noreplace) /etc/sysconfig/eFa-Monitor
%config(noreplace) /etc/logrotate.d/eFa
/usr/lib/sysusers.d/efa-rspamd.conf
%ghost %attr(0644,root,root) /etc/cron.d/eFa-Monitor.cron
%dir /usr/share/selinux/packages/eFa
/usr/share/selinux/packages/eFa/efa.pp
%dir %attr(0755,root,root) /etc/eFa
%dir %attr(0750,root,root) /var/log/eFa
%dir %attr(0750,root,root) /var/lib/eFa

%changelog
* Mon Nov 23 2026 Markus Lorber - 6.0.0.6.8-1
- 6.0.0.6.8: rspamd 4.3.1 is the minimum (DMARC reject bypass, hidden DKIM results, virus scan without a verdict, worker crashes); see CHANGELOG.md.

* Sun Nov 22 2026 Markus Lorber - 6.0.0.6.7-1
- 6.0.0.6.7: 2FA required for every admin, the compliance file of each release (JSON, Markdown, OSCAL), the base system updates with dnf, cluster hardening and break-glass admin, GDPR erasure, file check, restore test, incident reports; see CHANGELOG.md.

* Thu Nov 19 2026 Markus Lorber - 6.0.0.6.6.2-1
- 6.0.0.6.6.2: a cluster node keeps following its master when Fail2Ban or one journal entry fails, and the master raises an alarm when a node lags or stops; see CHANGELOG.md.

* Wed Nov 18 2026 Markus Lorber - 6.0.0.6.6.1-1
- 6.0.0.6.6.1: the status answer of a cluster node works again (the master saw every node as not reachable); settings files sent by the master get the owner of the settings table, not root:root; the second factors of the logins go to the nodes; web HTTP/2 off by default (nginx CVE-2026-123007, -123633, -121810, -113425); see CHANGELOG.md.

* Wed Nov 18 2026 Markus Lorber - 6.0.0.6.6-1
- 6.0.0.6.6: release upgrade to EL10 with leapp 0.25 (vendor maps 2.0.0, signing keys), SELinux module 1.4.1 for AlmaLinux 10.3, port 587 and checks after the upgrade, clusters of EL9 and EL10 nodes updated one at a time, guided 2FA setup and pages by task; see CHANGELOG.md.

* Wed Nov 18 2026 Markus Lorber - 6.0.0.6.5-1
- 6.0.0.6.5: 2FA set up again after a reset, Let's Encrypt behind split-horizon DNS, migration checks first; see CHANGELOG.md.

* Sun Nov 15 2026 Markus Lorber - 6.0.0.6.4-1
- 6.0.0.6.4: one Update card with versions, progress bar, step and time left; see CHANGELOG.md.

* Sat Nov 14 2026 Markus Lorber - 6.0.0.6.3-1
- 6.0.0.6.3: mail log search window, page Privacy & Compliance, language pill, dashboard and footer; see CHANGELOG.md.

* Sat Nov 14 2026 Markus Lorber - 6.0.0.6.2-2
- rspamd 4.3.0 required by its arch-bound name: the plain Provides of rspamd met "rspamd >= 4.3.0" with 4.2.3 too.

* Sat Nov 14 2026 Markus Lorber - 6.0.0.6.2-1
- 6.0.0.6.2: rspamd 4.3.0 is the minimum (worker crash, milter use-after-free, ARC and Authentication-Results); see CHANGELOG.md.

* Sat Nov 14 2026 Markus Lorber - 6.0.0.6.1-1
- 6.0.0.6.1: the 2FA of the main admin is never removed as a left-over row; a missing 2FA table refuses the login (S38); see CHANGELOG.md.

* Fri Nov 13 2026 Markus Lorber - 6.0.0.6-2
- 6.0.0.6 final: a test build of 6.0.0.6-1 (EL10, November 12) was online; -2 replaces it through a normal update.

* Tue Nov 10 2026 Markus Lorber - 6.0.0.6-1
- 6.0.0.6: security fixes first (web interface without sudo, restore, single sign-on, login directories); see CHANGELOG.md.

* Tue Nov 10 2026 Markus Lorber - 6.0.0.5.2-1
- 6.0.0.5.2: migration from eFa 5 (sender_access no longer read once moved), SELinux quiet without IPv6; see CHANGELOG.md.

* Mon Nov 09 2026 Markus Lorber - 6.0.0.5.1-1
- 6.0.0.5.1: security fixes (web forms, rspamd repository over https, settings files); see CHANGELOG.md.

* Sun Nov 08 2026 Markus Lorber - 6.0.0.5-1
- 6.0.0.5: security and protection additions, offline bundles, CVE watch, four-eyes approvals; see CHANGELOG.md.

* Sat Nov 07 2026 Markus Lorber - 6.0.0.4.1-1
- Packages renamed to eFa-next and eFa-next-base; they replace eFa and eFa-base, settings stay.
- 6.0.0.4.1: BEC checks on for new installs, subdomain trick and other domain endings caught; see CHANGELOG.md.

* Sat Nov 07 2026 Markus Lorber - 6.0.0.4-1
- 6.0.0.4: fast web interface, tenants and roles, quarantine self-service, link check, CDR, BEC, DMARC reports, TLS profiles, uplinks; see CHANGELOG.md.

* Thu Nov 05 2026 eFa-next contributors - 6.0.0.3-1
- Clean-room rebuild of the base package.
