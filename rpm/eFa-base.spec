# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
#
# eFa-base: OS packages, service configuration, monitor, SELinux module.
# Build with build/build-rpms.py.

# Keep the build host name out of the package header.
%global _buildhost localhost
# The file list is explicit; do not let rpmbuild add byte-compiled files.
%global __brp_python_bytecompile %{nil}

Name:           eFa-base
# Epoch 1 as in eFa-base 1:6.0.0.2: without it, 6.0.0.3 counts as a downgrade.
Epoch:          1
Version:        6.0.0.4
Release:        1%{?dist}
Summary:        eFa-next base: service configuration for the mail filter
License:        AGPL-3.0-or-later
URL:            https://github.com/MarkusLorber/eFa-next
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

BuildRequires:  checkpolicy
BuildRequires:  policycoreutils

Requires:       python3
Requires:       systemd
Requires:       postfix
Requires:       rsyslog
Requires:       mariadb-server
Requires:       redis
Requires:       rspamd
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
if [ "$1" -eq 1 ]; then
    touch /var/lib/rpm-state/eFa-base/first-install
fi
exit 0

%posttrans
mode=upgrade
if [ -e /var/lib/rpm-state/eFa-base/first-install ]; then
    mode=first-install
fi
rm -f /var/lib/rpm-state/eFa-base/first-install
/usr/sbin/efa-configure --package-hook eFa-base "$mode" --package-version %{version}

%preun
if [ "$1" -eq 0 ]; then
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
/usr/lib/eFa/python/efa_services.py
%attr(0755,root,root) /usr/sbin/efa-configure
%attr(0755,root,root) /usr/sbin/efa-monitor
/usr/lib/systemd/system/efa-reboot-check.service
/usr/lib/systemd/system/efa-reboot-check.timer
%config(noreplace) /etc/sysconfig/eFa-Monitor
%config(noreplace) /etc/logrotate.d/eFa
%ghost %attr(0644,root,root) /etc/cron.d/eFa-Monitor.cron
%dir /usr/share/selinux/packages/eFa
/usr/share/selinux/packages/eFa/efa.pp
%dir %attr(0755,root,root) /etc/eFa
%dir %attr(0750,root,root) /var/log/eFa
%dir %attr(0750,root,root) /var/lib/eFa

%changelog
* Sat Nov 07 2026 Markus Lorber - 6.0.0.4-1
- 6.0.0.4: fast web interface, tenants and roles, quarantine self-service, link check, CDR, BEC, DMARC reports, TLS profiles, uplinks; see CHANGELOG.md.

* Thu Nov 05 2026 eFa-next contributors - 6.0.0.3-1
- Clean-room rebuild of the base package.
