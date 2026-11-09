# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
#
# eFa-next: first-run setup programs plus the eFa-next programs (efactl,
# efa-web.py, efa-init.py, ...). Those come from the source folder next/,
# laid out like the target file system; build/build-rpms.py --next-dir adds it.

# Keep the build host name out of the package header.
%global _buildhost localhost
%global __brp_python_bytecompile %{nil}

Name:           eFa-next
Version:        6.0.0.5.1
Release:        1%{?dist}
Summary:        eFa-next email filter appliance
License:        AGPL-3.0-or-later
URL:            https://github.com/MarkusLorber/eFa-next
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch
# Replaces the package eFa of 6.0.0.4 and older.
Provides:       eFa = %{version}-%{release}
Obsoletes:      eFa < 6.0.0.4.1

Requires:       eFa-next-base = 1:%{version}-%{release}
# Used by the eFa-next programs in next/.
Requires:       python3-flask
Requires:       python3-waitress
Requires:       python3-PyMySQL
Requires:       python3-pymilter
# The journal of the cluster master is encrypted (Fernet).
Requires:       python3-cryptography
Requires:       python3-certbot-nginx
Requires:       certbot
Requires:       bind-utils
Requires:       gnupg2
Requires:       tar
Requires:       openldap-clients
Obsoletes:      clamav-unofficial-sigs
Requires:       python3
# Only for content disarm, installed when it is switched on.
Suggests:       qpdf
Requires:       sudo
Requires:       systemd

%description
eFa-next turns an EL9 host into an email filter gateway. This package
holds the first-run setup (the program that applies the wizard answers
and the after-first-boot job), the backup job and the eFa-next programs.

%prep
%setup -q

%build

%install
cp -a root/. %{buildroot}/
: > next-files.list
if [ -d next ]; then
    cp -a next/. %{buildroot}/
    ( cd next && find . \( -type f -o -type l \) | sort ) | sed 's|^\./|/|' |
    while IFS= read -r f; do
        case "$f" in
            /etc/*) echo "%%config(noreplace) $f" ;;
            *) echo "$f" ;;
        esac
    done > next-files.list
    # efactl runs for every page of the web interface: as a module Python keeps its bytecode instead of compiling 17,000 lines per call.
    mv %{buildroot}/usr/sbin/efactl %{buildroot}/usr/lib/eFa/python/efactl_main.py
    printf '%%s\n' '#!/usr/bin/python3' '# The code of efactl is /usr/lib/eFa/python/efactl_main.py.' 'import sys' \
        "sys.path.insert(0, '/usr/lib/eFa/python')" 'import efactl_main' 'sys.exit(efactl_main.main())' > %{buildroot}/usr/sbin/efactl
    chmod 0755 %{buildroot}/usr/sbin/efactl
    echo /usr/lib/eFa/python/efactl_main.py >> next-files.list
fi

%pre
# Stop before any file changes on an eFa 5 system, first install too (use efa-migrate).
if [ -e /etc/MailScanner/MailScanner.conf ]; then
    echo "eFa: /etc/MailScanner/MailScanner.conf exists: this is an eFa 5 system." >&2
    echo "eFa-next: upgrade stopped, nothing was changed. Use efa-migrate." >&2
    exit 1
fi
mkdir -p /var/lib/rpm-state/eFa
# First install unless eFa-next 6 or later is set up here (its version file is written only when every step passed):
# replacing the packages eFa and eFa-base of 6.0.0.4 (Obsoletes) is an upgrade, an eFa 5 host is a first install.
# Also a reinstall after a first install whose setup failed: without the version file the setup has not finished yet.
# A set-up host is never a first install, also when the version file is gone: the first-install steps would replace
# its nginx, rspamd and Postfix settings.
if ! grep -Eqs '^eFa-([6-9]|[1-9][0-9])\.' /etc/eFa-Version && ! grep -Eqs '^[[:space:]]*CONFIGURED[[:space:]]*:[[:space:]]*YES' /etc/eFa/eFa-Config; then
    touch /var/lib/rpm-state/eFa/first-install
fi
exit 0

%posttrans
mode=upgrade
if [ -e /var/lib/rpm-state/eFa/first-install ]; then
    mode=first-install
fi
rm -f /var/lib/rpm-state/eFa/first-install
# Bytecode of eFa-next programs next to /usr/sbin and /usr/local/sbin belongs to no package (a program loaded as a module):
# only files of eFa-next go, the folder only when it is empty then.
for cache in /usr/sbin/__pycache__ /usr/local/sbin/__pycache__; do
    [ -d "$cache" ] || continue
    find "$cache" -maxdepth 1 -type f -name 'efa*.pyc' -delete
    rmdir "$cache" 2>/dev/null || :
done
# The ExecStartPre drop-ins of the security minimum (postfix, nginx, dovecot) and efa-floor-guard.path count from here on, before
# efa-next-setup sets the limit and enables the path unit; the file trigger of systemd would reload only after this script.
systemctl daemon-reload >/dev/null 2>&1 || :
# The bytecode of every module, checked by the hash of its source: the build clamps all times to SOURCE_DATE_EPOCH, so a
# changed module of the same size kept its old bytecode by time and size, and an upgrade ran old code.
# efactl among them, written here instead of by the first web request.
python3 -m compileall -q -f --invalidation-mode checked-hash /usr/lib/eFa/python >/dev/null 2>&1 || :
# The own setup of the eFa-next programs comes first: if it fails, the version file stays unwritten.
/bin/sh /usr/lib/eFa/setup/efa-next-setup "$mode" && /usr/sbin/efa-configure --package-hook eFa "$mode" --package-version %{version}
result=$?
# rspamd reads the version for its headers when it loads its config.
systemctl try-reload-or-restart rspamd >/dev/null 2>&1 || :
exit $result

%preun
if [ "$1" -eq 0 ]; then
    # The bytecode belongs to no package: it goes with the last one, else a new install could find it.
    rm -rf /usr/lib/eFa/python/__pycache__
    systemctl --no-reload disable --now efa-setup-reboot.path >/dev/null 2>&1 || :
    # The guard of the security minimum goes with the package; its drop-ins leave with the files, the reload is in %postun.
    systemctl --no-reload disable --now efa-floor-guard.path >/dev/null 2>&1 || :
    systemctl --no-reload disable efa-firstboot.service efa-kickstart.service >/dev/null 2>&1 || :
fi

%postun
if [ "$1" -eq 0 ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
fi

%files -f next-files.list
/usr/lib/eFa/python/efa_apply.py
/usr/lib/eFa/python/efa_firstboot.py
%attr(0755,root,root) /usr/sbin/efa-apply
%dir /usr/libexec/eFa
%attr(0755,root,root) /usr/libexec/eFa/efa-firstboot
/usr/lib/systemd/system/efa-firstboot.service
/usr/lib/systemd/system/efa-kickstart.service
/usr/lib/systemd/system/efa-setup-reboot.path
/usr/lib/systemd/system/efa-setup-reboot.service
%config(noreplace) /etc/cron.d/eFa-Backup.cron

%changelog
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
- Clean-room rebuild of the setup programs and packaging.
