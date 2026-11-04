#-----------------------------------------------------------------------------#
# eFa SPEC file definition
#-----------------------------------------------------------------------------#
# Copyright (C) 2023 https://efa-project.org
#
# This SPEC is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This SPEC is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this SPEC. If not, see <http://www.gnu.org/licenses/>.
#-----------------------------------------------------------------------------#

%define releasenum 1

Name:      eFa
Summary:   eFa Maintenance rpm
Version:   6.0.0.1
Release:   %{releasenum}.eFa%{?dist}
Group:     Applications/System
URL:       https://efa-project.org
License:   GNU GPL v3+
# The source directory keeps its name, the scripts in it refer to it.
Source0:   eFa-5.0.0.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch: noarch
# Control dependencies here as updates are released
# Use version and release numbers required for each update
# to maintain strict version control and dependency resolution
Requires:  clamav >= 0.103.8-3
    # clamav                                     # epel    # AV
Requires:  clamav-update >= 0.103.8-3
    # clamav-update                              # epel    # AV
Requires:  clamd >= 0.103.8-3
    # clamd			                             # epel    # AV
Requires:  mariadb-server >= 3:10.5.16-2
    # httpd                                      # base    # mailwatch, frontend
Requires:  cyrus-sasl-md5 >= 2.1.27-20
    # mod_ssl                                    # base    # httpd
Requires: postfix
    # postfix                                    # eFa     # MTA
Requires:  unbound >= 1.16.2-2
    # unbound                                    # eFa     # DNS
Requires:  dnf-automatic >= 4.12.0-4
    # dnf auto updates                           # base    # dnf-automatic
Requires:  checkpolicy >= 3.4-1
    # checkpolicy                                # base    # selinux
Requires: python3-waitress
Requires: python3-flask
Requires: python3-PyMySQL
Requires: python3-pyyaml
    # migrated in Sprint 15 to python3-lxml + xml.etree.ElementTree
    # Decision: XML processing replaced by the Python stdlib
Requires: dovecot >= 1:2.3.16-7
    # dovecot                                    # base    # postfix
Requires: virt-what >= 1.25-1
    # virt-what                                  # base    # eFa
Requires: openssh-server >= 8.7p1-24
    # openssh-server                             # base    # eFa
Requires: sudo >= 1.9.5p2-7
    # sudo                                       # base    # eFa
Requires: chrony >= 4.2-1
    # chrony                                     # base    # eFa
Requires: firewalld >= 1.1.1-3
    #                                            # epel    # mailwatch, frontend
Requires: rsync => 3.2.3-18
    #                                            # epel    # eFa
Requires: cyrus-sasl >= 2.1.27-20
    #                                            # base    # eFa
Requires: cyrus-sasl-lib >= 2.1.27-20
    #                                            # base    # eFa
Requires: cyrus-sasl-plain >= 2.1.27-20
    #                                            # base    # opendmarc
Requires: fail2ban >= 1.0.1-2
    #                                            # epel    # eFa
Requires: rsyslog >= 8.2102.0-105
    #                                            # base    # eFa
Requires: NetworkManager >= 1.42.2-1
    # Decision: keep for cryptographic operations (if needed)
    # Check: whether eFa really uses it for cryptographic operations
    #                                            # appstream # eFa
Requires: ipcalc >= 1.0.0-5
    # migrated in Sprint 15 to argparse (Python stdlib)
    # Decision: argparse is more powerful than Getopt-Long, standard in Python
    #                                            # appstream # MailScanner
    #                                            # appstream # MailScanner, spamassassin
    #                                            # epel      # MailScanner
    #                                            # epel      # MailScanner
    #                                            # epel      # efa-milter-health
Requires: python3-pymilter
    #                                            # rspamd    # rspamd milter
Requires: nginx
Requires: python3-certbot-nginx
Requires: rspamd
    #                                            # appstream # rspamd Bayes, greylisting, DMARC reports
Requires: redis
    # MailScanner                                # eFa     # MailScanner
    # p7zip                                      # epel    # MailScanner
    # p7zip-plugins                              # epel    # MailScanner
Requires: file >= 5.39-10
    # file                                       # base    # MailScanner
Requires: tar >= 2:1.34-6
    #                                            # eFa     # MailScanner
    #                                            # appstream # spamassassin
    #                                            # eFa       # spamassassin
# migrated in Sprint 14 to python3-chardet for encoding detection
# Decision: chardet provides character detection via pip install chardet
    #                                            # appstream # spamassassin
    # perl-Encoding-FixLatin                     # eFa       # MailWatch
Requires:  tmpwatch >= 2.11-20
    # spamassassin                               # eFa     # MailScanner
Requires: clamav-unofficial-sigs
    # clamav-unofficial-sigs                     # eFa     # clamav
Requires: eFa-base >= 1:6.0.0.1
    # perl-DBD-mysql                             # base    # spamassassin
Requires: chkconfig >= 1.20-2
    #                                            # base    # dcc
Requires: python3-requests
    #                                            # epel    # spamassassin
Requires: certbot >= 2.9.0-1
    #                                            # epel    # eFa
Requires: tuned >= 2.22.1-1
    #                                            # base    # eFa
Requires: bash-completion >= 1:2.11-5
    #                                            # base    # eFa
Requires: vim-enhanced >= 8.2.2637-20
    #                                            # base    # eFa

# Unverified dependencies
#Requires:  openssl-devel >= 1:3.0.7-5
#    # openssl-devel                              # base    # MailScanner
#Requires:  patch >= 2.7.6-16
#    # patch                                      # base    # MailScanner
#Requires:  bzip2-devel >= 1.0.6-13
#    # bzip2-devel                                # base    # MailScanner
#Requires:  gcc >= 4.8.5-36
#    # gcc                                        # base    # MailScanner
#Requires:  perl-Convert-BinHex >= 1.119-20
#    # perl-Convert-BinHex                        # epel    # MailScanner
#Requires:  perl-Convert-TNEF >= 0.18-2
#    # perl-Convert-TNEF                          # epel    # MailScanner
#Requires:  perl-CPAN >= 1.9800-293
#    # perl-CPAN                                  # base    # MailScanner
#Requires:  perl-Data-Dump >= 1.22-1
#    # perl-Data-Dump                             # epel    # MailScanner
#Requires:  perl-Digest-HMAC >= 1.03-5
#    # perl-Digest-HMAC                           # base    # MailScanner
#Requires:  perl-Encode-Detect >= 1.01-13
#    # perl-Encode-Detect                         # base    # MailScanner
#Requires:  perl-ExtUtils-CBuilder >= 0.28.2.6-293
#    # perl-ExtUtils-CBuilder                     # base    # MailScanner
#Requires:  perl-ExtUtils-MakeMaker >= 6.68-3
#    # perl-ExtUtils-MakeMaker                    # base    # MailScanner
#Requires:  perl-File-ShareDir-Install >= 0.08-1
#    # perl-File-ShareDir-Install                 # epel    # MailScanner
#Requires:  perl-Inline >= 0.53-4
#    # perl-Inline                                # base    # MailScanner
#Requires:  perl-LDAP >= 0.56-6
#    # perl-LDAP                                  # base    # MailScanner
#Requires:  perl-Mail-IMAPClient >= 3.37-1
#    # perl-Mail-IMAPClient                       # epel    # MailScanner
#Requires:  perl-Module-Build >= 0.40.05-2
#    # perl-Module-Build                          # base    # MailScanner
#Requires:  perl-Net-IP >= 1.26-4
#    # perl-Net-IP                                # epel    # MailScanner
#Requires:  perl-Test-Manifest >= 1.23-2
#    # perl-Test-Manifest                         # base    # MailScanner
#Requires:  perl-Test-Pod >= 1.48-3
#    # perl-Test-Pod                              # base    # MailScanner
#Requires:  perl-YAML >= 0.84-5
#    # perl-YAML                                  # base    # MailScanner
#Requires:  libtool-ltdl >= 2.4.2-22
#    # libtool-ltdl                               # base    # MailScanner
#Requires:  perl-IP-Country >= 2.28-1
#    # perl-IP-Country                            # eFa     # MailScanner, Spamassassin
#Requires:  perl-Mail-SPF-Query >= 1.999.1-1
#    # perl-Mail-SPF-Query                        # eFa     # MailScanner
#Requires:  perl-Geography-Countries >= 2009041301-17
#    # perl-Geography-Countries                   # eFa     # Spamassassin
#Requires:  perl-libnet >= 3.11-1
#    # perl-libnet                                # eFa     # Spamassassin
#Requires: perl-Math-Int64 >= 0.52
#    #                                            # epel    # spamassassin
#Requires: perl-namespace-autoclean >= 0.19-1
#    #                                            # epel    # spamassassin
#Requires: perl-Data-IEEE754 >= 0.02-1
#    #                                            # eFa     # spamassassin
#Requires: perl-Data-Printer >= 0.40-1
#    #                                            # eFa     # spamassassin
#Requires: perl-Data-Validate-IP >= 0.27-1
#    #                                            # eFa     # spamassassin
#Requires: perl-GeoIP2-Country-Reader >= 2.006002-1
#    #                                            # eFa     # spamassassin
#Requires: perl-List-AllUtils >= 0.15-1
#    #                                            # eFa     # spamassassin
#Requires: perl-List-SomeUtils >= 0.58-1
#    #                                            # eFa     # spamassassin
#Requires: perl-List-UtilsBy >= 0.11-1
#    #                                            # eFa     # spamassassin
#Requires: perl-MaxMind-DB-Metadata >= 0.040001-1
#    #                                            # eFa     # spamassassin
#Requires: perl-Module-Runtime >= 0.016-1
#    #                                            # eFa     # spamassassin
#Requires: perl-Moo >= 2.003006-1
#    #                                            # eFa     # spamassassin
#Requires: perl-MooX-StrictConstructor >= 0.010-1
#    #                                            # eFa     # spamassassin
#Requires: perl-Role-Tiny >= 2.001004-1
#    #                                            # eFa     # spamassassin
#Requires: perl-Scalar-List-Utils >= 1.53-1
#    #                                            # eFa     # spamassassin
#Requires: perl-strictures >= 2.000006-1
#    #                                            # eFa     # spamassassin
#Requires: perl-Sub-Quote >= 2.006006-1
    # Decision in Sprint 16: removed - Sub::Quote functionality through stdlib
    # additions not needed in the eFa core
#    #                                            # eFa     # spamassassin
#Requires: perl-Math-Int128 >= 0.22-1
#    #                                            # eFa     # spamassassin
#Requires: perl-Net-Works-Network >= 0.22-1
#    #                                            # eFa     # spamassassin


%description
eFa stands for Email Filter Appliance. eFa is born out of a need for a
cost-effective email virus & spam scanning solution after the ESVA project
died.

We try to create a complete package using existing open-source anti-spam
projects and combine them to a single easy to use (virtual) appliance.

For more information go to https://efa-project.org

eFa v5 is a rebuild of the previous eFa v4; the same components are used whenever
possible but are all updated to the latest version.

%prep
%setup -q -n eFa-5.0.0

%build

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT

# Move eFa-Configure into position
mkdir -p $RPM_BUILD_ROOT%{_sbindir}
mv eFa/eFa-Configure $RPM_BUILD_ROOT%{_sbindir}

# Move modules into position
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/eFa/lib/selinux
mv eFa/eFa.fc $RPM_BUILD_ROOT%{_localstatedir}/eFa/lib/selinux
mv eFa/eFa9.te $RPM_BUILD_ROOT%{_localstatedir}/eFa/lib/selinux
mv eFa/eFa-Monitor-cron $RPM_BUILD_ROOT%{_sbindir}
mkdir -p $RPM_BUILD_ROOT%{_prefix}/local/sbin
mkdir -p $RPM_BUILD_ROOT/usr/lib/systemd/system
mv eFa/efa-milter-health.py $RPM_BUILD_ROOT%{_prefix}/local/sbin
mv eFa/efa-milter-health.service $RPM_BUILD_ROOT/usr/lib/systemd/system
mv eFa/efa-web.py $RPM_BUILD_ROOT%{_prefix}/local/sbin
mv eFa/efa-web.service $RPM_BUILD_ROOT/usr/lib/systemd/system
mv eFa/efa-maillog.py $RPM_BUILD_ROOT%{_prefix}/local/sbin
mv eFa/efa-init.py $RPM_BUILD_ROOT%{_prefix}/local/sbin
mv eFa/efa-init.service $RPM_BUILD_ROOT/usr/lib/systemd/system
mv eFa/efa-maillog.service $RPM_BUILD_ROOT/usr/lib/systemd/system
mv eFa/efactl $RPM_BUILD_ROOT%{_sbindir}
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/cron.daily
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
mv eFa/eFa-Monitor  $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/eFa-Monitor
mv eFa/eFa-Backup.cron $RPM_BUILD_ROOT%{_sysconfdir}/cron.daily
mv eFa/efa-maillog.cron $RPM_BUILD_ROOT%{_sysconfdir}/cron.daily
mv eFa/efa-quarantine.cron $RPM_BUILD_ROOT%{_sysconfdir}/cron.daily
mv eFa/eFa-logrotate $RPM_BUILD_ROOT%{_sysconfdir}/logrotate.d
mkdir -p $RPM_BUILD_ROOT%{_usrsrc}/eFa/mariadb
# Move update scripts into position
mv updates $RPM_BUILD_ROOT%{_usrsrc}/eFa

%pre
# Stops before any file is replaced: the post script runs too late to undo an upgrade.
if [ -e /etc/MailScanner/MailScanner.conf ]; then
    echo "ERROR: MailScanner is installed, nothing was changed. Use efa-migrate to upgrade this system." >&2
    exit 1
fi

%preun

# leave files alone during uninstall (eFa package installs are permanent)

%postun

# leave files alone during uninstall (eFa package installs are permanent)

%post

status=0
flag=0
if [ "$1" = "1" ]; then
    # Perform Installation tasks

    # Sanity check in case rpm was removed
    if [[ -e %{_sysconfdir}/eFa-Version ]]; then
        echo "Previous eFa install detected."
        echo "Skipping post phase configuration tasks and executing all updates."
        flag=1
    else
        echo -e "\nPreparing to install eFa"

        # A failed step does not stop the others, so the admin sees every failed step at once.
        failed=""
        for script in postfix-config-5.0.0.sh nginx-config-5.0.0.sh efa-web-config-5.0.0.sh clamav-config-5.0.0.sh clamav-unofficial-sigs-config-5.0.0.sh mariadb-config-5.0.0.sh unbound-config-5.0.0.sh rspamd-config-5.0.0.sh yum-cron-config-5.0.0.sh service-config-5.0.0.sh eFa-config-5.0.0.sh eFaInit-config-5.0.0.sh; do
            /bin/sh %{_usrsrc}/eFa/$script || failed="$failed $script"
        done

        if [ -z "$failed" ]; then
            echo "eFa-%{version}-%{releasenum}" > %{_sysconfdir}/eFa-Version
            echo "Build completed!"
        else
            echo "ERROR: eFa build incomplete, these steps failed:$failed"
            status=1
        fi
    fi
fi
if [[ "$1" == "2" || "$flag" == "1" ]]; then
    # Perform Update tasks
    echo -e "\nPreparing to update eFa..."

    # v5 cumulative fixes
    mkdir -p /var/log/eFa
    /bin/sh %{_usrsrc}/eFa/updates/update.sh 2>&1 | tee -a /var/log/eFa/update.log
    if [ "${PIPESTATUS[0]}" -ne 0 ]; then
        echo "ERROR: eFa update failed, the version was not changed. See /var/log/eFa/update.log."
        status=1
    else
        # cleanup if sucessful
        rm -rf /usr/src/eFa
        echo "eFa-%{version}-%{releasenum}" > %{_sysconfdir}/eFa-Version

        echo "Update completed successfully!"
    fi
fi

systemctl daemon-reload >/dev/null 2>&1 || :
systemctl enable --now redis >/dev/null 2>&1 || :
systemctl enable --now efa-milter-health >/dev/null 2>&1 || :
# Not efa-init: restarting it would lose a running first-run wizard.
systemctl try-restart efa-milter-health efa-maillog efa-web >/dev/null 2>&1 || :
exit $status

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-, root, root, -)
%{_usrsrc}/eFa
%attr(0755, root, root) %{_sbindir}/eFa-Configure
%attr(0755, root, root) %{_sbindir}/eFa-Monitor-cron
%attr(0755, root, root) %{_prefix}/local/sbin/efa-milter-health.py
%attr(0644, root, root) /usr/lib/systemd/system/efa-milter-health.service
%attr(0755, root, root) %{_prefix}/local/sbin/efa-web.py
%attr(0644, root, root) /usr/lib/systemd/system/efa-web.service
%attr(0755, root, root) %{_prefix}/local/sbin/efa-maillog.py
%attr(0755, root, root) %{_prefix}/local/sbin/efa-init.py
%attr(0644, root, root) /usr/lib/systemd/system/efa-init.service
%attr(0644, root, root) /usr/lib/systemd/system/efa-maillog.service
%attr(0755, root, root) %{_sysconfdir}/cron.daily/efa-maillog.cron
%attr(0755, root, root) %{_sysconfdir}/cron.daily/efa-quarantine.cron
%attr(0755, root, root) %{_sbindir}/efactl
%config(noreplace) %{_sysconfdir}/sysconfig/eFa-Monitor
%attr(0755, root, root) %{_localstatedir}/eFa/lib/selinux/eFa.fc
%attr(0755, root, root) %{_localstatedir}/eFa/lib/selinux/eFa9.te
%attr(0755, root, root) %{_sysconfdir}/cron.daily/eFa-Backup.cron
%attr(0644, root, root) %{_sysconfdir}/logrotate.d/eFa-logrotate

%changelog
* Wed Nov 04 2026 MarkusLorber <351974646+MarkusLorber@users.noreply.github.com> - 6.0.0.1-1
- Restart efa-web and efa-maillog on upgrade, so they do not keep running the old code
- Refuse the package before any file changes where MailScanner is installed
- Report a failed update or build step as failed, not as completed

* Wed Nov 04 2026 MarkusLorber <351974646+MarkusLorber@users.noreply.github.com> - 6.0.0.0-1
- Replace MailScanner, MailWatch, SpamAssassin, opendkim, opendmarc, sqlgrey, Apache, PHP and Perl modules with rspamd and nginx
- Add Python web interface on waitress and efactl with the same functions in CLI and web
- Replace eFaInit with a Python wizard, remove sgwi and Webmin
- Add mail log in MariaDB with retention by age and size, and quarantine in the Postfix hold queue
- Add efa-milter-health: mail is accepted and marked with X-Milter-Failed if a milter fails
- Follow published DMARC policies, mark SPF, DKIM and DMARC failures in the header and on hard failures optionally in the subject
- DKIM generation creates RSA with at least 2048 bits and always ED25519
- Add sender rules for IP addresses, patterns and single recipients
- Resolve DNS with unbound without forwarding, reduce the SELinux policy to what the new services need
