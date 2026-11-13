# Third-party notices

eFa-next bundles no third-party program code in this repository, except where the table says "in the repository".
All other components are separate packages that the installer gets from the operating system or the named repository.
Each stays under its own license.

Versions were read on 2026-11-05 from an AlmaLinux 9 host running eFa-next 6.0.0.2. Licenses come from the
package metadata of that host, unless marked "check".

## Mail and services

| Component | Version | License (SPDX) | Homepage | How it is used |
| --- | --- | --- | --- | --- |
| rspamd | 4.2.3 | Apache-2.0 | https://rspamd.com | package, rspamd repository |
| nginx | 1.26.3 | BSD-2-Clause | https://nginx.org | OS package |
| Postfix | 3.5.25 | (IPL-1.0 AND GPL-2.0-or-later) OR (EPL-2.0 AND GPL-2.0-or-later); package metadata says "IBM" | http://www.postfix.org | OS package |
| MariaDB | 10.5.29 | GPL-2.0-only AND LGPL-2.1-only (check) | https://mariadb.org | OS package |
| ClamAV | 1.4.6 | GPL-2.0-only | https://www.clamav.net | package |
| Sanesecurity signatures | downloaded at run time, not shipped | terms of Sanesecurity, see sanesecurity.com. Credit: Sanesecurity. The eFa-next package holds only their public signing key | https://www.sanesecurity.com |
| Unbound | 1.24.2 | BSD-3-Clause (check) | https://nlnetlabs.nl/projects/unbound/ | OS package |
| Redis | 7.2.16 | BSD-3-Clause AND BSD-2-Clause AND MIT AND BSL-1.0 | https://redis.io | package. This version is from before the license change of Redis 7.4 |
| Fail2Ban | 1.1.0 | GPL-2.0-or-later | https://www.fail2ban.org | package |
| firewalld | 1.3.4 | GPL-2.0-or-later | https://firewalld.org | OS package |
| GnuPG | 2.3.3 | GPL-3.0-or-later | https://www.gnupg.org | OS package, called as a program |
| BIND utilities (dig) | 9.16.23 | MPL-2.0 | https://www.isc.org | OS package, called as a program |
| OpenSSL | 3.5.8 | Apache-2.0 | https://www.openssl.org | OS package |
| dejavu-sans-fonts | 2.37 | Bitstream-Vera AND LicenseRef-Public-Domain | https://dejavu-fonts.github.io | OS package, the font of the PDF reports for letters outside Western European ones |
| OpenSSH | 9.9p1 | BSD (check exact text) | https://www.openssh.com | OS package |
| Certbot | 3.1.0 | Apache-2.0 | https://certbot.eff.org | package |
| dnf-automatic, yum-utils | 4.14.0, 4.3.0 | GPL-2.0-or-later | https://github.com/rpm-software-management | OS package |

## Operating system

Licenses and versions of these rows come from the License: and Version: fields of the spec files of CentOS Stream 9
(branch c9s, gitlab.com/redhat/centos-stream/rpms), the sources AlmaLinux 9 builds from, read on 2026-11-12. A license
the spec names without a clear SPDX form says what the spec says, marked "check". A subpackage without a License: field of
its own has the license of its spec.

| Component | Version | License (SPDX) | Homepage | How it is used |
| --- | --- | --- | --- | --- |
| python3 | 3.9.25 | LicenseRef-Python (check); spec says "Python" | https://www.python.org | OS package, runs the programs of eFa-next |
| systemd | 252 | LGPL-2.0-or-later AND MIT AND GPL-2.0-or-later; spec says "LGPLv2+ and MIT and GPLv2+" | https://systemd.io | OS package |
| rsyslog | 8.2604.0 | GPL-3.0-or-later AND Apache-2.0 | https://www.rsyslog.com | OS package |
| Valkey | 8.1.10 | BSD-3-Clause AND BSD-2-Clause AND MIT AND BSL-1.0 | https://valkey.io | OS package |
| cronie | 1.5.7 | MIT AND LicenseRef-BSD (check) AND ISC AND GPL-2.0-or-later; spec says "MIT and BSD and ISC and GPLv2+" | https://github.com/cronie-crond/cronie | OS package |
| logrotate | 3.18.0 | GPL-2.0-or-later | https://github.com/logrotate/logrotate | OS package |
| sudo | 1.9.17p2 | ISC | https://www.sudo.ws | OS package |
| NetworkManager | 1.54.4 | GPL-2.0-or-later AND LGPL-2.1-or-later | https://networkmanager.dev | OS package |
| chrony | 4.9 | GPL-2.0-only | https://chrony-project.org | OS package |
| policycoreutils | 3.6 | GPL-2.0-or-later | https://github.com/SELinuxProject/selinux | OS package |
| selinux-policy-targeted | 38.1.87 | GPL-2.0-or-later | https://github.com/fedora-selinux/selinux-policy | OS package |
| tar | 1.34 | GPL-3.0-or-later | https://www.gnu.org/software/tar/ | OS package, called as a program |
| openldap-clients | 2.6.13 | OLDAP-2.8 | https://www.openldap.org | OS package, called as a program |

## Python packages

That host had both OS packages and newer packages from pip under `/usr/local`. The second one is what ran there.
The spec file asks for the OS packages. **Check before release which one a fresh install uses.**

| Component | Running on that host | OS package | License (SPDX) | Homepage |
| --- | --- | --- | --- | --- |
| Flask | 3.1.3 | 2.0.3 | BSD-3-Clause | https://flask.palletsprojects.com |
| Werkzeug | 3.1.8 | 2.0.3 | BSD-3-Clause | https://werkzeug.palletsprojects.com |
| Jinja2 | 3.1.6 | 2.11.3 | BSD-3-Clause | https://jinja.palletsprojects.com |
| itsdangerous | 2.2.0 | 2.0.1 | BSD-3-Clause | https://itsdangerous.palletsprojects.com |
| MarkupSafe, click | 3.0.3, 8.1.8 | | BSD-3-Clause | https://palletsprojects.com |
| waitress | 3.0.2 | 1.4.4 | ZPL-2.1 | https://github.com/Pylons/waitress |
| PyMySQL | 1.1.1 | | MIT | https://github.com/PyMySQL/PyMySQL |
| pymilter | 1.0.5 | 1.0.5 | GPL-2.0-or-later | https://www.pymilter.org |
| cryptography | | 36.0.1 | Apache-2.0 OR LicenseRef-BSD (check); spec says "ASL 2.0 or BSD" | https://cryptography.io |

## In the repository

| Item | Where | Origin and license |
| --- | --- | --- |
| Flag of Austria and flag of the EU in the footer | `efa-web.py` | Drawn as simple SVG shapes for this project. National and EU symbols may have rules of use of their own |
| Web interface fonts, icons, CSS, JavaScript | `efa-web.py` | Written for this project. System fonts only, nothing bundled |
| CycloneDX 1.5 JSON schema (bom, spdx, jsf) | `third-party/cyclonedx-1.5/`, in the repository, build time only | CycloneDX specification, tag 1.5, Apache-2.0 |

## Not used anymore

The license file of eFa (`LICENSES/GPL-3.0.txt`) also names MySQLTuner, SpamAssassin, SQLGrey, Webmin, MailWatch, Pyzor, Razor
and other parts of eFa 5. eFa-next does not ship them; the file stays as it was, for the history of the project.

## License texts

`third-party/licenses/` holds the texts of the SPDX license list data, one file per license. **Still to add:**
and the copyright lines that some licenses, such as BSD and MIT, ask to keep. Those are in each package.
