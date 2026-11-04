#-----------------------------------------------------------------------------#
# eFa SPEC file definition
#-----------------------------------------------------------------------------#
# Copyright (C) 2013~2024 https://efa-project.org
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

Name:      eFa-base
Summary:   eFa-base files rpm
Version:   6.0.0.0
Release:   1.eFa%{?dist}
Epoch:     1
Group:     Applications/System
URL:       https://efa-project.org
License:   GNU GPL v3+
# The source directory keeps its name, the scripts in it refer to it.
Source0:   eFa-base-5.0.0.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch: noarch

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
%setup -q -n eFa-base-5.0.0

%build

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT

# Wizard translations
mkdir -p $RPM_BUILD_ROOT%{_datadir}/efa-init/translations
mv eFaInit/translations/messages.*.yml $RPM_BUILD_ROOT%{_datadir}/efa-init/translations
rm -rf eFaInit

# Move modules into position
mkdir -p $RPM_BUILD_ROOT%{_sbindir}
mv eFa/eFa-Init $RPM_BUILD_ROOT%{_sbindir}
mv eFa/eFa-Commit $RPM_BUILD_ROOT%{_sbindir}
mv eFa/eFa-Post-Init $RPM_BUILD_ROOT%{_sbindir}

# move remaining contents of source straight into rpm
mkdir -p $RPM_BUILD_ROOT%{_usrsrc}/eFa
mv * $RPM_BUILD_ROOT%{_usrsrc}/eFa


%pre

%preun

%postun

%post

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-, root, root, -)
%{_usrsrc}/eFa
%attr(0755, root, root) %{_sbindir}/eFa-Init
%attr(0755, root, root) %{_sbindir}/eFa-Commit
%attr(0755, root, root) %{_sbindir}/eFa-Post-Init
%{_datadir}/efa-init

%changelog
* Wed Nov 04 2026 MarkusLorber <351974646+MarkusLorber@users.noreply.github.com> - 6.0.0.0-1
- Configure rspamd, nginx, redis and the Python services instead of the old filter stack
