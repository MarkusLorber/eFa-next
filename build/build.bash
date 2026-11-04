#!/bin/bash
# Without pipefail, $? after "cmd | tee" reports tee and hides failures.
set -o pipefail
#-----------------------------------------------------------------------------#
# eFa-next 6.0.0.0 build script
#-----------------------------------------------------------------------------#
# Copyright (C) 2013~2024 https://efa-project.org
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#-----------------------------------------------------------------------------#
action=$1
[[ -z $action ]] && action="production" # default to prod if no arg supplied
# There is no package repo: the eFa and eFa-base RPMs come from the latest GitHub release,
# or from a local directory given as second argument.
rpmdir=$2
release="https://github.com/MarkusLorber/eFa-next/releases/latest/download"

#-----------------------------------------------------------------------------#
# Install eFa
#-----------------------------------------------------------------------------#
LOGFILE="/var/log/eFa/build.log"

#-----------------------------------------------------------------------------#
# Set up logging
#-----------------------------------------------------------------------------#
LOGGER='/usr/bin/logger'
HEADER='=============  EFA 5 (EL 9) BUILD SCRIPT STARTING  ============'

# CREATE LOG FOLDER IF NOT EXISTS
mkdir -p $(dirname "${LOGFILE}")

# TRY TO CREATE LOG FILE IF NOT EXISTS
( [ -e "$LOGFILE" ] || touch "$LOGFILE" ) && [ ! -w "$LOGFILE" ] && echo "Unable to create or write to $LOGFILE"

function logthis() {
    TAG='EFA'
    MSG="$1"
    $LOGGER -t "$TAG" "$MSG"
    echo "`date +%Y.%m.%d-%H:%M:%S` - $MSG"
    echo "`date +%Y.%m.%d-%H:%M:%S` - $MSG" >> $LOGFILE
}

logthis "$HEADER"
#-----------------------------------------------------------------------------#

#-----------------------------------------------------------------------------#
# check if user is root
#-----------------------------------------------------------------------------#
if [ `whoami` == root ]; then
  logthis "Good you are root."
else
  logthis "ERROR: Please become root first."
  logthis "^^^^^^^^^^ SCRIPT ABORTED ^^^^^^^^^^"
  exit 1
fi
#-----------------------------------------------------------------------------#

#-----------------------------------------------------------------------------#
# check if we run CentOS 9
#-----------------------------------------------------------------------------#
OSVERSION=`cat /etc/redhat-release`
if [[ $OSVERSION =~ .*'release 9'.* ]]; then
  logthis "Good you are running CentOS 9 Stream or similar flavor"
  RELEASE=9
else
  logthis "ERROR: You are not running CentOS 9 Stream or equivalent"
  logthis "ERROR: Unsupported system, stopping now"
  logthis "^^^^^^^^^^ SCRIPT ABORTED ^^^^^^^^^^"
  exit 1
fi
#-----------------------------------------------------------------------------#

#-----------------------------------------------------------------------------#
# Check that SELinux is not disabled (unless it is lxc)
#-----------------------------------------------------------------------------#
if [[ -z $(grep -i 'lxc\|docker' /proc/1/cgroup) ]]; then
    if [[ -f /etc/selinux/config && -n $(grep -i ^SELINUX=disabled$ /etc/selinux/config)  ]]; then
        logthis "ERROR: SELinux is disabled and this is not an lxc container"
        logthis "ERROR: Please enable SELinux and try again."
        logthis "^^^^^^^^^^ SCRIPT ABORTED ^^^^^^^^^^"
        exit 1
    fi
fi
#-----------------------------------------------------------------------------#

#-----------------------------------------------------------------------------#
# Check network connectivity
#-----------------------------------------------------------------------------#
logthis "Checking network connectivity"
# use curl to test in case wget not installed yet.
curl -s --connect-timeout 3 --max-time 10 --retry 3 --retry-delay 0 --retry-max-time 30 https://rspamd.com/rpm/rspamd.asc > /dev/null
if [[ $? -eq 0 ]]; then
  logthis "OK - rspamd.com is reachable"
else
  logthis "ERROR: No network connectivity"
  logthis "ERROR: unable to reach rspamd.com"
  logthis "^^^^^^^^^^ SCRIPT ABORTED ^^^^^^^^^^"
  exit 1
fi
#-----------------------------------------------------------------------------#

#-----------------------------------------------------------------------------#
# have network, install wget if missing
#-----------------------------------------------------------------------------#
rpm -q wget >/dev/null 2>&1
if [ $? -ne 0 ]; then
    logthis "Installing wget"
    yum -y install wget | tee -a $LOGFILE
    if [ $? -eq 0 ]; then
        logthis "wget installed"
    else
        logthis "ERROR: wget installation failed"
        # non-fatal for this script but will cause issues after system configuration
    fi
fi
#-----------------------------------------------------------------------------#

#-----------------------------------------------------------------------------#
# eFa packages
#-----------------------------------------------------------------------------#
if [[ -z "$rpmdir" && "$action" != "testingnoefa" && "$action" != "devnoefa" ]]; then
  rpmdir=/usr/src/eFa/rpms
  logthis "Downloading eFa packages from $release"
  mkdir -p "$rpmdir"
  # shortcut: the checksums come from the same release and only catch damaged downloads, sign the packages if that ever matters
  ( cd "$rpmdir" && curl -fsSLO "$release/SHA256SUMS" && awk '{print $2}' SHA256SUMS | while read -r name; do
      curl -fsSLO "$release/$name" || exit 1
    done && sha256sum -c SHA256SUMS )
  if [ $? -ne 0 ]; then
    logthis "ERROR: eFa packages could not be downloaded or verified"
    logthis "^^^^^^^^^^ SCRIPT ABORTED ^^^^^^^^^^"
    exit 1
  fi
fi
efarpms=$(ls "$rpmdir"/eFa-base-*.rpm "$rpmdir"/eFa-[0-9]*.rpm 2>/dev/null)
if [[ "$action" != "testingnoefa" && "$action" != "devnoefa" && $(echo "$efarpms" | wc -w) -ne 2 ]]; then
  logthis "ERROR: $rpmdir must hold one eFa-base and one eFa package. Usage: build.bash production /path/to/rpms"
  logthis "^^^^^^^^^^ SCRIPT ABORTED ^^^^^^^^^^"
  exit 1
fi
#-----------------------------------------------------------------------------#

#-----------------------------------------------------------------------------#
# epel repo
#-----------------------------------------------------------------------------#
rpm -q epel-release >/dev/null 2>&1
if [ $? -ne 0 ]; then
    logthis "Installing EPEL Repo"
    yum -y install epel-release | tee -a $LOGFILE
    if [ $? -eq 0 ]; then
        logthis "EPEL repo installed"
    else
        logthis "ERROR: EPEL installation failed"
        logthis "^^^^^^^^^^ SCRIPT ABORTED ^^^^^^^^^^"
        exit 1
    fi
fi


if [[ $RELEASE -eq 9 ]]; then
    #-----------------------------------------------------------------------------#
    # crb repo
    #-----------------------------------------------------------------------------#
    rpm -q redhat-release >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        dnf config-manager --set-enabled crb | tee -a $LOGFILE
        if [ $? -eq 0 ]; then
            logthis "crb repo enabled"
        else
            logthis "ERROR: crb repo enable failed"
            logthis "^^^^^^^^^^ SCRIPT ABORTED ^^^^^^^^^^"
            exit 1
        fi
    else
        subscription-manager repos --enable codeready-builder-for-rhel-9-x86_64-rpms
        if [ $? -eq 0 ]; then
            logthis "codeready-builder-for-rhel repo enabled"
        else
            logthis "ERROR: codeready-builder-for-rhel repo enable failed"
            logthis "^^^^^^^^^^ SCRIPT ABORTED ^^^^^^^^^^"
            exit 1
        fi
    fi
    #-----------------------------------------------------------------------------#
    # rspamd repo
    #-----------------------------------------------------------------------------#
    logthis "Adding rspamd Repo"
    mkdir -p /usr/src/eFa
    curl -sSL https://rspamd.com/rpm/rspamd.asc > /usr/src/eFa/rspamd.asc
    if ! gpg --show-keys --with-colons /usr/src/eFa/rspamd.asc | grep -q '^fpr:*3FA347D5E599BE4595CA2576FFA232EDBF21E25E:'; then
        logthis "ERROR: rspamd GPG key fingerprint mismatch"
        logthis "^^^^^^^^^^ SCRIPT ABORTED ^^^^^^^^^^"
        exit 1
    fi
    rpm --import /usr/src/eFa/rspamd.asc
    cat > /etc/yum.repos.d/rspamd.repo << 'EOF'
[rspamd]
name=Rspamd stable repository
baseurl=https://rspamd.com/rpm-stable/centos-9/$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://rspamd.com/rpm/rspamd.asc
EOF
    #-----------------------------------------------------------------------------#
    # nginx and redis: newest stream the repos offer, patches come with the OS update below
    #-----------------------------------------------------------------------------#
    for module in nginx redis; do
        STREAM=$(dnf -y -q module list $module 2>/dev/null | awk -v m=$module '$1==m && $2 ~ /^[0-9.]+$/ {print $2}' | sort -V | tail -n 1)
        if [ -z "$STREAM" ]; then
            logthis "ERROR: no $module stream found"
            logthis "^^^^^^^^^^ SCRIPT ABORTED ^^^^^^^^^^"
            exit 1
        fi
        dnf module -y enable $module:$STREAM | tee -a $LOGFILE
        if [ $? -ne 0 ]; then
            logthis "ERROR: $module $STREAM stream enable failed"
            logthis "^^^^^^^^^^ SCRIPT ABORTED ^^^^^^^^^^"
            exit 1
        fi
        logthis "$module $STREAM stream enabled"
    done
fi

#-----------------------------------------------------------------------------#

#-----------------------------------------------------------------------------#
#-----------------------------------------------------------------------------#
# Update OS
#-----------------------------------------------------------------------------#
logthis "Updating the OS"
yum -y update | tee -a $LOGFILE
if [ $? -eq 0 ]; then
    logthis "System Updated"
fi
#-----------------------------------------------------------------------------#

#-----------------------------------------------------------------------------#
# Remove not needed packages
#-----------------------------------------------------------------------------#
logthis "Removing conflicting packages"
yum -y remove postfix >/dev/null 2>&1
# Ignore return here
#-----------------------------------------------------------------------------#


#-----------------------------------------------------------------------------#
# install eFa
#-----------------------------------------------------------------------------#
logthis "Installing eFa packages (This can take a while)"
rpm -q eFa >/dev/null 2>&1
if [ $? -ne 0 ]; then
    if [[ "$action" != "testingnoefa" && "$action" != "devnoefa" ]]; then
        dnf -y install $efarpms | tee -a $LOGFILE
        if [ $? -eq 0 ]; then
            logthis "eFa Installed"
        else
            logthis "ERROR: eFa failed to install"
            logthis "^^^^^^^^^^ SCRIPT ABORTED ^^^^^^^^^^"
            exit 1
        fi
    fi
fi
#-----------------------------------------------------------------------------#

#-----------------------------------------------------------------------------#
# kickstart
#-----------------------------------------------------------------------------#
if [[ "$action" == "kstesting" || "$action" == "ksproduction" || "$action" == "ksdev" ]]; then
  # Set root default pass for kickstart builds
  echo 'echo "First time login: root/eFaPr0j3ct" >> /etc/issue' >> /etc/rc.d/rc.local
  echo "root:eFaPr0j3ct" | chpasswd --md5 root

  # Disable ssh for kickstart builds
  systemctl disable sshd
fi

if [[ "$action" == "ksproduction" ]]; then
  # Zero free space in preparation for export
  logthis "Zeroing free space"
  dd if=/dev/zero of=/filler bs=4096 >/dev/null 2>&1
  rm -f /filler
  dd if=/dev/zero of=/tmp/filler bs=4096 >/dev/null 2>&1
  rm -f /tmp/filler
  dd if=/dev/zero of=/boot/filler bs=4096 >/dev/null 2>&1
  rm -f /boot/filler
  dd if=/dev/zero of=/var/filler bs=4096 >/dev/null 2>&1
  rm -f /var/filler
  logthis "Zeroed free space"
fi
#-----------------------------------------------------------------------------#

#-----------------------------------------------------------------------------#
# finalize
#-----------------------------------------------------------------------------#
logthis "============  EFA BUILD SCRIPT FINISHED  ============"
logthis "============  PLEASE REBOOT YOUR SYSTEM   ============"

if [[ "$action" == "testing" || "$action" == "production" || "$action" == "dev" ]]; then
  read -p "Do you wish to reboot the system now? (Y/N): " yn
  if [[ "$yn" == "y" || "$yn" == "Y" ]]; then
    shutdown -r +1 "Installation requires reboot. Restarting in 1 minute"
    exit 0
  else
    exit 0
  fi
fi
exit 0
#-----------------------------------------------------------------------------#
