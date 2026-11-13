#!/bin/sh
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
#-----------------------------------------------------------------------------#
# SPDX-License-Identifier: AGPL-3.0-or-later
# eFa-next user portal (5q): its own system user without sudo, its own session key, the helper and the portal.
# Safe to run again; run on a new install and on the upgrade.
#-----------------------------------------------------------------------------#
set -e

id efa-portal >/dev/null 2>&1 || useradd -r -s /sbin/nologin -d /nonexistent efa-portal
# 5u: the login service of port 587, in place of Dovecot.
id efa-sasl >/dev/null 2>&1 || useradd -r -s /sbin/nologin -d /nonexistent efa-sasl
install -d -m 750 -o root -g efa-sasl /etc/efa-sasl
# The services that read mail (efa-cdr, efa-maillog, efa-milter-health) run as efa-mail: efactl-runner answers only efa-web.
# On an upgrade the quarantine of users moves over to it; systemd moves /var/lib/efa-cdr (StateDirectory) by itself.
id efa-mail >/dev/null 2>&1 || useradd -r -s /sbin/nologin -d /nonexistent efa-mail
# The read group of the settings files that services read (efactl CONF_READERS), also on an update. Members for good, not only
# in the units (SupplementaryGroups): sudo -u, the runner and the checks read as these users too.
getent group efa-conf >/dev/null 2>&1 || groupadd -r efa-conf
for user in efa-web efa-portal; do
    id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qx efa-conf || { id "$user" >/dev/null 2>&1 && usermod -aG efa-conf "$user"; }
done
# S32: the settings of the mail services (outbound.json, milter-health.json) in a group of their own; efa-mail leaves efa-conf.
getent group efa-mailconf >/dev/null 2>&1 || groupadd -r efa-mailconf
id -nG efa-mail | tr ' ' '\n' | grep -qx efa-mailconf || usermod -aG efa-mailconf efa-mail
! id -nG efa-mail | tr ' ' '\n' | grep -qx efa-conf || gpasswd -d efa-mail efa-conf >/dev/null
# S37: the secrets of the web interface (admin password, session key, key of nginx) in a group of their own: the mail services
# have the group efa-web for their files in /etc/efa-web (maillog.pw, quarantine keys), not for these. Also on an update;
# the restart of the running units after the setup gives efa-web and efa-init the new group.
getent group efa-websecret >/dev/null 2>&1 || groupadd -r efa-websecret
for user in efa-web efa-init; do
    id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qx efa-websecret || { id "$user" >/dev/null 2>&1 && usermod -aG efa-websecret "$user"; }
done
for f in admin.pw secret.key proxy.key; do
    [ ! -f "/etc/efa-web/$f" ] || { chown root:efa-websecret "/etc/efa-web/$f" && chmod 640 "/etc/efa-web/$f"; }
done
if [ -d /var/spool/efa-quarantine ]; then
    find /var/spool/efa-quarantine -xdev ! -user efa-mail -exec chown -h efa-mail:efa-mail {} +
fi
# 5o: the DKIM provisioning API; its only sudo rights are the two commands that take a call (DKIM keys, disclaimers). Off until dkim-provision-set.
id efa-dkim-api >/dev/null 2>&1 || useradd -r -s /sbin/nologin -d /nonexistent efa-dkim-api
install -d -m 750 -o root -g efa-dkim-api /etc/eFa/dkim-api
printf '%s\n' 'efa-dkim-api ALL=(root) NOPASSWD: /usr/sbin/efactl --client dkim-api dkim-provision-apply --source *' \
    'efa-dkim-api ALL=(root) NOPASSWD: /usr/sbin/efactl --client dkim-api disclaimer-provision-apply --source *' > /etc/sudoers.d/efa-dkim-api
chmod 440 /etc/sudoers.d/efa-dkim-api
visudo -cf /etc/sudoers.d/efa-dkim-api >/dev/null
install -d -m 750 -o root -g efa-portal /etc/efa-portal
if [ ! -f /etc/efa-portal/secret.key ]; then
    head -c 64 /dev/urandom > /etc/efa-portal/secret.key
    chown root:efa-portal /etc/efa-portal/secret.key
    chmod 640 /etc/efa-portal/secret.key
fi
# Through the platform layer, as every service of eFa-next.
python3 -I -c 'import sys; sys.path.insert(0, "/usr/lib/eFa/python"); import efa_platform
p = efa_platform.detect()
for unit in ("efa-portal-helper", "efa-portal"):
    p.service_enable(unit, start=True)'
