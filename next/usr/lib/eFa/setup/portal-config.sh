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
