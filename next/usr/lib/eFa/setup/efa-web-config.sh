#!/bin/sh
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
#-----------------------------------------------------------------------------#
# SPDX-License-Identifier: AGPL-3.0-or-later
# eFa web interface setup: unprivileged users, sudo rule for efactl, secret
#-----------------------------------------------------------------------------#
set -e

id efa-web >/dev/null 2>&1 || useradd -r -s /sbin/nologin -d /nonexistent efa-web
# The first-run wizard, with the group of the web interface for the session key.
id efa-init >/dev/null 2>&1 || useradd -r -s /sbin/nologin -d /nonexistent -g efa-web efa-init

echo 'efa-web ALL=(root) NOPASSWD: /usr/sbin/efactl' > /etc/sudoers.d/efa-web
chmod 440 /etc/sudoers.d/efa-web
visudo -cf /etc/sudoers.d/efa-web

install -d -m 750 -o root -g efa-web /etc/efa-web
if [ ! -f /etc/efa-web/secret.key ]; then
    head -c 64 /dev/urandom > /etc/efa-web/secret.key
    chown root:efa-web /etc/efa-web/secret.key
    chmod 640 /etc/efa-web/secret.key
fi

