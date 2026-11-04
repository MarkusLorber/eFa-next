#!/bin/sh
#-----------------------------------------------------------------------------#
# eFa 5.0.0 web interface setup: unprivileged user, sudo rule for efactl, secret
#-----------------------------------------------------------------------------#
set -e

id efa-web >/dev/null 2>&1 || useradd -r -s /sbin/nologin -d /nonexistent efa-web

echo 'efa-web ALL=(root) NOPASSWD: /usr/sbin/efactl' > /etc/sudoers.d/efa-web
chmod 440 /etc/sudoers.d/efa-web
visudo -cf /etc/sudoers.d/efa-web

install -d -m 750 -o root -g efa-web /etc/efa-web
if [ ! -f /etc/efa-web/secret.key ]; then
    head -c 64 /dev/urandom > /etc/efa-web/secret.key
    chown root:efa-web /etc/efa-web/secret.key
    chmod 640 /etc/efa-web/secret.key
fi

