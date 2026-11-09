#!/bin/sh
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
#-----------------------------------------------------------------------------#
# SPDX-License-Identifier: AGPL-3.0-or-later
# eFa-next initial nginx configuration
# The eFa-next web interface runs on waitress at 127.0.0.1:8080.
#-----------------------------------------------------------------------------#
set -e

# Hosts without IPv6 must not fail on the default server of the package.
sed -i -E 's/^(\s*)listen\s+\[::\]:80;/\1# listen [::]:80;/' /etc/nginx/nginx.conf

mkdir -p /etc/nginx/conf.d
cat > /etc/nginx/conf.d/efa.conf <<'EOF'
server {
    listen 80 default_server;
    server_name "";
    location /.well-known/acme-challenge/ { root /usr/share/nginx/html; }
    location / { return 302 https://$host$request_uri; }
}

server {
    listen 443 ssl default_server;
    http2 on;
    server_name "";
    # Self-signed by the eFa-next setup, until efactl letsencrypt-set requests a certificate.
    ssl_certificate /etc/pki/tls/certs/efa.crt;
    ssl_certificate_key /etc/pki/tls/private/efa.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 64m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300;
    }
}
EOF

# "http2 on;" exists from nginx 1.25.1 on (the module streams 1.26 and later); before (1.20 of AppStream) it is a flag of listen.
version="$(nginx -v 2>&1 | sed -n 's#.*nginx/\([0-9][0-9.]*\).*#\1#p')"
if ! printf '%s\n%s\n' 1.25.1 "${version:-0}" | sort -t. -k1,1n -k2,2n -k3,3n -C; then
    sed -i -e 's/^\(\s*\)listen 443 ssl default_server;/\1listen 443 ssl http2 default_server;/' -e '/^\s*http2 on;$/d' /etc/nginx/conf.d/efa.conf
fi

# SELinux must allow nginx to reach the local web application.
setsebool -P httpd_can_network_connect 1 || true

/usr/sbin/efactl web-harden

# The first-run wizard is reached through nginx.
systemctl enable --now nginx
