#!/bin/sh
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
#-----------------------------------------------------------------------------#
# SPDX-License-Identifier: AGPL-3.0-or-later
# eFa initial nginx configuration
# The eFa web interface runs on waitress at 127.0.0.1:8080.
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
    # Self-signed by the eFa setup, until efactl letsencrypt-set requests a certificate.
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

# SELinux must allow nginx to reach the local web application.
setsebool -P httpd_can_network_connect 1 || true

/usr/sbin/efactl web-harden

# The first-run wizard is reached through nginx.
systemctl enable --now nginx
