#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# S38 on the installed host (ci.sh --install): the sweep of maillog-setup leaves the accounts with @ (the main admin, console
# admins) and takes only a removed login; a missing table user_totp refuses the login of the main admin instead of letting it
# pass without 2FA. Everything is put back afterwards.
set -e
export MYSQL_PWD="$(sed -n 's/^MYSQLROOTPWD://p' /etc/eFa/MySQL-Config)"
q() { mysql --user=root -Ne "$1" efa; }
cleanup() {
    q "SELECT 1 FROM user_totp_ci LIMIT 0" >/dev/null 2>&1 && q "RENAME TABLE user_totp_ci TO user_totp" || :
    q "DELETE FROM user_totp WHERE username IN ('@ci-sweep', 'ci-orphan@example.com')" || :
    [ "$seeded" != yes ] || q "DELETE FROM user_totp WHERE username = '@admin'" || :
}
trap cleanup EXIT
# The main admin as an update meets it: a row @admin (seeded inactive when this host has none, removed again afterwards).
seeded=no
[ "$(q "SELECT COUNT(*) FROM user_totp WHERE username = '@admin'")" = 1 ] || { q "INSERT INTO user_totp (username, secret, active) VALUES ('@admin', 'x', 0)"; seeded=yes; }
q "INSERT INTO user_totp (username, secret, active) VALUES ('@ci-sweep', 'x', 0), ('ci-orphan@example.com', 'x', 0)"
/usr/sbin/efactl maillog-setup >/dev/null
[ "$(q "SELECT COUNT(*) FROM user_totp WHERE username IN ('@ci-sweep', '@admin')")" = 2 ] || { echo "S38: the sweep deleted an account with @ (the main admin)"; exit 1; }
[ "$(q "SELECT COUNT(*) FROM user_totp WHERE username = 'ci-orphan@example.com'")" = 0 ] || { echo "the sweep left the removed login"; exit 1; }
grep -q 'left-over rows of removed users deleted (ci-orphan@example.com)' /var/log/eFa/audit.log || { echo "the sweep did not name the removed login in the audit"; exit 1; }
q "RENAME TABLE user_totp TO user_totp_ci"
if out=$(printf '\n' | /usr/sbin/efactl admin-2fa-verify 2>&1); then
    echo "S38: without the table user_totp the main admin got in: $out"; exit 1
fi
echo "$out" | grep -q 'table user_totp missing' || { echo "no clear error without the table: $out"; exit 1; }
q "RENAME TABLE user_totp_ci TO user_totp"
echo "totp-failclosed-live: ok"
