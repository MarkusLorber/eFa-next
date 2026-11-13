#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# CL-RECIDIVE on the installed host (ci.sh --install): the jail of the cluster is loaded, and recidive with the filter of
# eFa-next does not count its bans (a fake fail2ban log through fail2ban-regex), the bans of every other jail it does.
# A ban in the jail of the cluster on every port (TEST-NET-3 address), lifted again.
set -e
fail2ban-client status efa-cluster >/dev/null || { echo "the jail efa-cluster is not loaded"; exit 1; }
log=$(mktemp)
trap 'rm -f "$log"; fail2ban-client set efa-cluster unbanip 203.0.113.61 >/dev/null 2>&1 || :' EXIT
for jail in postfix-sasl efa-cluster efa-cluster sshd efa-cluster recidive; do
    printf '2026-11-13 10:00:0%s,100 fail2ban.actions        [111]: NOTICE  [%s] Ban 203.0.113.60\n' "$(wc -l < "$log")" "$jail" >> "$log"
done
counted=$(fail2ban-regex "$log" /etc/fail2ban/filter.d/recidive.conf | sed -n 's/^Lines: .* \([0-9]*\) matched.*/\1/p')
[ "$counted" = 2 ] || { echo "recidive counted $counted of the 6 lines, expected 2 (postfix-sasl, sshd)"; fail2ban-regex -v "$log" /etc/fail2ban/filter.d/recidive.conf | tail -12; exit 1; }
fail2ban-client set efa-cluster banip 203.0.113.61 >/dev/null
fail2ban-client status efa-cluster | grep -q '203\.0\.113\.61' || { echo "the ban of the cluster is not set"; exit 1; }
fail2ban-client set efa-cluster unbanip 203.0.113.61 >/dev/null
echo "cluster-recidive-live: ok (recidive counted $counted of 6, the cluster jail bans and lifts)"
