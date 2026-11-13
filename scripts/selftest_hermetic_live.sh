#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# S33 on the installed host (ci.sh --install): the installed efactl --self-test leaves the host as it was. No file below
# /etc or the quarantine changes, nor the state files it wrote before, efa-cdr is not restarted and freshclam keeps its
# state; the namespace and the stand-ins are gone afterwards.
set -e
# The host first at rest: efa-floor-guard (its path unit fires after the steps before changed main.cf) writes floor-guard.json.
for i in $(seq 120); do
    [ "$(systemctl is-active efa-floor-guard.service 2>/dev/null)" != activating ] && [ -z "$(systemctl list-jobs --no-legend 2>/dev/null | grep efa-floor-guard)" ] && break
    sleep 1
done
sleep 2
guard=$(systemctl show -p ExecMainStartTimestampMonotonic --value efa-floor-guard.service)
marker=$(mktemp)
trap 'rm -f "$marker"' EXIT
cdr=$(systemctl show -p InvocationID --value efa-cdr)
fresh=$(systemctl is-enabled clamav-freshclam 2>/dev/null || :)
sleep 1
EFA_CI=yes /usr/sbin/efactl --self-test 2>&1 | tail -1 | grep -qx 'self-test ok' || { echo "the installed self-test failed"; exit 1; }
# /etc and the quarantine whole; of /var/lib/eFa (written by the timers of the host too) the files the self-test wrote before S33.
changed=$( { find /etc /var/spool/efa-quarantine -xdev -newer "$marker" ! -type d 2>/dev/null
            for f in standards-check.json rspamd-modules.json daily-notices.json floor-guard.json mailreport/tls-port25.json freshclam-off-in-cluster; do
                [ ! -e "/var/lib/eFa/$f" ] || [ ! "/var/lib/eFa/$f" -nt "$marker" ] || echo "/var/lib/eFa/$f"
            done; } | head -20)
# floor-guard.json counts as written by the host only when efa-floor-guard.service ran in the window of the self-test.
if echo "$changed" | grep -qx /var/lib/eFa/floor-guard.json && [ "$(systemctl show -p ExecMainStartTimestampMonotonic --value efa-floor-guard.service)" != "$guard" ]; then
    echo "/var/lib/eFa/floor-guard.json: host unit (efa-floor-guard.service ran in the window), not self-test"
    changed=$(echo "$changed" | grep -vx /var/lib/eFa/floor-guard.json || :)
fi
[ -z "$changed" ] || { echo "the self-test changed files of the host:"; echo "$changed"; exit 1; }
[ "$(systemctl show -p InvocationID --value efa-cdr)" = "$cdr" ] || { echo "the self-test restarted efa-cdr"; exit 1; }
[ "$(systemctl is-enabled clamav-freshclam 2>/dev/null || :)" = "$fresh" ] || { echo "the self-test switched freshclam"; exit 1; }
# Only a folder of this run counts (a run killed in CI earlier may have left one of its own).
[ -z "$(find /var/tmp -maxdepth 1 -name 'efa-selftest-*' -newer "$marker")" ] || { echo "the folder of the self-test was left"; exit 1; }
! awk '$5 == "/etc" || $5 == "/var/lib/eFa" || $5 == "/var/log/eFa" { if ($0 ~ / - overlay /) found = 1 } END { exit !found }' /proc/self/mountinfo ||
    { echo "an overlay of the self-test is left in the namespace of the host"; exit 1; }
echo "selftest-hermetic-live: ok"
