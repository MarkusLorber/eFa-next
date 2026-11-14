#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
#
# The checks of every change, on an EL9 build host, from the root of the repository:
#   scripts/ci.sh            lint, unit tests, self-tests, RPM build
#   scripts/ci.sh --install  also installs the built packages on this host (the upgrade path) and checks it, then the fresh install
#   scripts/ci.sh --fresh    the build and the fresh install only: set up anew from the packages, checked, then put back as it was
#   scripts/ci.sh --fresh-restore   puts back the state an interrupted fresh test left in /var/lib/efa-ci-fresh-saved
# The Forgejo workflow (.forgejo/workflows/ci.yml) runs the same once a runner exists. Push only when the last line says OK.
set -u
# efactl --self-test restarts services: it runs only where EFA_CI=yes says this is the CI host (6.0.0.6).
export EFA_CI=yes
cd "$(dirname "$0")/.." || exit 1
INSTALL=no
FRESH=no
[ "${1:-}" = "--install" ] && INSTALL=yes && FRESH=yes
[ "${1:-}" = "--fresh" ] && FRESH=yes
# Packages of an older or failed run are never used for a test install: the old run folders go, and only a green run leaves
# its packages, in GREEN with the hash of the source tree they were built from (scripts/ci.sh --tree-hash prints it for a tree).
GREEN=/var/tmp/efa-ci-green
tree_hash() {
    find next src migration build rpm -type f ! -path '*/__pycache__/*' | LC_ALL=C sort | xargs sha256sum | sha256sum | cut -d' ' -f1
}
[ "${1:-}" = "--tree-hash" ] && { tree_hash; exit 0; }
# One run per host: two runs at once install over each other. The second one stops at once and names the first.
LOCK=/var/tmp/efa-ci.lock
exec 9>>"$LOCK"
# The Forgejo runner waits for the run before it (EFA_CI_LOCK_WAIT seconds); by hand it stops at once.
if [ -n "${EFA_CI_LOCK_WAIT:-}" ]; then flock -w "$EFA_CI_LOCK_WAIT" 9; else flock -n 9; fi
if [ $? -ne 0 ]; then
    echo "ci: another run holds $LOCK: $(cat "$LOCK" 2>/dev/null || echo unknown). Nothing done."
    exit 2
fi
: > "$LOCK"
echo "pid $$ since $(date '+%F %T') in $(pwd)" >&9
# The folders of the two runs before stay (the logs of a failed run are still there for the next one to read), older ones go.
ls -dt /var/tmp/efa-ci.?????? 2>/dev/null | tail -n +3 | xargs -r rm -rf
OUT=$(mktemp -d /var/tmp/efa-ci.XXXXXX)
FAILED=""
SELF_TESTS=0
step() {
    name=$1
    shift
    if "$@" >"$OUT/$name.log" 2>&1; then
        echo "ci: $name ok"
        # A diagnosis line (a page that did not render and was asked again) stays visible in the summary, also on green runs.
        grep -E 'STANDARD VIEW CHECK' "$OUT/$name.log" | head -10 | cut -c1-600 | sed 's/^/ci:   /'
    else
        echo "ci: $name FAILED, last lines:"
        # The names of the failed unit tests first: the tail of a long log may not hold them.
        grep -E '^(FAIL|ERROR): |STANDARD VIEW CHECK' "$OUT/$name.log" | head -10 | cut -c1-600 | sed 's/^/ci:   /'
        tail -15 "$OUT/$name.log"
        FAILED="$FAILED $name"
    fi
}

lint_python() {
    for f in $(find next src migration scripts tests build -type f \( -name '*.py' -o -perm -u+x \) 2>/dev/null); do
        case "$(head -c 40 "$f")" in
            '#!/usr/bin/python3'*|'#!/usr/bin/env python3'*) python3 -m py_compile "$f" || return 1 ;;
            *) case "$f" in *.py) python3 -m py_compile "$f" || return 1 ;; esac ;;
        esac
    done
}

lint_names() {
    # A name that is used but never defined only fails when its line runs (efa-migrate stopped in the middle of a migration).
    python3 -m pyflakes --version >/dev/null 2>&1 || { echo "pyflakes missing: dnf install python3-pyflakes (EPEL)"; return 1; }
    found=$(for f in $(find next src migration scripts tests build -type f \( -name '*.py' -o -perm -u+x \) 2>/dev/null); do
        case "$(head -c 40 "$f")" in '#!/usr/bin/python3'*|'#!/usr/bin/env python3'*) ;; *) case "$f" in *.py) ;; *) continue ;; esac ;; esac
        python3 -m pyflakes "$f" 2>&1 | grep 'undefined name'
    done)
    [ -z "$found" ] || { echo "$found"; return 1; }
}

exec_bits() {
    # A script without its executable bit stops with "Permission denied" (a checkout from Windows loses it).
    found=$(find next src migration scripts tests build tools -type f ! -perm -u+x 2>/dev/null | while read -r f; do
        [ "$(head -c 2 "$f")" = '#!' ] && echo "$f"
    done)
    [ -z "$found" ] || { echo "a script without the executable bit (git update-index --chmod=+x):"; echo "$found"; return 1; }
}

lint_shell() {
    # Scripts that must run with any POSIX sh, also on FreeBSD later.
    # Not the compiled Python: a string constant there can follow a byte 0x0a and look like a script line.
    for f in $(grep -rl --exclude-dir=__pycache__ '^#!/bin/sh' next src scripts 2>/dev/null); do
        sh -n "$f" || return 1
    done
    bash -n build/build.bash
}

self_tests() {
    for p in build/sbom.py scripts/detection_benchmark.py scripts/load_test.py next/usr/sbin/efactl next/usr/local/sbin/efa-web.py next/usr/local/sbin/efa-maillog.py next/usr/local/sbin/efa-milter-health.py \
             next/usr/local/sbin/efa-init.py next/usr/sbin/efa-console-2fa next/usr/local/sbin/efa-tui next/usr/local/sbin/efa-cdr.py next/usr/local/sbin/efa-reports.py next/usr/local/sbin/efa-phish.py next/usr/local/sbin/efa-outbound.py next/usr/local/sbin/efa-cluster.py next/usr/local/sbin/efa-dkim-api.py next/usr/local/sbin/efactl-runner.py next/usr/local/sbin/efa-sasl.py next/usr/local/sbin/efa-qr.py next/usr/local/sbin/efa-roles.py next/usr/local/sbin/efa-unlock.py next/usr/local/sbin/efa-trap.py next/usr/local/sbin/efa-sandbox.py next/usr/local/sbin/efa-emergency.py next/usr/lib/eFa/python/efa_cluster.py next/usr/lib/eFa/python/efa_blocklist.py next/usr/lib/eFa/python/efa_mime.py next/usr/lib/eFa/python/efa_pdf.py next/usr/lib/eFa/python/efa_evidence.py next/usr/lib/eFa/python/efa5_convert.py next/usr/lib/eFa/python/efa_i18n.py next/usr/lib/eFa/python/efa_links.py next/usr/lib/eFa/python/efa_sign.py next/usr/lib/eFa/python/efa_zip.py next/usr/lib/eFa/python/efa_qcrypt.py next/usr/lib/eFa/python/efa_qr.py next/usr/lib/eFa/python/efa_totp.py next/usr/lib/eFa/python/efa_setup.py next/usr/lib/eFa/python/efa_webauthn.py next/usr/lib/eFa/python/efa_feeds.py next/usr/lib/eFa/python/efa_bimi.py next/usr/lib/eFa/python/efa_domaincheck.py next/usr/lib/eFa/python/efa_lookalike.py next/usr/lib/eFa/python/efa_a11y.py next/usr/lib/eFa/python/efa_crypto.py next/usr/lib/eFa/python/efa_host.py next/usr/lib/eFa/python/efa_release_upgrade.py next/usr/lib/eFa/python/efa_arc.py next/usr/lib/eFa/python/efa_shacrypt.py next/usr/lib/eFa/python/efa_redis.py \
             migration/efa-migrate migration/efa5-export scripts/os_lint.py scripts/license_check.py; do
        python3 -B "$p" --self-test 2>&1 | tail -1 | grep -q 'self-test ok' || { echo "self-test failed: $p"; python3 -B "$p" --self-test 2>&1 | tail -5; return 1; }
        SELF_TESTS=$((SELF_TESTS + 1))
    done
    # The user portal (5q): the same program without the admin routes, and its helper.
    EFA_WEB_MODE=portal python3 -B next/usr/local/sbin/efa-web.py --self-test 2>&1 | tail -1 | grep -q 'self-test ok' || { echo "self-test failed: portal"; EFA_WEB_MODE=portal python3 -B next/usr/local/sbin/efa-web.py --self-test 2>&1 | tail -5; return 1; }
    python3 -B next/usr/local/sbin/efa-portal-helper.py --self-test 2>&1 | tail -1 | grep -q 'self-test ok' || { echo "self-test failed: portal helper"; return 1; }
    SELF_TESTS=$((SELF_TESTS + 2))
}

reproducible() {
    # Q4: a second build of the same source gives the same files.
    python3 -I build/build-rpms.py --next-dir next --out "$OUT/rpms2" >/dev/null || return 1
    diff "$OUT/rpms/SHA256SUMS" "$OUT/rpms2/SHA256SUMS"
}

# After an install (its own step after install-upgrade; inside fresh_run before the restore): every service of the monitor runs, no untested
# sandbox drop-in is left on a distribution unit, and the unbound of the host answers names. EFA_CI_DNS_NAMES adds names of the
# site, such as the git server, without writing them into the repository. The variables start with hc_: step() keeps its name in
# "name", and a loop variable of that name made the step report under a host name.
host_check() {
    hc_failed=0
    for hc_unit in $(sed -n 's/^SERVICES="\(.*\)"$/\1/p' /etc/sysconfig/eFa-Monitor); do
        if systemctl is-active -q "$hc_unit"; then echo "service $hc_unit: ok"; else echo "service $hc_unit: FAILED (not active)"; hc_failed=1; fi
    done
    # 5v (h): the sandbox drop-ins only on the tested distribution units, and none brings NoNewPrivileges (SELinux domains).
    hc_left=$(ls /etc/systemd/system/*.service.d/efa-hardening.conf 2>/dev/null | grep -vE '/(rspamd|clamd@scan|clamav-freshclam|redis|unbound|nginx)\.service\.d/')
    hc_nnp=$(grep -l 'NoNewPrivileges' /etc/systemd/system/*.service.d/efa-hardening.conf 2>/dev/null)
    if [ -z "$hc_left$hc_nnp" ]; then echo "sandbox drop-ins: ok ($(ls /etc/systemd/system/*.service.d/efa-hardening.conf 2>/dev/null | wc -l) tested units)"
    else echo "sandbox drop-ins: FAILED (untested: $hc_left; NoNewPrivileges: $hc_nnp)"; hc_failed=1; fi
    # D-1: with the sandbox on default (new install, migration) the tested mail services run in it, none fell back without it.
    hc_sandbox=$(efactl service-harden-status 2>/dev/null | python3 -I -c 'import json, sys
s = json.load(sys.stdin)
if s.get("mode") == "default":
    print(" ".join(f"{n}={v}" for n, v in s.get("services", {}).items() if n in ("rspamd", "clamd@scan", "clamav-freshclam", "unbound") and v not in ("on", "unchanged")))' 2>&1)
    if [ -z "$hc_sandbox" ]; then echo "sandbox default units: ok"; else echo "sandbox default units: FAILED ($hc_sandbox)"; hc_failed=1; fi
    # Through 127.0.0.1 itself, not resolv.conf: dig comes with bind-utils, a Requires of eFa-next.
    if ! command -v dig >/dev/null; then
        echo "dns: FAILED (dig missing, package bind-utils)"; hc_failed=1
    else
        for hc_dns in repo.efa-next.eu ${EFA_CI_DNS_NAMES:-}; do
            hc_answer=$(dig +short +time=3 +tries=2 @127.0.0.1 "$hc_dns" A 2>&1; dig +short +time=3 +tries=2 @127.0.0.1 "$hc_dns" AAAA 2>&1)
            if echo "$hc_answer" | grep -qE '^[0-9a-f.:]+$'; then echo "dns $hc_dns: ok"
            else echo "dns $hc_dns: FAILED ($(echo ${hc_answer:-no answer} | cut -c1-160))"; hc_failed=1; fi
        done
    fi
    # Only a hint, the host is the admin's: its own name in /etc/hosts on an address of no interface (efactl status warns too).
    for hc_addr in $(awk -v a="$(hostname -s)" -v b="$(hostname)" '!/^[ \t]*#/ { for (i = 2; i <= NF; i++) if ($i == a || $i == b) print $1 }' /etc/hosts | sort -u); do
        case "$hc_addr" in 127.*|::1) continue ;; esac
        ip -o addr | grep -q " $hc_addr/" || echo "hosts: WARNING $hc_addr carries the host name in /etc/hosts but is no address of this host"
    done
    # 6.0.0.5: the guard of the security minimum watches, and its ExecStartPre (floor-check) lets postfix, nginx and dovecot start
    # again without an SELinux denial: each restarted here, the denials below cover them.
    if systemctl is-active -q efa-floor-guard.path; then echo "floor guard path unit: ok"; else echo "floor guard path unit: FAILED (not active)"; hc_failed=1; fi
    for hc_unit in postfix nginx dovecot; do
        systemctl is-active -q "$hc_unit" || continue
        if systemctl restart "$hc_unit" && systemctl is-active -q "$hc_unit"; then echo "restart with floor check $hc_unit: ok"
        else echo "restart with floor check $hc_unit: FAILED ($(systemctl status "$hc_unit" 2>&1 | grep -m1 -i 'efactl\|failed'))"; hc_failed=1; fi
    done
    # T-3: each own module of rspamd that is switched on is loaded (rspamd lists its symbol), not only a line in the rspamd log.
    hc_mods=$(efactl os-check-run 2>/dev/null | python3 -I -c 'import json, sys; print("; ".join(f for f in json.load(sys.stdin).get("findings", []) if "has not loaded" in f))' 2>&1)
    if [ -z "$hc_mods" ]; then echo "rspamd own modules: ok ($(grep -c -- '-- efa-' /etc/rspamd/rspamd.local.lua 2>/dev/null || echo 0) switched on)"
    else echo "rspamd own modules: FAILED ($hc_mods)"; journalctl -u rspamd --since '-30 min' --no-pager -o cat | grep -E 'efa-[a-z-]+:' | tail -5; hc_failed=1; fi
    # The installer takes the nginx module stream 1.26 (1.20 of AppStream does not know "http2 on;"), and nginx loads its files.
    hc_nginx=$(nginx -v 2>&1 | sed -n 's#.*nginx/\([0-9][0-9.]*\).*#\1#p')
    if printf '%s\n%s\n' 1.25.1 "${hc_nginx:-0}" | sort -t. -k1,1n -k2,2n -k3,3n -C && nginx -t >/dev/null 2>&1; then echo "nginx $hc_nginx: ok"
    else echo "nginx ${hc_nginx:-missing}: FAILED (older than 1.25.1 or nginx -t refuses the files)"; hc_failed=1; fi
    # No IPv6 on the host: Postfix must not try IPv6 sockets (SELinux denies sendmail_t loading the module).
    hc_proto=$(postconf -h inet_protocols 2>/dev/null)
    if [ -e /proc/net/if_inet6 ] || [ "$hc_proto" = ipv4 ]; then echo "postfix inet_protocols: ok ($hc_proto)"
    else echo "postfix inet_protocols: FAILED ($hc_proto on a host without IPv6)"; hc_failed=1; fi
    # MIG-587: nothing of main.cf unused (efa_submission_restrictions above all), and submission (and smtps, if there) refer to it.
    hc_unused=$(postconf -n 2>&1 >/dev/null | grep 'unused parameter')
    if [ -z "$hc_unused" ]; then echo "postfix unused parameters: none"; else echo "postfix unused parameters: FAILED"; echo "$hc_unused"; hc_failed=1; fi
    for hc_service in submission/inet smtps/inet; do
        postconf -M "$hc_service" 2>/dev/null | grep -q . || continue
        if postconf -P "$hc_service/smtpd_recipient_restrictions" 2>/dev/null | grep -qF '$efa_submission_restrictions'; then echo "postfix $hc_service: ok"
        else echo "postfix $hc_service: FAILED (does not refer to \$efa_submission_restrictions)"; hc_failed=1; fi
    done
    if sudo -u unbound test -r /var/lib/unbound/root.key; then echo "unbound root.key: ok"; else echo "unbound root.key: FAILED (not readable for unbound)"; hc_failed=1; fi
    # SELinux: no denial for a distribution service since the install began (HOST_CHECK_SINCE, set by install_test and fresh_run).
    if command -v ausearch >/dev/null && [ -n "${HOST_CHECK_SINCE:-}" ]; then
        hc_denied=$(ausearch -m avc -i -ts $HOST_CHECK_SINCE 2>/dev/null | grep -oE 'comm=[^ ]+' | sort | uniq -c |
            grep -E 'comm=(unbound|unbound-checkco|unbound-anchor|rspamd|clamd|freshclam|redis-server|nginx|postfix|master|smtpd|sendmail|newaliases|postmap|postalias|mariadbd|mysqld|dovecot|doveconf|efactl|postconf|chronyd|chronyc)$')
        if [ -z "$hc_denied" ]; then echo "selinux denials: none"; else echo "selinux denials: FAILED"; echo "$hc_denied"; hc_failed=1; fi
    fi
    # The SELinux module the policy holds is the one of the package (what apply_policy_module compares, not its stamp).
    if command -v getenforce >/dev/null && [ "$(getenforce)" != Disabled ]; then
        hc_policy=$(python3 -I -c 'import hashlib, sys
sys.path.insert(0, "/usr/lib/eFa/python")
import efa_platform
loaded = efa_platform.detect().loaded_policy_digest("efa")
shipped = hashlib.sha256(open("/usr/share/selinux/packages/eFa/efa.pp", "rb").read()).hexdigest()
print("ok" if loaded == shipped else "FAILED (loaded %s, package %s)" % (loaded, shipped))' 2>&1)
        echo "selinux module efa: $hc_policy"
        [ "$hc_policy" = ok ] || hc_failed=1
    fi
    if command -v ausearch >/dev/null && [ -n "${HOST_CHECK_BEFORE:-}" ] && [ -n "${HOST_CHECK_SINCE:-}" ]; then
        hc_before=$(ausearch -m avc -i -ts $HOST_CHECK_BEFORE -te $HOST_CHECK_SINCE 2>/dev/null | grep -oE 'comm=[^ ]+' | sort | uniq -c)
        [ -z "$hc_before" ] || { echo "selinux denials before the eFa-next install (stock packages, not counted):"; echo "$hc_before"; }
    fi
    return $hc_failed
}

# MIG-GREY / MIG-DNS: an update changes no settings. Before the install: greylisting and BEC off, a forwarder for all names to
# a public resolver (forward-first, so names still resolve if it does not answer); afterwards all three are as they were and the
# dashboard names them. upgrade_unplant puts the host back, also when the install failed.
UPGRADE_FORWARD=/etc/unbound/conf.d/efa-ci-upgrade-forward.conf
upgrade_plant() {
    mkdir -p "$OUT/upgrade-keep"
    efactl settings > "$OUT/upgrade-keep/settings.json" && efactl bec-status > "$OUT/upgrade-keep/bec.json" || return 1
    efactl greylisting-set --mode off >/dev/null && efactl bec-set --mode off >/dev/null || return 1
    printf 'forward-zone:\n  name: "."\n  forward-first: yes\n  forward-addr: 8.8.8.8\n' > "$UPGRADE_FORWARD"
}

# The heal of the submission service runs on every package upgrade: a second run changes nothing (no rewrite, no .bak).
submission_heal_twice() {
    efactl postfix-submission-heal > /dev/null || return 1
    before=$(sha256sum /etc/postfix/master.cf | cut -d' ' -f1); baks=$(ls /etc/postfix/master.cf.efa-submission-*.bak 2>/dev/null | wc -l)
    efactl postfix-submission-heal | grep -q '"submission": "eFa-next"' || { echo "the second heal had something to do"; return 1; }
    [ "$(sha256sum /etc/postfix/master.cf | cut -d' ' -f1)" = "$before" ] || { echo "the second heal rewrote master.cf"; return 1; }
    [ "$(ls /etc/postfix/master.cf.efa-submission-*.bak 2>/dev/null | wc -l)" = "$baks" ] || { echo "the second heal wrote a .bak"; return 1; }
}

# MIG-587 (owner's choice c, 2026-11-12): the submission block of eFa 5 with AUTH through Dovecot is replaced, AUTH is not taken
# over (no login of eFa-next exists), and that is in the audit log and on the dashboard. master.cf is put back afterwards.
efa5_587_check() {
    keep=$(mktemp); cp -p /etc/postfix/master.cf "$keep"
    mark=/var/lib/eFa/submission-efa5-auth; had_mark=no; [ -e "$mark" ] && had_mark=yes
    baks=$(ls /etc/postfix/master.cf.efa-submission-*.bak 2>/dev/null)
    # The SASL options of the eFa 5 block (postconf -P takes no value with a space, so not its client checks).
    postconf -P submission/inet/smtpd_sasl_type=dovecot submission/inet/smtpd_sasl_path=private/auth submission/inet/smtpd_sasl_auth_enable=yes \
        submission/inet/smtpd_sasl_security_options=noanonymous || { rm -f "$keep"; return 1; }
    result=0
    efactl postfix-submission-heal | grep -q '"submission": "replaced"' || { echo "the eFa 5 block was not replaced"; result=1; }
    efactl sasl-apply > /dev/null || { echo "sasl-apply failed"; result=1; }
    auth=$(postconf -Ph submission/inet/smtpd_sasl_auth_enable 2>/dev/null)
    echo "587 AUTH after the heal: ${auth:-main.cf}"
    [ "$auth" = no ] || { echo "AUTH of eFa 5 was taken over"; result=1; }
    [ -e "$mark" ] || { echo "no record of the AUTH of eFa 5"; result=1; }
    efactl status | grep -q 'offers no SMTP AUTH since the migration' || { echo "no dashboard notice"; result=1; }
    cp -p "$keep" /etc/postfix/master.cf; rm -f "$keep"
    [ "$had_mark" = yes ] || rm -f "$mark"
    for bak in /etc/postfix/master.cf.efa-submission-*.bak; do
        [ -e "$bak" ] && ! printf '%s\n' "$baks" | grep -qx "$bak" && rm -f "$bak"
    done
    efactl sasl-apply > /dev/null && postfix reload >/dev/null 2>&1
    return $result
}

# WEB-RESTART: ten restarts of efa-web in a row, each answers within 3 s, and not one "Address already in use".
web_restart_check() {
    since=$(date '+%F %T')
    for i in 1 2 3 4 5 6 7 8 9 10; do
        start=$(date +%s.%N)
        systemctl restart efa-web || return 1
        until [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/login)" = 200 ]; do
            [ "$(echo "$(date +%s.%N) - $start > 10" | bc)" = 1 ] && { echo "restart $i: no 200 within 10 s"; return 1; }
            sleep 0.1
        done
        took=$(echo "$(date +%s.%N) - $start" | bc)
        echo "restart $i: 200 after ${took} s"
        [ "$(echo "$took < 3" | bc)" = 1 ] || { echo "restart $i: over 3 s"; return 1; }
    done
    errors=$(journalctl -u efa-web --since "$since" --no-pager | grep -c 'Address already in use')
    [ "$errors" = 0 ] || { echo "bind errors: $errors"; return 1; }
    # The folder of the wizard decides: while a unit with it runs, efa-web is skipped; after a kill (failed) the folder is
    # gone and efa-web starts. The probe has the runtime folder settings of efa-init.service, not its program (port 8080 stays free).
    dir=$(systemctl show efa-init.service -p RuntimeDirectory --value); keep=$(systemctl show efa-init.service -p RuntimeDirectoryPreserve --value)
    [ "$dir" = efa-init ] || { echo "efa-init.service: RuntimeDirectory is '$dir', not efa-init"; return 1; }
    systemd-run --unit=efa-ci-wizard-probe -p RuntimeDirectory="$dir" -p RuntimeDirectoryPreserve="$keep" -p Restart=no sleep 300 >/dev/null || return 1
    sleep 1
    systemctl restart efa-web
    [ "$(systemctl show efa-web -p ActiveState --value)" != active ] && [ "$(systemctl show efa-web -p ConditionResult --value)" = no ] \
        || { echo "efa-web started although the folder of the wizard is there"; systemctl stop efa-ci-wizard-probe; return 1; }
    systemctl kill -s KILL efa-ci-wizard-probe; sleep 1
    [ ! -e /run/efa-init ] || { echo "/run/efa-init left after the kill"; systemctl reset-failed efa-ci-wizard-probe; return 1; }
    systemctl reset-failed efa-ci-wizard-probe 2>/dev/null
    systemctl start efa-web && sleep 2 && [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/login)" = 200 ] \
        || { echo "efa-web did not start after the kill of the wizard"; return 1; }
    echo "wizard folder: skipped while it runs, gone after KILL, efa-web up again"
}

# NGINX-PID: with nginx stopped, an "nginx -t" as efactl runs it (unconfined_service_t) creates /run/nginx.pid; it must get the
# type of nginx (httpd_var_run_t, efa.te), and nginx must start after it. Without the rule the next start failed (13).
nginx_pid_check() {
    command -v getenforce >/dev/null && [ "$(getenforce)" = Enforcing ] || { echo "SELinux not enforcing: nothing to check"; return 0; }
    systemctl stop nginx || return 1
    rm -f /run/nginx.pid
    # Through python3 as efactl does it: nginx then stays in unconfined_service_t (started directly it would become httpd_t).
    systemd-run --wait --quiet --unit=efa-ci-nginx-test /usr/bin/python3 -c "import subprocess, sys; sys.exit(subprocess.run(['/usr/sbin/nginx', '-t']).returncode)"         || { systemctl start nginx; return 1; }
    label=$(stat -c %C /run/nginx.pid 2>/dev/null)
    echo "pid file after nginx -t of unconfined_service_t: ${label:-none}"
    systemctl start nginx || { echo "nginx did not start"; return 1; }
    case "$label" in *:httpd_var_run_t:*) ;; *) echo "wrong label of /run/nginx.pid: $label"; return 1;; esac
    systemctl is-active -q nginx || return 1
}

admin_allow_loopback_check() {
    # The health check of the updater (6.0.0.5.x too) asks https://127.0.0.1/login after an update: with the admin allowlist
    # on, nginx must still answer the host itself, or the update rolls back (403 on a production host, 2026-11-12).
    allow=/etc/eFa/web-allowlist.json
    saved=$(mktemp)
    had=no; [ -e "$allow" ] && { cp -p "$allow" "$saved"; had=yes; }
    efactl web-allowlist-set --mode=allowed --networks=192.0.2.0/24 --confirm=yes >/dev/null || { echo "web-allowlist-set failed"; rm -f "$saved"; return 1; }
    code=$(python3 -c 'import ssl, urllib.request, urllib.error
try:
    print(urllib.request.urlopen("https://127.0.0.1/login", timeout=10, context=ssl._create_unverified_context()).status)
except urllib.error.HTTPError as err:
    print(err.code)')
    if [ "$had" = yes ]; then cp -p "$saved" "$allow"; else rm -f "$allow"; fi
    rm -f "$saved"
    efactl web-harden >/dev/null || { echo "web-harden after the check failed"; return 1; }
    echo "https://127.0.0.1/login with the allowlist on: $code"
    [ "$code" = 200 ]
}

upgrade_keep_check() {
    efactl settings | python3 -c 'import json,sys; sys.exit(json.load(sys.stdin)["greylisting"])' || { echo "the update switched greylisting on"; return 1; }
    efactl bec-status | python3 -c 'import json,sys; sys.exit(json.load(sys.stdin)["enabled"])' || { echo "the update switched BEC on"; return 1; }
    [ -e "$UPGRADE_FORWARD" ] || { echo "the update removed the forwarder for all names"; return 1; }
    efactl status | python3 -c 'import json,sys
d = json.load(sys.stdin)
feature = [item[0] for item in d.get("feature_notices", [])]
system = d.get("system_notices", [])
ok = any("no action" in text for text in feature) and any("BEC" in text for text in feature) and any("unbound sends all names to" in text for text in feature)
print("feature notices:", feature)
sys.exit(not ok)' || { echo "the dashboard does not name the gap, BEC off and the forwarder"; return 1; }
}

upgrade_unplant() {
    rm -f "$UPGRADE_FORWARD"
    [ -s "$OUT/upgrade-keep/settings.json" ] || return 0
    python3 -c 'import json,sys
s = json.load(open(sys.argv[1])); b = json.load(open(sys.argv[2]))
print("on" if s["greylisting"] else "off", s.get("greylist_minutes", 5), s.get("greylist_days", 1), "on" if b["enabled"] else "off")' \
        "$OUT/upgrade-keep/settings.json" "$OUT/upgrade-keep/bec.json" > "$OUT/upgrade-keep/before" || return 1
    read -r grey minutes days bec < "$OUT/upgrade-keep/before"
    efactl greylisting-set --mode "$grey" --minutes "$minutes" --days "$days" >/dev/null && efactl bec-set --mode "$bec" >/dev/null || return 1
    systemctl restart unbound
}

install_test() {
    HOST_CHECK_SINCE="$(date +%x) $(date +%T)"
    upgrade_plant || { echo "install: could not set the state before the update"; return 1; }
    # The firewall tables of eFa-next must never go away during an install or upgrade: nft monitor writes down every table event.
    guard=no
    nft list table inet efa_guard >/dev/null 2>&1 && guard=yes
    nft monitor tables > "$OUT/nft-monitor.log" 2>&1 &
    monitor=$!
    # Bytecode of a changed module of the same size and time, as the clamped build times left it: the install must not run it.
    python3 -I scripts/stale_bytecode.py --plant || { kill $monitor; return 1; }
    # The same version again is a reinstall, a newer one the upgrade an admin runs; afterwards exactly the built packages are installed.
    built=$(rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' "$OUT"/rpms/eFa-next-base-*.rpm "$OUT"/rpms/eFa-next-6*.rpm | sort)
    before=$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' eFa-next eFa-next-base 2>/dev/null | sort)
    if [ "$before" = "$built" ]; then
        echo "install: reinstall of $(echo $built)"
        dnf -y -q reinstall "$OUT"/rpms/eFa-next-base-*.rpm "$OUT"/rpms/eFa-next-6*.rpm
    else
        echo "install: upgrade from $(echo ${before:-nothing}) to $(echo $built)"
        dnf -y -q install "$OUT"/rpms/eFa-next-base-*.rpm "$OUT"/rpms/eFa-next-6*.rpm
    fi || { kill $monitor; echo "install: dnf failed, nothing checked"; return 1; }
    [ "$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' eFa-next eFa-next-base | sort)" = "$built" ] || {
        kill $monitor; echo "install: installed are $(rpm -q eFa-next eFa-next-base | tr '\n' ' '), not the built $(echo $built)"; return 1; }
    python3 -I scripts/stale_bytecode.py --check || { kill $monitor; return 1; }
    # A step of the package setup that failed is never green: efa-next-setup names it in /var/lib/eFa/setup-failed.
    if [ -e /var/lib/eFa/setup-failed ]; then
        kill $monitor; echo "install: the package setup did not finish: $(tr '\n' ' ' < /var/lib/eFa/setup-failed)"
        tail -5 /var/log/eFa/setup.log 2>/dev/null; return 1
    fi
    sleep 2
    kill $monitor
    if grep -qE 'delete table inet (efa_guard|efa_test_block)' "$OUT/nft-monitor.log"; then
        echo "a firewall table of eFa-next was removed during the install:"; cat "$OUT/nft-monitor.log"; return 1
    fi
    if [ "$guard" = yes ] && ! nft list table inet efa_guard >/dev/null 2>&1; then
        echo "the allowlist table efa_guard is gone after the install"; return 1
    fi
    # The package hooks restart the running eFa-next units; the health service checks every 10 seconds.
    for _ in 1 2 3 4 5 6; do
        efactl status | grep -q '"status": "ok"' && break
        sleep 5
    done
    efactl status | grep -q '"status": "ok"' || { efactl status; systemctl --failed --no-pager; systemctl list-units 'efa-*' --all --no-pager --state=inactive | head -20; return 1; }
    rpm -V eFa-next eFa-next-base | grep -v ' c /' | grep -q . && { rpm -V eFa-next eFa-next-base; return 1; }
    # A changed config file is the admin's; a missing one (a cron job of the package) is a fault.
    rpm -V eFa-next eFa-next-base | grep '^missing' && return 1
    python3 -B /usr/sbin/efactl --self-test 2>&1 | tail -1 | grep -q 'self-test ok' || return 1
    # Every form shows what is set now on this host (efa_nav.FORM_SOURCE).
    efactl form-check | grep -q '"ok": true' || { efactl form-check; return 1; }
    # Q5b: the hardening report as PDF is valid and holds the host and the checks.
    efactl hardening-report --pdf "$OUT/hardening.pdf" >/dev/null || return 1
    qpdf --check "$OUT/hardening.pdf" | grep -q 'No syntax or stream encoding errors' || { qpdf --check "$OUT/hardening.pdf"; return 1; }
    if command -v pdftotext >/dev/null; then
        # The name eFa-next uses for itself (efa_host), not hostname -f: that asks the resolver and /etc/hosts.
        own=$(python3 -I /usr/lib/eFa/python/efa_host.py)
        pdftotext "$OUT/hardening.pdf" - | grep -q "$own" || { echo "hardening PDF without the host name $own"; return 1; }
        pdftotext "$OUT/hardening.pdf" - | grep -q 'CIS AlmaLinux 9' || { echo "hardening PDF without the checks"; return 1; }
    fi
    # S1 (docs/SECURITY-DESIGN.md): no file readable by everyone holds a password, token, secret or private key.
    open_secrets=$(find /etc/eFa /etc/efa-web /etc/efa-portal /etc/postfix /etc/rspamd/local.d /etc/rspamd/override.d /etc/dovecot /etc/nginx /var/lib/eFa -type f -perm -o+r 2>/dev/null | xargs -r grep -lE '^[^#]*(password|passwd|secret|requirepass|bind_pw|token)[a-z_]*[ ]*[=:][ ]*"?[^ "]{6,}|BEGIN [A-Z ]*PRIVATE KEY' 2>/dev/null)
    [ -z "$open_secrets" ] || { echo "files readable by everyone with secrets: $open_secrets"; return 1; }
    # 5y: the legal PDFs of the package are valid and open without a login; the CI host confirms the texts of this build as an
    # admin would, so the admin pages open for the checks below.
    for pdf in /usr/share/eFa/legal/*.pdf; do
        qpdf --check "$pdf" | grep -q 'No syntax or stream encoding errors' || { qpdf --check "$pdf"; return 1; }
    done
    efactl legal-accept --digest "$(cat /usr/share/eFa/legal/digest.txt)" --confirm yes >/dev/null || return 1
    [ "$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1/legal)" = 200 ] || { echo "/legal is not open"; return 1; }
    # Every page of the web interface within its budget (Hans: "muss super schnell sein"): median per page at most 100 ms.
    efa_web_wait=0
    until [ -S /run/efactl-runner/runner.sock ] || [ $efa_web_wait -ge 10 ]; do sleep 1; efa_web_wait=$((efa_web_wait + 1)); done
    # efactl-runner (docs/security-model.md): the socket only for root and efa-web, and of the users only efa-web gets an answer;
    # the portal user cannot even open it, the wizard user efa-init (group efa-web) is refused by its uid.
    [ "$(stat -c '%a %U %G' /run/efactl-runner/runner.sock)" = "660 root efa-web" ] || { stat /run/efactl-runner/runner.sock; return 1; }
    [ "$(sudo -u efa-web python3 -I /usr/local/sbin/efactl-runner.py --probe)" = ok ] || return 1
    [ "$(sudo -u efa-portal python3 -I /usr/local/sbin/efactl-runner.py --probe)" = denied ] || return 1
    [ "$(sudo -u efa-init python3 -I /usr/local/sbin/efactl-runner.py --probe)" = refused ] || return 1
    [ "$(sudo -u nobody python3 -I /usr/local/sbin/efactl-runner.py --probe)" = denied ] || return 1
    # No sudo for efa-web (the rule of 6.0.0.5 goes on the update), so its unit runs with NoNewPrivileges; the backup download
    # and upload reach efactl through pipes handed to efactl-runner.
    [ ! -e /etc/sudoers.d/efa-web ] || { echo "/etc/sudoers.d/efa-web is still there"; return 1; }
    ! sudo -l -U efa-web 2>/dev/null | grep -q efactl || { echo "efa-web may still run efactl by sudo"; return 1; }
    [ "$(systemctl show -p NoNewPrivileges --value efa-web)" = yes ] || { echo "efa-web runs without NoNewPrivileges"; return 1; }
    sudo -u efa-web python3 -I - < scripts/runner_stream_check.py || return 1
    # X-Real-IP counts only with the key of nginx: the include only for root, the key for the two web programs.
    [ "$(stat -c '%a %U' /etc/nginx/efa-proxy.inc)" = "600 root" ] || { stat /etc/nginx/efa-proxy.inc; return 1; }
    [ "$(stat -c '%a %U %G' /etc/efa-web/proxy.key)" = "640 root efa-websecret" ] || { stat /etc/efa-web/proxy.key; return 1; }
    # S37: the secrets of the web interface only for efa-web and the wizard; efa-maillog (user efa-mail with the groups of its
    # unit, efa-web among them for maillog.pw) reads none of them.
    as_maillog() { systemd-run --quiet --pipe --wait --collect -p User=efa-mail -p "SupplementaryGroups=$(systemctl show -p SupplementaryGroups --value efa-maillog)" "$@"; }
    for f in admin.pw secret.key proxy.key; do
        [ -e "/etc/efa-web/$f" ] || continue
        [ "$(stat -c '%a %U %G' "/etc/efa-web/$f")" = "640 root efa-websecret" ] || { stat "/etc/efa-web/$f"; return 1; }
        ! as_maillog test -r "/etc/efa-web/$f" || { echo "efa-maillog reads /etc/efa-web/$f"; return 1; }
        sudo -u efa-web test -r "/etc/efa-web/$f" || { echo "efa-web cannot read /etc/efa-web/$f"; return 1; }
    done
    sudo -u efa-init test -r /etc/efa-web/secret.key || { echo "the wizard cannot read the session key"; return 1; }
    [ ! -e /etc/efa-web/maillog.pw ] || as_maillog test -r /etc/efa-web/maillog.pw || { echo "efa-maillog cannot read maillog.pw"; return 1; }
    [ "$(stat -c '%a %U %G' /etc/efa-portal/proxy.key)" = "640 root efa-portal" ] || { stat /etc/efa-portal/proxy.key; return 1; }
    grep -q 'include /etc/nginx/efa-proxy.inc;' /etc/nginx/conf.d/efa.conf || { echo "nginx sends X-Real-IP without its key"; return 1; }
    # Packages and keys of rspamd only over https.
    ! grep -q 'http://' /etc/yum.repos.d/rspamd.repo 2>/dev/null || { echo "rspamd.repo names a plain http address"; return 1; }
    # The credentials of efa-outbound and efa-sandbox exist, so systemd can start them whenever they are enabled.
    for f in /etc/eFa/pdf-passwords.json /etc/eFa/signature-fields.json /etc/eFa/sandbox-service.json /etc/eFa/crypto; do
        [ -e "$f" ] || { echo "$f is missing: efa-outbound or efa-sandbox cannot start"; return 1; }
    done
    [ ! -f /etc/yum.repos.d/rspamd.repo ] || grep -q '^exclude=rspamd-\[5-9\]' /etc/yum.repos.d/rspamd.repo || { echo "rspamd.repo lets a new major version in"; return 1; }
    grep -qE '^(excludepkgs|exclude)=.*clamav-\[2-9\]' /etc/dnf/dnf.conf || { echo "dnf.conf lets new major versions from EPEL in (PKG-5)"; return 1; }
    # The guard of the security minimum checks after the install's changes: the page times measure the web interface, not it.
    pages_wait=0
    while [ "$(systemctl show -p ActiveState --value efa-floor-guard.service 2>/dev/null)" != inactive ] &&
          [ "$(systemctl show -p ActiveState --value efa-floor-guard.service 2>/dev/null)" != failed ] && [ $pages_wait -lt 120 ]; do
        sleep 2
        pages_wait=$((pages_wait + 2))
    done
    [ $pages_wait -lt 120 ] || echo "page times: efa-floor-guard.service still running after 120 s, measured anyway"
    # Over stdin: efa-web cannot read the build folder.
    sudo -u efa-web python3 -I - --rounds 5 --budget-ms 100 < scripts/page_times.py > "$OUT/page-times.txt" 2>&1
    pages_ok=$?
    grep -v WARNING "$OUT/page-times.txt"
    [ $pages_ok -eq 0 ] || return 1
    # The Security page read by read: the slow reads come from the read cache, none over 100 ms without it.
    sudo -u efa-web python3 -I - --profile sec --rounds 3 < scripts/page_times.py > "$OUT/profile-sec.txt" 2>&1 || { grep -v WARNING "$OUT/profile-sec.txt"; return 1; }
    # Standard view: only cards with a setting or a warning (Hans: values without a setting belong to the expert view), and the
    # same values as the expert view in every card and tile it shows.
    sudo -u efa-web python3 -I - --check-standard < scripts/page_times.py 2>&1 | grep -v WARNING > "$OUT/standard-view.txt"
    cat "$OUT/standard-view.txt"
    grep -q 'standard view: problems: none' "$OUT/standard-view.txt" || return 1
}

# The fresh-install path (--fresh, and with --install after the upgrade): this host is set up anew from the packages of this
# run, as an admin would (packages, wizard, first boot), checked, and then put back exactly as it was. The eFa-next files move
# aside (so the install finds none), what the setup changes besides them is copied, the eFa-next database and its users are dumped.
# The state waits in FRESH_SAVED until it is back: an interrupted run leaves it there, and --fresh-restore puts it back.
FRESH_SAVED=/var/lib/efa-ci-fresh-saved
# systemctl of the fresh test never asks for a password and never waits for ever: after many daemon-reloads a restart lost its
# connection to systemd and waited although every service was up.
sc() { timeout 300 systemctl --no-ask-password "$@"; }
FRESH_MOVE='/etc/eFa /etc/efa-web /etc/efa-portal /etc/efa-sasl /etc/eFa-next-Version /etc/eFa-Version /var/lib/eFa /var/eFa /var/log/eFa /var/log/eFa-archive
    /etc/cron.d/eFa-Backup.cron /etc/cron.d/efa-maillog /etc/cron.d/eFa-Monitor.cron /etc/cron.d/efa-quarantine /etc/nginx/conf.d/efa-admin-allow.conf
    /etc/nginx/conf.d/efa.conf /etc/rspamd/local.d /etc/rspamd/override.d /etc/rspamd/dkim /etc/postfix /etc/my.cnf.d/efa.cnf /etc/sudoers.d/efa-init
    /etc/pki/tls/certs/efa.crt /etc/pki/tls/private/efa.key /var/lib/rpm-state/eFa /var/lib/rpm-state/eFa-base'
FRESH_COPY='/etc/ssh /etc/hosts /etc/unbound /etc/resolv.conf /etc/NetworkManager/system-connections /etc/fail2ban /etc/dnf/automatic.conf
    /etc/localtime /etc/sysconfig/eFa-Monitor'
FRESH_USER=efa-ci-fresh
FRESH_CONFIG=/etc/eFa/eFa-Config
FRESH_VERSION=/etc/eFa-next-Version

# A tar of the live settings while eFa-next runs: its writers replace their files atomically (a .tmp of their own, then rename),
# so tar may see a folder change under it ("file changed as we read it", exit 1). The writers of efactl (_json_write) wait for
# the lock tar holds; the .tmp files stay out; a run that a writer outside efactl changed is repeated, up to five times. Any
# other message, or a change that never settles, fails: nothing of the settings is ignored.
snap_tar() {
    out=$1; shift
    for try in 1 2 3 4 5; do
        flock -x -w 60 "${EFA_STATE_LOCK:-/run/efa-state.lock}" tar -C / --exclude='*.tmp' -cpf "$out" "$@" 2> "$out.err"; rc=$?
        [ "$rc" = 0 ] && { rm -f "$out.err"; return 0; }
        [ "$rc" = 1 ] && ! grep -qv 'file changed as we read it$' "$out.err" || { cat "$out.err"; rm -f "$out" "$out.err"; return 1; }
        echo "snapshot: a file changed while tar read it (try $try): $(tr '\n' ' ' < "$out.err")"
        sleep 1
    done
    cat "$out.err"; rm -f "$out" "$out.err"; return 1
}

efa_units_stop() {
    sc stop 'efa-*.timer' efactl-runner.service $(systemctl list-units --no-legend --plain 'efa-*.service' | awk '{print $1}' | grep -v '^efa-test-block\|^efa-ci-') 2>/dev/null
    return 0
}

fresh_save() {
    [ -e "$FRESH_SAVED" ] && { echo "$FRESH_SAVED exists: an earlier fresh test did not finish. Run scripts/ci.sh --fresh-restore first."; return 1; }
    grep -q '^CONFIGURED:YES' "$FRESH_CONFIG" 2>/dev/null || { echo "this host is not set up: no state to come back to"; return 1; }
    [ -s "$FRESH_VERSION" ] && rpm -q eFa-next eFa-next-base >/dev/null || { echo "eFa-next is not fully installed here: no fresh test"; return 1; }
    # Built aside and renamed to FRESH_SAVED only when complete: a half save never blocks the next run, and --fresh-restore
    # never takes one. Nothing is moved before the rename, so a failed save only has to remove its own folder.
    part="$FRESH_SAVED.partial"
    rm -rf "$part"
    mkdir -m 0700 "$part" "$part/move" "$part/copy" || return 1
    fresh_save_into "$part" || { rm -rf "$part"; return 1; }
    ( cd "$part" && sha256sum settings.tar efa.sql users.sql hostname enabled-units > MANIFEST ) && touch "$part/complete" &&
        mv "$part" "$FRESH_SAVED" || { rm -rf "$part"; return 1; }
    echo saved
}

fresh_save_into() {
    dir=$1
    # A copy of the settings before anything is removed: dnf remove deletes files of the packages, and an interrupted run once
    # left a host without /etc/eFa. The restore takes it when the moved copy is missing.
    snap_tar "$dir/settings.tar" $(for p in $FRESH_MOVE; do case "$p" in /var/log/*) ;; *) [ -e "$p" ] && echo "${p#/}";; esac; done) || return 1
    for p in $FRESH_COPY; do [ -e "$p" ] && { cp -a --parents "$p" "$dir/copy/" || return 1; }; done
    mysqldump --single-transaction efa > "$dir/efa.sql" || return 1
    # The accounts with their password hashes, root too: the setup gives root a new password.
    for who in $(mysql -N -e "SELECT CONCAT(QUOTE(user), '@', QUOTE(host)) FROM mysql.user WHERE user LIKE 'efa%' OR user = 'root'"); do
        mysql -N -e "SHOW CREATE USER $who" | sed 's/$/;/'
        mysql -N -e "SHOW GRANTS FOR $who" | sed 's/$/;/'
    done > "$dir/users.sql" || return 1
    systemctl --failed --no-legend --plain | awk '{print $1}' | sort > "$dir/failed-before"
    # Which eFa-next units were on: the new install turns on its own, the restore puts back exactly these.
    systemctl list-unit-files --no-legend --plain --state=enabled 'efa-*' | awk '{print $1}' | sort > "$dir/enabled-units"
    nft list table inet efa_test_block >/dev/null 2>&1 && touch "$dir/test-block"
    # The name of the kernel: the wizard gives it again, the restore puts it back and compares.
    uname -n > "$dir/hostname" || return 1
    # An empty name once made the restore fail for good: fail here, while nothing is changed yet.
    grep -q '[a-z]' "$dir/hostname" || {
        echo "no host name to come back to: uname -n [$(uname -n)] hostname [$(hostname 2>&1)] static [$(hostnamectl --static 2>&1)]"; return 1; }
    [ -s "$dir/efa.sql" ] && [ -s "$dir/settings.tar" ] || { echo "the save is empty: no database dump or no settings"; return 1; }
    # HARD-W: the SSH profile of the host; the setup must not change it (fresh_standards).
    efactl ssh-profile-status | python3 -c 'import json,sys; print(json.load(sys.stdin)["profile"])' > "$dir/ssh-profile" || return 1
}

fresh_run() {
    HOST_CHECK_BEFORE="$(date +%x) $(date +%T)"
    efa_units_stop
    timeout 600 dnf -y -q remove --noautoremove eFa-next eFa-next-base || return 1
    for p in $FRESH_MOVE; do [ -e "$p" ] && { mkdir -p "$FRESH_SAVED/move$(dirname "$p")" && mv "$p" "$FRESH_SAVED/move$p" || return 1; }; done
    mysql -e "DROP DATABASE IF EXISTS efa" || return 1
    for who in $(mysql -N -e "SELECT CONCAT(QUOTE(user), '@', QUOTE(host)) FROM mysql.user WHERE user LIKE 'efa%'"); do mysql -e "DROP USER $who"; done
    # Postfix and rspamd with the configuration of their packages, as on a new host.
    timeout 600 dnf -y -q reinstall postfix rspamd || return 1
    # The scriptlets of the stock postfix (newaliases) run with its inet_protocols=all: on a host without IPv6 SELinux denies
    # sendmail_t the IPv6 module. That is before eFa-next: host_check counts from here and lists the earlier ones as not counted.
    HOST_CHECK_SINCE="$(date +%x) $(date +%T)"
    echo "== install"
    timeout 900 dnf -y install "$OUT"/rpms/eFa-next-base-*.rpm "$OUT"/rpms/eFa-next-6*.rpm > "$OUT/fresh-dnf.log" 2>&1 || { tail -20 "$OUT/fresh-dnf.log"; return 1; }
    grep -i 'error in .*scriptlet' "$OUT/fresh-dnf.log" && { echo "a package scriptlet failed"; tail -30 "$OUT/fresh-dnf.log"; return 1; }
    for pkg in eFa-base eFa; do
        grep -q ' OK$' "/var/lib/eFa/install-state/$pkg" 2>/dev/null || { echo "install-state of $pkg: $(cat /var/lib/eFa/install-state/$pkg 2>&1)"; return 1; }
    done
    systemctl is-active -q efa-init || { echo "the wizard does not run"; return 1; }
    [ -s /run/efa-init/setup-code ] || { echo "no setup code"; return 1; }
    echo "== wizard"
    # The reboot at the end of the setup would end this run: the first boot runs below instead.
    systemctl mask --runtime efa-setup-reboot.service >/dev/null 2>&1
    dev=$(ip -4 route show default | awk '{print $5; exit}')
    addr=$(ip -4 -o addr show dev "$dev" | awk '{print $4; exit}')
    timeout 1200 python3 -I scripts/fresh_wizard.py --creds "$FRESH_SAVED/wizard-creds" --host "$(cut -d. -f1 "$FRESH_SAVED/hostname")" --domain "$(cut -s -d. -f2- "$FRESH_SAVED/hostname" | grep . || echo example.com)" \
        --interface "$dev" --ipv4 "${addr%/*}" --prefix "${addr#*/}" --gateway "$(ip -4 route show default | awk '{print $3; exit}')" \
        --timezone "$(timedatectl show -p Timezone --value)" || return 1
    echo "== first boot"
    # The reboot request of the wizard hits the masked service: its watcher fails, which a real reboot would not show.
    sc stop efa-setup-reboot.path
    systemctl reset-failed efa-setup-reboot.path efa-setup-reboot.service 2>/dev/null
    rm -f /var/lib/eFa/setup-reboot
    # In place of the reboot: the services with their new settings, then what a boot starts, the first-boot job among them.
    systemctl daemon-reload
    timeout 300 systemctl restart unbound postfix rspamd nginx || return 1
    timeout 1800 systemctl start multi-user.target || { systemctl --failed --no-pager; return 1; }
    timeout 1800 systemctl start efa-firstboot.service || { journalctl -u efa-firstboot -n 20 --no-pager; return 1; }
    [ ! -e /var/lib/eFa/firstboot-pending ] || { echo "first boot left its marker: a step failed"; journalctl -u efa-firstboot -n 20 --no-pager; return 1; }
    echo "== checks"
    for _ in $(seq 24); do efactl status | grep -q '"status": "ok"' && break; sleep 5; done
    efactl status | grep -q '"status": "ok"' || { efactl status; return 1; }
    systemctl is-active -q nginx || { echo "nginx does not run after the first boot"; journalctl -u nginx -n 10 --no-pager; return 1; }
    case "$(stat -c %C /run/nginx.pid 2>/dev/null)" in *:httpd_var_run_t:*) ;; *) echo "/run/nginx.pid: $(ls -Z /run/nginx.pid 2>&1)"; return 1;; esac
    # The new host itself, before fresh_restore puts the saved one back (after it, the check would see the old configuration).
    host_check || return 1
    systemctl --failed --no-legend --plain | awk '{print $1}' | sort | comm -13 "$FRESH_SAVED/failed-before" - > "$OUT/fresh-failed"
    [ -s "$OUT/fresh-failed" ] && { echo "failed units after the setup:"; cat "$OUT/fresh-failed"; return 1; }
    efactl attachment-status | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(not (d["enabled"] and d["executables"] == "reject" and d["names"] == "reject"))' \
        || { echo "attachment checks of a new install are not on"; efactl attachment-status; return 1; }
    efactl cdr-status | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(not (d["enabled"] and d["milter_in_chain"]))' \
        || { echo "content disarm of a new install is not on"; efactl cdr-status; return 1; }
    efactl bec-status | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(not (d["enabled"] and d["own_domains"]))' \
        || { echo "the BEC checks of a new install are not on, or protect no domain"; efactl bec-status; return 1; }
    # MIG-DNS: a new install resolves through the root servers: no forwarder for all names, the system asks its own unbound
    # (also after NetworkManager starts again), and the test entry of Spamhaus ZEN answers listed.
    efactl dns-forward-status | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(d["forward_all"] or not d["system_uses_unbound"])' \
        || { echo "a new install forwards all names, or the system does not ask its own unbound"; efactl dns-forward-status; return 1; }
    timeout 120 systemctl restart NetworkManager && sleep 5
    [ "$(grep '^nameserver' /etc/resolv.conf)" = "nameserver 127.0.0.1" ] || { echo "resolv.conf after NetworkManager:"; cat /etc/resolv.conf; return 1; }
    zen=no
    for _ in 1 2 3 4; do dig +short @127.0.0.1 2.0.0.127.zen.spamhaus.org A | grep -q '^127\.0\.0\.' && { zen=yes; break; }; sleep 3; done
    [ $zen = yes ] || { echo "Spamhaus ZEN does not answer its test entry"; return 1; }
    efactl settings | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(not (d["greylisting"] and d["greylist_minutes"] == 5 and d["greylist_days"] == 7))' \
        || { echo "greylisting of a new install is not on with 5 minutes and 7 days"; efactl settings; return 1; }
    efactl form-check | grep -q '"ok": true' || { efactl form-check; return 1; }
    fresh_standards || return 1
    [ ! -e "$FRESH_SAVED/test-block" ] || nft list table inet efa_test_block >/dev/null 2>&1 || { echo "the outbound block of this host is gone"; return 1; }
    echo "fresh install ok"
}

# HARD-W: the wizard chose BSI TR-02102-2 and RFC 9325: the strictest of both is in effect (the BSI profile: no CHACHA20, no
# TLS below 1.2) on 443 and 587, the standards check says so, the SSH profile stayed as it was.
fresh_standards() {
    efactl standards-status | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(d["selected"] != ["bsi-02102-2", "rfc9325"] or d["port25_tls"] != "off")' \
        || { echo "the standards of the setup are not chosen"; efactl standards-status; return 1; }
    efactl tls-profile-status | grep -q '"profile": "bsi"' || { echo "TLS profile is not bsi"; efactl tls-profile-status; return 1; }
    [ "$(efactl ssh-profile-status | python3 -c 'import json,sys; print(json.load(sys.stdin)["profile"])')" = "$(cat "$FRESH_SAVED/ssh-profile")" ] \
        || { echo "the setup changed the SSH profile"; return 1; }
    strong='ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'
    weak='ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'
    for where in '-connect 127.0.0.1:443' '-starttls smtp -connect 127.0.0.1:587'; do
        echo | timeout 20 openssl s_client $where -tls1_2 -cipher "$strong" 2>&1 | grep -q '^ *Cipher *: *ECDHE-' || { echo "TLS 1.2 with AES-GCM refused: $where"; return 1; }
        echo | timeout 20 openssl s_client $where -tls1_2 -cipher "$weak" 2>&1 | grep -q '^ *Cipher *: *ECDHE-' && { echo "CHACHA20 offered with BSI: $where"; return 1; }
        echo | timeout 20 openssl s_client $where -tls1_3 2>&1 | grep -q 'TLSv1.3' || { echo "no TLS 1.3: $where"; return 1; }
    done
    efactl standards-check | python3 -c 'import json,sys; d=json.load(sys.stdin)["standards"]; sys.exit(d["rfc9325"]["status"] not in ("fulfilled", "over") or any(r["status"] == "not" and (r["wanted"].startswith("from TLS") or "ECDHE-" in r["now"]) for r in d["bsi-02102-2"]["rows"]))' \
        || { echo "the standards check of the setup"; efactl standards-check; return 1; }
    echo "standards of the setup ok"
}

fresh_restore() {
    [ -d "$FRESH_SAVED" ] || { echo "nothing saved"; return 1; }
    # Only a complete save: a half one would unpack a part of the settings over the live ones. Nothing is touched then.
    [ -e "$FRESH_SAVED/complete" ] && ( cd "$FRESH_SAVED" && sha256sum -c --quiet MANIFEST ) || {
        echo "$FRESH_SAVED is not a complete save (no complete mark, or MANIFEST does not match): nothing restored, nothing changed."
        echo "Check it by hand; a save that never moved anything (move/ and copy/ empty) can be removed."
        return 1; }
    echo "== back to the state before"
    systemctl unmask --runtime efa-setup-reboot.service >/dev/null 2>&1
    rm -f /var/lib/eFa/setup-reboot
    efa_units_stop
    sc stop efa-init.service 2>/dev/null
    id "$FRESH_USER" >/dev/null 2>&1 && userdel -r "$FRESH_USER" 2>/dev/null
    # What the setup made goes, also where there was nothing before (the sudo rule of the wizard). A file of a package that
    # did not exist before stays: dnf remove took it away before the save (the cron jobs of eFa), the install put it back.
    if [ ! -e "$FRESH_SAVED/move/etc/eFa" ] && [ -s "$FRESH_SAVED/settings.tar" ]; then
        # The run stopped before it moved the settings away: they come from the copy made at the start.
        tar -C "$FRESH_SAVED/move" -xpf "$FRESH_SAVED/settings.tar" || return 1
    fi
    for p in $FRESH_MOVE; do
        if [ -e "$FRESH_SAVED/move$p" ] || [ -L "$FRESH_SAVED/move$p" ]; then
            rm -rf "$p" && mv "$FRESH_SAVED/move$p" "$p" || return 1
        elif [ -e "$p" ] && ! rpm -qf "$p" >/dev/null 2>&1; then
            rm -rf "$p" || return 1
        fi
    done
    for p in $FRESH_COPY; do
        [ -e "$FRESH_SAVED/copy$p" ] || continue
        rm -rf "$p" && cp -a "$FRESH_SAVED/copy$p" "$p" || return 1
    done
    # Every path that came back from the saved copy gets its label again: with the one of /var/lib, MariaDB skipped its
    # settings (and listened on all addresses) and Postfix could not read the TLS key.
    restorecon -R $FRESH_MOVE $FRESH_COPY 2>/dev/null
    [ -z "$(restorecon -R -n -v $FRESH_MOVE $FRESH_COPY 2>/dev/null)" ] || { echo "SELinux labels still wrong after the restore"; return 1; }
    # Stopped between the removal of the packages and the install: the last green packages, as an upgrade (eFa-Version is back).
    if ! rpm -q eFa-next eFa-next-base >/dev/null 2>&1; then
        timeout 900 dnf -y -q install "$GREEN"/eFa-next-base-*.rpm "$GREEN"/eFa-next-6*.rpm || { echo "no eFa-next packages to put back"; return 1; }
    fi
    mysql -e "DROP DATABASE IF EXISTS efa; CREATE DATABASE efa" && mysql efa < "$FRESH_SAVED/efa.sql" || return 1
    for who in $(mysql -N -e "SELECT CONCAT(QUOTE(user), '@', QUOTE(host)) FROM mysql.user WHERE user LIKE 'efa%'"); do mysql -e "DROP USER $who"; done
    sed 's/^CREATE USER `root`/ALTER USER `root`/' "$FRESH_SAVED/users.sql" | mysql || return 1
    mysql -e 'FLUSH PRIVILEGES' || return 1
    systemctl daemon-reload
    # The units the new install turned on stay off when the host had them off (efa-cluster, efa-dkim-api without their keys
    # would start again and again).
    if [ -s "$FRESH_SAVED/enabled-units" ]; then
        for u in $(systemctl list-unit-files --no-legend --plain --state=enabled 'efa-*' | awk '{print $1}'); do
            grep -qx "$u" "$FRESH_SAVED/enabled-units" || systemctl disable -q "$u"
        done
        xargs -r systemctl enable -q < "$FRESH_SAVED/enabled-units"
    fi
    nmcli connection reload 2>/dev/null
    sc reload sshd
    # Once more after a pause: a start right after the files came back failed once (nginx: /run/nginx.pid, permission denied).
    sc restart unbound mariadb postfix rspamd nginx || { sleep 10; sc restart unbound mariadb postfix rspamd nginx; } || return 1
    sc try-restart fail2ban
    # A timer job that ran while the restore stopped the units ended with TERM: the restore, not a failure of the host. Before
    # the start, so a job that fails after it still shows.
    for timer in $(systemctl list-unit-files --no-legend --plain 'efa-*.timer' | awk '{print $1}'); do
        systemctl reset-failed "${timer%.timer}.service" 2>/dev/null
    done
    sc start $(systemctl list-unit-files --no-legend --plain 'efa-*.timer' 'efa-*.service' | awk '$2 == "enabled" {print $1}' | grep -v '^efa-firstboot\|^efa-init') efactl-runner.service
    # A CVE watch run that a package change started is stopped by the restore (TERM): no failure of the host.
    systemctl reset-failed efa-cve-watch.service 2>/dev/null
    # The sandbox drop-ins of the fresh install stay in /etc/systemd/system: the restored setting (off after an update) decides.
    efactl service-harden --mode keep >/dev/null || return 1
    for _ in $(seq 24); do efactl status | grep -q '"status": "ok"' && break; sleep 5; done
    efactl status | grep -q '"status": "ok"' || { efactl status; return 1; }
    efactl form-check | grep -q '"ok": true' || { efactl form-check; return 1; }
    grep -q '^CONFIGURED:YES' /etc/eFa/eFa-Config || return 1
    rpm -V eFa-next eFa-next-base | grep '^missing' && { echo "files of the packages are missing after the restore"; return 1; }
    # The host name and /etc/hosts as before: the wizard set the name, the setup its block in /etc/hosts.
    hostnamectl set-hostname "$(cat "$FRESH_SAVED/hostname")" || return 1
    [ "$(hostname)" = "$(cat "$FRESH_SAVED/hostname")" ] || { echo "host name not as before: $(hostname)"; return 1; }
    cmp -s /etc/hosts "$FRESH_SAVED/copy/etc/hosts" || { echo "/etc/hosts not as before"; diff "$FRESH_SAVED/copy/etc/hosts" /etc/hosts; return 1; }
    rm -rf "$FRESH_SAVED"
    echo "state before restored"
}

fresh_test() {
    fresh_save || return 1
    # Ctrl-C or a lost SSH connection during the fresh test: the saved host goes back at once, not half wiped.
    trap 'echo "ci: fresh test interrupted, putting the saved host back"; fresh_restore; exit 1' INT TERM HUP
    fresh_run
    result=$?
    trap - INT TERM HUP
    fresh_restore || { echo "RESTORE FAILED: the saved state stays in $FRESH_SAVED; fix and run scripts/ci.sh --fresh-restore"; return 1; }
    return $result
}

[ "${1:-}" = "--fresh-restore" ] && { fresh_restore; exit $?; }

# The SBOM check of rpm-build needs the official schema check (python3-jsonschema, AlmaLinux AppStream).
python3 -c 'import jsonschema' 2>/dev/null || dnf -y -q install python3-jsonschema || echo "ci: python3-jsonschema missing, rpm-build will fail"
# A fresh test that never finished left the host half replaced: nothing that installs runs on it until it is put back.
rm -rf "$FRESH_SAVED.partial"
if [ "$INSTALL" = yes ] && [ -e "$FRESH_SAVED" ]; then
    echo "ci: $FRESH_SAVED exists, an earlier fresh test did not finish: run scripts/ci.sh --fresh-restore first."
    exit 1
fi
step lint-python lint_python
step lint-names lint_names
step lint-shell lint_shell
step exec-bits exec_bits
step lint-os-calls python3 -I scripts/os_lint.py
step consistency python3 -I scripts/consistency_check.py
# PKG-1: the operating system updated alone, eFa-next as built: the packages of others move, the checks after the install must
# still hold. Left out: firewalld (its scripts reload the firewall, as in efactl update-system) and the kernel (no reboot here).
os_update_test() {
    dnf -y -q --refresh upgrade -x 'eFa-next*' -x 'firewalld*' -x 'kernel*' || { echo "os-update: dnf failed"; return 1; }
    rpm -q eFa-next eFa-next-base
    for _ in 1 2 3 4 5 6; do
        efactl status | grep -q '"status": "ok"' && break
        sleep 5
    done
    efactl status | grep -q '"status": "ok"' || { efactl status; systemctl --failed --no-pager; return 1; }
    python3 -B /usr/sbin/efactl --self-test 2>&1 | tail -1 | grep -q 'self-test ok' || return 1
    # PKG-2: the same check the host runs after each package change, here at once.
    efactl os-check-run > "$OUT/os-check.json" || { cat "$OUT/os-check.json"; return 1; }
    grep -q '"ok": true' "$OUT/os-check.json" || { cat "$OUT/os-check.json"; return 1; }
}

# S28: the release upgrade for real on this EL9 host, read only: preflight through its unit, then status. Expected: blocked (no
# eFa-next repository for EL10 yet), and no traceback anywhere.
release_upgrade_real() {
    efactl release-upgrade --action=preflight || return 1
    # A oneshot unit is "activating" while it runs: wait for the state of the step instead.
    for _ in $(seq 150); do
        out=$(efactl release-upgrade --action=status) || { echo "$out"; return 1; }
        echo "$out" | grep -qE '"state": "(queued|preflight)"' || break
        sleep 2
    done
    echo "$out" | grep -q '"state": "blocked"' || { echo "$out"; return 1; }
    echo "$out" | grep -q 'repository for EL10' || { echo "$out"; return 1; }
    if journalctl -u efa-release-upgrade.service --since '-15 min' --no-pager | grep -q Traceback; then
        journalctl -u efa-release-upgrade.service --since '-15 min' --no-pager | tail -40; return 1
    fi
}

arc_independent() {
    # M1-1: the ARC set of efa-cdr checked by dkimpy, not by our own code; in the unit tests it is skipped without the package.
    python3 -c 'import dkim, authres' 2>/dev/null || { echo "dkimpy missing: dnf install python3-dkimpy python3-authres (EPEL)"; return 1; }
    EFA_CI_ARC_DKIMPY=yes python3 -B -m unittest discover -s tests -p test_arc_independent.py -v
}

passkey_browser() {
    # 5s: register and log in with a passkey in Chromium (virtual authenticator) against efactl; the Python of the live-test venv.
    venv=${EFA_LIVE_VENV:-/root/efa-live-venv}
    [ -x "$venv/bin/python" ] || { echo "no venv with playwright: python3 -m venv $venv && $venv/bin/pip install playwright"; return 1; }
    EFA_LIVE_BROWSER="${EFA_LIVE_BROWSER:-/usr/lib64/chromium-browser/headless_shell}" EFA_CI_PASSKEY_BROWSER=yes \
        "$venv/bin/python" -B -m unittest discover -s tests -p test_passkey_browser.py -v
}

retro_imap() {
    # N6: taking mail back over IMAP against a Dovecot of its own (temporary folder, 127.0.0.1, a free port); the Dovecot of the
    # host keeps running untouched.
    # SELinux enforcing: this script runs in initrc_t, whose rules move Dovecot and its children into dovecot_t, which may not
    # use the temporary folder (tmp_t). The test runs in a unit of its own as unconfined_service_t; the policy stays as it is.
    if command -v getenforce >/dev/null && [ "$(getenforce)" = Enforcing ]; then
        # No --pipe: systemd (init_t) may not write the log of this step in /var/tmp; the output goes to the journal of the unit.
        ri_unit="efa-ci-retro-imap-$$"
        systemd-run --wait --quiet --collect --unit="$ri_unit" -p SELinuxContext=system_u:system_r:unconfined_service_t:s0 \
            -p WorkingDirectory="$PWD" -E EFA_CI_RETRO_IMAP=yes python3 -B -m unittest discover -s tests -p test_retro_imap_dovecot.py -v
        ri_code=$?
        journalctl -u "$ri_unit" -o cat --no-pager 2>/dev/null | tail -60
        return $ri_code
    else
        EFA_CI_RETRO_IMAP=yes python3 -B -m unittest discover -s tests -p test_retro_imap_dovecot.py -v
    fi
}

step product-name python3 -I scripts/name_check.py
step license python3 -I scripts/license_check.py
step unit-tests python3 -B -m unittest discover -s tests
step arc-independent arc_independent
step passkey-browser passkey_browser
step retro-imap retro_imap
step self-tests self_tests
# CVE-2026-109786: the sshd filter fix of efactl against the fail2ban of this host (skipped where fail2ban-regex is missing).
step fail2ban-sshd python3 -I scripts/fail2ban_sshd_check.py
step i18n python3 -B scripts/i18n_extract.py --check
step fuzz python3 -B scripts/fuzz.py --seconds 60
step rpm-build python3 -I build/build-rpms.py --next-dir next --out "$OUT/rpms"
[ -z "$FAILED" ] && step reproducible reproducible
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step install-upgrade install_test
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step upgrade-keeps upgrade_keep_check
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step submission-heal-twice submission_heal_twice
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step efa5-587-auth efa5_587_check
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step web-restart web_restart_check
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step nginx-pid nginx_pid_check
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step admin-allow-loopback admin_allow_loopback_check
[ "$INSTALL" = yes ] && step upgrade-unplant upgrade_unplant
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step host-check host_check
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step os-update os_update_test
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step release-upgrade-real release_upgrade_real
# MIG-LE: a certbot lineage of eFa 5 from a local test CA taken over for nginx and Postfix, key unchanged; put back afterwards.
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step le-takeover-live python3 -I scripts/le_takeover_live.py
# MIG-DNS: a forward-zone "." of eFa 5 (to 8.8.8.8) and an internal zone: dns-forward-fix removes the first, keeps the second.
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step dns-forward-live python3 -I scripts/dns_forward_live.py
# DNS-SHARE: the own address as an allowed /32 gets an answer and two firewall rules; after the removal it is refused, the rules gone.
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step dns-share-live python3 -I scripts/dns_share_live.py
# MIG-ALLOW: an allowed sender gets past RBL, HELO and DNS, never through as a relay; its virus is cut out, another's rejected.
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step sender-allow-live python3 -I scripts/sender_allow_live.py
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step maintenance-cidr-live python3 -I scripts/maintenance_cidr_live.py
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step cluster-recidive-live sh scripts/cluster_recidive_live.sh
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step selftest-hermetic-live sh scripts/selftest_hermetic_live.sh
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step totp-failclosed-live sh scripts/totp_failclosed_live.sh
# T-2: the mail paths of the live test in every run: clean, GTUBE, EICAR, quarantine list and release, outbound into the queue.
# Nothing leaves the host (defer_transports for the time of the step, main.cf as before afterwards).
live_mail_step() {
    EFA_CI_LOCK_HELD=1 EFA_LIVE_STEPS=mail EFA_LIVE_DOMAIN="${EFA_LIVE_DOMAIN:-$(awk '!/^#/ && NF {print $1; exit}' /etc/postfix/transport)}" sh scripts/live_test.sh
}
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step live-mail live_mail_step
# T-1 (mails of its own test domain efa-live.test, see live_test.sh): the functions in the mail flow, each switched on for its check and put back: a real mail through Postfix, rspamd and the
# milters, the result read from the queue. Same defer_transports as live-mail: nothing leaves the host.
live_features_step() {
    EFA_CI_LOCK_HELD=1 EFA_LIVE_STEPS=features EFA_LIVE_DOMAIN="${EFA_LIVE_DOMAIN:-$(awk '!/^#/ && NF {print $1; exit}' /etc/postfix/transport)}" sh scripts/live_test.sh
}
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step live-features live_features_step
# 6.0.0.6: the account ID of SecuriteInfo and the key of a threat feed stay out of journal entries, snapshot, backup and logs.
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step secrets-clean python3 -I scripts/secrets_live.py
# SEC-STD: preview changes nothing; Mozilla modern makes the web TLS 1.3 only, 587 keeps 1.2; the check reads sshd -T; the rollback.
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step standards-live python3 -I scripts/standards_live.py
# SBOM-2: what the installed eFa-next needs at runtime holds no Perl, except through the packages in build/sbom.py PERL_VIA.
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step perl-free python3 -I build/sbom.py --perl-check
# Q11: a small load run through rspamd (check only), after the install so the new rules are in.
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step load python3 -I scripts/load_test.py --mode rspamd --mails 200 --parallel 8
# The live UI test (Playwright) of exactly the tree this run installed, in the same hold of the lock: no other run can install
# in between. On with EFA_CI_LIVE_UI=yes (a venv with playwright, see live_test.sh; the Chromium of EPEL chromium-headless unless
# EFA_LIVE_BROWSER names another); efa-web.py of the host is
# compared with the one of this tree before and after.
live_ui_step() {
    cmp -s /usr/local/sbin/efa-web.py next/usr/local/sbin/efa-web.py || { echo "efa-web.py of the host is not the one of this tree"; return 1; }
    EFA_LIVE_BROWSER="${EFA_LIVE_BROWSER:-/usr/lib64/chromium-browser/headless_shell}" EFA_CI_LOCK_HELD=1 EFA_LIVE_STEPS=ui EFA_LIVE_DOMAIN="${EFA_LIVE_DOMAIN:-$(awk '!/^#/ && NF {print $1; exit}' /etc/postfix/transport)}"         sh scripts/live_test.sh || return 1
    cmp -s /usr/local/sbin/efa-web.py next/usr/local/sbin/efa-web.py || { echo "efa-web.py changed during the live test"; return 1; }
}
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && [ "${EFA_CI_LIVE_UI:-}" = yes ] && step live-ui live_ui_step
# The fresh install last: it puts this host back as it was before it.
# Its wizard makes new SSH host keys and the restore puts the saved ones back: a login in between sees another key.
if [ "$FRESH" = yes ] && [ -z "$FAILED" ]; then
    echo "ci: fresh phase from $(date '+%F %T'): temporary SSH host keys until the restore"
    step fresh-install fresh_test
    [ -e "$FRESH_SAVED" ] || echo "ci: fresh phase over $(date '+%F %T'): the saved SSH host keys are back"
fi

UNITS=$(grep -o 'Ran [0-9]* tests' "$OUT/unit-tests.log" 2>/dev/null)
if [ -z "$FAILED" ]; then
    echo "ci: OK ($UNITS; self-tests $SELF_TESTS; rpm built; install: $INSTALL; fresh: $FRESH) $(date '+%F %T')"
    rm -rf "$GREEN"
    mv "$OUT/rpms" "$GREEN" && tree_hash >"$GREEN/TREE" && date '+%F %T' >"$GREEN/WHEN"
    # EFA_CI_KEEP=<folder>: a copy of these packages, still under the lock, that the next green run does not replace.
    if [ -n "${EFA_CI_KEEP:-}" ]; then
        rm -rf "$EFA_CI_KEEP.tmp" && mkdir -p "$EFA_CI_KEEP.tmp" && cp -p "$GREEN"/* "$EFA_CI_KEEP.tmp/" && rm -rf "$EFA_CI_KEEP" &&
            mv "$EFA_CI_KEEP.tmp" "$EFA_CI_KEEP" && echo "ci: packages kept in $EFA_CI_KEEP"
    fi
    rm -rf "$OUT"
    exit 0
fi
rm -rf "$OUT/rpms" "$OUT/rpms2"
echo "ci: FAILED:$FAILED (logs in $OUT)"
exit 1
