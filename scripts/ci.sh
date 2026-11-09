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
rm -rf /var/tmp/efa-ci.??????
OUT=$(mktemp -d /var/tmp/efa-ci.XXXXXX)
FAILED=""
SELF_TESTS=0
step() {
    name=$1
    shift
    if "$@" >"$OUT/$name.log" 2>&1; then
        echo "ci: $name ok"
    else
        echo "ci: $name FAILED, last lines:"
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
    for f in $(grep -rl '^#!/bin/sh' next src scripts 2>/dev/null); do
        sh -n "$f" || return 1
    done
    bash -n build/build.bash
}

self_tests() {
    for p in build/sbom.py scripts/detection_benchmark.py scripts/load_test.py next/usr/sbin/efactl next/usr/local/sbin/efa-web.py next/usr/local/sbin/efa-maillog.py next/usr/local/sbin/efa-milter-health.py \
             next/usr/local/sbin/efa-init.py next/usr/sbin/efa-console-2fa next/usr/local/sbin/efa-tui next/usr/local/sbin/efa-cdr.py next/usr/local/sbin/efa-reports.py next/usr/local/sbin/efa-phish.py next/usr/local/sbin/efa-outbound.py next/usr/local/sbin/efa-cluster.py next/usr/local/sbin/efa-dkim-api.py next/usr/local/sbin/efactl-runner.py next/usr/local/sbin/efa-sasl.py next/usr/local/sbin/efa-qr.py next/usr/local/sbin/efa-roles.py next/usr/local/sbin/efa-unlock.py next/usr/local/sbin/efa-trap.py next/usr/local/sbin/efa-sandbox.py next/usr/local/sbin/efa-emergency.py next/usr/lib/eFa/python/efa_cluster.py next/usr/lib/eFa/python/efa_blocklist.py next/usr/lib/eFa/python/efa_mime.py next/usr/lib/eFa/python/efa_pdf.py next/usr/lib/eFa/python/efa_evidence.py next/usr/lib/eFa/python/efa5_convert.py next/usr/lib/eFa/python/efa_i18n.py next/usr/lib/eFa/python/efa_links.py next/usr/lib/eFa/python/efa_sign.py next/usr/lib/eFa/python/efa_zip.py next/usr/lib/eFa/python/efa_qcrypt.py next/usr/lib/eFa/python/efa_qr.py next/usr/lib/eFa/python/efa_totp.py next/usr/lib/eFa/python/efa_setup.py next/usr/lib/eFa/python/efa_webauthn.py next/usr/lib/eFa/python/efa_feeds.py next/usr/lib/eFa/python/efa_bimi.py next/usr/lib/eFa/python/efa_domaincheck.py next/usr/lib/eFa/python/efa_lookalike.py next/usr/lib/eFa/python/efa_a11y.py next/usr/lib/eFa/python/efa_crypto.py next/usr/lib/eFa/python/efa_host.py \
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
    hc_left=$(ls /etc/systemd/system/*.service.d/efa-hardening.conf 2>/dev/null)
    if [ -z "$hc_left" ]; then echo "sandbox drop-ins: none"; else echo "sandbox drop-ins: FAILED ($hc_left)"; hc_failed=1; fi
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
    # The installer takes the nginx module stream 1.26 (1.20 of AppStream does not know "http2 on;"), and nginx loads its files.
    hc_nginx=$(nginx -v 2>&1 | sed -n 's#.*nginx/\([0-9][0-9.]*\).*#\1#p')
    if printf '%s\n%s\n' 1.25.1 "${hc_nginx:-0}" | sort -t. -k1,1n -k2,2n -k3,3n -C && nginx -t >/dev/null 2>&1; then echo "nginx $hc_nginx: ok"
    else echo "nginx ${hc_nginx:-missing}: FAILED (older than 1.25.1 or nginx -t refuses the files)"; hc_failed=1; fi
    # No IPv6 on the host: Postfix must not try IPv6 sockets (SELinux denies sendmail_t loading the module).
    hc_proto=$(postconf -h inet_protocols 2>/dev/null)
    if [ -e /proc/net/if_inet6 ] || [ "$hc_proto" = ipv4 ]; then echo "postfix inet_protocols: ok ($hc_proto)"
    else echo "postfix inet_protocols: FAILED ($hc_proto on a host without IPv6)"; hc_failed=1; fi
    if sudo -u unbound test -r /var/lib/unbound/root.key; then echo "unbound root.key: ok"; else echo "unbound root.key: FAILED (not readable for unbound)"; hc_failed=1; fi
    # SELinux: no denial for a distribution service since the install began (HOST_CHECK_SINCE, set by install_test and fresh_run).
    if command -v ausearch >/dev/null && [ -n "${HOST_CHECK_SINCE:-}" ]; then
        hc_denied=$(ausearch -m avc -i -ts $HOST_CHECK_SINCE 2>/dev/null | grep -oE 'comm=[^ ]+' | sort | uniq -c |
            grep -E 'comm=(unbound|unbound-checkco|unbound-anchor|rspamd|clamd|freshclam|redis-server|nginx|postfix|master|smtpd|sendmail|newaliases|postmap|postalias|mariadbd|mysqld|dovecot|doveconf|efactl|postconf|chronyd|chronyc)$')
        if [ -z "$hc_denied" ]; then echo "selinux denials: none"; else echo "selinux denials: FAILED"; echo "$hc_denied"; hc_failed=1; fi
    fi
    if command -v ausearch >/dev/null && [ -n "${HOST_CHECK_BEFORE:-}" ] && [ -n "${HOST_CHECK_SINCE:-}" ]; then
        hc_before=$(ausearch -m avc -i -ts $HOST_CHECK_BEFORE -te $HOST_CHECK_SINCE 2>/dev/null | grep -oE 'comm=[^ ]+' | sort | uniq -c)
        [ -z "$hc_before" ] || { echo "selinux denials before the eFa-next install (stock packages, not counted):"; echo "$hc_before"; }
    fi
    return $hc_failed
}

install_test() {
    HOST_CHECK_SINCE="$(date +%x) $(date +%T)"
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
FRESH_MOVE='/etc/eFa /etc/efa-web /etc/efa-portal /etc/efa-sasl /etc/eFa-Version /var/lib/eFa /var/eFa /var/log/eFa /var/log/eFa-archive
    /etc/cron.d/eFa-Backup.cron /etc/cron.d/efa-maillog /etc/cron.d/eFa-Monitor.cron /etc/cron.d/efa-quarantine /etc/nginx/conf.d/efa-admin-allow.conf
    /etc/nginx/conf.d/efa.conf /etc/rspamd/local.d /etc/rspamd/override.d /etc/rspamd/dkim /etc/postfix /etc/my.cnf.d/efa.cnf /etc/sudoers.d/efa-init
    /etc/pki/tls/certs/efa.crt /etc/pki/tls/private/efa.key /var/lib/rpm-state/eFa /var/lib/rpm-state/eFa-base'
FRESH_COPY='/etc/ssh /etc/hosts /etc/unbound /etc/resolv.conf /etc/NetworkManager/system-connections /etc/fail2ban /etc/dnf/automatic.conf
    /etc/localtime /etc/sysconfig/eFa-Monitor'
FRESH_USER=efa-ci-fresh

efa_units_stop() {
    sc stop 'efa-*.timer' efactl-runner.service $(systemctl list-units --no-legend --plain 'efa-*.service' | awk '{print $1}' | grep -v '^efa-test-block\|^efa-ci-') 2>/dev/null
    return 0
}

fresh_save() {
    [ -e "$FRESH_SAVED" ] && { echo "$FRESH_SAVED exists: an earlier fresh test did not finish. Run scripts/ci.sh --fresh-restore first."; return 1; }
    grep -q '^CONFIGURED:YES' /etc/eFa/eFa-Config 2>/dev/null || { echo "this host is not set up: no state to come back to"; return 1; }
    [ -s /etc/eFa-Version ] && rpm -q eFa-next eFa-next-base >/dev/null || { echo "eFa-next is not fully installed here: no fresh test"; return 1; }
    mkdir -m 0700 "$FRESH_SAVED" "$FRESH_SAVED/move" "$FRESH_SAVED/copy" || return 1
    # A copy of the settings before anything is removed: dnf remove deletes files of the packages, and an interrupted run once
    # left a host without /etc/eFa. The restore takes it when the moved copy is missing.
    tar -C / -cpf "$FRESH_SAVED/settings.tar" $(for p in $FRESH_MOVE; do case "$p" in /var/log/*) ;; *) [ -e "$p" ] && echo "${p#/}";; esac; done) || return 1
    for p in $FRESH_COPY; do [ -e "$p" ] && { cp -a --parents "$p" "$FRESH_SAVED/copy/" || return 1; }; done
    mysqldump --single-transaction efa > "$FRESH_SAVED/efa.sql" || return 1
    # The accounts with their password hashes, root too: the setup gives root a new password.
    for who in $(mysql -N -e "SELECT CONCAT(QUOTE(user), '@', QUOTE(host)) FROM mysql.user WHERE user LIKE 'efa%' OR user = 'root'"); do
        mysql -N -e "SHOW CREATE USER $who" | sed 's/$/;/'
        mysql -N -e "SHOW GRANTS FOR $who" | sed 's/$/;/'
    done > "$FRESH_SAVED/users.sql" || return 1
    systemctl --failed --no-legend --plain | awk '{print $1}' | sort > "$FRESH_SAVED/failed-before"
    nft list table inet efa_test_block >/dev/null 2>&1 && touch "$FRESH_SAVED/test-block"
    # The name of the kernel: the wizard gives it again, the restore puts it back and compares.
    uname -n > "$FRESH_SAVED/hostname" || return 1
    # An empty name once made the restore fail for good: fail here, while nothing is changed yet.
    grep -q '[a-z]' "$FRESH_SAVED/hostname" || {
        echo "no host name to come back to: uname -n [$(uname -n)] hostname [$(hostname 2>&1)] static [$(hostnamectl --static 2>&1)]"
        rm -rf "$FRESH_SAVED"; return 1; }
    echo saved
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
    efactl form-check | grep -q '"ok": true' || { efactl form-check; return 1; }
    [ ! -e "$FRESH_SAVED/test-block" ] || nft list table inet efa_test_block >/dev/null 2>&1 || { echo "the outbound block of this host is gone"; return 1; }
    echo "fresh install ok"
}

fresh_restore() {
    [ -d "$FRESH_SAVED" ] || { echo "nothing saved"; return 1; }
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
    restorecon -R /etc/ssh /etc/postfix /etc/eFa /var/lib/eFa 2>/dev/null
    # Stopped between the removal of the packages and the install: the last green packages, as an upgrade (eFa-Version is back).
    if ! rpm -q eFa-next eFa-next-base >/dev/null 2>&1; then
        timeout 900 dnf -y -q install "$GREEN"/eFa-next-base-*.rpm "$GREEN"/eFa-next-6*.rpm || { echo "no eFa-next packages to put back"; return 1; }
    fi
    mysql -e "DROP DATABASE IF EXISTS efa; CREATE DATABASE efa" && mysql efa < "$FRESH_SAVED/efa.sql" || return 1
    for who in $(mysql -N -e "SELECT CONCAT(QUOTE(user), '@', QUOTE(host)) FROM mysql.user WHERE user LIKE 'efa%'"); do mysql -e "DROP USER $who"; done
    sed 's/^CREATE USER `root`/ALTER USER `root`/' "$FRESH_SAVED/users.sql" | mysql || return 1
    mysql -e 'FLUSH PRIVILEGES' || return 1
    systemctl daemon-reload
    nmcli connection reload 2>/dev/null
    sc reload sshd
    sc restart unbound mariadb postfix rspamd nginx || return 1
    sc try-restart fail2ban
    sc start $(systemctl list-unit-files --no-legend --plain 'efa-*.timer' 'efa-*.service' | awk '$2 == "enabled" {print $1}' | grep -v '^efa-firstboot\|^efa-init') efactl-runner.service
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
step product-name python3 -I scripts/name_check.py
step license python3 -I scripts/license_check.py
step unit-tests python3 -B -m unittest discover -s tests
step self-tests self_tests
step i18n python3 -B scripts/i18n_extract.py --check
step fuzz python3 -B scripts/fuzz.py --seconds 60
step rpm-build python3 -I build/build-rpms.py --next-dir next --out "$OUT/rpms"
[ -z "$FAILED" ] && step reproducible reproducible
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step install-upgrade install_test
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step host-check host_check
# SBOM-2: what the installed eFa-next needs at runtime holds no Perl, except through the packages in build/sbom.py PERL_VIA.
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step perl-free python3 -I build/sbom.py --perl-check
# Q11: a small load run through rspamd (check only), after the install so the new rules are in.
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step load python3 -I scripts/load_test.py --mode rspamd --mails 200 --parallel 8
# The fresh install last: it puts this host back as it was before it.
[ "$FRESH" = yes ] && [ -z "$FAILED" ] && step fresh-install fresh_test

UNITS=$(grep -o 'Ran [0-9]* tests' "$OUT/unit-tests.log" 2>/dev/null)
if [ -z "$FAILED" ]; then
    echo "ci: OK ($UNITS; self-tests $SELF_TESTS; rpm built; install: $INSTALL; fresh: $FRESH) $(date '+%F %T')"
    rm -rf "$GREEN"
    mv "$OUT/rpms" "$GREEN" && tree_hash >"$GREEN/TREE" && date '+%F %T' >"$GREEN/WHEN"
    rm -rf "$OUT"
    exit 0
fi
rm -rf "$OUT/rpms" "$OUT/rpms2"
echo "ci: FAILED:$FAILED (logs in $OUT)"
exit 1
