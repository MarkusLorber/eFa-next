#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
#
# The checks of every change, on an EL9 build and test host, from the root of the repository:
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
if ! flock -n 9; then
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

lint_shell() {
    # Scripts that must run with any POSIX sh, also on FreeBSD later.
    for f in $(grep -rl '^#!/bin/sh' next src scripts 2>/dev/null); do
        sh -n "$f" || return 1
    done
    bash -n build/build.bash
}

self_tests() {
    for p in build/sbom.py scripts/detection_benchmark.py scripts/load_test.py next/usr/sbin/efactl next/usr/local/sbin/efa-web.py next/usr/local/sbin/efa-maillog.py next/usr/local/sbin/efa-milter-health.py \
             next/usr/local/sbin/efa-init.py next/usr/local/sbin/efa-tui next/usr/local/sbin/efa-cdr.py next/usr/local/sbin/efa-reports.py next/usr/local/sbin/efa-phish.py next/usr/local/sbin/efa-outbound.py next/usr/local/sbin/efa-cluster.py next/usr/local/sbin/efa-dkim-api.py next/usr/local/sbin/efactl-runner.py next/usr/local/sbin/efa-sasl.py next/usr/lib/eFa/python/efa_cluster.py next/usr/lib/eFa/python/efa_blocklist.py next/usr/lib/eFa/python/efa_mime.py next/usr/lib/eFa/python/efa_pdf.py next/usr/lib/eFa/python/efa_evidence.py next/usr/lib/eFa/python/efa5_convert.py next/usr/lib/eFa/python/efa_i18n.py next/usr/lib/eFa/python/efa_links.py next/usr/lib/eFa/python/efa_sign.py next/usr/lib/eFa/python/efa_zip.py \
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

install_test() {
    # The firewall tables of eFa must never go away during an install or upgrade: nft monitor writes down every table event.
    guard=no
    nft list table inet efa_guard >/dev/null 2>&1 && guard=yes
    nft monitor tables > "$OUT/nft-monitor.log" 2>&1 &
    monitor=$!
    dnf -y -q reinstall "$OUT"/rpms/eFa-base-*.rpm "$OUT"/rpms/eFa-6*.rpm || dnf -y -q install "$OUT"/rpms/eFa-base-*.rpm "$OUT"/rpms/eFa-6*.rpm || { kill $monitor; return 1; }
    sleep 2
    kill $monitor
    if grep -qE 'delete table inet (efa_guard|efa_test_block)' "$OUT/nft-monitor.log"; then
        echo "a firewall table of eFa was removed during the install:"; cat "$OUT/nft-monitor.log"; return 1
    fi
    if [ "$guard" = yes ] && ! nft list table inet efa_guard >/dev/null 2>&1; then
        echo "the allowlist table efa_guard is gone after the install"; return 1
    fi
    # The package hooks restart the running eFa units; the health service checks every 10 seconds.
    for _ in 1 2 3 4 5 6; do
        efactl status | grep -q '"status": "ok"' && break
        sleep 5
    done
    efactl status | grep -q '"status": "ok"' || { efactl status; return 1; }
    rpm -V eFa eFa-base | grep -v ' c /' | grep -q . && { rpm -V eFa eFa-base; return 1; }
    python3 -B /usr/sbin/efactl --self-test 2>&1 | tail -1 | grep -q 'self-test ok' || return 1
    # Every form shows what is set now on this host (efa_nav.FORM_SOURCE).
    efactl form-check | grep -q '"ok": true' || { efactl form-check; return 1; }
    # Q5b: the hardening report as PDF is valid and holds the host and the checks.
    efactl hardening-report --pdf "$OUT/hardening.pdf" >/dev/null || return 1
    qpdf --check "$OUT/hardening.pdf" | grep -q 'No syntax or stream encoding errors' || { qpdf --check "$OUT/hardening.pdf"; return 1; }
    if command -v pdftotext >/dev/null; then
        pdftotext "$OUT/hardening.pdf" - | grep -q "$(hostname -f)" || { echo "hardening PDF without the host name"; return 1; }
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
    # Over stdin: efa-web cannot read the build folder.
    sudo -u efa-web python3 -I - --rounds 5 --budget-ms 100 < scripts/page_times.py > "$OUT/page-times.txt" 2>&1
    pages_ok=$?
    grep -v WARNING "$OUT/page-times.txt"
    [ $pages_ok -eq 0 ] || return 1
    # Standard view: only cards with a setting or a warning (Hans: values without a setting belong to the expert view), and the
    # same values as the expert view in every card and tile it shows.
    sudo -u efa-web python3 -I - --check-standard < scripts/page_times.py 2>&1 | grep -v WARNING > "$OUT/standard-view.txt"
    cat "$OUT/standard-view.txt"
    grep -q 'standard view: problems: none' "$OUT/standard-view.txt" || return 1
}

# The fresh-install path (--fresh, and with --install after the upgrade): this host is set up anew from the packages of this
# run, as an admin would (packages, wizard, first boot), checked, and then put back exactly as it was. The eFa files move
# aside (so the install finds none), what the setup changes besides them is copied, the eFa database and its users are dumped.
# The state waits in FRESH_SAVED until it is back: an interrupted run leaves it there, and --fresh-restore puts it back.
FRESH_SAVED=/var/lib/efa-ci-fresh-saved
FRESH_MOVE='/etc/eFa /etc/efa-web /etc/efa-portal /etc/efa-sasl /etc/eFa-Version /var/lib/eFa /var/eFa /var/log/eFa /var/log/eFa-archive
    /etc/cron.d/eFa-Backup.cron /etc/cron.d/efa-maillog /etc/cron.d/eFa-Monitor.cron /etc/cron.d/efa-quarantine /etc/nginx/conf.d/efa-admin-allow.conf
    /etc/nginx/conf.d/efa.conf /etc/rspamd/local.d /etc/rspamd/override.d /etc/rspamd/dkim /etc/postfix /etc/my.cnf.d/efa.cnf /etc/sudoers.d/efa-init
    /etc/pki/tls/certs/efa.crt /etc/pki/tls/private/efa.key /var/lib/rpm-state/eFa /var/lib/rpm-state/eFa-base'
FRESH_COPY='/etc/ssh /etc/hosts /etc/unbound /etc/resolv.conf /etc/NetworkManager/system-connections /etc/fail2ban /etc/dnf/automatic.conf
    /etc/localtime /etc/sysconfig/eFa-Monitor'
FRESH_USER=efa-ci-fresh

efa_units_stop() {
    systemctl stop 'efa-*.timer' efactl-runner.service $(systemctl list-units --no-legend --plain 'efa-*.service' | awk '{print $1}' | grep -v '^efa-test-block') 2>/dev/null
    return 0
}

fresh_save() {
    [ -e "$FRESH_SAVED" ] && { echo "$FRESH_SAVED exists: an earlier fresh test did not finish. Run scripts/ci.sh --fresh-restore first."; return 1; }
    grep -q '^CONFIGURED:YES' /etc/eFa/eFa-Config 2>/dev/null || { echo "this host is not set up: no state to come back to"; return 1; }
    mkdir -m 0700 "$FRESH_SAVED" "$FRESH_SAVED/move" "$FRESH_SAVED/copy" || return 1
    for p in $FRESH_COPY; do [ -e "$p" ] && { cp -a --parents "$p" "$FRESH_SAVED/copy/" || return 1; }; done
    mysqldump --single-transaction efa > "$FRESH_SAVED/efa.sql" || return 1
    # The accounts with their password hashes, root too: the setup gives root a new password.
    for who in $(mysql -N -e "SELECT CONCAT(QUOTE(user), '@', QUOTE(host)) FROM mysql.user WHERE user LIKE 'efa%' OR user = 'root'"); do
        mysql -N -e "SHOW CREATE USER $who" | sed 's/$/;/'
        mysql -N -e "SHOW GRANTS FOR $who" | sed 's/$/;/'
    done > "$FRESH_SAVED/users.sql" || return 1
    systemctl --failed --no-legend --plain | awk '{print $1}' | sort > "$FRESH_SAVED/failed-before"
    nft list table inet efa_test_block >/dev/null 2>&1 && touch "$FRESH_SAVED/test-block"
    echo saved
}

fresh_run() {
    efa_units_stop
    timeout 600 dnf -y -q remove --noautoremove eFa eFa-base || return 1
    for p in $FRESH_MOVE; do [ -e "$p" ] && { mkdir -p "$FRESH_SAVED/move$(dirname "$p")" && mv "$p" "$FRESH_SAVED/move$p" || return 1; }; done
    mysql -e "DROP DATABASE IF EXISTS efa" || return 1
    for who in $(mysql -N -e "SELECT CONCAT(QUOTE(user), '@', QUOTE(host)) FROM mysql.user WHERE user LIKE 'efa%'"); do mysql -e "DROP USER $who"; done
    # Postfix and rspamd with the configuration of their packages, as on a new host.
    timeout 600 dnf -y -q reinstall postfix rspamd || return 1
    echo "== install"
    timeout 900 dnf -y install "$OUT"/rpms/eFa-base-*.rpm "$OUT"/rpms/eFa-6*.rpm > "$OUT/fresh-dnf.log" 2>&1 || { tail -20 "$OUT/fresh-dnf.log"; return 1; }
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
    timeout 1200 python3 -I scripts/fresh_wizard.py --creds "$FRESH_SAVED/wizard-creds" --host "$(hostname -s)" --domain "$(hostname -d | grep . || echo example.com)" \
        --interface "$dev" --ipv4 "${addr%/*}" --prefix "${addr#*/}" --gateway "$(ip -4 route show default | awk '{print $3; exit}')" \
        --timezone "$(timedatectl show -p Timezone --value)" || return 1
    echo "== first boot"
    # The reboot request of the wizard hits the masked service: its watcher fails, which a real reboot would not show.
    systemctl stop efa-setup-reboot.path
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
    systemctl --failed --no-legend --plain | awk '{print $1}' | sort | comm -13 "$FRESH_SAVED/failed-before" - > "$OUT/fresh-failed"
    [ -s "$OUT/fresh-failed" ] && { echo "failed units after the setup:"; cat "$OUT/fresh-failed"; return 1; }
    efactl attachment-status | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(not (d["enabled"] and d["executables"] == "reject" and d["names"] == "reject"))' \
        || { echo "attachment checks of a new install are not on"; efactl attachment-status; return 1; }
    efactl cdr-status | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(not (d["enabled"] and d["milter_in_chain"]))' \
        || { echo "content disarm of a new install is not on"; efactl cdr-status; return 1; }
    efactl form-check | grep -q '"ok": true' || { efactl form-check; return 1; }
    [ ! -e "$FRESH_SAVED/test-block" ] || nft list table inet efa_test_block >/dev/null 2>&1 || { echo "the outbound block of this test host is gone"; return 1; }
    echo "fresh install ok"
}

fresh_restore() {
    [ -d "$FRESH_SAVED" ] || { echo "nothing saved"; return 1; }
    echo "== back to the state before"
    systemctl unmask --runtime efa-setup-reboot.service >/dev/null 2>&1
    rm -f /var/lib/eFa/setup-reboot
    efa_units_stop
    systemctl stop efa-init.service 2>/dev/null
    id "$FRESH_USER" >/dev/null 2>&1 && userdel -r "$FRESH_USER" 2>/dev/null
    # What the setup made goes, also where there was nothing before (the sudo rule of the wizard).
    for p in $FRESH_MOVE; do
        rm -rf "$p" || return 1
        if [ -e "$FRESH_SAVED/move$p" ] || [ -L "$FRESH_SAVED/move$p" ]; then mv "$FRESH_SAVED/move$p" "$p" || return 1; fi
    done
    for p in $FRESH_COPY; do
        [ -e "$FRESH_SAVED/copy$p" ] || continue
        rm -rf "$p" && cp -a "$FRESH_SAVED/copy$p" "$p" || return 1
    done
    restorecon -R /etc/ssh /etc/postfix /etc/eFa /var/lib/eFa 2>/dev/null
    mysql -e "DROP DATABASE IF EXISTS efa; CREATE DATABASE efa" && mysql efa < "$FRESH_SAVED/efa.sql" || return 1
    for who in $(mysql -N -e "SELECT CONCAT(QUOTE(user), '@', QUOTE(host)) FROM mysql.user WHERE user LIKE 'efa%'"); do mysql -e "DROP USER $who"; done
    sed 's/^CREATE USER `root`/ALTER USER `root`/' "$FRESH_SAVED/users.sql" | mysql || return 1
    mysql -e 'FLUSH PRIVILEGES' || return 1
    systemctl daemon-reload
    nmcli connection reload 2>/dev/null
    systemctl reload sshd
    systemctl restart unbound mariadb postfix rspamd nginx || return 1
    systemctl try-restart fail2ban
    systemctl start $(systemctl list-unit-files --no-legend --plain 'efa-*.timer' 'efa-*.service' | awk '$2 == "enabled" {print $1}' | grep -v '^efa-firstboot\|^efa-init') efactl-runner.service
    for _ in $(seq 24); do efactl status | grep -q '"status": "ok"' && break; sleep 5; done
    efactl status | grep -q '"status": "ok"' || { efactl status; return 1; }
    efactl form-check | grep -q '"ok": true' || { efactl form-check; return 1; }
    grep -q '^CONFIGURED:YES' /etc/eFa/eFa-Config || return 1
    rm -rf "$FRESH_SAVED"
    echo "state before restored"
}

fresh_test() {
    fresh_save || return 1
    fresh_run
    result=$?
    fresh_restore || { echo "RESTORE FAILED: the saved state stays in $FRESH_SAVED; fix and run scripts/ci.sh --fresh-restore"; return 1; }
    return $result
}

[ "${1:-}" = "--fresh-restore" ] && { fresh_restore; exit $?; }

step lint-python lint_python
step lint-names lint_names
step lint-shell lint_shell
step lint-os-calls python3 -I scripts/os_lint.py
step license python3 -I scripts/license_check.py
step unit-tests python3 -B -m unittest discover -s tests
step self-tests self_tests
step i18n python3 -B scripts/i18n_extract.py --check
step fuzz python3 -B scripts/fuzz.py --seconds 60
step rpm-build python3 -I build/build-rpms.py --next-dir next --out "$OUT/rpms"
[ -z "$FAILED" ] && step reproducible reproducible
[ "$INSTALL" = yes ] && [ -z "$FAILED" ] && step install-upgrade install_test
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
