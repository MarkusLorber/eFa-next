#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
#
# Live tests of a release on an installed host (RELEASE-CHECKLIST section 2), as root, after a green scripts/ci.sh --install.
# Under the lock of ci.sh, one after the other; every check prints ok, FAILED or SKIPPED, the logs and screenshots go to
# /var/tmp/efa-live.<date>. What a step makes it removes again, a changed setting goes back (also when a step stops).
#
#   EFA_LIVE_DOMAIN=<local test domain> scripts/live_test.sh
#
# EFA_LIVE_DOMAIN   a local test domain of this host (mail paths, the portal user)              required
# EFA_LIVE_TENANT   an existing test tenant with EFA_LIVE_DOMAIN: also the tenant, domain and helpdesk roles  optional
# EFA_LIVE_VENV     the venv with playwright (default /root/efa-live-venv)
# EFA_LIVE_BROWSER  a Chromium of the system (EPEL: chromium-headless), else the one of playwright
# EFA_LIVE_IDLE_MINUTES  minutes of the idle test (default 10); EFA_LIVE_IDLE_CPU  the most CPU % of all eFa-next processes (5)
# EFA_LIVE_FASTTEXT_MODEL  a FastText model file for the RAM measure of N5 (only measured, then taken out again)
# EFA_LIVE_STEPS    the steps to run (default: ui idle mail pages cve pgp n5)
# EFA_CI_LOCK_WAIT  seconds to wait for a running ci.sh or live test (default 7200)

cd "$(dirname "$0")/.." || exit 1
[ "$(id -u)" = 0 ] || { echo "live tests: as root"; exit 2; }
[ -n "${EFA_LIVE_DOMAIN:-}" ] || { echo "live tests: set EFA_LIVE_DOMAIN to a local test domain of this host"; exit 2; }
OUT=/var/tmp/efa-live.$(date +%Y%m%d-%H%M%S)
mkdir -m 0700 "$OUT" || exit 1
RUN=$(date +%s)
VENV=${EFA_LIVE_VENV:-/root/efa-live-venv}
STEPS=${EFA_LIVE_STEPS:-ui idle mail pages cve pgp n5}
SUMMARY="$OUT/summary.txt"
: > "$SUMMARY"

exec 9>>/var/tmp/efa-ci.lock
flock -w "${EFA_CI_LOCK_WAIT:-7200}" 9 || { echo "live tests: the lock of ci.sh stays taken"; exit 1; }

result() { echo "$1: $2" | tee -a "$SUMMARY"; }

# Settings a step changes come back here, also when the script is stopped.
RESTORE=""
restore() {
    [ -z "$RESTORE" ] && return 0
    sh -c "$RESTORE" >> "$OUT/restore.log" 2>&1
    RESTORE=""
}
trap 'restore' EXIT INT TERM

step_ui() {
    if [ ! -x "$VENV/bin/python" ] || ! "$VENV/bin/python" -c 'import playwright' 2>/dev/null; then
        result ui "SKIPPED (no playwright: python3 -m venv $VENV && $VENV/bin/pip install playwright; a browser: dnf install chromium-headless (EPEL) and EFA_LIVE_BROWSER=/usr/lib64/chromium-browser/headless_shell, or $VENV/bin/playwright install chromium)"
        return 0
    fi
    "$VENV/bin/python" -I scripts/live_ui.py "$OUT/ui" "$EFA_LIVE_DOMAIN" "${EFA_LIVE_TENANT:-}" > "$OUT/ui.log" 2>&1
    code=$?
    cat "$OUT/ui.log" >> "$SUMMARY"; grep -E '^ui ' "$OUT/ui.log"
    [ $code -eq 0 ] && result ui ok || result ui FAILED
}

step_idle() {
    minutes=${EFA_LIVE_IDLE_MINUTES:-10}
    samples=$((minutes * 6))
    ctxt_start=$(awk '/^ctxt/ {print $2}' /proc/stat)
    : > "$OUT/idle.tsv"
    i=0
    while [ $i -lt $samples ]; do
        # CPU % and RSS of the eFa-next processes and of the services they run on, one line per sample.
        ps -eo pcpu=,rss=,comm=,args= | awk -v t="$(date +%s)" '
            $3 ~ /^(rspamd|clamd|freshclam|redis-server|mariadbd|mysqld|nginx|master|unbound|python3|fail2ban-server)$/ || $0 ~ /efa|efactl/ {
                cpu += $1; rss += $2; n++ }
            END { printf "%s\t%.1f\t%d\t%d\n", t, cpu, rss / 1024, n }' >> "$OUT/idle.tsv"
        sleep 10
        i=$((i + 1))
    done
    ctxt_end=$(awk '/^ctxt/ {print $2}' /proc/stat)
    free -m > "$OUT/idle-memory.txt"
    ps -eo pcpu=,rss=,comm= --sort=-rss | head -25 > "$OUT/idle-top.txt"
    summary=$(awk -v ctxt=$(( (ctxt_end - ctxt_start) / (minutes * 60) )) '{ cpu += $2; if ($3 > rss) rss = $3; n = $4 } END {
        printf "cpu %.1f %% (mean of the eFa-next processes and services), rss %d MB at most, %d processes, %d context switches/s", cpu / NR, rss, n, ctxt }' "$OUT/idle.tsv")
    mean=$(awk '{ cpu += $2 } END { printf "%d", cpu / NR }' "$OUT/idle.tsv")
    [ "$mean" -le "${EFA_LIVE_IDLE_CPU:-5}" ] && result idle "ok ($summary)" || result idle "FAILED ($summary)"
    # Who holds the memory and the CPU at the end of the idle time: one line per service, eFa-next programs by their script.
    ps -eo pcpu=,rss=,comm=,args= | awk '
        { name = $3 }
        $0 ~ /efa[-_a-z]*\.py|efactl|efa-tui|efa-console/ { if (match($0, /efa[-_a-z]*(\.py)?|efactl[-a-z]*/)) name = substr($0, RSTART, RLENGTH) }
        name ~ /^(rspamd|clamd|freshclam|redis-server|mariadbd|mysqld|nginx|master|smtpd|qmgr|unbound|fail2ban-server|dovecot)$/ || name ~ /^efa/ {
            rss[name] += $2; cpu[name] += $1 }
        END { for (n in rss) printf "%d\t%.1f\t%s\n", rss[n] / 1024, cpu[n], n }' | sort -rn > "$OUT/idle-services.tsv"
    awk '{ printf "    %-24s %6d MB  %5.1f %% CPU\n", $3, $1, $2 }' "$OUT/idle-services.tsv" | tee -a "$SUMMARY"
}

step_mail() {
    # Nothing leaves the host: every transport waits for the time of the test, then the main.cf of before comes back.
    cp -p /etc/postfix/main.cf "$OUT/main.cf.before" || { result mail "FAILED (no main.cf)"; return 0; }
    RESTORE="${RESTORE:+$RESTORE; }cp -p '$OUT/main.cf.before' /etc/postfix/main.cf; postfix reload"
    postconf -e 'defer_transports = smtp, relay, lmtp, local, virtual' && postfix reload > /dev/null 2>&1
    python3 -I scripts/live_mail.py "$EFA_LIVE_DOMAIN" "$RUN" > "$OUT/mail.log" 2>&1
    code=$?
    restore
    cat "$OUT/mail.log" | tee -a "$SUMMARY"
    cmp -s "$OUT/main.cf.before" /etc/postfix/main.cf || { result mail "FAILED (main.cf not as before)"; return 0; }
    [ $code -eq 0 ] && result mail ok || result mail FAILED
}

step_pages() {
    # The page times with more rounds than ci.sh, the Security page among them (budget 100 ms median).
    sudo -u efa-web python3 -I - --rounds 20 --budget-ms 100 < scripts/page_times.py > "$OUT/page-times.txt" 2>&1
    code=$?
    grep -v WARNING "$OUT/page-times.txt" | tail -40 >> "$SUMMARY"
    [ $code -eq 0 ] && result pages "ok (every page within 100 ms median)" || result pages FAILED
}

step_cve() {
    # 9o: one run of the CVE watch, with its time and its most memory.
    if ! efactl cve-watch-status 2>/dev/null | grep -q '"mode": "on"'; then
        result cve "SKIPPED (CVE watch off on this host)"
        return 0
    fi
    /usr/bin/time -v efactl cve-watch-run > "$OUT/cve.log" 2>&1
    code=$?
    rss=$(awk -F: '/Maximum resident set size/ {gsub(/ /, "", $2); print int($2 / 1024)}' "$OUT/cve.log")
    took=$(awk -F': ' '/Elapsed \(wall clock\)/ {print $2}' "$OUT/cve.log")
    [ $code -eq 0 ] && result cve "ok (${rss} MB at most, $took)" || result cve FAILED
}

step_pgp() {
    # 15: S/MIME and PGP with the real openssl and gpg of the host, keys only in a temporary folder.
    python3 -B /usr/lib/eFa/python/efa_crypto.py --self-test > "$OUT/pgp.log" 2>&1
    tail -1 "$OUT/pgp.log" | grep -q 'self-test ok' && result pgp "ok (sign, encrypt, decrypt; S/MIME and PGP)" || result pgp FAILED
}

step_n5() {
    # N5 is not built: the RAM a FastText model costs rspamd, measured once and taken out again.
    if [ -z "${EFA_LIVE_FASTTEXT_MODEL:-}" ] || [ ! -r "$EFA_LIVE_FASTTEXT_MODEL" ]; then
        # Not fetched here: deps only from repositories, and the model is in none (EL9, EPEL). The admin decides and brings it.
        result n5 "SKIPPED (no model: EFA_LIVE_FASTTEXT_MODEL=<path of lid.176.ftz>, the compressed FastText language model of Meta (CC BY-SA 3.0), from dl.fbaipublicfiles.com/fasttext/supervised-models/; no checksum is published there: note the SHA256 of the file you measure with)"
        return 0
    fi
    rss() { ps -C rspamd -o rss= | awk '{ s += $1 } END { print int(s / 1024) }'; }
    before=$(rss)
    file=/etc/rspamd/local.d/efa-live-n5.inc
    options=/etc/rspamd/local.d/options.inc
    if [ -e "$options" ]; then
        cp -p "$options" "$OUT/options.inc.before"; undo="cp -p '$OUT/options.inc.before' '$options'"
    else
        undo="rm -f '$options'"
    fi
    RESTORE="${RESTORE:+$RESTORE; }rm -f '$file'; $undo; systemctl restart rspamd"
    printf 'languages_fasttext_model = "%s";\n' "$EFA_LIVE_FASTTEXT_MODEL" > "$file"
    printf '.include(try=true) "$LOCAL_CONFDIR/local.d/efa-live-n5.inc"\n' >> "$options"
    systemctl restart rspamd && sleep 20
    after=$(rss)
    restore
    systemctl is-active -q rspamd || { result n5 "FAILED (rspamd not back after the measure)"; return 0; }
    result n5 "ok (rspamd ${before} MB without, ${after} MB with the model, taken out again)"
}

for name in $STEPS; do
    echo "== $name"
    "step_$name"
done
restore
echo
echo "live tests: logs and screenshots in $OUT"
cat "$SUMMARY" | grep -E '^[a-z0-9]+: ' | grep -vE '^(ui|mail) [a-z]'
grep -qE '^[a-z0-9]+: FAILED' "$SUMMARY" && exit 1
exit 0
