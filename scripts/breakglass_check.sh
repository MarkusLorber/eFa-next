#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# The break-glass admin on a real host (sshd, PAM, sudo), for CI on a disposable host only: never on a host in use. Makes a break-glass
# admin, checks it, reinstalls openssh-server, sudo and util-linux (OS packages stay updatable: Hans's rule), heals and checks
# again, then removes it and checks that PAM and SSH are as before. Needs pamtester (EPEL).
#   sh scripts/breakglass_check.sh          EFACTL=... picks another efactl (a source tree)
EFACTL=${EFACTL:-/usr/sbin/efactl}
PY=${PY:-/usr/lib/eFa/python}
B=$(mktemp -d /root/bg-check.XXXXXX)
cp -a /etc/pam.d "$B/pam.d"
cp -a /etc/ssh/sshd_config.d "$B/sshd_config.d"
FAILED=0
ok() { echo "OK   $*"; }
bad() { echo "FAIL $*"; FAILED=1; }
rpm -q pamtester >/dev/null || dnf -y -q install pamtester >/dev/null || { echo "pamtester missing"; exit 2; }
$EFACTL breakglass-status | grep -q '"user": ""' || { echo "a break-glass admin exists already: not on this host"; exit 2; }
$EFACTL breakglass-issue --confirm yes > /dev/null 2>"$B/err" || bad "issue: $(tail -2 "$B/err")"
U=$(PYTHONPATH=$PY python3 -c 'import efa_breakglass as b; print(b.read_state().get("user", ""))')
[ -n "$U" ] && ok "user $U" || { bad "no user"; exit 1; }
codes() { PYTHONPATH=$PY python3 -c "
import efa_breakglass as b
s = b.read_state(); s['networks'] = ['10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12']; codes, s = b.issue(s, s['user']); b.write_state(s); print(' '.join(codes))"; }
check() {
    set -- $(codes)
    printf '%s\n' "$1" | pamtester -I rhost=10.0.0.5 sshd "$U" authenticate >/dev/null 2>&1 && ok "$PHASE sshd: a code" || bad "$PHASE sshd code"
    printf '%s\n' "$1" | pamtester -I rhost=10.0.0.5 sshd "$U" authenticate >/dev/null 2>&1 && bad "$PHASE sshd: twice" || ok "$PHASE sshd: never twice"
    printf '%s\n' "$2" | pamtester sudo "$U" authenticate >/dev/null 2>&1 && ok "$PHASE sudo: a code" || bad "$PHASE sudo"
    printf '%s\n' "$3" | pamtester -I tty=tty1 login "$U" authenticate >/dev/null 2>&1 && ok "$PHASE console: a code" || bad "$PHASE console"
    printf 'x\n' | pamtester sudo nobody authenticate >/dev/null 2>&1 && bad "$PHASE nobody got in" || ok "$PHASE other users as before"
    sshd -T -C user=root,addr=10.0.0.5,host=x,laddr=127.0.0.1,lport=22 | grep -qi '^kbdinteractiveauthentication no' && ok "$PHASE root: no keyboard-interactive" || bad "$PHASE root kbd"
    for f in /etc/pam.d/system-auth /etc/pam.d/password-auth; do grep -q 'efa-breakglass' "$f" && bad "$PHASE lines in $f (authselect)"; done
}
PHASE=before check
dnf -y -q reinstall openssh-server sudo util-linux >/dev/null 2>&1 && ok "openssh-server, sudo, util-linux reinstalled" || bad "reinstall"
$EFACTL breakglass-heal > "$B/heal1" 2>&1 || bad "heal: $(tail -2 "$B/heal1")"
sums() { sha256sum /etc/pam.d/sshd /etc/pam.d/sudo /etc/pam.d/login /etc/ssh/sshd_config.d/45-efa-breakglass.conf /etc/sudoers.d/efa-breakglass; }
sums > "$B/s1"
$EFACTL breakglass-heal > "$B/heal2" 2>&1
grep -q '"healed": \[\]' "$B/heal2" && ok "a second heal changes nothing" || bad "second heal: $(cat "$B/heal2" | head -3)"
sums | cmp -s - "$B/s1" && ok "files byte-identical after the second heal" || bad "files changed by the second heal"
grep -q '"problems": \[\]' "$B/heal2" && ok "no problem left" || bad "problems: $(grep -A3 problems "$B/heal2")"
PHASE=after-reinstall check
$EFACTL breakglass-remove --confirm yes >/dev/null 2>&1 && ok "removed" || bad "remove"
getent passwd "$U" >/dev/null && bad "user still there" || ok "user gone"
diff -r "$B/pam.d" /etc/pam.d >/dev/null && ok "PAM as before" || { bad "PAM differs"; cp -a "$B/pam.d/." /etc/pam.d/; }
diff -r "$B/sshd_config.d" /etc/ssh/sshd_config.d >/dev/null && ok "sshd as before" || { bad "sshd differs"; cp -a "$B/sshd_config.d/." /etc/ssh/sshd_config.d/; rm -f /etc/ssh/sshd_config.d/45-efa-breakglass.conf; }
sshd -t && systemctl reload sshd
faillock --reset --user "$U" 2>/dev/null; faillock --dir /var/run/faillock-efa-bg-tty --reset --user "$U" 2>/dev/null
rm -rf "$B"
echo "FAILED=$FAILED"
exit $FAILED
