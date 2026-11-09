#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
#
# eFa-next installer for a fresh EL9 host (AlmaLinux, Rocky Linux, RHEL 9).
#
#   build.bash [ACTION] [RPM_DIR | BRANCH]
#
# ACTION   production (default): install the latest release.
#          kickstart: as production, then apply the settings of an
#          unattended install from $EFA_KICKSTART_CONFIG (default
#          /root/eFa-kickstart.conf, KEY:value lines as for efa-apply)
#          at the next boot, and arrange that reboot.
#          source: a test installation from the source in one call: the build
#          tools, the packages built from the clone this script is in
#          (or from $EFA_GIT_URL into /root/efa-next-src), installed.
#          Not for production: the packages carry no signature.
# RPM_DIR  production, kickstart: optional local folder with the two
#          RPMs and SHA256SUMS, used instead of the download.
# BRANCH   source: optional branch to check out first.
#
# Run as root. Every step logs to /var/log/eFa/eFa-install.log; the
# installer stops at the first failed step.

set -u
set -o pipefail
umask 022

ACTION="${1:-production}"
RPM_DIR="${2:-}"
# 9k: the own signed repository first, the GitHub releases as a mirror; both only with SHA256SUMS signed by this key.
REPO_URL="https://repo.efa-next.eu/el9/latest"
RELEASE_URL="https://github.com/MarkusLorber/eFa-next/releases/latest/download"
KEY_URLS="https://repo.efa-next.eu/RPM-GPG-KEY-efa-next $RELEASE_URL/RPM-GPG-KEY-efa-next"
KEY_FPR="1823D6D3BB7D5AEA286E836DCFE7E07916CC8046"
# The keys of the repositories eFa-next needs, checked before rpm imports them. Each fingerprint as two sources gave it on
# 2026-11-08: rspamd from rspamd.com/rpm/gpg.key, keys.openpgp.org and keyserver.ubuntu.com; EPEL 9 from
# dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-9 and fedoraproject.org/security.
RSPAMD_KEY_FPR="3FA347D5E599BE4595CA2576FFA232EDBF21E25E"
EPEL_KEY_URL="https://dl.fedoraproject.org/pub/epel/RPM-GPG-KEY-EPEL-9"
EPEL_KEY_FPR="FF8AD1344597106ECE813B918A3872BF3228467C"
RSPAMD_REPO_URL="https://rspamd.com/rpm-stable/centos-9/rspamd.repo"
RSPAMD_KEY_URL="https://rspamd.com/rpm/gpg.key"
KICKSTART_CONFIG="${EFA_KICKSTART_CONFIG:-/root/eFa-kickstart.conf}"
KICKSTART_TARGET="/var/lib/eFa/setup/kickstart.conf"
LOG_DIR="/var/log/eFa"
LOG_FILE="$LOG_DIR/eFa-install.log"
WORK_DIR=""

STATUS_FILE=/run/efa-install.status

# The shell that started the unit efa-install: its progress until it ends, then its result. Ctrl-C ends only the display.
follow_install() {
    echo "eFa-next installs as the systemd unit efa-install: a lost connection does not stop it."
    echo "Follow it again with: journalctl -fu efa-install"
    journalctl -fu efa-install -n 200 -o cat &
    local follower=$!
    trap 'kill $follower 2>/dev/null; echo; echo "display stopped, the install goes on: journalctl -fu efa-install"; exit 0' INT TERM HUP
    # Only a final state ends the wait: the update of the system re-executes systemd, which then gives no answer for a moment.
    while :; do
        case "$(systemctl is-active efa-install 2>/dev/null)" in
            inactive|failed) break ;;
        esac
        sleep 2
    done
    sleep 1
    kill "$follower" 2>/dev/null
    [ "$(cat "$STATUS_FILE" 2>/dev/null)" = OK ] && exit 0
    echo "eFa-next install did not finish, see $LOG_FILE" >&2
    exit 1
}

die() {
    echo FAILED > "$STATUS_FILE" 2>/dev/null
    echo "eFa-next install FAILED: $*" >&2
    # The end of the step's output, the rest stays in the log (rpmbuild alone writes thousands of lines).
    [ -r "$LOG_FILE" ] && grep -v '^+ ' "$LOG_FILE" | tail -8 | sed 's/^/    /' >&2
    [ -w "$LOG_FILE" ] && echo "$(date '+%F %T') FAILED: $*" >>"$LOG_FILE"
    echo "Details: $LOG_FILE" >&2
    exit 1
}

# step "description" command [args...]: run one step, stop on failure.
step() {
    local what="$1"
    shift
    echo "==> $what"
    echo "$(date '+%F %T') step: $what" >>"$LOG_FILE"
    "$@" >>"$LOG_FILE" 2>&1 || die "$what"
}

cleanup() {
    [ -n "$WORK_DIR" ] && rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# The tools this script itself uses, from the signed repositories of the distribution; a minimal install lacks some of them.
# chrony: a wrong clock makes every TLS download fail.
PREFLIGHT_TOOLS="curl gnupg2 ca-certificates dnf-plugins-core libselinux-utils policycoreutils tar chrony"
[ "$ACTION" = source ] && PREFLIGHT_TOOLS="$PREFLIGHT_TOOLS git-core"

preflight() {
    local missing="" tool
    for tool in $PREFLIGHT_TOOLS; do
        rpm -q "$tool" >/dev/null 2>&1 || missing="$missing $tool"
    done
    if [ -n "$missing" ]; then
        echo "missing, installed now:$missing"
        dnf -y install $missing || return 1
    fi
    systemctl enable --now chronyd >/dev/null 2>&1 || true
    # The clock set now, not slewed for hours: TLS downloads and the 2FA codes of the setup wizard need it. A new VM is
    # often minutes off; measure at once (burst), wait for a source, step, then up to 30 s for the sync.
    echo "clock before: $(chronyc -c tracking 2>/dev/null | cut -d, -f5) s off"
    chronyc -a burst 4/4 >/dev/null 2>&1
    chronyc waitsync 10 0 0 2 >/dev/null 2>&1
    chronyc -a makestep >/dev/null 2>&1
    if chronyc waitsync 15 1 0 2 >/dev/null 2>&1; then
        echo "clock after: $(chronyc -c tracking 2>/dev/null | cut -d, -f5) s off, synchronized"
    else
        echo "WARNING: the clock is not synchronized (chronyc tracking): check UDP port 123 and DNS; 2FA codes fail if it is off"
    fi
    getent hosts rspamd.com >/dev/null || { echo "no DNS: rspamd.com does not resolve, check /etc/resolv.conf"; return 1; }
}

check_os() {
    [ -r /etc/os-release ] || { echo "no /etc/os-release"; return 1; }
    . /etc/os-release
    case "${ID:-}" in
        almalinux|rocky|rhel|centos) ;;
        *) echo "unsupported OS: ${ID:-unknown}"; return 1 ;;
    esac
    [ "${VERSION_ID%%.*}" = "9" ] || { echo "unsupported version: ${VERSION_ID:-}"; return 1; }
    if ! command -v getenforce >/dev/null 2>&1 || [ "$(getenforce)" = "Disabled" ]; then
        echo "SELinux is disabled; enable it (enforcing) before installing eFa-next"
        return 1
    fi
}

# import_key URL FINGERPRINT: the key only when it is exactly the one with this fingerprint (one primary key), else nothing.
import_key() {
    local file got
    file="$(mktemp /tmp/efa-key.XXXXXX)" || return 1
    curl -fsSL -o "$file" "$1" || { rm -f "$file"; return 1; }
    got="$(gpg --batch --with-colons --show-keys "$file" 2>/dev/null | awk -F: '$1 == "pub" {pub++} $1 == "fpr" && !seen {print $10; seen = 1} END {if (pub != 1) print "more than one key"}')"
    if [ "$got" != "$2" ]; then
        echo "the key from $1 is not the expected one: $got instead of $2"
        rm -f "$file"
        return 1
    fi
    rpm --import "$file"
    local result=$?
    rm -f "$file"
    return $result
}

enable_repos() {
    . /etc/os-release
    if [ "$ID" = "rhel" ]; then
        # The EPEL release package from a URL: its signature counts only with the checked EPEL key (dnf does not check
        # the signature of a package given by URL unless told to).
        import_key "$EPEL_KEY_URL" "$EPEL_KEY_FPR" || return 1
        dnf -y --setopt=localpkg_gpgcheck=1 install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm" || return 1
        subscription-manager repos --enable "codeready-builder-for-rhel-9-$(arch)-rpms" || return 1
    else
        # epel-release comes from the repositories of the distribution, signed with its key.
        dnf -y install epel-release dnf-plugins-core || return 1
        dnf config-manager --set-enabled crb || return 1
    fi
    import_key "$RSPAMD_KEY_URL" "$RSPAMD_KEY_FPR" || return 1
    curl -fsSL -o /etc/yum.repos.d/rspamd.repo "$RSPAMD_REPO_URL" || return 1
    # The file of rspamd.com names http: packages and key only over https (dnf -y would take a new key unasked).
    sed -i 's#http://rspamd\.com/#https://rspamd.com/#g' /etc/yum.repos.d/rspamd.repo || return 1
    ! grep -q 'http://' /etc/yum.repos.d/rspamd.repo || { echo "rspamd.repo names a plain http address"; return 1; }
    # A new major version of rspamd only with an eFa-next release tested with it: a plain dnf update stays on 4.x.
    grep -q '^exclude=' /etc/yum.repos.d/rspamd.repo || echo 'exclude=rspamd-[5-9]* rspamd-[1-9][0-9]*' >> /etc/yum.repos.d/rspamd.repo
}

NGINX_STREAM=1.26
NGINX_MIN=1.25.1

# 1.26 by name; only where it does not exist the newest stream the list shows (a minimal install lists none of them as found).
enable_nginx_stream() {
    local stream="$NGINX_STREAM"
    dnf -y module reset nginx || return 1
    if ! dnf -y module enable "nginx:$stream"; then
        stream="$(dnf module list nginx 2>/dev/null |
                  awk '$1 == "nginx" && $2 ~ /^[0-9][0-9.]*$/ {print $2}' |
                  sort -t. -k1,1n -k2,2n | tail -n 1)"
        [ -n "$stream" ] || { echo "no nginx module stream; the default nginx is older than $NGINX_MIN"; return 1; }
        dnf -y module enable "nginx:$stream" || return 1
    fi
    echo "nginx stream: $stream"
    # An nginx already there (1.20 of AppStream, from an earlier attempt) moves to the stream; enabling alone does not.
    if rpm -q nginx >/dev/null 2>&1; then
        dnf -y distro-sync 'nginx*' || return 1
    fi
}

# SHA256SUMS in $WORK_DIR count only with a valid signature of the key $KEY_FPR (VALIDSIG names the primary key last).
signed_sums() {
    local home url ok=1
    home="$(mktemp -d /tmp/efa-gpg.XXXXXX)" || return 1
    for url in $KEY_URLS; do
        curl -fsSL -o "$home/key.asc" "$url" && gpg --homedir "$home" --batch -q --import "$home/key.asc" 2>/dev/null && break
    done
    if gpg --homedir "$home" --batch --status-fd 1 --verify "$WORK_DIR/SHA256SUMS.asc" "$WORK_DIR/SHA256SUMS" 2>/dev/null |
            grep -Eq "^\[GNUPG:\] VALIDSIG .* $KEY_FPR\$"; then
        ok=0
    fi
    gpgconf --homedir "$home" --kill all 2>/dev/null
    rm -rf "$home"
    [ "$ok" -eq 0 ] || echo "SHA256SUMS not signed by the eFa-next key $KEY_FPR"
    return "$ok"
}

get_rpms() {
    WORK_DIR="$(mktemp -d /tmp/efa-install.XXXXXX)" || return 1
    if [ -n "$RPM_DIR" ]; then
        cp "$RPM_DIR"/SHA256SUMS "$RPM_DIR"/eFa*.noarch.rpm "$WORK_DIR"/ || return 1
        return 0
    fi
    local base name
    for base in "$REPO_URL" "$RELEASE_URL"; do
        rm -f "$WORK_DIR"/SHA256SUMS*
        curl -fsSL -o "$WORK_DIR/SHA256SUMS" "$base/SHA256SUMS" &&
            curl -fsSL -o "$WORK_DIR/SHA256SUMS.asc" "$base/SHA256SUMS.asc" && signed_sums || continue
        echo "release source: $base"
        for name in $(awk '{sub(/^\*/, "", $2); print $2}' "$WORK_DIR/SHA256SUMS" |
                      grep -E '^eFa-next(-base)?-[0-9][A-Za-z0-9._-]*\.noarch\.rpm$'); do
            curl -fsSL -o "$WORK_DIR/$name" "$base/$name" || return 1
        done
        return 0
    done
    echo "no signed release found at $REPO_URL or $RELEASE_URL"
    return 1
}

verify_rpms() {
    cd "$WORK_DIR" || return 1
    ls eFa-next-base-[0-9]*.noarch.rpm >/dev/null 2>&1 || { echo "eFa-next-base RPM missing"; return 1; }
    ls eFa-next-[0-9]*.noarch.rpm >/dev/null 2>&1 || { echo "eFa-next RPM missing"; return 1; }
    local rpm line
    : >checked.sums
    for rpm in eFa*.noarch.rpm; do
        line="$(awk -v f="$rpm" '{n = $2; sub(/^\*/, "", n)} n == f {print $1 "  " n; exit}' SHA256SUMS)"
        [ -n "$line" ] || { echo "no checksum for $rpm"; return 1; }
        echo "$line" >>checked.sums
    done
    sha256sum -c --strict checked.sums
}

# The nginx the install would take (or has), at least NGINX_MIN: the configuration of eFa-next uses "http2 on;".
check_nginx() {
    local version
    version="$(rpm -q --qf '%{VERSION}' nginx 2>/dev/null)" || version="$(dnf -q repoquery --latest-limit 1 --qf '%{version}' nginx 2>/dev/null | tail -n 1)"
    printf '%s\n%s\n' "$NGINX_MIN" "${version:-0}" | sort -t. -k1,1n -k2,2n -k3,3n -C && { echo "nginx $version"; return 0; }
    echo "nginx ${version:-not found} is older than $NGINX_MIN: enable the module stream: dnf module reset nginx && dnf module enable nginx:$NGINX_STREAM"
    return 1
}

# source: the pure build tools the build brought (BUILD_ONLY), minus all the installed eFa-next needs at runtime: a test
# installation from source ends as a released one, without Perl. builddep also brings runtime packages (postfix, rspamd ...): they stay.
BUILD_ONLY='^(rpm-build|redhat-rpm-config|.*-srpm-macros|.*-rpm-macros|python3-rpm-generators|debugedit|dwz|elfutils|gdb-minimal|patch|pkgconf.*|python3-jsonschema|python3-attrs|python3-pyrsistent|perl.*|annobin.*|make|m4)$'

remove_build_tools() {
    local added runtime removal
    # What the installed eFa-next needs at runtime stays, whatever brought it in.
    runtime="$(python3 -I "$SOURCE_DIR/build/sbom.py" --closure-installed | sort -u)" || { echo "WARNING: runtime packages unknown, build tools kept"; return 0; }
    [ -n "$runtime" ] || { echo "WARNING: runtime packages unknown, build tools kept"; return 0; }
    added="$(rpm -qa --qf '%{NAME}\n' | sort -u | comm -13 "$LOG_DIR/before-build-tools.txt" - | grep -E "$BUILD_ONLY")"
    removal="$(comm -23 <(printf '%s\n' "$added") <(printf '%s\n' "$runtime" eFa-next eFa-next-base git-core | sort -u) | grep -v '^$')"
    [ -n "$removal" ] || { echo "no build tools to remove"; return 0; }
    dnf -y mark install eFa-next eFa-next-base >/dev/null 2>&1
    # What a package that stays still needs stays too (mariadb-server-utils, a weak dependency outside the closure, needs Perl):
    # out of the removal, until the test passes.
    local keep cap _
    for _ in $(seq 30); do
        rpm -e --test $removal >"$LOG_DIR/remove-build-tools.txt" 2>&1 && break
        keep="$(sed -n 's/^[[:space:]]*\(.*\) is needed by (installed) .*/\1/p' "$LOG_DIR/remove-build-tools.txt" | sort -u |
            while read -r cap; do rpm -q --whatprovides "${cap%% *}" --qf '%{NAME}\n' 2>/dev/null; done | sort -u)"
        [ -n "$keep" ] || break
        removal="$(comm -23 <(printf '%s\n' $removal | sort -u) <(printf '%s\n' "$keep") | grep -v '^$')"
        [ -n "$removal" ] || { echo "no build tools to remove: the installed packages need them"; return 0; }
    done
    # rpm -e removes only what it is given and refuses when anything that stays needs one of them: test first, keep all on doubt.
    if ! rpm -e --test $removal >"$LOG_DIR/remove-build-tools.txt" 2>&1; then
        echo "WARNING: the build tools stay, something still needs them (see $LOG_DIR/remove-build-tools.txt)"
        return 0
    fi
    echo "build tools and their dependencies removed:" $removal
    rpm -e $removal || return 1
    rpm -q eFa-next eFa-next-base >/dev/null || { echo "eFa-next is gone after removing the build tools"; return 1; }
}

install_rpms() {
    # The same version again (a second run, a new build of a test branch) is a reinstall, else nothing would change.
    local built installed
    built="$(rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' "$WORK_DIR"/eFa-next-base-[0-9]*.noarch.rpm "$WORK_DIR"/eFa-next-[0-9]*.noarch.rpm | sort)"
    installed="$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' eFa-next eFa-next-base 2>/dev/null | sort)"
    if [ "$built" = "$installed" ]; then
        dnf -y reinstall "$WORK_DIR"/eFa-next-base-[0-9]*.noarch.rpm "$WORK_DIR"/eFa-next-[0-9]*.noarch.rpm || return 1
    else
        dnf -y install "$WORK_DIR"/eFa-next-base-[0-9]*.noarch.rpm "$WORK_DIR"/eFa-next-[0-9]*.noarch.rpm || return 1
    fi
    # The package scripts write the version file only if every step passed.
    [ -e /etc/eFa-Version ] || { echo "configuration steps failed (no /etc/eFa-Version)"; return 1; }
}

SOURCE_DIR=""

# source: the clone this script is in, else $EFA_GIT_URL cloned (or updated) into /root/efa-next-src; BRANCH checked out.
get_source() {
    local here
    here="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)"
    if [ -n "$here" ] && [ -d "$here/.git" ] && [ -f "$here/rpm/eFa.spec" ]; then
        SOURCE_DIR="$here"
    elif [ -n "${EFA_GIT_URL:-}" ]; then
        SOURCE_DIR=/root/efa-next-src
        if [ -d "$SOURCE_DIR/.git" ]; then
            git -C "$SOURCE_DIR" fetch --prune origin || return 1
        else
            git clone "$EFA_GIT_URL" "$SOURCE_DIR" || return 1
        fi
    else
        echo "not in a clone of eFa-next: set EFA_GIT_URL to the git address"
        return 1
    fi
    if [ -n "$RPM_DIR" ]; then
        git -C "$SOURCE_DIR" fetch origin "$RPM_DIR" && git -C "$SOURCE_DIR" checkout "$RPM_DIR" || return 1
    fi
    # A branch that has an upstream follows it; a changed tree stays as it is (the build takes what is there).
    if git -C "$SOURCE_DIR" rev-parse --abbrev-ref '@{u}' >/dev/null 2>&1 && [ -z "$(git -C "$SOURCE_DIR" status --porcelain)" ]; then
        git -C "$SOURCE_DIR" pull --ff-only || return 1
    fi
    echo "source: $SOURCE_DIR at $(git -C "$SOURCE_DIR" log --oneline -1)"
}

build_rpms() {
    WORK_DIR="$(mktemp -d /tmp/efa-install.XXXXXX)" || return 1
    python3 -I "$SOURCE_DIR/build/build-rpms.py" --next-dir "$SOURCE_DIR/next" --out "$WORK_DIR" || return 1
    ls "$WORK_DIR"
}

prepare_kickstart() {
    [ -f "$KICKSTART_CONFIG" ] || { echo "kickstart settings missing: $KICKSTART_CONFIG"; return 1; }
    install -D -m 0600 -o root -g root "$KICKSTART_CONFIG" "$KICKSTART_TARGET" || return 1
    rm -f "$KICKSTART_CONFIG"
    systemctl enable efa-kickstart.service
}

arrange_reboot() {
    if [ -d /run/systemd/system ] && ! systemd-detect-virt --chroot >/dev/null 2>&1; then
        shutdown -r +1 "eFa-next: reboot to apply the unattended settings"
    else
        echo "running in an installer chroot: the installer reboots the host"
    fi
}

main() {
    [ "$(id -u)" = "0" ] || { echo "run as root" >&2; exit 1; }
    case "$ACTION" in
        production|kickstart|source) ;;
        *) echo "unknown action: $ACTION (production, kickstart or source)" >&2; exit 1 ;;
    esac
    if [ "$ACTION" != source ] && [ -n "$RPM_DIR" ] && [ ! -d "$RPM_DIR" ]; then
        echo "not a folder: $RPM_DIR" >&2
        exit 1
    fi
    mkdir -p "$LOG_DIR" && chmod 0750 "$LOG_DIR" || exit 1
    # Started by hand: the install runs as the systemd unit efa-install, so a lost SSH connection does not stop it; this
    # shell only shows its progress. Not in the chroot of an installer (kickstart), there is no systemd to run it.
    if [ -z "${EFA_INSTALL_UNIT:-}" ] && [ -d /run/systemd/system ] && command -v systemd-run >/dev/null \
            && ! systemd-detect-virt --chroot -q 2>/dev/null; then
        systemctl is-active -q efa-install && follow_install
        rm -f "$STATUS_FILE"
        systemd-run --unit=efa-install --collect --quiet --setenv=EFA_INSTALL_UNIT=1 \
            ${EFA_GIT_URL:+--setenv=EFA_GIT_URL="$EFA_GIT_URL"} ${EFA_KICKSTART_CONFIG:+--setenv=EFA_KICKSTART_CONFIG="$EFA_KICKSTART_CONFIG"} \
            /bin/bash "$(readlink -f "$0")" "$ACTION" ${RPM_DIR:+"$RPM_DIR"} || { echo "could not start the unit efa-install" >&2; exit 1; }
        follow_install
    fi
    echo "$(date '+%F %T') eFa-next install, action $ACTION" >>"$LOG_FILE"

    step "install the tools of the installer" preflight
    step "check the operating system and SELinux" check_os
    step "enable the EPEL, CRB and rspamd repositories" enable_repos
    step "enable the newest nginx stream" enable_nginx_stream
    if [ "$ACTION" = source ]; then
        # What is there before the build tools: they and what builddep adds go again after the install (Perl among them).
        rpm -qa --qf '%{NAME}\n' | sort -u >"$LOG_DIR/before-build-tools.txt"
        step "install the build tools" dnf -y install git-core rpm-build dnf-plugins-core python3 python3-jsonschema
        step "get the source" get_source
        step "install the build dependencies" dnf -y builddep "$SOURCE_DIR/rpm/eFa-base.spec" "$SOURCE_DIR/rpm/eFa.spec"
        step "build the eFa packages from the source" build_rpms
    else
        step "get the eFa packages" get_rpms
    fi
    step "verify the eFa packages" verify_rpms
    # The update last before the install: packages such as firewalld or NetworkManager may restart their service.
    step "update the operating system" dnf -y upgrade --refresh
    step "check the nginx version" check_nginx
    step "install the eFa packages" install_rpms
    [ "$ACTION" = source ] && step "remove the build tools" remove_build_tools
    if [ "$ACTION" = "kickstart" ]; then
        step "store the unattended settings" prepare_kickstart
        step "arrange the reboot" arrange_reboot
    fi
    echo "eFa-next installed. Open the setup wizard in a web browser to finish:"
    echo "    https://$(hostname -I 2>/dev/null | awk '{print $1}')/    setup code: cat /run/efa-init/setup-code"
    echo OK > "$STATUS_FILE"
}

main
