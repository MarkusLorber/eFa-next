#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
#
# eFa-next installer for a fresh EL9 host (AlmaLinux, Rocky Linux, RHEL 9).
#
#   build.bash [ACTION] [RPM_DIR]
#
# ACTION   production (default): install the latest release.
#          kickstart: as production, then apply the settings of an
#          unattended install from $EFA_KICKSTART_CONFIG (default
#          /root/eFa-kickstart.conf, KEY:value lines as for efa-apply)
#          at the next boot, and arrange that reboot.
# RPM_DIR  optional local folder with the two RPMs and SHA256SUMS,
#          used instead of the download.
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
RSPAMD_REPO_URL="https://rspamd.com/rpm-stable/centos-9/rspamd.repo"
RSPAMD_KEY_URL="https://rspamd.com/rpm/gpg.key"
KICKSTART_CONFIG="${EFA_KICKSTART_CONFIG:-/root/eFa-kickstart.conf}"
KICKSTART_TARGET="/var/lib/eFa/setup/kickstart.conf"
LOG_DIR="/var/log/eFa"
LOG_FILE="$LOG_DIR/eFa-install.log"
WORK_DIR=""

die() {
    echo "eFa install FAILED: $*" >&2
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

check_os() {
    [ -r /etc/os-release ] || { echo "no /etc/os-release"; return 1; }
    . /etc/os-release
    case "${ID:-}" in
        almalinux|rocky|rhel|centos) ;;
        *) echo "unsupported OS: ${ID:-unknown}"; return 1 ;;
    esac
    [ "${VERSION_ID%%.*}" = "9" ] || { echo "unsupported version: ${VERSION_ID:-}"; return 1; }
    if ! command -v getenforce >/dev/null 2>&1 || [ "$(getenforce)" = "Disabled" ]; then
        echo "SELinux is disabled; enable it (enforcing) before installing eFa"
        return 1
    fi
}

enable_repos() {
    . /etc/os-release
    if [ "$ID" = "rhel" ]; then
        dnf -y install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm" || return 1
        subscription-manager repos --enable "codeready-builder-for-rhel-9-$(arch)-rpms" || return 1
    else
        dnf -y install epel-release dnf-plugins-core || return 1
        dnf config-manager --set-enabled crb || return 1
    fi
    curl -fsSL -o /etc/yum.repos.d/rspamd.repo "$RSPAMD_REPO_URL" || return 1
    rpm --import "$RSPAMD_KEY_URL"
}

enable_nginx_stream() {
    local stream
    stream="$(dnf -q module list nginx 2>/dev/null |
              awk '$1 == "nginx" && $2 ~ /^[0-9][0-9.]*$/ {print $2}' |
              sort -t. -k1,1n -k2,2n | tail -n 1)"
    if [ -z "$stream" ]; then
        echo "no nginx module stream; using the default nginx package"
        return 0
    fi
    echo "nginx stream: $stream"
    dnf -y module reset nginx && dnf -y module enable "nginx:$stream"
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
                      grep -E '^eFa(-base)?-[0-9][A-Za-z0-9._-]*\.noarch\.rpm$'); do
            curl -fsSL -o "$WORK_DIR/$name" "$base/$name" || return 1
        done
        return 0
    done
    echo "no signed release found at $REPO_URL or $RELEASE_URL"
    return 1
}

verify_rpms() {
    cd "$WORK_DIR" || return 1
    ls eFa-base-[0-9]*.noarch.rpm >/dev/null 2>&1 || { echo "eFa-base RPM missing"; return 1; }
    ls eFa-[0-9]*.noarch.rpm >/dev/null 2>&1 || { echo "eFa RPM missing"; return 1; }
    local rpm line
    : >checked.sums
    for rpm in eFa*.noarch.rpm; do
        line="$(awk -v f="$rpm" '{n = $2; sub(/^\*/, "", n)} n == f {print $1 "  " n; exit}' SHA256SUMS)"
        [ -n "$line" ] || { echo "no checksum for $rpm"; return 1; }
        echo "$line" >>checked.sums
    done
    sha256sum -c --strict checked.sums
}

install_rpms() {
    dnf -y install "$WORK_DIR"/eFa-base-[0-9]*.noarch.rpm "$WORK_DIR"/eFa-[0-9]*.noarch.rpm || return 1
    # The package scripts write the version file only if every step passed.
    [ -e /etc/eFa-Version ] || { echo "configuration steps failed (no /etc/eFa-Version)"; return 1; }
}

prepare_kickstart() {
    [ -f "$KICKSTART_CONFIG" ] || { echo "kickstart settings missing: $KICKSTART_CONFIG"; return 1; }
    install -D -m 0600 -o root -g root "$KICKSTART_CONFIG" "$KICKSTART_TARGET" || return 1
    rm -f "$KICKSTART_CONFIG"
    systemctl enable efa-kickstart.service
}

arrange_reboot() {
    if [ -d /run/systemd/system ] && ! systemd-detect-virt --chroot >/dev/null 2>&1; then
        shutdown -r +1 "eFa: reboot to apply the unattended settings"
    else
        echo "running in an installer chroot: the installer reboots the host"
    fi
}

main() {
    [ "$(id -u)" = "0" ] || { echo "run as root" >&2; exit 1; }
    case "$ACTION" in
        production|kickstart) ;;
        *) echo "unknown action: $ACTION (production or kickstart)" >&2; exit 1 ;;
    esac
    if [ -n "$RPM_DIR" ] && [ ! -d "$RPM_DIR" ]; then
        echo "not a folder: $RPM_DIR" >&2
        exit 1
    fi
    mkdir -p "$LOG_DIR" && chmod 0750 "$LOG_DIR" || exit 1
    echo "$(date '+%F %T') eFa install, action $ACTION" >>"$LOG_FILE"

    step "check the operating system and SELinux" check_os
    step "enable the EPEL, CRB and rspamd repositories" enable_repos
    step "enable the newest nginx stream" enable_nginx_stream
    step "update the operating system" dnf -y upgrade --refresh
    step "get the eFa packages" get_rpms
    step "verify the eFa packages" verify_rpms
    step "install the eFa packages" install_rpms
    if [ "$ACTION" = "kickstart" ]; then
        step "store the unattended settings" prepare_kickstart
        step "arrange the reboot" arrange_reboot
    fi
    echo "eFa installed. Open the setup wizard in a web browser to finish."
}

main
