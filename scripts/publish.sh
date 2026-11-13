#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# Builds, signs and publishes eFa-next to https://repo.efa-next.eu (9k). Runs on the signing PC in Git Bash:
#   sh scripts/publish.sh test      -> el9-test/<tag>/, not used by any install
#   sh scripts/publish.sh release   -> el9/<tag>/ and el9/latest/, what installs and updates take
# The private key stays on this PC: the build host only gets signatures (scripts/publish/gpg-relay). gpg asks the passphrase in
# its own window. The build host uploads with rsync over SSH, key only.
# EFA_BUILD_HOST (user@host of the build host) and EFA_REPO_SSH (login@host of the repo webspace) must be set, and on the build
# host the SSH port, key and known hosts of the webspace (EFA_REPO_PORT, EFA_REPO_KEY, EFA_REPO_KNOWN). They can also come from a
# local file that is not in the repository, ~/.efa-publish.conf, for example:
#   EFA_BUILD_HOST=ci@build.example.com
#   EFA_REPO_SSH=login@repo.example.com
#   EFA_REPO_PORT=2222
#   EFA_REPO_KEY=/root/.ssh/repo_upload_key
#   EFA_REPO_KNOWN=/root/.ssh/known_hosts_repo
set -eu
[ -r "$HOME/.efa-publish.conf" ] && . "$HOME/.efa-publish.conf"
MODE=${1:-test}
case "$MODE" in test) DEST=el9-test ;; release) DEST=el9 ;; dryrun) DEST=el9-dryrun ;; *) echo "usage: sh scripts/publish.sh test|release"; exit 2 ;; esac
# dryrun (only to test this script): a throwaway key from EFA_SIGN_FPR, GNUPGHOME and EFA_SIGN_KEY on the build host.
FPR=${EFA_SIGN_FPR:-1823D6D3BB7D5AEA286E836DCFE7E07916CC8046}
# The build host and the SSH login of the repo webspace come from the environment; no default, so nothing goes to a wrong host.
BUILD=${EFA_BUILD_HOST:?set EFA_BUILD_HOST, for example efa-ci@build.example.com}
BUILD_KNOWN=${EFA_BUILD_KNOWN:-$HOME/.ssh/known_hosts_efa_build}
REPO_SSH=${EFA_REPO_SSH:?set EFA_REPO_SSH, the SSH login of the repo webspace}
REPO_PORT=${EFA_REPO_PORT:?set EFA_REPO_PORT, the SSH port of the repo webspace}
REPO_KEY=${EFA_REPO_KEY:?set EFA_REPO_KEY, the upload key on the build host}
REPO_KNOWN=${EFA_REPO_KNOWN:?set EFA_REPO_KNOWN, the known hosts file of the webspace on the build host}
REPO_ROOT='domains/repo.efa-next.eu/public_html'
W=/root/efa-publish
export GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg-efa-repo}"
KEY=${EFA_SIGN_KEY:-$W/src/next/usr/share/eFa/RPM-GPG-KEY-efa-next}
HERE=$(cd "$(dirname "$0")/.." && pwd)
LOCAL=$(mktemp -d)
B() { ssh -i "$HOME/.ssh/efa_test_vm_ed25519" -o BatchMode=yes -o LogLevel=ERROR -o UserKnownHostsFile="$BUILD_KNOWN" "$BUILD" "$@"; }
sign() { gpg --yes -u "$FPR" "$@"; }  # the window of gpg asks the passphrase once, the agent keeps it for 10 minutes

echo "== build on $BUILD"
git -C "$HERE" archive HEAD | B "sudo sh -c 'rm -rf $W/src $W/out $W/spool $W/sign.done $W/sign.log && mkdir -p $W/src $W/spool && chmod 700 $W $W/spool && tar -x -C $W/src && \
    install -m 0700 $W/src/scripts/publish/gpg-relay $W/gpg-relay && python3 -I $W/src/build/build-rpms.py --next-dir $W/src/next --out $W/out >$W/build.log 2>&1 || { tail -20 $W/build.log; exit 1; }'"
TAG=v$(B "sudo sh -c 'rpm -qp --qf %{VERSION}-%{RELEASE} $W/out/eFa-next-base-*.rpm'")
case "$TAG" in v[0-9]*) ;; *) echo "no version from the build: $TAG"; exit 1 ;; esac
[ "$MODE" != release ] && TAG="$TAG-test$(date -u +%Y%m%d%H%M)"
echo "tag $TAG"

echo "== rpmsign through the relay"
B "sudo sh -c 'nohup sh $W/src/scripts/publish/sign-rpms.sh $W $FPR >/dev/null 2>&1 &'"
while :; do
    for id in $(B "sudo sh -c 'cd $W/spool && for f in *.data; do [ -e \"\$f\" ] && [ ! -e \"\${f%.data}.sig\" ] && echo \${f%.data}; done; true'"); do
        B "sudo cat $W/spool/$id.data" > "$LOCAL/$id.data"
        sign --detach-sign --no-armor -o "$LOCAL/$id.sig" "$LOCAL/$id.data"
        B "sudo sh -c 'cat > $W/spool/$id.sig.tmp && mv $W/spool/$id.sig.tmp $W/spool/$id.sig'" < "$LOCAL/$id.sig"
    done
    [ -n "$(B "sudo cat $W/sign.done 2>/dev/null")" ] && break
    sleep 1
done
[ "$(B "sudo cat $W/sign.done")" = 0 ] || { B "sudo cat $W/sign.log"; exit 1; }
# rpm checks the signature against the pinned key alone, in a database of its own.
B "sudo sh -c 'rm -rf $W/rpmdb && mkdir $W/rpmdb && rpm --dbpath $W/rpmdb --import $KEY && \
    rpm --dbpath $W/rpmdb -K $W/out/*.rpm'" | tee "$LOCAL/rpmk.txt"
grep -qv 'digests signatures OK' "$LOCAL/rpmk.txt" && { echo "rpm -K: not all packages signed"; exit 1; }

echo "== SHA256SUMS and the repository"
B "sudo sh -c 'cd $W/out && sha256sum eFa*.rpm > SHA256SUMS && cp $KEY RPM-GPG-KEY-efa-next'"
B "sudo cat $W/out/SHA256SUMS" > "$LOCAL/SHA256SUMS"
sign --detach-sign --armor -o "$LOCAL/SHA256SUMS.asc" "$LOCAL/SHA256SUMS"
B "sudo sh -c 'cat > $W/out/SHA256SUMS.asc'" < "$LOCAL/SHA256SUMS.asc"
RS="ssh -p $REPO_PORT -i $REPO_KEY -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$REPO_KNOWN -o PubkeyAcceptedAlgorithms=rsa-sha2-512"
# The repository as it is online, the new release added, the index made new: older releases stay listed.
B "sudo sh -c 'mkdir -p $W/repo/$DEST && rsync -a -e \"$RS\" $REPO_SSH:$REPO_ROOT/$DEST/ $W/repo/$DEST/ 2>/dev/null; \
    mkdir -p $W/repo/$DEST/$TAG && cp $W/out/eFa*.rpm $W/out/SHA256SUMS $W/out/SHA256SUMS.asc $W/out/RPM-GPG-KEY-efa-next $W/repo/$DEST/$TAG/ && \
    createrepo_c -q --update $W/repo/$DEST && rm -f $W/repo/$DEST/repodata/repomd.xml.asc'"
B "sudo cat $W/repo/$DEST/repodata/repomd.xml" > "$LOCAL/repomd.xml"
sign --detach-sign --armor -o "$LOCAL/repomd.xml.asc" "$LOCAL/repomd.xml"
B "sudo sh -c 'cat > $W/repo/$DEST/repodata/repomd.xml.asc'" < "$LOCAL/repomd.xml.asc"
if [ "$MODE" = release ]; then
    # prerelease false: a host with a pre-release (6.0.0.6-alpha2) takes the release of the same numbers only from an answer that
    # says so (efactl _update_available); without the flag the release is not offered to it.
    printf '{"tag_name": "%s", "name": "eFa-next %s", "published_at": "%s", "prerelease": false, "body": ""}\n' "$TAG" "${TAG#v}" "$(date -u +%FT%TZ)" > "$LOCAL/latest.json"
    B "sudo sh -c 'rm -rf $W/repo/$DEST/latest && cp -a $W/repo/$DEST/$TAG $W/repo/$DEST/latest && cat > $W/repo/$DEST/latest.json'" < "$LOCAL/latest.json"
fi

echo "== upload"
# Packages first, the signed index after them, latest last: a client never sees an index without its packages.
B "sudo sh -c 'cd $W/repo && rsync -a --chmod=D755,F644 -e \"$RS\" --exclude repodata --exclude latest --exclude latest.json $DEST $REPO_SSH:$REPO_ROOT/ && \
    rsync -a --chmod=D755,F644 -e \"$RS\" $DEST/repodata $REPO_SSH:$REPO_ROOT/$DEST/ && \
    { [ ! -d $DEST/latest ] || rsync -a --chmod=D755,F644 -e \"$RS\" $DEST/latest $DEST/latest.json $REPO_SSH:$REPO_ROOT/$DEST/; }'"

echo "== check over HTTPS"
U="https://repo.efa-next.eu/$DEST"
for f in "$TAG/SHA256SUMS" "repodata/repomd.xml"; do
    curl -fsS -o "$LOCAL/check" "$U/$f" && curl -fsS -o "$LOCAL/check.asc" "$U/$f.asc"
    gpg --status-fd 1 --verify "$LOCAL/check.asc" "$LOCAL/check" 2>/dev/null | grep -q "VALIDSIG .* $FPR\$" || { echo "$f: signature NOT valid online"; exit 1; }
    echo "$f: signed by $FPR"
done
if [ "$MODE" = release ]; then
    # The signed security advisories of this release for the CVE watch of every host (9o); one file for EL9 and EL10. The data
    # goes first, its signature after it: a host takes the file only with a valid signature and keeps its last good copy.
    echo "== advisories"
    git -C "$HERE" show HEAD:advisories/advisories.json > "$LOCAL/advisories.json"
    python -I -c 'import json, re, sys; a = json.load(open(sys.argv[1], encoding="utf-8"))["advisories"]; assert isinstance(a, list); assert all(e["id"] and len(e["fixed"]) == 3 and re.fullmatch(r"[0-9]+", e["fixed"][2]) for e in a); print(len(a), "advisories")' \
        "$(cygpath -w "$LOCAL/advisories.json" 2>/dev/null || echo "$LOCAL/advisories.json")"
    sign --detach-sign --no-armor -o "$LOCAL/advisories.json.sig" "$LOCAL/advisories.json"
    B "sudo sh -c 'mkdir -p $W/repo/advisories && cat > $W/repo/advisories/advisories.json'" < "$LOCAL/advisories.json"
    B "sudo sh -c 'cat > $W/repo/advisories/advisories.json.sig'" < "$LOCAL/advisories.json.sig"
    B "sudo sh -c 'cd $W/repo/advisories && rsync -a --chmod=F644 -e \"$RS\" advisories.json $REPO_SSH:$REPO_ROOT/advisories/ && \
        rsync -a --chmod=F644 -e \"$RS\" advisories.json.sig $REPO_SSH:$REPO_ROOT/advisories/'"
    curl -fsS -o "$LOCAL/check" https://repo.efa-next.eu/advisories/advisories.json
    curl -fsS -o "$LOCAL/check.sig" https://repo.efa-next.eu/advisories/advisories.json.sig
    gpg --status-fd 1 --verify "$LOCAL/check.sig" "$LOCAL/check" 2>/dev/null | grep -q "VALIDSIG .* $FPR\$" || { echo "advisories: signature NOT valid online"; exit 1; }
    cmp -s "$LOCAL/check" "$LOCAL/advisories.json" || { echo "advisories online differ from this release"; exit 1; }
    echo "advisories: signed by $FPR"
fi
rm -rf "$LOCAL"
echo "published $TAG to $U"
