# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Signatures of the eFa-next releases: a file counts only with a valid signature of the pinned repository key."""
import os
import shutil
import subprocess
import tempfile

# The repository signing key of eFa-next; installer, efa-migrate and the update check trust only this one.
FINGERPRINT = '1823D6D3BB7D5AEA286E836DCFE7E07916CC8046'
KEY_FILE = '/usr/share/eFa/RPM-GPG-KEY-efa-next'
REPO = 'https://repo.efa-next.eu/el9'
MIRROR = 'https://github.com/MarkusLorber/eFa-next/releases/download'


def verify(data, signature, key, fingerprint=FINGERPRINT):
    """True when signature (detached, bytes) is a valid signature over data (bytes) by the key with this fingerprint.
    The key (bytes, armored or binary) may come from anywhere: only the fingerprint decides."""
    home = tempfile.mkdtemp(prefix='efa-sign-')
    try:
        paths = {name: os.path.join(home, name) for name in ('key', 'data', 'sig')}
        for name, content in (('key', key), ('data', data), ('sig', signature)):
            with open(paths[name], 'wb') as f:
                f.write(content)
        gpg = ['gpg', '--homedir', home, '--batch', '--no-autostart', '--quiet']
        if subprocess.run(gpg + ['--import', paths['key']], capture_output=True).returncode != 0:
            return False
        done = subprocess.run(gpg + ['--status-fd', '1', '--verify', paths['sig'], paths['data']], capture_output=True, text=True)
        # VALIDSIG ends with the fingerprint of the primary key; a key under another fingerprint never matches.
        return done.returncode == 0 and any(line.startswith('[GNUPG:] VALIDSIG ') and line.split()[-1] == fingerprint
                                            for line in done.stdout.splitlines())
    finally:
        subprocess.run(['gpgconf', '--homedir', home, '--kill', 'all'], capture_output=True, check=False)
        shutil.rmtree(home, ignore_errors=True)


def self_test():
    home = tempfile.mkdtemp(prefix='efa-sign-test-')
    try:
        gpg = ['gpg', '--homedir', home, '--batch', '--quiet', '--pinentry-mode', 'loopback', '--passphrase', '']
        subprocess.run(gpg + ['--quick-generate-key', 'Test <t@example.org>', 'ed25519', 'sign', '1d'], check=True, capture_output=True)
        listing = subprocess.run(gpg + ['--with-colons', '--list-keys'], check=True, capture_output=True, text=True).stdout
        fpr = [line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')][0]
        key = subprocess.run(gpg + ['--armor', '--export', fpr], check=True, capture_output=True).stdout
        data = b'0123  eFa-1.rpm\n'
        sig = subprocess.run(gpg + ['--detach-sign', '--armor'], input=data, check=True, capture_output=True).stdout
        assert verify(data, sig, key, fpr), 'a valid signature counts'
        assert not verify(data + b'x', sig, key, fpr), 'changed data does not'
        assert not verify(data, sig, key, 'A' * 40), 'another fingerprint does not'
        assert not verify(data, b'garbage', key, fpr) and not verify(data, sig, b'garbage', fpr)
        assert len(FINGERPRINT) == 40 and REPO.startswith('https://')
    finally:
        subprocess.run(['gpgconf', '--homedir', home, '--kill', 'all'], capture_output=True, check=False)
        shutil.rmtree(home, ignore_errors=True)
    print('self-test ok')


if __name__ == '__main__':
    self_test()
