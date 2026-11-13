#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""6.0.0.6 on the installed host (ci.sh --install, step secrets-clean): the account ID of SecuriteInfo and the API key of a
threat feed never leave the host by the cluster or show up in a log. A made-up ID and key are set through the real code of
efactl (clam-source-set, feed-set, nothing is downloaded), then:
- the journal entries the master would hand to its nodes for both commands hold neither;
- the snapshot a new node gets holds neither (sane_without_secrets, the key files are outside /etc);
- a backup holds neither (sanesecurity.json without the ID, the URL lines of SecuriteInfo not at all);
- no log of eFa-next, Postfix or the system journal since the start of the test holds either.
Everything is put back afterwards."""
import argparse
import base64
import importlib.machinery
import importlib.util
import json
import os
import secrets
import subprocess
import sys
import tarfile
import time

EFACTL = '/usr/lib/eFa/python/efactl_main.py'
FEED = 'cicanary'
LOGS = ('/var/log/eFa', '/var/log/maillog', '/var/log/messages', '/var/log/secure')


def load():
    loader = importlib.machinery.SourceFileLoader('efactl_secrets', EFACTL)
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_secrets', loader))
    loader.exec_module(module)
    return module


def texts(path):
    """(name, text) of a log file or of every file below a log folder."""
    paths = [path] if os.path.isfile(path) else [os.path.join(root, name) for root, _dirs, names in os.walk(path) for name in names]
    for item in paths:
        if os.path.isfile(item) and not item.endswith(('.gz', '.xz', '.bz2')):
            with open(item, 'rb') as f:
                yield item, f.read().decode(errors='replace')


class Master:
    """The cluster side of cluster_snapshot: a master whose journal is empty."""
    @staticmethod
    def journal_read(base):
        return []


def main():
    if os.geteuid() != 0 or not os.path.exists(EFACTL):
        print('secrets-clean: needs root on a host with eFa-next installed')
        return 1
    m = load()
    site_id, feed_key = 'EFACISIID' + secrets.token_hex(12), 'efacifeedkey' + secrets.token_hex(12)
    canaries = {'SecuriteInfo ID': site_id, 'feed key': feed_key}
    key_file = f'{m.FEEDS_DIR}/{FEED}.key'
    kept = {}
    for path in (m.SANE_FILE, m.FEEDS_FILE, key_file):
        kept[path] = None
        if os.path.exists(path):
            with open(path, 'rb') as f:
                kept[path] = f.read()
    started = time.strftime('%Y-%m-%d %H:%M:%S')
    given = [site_id, feed_key]
    m._secrets = lambda count, prompt: (m.SECRETS_SEEN.extend(given[:count]), [given.pop(0) for _ in range(count)])[1]
    m.sanesecurity_update = lambda args: None  # nothing is downloaded with the made-up ID
    problems, backup = [], None
    try:
        si_args = argparse.Namespace(source='securiteinfo', mode='on', id=None, accept_terms='yes')
        m.clam_source_set(si_args)
        feed_args = argparse.Namespace(name=FEED, action='add', kind='stix', url='https://feed.invalid/taxii2/collections/ci/objects/',
                                       api_key=None, accept_terms='yes')
        m.feed_set(feed_args)
        assert os.path.exists(key_file) and site_id in open(m.SANE_FILE).read(), 'the made-up ID and key were not stored'
        # What the master hands to its nodes for these two commands.
        for command, args in (('clam-source-set', si_args), ('feed-set', feed_args)):
            text = json.dumps(m.cluster_entries(command, args, m.SECRETS_SEEN))
            problems += [f'journal entry of {command}: {what}' for what, value in canaries.items() if value in text]
        # The snapshot of a master for a new node, its files decoded.
        m._cluster_parts = lambda: (Master, '/nonexistent', {'role': 'master'})
        snapshot = m.cluster_snapshot(None)
        text = json.dumps(snapshot) + ''.join(base64.b64decode(item['data']).decode(errors='replace')
                                              for item in snapshot['files'] if item.get('data'))
        problems += [f'snapshot: {what}' for what, value in canaries.items() if value in text]
        # A backup: neither the feed key nor the ID, in no file.
        backup = os.path.join(m.BACKUP_DIR, m._backup_make(None, database=False, prefix='ci-secrets-')['backup'])
        with tarfile.open(backup) as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                data = tar.extractfile(member).read().decode(errors='replace')
                if feed_key in data:
                    problems.append(f'backup {member.name}: feed key')
                if site_id in data:
                    problems.append(f'backup {member.name}: SecuriteInfo ID')
        # The logs.
        for path in LOGS + (m.AUDIT_LOG,):
            if os.path.exists(path):
                for name, text in texts(path):
                    problems += [f'log {name}: {what}' for what, value in canaries.items() if value in text]
        journal = subprocess.run(['journalctl', '--since', started, '-o', 'cat', '--no-pager'], capture_output=True, text=True).stdout
        problems += [f'system journal: {what}' for what, value in canaries.items() if value in journal]
    finally:
        for path, data in kept.items():
            if data is None:
                if os.path.exists(path):
                    os.remove(path)
            else:
                with open(path, 'wb') as f:
                    f.write(data)
        if backup and os.path.exists(backup):
            os.remove(backup)
    for line in problems:
        print('secrets-clean:', line)
    print('secrets-clean:', 'FAILED' if problems else 'ok: no SecuriteInfo ID or feed key in journal entries, snapshot, backup or logs')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
