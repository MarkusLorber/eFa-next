#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Detection rate and false alarms of eFa-next (Q10): sends each mail of a corpus to rspamd for a check only (checkv2: rspamd
learns nothing from it) and counts what the actions would do.

    detection_benchmark.py --spam DIR --ham DIR [--url http://127.0.0.1:11333] [--limit N] [--parallel N] [--markdown]
                           [--without SYMBOL,SYMBOL]

--without turns rules off for these checks only (the rspamd Settings header), such as DATE_IN_PAST for an old corpus, or the
Bayes symbols when the Bayes data of the test system are not trained on real mail.

DIR holds one mail per file, or mbox files, in any depth. Public corpora that fit, each under its own terms (download them
yourself, they are not in this repository): the SpamAssassin public corpus (spamassassin.apache.org/old/publiccorpus), the
TREC 2007 public spam corpus. Their mails are old: the result shows the rules and the classifier, not today's spam waves.
Run it on a test system, not in production: Bayes and the neural network do not learn from checkv2, but the scans count in the
rspamd statistics.
"""
import argparse
import json
import mailbox
import os
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

CAUGHT = ('reject', 'add header', 'rewrite subject', 'soft reject')
MAX_MAIL = 10 * 1024 * 1024


def mails(folder):
    """The raw mails below a folder: single files, and the messages of mbox files."""
    for root, dirs, files in os.walk(folder):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(root, name)
            with open(path, 'rb') as f:
                head = f.read(5)
            if head == b'From ':
                for message in mailbox.mbox(path):
                    yield message.as_bytes()
            elif os.path.getsize(path) <= MAX_MAIL:
                with open(path, 'rb') as f:
                    yield f.read()


def settings_header(symbols):
    """The rspamd Settings header that turns these rules off for one check."""
    return '{symbols_disabled = [' + ', '.join(f'"{name}"' for name in symbols) + ']}' if symbols else ''


def check(url, raw, timeout=60, without=()):
    headers = {'Content-Type': 'message/rfc822', 'Pass': 'all'}
    if without:
        headers['Settings'] = settings_header(without)
    request = urllib.request.Request(url.rstrip('/') + '/checkv2', data=raw, method='POST', headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as answer:
        result = json.load(answer)
    return result.get('action', 'no action'), float(result.get('score', 0.0))


def tally(results):
    """Counts per class and action, the detection rate of spam and the false alarm rate of ham."""
    out = {}
    for kind in ('spam', 'ham'):
        rows = [action for klass, action, _score in results if klass == kind]
        actions = {action: rows.count(action) for action in sorted(set(rows))}
        caught = sum(count for action, count in actions.items() if action in CAUGHT)
        out[kind] = {'mails': len(rows), 'actions': actions, 'caught': caught,
                     'rate': round(100.0 * caught / len(rows), 2) if rows else None}
    out['detection_rate_percent'] = out['spam']['rate']
    out['false_alarm_percent'] = out['ham']['rate']
    return out


def markdown(summary, seconds, url, without=()):
    lines = ['# Detection benchmark', '', f'rspamd at {url}, {seconds:.0f} s.' + (f" Rules off: {', '.join(without)}." if without else ''), '',
             '| | Mails | Caught (reject, add header, rewrite subject, soft reject) | Rate |', '| --- | --- | --- | --- |']
    for kind, label in (('spam', 'Spam (detection)'), ('ham', 'Ham (false alarms)')):
        item = summary[kind]
        lines.append(f"| {label} | {item['mails']} | {item['caught']} | {item['rate']} % |")
    lines += ['', 'Actions: ' + '; '.join(f"{kind}: {item}" for kind, item in ((k, summary[k]['actions']) for k in ('spam', 'ham')))]
    return '\n'.join(lines) + '\n'


def self_test():
    results = [('spam', 'reject', 20.0), ('spam', 'add header', 7.0), ('spam', 'no action', 1.0), ('spam', 'greylist', 4.5),
               ('ham', 'no action', -1.0), ('ham', 'add header', 6.5), ('ham', 'no action', 0.0), ('ham', 'no action', 2.0)]
    summary = tally(results)
    assert summary['spam']['caught'] == 2 and summary['detection_rate_percent'] == 50.0 and summary['false_alarm_percent'] == 25.0
    assert '| Spam (detection) | 4 | 2 | 50.0 % |' in markdown(summary, 1, 'x')
    import tempfile
    with tempfile.TemporaryDirectory() as folder:
        with open(os.path.join(folder, 'one.eml'), 'wb') as f:
            f.write(b'From: a@x.example\nSubject: one\n\nbody\n')
        with open(os.path.join(folder, 'box.mbox'), 'wb') as f:
            f.write(b'From a@x.example Thu Jan  1 00:00:00 2026\nSubject: two\n\nx\n\nFrom b@x.example Thu Jan  1 00:00:00 2026\nSubject: three\n\ny\n')
        assert len(list(mails(folder))) == 3
    assert tally([])['detection_rate_percent'] is None
    assert settings_header(['DATE_IN_PAST', 'BAYES_SPAM']) == '{symbols_disabled = ["DATE_IN_PAST", "BAYES_SPAM"]}' and settings_header([]) == ''
    print('self-test ok')


def main():
    if '--self-test' in sys.argv:
        self_test()
        return 0
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--spam', required=True)
    ap.add_argument('--ham', required=True)
    ap.add_argument('--url', default='http://127.0.0.1:11333')
    ap.add_argument('--limit', type=int, default=0, help='at most this many mails per class')
    ap.add_argument('--markdown', action='store_true')
    ap.add_argument('--parallel', type=int, default=1)
    ap.add_argument('--without', default='', help='rules to turn off for these checks, comma separated')
    args = ap.parse_args()
    without = [item.strip() for item in args.without.split(',') if item.strip()]
    start = time.monotonic()

    def one(job):
        kind, raw = job
        try:
            action, score = check(args.url, raw, without=without)
        except (OSError, ValueError) as err:
            print(f'skipped one {kind} mail: {err}', file=sys.stderr)
            return None
        return kind, action, score
    jobs = [(kind, raw) for kind, folder in (('spam', args.spam), ('ham', args.ham))
            for index, raw in enumerate(mails(folder)) if not args.limit or index < args.limit]
    with ThreadPoolExecutor(max_workers=max(1, args.parallel)) as pool:
        results = [item for item in pool.map(one, jobs) if item]
    summary = tally(results)
    print(markdown(summary, time.monotonic() - start, args.url, without) if args.markdown else json.dumps(summary, indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main())
