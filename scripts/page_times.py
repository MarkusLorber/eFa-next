#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Server time of every page of the web interface, on an installed host, as the main admin.

Runs the installed efa-web.py in this process (Flask test client, no network) with the real efactl, so it must run as the
user efa-web: sudo -u efa-web python3 -I scripts/page_times.py [--rounds 5] [--budget-ms 100]
With --portal USER the user portal instead, as the user efa-portal, logged in as USER (role user) with the password from
stdin: sudo -u efa-portal python3 -I scripts/page_times.py --portal a@example.org < password-file
With --check-standard every page in the standard view: a card there needs a control (form or button) unless it is a
warning card or a list of every day (efa-web WARNING_CARDS, DAILY_LISTS).
One round first fills the caches; then the median and the slowest of the rounds per page. With --budget-ms every page
whose median is over the budget fails the run (the slowest of a few rounds is mostly noise of the host).
"""
import importlib.util
import os
import secrets
import statistics
import sys
import time

WEB = '/usr/local/sbin/efa-web.py'


def option(name, default):
    return type(default)(sys.argv[sys.argv.index(name) + 1]) if name in sys.argv else default


def load_web():
    spec = importlib.util.spec_from_file_location('efa_web', WEB)
    web = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(web)
    return web


def measure_portal(web, rounds, user, password):
    """The pages of the portal a user of the role user reaches, through efa-portal-helper as in real use."""
    web.app.secret_key = secrets.token_bytes(32)
    client = web.app.test_client()
    https = {'base_url': 'https://localhost'}
    client.get('/portal/login', **https)
    with client.session_transaction(**https) as sess:
        csrf = sess.get('csrf') or 'x'
        sess['csrf'] = csrf
    answer = client.post('/portal/login', data={'csrf': csrf, 'username': user, 'password': password}, **https)
    if answer.status_code != 302 or '/portal/login' in answer.headers.get('Location', ''):
        raise SystemExit('portal login failed')
    times = {}
    for slug in ['index'] + list(web.PAGES):
        path = '/portal/' if slug == 'index' else f'/portal/p/{slug}'
        seen, status = [], None
        for number in range(rounds + 1):
            start = time.perf_counter()
            status = client.get(path, **https).status_code
            if number:
                seen.append((time.perf_counter() - start) * 1000)
            if status != 200:
                break
        if status == 200:
            times[slug] = (status, statistics.median(seen), max(seen))
    return times


def _render_all(web, view):
    web.app.secret_key = secrets.token_bytes(32)
    client = web.app.test_client()
    https = {'base_url': 'https://localhost'}
    sid = secrets.token_urlsafe(16)
    with client.session_transaction(**https) as sess:
        sess.update(admin=True, csrf='x', sid=sid, view=view, lang='en')
    web.active_sessions[sid] = time.time() + 3600
    pages = {}
    for slug in web.PAGES:
        web.session_checked[sid] = time.time()
        pages[slug] = client.get('/' if slug == 'dash' else f'/p/{slug}', **https).get_data(as_text=True)
    return pages


def check_standard(web):
    """Cards without a control belong to the expert view, and the view only hides: a card or tile seen in both views shows
    the same values in both. Returns what breaks it."""
    import re
    card = re.compile(r'<div class="card(?: warncard)?" id="([a-z0-9-]+)">(.*?)(?=<div class="card[ "]|</main>)', re.S)
    values = re.compile(r'(?:value|data-countdown)="[^"]*"|\bchecked\b|\bselected\b')
    standard, expert = _render_all(web, 'standard'), _render_all(web, 'expert')
    # The form token is per session, the hint to the expert view only in the standard view: neither is a value of a card.
    for pages in (standard, expert):
        for slug, html in pages.items():
            html = re.sub(r'<input type="hidden" name="csrf" value="[^"]*">', '', html)
            pages[slug] = re.sub(r'<p class="h expert-note">.*?</p>', '', html, flags=re.S)
    broken = []
    for slug, html in standard.items():
        cards_expert = dict(card.findall(expert[slug]))
        for name, body in card.findall(html):
            if '<form' not in body and '<button' not in body and 'warnbox' not in body and name not in web.WARNING_CARDS | web.DAILY_LISTS:
                broken.append(f'{slug}/{name}: no control')
            form = body[body.find('<form'):] if '<form' in body else ''
            other = cards_expert.get(name, '')
            other_form = other[other.find('<form'):] if '<form' in other else ''
            if form and sorted(values.findall(form)) != sorted(values.findall(other_form)):
                broken.append(f'{slug}/{name}: other values than in the expert view')
        tiles = re.findall(r'<div class="tiles">.*?</div>\s*</div>', html, re.S)
        if tiles != re.findall(r'<div class="tiles">.*?</div>\s*</div>', expert[slug], re.S):
            broken.append(f'{slug}: tiles differ from the expert view')
        if html.count('Unknown') > expert[slug].count('Unknown'):
            broken.append(f'{slug}: Unknown in the standard view')
    return broken


def measure(web, rounds):
    web.app.secret_key = secrets.token_bytes(32)
    client = web.app.test_client()
    https = {'base_url': 'https://localhost'}
    sid = secrets.token_urlsafe(16)
    with client.session_transaction(**https) as sess:
        sess.update(admin=True, csrf='x', sid=sid)
    web.active_sessions[sid] = time.time() + 3600
    web.session_checked[sid] = time.time()
    times = {}
    for slug in web.PAGES:
        path = '/' if slug == 'dash' else f'/p/{slug}'
        seen = []
        for number in range(rounds + 1):
            # The session of this run is not in the database: no check of it against efactl.
            web.session_checked[sid] = time.time()
            start = time.perf_counter()
            status = client.get(path, **https).status_code
            if number:
                seen.append((time.perf_counter() - start) * 1000)
        times[slug] = (status, statistics.median(seen), max(seen))
    return times


def main():
    rounds, budget = option('--rounds', 5), option('--budget-ms', 0)
    if '--check-standard' in sys.argv:
        broken = check_standard(load_web())
        print('standard view: problems: ' + (', '.join(broken) or 'none'))
        return 1 if broken else 0
    if '--portal' in sys.argv:
        os.environ['EFA_WEB_MODE'] = 'portal'
        times = measure_portal(load_web(), rounds, option('--portal', ''), sys.stdin.readline().strip())
    else:
        times = measure(load_web(), rounds)
    over = []
    print(f'{"page":<14} status  median ms  slowest ms')
    for slug, (status, median, slowest) in sorted(times.items(), key=lambda item: -item[1][2]):
        print(f'{slug:<14} {status:>6} {median:>10.0f} {slowest:>11.0f}')
        if status != 200 or (budget and median > budget):
            over.append(slug)
    print(f'pages: {len(times)}, median of all: {statistics.median(t[1] for t in times.values()):.0f} ms')
    if over:
        print('over budget or failed: ' + ', '.join(over))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
