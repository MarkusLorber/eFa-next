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
warning card or a list of every day (efa-web WARNING_CARDS, DAILY_LISTS); a task card (task_card_problems) its own rules.
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
        reply = client.get('/' if slug == 'dash' else f'/p/{slug}', **https)
        if reply.status_code != 200:
            # A page that did not render (right after an update a read can break off) is not a difference of the views:
            # asked once more, named in the output, and a second failure counts on its own.
            print(f'STANDARD VIEW CHECK: {view} /{slug} did not render at {time.strftime("%Y-%m-%d %H:%M:%S")}: status {reply.status_code}, '
                  f'body {reply.get_data(as_text=True)[:500]!r}; asked again (a product fault: see the journal of efa-web and efactl-runner)')
            time.sleep(2)
            web.session_checked[sid] = time.time()
            reply = client.get('/' if slug == 'dash' else f'/p/{slug}', **https)
        RENDER_STATUS[(view, slug)] = reply.status_code
        pages[slug] = reply.get_data(as_text=True)
    return pages


RENDER_STATUS = {}


def form_fields(html):
    """(action, field name, value) of every form field: the value of a text or hidden field, a checked box or radio button,
    the chosen option, the text of a text area. The form token is left out (one per session)."""
    import re
    found = set()
    for head, action, body in re.findall(r'(<form\b[^>]*\baction="([^"]*)"[^>]*>)(.*?)</form>', html, re.S):
        if re.search(r'\bclass="[^"]*\btoggle\b', head):
            # A switch (efa-web toggle()): its hidden fields carry what a click would post (empty keeps a value), so it is
            # compared by the state it shows, as the switch in the head of the Expert card shows it.
            state = re.search(r'\baria-(?:pressed|checked)="(true|false)"', body)
            found.add((action, '@switch', state[1] if state else ''))
            continue
        for tag in re.findall(r'<input\b[^>]*>', body):
            name = re.search(r'\bname="([^"]*)"', tag)
            kind = (re.search(r'\btype="([^"]*)"', tag) or [None, 'text'])[1]
            if not name or name[1] == 'csrf' or kind in ('submit', 'button', 'file'):
                continue
            if kind in ('checkbox', 'radio') and not re.search(r'\bchecked\b', tag):
                continue
            found.add((action, name[1], (re.search(r'\bvalue="([^"]*)"', tag) or [None, ''])[1]))
        for name, options in re.findall(r'<select\b[^>]*\bname="([^"]*)"[^>]*>(.*?)</select>', body, re.S):
            chosen = re.search(r'<option\b[^>]*\bvalue="([^"]*)"[^>]*\bselected\b', options)
            found.add((action, name, chosen[1] if chosen else ''))
        for name, text in re.findall(r'<textarea\b[^>]*\bname="([^"]*)"[^>]*>(.*?)</textarea>', body, re.S):
            found.add((action, name, text))
    return found


def task_card_problems(slug, standard, expert):
    """6.0.0.6.6: a task card (class card task) exists only in the standard view and sums up full cards of Expert. It needs a
    control or a link to ?view=expert#anchor; every such anchor exists in Expert; every field it posts has the same value as
    the field of that name in a form of Expert that posts to the same address."""
    import re
    task = re.compile(r'<div class="card task" id="([a-z0-9-]+)">(.*?)(?=<div class="card[ "]|</main>)', re.S)
    in_expert = form_fields(expert)
    # Every address a form of Expert posts to, also a form whose only field is an unticked box (it gives no field).
    actions = set(re.findall(r'<form\b[^>]*\baction="([^"]*)"', expert))
    broken = []
    for name, body in task.findall(standard):
        anchors = re.findall(r'href="[^"#]*[?&](?:amp;)?view=expert#([A-Za-z0-9_-]+)"', body)
        if not anchors and not re.search(r'<form\b|<button\b|<input\b', body):
            broken.append(f'{slug}/{name}: task card without a control or a link to the expert view')
        for anchor in anchors:
            if f'id="{anchor}"' not in expert:
                broken.append(f'{slug}/{name}: link to #{anchor}, which the expert view lacks')
        for action, field, value in sorted(form_fields(body)):
            if action not in actions:
                broken.append(f'{slug}/{name}: posts to {action}, no form of the expert view does')
            elif field == '@switch' and any(a == action and f == '@switch' for a, f, _v in in_expert):
                # Expert has the same switch: only its state counts.
                if (action, field, value) not in in_expert:
                    broken.append(f"{slug}/{name}: switch {value}, the expert view shows it "
                                  f"{sorted(v for a, f, v in in_expert if a == action and f == '@switch')} ({action})")
            elif field == '@switch' and (action, 'mode', 'on' if value == 'true' else 'off') in in_expert:
                # Expert shows the same switch as the mode field of its form: on as mode=on, off as mode=off.
                continue
            elif field == '@switch' and value == 'false' and (action, 'mode', 'on') not in in_expert:
                # Off with an unticked box: the box posts nothing, so no mode=on in Expert is the same off.
                continue
            elif (action, field, value) not in in_expert:
                other = sorted(v for a, f, v in in_expert if a == action and f == field)
                broken.append(f'{slug}/{name}: {field}={value!r}, the expert view has {other or "no such field"} ({action})')
    return broken


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
    broken = [f'{slug}: status {code} in the {view} view' for (view, slug), code in sorted(RENDER_STATUS.items()) if code != 200]
    for slug, html in standard.items():
        if RENDER_STATUS.get(('standard', slug)) != 200 or RENDER_STATUS.get(('expert', slug)) != 200:
            continue
        cards_expert = dict(card.findall(expert[slug]))
        broken.extend(task_card_problems(slug, html, expert[slug]))
        for name, body in card.findall(html):
            if '<form' not in body and '<button' not in body and 'warnbox' not in body and name not in web.WARNING_CARDS | web.DAILY_LISTS:
                broken.append(f'{slug}/{name}: no control')
            form = body[body.find('<form'):] if '<form' in body else ''
            other = cards_expert.get(name, '')
            other_form = other[other.find('<form'):] if '<form' in other else ''
            if form and sorted(values.findall(form)) != sorted(values.findall(other_form)):
                broken.append(f'{slug}/{name}: other values than in the expert view')
        # Counters (mails today, queues, processes, times) move between the two renders: they are masked, the tiles, their
        # titles, states and notices are compared as they are.
        masked = lambda text: re.sub(r'\d+(?:[.:,]\d+)*', '#', text)
        # The block of the tiles: from its start to the next card (a closing pattern of divs depends on the last tile); the
        # folded load card is a card too.
        def block(text):
            start = text.find('<div class="tiles">')
            if start < 0:
                return ''
            ends = [found for found in (text.find('<div class="card', start), text.find('<details class="card', start)) if found >= 0]
            return text[start:min(ends)] if ends else text[start:]
        tiles, other_tiles = [masked(block(html))], [masked(block(expert[slug]))]
        if tiles != other_tiles:
            a, b = ''.join(tiles), ''.join(other_tiles)
            at = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
            broken.append(f'{slug}: tiles differ from the expert view: {a[max(0, at - 60):at + 60]!r} / {b[max(0, at - 60):at + 60]!r}')
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


def profile(web, slug, rounds):
    """Each read a page makes, timed alone and without the read cache, as efa-web calls efactl (through efactl-runner).
    Only reads without arguments, as the page itself takes them: nothing is changed."""
    who = []  # the main admin, as acting_as() outside a request
    ok, commands = web.efactl('schema', who=who)
    if not ok:
        raise SystemExit(f'schema: {commands}')
    page = web.PAGES[slug]
    wanted = [name for name in dict.fromkeys(['settings'] + page['commands'] + page.get('load', []))
              if name in commands and not commands[name]['writes'] and not commands[name]['args'] and not web.on_button_only(name)]
    wanted += [source for source in dict.fromkeys(web.FORM_SOURCE[name][0] for name in page['commands'] if name in web.FORM_SOURCE)
               if source not in wanted and source in commands and not commands[source]['writes']]
    times = []
    for name in wanted:
        seen = []
        for _ in range(rounds):
            start = time.perf_counter()
            web.efactl(name, who=who)
            seen.append((time.perf_counter() - start) * 1000)
        times.append((statistics.median(seen), name))
    # A read of the cache: the second one comes from it (well under a millisecond), else the cache does not hold it.
    missed = []
    for name in wanted:
        if web.READ_CACHE_SECONDS.get(name):
            web.efactl_read(name, who)
            start = time.perf_counter()
            web.efactl_read(name, who)
            if (time.perf_counter() - start) * 1000 > 2:
                missed.append(name)
    print(f'{"read of " + slug:<28} median ms  kept by the read cache (seconds)')
    for median, name in sorted(times, reverse=True):
        kept = web.READ_CACHE_SECONDS.get(name)
        print(f'{name:<28} {median:>9.0f}  {kept if kept else "-"}{"  NOT FROM THE CACHE" if name in missed else ""}')
    uncached = [name for median, name in times if median > 100 and not web.READ_CACHE_SECONDS.get(name)]
    print(f'{slug}: {len(wanted)} reads, the slowest without the cache: {max(times)[0]:.0f} ms' if times else f'{slug}: no reads')
    if missed or uncached:
        print('problems: ' + ', '.join([f'{name} not from the cache' for name in missed] + [f'{name} over 100 ms without a cache' for name in uncached]))
        return 1
    return 0


def main():
    rounds, budget = option('--rounds', 5), option('--budget-ms', 0)
    if '--profile' in sys.argv:
        return profile(load_web(), option('--profile', 'sec'), rounds)
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
