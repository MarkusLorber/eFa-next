#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Live test of the web interface in a real browser (Playwright, Chromium), run by scripts/live_test.sh as root with the Python
of its own venv:

    live_ui.py OUT_DIR DOMAIN [TENANT]

For each role a test user efa-live-<role> is made with a random password and removed at the end: super, readonly and auditor
always; tenant, domain and helpdesk only with TENANT (an existing test tenant, DOMAIN one of its domains); user (the portal)
with an address of DOMAIN. Per role: every page of the menu (status below 400, no server error, no console error), a
screenshot at 1280 px, at phone width 390 px (no page wider than the screen) and in dark mode; every action by GET (a
redirect, never 405); every form that has required fields sent without them (a clear message, never a server error). No form
is sent with values: nothing is changed. Prints one line per role and check; exits 1 when one failed.
"""
import json
import os
import re
import secrets
import subprocess
import sys

from playwright.sync_api import sync_playwright

HOST = 'https://127.0.0.1'
BROWSER = os.environ.get('EFA_LIVE_BROWSER') or None


def efactl(*args, stdin=''):
    return subprocess.run(['efactl', *args], input=stdin, capture_output=True, text=True, timeout=120)


def make_users(domain, tenant):
    users = {}
    for role in ('super', 'readonly', 'auditor') + (('tenant', 'domain', 'helpdesk') if tenant else ()) + ('user',):
        name = f'efa-live-{role}@{domain}' if role == 'user' else f'efa-live-{role}'
        password = secrets.token_urlsafe(18)
        scope = ([f'--tenant={tenant}'] if role in ('tenant', 'helpdesk') else []) + ([f'--domain={domain}'] if role in ('domain', 'user') else [])
        done = efactl('user-set', f'--username={name}', '--action=set', f'--role={role}', *scope, stdin=f'{password}\n{password}\n')
        if done.returncode != 0:
            raise SystemExit(f'test user {name}: {done.stderr.strip()[:200]}')
        users[role] = (name, password)
    return users


def remove_users(users):
    for name, _password in users.values():
        efactl('user-set', f'--username={name}', '--action=remove', '--confirm=yes')


def check_role(browser, out, role, name, password):
    problems, login = [], HOST + ('/portal/login' if role == 'user' else '/login')
    errors = []
    context = browser.new_context(ignore_https_errors=True, viewport={'width': 1280, 'height': 900})
    page = context.new_page()
    page.on('console', lambda message: errors.append(message.text) if message.type == 'error' else None)
    page.goto(login)
    page.fill('input[name=username]', name)
    page.fill('input[name=password]', password)
    page.click('button[type=submit], input[type=submit]')
    page.wait_for_load_state('networkidle')
    if page.url.startswith(login):
        return [f'login failed ({page.url})'], 0
    links = sorted({href for href in page.eval_on_selector_all('nav a[href], a[href^="/p/"], a[href^="/portal/"]',
                                                                 'items => items.map(item => item.getAttribute("href"))')
                    if href and re.match(r'^/(p|portal)/', href) and 'logout' not in href})
    for href in links or [page.url.replace(HOST, '') or '/']:
        slug = re.sub(r'[^a-z0-9]+', '-', href.lower()).strip('-') or 'start'
        errors.clear()
        answer = page.goto(HOST + href)
        page.wait_for_load_state('networkidle')
        if answer is None or answer.status >= 400 or 'Internal Server Error' in page.content():
            problems.append(f'{href}: status {answer.status if answer else "none"}')
            continue
        page.screenshot(path=os.path.join(out, f'{role}-{slug}.png'), full_page=True)
        if errors:
            problems.append(f'{href}: console errors: {errors[:2]}')
        # Every action by GET: a redirect back to the page, never 405.
        for action in sorted(set(page.eval_on_selector_all('form[method=post][action*="/run/"]', 'items => items.map(item => item.getAttribute("action"))'))):
            reply = context.request.get(HOST + action, max_redirects=0)
            if reply.status not in (302, 303):
                problems.append(f'GET {action}: {reply.status}')
        # Forms with required fields, sent without them: a clear message, never a server error; no values, nothing changes.
        for form in page.query_selector_all('form[method=post]'):
            if not form.query_selector('[required]'):
                continue
            action = form.get_attribute('action') or href
            csrf = form.query_selector('input[name=csrf]')
            reply = context.request.post(HOST + action,
                                         form={'csrf': csrf.get_attribute('value') if csrf else ''}, max_redirects=0)
            if reply.status >= 500:
                problems.append(f'POST {action} without its required fields: {reply.status}')
        page.set_viewport_size({'width': 390, 'height': 844})
        if page.evaluate('document.documentElement.scrollWidth > window.innerWidth + 1'):
            problems.append(f'{href}: wider than a phone at 390 px')
        page.screenshot(path=os.path.join(out, f'{role}-{slug}-phone.png'), full_page=True)
        page.emulate_media(color_scheme='dark')
        page.set_viewport_size({'width': 1280, 'height': 900})
        page.screenshot(path=os.path.join(out, f'{role}-{slug}-dark.png'), full_page=True)
        page.emulate_media(color_scheme='light')
    context.close()
    return problems, len(links)


def main():
    out, domain, tenant = sys.argv[1], sys.argv[2], (sys.argv[3] if len(sys.argv) > 3 else '')
    os.makedirs(out, exist_ok=True)
    users, failed = make_users(domain, tenant), False
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=BROWSER, args=['--no-sandbox'] if os.geteuid() == 0 else [])
            for role, (name, password) in users.items():
                problems, pages = check_role(browser, out, role, name, password)
                print(f'ui {role}: ' + (f'ok ({pages} pages)' if not problems else 'FAILED'))
                for problem in problems[:30]:
                    print(f'    {problem}')
                failed |= bool(problems)
            browser.close()
    finally:
        remove_users(users)
    left = [name for name, _ in users.values() if name in json.dumps(json.loads(efactl('user-list').stdout or '{}'))]
    print('ui test users removed: ' + ('ok' if not left else f'FAILED ({left})'))
    return 1 if failed or left else 0


if __name__ == '__main__':
    sys.exit(main())
