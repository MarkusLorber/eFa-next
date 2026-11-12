#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Live test of the guided wizards in a real browser (Playwright, Chromium), run by scripts/live_test.sh (step ui) as root:

    wizard_live.py OUT_DIR DOMAIN

A main admin and a domain admin of DOMAIN are made with random passwords and removed at the end. Checked: the wizard comes
first and the manual switch stays after a new login; the disclaimer preview shows its HTML under the real security header;
the connection test of the archive runs in the background and names the problem of a host that does not answer and of one
without STARTTLS within seconds; the domain and DKIM wizards apply and show their result; the German view; the domain admin
gets no archive wizard and a refusal for a disclaimer of all domains. Screenshots go to OUT_DIR. Everything the test made
(domain route, DKIM keys, disclaimer, archive target, the users) is removed again.
"""
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time

from playwright.sync_api import sync_playwright

HOST = 'https://127.0.0.1'
BROWSER = os.environ.get('EFA_LIVE_BROWSER') or None
TEST_DOMAIN = 'wizard-live.example'
NO_TLS_PORT = 2526


def efactl(*args, stdin=''):
    return subprocess.run(['efactl', *args], input=stdin, capture_output=True, text=True, timeout=120)


def smtp_without_starttls(stop):
    """A mail server on 127.0.0.1 that answers EHLO without STARTTLS."""
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', NO_TLS_PORT))
    server.listen(4)
    server.settimeout(0.5)
    while not stop.is_set():
        try:
            client, _address = server.accept()
        except socket.timeout:
            continue
        with client:
            client.settimeout(3)
            client.sendall(b'220 plain.example ESMTP\r\n')
            try:
                for line in client.makefile('rb'):
                    word = line[:4].upper()
                    if word in (b'EHLO', b'HELO'):
                        client.sendall(b'250-plain.example\r\n250 SIZE 1000000\r\n')
                    elif word == b'QUIT':
                        client.sendall(b'221 bye\r\n')
                        break
                    else:
                        client.sendall(b'502 no\r\n')
            except OSError:
                pass
    server.close()


def login(browser, name, password, locale='en-US'):
    context = browser.new_context(ignore_https_errors=True, viewport={'width': 1280, 'height': 1000}, locale=locale)
    page = context.new_page()
    errors = []
    page.on('console', lambda message: errors.append(message.text) if message.type == 'error' else None)
    page.goto(HOST + '/login')
    page.fill('input[name=username]', name)
    page.fill('input[name=password]', password)
    page.click('form button:not([type=button]), input[type=submit]')
    page.wait_for_load_state('networkidle')
    return context, page, errors


def logout(page):
    page.goto(HOST + '/p/account')
    page.evaluate("() => document.querySelector('form[action=\"/logout\"]').submit()")
    page.wait_for_load_state('networkidle')


def put(page, name, value):
    """One field of the wizard step, whatever it is rendered as: text, list, pills or a switch."""
    selector = f'#wizard [name="{name}"]'
    kind = page.eval_on_selector(selector, 'item => item.tagName.toLowerCase() + ":" + (item.type || "")')
    if kind.startswith('select'):
        page.select_option(selector, value)
    elif kind == 'input:radio':
        # A pill: the radio itself is hidden, a person clicks its label.
        page.click(f'#wizard label:has(> input[name="{name}"][value="{value}"])')
        if not page.is_checked(f'#wizard input[name="{name}"][value="{value}"]'):
            raise AssertionError(f'the pill {name}={value} does not take a click')
    elif kind == 'input:checkbox':
        page.set_checked(selector, value in ('on', 'yes'), force=True)
    else:
        page.fill(selector, value)


def go(page, button='next', **fields):
    for name, value in fields.items():
        put(page, name, value)
    started = time.monotonic()
    page.click(f'#wizard button[name=go][value={button}]')
    page.wait_for_load_state('networkidle')
    return time.monotonic() - started


WIZARD_OF = {'archive': 'archive', 'disclaimer': 'disclaimer', 'dkim': 'dkim', 'flow': 'route', 'standards': 'hardening'}


def wizard_page(page, slug):
    """The page of a wizard with an empty draft: Start again, as its button sends it."""
    page.goto(f'{HOST}/p/{slug}')
    page.wait_for_load_state('networkidle')
    csrf = page.get_attribute('input[name=csrf]', 'value')
    page.request.post(f'{HOST}/wizard/{WIZARD_OF[slug]}', form={'csrf': csrf, 'go': 'restart', 'step': ''}, max_redirects=0)
    page.goto(f'{HOST}/p/{slug}')
    page.wait_for_load_state('networkidle')


def shot(page, out, name):
    if page.query_selector('#wizard'):
        top = page.evaluate("() => { const box = document.querySelector('form.wizmode').getBoundingClientRect(), bar = document.querySelector('.viewbar'); "
                            "return bar ? box.top - bar.getBoundingClientRect().bottom : 0; }")
        if top < 0:
            SHOT_PROBLEMS.append(f'{name}: the sticky bar covers the Wizard/Manual switch by {-top:.0f} px')
    page.screenshot(path=os.path.join(out, name + '.png'), full_page=True)


SHOT_PROBLEMS = []


def check_hardening(page, out):
    """The hardening wizard up to its preview, then Start again: the preview reads only, nothing is applied here (Apply changes
    the operating system; it is tested in the self-test of efactl and by hand)."""
    problems, before = [], efactl('standards-status').stdout
    wizard_page(page, 'standards')
    for box in page.query_selector_all('#wizard input[name="select"]'):
        page.set_checked(f'#wizard input[name="select"][value="{box.get_attribute("value")}"]', False, force=True)
    for sid in ('bsi-02102-2', 'rfc9325'):
        page.set_checked(f'#wizard input[name="select"][value="{sid}"]', True, force=True)
    shot(page, out, 'hardening-standards')
    go(page)
    go(page)
    for item in ('ssh-profile', 'crypto-future', 'sshd-cis'):
        go_keep = f'os_{item}'
        if page.query_selector(f'#wizard input[name="{go_keep}"][value="keep"]'):
            put(page, go_keep, 'keep')
    page.evaluate('() => window.scrollTo(0, 0)')  # the clicks on the pills scrolled down; the sticky bar check counts from the top
    shot(page, out, 'hardening-os')
    go(page)
    go(page)
    text = page.inner_text('#wizard')
    shot(page, out, 'hardening-preview')
    if 'Step 5 of 6' not in text or 'Setting' not in text and 'SETTING' not in text:
        problems.append('hardening: no preview table on step 5')
    if 'The preview shows no pictures' in text:
        problems.append('hardening: the preview of the disclaimer wizard on its preview step')
    go(page, 'restart')
    if not page.query_selector('#wizard input[name="select"]'):
        problems.append('hardening: Start again does not go back to the standards')
    if efactl('standards-status').stdout != before:
        problems.append('hardening: the steps up to the preview changed something')
    return problems


def check_super(browser, out, name, password):
    problems = []
    context, page, errors = login(browser, name, password)
    # Wizard first, the manual switch kept after a new login.
    page.goto(HOST + '/p/archive')
    if not page.query_selector('#wizard') or page.query_selector('#archive-set'):
        problems.append('/p/archive: the wizard does not come first')
    shot(page, out, 'archive-wizard')
    page.click('form.wizmode button[value=manual]')
    page.wait_for_load_state('networkidle')
    if not page.query_selector('#archive-set'):
        problems.append('/p/archive: Manual shows no manual cards')
    shot(page, out, 'archive-manual')
    logout(page)
    context.close()
    context, page, errors = login(browser, name, password)
    page.goto(HOST + '/p/archive')
    if not page.query_selector('#archive-set') or page.query_selector('#wizard'):
        problems.append('/p/archive: the manual view is not kept after a new login')
    page.click('form.wizmode button[value=wizard]')
    page.wait_for_load_state('networkidle')
    if not page.query_selector('#wizard'):
        problems.append('/p/archive: Wizard does not go back')
    # Domain and its mail server first: the archive and the disclaimer below take only this test domain.
    wizard_page(page, 'flow')
    go(page, domain=TEST_DOMAIN)
    go(page, destination='127.0.0.1:2527')
    go(page, 'apply')
    if TEST_DOMAIN not in efactl('settings').stdout:
        problems.append('route: Apply did not add the domain')
    # Archive: the connection test in the background, a host that does not answer and one without STARTTLS.
    for host, port, wanted in (('192.0.2.1', '25', ('timed out', 'unreachable', 'No route', 'refused')), ('127.0.0.1', str(NO_TLS_PORT), ('no STARTTLS',))):
        wizard_page(page, 'archive')
        go(page, target='+new', template='piler')
        go(page, name='wizardlive', address='journal@archive.example.net', host=host, port=port, format='copy')
        go(page, direction='both', all='+chosen')
        go(page, domains=TEST_DOMAIN)
        took = go(page, 'test', tls='verify')
        if took > 1.5:
            problems.append(f'archive test: the page waited {took:.1f} s for the test')
        try:
            page.wait_for_selector('#wizard table.kv', timeout=8000)
        except Exception:  # noqa: BLE001 - the missing result is named below
            pass
        text = page.inner_text('#wizard')
        if not any(item in text for item in wanted):
            problems.append(f'archive test {host}:{port}: none of {wanted} shown within 8 s')
        shot(page, out, f'archive-test-{port}')
    go(page, tls='verify')
    shot(page, out, 'archive-summary')
    go(page, 'apply')
    if 'wizardlive' not in efactl('archive-status').stdout:
        problems.append('archive: Apply made no target')
    shot(page, out, 'archive-done')
    wizard_page(page, 'dkim')
    if not page.query_selector(f'#wizard option[value="{TEST_DOMAIN}"]'):
        problems.append('dkim: the new domain is not in the list')
    else:
        go(page, domain=TEST_DOMAIN)
        go(page, kind='both', bits='2048')
        go(page, 'apply')
        if 'v=DKIM1' not in page.inner_text('#wizard'):
            problems.append('dkim: the result shows no DNS record')
        shot(page, out, 'dkim-done')
    problems += check_hardening(page, out)
    # Disclaimer: the preview under the real security header.
    wizard_page(page, 'disclaimer')
    go(page, id='+new')
    go(page, new_id='wizard-live', scope='domain')
    go(page, domain=TEST_DOMAIN)
    go(page, name='Wizard live test', format='html', text='Live test text.')
    errors.clear()
    go(page, html='<p><b>Live</b> test HTML.</p>')
    frame = page.frame_locator('#wizard iframe')
    try:
        shown = frame.locator('body').inner_text(timeout=5000)
    except Exception as err:  # noqa: BLE001
        shown = f'({type(err).__name__})'
    if 'Live test HTML.' not in shown:
        problems.append(f'disclaimer: the preview frame shows "{shown[:80]}"')
    if errors:
        problems.append(f'disclaimer preview: console errors {errors[:3]}')
    shot(page, out, 'disclaimer-preview')
    go(page, enabled='on')
    go(page, 'apply')
    if 'wizard-live' not in efactl('disclaimer-status').stdout:
        problems.append('disclaimer: Apply made no disclaimer')
    context.close()
    # German, from the language of the browser.
    context, page, errors = login(browser, name, password, locale='de-DE')
    wizard_page(page, 'disclaimer')
    if 'Assistent' not in page.inner_text('form.wizmode') or 'Welcher Disclaimer' not in page.inner_text('#wizard'):
        problems.append('German: the wizard is not in German')
    shot(page, out, 'disclaimer-de')
    context.close()
    return problems + SHOT_PROBLEMS


def check_domain_admin(browser, out, name, password, domain):
    problems = []
    context, page, errors = login(browser, name, password)
    answer = page.goto(HOST + '/p/archive')
    if answer and answer.status < 400 and page.query_selector('#wizard'):
        problems.append('domain admin: the archive wizard is shown')
    answer = page.goto(HOST + '/p/standards')
    if answer and answer.status < 400 and page.query_selector('#wizard'):
        problems.append('domain admin: the hardening wizard is shown')
    wizard_page(page, 'disclaimer')
    if not page.query_selector('#wizard'):
        problems.append('domain admin: no disclaimer wizard')
    else:
        go(page, id='+new')
        go(page, new_id='wizard-live-all', scope='global')
        go(page, name='', format='text', text='All domains test.')
        go(page, enabled='on')
        go(page, 'apply')
        if 'Not allowed' not in page.inner_text('#wizard'):
            problems.append('domain admin: a disclaimer for all domains was not refused')
        shot(page, out, 'domain-admin-refused')
    wizard_page(page, 'dkim')
    others = [item for item in page.eval_on_selector_all('#wizard select[name=domain] option', 'items => items.map(item => item.value)') if item != domain]
    if others:
        problems.append(f'domain admin: the DKIM wizard lists other domains {others[:5]}')
    context.close()
    return problems


def clean_up():
    for key in json.loads(efactl('dkim-check').stdout or '{}').get('keys', []):
        if key.get('domain') == TEST_DOMAIN:
            efactl('dkim-remove', f'--domain={TEST_DOMAIN}', f"--selector={key['selector']}", '--confirm=yes')
    efactl('disclaimer-template-remove', '--id=wizard-live')
    efactl('disclaimer-template-remove', '--id=wizard-live-all')
    efactl('archive-remove', '--name=wizardlive', '--confirm=yes')
    efactl('transport-set', f'--domain={TEST_DOMAIN}', '--action=remove', '--destination=')


def main():
    out, domain = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    users = {}
    for role, scope in (('super', []), ('domain', [f'--domain={domain}'])):
        name, password = f'efa-live-wizard-{role}', secrets.token_urlsafe(18)
        done = efactl('user-set', f'--username={name}', '--action=set', f'--role={role}', *scope, stdin=f'{password}\n{password}\n')
        if done.returncode != 0:
            raise SystemExit(f'test user {name}: {done.stderr.strip()[:200]}')
        users[role] = (name, password)
    stop = threading.Event()
    threading.Thread(target=smtp_without_starttls, args=(stop,), daemon=True).start()
    failed = False
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=BROWSER, args=['--no-sandbox'] if os.geteuid() == 0 else [])
            for role, check in (('super', lambda: check_super(browser, out, *users['super'])),
                                ('domain', lambda: check_domain_admin(browser, out, *users['domain'], domain))):
                try:
                    problems = check()
                except Exception as err:  # noqa: BLE001 - a broken page is a failed check, the clean up still runs
                    problems = [f'{type(err).__name__}: {str(err)[:300]}']
                print(f'ui wizards {role}: ' + ('ok' if not problems else 'FAILED'))
                for problem in problems:
                    print(f'    {problem}')
                failed |= bool(problems)
            browser.close()
    finally:
        stop.set()
        clean_up()
        for name, _password in users.values():
            efactl('user-set', f'--username={name}', '--action=remove', '--confirm=yes')
    left = [item for item in (TEST_DOMAIN, 'wizardlive', 'wizard-live') if item in efactl('settings').stdout + efactl('archive-status').stdout
            + efactl('disclaimer-status').stdout]
    print('ui wizards clean up: ' + ('ok' if not left else f'FAILED ({left})'))
    return 1 if failed or left else 0


if __name__ == '__main__':
    sys.exit(main())
