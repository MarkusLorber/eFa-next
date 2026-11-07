#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The first-run wizard of a fresh install, run by scripts/ci.sh --fresh as an admin would: setup code from the console file,
then every step, the confirmation, and the progress page until it says done. The host keeps its name, interface and address;
mail goes to 192.0.2.25 (TEST-NET-1). The passwords are made here and written only to the file given (root, 0600).
    fresh_wizard.py --creds FILE --host NAME --domain DOMAIN --interface DEV --ipv4 ADDR --prefix N --gateway GW --timezone ZONE
"""
import argparse
import http.cookiejar
import os
import re
import secrets
import ssl
import sys
import time
import urllib.parse
import urllib.request

BASE = 'https://127.0.0.1'
CODE_FILE = '/run/efa-init/setup-code'


def opener():
    context = ssl.create_default_context()
    # Only to this host itself: the wizard has its self-signed placeholder certificate.
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),
                                       urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def csrf(page):
    found = re.search(r'name="csrf" value="([^"]+)"', page)
    if not found:
        raise SystemExit('wizard: no form on the page: ' + re.sub(r'<[^>]+>', ' ', page)[:300])
    return found.group(1)


def post(web, path, fields):
    page = web.open(BASE + path, timeout=30).read().decode()
    data = urllib.parse.urlencode({'csrf': csrf(page), **fields}).encode()
    answer = web.open(BASE + path, data=data, timeout=60)
    return answer.geturl().replace(BASE, ''), answer.read().decode()


def answers(args, web_pw, cli_pw):
    return [('hostname', {'value': args.host}), ('domainname', {'value': args.domain}), ('email', {'value': 'admin@example.com'}),
            ('interface', {'value': args.interface}), ('configipv4', {'value': 'yes'}), ('ipv4address', {'value': args.ipv4}),
            ('ipv4netmask', {'value': args.prefix}), ('ipv4gateway', {'value': args.gateway}), ('ipv6dns', {'value': 'no'}),
            ('configipv6', {'value': 'no'}), ('configrecursion', {'value': 'yes'}),
            ('webpassword', {'value': web_pw, 'repeat': web_pw}), ('cliusername', {'value': 'efa-ci-fresh'}),
            ('clipassword', {'value': cli_pw, 'repeat': cli_pw}), ('configvirtual', {'value': 'no'}),
            ('configutc', {'value': 'yes'}), ('timezone', {'value': args.timezone}), ('mailserver', {'value': '192.0.2.25'})]


def main():
    parser = argparse.ArgumentParser()
    for name in ('creds', 'host', 'domain', 'interface', 'ipv4', 'prefix', 'gateway', 'timezone'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    web_pw, cli_pw = secrets.token_urlsafe(18), secrets.token_urlsafe(18)
    fd = os.open(args.creds, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(f'web={web_pw}\ncli={cli_pw}\n')
    web = opener()
    with open(CODE_FILE) as f:
        where, _page = post(web, '/unlock', {'code': f.read().strip()})
    if where.startswith('/unlock'):
        raise SystemExit('wizard: the setup code was not taken')
    for slug, fields in answers(args, web_pw, cli_pw):
        where, page = post(web, '/step/' + slug, fields)
        if where == '/step/' + slug:
            error = re.search(r'role="alert">([^<]+)<', page)
            raise SystemExit(f'wizard: step {slug} refused: {error.group(1) if error else "?"}')
    if where != '/verify':
        raise SystemExit('wizard: after the last step not on /verify but on ' + where)
    where, _page = post(web, '/verify', {'accept': 'yes'})
    deadline = time.time() + 900
    while time.time() < deadline:
        page = web.open(BASE + '/progress', timeout=30).read().decode()
        if 'Configuration complete' in page:
            print('wizard: configuration complete')
            return 0
        if 'Configuration failed' in page:
            raise SystemExit('wizard: configuration failed: ' + re.sub(r'<[^>]+>', ' ', page)[-1500:])
        time.sleep(5)
    raise SystemExit('wizard: no result after 15 minutes')


if __name__ == '__main__':
    sys.exit(main())
