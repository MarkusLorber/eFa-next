#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""eFa first-run wizard. Collects settings, then runs efa-apply --all and hands the answers over on stdin.

Runs as efa-init on 127.0.0.1:8080 behind nginx, only until the system is configured.
"""
import hmac
import ipaddress
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import zoneinfo

from flask import Flask, abort, redirect, render_template_string, request, session, url_for
from waitress import serve

EFA_APPLY = ['sudo', '-n', '/usr/sbin/efa-apply', '--verbose', '--answers', '-', '--all']
HOST_RE = re.compile(r'^[-a-zA-Z0-9]{1,63}$')
DOMAIN_RE = re.compile(r'^[a-zA-Z0-9]+([\-.][a-zA-Z0-9-]+)*$')
EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
CLI_USER_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
SERVER_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$')
MIN_PASSWORD = 12


def is_ip(version):
    def check(value):
        try:
            return ipaddress.ip_address(value).version == version
        except ValueError:
            return False
    return check


def in_range(low, high):
    return lambda value: value.isdigit() and low <= int(value) <= high


def interfaces():
    out = subprocess.run(['ip', '-o', 'link', 'show'], capture_output=True, text=True, timeout=10).stdout
    return [m for m in re.findall(r'^\d+: ([^:@]+)', out, re.M) if m != 'lo']


def has_address(dig_output):
    # dig +short also lists the names of CNAME records.
    return any(is_ip(4)(line) or is_ip(6)(line) for line in dig_output.split())


def resolves(name, server):
    try:
        done = subprocess.run(['dig', '+short', '+time=2', '+tries=2', f'@{server}', name, 'A', name, 'AAAA'],
                              capture_output=True, text=True, timeout=15)
    except (subprocess.SubprocessError, OSError):
        return False
    return has_address(done.stdout)


def mail_server_resolves(name):
    """Asks the resolver Postfix will use: the local Unbound, or the forwarders the admin chose."""
    if is_ip(4)(name):
        return True
    return resolves(name, '127.0.0.1' if answers.get('configrecursion') == 'yes' else answers.get('dns1', '127.0.0.1'))


def timezones():
    return sorted(zoneinfo.available_timezones())


# Confirmed before the setup runs (DISCLAIMER.md).
DISCLAIMER_SHORT = ('I am a qualified administrator and do not use eFa-next as a consumer; it is a mail filter server for businesses and '
                    'organisations. I accept: it comes without any warranty. To the maximum extent permitted by applicable law, Markus Lorber, all authors '
                    'and contributors of eFa-next and its sponsors, including IT-World ITW GmbH, are not liable for any damage from its use; '
                    'I use it at my own risk.')
STEPS = [
    {'slug': 'hostname', 'label': 'Please enter a hostname', 'check': HOST_RE.match},
    {'slug': 'domainname', 'label': 'Please enter a domain name', 'check': DOMAIN_RE.match},
    {'slug': 'email', 'label': 'Please enter an email address for important notifications', 'check': EMAIL_RE.match},
    {'slug': 'interface', 'label': 'Interface', 'choices': interfaces},
    {'slug': 'configipv4', 'label': 'Do you want to set a static IPv4 address?', 'yesno': True},
    {'slug': 'ipv4address', 'label': 'Please enter a valid IPv4 address', 'check': is_ip(4), 'if': 'configipv4'},
    {'slug': 'ipv4netmask', 'label': 'Please enter a valid IPv4 netmask', 'check': in_range(1, 32), 'if': 'configipv4'},
    {'slug': 'ipv4gateway', 'label': 'Please enter a valid IPv4 gateway', 'check': is_ip(4), 'if': 'configipv4'},
    {'slug': 'ipv6dns', 'label': 'Do you want to Enable IPv6 DNS?', 'yesno': True},
    {'slug': 'configipv6', 'label': 'Do you want to set a static IPv6 address?', 'yesno': True},
    {'slug': 'ipv6address', 'label': 'Please enter a valid IPv6 address', 'check': is_ip(6), 'if': 'configipv6'},
    {'slug': 'ipv6prefix', 'label': 'Please enter a valid IPv6 prefix', 'check': in_range(1, 128), 'if': 'configipv6'},
    {'slug': 'ipv6gateway', 'label': 'Please enter a valid IPv6 gateway', 'check': is_ip(6), 'if': 'configipv6'},
    {'slug': 'configrecursion', 'label': 'Do you want to enable full DNS Recursion?', 'yesno': True, 'default': 'yes'},
    {'slug': 'dns1', 'label': 'Please enter the primary DNS address', 'check': is_ip(4), 'unless': 'configrecursion'},
    {'slug': 'dns2', 'label': 'Please enter the secondary DNS address', 'check': is_ip(4), 'unless': 'configrecursion'},
    {'slug': 'webpassword', 'label': 'Please enter the web admin password', 'password': True},
    {'slug': 'cliusername', 'label': 'Please enter the username for the admin console interface',
     'check': lambda v: CLI_USER_RE.match(v) and v != 'root'},
    {'slug': 'clipassword', 'label': 'Please enter the console admin password', 'password': True},
    {'slug': 'configvirtual', 'label': 'Do you want to install hypervisor tools for your hypervisor?', 'yesno': True},
    {'slug': 'configutc', 'label': 'Is the host set to UTC time?', 'yesno': True, 'default': 'yes'},
    {'slug': 'timezone', 'label': 'Timezone', 'choices': timezones},
    {'slug': 'mailserver', 'label': 'Please enter the IP or hostname of the local mail server',
     'check': SERVER_RE.match},
    {'slug': 'mailserverdns', 'if': 'mailserverunresolved', 'back': 'mailserver',
     'label': 'This system cannot resolve the name of the mail server, and mail to it would bounce. '
              'Enter the internal DNS server that knows the name, or go back and enter the IP address of the mail server',
     'check': lambda v: '.' in answers['mailserver'] and (is_ip(4)(v) or is_ip(6)(v)) and resolves(answers['mailserver'], v)},
]
BY_SLUG = {step['slug']: step for step in STEPS}

app = Flask(__name__)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict', SESSION_COOKIE_SECURE=True)
# shortcut: one wizard state for all visitors, fine because a host is set up once by one admin.
answers = {}
commit = {'state': 'idle', 'log': ''}

PAGE = """<!doctype html><html lang="{{ lang }}"><head><meta charset="utf-8"><title>eFa-next: open source mail server protection</title>
<meta name="viewport" content="width=device-width, initial-scale=1">{% if refresh %}
<meta http-equiv="refresh" content="5">{% endif %}
<style>body{font-family:sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}label{display:block;margin:.75rem 0}
input,select{display:block;width:100%;padding:.4rem;box-sizing:border-box}input[type=radio]{display:inline;width:auto}
button{margin:.5rem .5rem 0 0;padding:.4rem 1rem}.err{color:#b00}pre{background:#eee;padding:.5rem;overflow:auto}
th{text-align:left;padding-right:1rem}</style></head><body><h1>eFa</h1>{% if error %}<p class="err" role="alert">{{ error }}</p>{% endif %}
{{ body|safe }}</body></html>"""


def page(body, error=None, refresh=False):
    return render_template_string(PAGE, body=body, error=error, refresh=refresh, lang=session.get('lang', 'en'))


def csrf_token():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_urlsafe(32)
    return session['csrf']


@app.before_request
def protect():
    if request.method == 'POST' and not hmac.compare_digest(request.form.get('csrf', ''), session.get('csrf') or secrets.token_urlsafe(8)):
        abort(403)
    if request.endpoint != 'unlock' and session.get('setup') not in setup['unlocked']:
        return redirect(url_for('unlock'))


# Until the system is set up, anyone who reaches port 443 would reach this wizard: it opens only with the code on the console.
SETUP_CODE_FILE = '/run/efa-init/setup-code'
SETUP_TRIES = 10
setup = {'code': None, 'failed': 0, 'unlocked': set()}


def setup_code_write(path=SETUP_CODE_FILE):
    setup['code'] = ''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(12))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(setup['code'] + '\n')


@app.route('/unlock', methods=['GET', 'POST'])
def unlock():
    error = None
    if request.method == 'POST':
        given = request.form.get('code', '').strip().upper().replace(' ', '')
        if setup['failed'] >= SETUP_TRIES:
            error = 'Too many wrong codes: restart the service efa-init on the console for a new one.'
        elif setup['code'] and hmac.compare_digest(given, setup['code']):
            session['setup'] = secrets.token_urlsafe(32)
            setup['unlocked'].add(session['setup'])
            return redirect(url_for('language'))
        else:
            setup['failed'] += 1
            error = 'Wrong setup code.'
    return page(f"""<p>Enter the setup code. On the console of this server: <code>cat {SETUP_CODE_FILE}</code></p>
<form method="post"><input type="hidden" name="csrf" value="{csrf_token()}"><label>Setup code <input name="code" required autofocus
autocomplete="off"></label><button>Next</button></form>""", error=error)


@app.after_request
def harden(response):
    response.headers.update({'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff',
                             'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'",
                             'Cache-Control': 'no-store'})
    return response


def active_steps():
    """Steps that apply with the answers given so far."""
    result = []
    for step in STEPS:
        if 'if' in step and answers.get(step['if']) != 'yes':
            continue
        if 'unless' in step and answers.get(step['unless']) == 'yes':
            continue
        result.append(step)
    return result


def next_slug(slug):
    steps = [s['slug'] for s in active_steps()]
    index = steps.index(slug) + 1
    return steps[index] if index < len(steps) else None


def validate(step, form):
    if step.get('yesno'):
        value = form.get('value', '')
        return (value, None) if value in ('yes', 'no') else (None, step['label'])
    value = form.get('value', '').strip()
    if any(char in value for char in '\r\n\0'):
        # The answers go to efa-apply as KEY:value lines.
        return None, step['label']
    if step.get('password'):
        if len(value) < MIN_PASSWORD:
            return None, f'{step["label"]} (min. {MIN_PASSWORD})'
        if value != form.get('repeat', ''):
            return None, 'The two entries are not the same. Please enter the password again.'
        return value, None
    if 'choices' in step:
        return (value, None) if value in step['choices']() else (None, step['label'])
    return (value, None) if step['check'](value) else (None, step['label'])


@app.route('/')
def language():
    return redirect(url_for('step', slug=STEPS[0]['slug']))


@app.route('/step/<slug>', methods=['GET', 'POST'])
def step(slug):
    current = BY_SLUG.get(slug)
    if current is None:
        abort(404)
    error = None
    if request.method == 'POST':
        value, error = validate(current, request.form)
        if error is None:
            answers[slug] = value
            if slug == 'mailserver':
                answers['mailserverunresolved'] = 'no' if mail_server_resolves(value) else 'yes'
            following = next_slug(slug)
            return redirect(url_for('step', slug=following) if following else url_for('verify'))
    return page(step_form(current), error=error)


def step_form(current):
    token = csrf_token()
    back = f'<p><a href="{url_for("step", slug=current["back"])}">Back</a></p>' if 'back' in current else ''
    label = render_template_string('{{ t }}', t=current['label'])
    saved = render_template_string('{{ v }}', v='' if current.get('password') else answers.get(current['slug'], current.get('default', '')))
    if current.get('yesno'):
        field = ''.join(f'<label><input type="radio" name="value" value="{v}" {"checked" if saved == v else ""} required> '
                        f'{t}</label>' for v, t in (('yes', 'Yes'), ('no', 'No')))
        field = f'<p>{label}</p>{field}'
    elif 'choices' in current:
        options = ''.join(f'<option {"selected" if saved == c else ""}>{c}</option>' for c in current['choices']())
        field = f'<label>{label} <select name="value" required>{options}</select></label>'
    elif current.get('password'):
        again = render_template_string('{{ t }}', t=current['label'].replace('enter', 're-enter'))
        field = (f'<label>{label} <input type="password" name="value" minlength="{MIN_PASSWORD}" required autofocus></label>'
                 f'<label>{again} <input type="password" name="repeat" required></label>')
    else:
        field = f'<label>{label} <input name="value" value="{saved}" required autofocus></label>'
    return f"""<form method="post"><input type="hidden" name="csrf" value="{token}">{field}<button>Next</button></form>{back}"""


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    missing = [s['slug'] for s in active_steps() if s['slug'] not in answers]
    if missing:
        return redirect(url_for('step', slug=missing[0]))
    if request.method == 'POST':
        if request.form.get('accept') != 'yes':
            return redirect(url_for('verify'))
        # 5y: the digest of the legal texts that were confirmed with the box.
        answers['legal'] = legal_digest()
        if commit['state'] != 'running':
            commit.update(state='running', log='')
            threading.Thread(target=run_commit, daemon=True).start()
        return redirect(url_for('progress'))
    rows = ''
    for item in active_steps():
        shown = '********' if item.get('password') else answers[item['slug']]
        rows += render_template_string('<tr><th><a href="{{ u }}">{{ l }}</a></th><td>{{ v }}</td></tr>',
                                       u=url_for('step', slug=item['slug']), l=item['label'], v=shown)
    return page(f"""<h2>Verify Settings</h2><table>{rows}</table>
<form method="post"><input type="hidden" name="csrf" value="{csrf_token()}">
<p><label><input type="checkbox" name="accept" value="yes" required> {DISCLAIMER_SHORT}
(<a href="https://github.com/MarkusLorber/eFa-next/blob/master/DISCLAIMER.md" target="_blank" rel="noopener noreferrer">DISCLAIMER.md</a>)</label></p>
<button>Next</button></form>""")


def legal_digest():
    """The digest of the installed legal texts (efa_legal), empty without them."""
    try:
        with open('/usr/share/eFa/legal/digest.txt') as f:
            found = f.read().strip()
    except OSError:
        return ''
    return found if re.fullmatch(r'[0-9a-f]{16}', found) else ''


def commit_answers():
    """KEY:value lines for efa-apply: on stdin, so passwords stay out of the process list."""
    a = answers
    static4, static6, recursion = a.get('configipv4') == 'yes', a.get('configipv6') == 'yes', a.get('configrecursion') == 'yes'
    yes_no = lambda value: 'YES' if value == 'yes' else 'NO'
    lines = {'HOSTNAME': a['hostname'], 'DOMAINNAME': a['domainname'], 'ADMINEMAIL': a['email'], 'INTERFACE': a['interface'],
             'IPV4ADDRESS': a['ipv4address'] if static4 else '', 'IPV4NETMASK': a['ipv4netmask'] if static4 else '',
             'IPV4GATEWAY': a['ipv4gateway'] if static4 else '', 'IPV6DNS': yes_no(a['ipv6dns']),
             'IPV6ADDRESS': a['ipv6address'] if static6 else '', 'IPV6MASK': a['ipv6prefix'] if static6 else '',
             'IPV6GATEWAY': a['ipv6gateway'] if static6 else '', 'RECURSION': yes_no(a['configrecursion']),
             'DNSIP1': '' if recursion else a.get('dns1', ''), 'DNSIP2': '' if recursion else a.get('dns2', ''),
             'WEBADMINPASSWORD': a['webpassword'], 'CLIUSERNAME': a['cliusername'], 'CLIPASSWORD': a['clipassword'],
             'VMTOOLS': yes_no(a['configvirtual']), 'ISUTC': yes_no(a['configutc']), 'TZONE': a['timezone'],
             'MAILSERVER': a['mailserver']}
    if a.get('mailserverunresolved') == 'yes':
        lines['MAILSERVERDNS'] = a['mailserverdns']
    if a.get('legal'):
        lines['LEGALACCEPTED'] = a['legal']
    return ''.join(f'{key}:{value}\n' for key, value in lines.items())


def run_commit():
    try:
        done = subprocess.run(EFA_APPLY, input=commit_answers(), capture_output=True, text=True, timeout=3600)
        commit.update(state='done' if done.returncode == 0 else 'failed', log=(done.stdout + done.stderr)[-4000:])
    except (subprocess.SubprocessError, OSError) as err:
        commit.update(state='failed', log=str(err))
    finally:
        # Plain-text passwords are no longer needed.
        answers.pop('webpassword', None)
        answers.pop('clipassword', None)


@app.route('/progress')
def progress():
    state = commit['state']
    if state == 'idle':
        return redirect(url_for('language'))
    if state == 'failed':
        log = render_template_string('{{ t }}', t=commit['log'])
        return page(f'<pre>{log}</pre><p><a href="{url_for("language")}">Back</a></p>', error='Configuration failed.')
    if state == 'done':
        return page('<p>Configuration complete. The system restarts now; afterwards log in at this address.</p>')
    return page('<p>Configuring the system, this takes several minutes...</p>', refresh=True)


def self_test():
    assert HOST_RE.match('mx1') and not HOST_RE.match('a b') and not HOST_RE.match('a;id')
    assert DOMAIN_RE.match('example.org') and not DOMAIN_RE.match('example.org;id')
    assert is_ip(4)('192.0.2.1') and not is_ip(4)('2001:db8::1') and is_ip(6)('2001:db8::1')
    assert in_range(1, 32)('24') and not in_range(1, 32)('33') and not in_range(1, 32)('x')
    assert not CLI_USER_RE.match('Root Admin') and CLI_USER_RE.match('efaadmin')
    long_enough = 'long-enough-password'
    assert validate(BY_SLUG['webpassword'], {'value': long_enough, 'repeat': long_enough}) == (long_enough, None)
    assert 'not the same' in validate(BY_SLUG['clipassword'], {'value': long_enough, 'repeat': 'other'})[1]
    assert validate(BY_SLUG['webpassword'], {'value': 'short', 'repeat': 'short'})[0] is None
    answers.clear()
    assert 'ipv4address' not in [s['slug'] for s in active_steps()]
    answers['configipv4'] = 'yes'
    assert 'ipv4address' in [s['slug'] for s in active_steps()]
    answers['configrecursion'] = 'yes'
    assert 'dns1' not in [s['slug'] for s in active_steps()]
    assert has_address('alias.example.org.\n192.0.2.1\n') and has_address('2001:db8::1\n') and not has_address('') and not has_address('alias.example.org.\n')
    answers.clear()
    assert 'mailserverdns' not in [s['slug'] for s in active_steps()]
    answers['mailserverunresolved'] = 'yes'
    assert 'mailserverdns' in [s['slug'] for s in active_steps()]
    answers['mailserver'] = 'mail'
    assert not BY_SLUG['mailserverdns']['check']('192.0.2.1')  # a name without a domain has no zone to forward
    answers['mailserver'] = 'mail.corp.example'
    assert not BY_SLUG['mailserverdns']['check']('not-an-ip') and mail_server_resolves('192.0.2.5')
    answers.clear()
    answers.update(hostname='mx1', domainname='example.org', email='a@example.org', interface='eth0', configipv4='no', ipv6dns='no',
                   configipv6='no', configrecursion='yes', webpassword='web-password-1', cliusername='efaadmin',
                   clipassword='cli-password-1', configvirtual='no', configutc='yes', timezone='UTC', mailserver='10.0.0.5')
    lines = commit_answers().splitlines()
    assert 'RECURSION:YES' in lines and 'IPV4ADDRESS:' in lines and 'WEBADMINPASSWORD:web-password-1' in lines and 'ISUTC:YES' in lines
    assert not [line for line in lines if line.startswith('MAILSERVERDNS')]
    answers.update(mailserver='mail.corp.example', mailserverunresolved='yes', mailserverdns='10.0.0.53')
    assert 'MAILSERVERDNS:10.0.0.53' in commit_answers().splitlines()
    # The setup runs only once the disclaimer is accepted.
    app.config.update(TESTING=True, SECRET_KEY=b'test')
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['csrf'] = 'token'
    # Nothing opens without the setup code of the console, and only so many wrong tries.
    with tempfile.TemporaryDirectory() as folder:
        setup_code_write(folder + '/code')
        assert oct(os.stat(folder + '/code').st_mode)[-3:] == '600' or os.name != 'posix'
    assert client.get('/verify').headers['Location'].endswith('/unlock') and client.get('/step/hostname').status_code == 302
    assert 'Wrong setup code' in client.post('/unlock', data={'csrf': 'token', 'code': 'nope'}).get_data(as_text=True)
    assert client.post('/unlock', data={'csrf': 'token', 'code': setup['code'].lower()}).status_code == 302
    setup['failed'] = SETUP_TRIES
    assert 'Too many' in client.post('/unlock', data={'csrf': 'token', 'code': setup['code']}).get_data(as_text=True)
    setup['failed'] = 0
    assert validate(BY_SLUG['webpassword'], {'value': 'long-enough-pass\nMAILSERVER:x', 'repeat': 'long-enough-pass\nMAILSERVER:x'})[0] is None
    page_text = client.get('/verify').get_data(as_text=True)
    assert 'name="accept"' in page_text and 'IT-World ITW GmbH' in page_text and 'DISCLAIMER.md' in page_text
    reply = client.post('/verify', data={'csrf': 'token'})
    assert reply.status_code == 302 and reply.headers['Location'].endswith('/verify') and commit['state'] != 'running'
    answers.clear()
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
        sys.exit(0)
    with open('/etc/efa-web/secret.key', 'rb') as secret:
        app.secret_key = secret.read()
    setup_code_write()
    serve(app, host='127.0.0.1', port=8080, threads=4)
