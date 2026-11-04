#!/usr/bin/python3
"""eFa first-run wizard, replaces the PHP eFaInit. Collects settings, then runs eFa-Commit --commitall.

Runs as efa-web on 127.0.0.1:8080 behind nginx, only until the system is configured.
"""
import crypt
import glob
import hmac
import ipaddress
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import zoneinfo

import yaml
from flask import Flask, abort, redirect, render_template_string, request, session, url_for
from waitress import serve
from werkzeug.security import generate_password_hash

TRANSLATIONS = '/usr/share/efa-init/translations'
EFA_COMMIT = ['sudo', '-n', '/usr/sbin/eFa-Commit', '--commitall', '--verbose']
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
    out = subprocess.run(['ip', '-o', 'link', 'show'], capture_output=True, text=True).stdout
    return [m for m in re.findall(r'^\d+: ([^:@]+)', out, re.M) if m != 'lo']


def timezones():
    return sorted(zoneinfo.available_timezones())


# Order and texts follow the old wizard, so the existing translations keep working.
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
]
BY_SLUG = {step['slug']: step for step in STEPS}

app = Flask(__name__)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict', SESSION_COOKIE_SECURE=True)
# shortcut: one wizard state for all visitors, fine because a host is set up once by one admin.
answers = {}
commit = {'state': 'idle', 'log': ''}

PAGE = """<!doctype html><html lang="{{ lang }}"><head><meta charset="utf-8"><title>eFa</title>
<meta name="viewport" content="width=device-width, initial-scale=1">{% if refresh %}
<meta http-equiv="refresh" content="5">{% endif %}
<style>body{font-family:sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}label{display:block;margin:.75rem 0}
input,select{display:block;width:100%;padding:.4rem;box-sizing:border-box}input[type=radio]{display:inline;width:auto}
button{margin:.5rem .5rem 0 0;padding:.4rem 1rem}.err{color:#b00}pre{background:#eee;padding:.5rem;overflow:auto}
th{text-align:left;padding-right:1rem}</style></head><body><h1>eFa</h1>{% if error %}<p class="err" role="alert">{{ error }}</p>{% endif %}
{{ body|safe }}</body></html>"""


def translator():
    lang = session.get('lang', 'en')
    path = f'{TRANSLATIONS}/messages.{lang}.yml'
    try:
        with open(path, encoding='utf-8') as f:
            table = yaml.safe_load(f) or {}
    except OSError:
        table = {}
    return lambda text: table.get(text, text)


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
    _ = translator()
    if step.get('yesno'):
        value = form.get('value', '')
        return (value, None) if value in ('yes', 'no') else (None, _(step['label']))
    value = form.get('value', '').strip()
    if step.get('password'):
        if len(value) < MIN_PASSWORD:
            return None, f'{_(step["label"])} (min. {MIN_PASSWORD})'
        if value != form.get('repeat', ''):
            return None, _(step['label'].replace('enter', 're-enter'))
        return value, None
    if 'choices' in step:
        return (value, None) if value in step['choices']() else (None, _(step['label']))
    return (value, None) if step['check'](value) else (None, _(step['label']))


@app.route('/', methods=['GET', 'POST'])
def language():
    if request.method == 'POST':
        lang = request.form.get('lang', 'en')
        if lang in languages():
            session['lang'] = lang
        return redirect(url_for('step', slug=STEPS[0]['slug']))
    options = ''.join(f'<option value="{code}">{code}</option>' for code in languages())
    return page(f"""<form method="post"><input type="hidden" name="csrf" value="{csrf_token()}">
<label>Language <select name="lang">{options}</select></label><button>Next</button></form>""")


def languages():
    found = [os.path.basename(p)[len('messages.'):-len('.yml')] for p in glob.glob(f'{TRANSLATIONS}/messages.*.yml')]
    return sorted(found) or ['en']


@app.route('/step/<slug>', methods=['GET', 'POST'])
def step(slug):
    current = BY_SLUG.get(slug)
    if current is None:
        abort(404)
    _ = translator()
    error = None
    if request.method == 'POST':
        value, error = validate(current, request.form)
        if error is None:
            answers[slug] = value
            following = next_slug(slug)
            return redirect(url_for('step', slug=following) if following else url_for('verify'))
    return page(step_form(current, _), error=error)


def step_form(current, _):
    token = csrf_token()
    label = render_template_string('{{ t }}', t=_(current['label']))
    saved = render_template_string('{{ v }}', v='' if current.get('password') else answers.get(current['slug'], current.get('default', '')))
    if current.get('yesno'):
        field = ''.join(f'<label><input type="radio" name="value" value="{v}" {"checked" if saved == v else ""} required> '
                        f'{_(t)}</label>' for v, t in (('yes', 'Yes'), ('no', 'No')))
        field = f'<p>{label}</p>{field}'
    elif 'choices' in current:
        options = ''.join(f'<option {"selected" if saved == c else ""}>{c}</option>' for c in current['choices']())
        field = f'<label>{label} <select name="value" required>{options}</select></label>'
    elif current.get('password'):
        again = render_template_string('{{ t }}', t=_(current['label'].replace('enter', 're-enter')))
        field = (f'<label>{label} <input type="password" name="value" minlength="{MIN_PASSWORD}" required autofocus></label>'
                 f'<label>{again} <input type="password" name="repeat" required></label>')
    else:
        field = f'<label>{label} <input name="value" value="{saved}" required autofocus></label>'
    return f"""<form method="post"><input type="hidden" name="csrf" value="{token}">{field}<button>{_('Next')}</button></form>"""


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    _ = translator()
    missing = [s['slug'] for s in active_steps() if s['slug'] not in answers]
    if missing:
        return redirect(url_for('step', slug=missing[0]))
    if request.method == 'POST':
        if commit['state'] != 'running':
            commit.update(state='running', log='')
            threading.Thread(target=run_commit, daemon=True).start()
        return redirect(url_for('progress'))
    rows = ''
    for item in active_steps():
        shown = '********' if item.get('password') else answers[item['slug']]
        rows += render_template_string('<tr><th><a href="{{ u }}">{{ l }}</a></th><td>{{ v }}</td></tr>',
                                       u=url_for('step', slug=item['slug']), l=_(item['label']), v=shown)
    return page(f"""<h2>{_('Verify Settings')}</h2><table>{rows}</table>
<form method="post"><input type="hidden" name="csrf" value="{csrf_token()}"><button>{_('Next')}</button></form>""")


def commit_args():
    a = answers
    static4, static6, recursion = a.get('configipv4') == 'yes', a.get('configipv6') == 'yes', a.get('configrecursion') == 'yes'
    cli_hash = crypt.crypt(a['clipassword'], crypt.mksalt(crypt.METHOD_SHA512))
    return [f"--hostname={a['hostname']}", f"--domainname={a['domainname']}", f"--adminemail={a['email']}",
            f"--interface={a['interface']}", f"--ipv4address={a['ipv4address'] if static4 else ''}",
            f"--ipv4netmask={a['ipv4netmask'] if static4 else ''}", f"--ipv4gateway={a['ipv4gateway'] if static4 else ''}",
            f"--ipv6dns={1 if a['ipv6dns'] == 'yes' else 0}", f"--ipv6address={a['ipv6address'] if static6 else ''}",
            f"--ipv6mask={a['ipv6prefix'] if static6 else ''}", f"--ipv6gateway={a['ipv6gateway'] if static6 else ''}",
            f"--enablerecursion={1 if recursion else 0}", f"--dnsip1={a.get('dns1', '') if not recursion else ''}",
            f"--dnsip2={a.get('dns2', '') if not recursion else ''}",
            f"--efauserpwd={generate_password_hash(a['webpassword'], method='pbkdf2:sha256:600000')}",
            f"--cliusername={a['cliusername']}", f"--efaclipwd={cli_hash}",
            f"--configvirtual={1 if a['configvirtual'] == 'yes' else 0}", f"--isutc={1 if a['configutc'] == 'yes' else 0}",
            f"--timezone={a['timezone']}", f"--mailserver={a['mailserver']}"]


def run_commit():
    try:
        done = subprocess.run(EFA_COMMIT + commit_args(), capture_output=True, text=True, timeout=3600)
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
    answers.clear()
    assert 'ipv4address' not in [s['slug'] for s in active_steps()]
    answers['configipv4'] = 'yes'
    assert 'ipv4address' in [s['slug'] for s in active_steps()]
    answers['configrecursion'] = 'yes'
    assert 'dns1' not in [s['slug'] for s in active_steps()]
    answers.clear()
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
        sys.exit(0)
    with open('/etc/efa-web/secret.key', 'rb') as secret:
        app.secret_key = secret.read()
    serve(app, host='127.0.0.1', port=8080, threads=4)
