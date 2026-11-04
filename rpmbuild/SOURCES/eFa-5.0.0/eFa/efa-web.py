#!/usr/bin/python3
"""eFa web interface. Holds no eFa logic: forms come from `efactl schema`, actions call efactl.

Runs as user efa-web behind nginx on 127.0.0.1:8080. sudo allows only /usr/sbin/efactl.
"""
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import time

from flask import Flask, abort, redirect, render_template_string, request, session, url_for
from waitress import serve
from werkzeug.security import check_password_hash

WEB_DIR = os.environ.get('EFA_ETC', '/etc') + '/efa-web'
PASSWORD_FILE = WEB_DIR + '/admin.pw'
SECRET_FILE = WEB_DIR + '/secret.key'
EFACTL = ['sudo', '-n', '/usr/sbin/efactl']
SESSION_MAX_AGE = 3600
MAX_LOGIN_FAILURES = 5
LOCKOUT_SECONDS = 300

app = Flask(__name__)
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
                  PERMANENT_SESSION_LIFETIME=SESSION_MAX_AGE)
login_failures = {}

REPO_URL = 'https://github.com/MarkusLorber/eFa-next'
# Same drawing as assets/logo.svg. Inline, because this script ships alone and the login page shows it too.
LOGO = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 440 120" role="img" aria-label="eFa-next">
  <title>eFa-next</title>
  <style>
    .text { fill: #646563; }
    .line { stroke: #646563; }
    @media (prefers-color-scheme: dark) {
      .text { fill: #f2f2f2; }
      .line { stroke: #f2f2f2; }
    }
  </style>
  <!-- Rings and outlined envelope, a flat take on the eFa logo -->
  <g transform="rotate(-14 80 54)">
    <rect x="42" y="22" width="76" height="54" rx="6" fill="#ffffff" fill-opacity="0" class="line" stroke-width="5"/>
    <path d="M45 26 80 54l35-28" fill="none" class="line" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>
  </g>
  <text x="166" y="76" font-family="Segoe UI, Helvetica, Arial, sans-serif" font-size="68" font-weight="800" letter-spacing="-2" class="text">e<tspan fill="#c0cf48">F</tspan>a<tspan font-weight="300" letter-spacing="0" dx="8">next</tspan></text>
  <text x="169" y="102" font-family="Segoe UI, Helvetica, Arial, sans-serif" font-size="17" letter-spacing="1.5" class="text">email <tspan font-weight="700">FILTER</tspan> appliance</text>
</svg>"""
BRAND = '<a class="brand" href="' + REPO_URL + '">' + LOGO + '</a>'
FLAG_AT = """<svg viewBox="0 0 30 20" role="img" aria-label="Austria"><rect width="30" height="20" fill="#fff"/>
<rect width="30" height="6.67" fill="#ED2939"/><rect y="13.33" width="30" height="6.67" fill="#ED2939"/></svg>"""
FLAG_EU = """<svg viewBox="0 0 30 20" role="img" aria-label="European Union"><rect width="30" height="20" fill="#003399"/>
<g fill="#FFCC00" font-size="3.4" text-anchor="middle"><text x="15" y="4.7">★</text><text x="18.25" y="5.6">★</text>
<text x="20.6" y="8">★</text><text x="21.5" y="11.2">★</text><text x="20.6" y="14.4">★</text>
<text x="18.25" y="16.8">★</text><text x="15" y="17.7">★</text><text x="11.75" y="16.8">★</text>
<text x="9.4" y="14.4">★</text><text x="8.5" y="11.2">★</text><text x="9.4" y="8">★</text>
<text x="11.75" y="5.6">★</text></g></svg>"""

# The sidebar. Each page offers the listed efactl commands: read commands without arguments show their output,
# all others a form. 'load' only fetches data for the page, 'show' lists current values from `efactl settings`.
NAV = [
    ('Overview', [
        {'slug': 'dash', 'title': 'Dashboard', 'sub': 'Current state of this server.',
         'commands': ['status', 'settings'], 'load': ['quarantine-list', 'backup-list', 'dkim-check']}]),
    ('Mail flow', [
        {'slug': 'flow', 'title': 'Domains & destinations',
         'sub': 'Which domains this server accepts mail for and where it delivers them.',
         'commands': ['transport-set'], 'show': ['transports']},
        {'slug': 'relay', 'title': 'Relay networks & smarthost',
         'sub': 'Who may send through this server, and whether outgoing mail goes through a provider.',
         'commands': ['relay-networks-set', 'smarthost-set']},
        {'slug': 'limits', 'title': 'Limits & recipient check',
         'sub': 'Size limit and rejection of unknown recipients.',
         'commands': ['message-size-set', 'recipient-verification-set']}]),
    ('Spam & threats', [
        {'slug': 'spam', 'title': 'Spam scores & greylisting',
         'sub': 'Decide when a message is greylisted, marked or rejected.',
         'commands': ['spam-scores-set', 'greylisting-set', 'subject-get', 'subject-set'],
         'notes': {'subject-set': 'Put in front of the subject of mail with a hard SPF, DKIM or DMARC failure.'}},
        {'slug': 'senders', 'title': 'Sender lists & rules',
         'sub': 'Always allow or block senders, by address, domain, IP or pattern.',
         'commands': ['sender-list-set', 'sender-rule-set'], 'show': ['sender_allow', 'sender_block']},
        {'slug': 'quar', 'title': 'Quarantine', 'sub': 'Spam held back instead of delivered.',
         'commands': ['quarantine-list', 'quarantine-show', 'quarantine-release', 'quarantine-delete',
                      'quarantine-set', 'quarantine-days-set', 'quarantine-purge']},
        {'slug': 'dkim', 'title': 'DKIM & DMARC', 'sub': 'Sender signatures and DMARC reports.',
         'commands': ['dkim-check', 'dkim-generate', 'dmarc-reports-set'],
         'notes': {'dkim-generate': 'To import a key, on the console: efactl dkim-import'}}]),
    ('Logs', [
        {'slug': 'log', 'title': 'Mail log', 'sub': 'Search delivered and rejected mail.',
         'commands': ['maillog-search', 'maillog-retention-set', 'maillog-size-set', 'maillog-purge']}]),
    ('System', [
        {'slug': 'net', 'title': 'Network & certificate', 'sub': 'Changes to the network apply after a reboot.',
         'commands': ['network-show', 'network-set', 'dns-zone-set', 'letsencrypt-set'], 'show': ['dns_zones']},
        {'slug': 'sec', 'title': 'Security & admin', 'sub': 'Protection against attacks and administrator access.',
         'commands': ['fail2ban-set', 'admin-email-set'],
         'notes': {'admin-email-set': 'To change the web password, on the console: efactl admin-password'}},
        {'slug': 'bak', 'title': 'Backup & restore', 'sub': 'Automatic and manual backups of this server.',
         'commands': ['backup-list', 'backup-now', 'backup-set', 'restore']},
        {'slug': 'maint', 'title': 'Maintenance & update',
         'sub': 'Actions that interrupt mail delivery ask for a confirmation first.',
         'commands': ['maintenance-set', 'milter-chain-set', 'extra-service-set', 'update-now', 'mariadb-repair',
                      'reboot', 'halt'],
         'show': ['smtpd_milters', 'extra_services'],
         'notes': {'maintenance-set': 'Stops the service monitor from restarting services.'}}]),
]
PAGES = {page['slug']: page for _, pages in NAV for page in pages}
# A command missing from NAV stays reachable here, so a new efactl command cannot get lost.
FALLBACK_PAGE = 'maint'
# Display only: arguments with a fixed set of values, by their label in the schema.
CHOICES = {'add or remove': ('Action', ('add', 'remove')), 'allow or block': ('List', ('allow', 'block')),
           'auto or manual': ('IPv4 method', ('auto', 'manual')),
           'IPv6: auto, manual or ignore': ('IPv6 method', ('auto', 'manual', 'ignore'))}
# Which current value fills a form field: command, argument, key in `efactl settings` or a read command's output.
PREFILL = {
    'relay-networks-set': {'networks': 'relay_networks'}, 'smarthost-set': {'host': 'smarthost'},
    'message-size-set': {'megabytes': 'message_size_limit_mb'},
    'spam-scores-set': {'greylist': 'greylist', 'mark': 'rewrite_subject', 'reject': 'reject'},
    'subject-set': {'text': 'subject_tag'}, 'admin-email-set': {'email': 'admin_email'},
    'maintenance-set': {'mode': 'maintenance_mode'}, 'greylisting-set': {'mode': 'greylisting'},
    'recipient-verification-set': {'mode': 'recipient_verification'}, 'fail2ban-set': {'mode': 'fail2ban'},
    'backup-set': {'mode': 'auto_backup'}, 'quarantine-set': {'mode': 'quarantine'},
    'dmarc-reports-set': {'mode': 'dmarc_reports'}, 'quarantine-days-set': {'days': 'quarantine_days'},
    'maillog-retention-set': {'days': 'maillog_days'}, 'maillog-size-set': {'megabytes': 'maillog_max_mb'},
    'network-set': {'hostname': 'hostname', 'method': 'ipv4.method', 'address': 'ipv4.addresses',
                    'gateway': 'ipv4.gateway'},
}
# Title of each 'show' value, and for those with a remove button: command, argument for the entry, fixed arguments.
CURRENT = {
    'transports': ('Current domains', 'transport-set', 'domain', {}),
    'sender_allow': ('Allowed senders', 'sender-list-set', 'address', {'list': 'allow'}),
    'sender_block': ('Blocked senders', 'sender-list-set', 'address', {'list': 'block'}),
    'dns_zones': ('Current internal DNS zones', 'dns-zone-set', 'zone', {}),
    'extra_services': ('Watched extra services', 'extra-service-set', 'name', {}),
    'smtpd_milters': ('Current milter order',),
}
DANGER = {'reboot', 'halt', 'restore', 'quarantine-delete', 'quarantine-purge', 'maillog-purge'}

BLOCK = '{% block %}{% endblock %}'
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>eFa-next</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{--lime:#C0CF48;--gray:#646563;--ink:#3f444a;--bg:#f4f5f2;--card:#fff;--line:#e2e4dc;--ok:#3d8b4a;--warn:#c98a00;--bad:#b83a3a}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--ink);display:flex;min-height:100vh;flex-direction:column}
.wrap{display:flex;flex:1}
aside{width:260px;background:var(--ink);color:#e9ebe4;padding:18px 0;flex-shrink:0}
.brand{display:block;padding:0 22px 12px;background:var(--ink)}
.brand svg{display:block;width:100%;height:auto}
.brand .text{fill:#f2f2f2}.brand .line{stroke:#f2f2f2}
aside h4{margin:18px 22px 6px;font-size:11px;text-transform:uppercase;letter-spacing:1.2px;color:#b4baa3}
aside a.nav{display:block;padding:8px 22px;color:#e9ebe4;text-decoration:none;border-left:3px solid transparent}
aside a.nav:hover{background:rgba(255,255,255,.06)}
aside a.nav.on{background:rgba(192,207,72,.14);border-left-color:var(--lime);color:#fff}
aside form{padding:18px 22px 0}
main{flex:1;min-width:0;padding:28px 36px;max-width:980px}
main.solo{flex:none;width:100%;max-width:420px;margin:auto;padding:16px}
main.solo .brand{padding:18px 22px;border-radius:12px 12px 0 0}
main.solo .card{border-radius:0 0 12px 12px}
main.solo .row{grid-template-columns:1fr}
h1{margin:0 0 4px;font-size:26px}
.sub{color:var(--gray);margin:0 0 22px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin-bottom:24px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.tile b{display:block;font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--gray)}
.tile .v{font-size:20px;font-weight:600;margin-top:4px}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;background:var(--ok)}
.dot.w{background:var(--warn)}.dot.b{background:var(--bad)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:18px;overflow-x:auto}
.card h2{margin:0 0 2px;font-size:17px}
.card p.h{margin:0 0 14px;color:var(--gray);font-size:13px}
.card.done{border-color:var(--lime);border-width:2px}
.err{color:var(--bad);font-weight:500;overflow-wrap:anywhere}
.row{display:grid;grid-template-columns:230px 1fr;gap:6px 18px;align-items:center;margin:10px 0}
.row label{font-weight:500}
input[type=text],input[type=password],select{width:100%;max-width:380px;padding:8px 10px;border:1px solid #cfd2c6;border-radius:8px;font:inherit;background:#fff}
input:focus,select:focus{outline:2px solid var(--lime);border-color:var(--lime)}
.sw{position:relative;width:44px;height:24px;display:inline-block}
.sw input{position:absolute;opacity:0;width:0;height:0}
.sw i{position:absolute;inset:0;background:#c5c8bd;border-radius:24px;transition:.15s}
.sw i:before{content:"";position:absolute;width:18px;height:18px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.15s}
.sw input:checked+i{background:var(--lime)}
.sw input:checked+i:before{transform:translateX(20px)}
.sw input:focus-visible+i{outline:2px solid var(--ink);outline-offset:2px}
.btns{display:flex;gap:10px;margin-top:14px;flex-wrap:wrap}
button,a.btn{font:inherit;padding:8px 18px;border-radius:8px;border:1px solid var(--line);background:#fff;color:var(--ink);cursor:pointer;text-decoration:none;display:inline-block}
button.p{background:var(--lime);border-color:var(--lime);color:#2a2e22;font-weight:600}
button.d,a.btn.d{color:var(--bad);border-color:#e4b9b9}
td form{display:inline}td button,td a.btn{padding:4px 12px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:var(--gray);padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:9px 8px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
pre{background:#eef0e8;padding:10px;border-radius:8px;overflow:auto;font-size:13px;margin:0}
.pill{display:inline-block;padding:1px 9px;border-radius:12px;font-size:12px;background:#eef1d2}
.pill.g{background:#dcefdf;color:#2c6b38}
.pill.w{background:#fbefcf;color:#8a6200}
footer{background:#fff;border-top:1px solid var(--line);padding:14px 36px;display:flex;gap:18px;align-items:center;flex-wrap:wrap;font-size:13px;color:var(--gray)}
footer .mie{display:flex;align-items:center;gap:8px;font-weight:600;color:var(--ink)}
footer svg{height:20px;width:auto;border-radius:2px;box-shadow:0 0 0 1px #0002}
footer a{color:var(--ink)}
@media(max-width:760px){.wrap{flex-direction:column}aside{width:100%}main{padding:20px 16px}.row{grid-template-columns:1fr}footer{padding:14px 16px}}
</style></head><body><div class="wrap">{% block %}{% endblock %}</div>
<footer><span class="mie">""" + FLAG_AT + FLAG_EU + """ Made in Europe, Austria</span>
<span>eFa-next is open source: <a href=\"""" + REPO_URL + """\">github.com/MarkusLorber/eFa-next</a></span></footer>
</body></html>"""
SOLO = '<main class="solo">' + BRAND
FAILED = PAGE.replace(BLOCK, SOLO + """<div class="card"><p class="err" role="alert">{{ error }}</p></div></main>""")
LOGIN = PAGE.replace(BLOCK, SOLO + """<div class="card">
{% if error %}<p class="err" role="alert">{{ error }}</p>{% endif %}<form method="post">
<input type="hidden" name="csrf" value="{{ csrf }}"><div class="row"><label for="password">Password</label>
<input type="password" id="password" name="password" autofocus required></div>
<div class="btns"><button class="p">Log in</button></div></form></div></main>""")
MAIN = PAGE.replace(BLOCK, """
{%- macro show(value, key='') -%}
  {%- if value is none or value == '' -%}<span class="pill">none</span>
  {%- elif value is sameas true -%}<span class="pill g">yes</span>
  {%- elif value is sameas false -%}<span class="pill w">no</span>
  {%- elif key in ('arrived', 'checked_at') and value is number -%}{{ value|when }}
  {%- elif value is string -%}{% if value.count('\\n') %}<pre>{{ value }}</pre>{% else %}{{ value }}{% endif %}
  {%- elif value is mapping -%}
    {%- if not value -%}<span class="pill">none</span>{%- else -%}<table>
    {%- for k, v in value.items() -%}<tr><th>{{ k|replace('_', ' ') }}</th><td>{{ show(v, k) }}</td></tr>{%- endfor -%}
    </table>{%- endif -%}
  {%- elif value is sequence -%}
    {%- if not value -%}<span class="pill">none</span>
    {%- elif value[0] is mapping -%}<table><tr>{% for k in value[0] %}<th>{{ k|replace('_', ' ') }}</th>{% endfor %}</tr>
      {%- for item in value -%}<tr>{% for k in value[0] %}<td>{{ show(item.get(k), k) }}</td>{% endfor %}</tr>{%- endfor -%}
    </table>
    {%- else -%}{% for item in value %}<div>{{ show(item) }}</div>{% endfor %}{%- endif -%}
  {%- else -%}{{ value }}{%- endif -%}
{%- endmacro -%}
{%- macro post(name, label, fields, cls='') -%}
  <form method="post" action="{{ url_for('run', name=name) }}"><input type="hidden" name="csrf" value="{{ csrf }}">
  {%- for k, v in fields.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor -%}
  <button{% if cls %} class="{{ cls }}"{% endif %}>{{ label }}</button></form>
{%- endmacro -%}
{%- macro field(name, arg) -%}
  {%- set id = name ~ '-' ~ arg.name -%}{%- set value = current(name, arg) -%}
  <div class="row">
  {%- if arg.label == 'on or off' -%}
    <label for="{{ id }}">Active</label>
    {#- The hidden field comes second: a ticked switch sends on first, an unticked one only off. -#}
    <div><label class="sw"><input type="checkbox" id="{{ id }}" name="{{ arg.name }}" value="on"
    {%- if value is sameas true %} checked{% endif %}><i></i></label>
    <input type="hidden" name="{{ arg.name }}" value="off"></div>
  {%- elif arg.label in choices -%}
    <label for="{{ id }}">{{ choices[arg.label][0] }}</label>
    <select id="{{ id }}" name="{{ arg.name }}">{% for option in choices[arg.label][1] %}<option
    {%- if option == value %} selected{% endif %}>{{ option }}</option>{% endfor %}</select>
  {%- else -%}
    <label for="{{ id }}">{{ arg.label }}</label>
    <input type="text" id="{{ id }}" name="{{ arg.name }}" value="{{ value }}"{% if arg.required %} required{% endif %}>
  {%- endif -%}
  </div>
{%- endmacro -%}
<aside>""" + BRAND + """
{% for group, pages in nav %}<h4>{{ group }}</h4>{% for p in pages %}<a class="nav{% if p.slug == page.slug %} on{% endif %}"
{%- if p.slug == page.slug %} aria-current="page"{% endif %} href="{{ url_for('show_page', slug=p.slug) }}">{{ p.title }}</a>{% endfor %}{% endfor %}
<form method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><button>Log out</button></form>
</aside><main><h1>{{ page.title }}</h1><p class="sub">{{ page.sub }}</p>
{% if error %}<div class="card"><p class="err" role="alert">{{ error }}</p></div>{% endif %}
{% if result is not none %}<div class="card done"><h2>{{ result_title }}</h2><p class="h">Done.</p>{{ show(result) }}</div>{% endif %}
{% if tiles %}<div class="tiles">{% for label, value, dot in tiles %}<div class="tile"><b>{{ label }}</b>
<div class="v">{% if dot is not none %}<span class="dot {{ dot }}"></span>{% endif %}{{ value }}</div></div>{% endfor %}</div>
{% if attention %}<div class="card"><h2>Needs attention</h2><table>{% for text, slug in attention %}<tr><td><span class="dot w"></span>{{ text }}</td>
<td>{% if slug %}<a href="{{ url_for('show_page', slug=slug) }}">Open {{ pages_by_slug[slug].title }}</a>{% endif %}</td></tr>{% endfor %}</table></div>{% endif %}{% endif %}
{% for key in page.show or [] %}{% if key in values %}{% set info = current_info[key] %}<div class="card"><h2>{{ info[0] }}</h2>
{% if info|length == 1 %}{{ show(values[key]) }}
{% elif not values[key] %}<span class="pill">none</span>
{% else %}<table>{% for entry in values[key] %}<tr><td>{{ entry }}</td>{% if values[key] is mapping %}<td>{{ show(values[key][entry]) }}</td>{% endif %}
<td>{{ post(info[1], 'Remove', dict(info[3], action='remove', **{info[2]: entry}), 'd') }}</td></tr>{% endfor %}</table>{% endif %}</div>{% endif %}{% endfor %}
{% for name in names %}{% set cmd = commands[name] %}
{#- subject-get only fills the form of subject-set. -#}
{% if name != 'subject-get' %}<div class="card" id="{{ name }}"><h2>{{ cmd.title }}</h2>
{% if page.notes and name in page.notes %}<p class="h">{{ page.notes[name] }}</p>{% endif %}
{% if name in loaded %}{% set ok, output = loaded[name] %}
  {% if not ok %}<p class="err">{{ output.error }}</p>
  {% elif name == 'quarantine-list' %}{% if output.quarantine %}<table><tr><th>Received</th><th>From</th><th>To</th><th>Size</th><th>Queue ID</th><th></th></tr>
    {% for mail in output.quarantine %}<tr><td>{{ show(mail.arrived, 'arrived') }}</td><td>{{ show(mail.sender) }}</td><td>{{ show(mail.recipients) }}</td>
    <td>{{ (mail.size or 0)|filesizeformat }}</td><td>{{ mail.id }}</td><td>{{ post('quarantine-release', 'Deliver', {'id': mail.id}) }}
    {{ post('quarantine-show', 'Headers', {'id': mail.id}) }}
    <a class="btn d" href="{{ url_for('show_page', slug='quar', id=mail.id) }}#quarantine-delete">Delete</a></td></tr>{% endfor %}</table>
    {% else %}<span class="pill">empty</span>{% endif %}
  {% elif name == 'backup-list' %}{% if output.backups %}<table>{% for backup in output.backups %}<tr><td>{{ backup }}</td>
    <td><a class="btn" href="{{ url_for('show_page', slug='bak', name=backup) }}#restore">Restore</a></td></tr>{% endfor %}</table>
    {% else %}<span class="pill">none</span>{% endif %}
  {% else %}{{ show(output) }}{% endif %}
{% else %}<form method="post" action="{{ url_for('run', name=name) }}"><input type="hidden" name="csrf" value="{{ csrf }}">
  {% for arg in cmd.args %}{{ field(name, arg) }}{% endfor %}
  <div class="btns"><button class="{{ 'd' if name in danger else 'p' }}">{{ ('Run' if not cmd.args else 'Apply') if cmd.writes else 'Show' }}</button></div></form>
{% endif %}</div>{% endif %}{% endfor %}</main>""")


def efactl(*args):
    """Runs efactl without a shell, so form input stays a plain argument."""
    try:
        done = subprocess.run(EFACTL + list(args), capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        app.logger.error('efactl %s timed out', args[:1])
        return False, {'error': 'efactl timed out, see the log.'}
    try:
        return done.returncode == 0, json.loads(done.stdout)
    except ValueError:
        app.logger.error('efactl %s failed: %s', args[:1], done.stderr)
        return False, {'error': 'efactl failed, see the log.'}


def csrf_token():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_urlsafe(32)
    return session['csrf']


@app.before_request
def protect():
    if request.method == 'POST' and not hmac.compare_digest(request.form.get('csrf', ''), session.get('csrf', '')
                                                            or secrets.token_urlsafe(8)):
        abort(403)
    if request.endpoint != 'login' and not session.get('admin'):
        return redirect(url_for('login'))


@app.after_request
def harden(response):
    response.headers.update({'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff',
                             'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'",
                             'Cache-Control': 'no-store'})
    return response


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        client = request.headers.get('X-Real-IP', request.remote_addr)
        count, since = login_failures.get(client, (0, 0))
        if count >= MAX_LOGIN_FAILURES and time.time() - since < LOCKOUT_SECONDS:
            error = 'Too many failed logins, try again later.'
        else:
            try:
                with open(PASSWORD_FILE) as f:
                    stored = f.read().strip()
            except OSError:
                stored = ''
            if stored and check_password_hash(stored, request.form.get('password', '')):
                login_failures.pop(client, None)
                session.clear()
                session.permanent = True
                session['admin'] = True
                return redirect(url_for('index'))
            login_failures[client] = (count + 1, time.time())
            error = 'Wrong password.'
    return render_template_string(LOGIN, csrf=csrf_token(), error=error)


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.template_filter('when')
def when(stamp):
    return time.strftime('%Y-%m-%d %H:%M', time.localtime(stamp))


def page_of(name):
    return next((slug for slug, page in PAGES.items() if name in page['commands']), FALLBACK_PAGE)


def dashboard(loaded):
    """Tiles and warnings of the dashboard, only from what the read commands returned."""
    status, settings, held, backups, dkim = (loaded[name][1] if loaded.get(name, (False,))[0] else None for name in
                                             ('status', 'settings', 'quarantine-list', 'backup-list', 'dkim-check'))
    down = status['down'] if status else []
    services = [name for name in down if not name.startswith('milter:')]
    milters = [name for name in down if name.startswith('milter:')]
    tiles = [('Mail system', 'Unknown', 'w') if not status else
             ('Mail system', f'{len(services)} down', 'b') if services else ('Mail system', 'Running', ''),
             ('Milters', 'Unknown', 'w') if not status else
             ('Milters', f'{len(milters)} not answering', 'b') if milters else ('Milters', 'All answering', '')]
    if settings and not settings['quarantine']:
        tiles.append(('Quarantine', 'Off', None))
    else:
        count = len(held['quarantine']) if held else 0
        tiles.append(('Quarantine', f"{count} message{'' if count == 1 else 's'}" if held else 'Unknown',
                      None if held else 'w'))
    names = backups['backups'] if backups else []
    # Shows the plain file name if it does not follow the usual pattern.
    last = re.sub(r'^efa-backup-(\d{4})(\d\d)(\d\d)-(\d\d)(\d\d).*', r'\1-\2-\3 \4:\5', names[-1]) if names else 'None'
    tiles.append(('Last backup', last, '' if names else 'w'))
    attention = [(f'{name} is down', None) for name in down]
    if backups and not names:
        attention.append(('No backup yet', 'bak'))
    if settings and not settings['auto_backup']:
        attention.append(('Automatic backup is off', 'bak'))
    if settings and settings['maintenance_mode']:
        attention.append(('Maintenance mode is on', 'maint'))
    attention += [(warning, 'dkim') for warning in (dkim or {}).get('warnings', [])]
    return tiles, attention


def page_view(slug, result=None, result_title=None, error=None):
    page = PAGES[slug]
    ok, commands = efactl('schema')
    if not ok:
        return render_template_string(FAILED, error=commands.get('error')), 500
    names = [name for name in page['commands'] if name in commands]
    if slug == FALLBACK_PAGE:
        listed = {name for other in PAGES.values() for name in other['commands']}
        names += [name for name in commands if name not in listed]
    loaded = {'settings': efactl('settings')}
    for name in names + page.get('load', []):
        if name not in loaded and name in commands and not commands[name]['writes'] and not commands[name]['args']:
            loaded[name] = efactl(name)
    if not loaded['settings'][0]:
        error = error or loaded['settings'][1].get('error')
    values = {}
    # Settings last: quarantine-list also returns a key named quarantine.
    for ok, output in reversed(list(loaded.values())):
        if ok:
            values.update(output)
    values.update(values.get('spam_scores', {}))

    def current(name, arg):
        if arg['name'] in request.args:
            return request.args[arg['name']]
        value = values.get(PREFILL.get(name, {}).get(arg['name']), arg.get('default') or '')
        return ' '.join(value) if isinstance(value, list) else value

    tiles, attention = dashboard(loaded) if slug == 'dash' else (None, None)
    return render_template_string(MAIN, nav=NAV, page=page, names=names, commands=commands, loaded=loaded, values=values,
                                  current=current, choices=CHOICES, current_info=CURRENT, danger=DANGER, tiles=tiles,
                                  attention=attention, pages_by_slug=PAGES, csrf=csrf_token(), result=result,
                                  result_title=result_title, error=error)


@app.route('/')
def index():
    return page_view('dash')


@app.route('/p/<slug>')
def show_page(slug):
    if slug not in PAGES:
        abort(404)
    return page_view(slug)


@app.route('/run/<name>', methods=['POST'])
def run(name):
    ok, commands = efactl('schema')
    if not ok or name not in commands:
        abort(404)
    args = [name]
    for arg in commands[name]['args']:
        args += [f"--{arg['name']}={request.form.get(arg['name'], '')}"]
    ok, output = efactl(*args)
    if not ok:
        return page_view(page_of(name), error=output.get('error'))
    return page_view(page_of(name), result=output, result_title=commands[name]['title'])


def self_test():
    global efactl
    calls = []
    outputs = {
        'schema': {
            'status': {'title': 'Status', 'args': [], 'writes': False},
            'settings': {'title': 'Settings: show', 'args': [], 'writes': False},
            'quarantine-list': {'title': 'Quarantine: list', 'args': [], 'writes': False},
            'quarantine-delete': {'title': 'Quarantine: delete', 'writes': True,
                                  'args': [{'name': 'id', 'label': 'Queue ID', 'required': True},
                                           {'name': 'confirm', 'label': 'Type yes to confirm', 'required': True}]},
            'backup-list': {'title': 'Backup: list', 'args': [], 'writes': False},
            'dkim-check': {'title': 'DKIM keys', 'args': [], 'writes': False},
            'greylisting-set': {'title': 'Greylisting', 'writes': True,
                                'args': [{'name': 'mode', 'label': 'on or off', 'required': True}]},
            'spam-scores-set': {'title': 'Spam scores', 'writes': True,
                                'args': [{'name': 'mark', 'label': 'Mark from', 'required': True, 'default': '6'}]},
            'transport-set': {'title': 'Domains', 'writes': True,
                              'args': [{'name': 'domain', 'label': 'Domain', 'required': True},
                                       {'name': 'action', 'label': 'add or remove', 'required': True}]},
            'brand-new': {'title': 'Brand new command', 'args': [], 'writes': True}},
        'status': {'status': 'down', 'down': ['service:rspamd', 'milter:8999'], 'checks': {}, 'checked_at': 0},
        'settings': {'quarantine': True, 'auto_backup': True, 'maintenance_mode': False, 'greylisting': True,
                     'spam_scores': {'rewrite_subject': '7'}, 'transports': {'a.example': 'b.example:25'}},
        'quarantine-list': {'quarantine': [{'id': 'ABC', 'sender': '<b>x', 'recipients': ['a@b.example'],
                                            'arrived': 0, 'size': 10}], 'quarantine_days': 14},
        'backup-list': {'backups': ['efa-backup-20261101-020000.tar.gz']},
        'dkim-check': {'keys': [], 'warnings': ['a.example: no ED25519 key.']},
    }
    failing = []

    def fake(*args):
        calls.append(args)
        if args[0] in failing:
            return False, {'error': f'{args[0]} failed'}
        return True, outputs.get(args[0], {'done': True})

    efactl = fake
    app.secret_key = b'self-test'
    client = app.test_client()
    https = {'base_url': 'https://localhost'}
    assert client.get('/', **https).status_code == 302
    login_page = client.get('/login', **https).get_data(as_text=True)
    assert 'Made in Europe, Austria' in login_page and REPO_URL in login_page and 'aria-label="eFa-next"' in login_page
    with client.session_transaction(**https) as sess:
        sess.update(admin=True, csrf='token')
    assert client.post('/run/greylisting-set', data={'mode': 'on'}, **https).status_code == 403
    assert client.get('/p/nope', **https).status_code == 404

    dash = client.get('/', **https).get_data(as_text=True)
    assert '1 down' in dash and '1 not answering' in dash and '1 message<' in dash and '2026-11-01 02:00' in dash
    assert 'service:rspamd is down' in dash and 'no ED25519 key' in dash and 'European Union' in dash

    # An unticked switch posts only the hidden off, a ticked one posts on first.
    spam = client.get('/p/spam', **https).get_data(as_text=True)
    assert 'value="7"' in spam and ' checked' in spam and spam.index('value="on"') < spam.index('value="off"')
    client.post('/run/greylisting-set', data={'csrf': 'token', 'mode': ['on', 'off']}, **https)
    assert ('greylisting-set', '--mode=on') in calls
    client.post('/run/greylisting-set', data={'csrf': 'token', 'mode': 'off'}, **https)
    assert ('greylisting-set', '--mode=off') in calls

    flow = client.get('/p/flow', **https).get_data(as_text=True)
    assert 'a.example' in flow and '/run/transport-set' in flow and '<option>add</option>' in flow
    quarantine = client.get('/p/quar', **https).get_data(as_text=True)
    assert '<b>x' not in quarantine and '&lt;b&gt;x' in quarantine
    assert 'id="quarantine-delete-id" name="id" value="ABC"' in client.get('/p/quar?id=ABC', **https).get_data(as_text=True)
    # A command nobody put on a page stays reachable, and its result lands on that page.
    assert 'Brand new command' in client.get('/p/maint', **https).get_data(as_text=True)
    assert 'Done.' in client.post('/run/brand-new', data={'csrf': 'token'}, **https).get_data(as_text=True)
    assert page_of('brand-new') == FALLBACK_PAGE and page_of('transport-set') == 'flow'

    failing += ['settings', 'status']
    assert 'settings failed' in client.get('/p/flow', **https).get_data(as_text=True)
    assert 'Unknown' in client.get('/', **https).get_data(as_text=True)
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
        sys.exit(0)
    with open(SECRET_FILE, 'rb') as secret:
        app.secret_key = secret.read()
    serve(app, host='127.0.0.1', port=8080, threads=4)
