#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""eFa web interface. Holds no eFa logic: forms come from `efactl schema`, actions call efactl.

Runs as user efa-web behind nginx on 127.0.0.1:8080. sudo allows only /usr/sbin/efactl.
"""
from html import escape as html_escape
import base64
import collections
import concurrent.futures
import functools
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

from flask import Flask, Response, abort, g, has_request_context, jsonify, redirect, render_template_string, request, session, url_for
from itsdangerous import BadSignature, URLSafeTimedSerializer
from waitress import serve
from werkzeug.security import check_password_hash

WEB_DIR = os.environ.get('EFA_ETC', '/etc') + '/efa-web'
PASSWORD_FILE = WEB_DIR + '/admin.pw'
SECRET_FILE = WEB_DIR + '/secret.key'
EFACTL = ['sudo', '-n', '/usr/sbin/efactl']
# efactl-runner: efactl loaded once, one fork per call instead of a new Python behind sudo; sudo when it is not there.
RUNNER_SOCKET = os.environ.get('EFA_RUNNER_SOCKET', '/run/efactl-runner/runner.sock')
# 5q: the same program runs a second time as the user portal (efa-portal.service): its own system user, no sudo, its own
# session key and cookie, only the routes of the users, and efactl only through efa-portal-helper with a few fixed commands.
PORTAL = os.environ.get('EFA_WEB_MODE') == 'portal'
PORTAL_SOCKET = os.environ.get('EFA_PORTAL_SOCKET', '/run/efa-portal-helper/helper.sock')
PORTAL_SECRET = os.environ.get('EFA_ETC', '/etc') + '/efa-portal/secret.key'
PORTAL_ROUTES = {'login': '/portal/login', 'logout': '/portal/logout', 'index': '/portal/', 'show_page': '/portal/p/<slug>', 'run': '/portal/run/<name>',
                 'copy_js': '/portal/copy.js', 'favicon': '/portal/favicon.svg', 'brand_logo': '/portal/brand/logo', 'quarantine_link': '/q/<token>', 'link_check': '/l/<token>'}
SESSION_MAX_AGE = 3600
MAX_LOGIN_FAILURES = 5
LOCKOUT_SECONDS = 300
# A3: the largest upload the interface takes. A backup (database, keys, config, gpg) is the biggest; every other upload checks
# its own smaller limit. The hard cap stops an endless upload from filling memory or disk.
MAX_UPLOAD = 8 * 1024 * 1024 * 1024

app = Flask(__name__)
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
                  PERMANENT_SESSION_LIFETIME=SESSION_MAX_AGE, SESSION_COOKIE_NAME='efa_portal' if PORTAL else 'session',
                  MAX_CONTENT_LENGTH=MAX_UPLOAD)
login_failures = {}
# The session cookie is only signed, so logout could not end it without this list. A restart logs everyone out.
active_sessions = {}
# When each session was last checked with efactl: ended or locked elsewhere means out within this time.
session_checked = {}
SESSION_CHECK_SECONDS = 15

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
BRAND = '<a class="brand" href="' + REPO_URL + '" target="_blank" rel="noopener noreferrer">' + LOGO + '</a>'
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
# The source tree first, so a self test there uses its own libraries, not the installed ones.
sys.path[:0] = [os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../lib/eFa/python'), '/usr/lib/eFa/python']
from efa_nav import FORM_SOURCE, MOVED, NAV, NOTE_SHORT, PAGES, STATUS_OF, form_value  # noqa: E402  the menu, shared with efa-tui
import efa_i18n  # noqa: E402
import efa_legal  # noqa: E402
import efa_links  # noqa: E402
# Also the start page of the role user, who has no dashboard.
USER_PAGE = 'held'
# A command missing from NAV stays reachable here, so a new efactl command cannot get lost.
FALLBACK_PAGE = 'maint'
# Display only: arguments with a fixed set of values, by their label in the schema.
POLICIES = ('none', 'quarantine', 'reject')
CHOICES = {'RSA bits': ('RSA key size', ('2048', '3072', '4096')), 'zone or csv': ('Format', ('zone', 'csv')),
           'Interval in months': ('Interval in months', ('3', '6', '12', '24')),
           'rsa, ed25519 or arc': ('Key type', ('rsa', 'ed25519', 'arc')),
           'on, off or default': ('Mode', ('default', 'on', 'off')), 'ARC key': ('ARC key', ('dkim', 'own')),
           'Policy (p)': ('Policy (p)', POLICIES),
           'Policy for subdomains (sp)': ('Policy for subdomains (sp)', ('',) + POLICIES),
           'Policy for non-existent subdomains (np)': ('Policy for non-existent subdomains (np)', ('',) + POLICIES),
           'DKIM alignment (adkim)': ('DKIM alignment (adkim)', ('r', 's')),
           'SPF alignment (aspf)': ('SPF alignment (aspf)', ('r', 's')), 'Test mode (t)': ('Test mode (t)', ('n', 'y')),
           'Failure report options (fo)': ('Failure report options (fo)', ('0', '1', 'd', 's')),
           'off, read-only or full': ('Mode', ('off', 'read-only', 'full')),
           'Test group': ('Test group', ('all', 'dns', 'smtp', 'https', 'http', 'ntp', 'inbound')),
           'Mail the admin on a failed check: yes or no': ('Mail the admin on a failed check', ('yes', 'no')),
           'Only try it: yes or empty': ('Only try it, install nothing', ('', 'yes')),
           'set or remove': ('Action', ('set', 'remove')), 'off, notify or auto': ('Mode', ('off', 'notify', 'auto')),
           'add or remove': ('Action', ('add', 'remove')), 'allow or block': ('List', ('allow', 'block')),
           'Blocklist type': ('Type', ('ip', 'helo', 'domain', 'url')),
           'auto or manual': ('IPv4 method', ('auto', 'manual')),
           'IPv6: auto, manual or ignore': ('IPv6 method', ('auto', 'manual', 'ignore'))}
# Which current value fills a form field: command, argument, key in `efactl settings` or a read command's output.
PREFILL = {
    'message-search': {'limit': 'page_size'}, 'maillog-search': {'limit': 'page_size'},
    'relay-networks-set': {'networks': 'relay_networks'}, 'smarthost-set': {'host': 'smarthost'},
    'message-size-set': {'megabytes': 'message_size_limit_mb'},
    'spam-scores-set': {'greylist': 'greylist', 'mark': 'rewrite_subject', 'reject': 'reject'},
    'subject-set': {'text': 'subject_tag'}, 'admin-email-set': {'email': 'admin_email'}, 'subject-display-set': {'mode': 'show_subjects'}, 'headers-store-set': {'mode': 'store_headers', 'days': 'headers_days'},
    'maintenance-set': {'mode': 'maintenance_mode'}, 'greylisting-set': {'mode': 'greylisting'},
    'recipient-verification-set': {'mode': 'recipient_verification'}, 'fail2ban-set': {'mode': 'fail2ban'},
    'backup-set': {'mode': 'auto_backup'}, 'quarantine-set': {'mode': 'quarantine'},
    'dmarc-reports-set': {'mode': 'dmarc_reports'}, 'quarantine-days-set': {'days': 'quarantine_days'},
    'maillog-retention-set': {'days': 'maillog_days'}, 'maillog-size-set': {'megabytes': 'maillog_max_mb'},
    'rotation-all-set': {'mode': 'rotation_all', 'interval': 'rotation_interval', 'horizon': 'rotation_horizon',
                         'bits': 'rotation_bits'},
    'resolver-set': {'ipv4_1': 'ipv4_1', 'ipv4_2': 'ipv4_2', 'ipv6_1': 'ipv6_1', 'ipv6_2': 'ipv6_2',
                     'threshold': 'threshold'},
    'rspamd-sso-set': {'mode': 'rspamd_sso'},
    'firewall-set': {'allowlist': 'firewall_allowlist', 'submission': 'firewall_submission'},
    'firewall-guard-set': {'mode': 'guard'},
    'sanesecurity-set': {'mode': 'sanesecurity'}, 'mailreport-set': {'mode': 'mailreport_daily'},
    'load-set': {'percent': 'load_percent', 'minutes': 'load_minutes'},
    'firewall-probe-set': {'url': 'firewall_probe_url'},
    'arc-all-set': {'mode': 'arc_all', 'key': 'arc_all_key', 'bits': 'arc_all_bits'},
    'autoupdate-set': {'mode': 'mode', 'days': 'days', 'time': 'time'},
    'network-set': {'hostname': 'hostname', 'method': 'ipv4.method', 'address': 'ipv4.addresses',
                    'gateway': 'ipv4.gateway'},
}
# Title of each 'show' value, and for those with a remove button: command, argument for the entry, fixed arguments.
OPTION_TEXT = {'dkim': 'Use DKIM RSA key', 'own': 'Own key', '': 'not set', 'r': 'relaxed', 's': 'strict', 'n': 'no', 'y': 'yes'}
CURRENT = {
    'transports': ('Current domains', 'transport-set', 'domain', {}),
    'sender_allow': ('Allowed senders', 'sender-list-set', 'address', {'list': 'allow'}),
    'sender_block': ('Blocked senders', 'sender-list-set', 'address', {'list': 'block'}),
    'dns_zones': ('Current internal DNS zones', 'dns-zone-set', 'zone', {}),
    'extra_services': ('Watched extra services', 'extra-service-set', 'name', {}),
    'smtpd_milters': ('Current milter order',),
}
# 9l start page picture: off until a better drawing exists; only this switch turns it back on, there is no option in the UI.
FLOW_PICTURE = False
# These run from buttons or popups of another card; subject-get only fills a form.
HIDDEN_CARDS = {'mail-check', 'disclaimer-import', 'disclaimer-export', 'flow-status', 'flow-set', 'neural-settings', 'ml-settings', 'dkim-generate', 'dkim-generate-ed25519', 'audit-note', 'mail-show', 'uq-content', 'quarantine-content', 'session-open', 'session-check', 'events-run', 'uq-link-view', 'uq-link-use', 'uq-show', 'uq-release', 'uq-request', 'uq-sender', 'oidc-start', 'oidc-finish', 'user-verify', 'token-check', 'audit-purge', 'metrics', 'subject-get', 'dmarc-record-history', 'maillog-live', 'relay-networks-set', 'relay-networks-remove',
                'relay-networks-apply', 'relay-networks-discard', 'load-notify', 'firewall-revert', 'firewall-guard-run', 'web-harden', 'audit-rspamd', 'update-system-run', 'update-post-boot', 'update-now', 'backup-download', 'backup-read', 'backup-import', 'update-run', 'sender-add', 'sender-remove', 'sender-move', 'sender-list-set', 'sanesecurity-run', 'rbl-apply', 'mailreport-run'}
DANGER = {'dkim-remove', 'reboot', 'halt', 'restore', 'update-rollback', 'quarantine-delete', 'quarantine-purge', 'maillog-purge'}

BLOCK = '{% block %}{% endblock %}'
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>eFa-next: open source mail server protection</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><link rel="icon" href="{{ url_for('favicon') }}" type="image/svg+xml">
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
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
small.now{grid-column:2;color:#5b6157;margin-top:-4px}
@media(max-width:760px){small.now{grid-column:1}}
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
a.tile,a.cardlink{display:block;color:inherit;text-decoration:none}a.tile:hover,a.cardlink:hover .card,details.tile[open]{border-color:var(--lime)}
a.tile:focus-visible,a.cardlink:focus-visible,details.tile>summary:focus-visible{outline:2px solid var(--ink);outline-offset:2px}
a.tile .v:after{content:" ›";color:var(--gray)}details.tile>summary{cursor:pointer;list-style:none}details.tile>summary::-webkit-details-marker{display:none}
details.tile p{margin:8px 0 0;font-size:13px;color:var(--gray)}.tile .note{font-size:12px;color:var(--gray);margin-top:4px;overflow-wrap:anywhere}
svg.chart,svg.flow{width:100%;height:auto;display:block}svg.flow{max-height:340px}svg.chart rect.m{fill:#c5c8bd}svg.chart rect.s{fill:var(--warn)}svg.chart rect.v{fill:var(--bad)}svg.chart line{stroke:var(--line)}
.legend{font-size:12px;color:var(--gray);margin:6px 0 0}.legend .key{display:inline-block;width:10px;height:10px;margin:0 4px 0 10px;border-radius:2px}
.legend .key.m{background:#c5c8bd;margin-left:0}.legend .key.s{background:var(--warn)}.legend .key.v{background:var(--bad)}.legend .span{float:right}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;background:var(--ok)}
.dot.w{background:var(--warn)}.dot.b{background:var(--bad)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:18px;overflow-x:auto}
.card h2{margin:0 0 2px;font-size:17px}
details.section{margin:0 0 10px}details.section>summary{cursor:pointer;font-size:19px;font-weight:600;margin:18px 0 10px;color:var(--ink)}
details.help{margin:0 0 12px;font-size:13px;color:var(--gray)}details.help>summary{cursor:pointer;color:var(--gray)}
.live-table td.subj{max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.sub2{display:none;font-size:12px;color:var(--gray)}
@media (max-width:600px){.live-table .subj{display:none}.live-table .sub2{display:block}
table.stack,table.stack tbody,table.stack tr,table.stack td{display:block;width:100%}table.stack tr:first-child{display:none}
table.stack tr{border-bottom:1px solid var(--line);padding:8px 0}table.stack td{border:0;padding:2px 0}table.stack td:empty{display:none}
table.stack td form{margin:4px 4px 0 0}}
.pending{position:sticky;top:0;z-index:20;display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;justify-content:space-between;margin:-28px -36px 18px;
padding:12px 36px;background:#fff4d6;border-bottom:2px solid var(--warn);color:#3f444a}.pending form{display:inline}.pending-buttons{display:flex;gap:8px}
@media (max-width:600px){.pending{margin:-16px -16px 14px;padding:10px 16px}}
.badge{float:right;font-size:12px;font-weight:600;padding:2px 10px;border-radius:10px;background:var(--line)}.badge.on{background:var(--ok);color:#fff}
.viewbar{position:sticky;top:0;z-index:5;display:flex;justify-content:flex-end;padding:6px 0;background:var(--bg)}form.view{display:inline;margin:0}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:14px;overflow:hidden}.seg button{border:0;border-radius:0;padding:3px 12px;background:var(--card);cursor:pointer}
.seg button.cur{background:var(--lime);color:var(--ink);font-weight:600}
form.toggle{display:inline;margin:0}button.badge{border:0;cursor:pointer;color:var(--ink)}button.badge.on{color:#fff}button.badge:hover{outline:2px solid var(--lime)}
.chips{display:flex;flex-wrap:wrap;gap:4px}.chip{background:var(--line);border-radius:8px;padding:1px 8px;font-size:13px}details.more summary{cursor:pointer;font-size:13px;margin-top:4px}
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
.rufbox,.ownbox,.encryptbox,.rebootbox{display:none}
form:has(input[name=reboot]:checked) .rebootbox{display:grid}
form:has(input[name=encrypt]:checked) .encryptbox{display:grid}
dialog#live-log,dialog.popup{width:min(1400px,96vw);height:90vh;border:1px solid var(--line);border-radius:12px;padding:16px;color:var(--ink)}
dialog#live-log[open],dialog.popup[open]{display:flex;flex-direction:column;gap:10px}
dialog::backdrop{background:rgba(0,0,0,.45)}
.live-head{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.live-head h2{margin:0;font-size:17px}.live-head span{flex:1;color:var(--gray);font-size:13px}
.live-filters{display:flex;gap:8px;flex-wrap:wrap}.live-filters input,.live-filters select{width:auto;flex:1 1 130px;max-width:none}
.live-table{flex:1;overflow:auto;border:1px solid var(--line);border-radius:8px}.live-table th{position:sticky;top:0;background:#fff}.live-table tr:hover td{background:#f4f5f2;cursor:pointer}
#live-detail{max-height:22vh}#live-detail:empty{display:none}
form:has(input[name=ruf_enable]:checked) .rufbox{display:grid}
form:has(select[name=key] option[value=own]:checked) .ownbox{display:grid}
form:has(select[name=kind] option[value=own]:checked) .feedbox,form:has(select[name=kind] option[value=ed25519]:checked) .rsabox,form:has(select[name=kind] option[value=rsa]:checked) .edbox{display:none}
.warnbox{grid-column:1/-1;background:#fbefcf;color:#8a6200;border-radius:8px;padding:8px 12px;margin:0;font-size:13px}
textarea{width:100%;font:13px/1.4 monospace;padding:8px 10px;border:1px solid #cfd2c6;border-radius:8px;background:#f8f9f4;resize:vertical}
.sw input:focus-visible+i{outline:2px solid var(--ink);outline-offset:2px}
.btns{display:flex;gap:10px;margin-top:14px;flex-wrap:wrap}
button,a.btn{font:inherit;padding:8px 18px;border-radius:8px;border:1px solid var(--line);background:#fff;color:var(--ink);cursor:pointer;text-decoration:none;display:inline-block}
button.p,a.btn.p{background:var(--lime);border-color:var(--lime);color:#2a2e22;font-weight:600}
button.d,a.btn.d{color:var(--bad);border-color:#e4b9b9}
td form{display:inline}td button,td a.btn{padding:4px 12px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:var(--gray);padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:9px 8px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
pre{background:#eef0e8;padding:10px;border-radius:8px;overflow:auto;font-size:13px;margin:0}
.pill{display:inline-block;padding:1px 9px;border-radius:12px;font-size:12px;background:#eef1d2}
.pill.g{background:#dcefdf;color:#2c6b38}
.pill.w{background:#fbefcf;color:#8a6200}
footer{position:sticky;bottom:0;z-index:15;background:#fff;border-top:1px solid var(--line);padding:8px 36px;display:flex;gap:18px;
align-items:center;flex-wrap:wrap;font-size:13px;color:var(--gray)}
footer .mie{display:flex;align-items:center;gap:8px;font-weight:600;color:var(--ink)}
footer svg{height:20px;width:auto;border-radius:2px;box-shadow:0 0 0 1px #0002}
footer a{color:var(--ink)}
.att td{overflow-wrap:normal;hyphens:auto}
@media(max-width:760px){.wrap{flex-direction:column}aside{width:100%}main{padding:20px 16px}.row{grid-template-columns:1fr}
footer{padding:6px 12px;gap:10px;font-size:11px;flex-wrap:nowrap;white-space:nowrap;overflow-x:auto}footer .long{display:none}footer svg{height:14px}
#load-card th:last-child,#load-card td:last-child{display:none}#load-card td,#load-card th{padding:6px 4px;overflow-wrap:normal}}
@media print{footer{position:static}.pending{position:static}}
</style></head><body><div class="wrap">{% block %}{% endblock %}</div>
<footer><span class="mie">""" + FLAG_AT + FLAG_EU + """ {{ _('Made in Europe, Austria') }}</span>
<span><span class="long">{{ _('eFa-next is a private open source project:') }} </span><a target=\"_blank\" rel=\"noopener noreferrer\" href=\"""" + REPO_URL + """\">{{ _('Source code') }}</a> ·
{{ _('For qualified administrators, not for consumers. No warranty, no liability as far as the law allows:') }} <a target=\"_blank\" rel=\"noopener noreferrer\" href=\"""" + REPO_URL + """/blob/master/DISCLAIMER.md\">{{ _('Disclaimer') }}</a> · <a target=\"_blank\" rel=\"noopener noreferrer\" href=\"""" + REPO_URL + """/blob/master/AUTHORS.md\">{{ _('Authors') }}</a> ·
<a target=\"_blank\" rel=\"noopener noreferrer\" href=\"""" + REPO_URL + """/blob/master/THIRD-PARTY-NOTICES.md\">{{ _('Third-party notices') }}</a></span></footer>
</body></html>"""
LIVE_JS = """(function () {
  var box = document.getElementById('live-log'), rows = [], timer = null, paused = false, chosen = null;
  if (!box) return;
  var body = document.getElementById('live-rows'), detail = document.getElementById('live-detail');
  var count = document.getElementById('live-count'), pause = document.getElementById('live-pause');
  var columns = ['ts', 'sender', 'rcpt', 'subject', 'action', 'spf', 'dkim', 'dmarc', 'score', 'qid'];
  function value(id) { return document.getElementById(id).value.toLowerCase(); }
  function shown(mail) {
    var domain = value('live-domain'), mailbox = value('live-email'), search = value('live-search');
    var from = (mail.sender || '').toLowerCase(), to = (mail.rcpt || '').toLowerCase();
    if (domain && from.split('@').pop().indexOf(domain) < 0
        && !to.split(', ').some(function (a) { return a.split('@').pop().indexOf(domain) >= 0; })) return false;
    if (mailbox && from.indexOf(mailbox) < 0 && to.indexOf(mailbox) < 0) return false;
    if (value('live-action') && (mail.action || '') !== value('live-action')) return false;
    if (['spf', 'dkim', 'dmarc'].some(function (c) { var f = value('live-' + c); return f && (mail[c] || '') !== f; })) return false;
    return !search || JSON.stringify(mail).toLowerCase().indexOf(search) >= 0;
  }
  function draw() {
    if (paused) return;
    body.textContent = '';
    var list = rows.filter(shown);
    list.forEach(function (mail) {
      var tr = document.createElement('tr');
      columns.forEach(function (c) {
        var td = document.createElement('td');
        td.textContent = mail[c] === null || mail[c] === undefined ? '' : mail[c];
        if (c === 'subject') { td.className = 'subj'; td.title = mail.subject || ''; }
        if (c === 'sender' && mail.subject) {
          // On a phone the subject is a second line under the sender, not a column.
          var line = document.createElement('div');
          line.className = 'sub2';
          line.textContent = mail.subject;
          td.appendChild(line);
        }
        tr.appendChild(td);
      });
      tr.addEventListener('click', function () {
        chosen = mail;
        detail.textContent = JSON.stringify(mail, null, 2);
        var link = document.createElement('a');
        link.href = '/mail/' + encodeURIComponent(mail.id);
        link.target = '_blank';
        link.rel = 'noopener';
        link.textContent = 'Details and headers';
        detail.insertBefore(document.createElement('br'), detail.firstChild);
        detail.insertBefore(link, detail.firstChild);
      });
      body.appendChild(tr);
    });
    count.textContent = list.length + ' of ' + rows.length + ' mails';
  }
  function load() {
    var after = rows.length ? rows[0].id : '';
    fetch(box.getAttribute('data-url') + '?after=' + after, {credentials: 'same-origin'}).then(function (reply) {
      if (!reply.ok || reply.redirected) throw new Error('reply');
      return reply.json();
    }).then(function (data) {
      rows = data.mails.concat(rows).slice(0, 1000);
      draw();
    }).catch(function () { count.textContent = 'Live log not available, log in again if needed.'; });
  }
  document.getElementById('live-open').addEventListener('click', function () {
    box.showModal();
    load();
    timer = setInterval(function () { if (!paused) load(); }, 5000);
  });
  box.addEventListener('close', function () { clearInterval(timer); timer = null; });
  document.getElementById('live-close').addEventListener('click', function () { box.close(); });
  pause.addEventListener('click', function () {
    paused = !paused;
    pause.textContent = paused ? 'Resume' : 'Pause';
    if (!paused) { load(); }
  });
  document.getElementById('live-reset').addEventListener('click', function () {
    box.querySelectorAll('input, select').forEach(function (field) { field.value = ''; });
    draw();
  });
  box.querySelectorAll('input, select').forEach(function (field) {
    field.addEventListener('input', function () { var was = paused; paused = false; draw(); paused = was; });
  });
})();"""
SENDERS_JS = """(function () {
  var box = document.getElementById('sender-box');
  if (!box) return;
  var data = null, name = 'allow', page = 0, size = 50, sortBy = 'entry', ascending = true, chosen = {};
  var csrf = box.getAttribute('data-csrf'), body = document.getElementById('sender-rows');
  var search = document.getElementById('sender-search'), info = document.getElementById('sender-info');
  function post(command, fields) {
    var form = document.createElement('form');
    form.method = 'post';
    form.action = box.getAttribute('data-run') + command;
    fields.csrf = csrf;
    Object.keys(fields).forEach(function (key) {
      var input = document.createElement('input');
      input.type = 'hidden'; input.name = key; input.value = fields[key];
      form.appendChild(input);
    });
    document.body.appendChild(form);
    form.submit();
  }
  function rows() {
    var needle = search.value.toLowerCase();
    return data[name].filter(function (row) { return JSON.stringify(row).toLowerCase().indexOf(needle) >= 0; }).sort(function (a, b) {
      var order = String(a[sortBy] || '').localeCompare(String(b[sortBy] || ''));
      return ascending ? order : -order;
    });
  }
  function other(row) { var now = name === 'rules' ? row.list : name; return now === 'allow' ? 'block' : 'allow'; }
  function draw() {
    var list = rows(), pages = Math.max(1, Math.ceil(list.length / size));
    page = Math.min(page, pages - 1);
    body.textContent = '';
    list.slice(page * size, (page + 1) * size).forEach(function (row) {
      var tr = document.createElement('tr'), td = document.createElement('td'), tick = document.createElement('input');
      tick.type = 'checkbox'; tick.checked = !!chosen[row.entry];
      tick.setAttribute('aria-label', 'Select ' + row.entry);
      tick.addEventListener('change', function () { chosen[row.entry] = tick.checked; });
      td.appendChild(tick); tr.appendChild(td);
      [row.entry, row.type, row.comment, row.added, name === 'rules' ? row.list + ', for ' + row.recipient : ''].forEach(function (text) {
        var cell = document.createElement('td'); cell.textContent = text; tr.appendChild(cell);
      });
      var actions = document.createElement('td'), move = document.createElement('button');
      move.type = 'button'; move.textContent = 'To ' + other(row);
      move.addEventListener('click', function () { post('sender-move', {entry: row.entry, to: other(row)}); });
      var remove = document.createElement('button');
      remove.type = 'button'; remove.textContent = 'Remove'; remove.className = 'd';
      remove.addEventListener('click', function () { removeEntries([row.entry]); });
      actions.appendChild(move); actions.appendChild(remove); tr.appendChild(actions);
      body.appendChild(tr);
    });
    info.textContent = list.length + ' entries, page ' + (page + 1) + ' of ' + pages;
  }
  function removeEntries(entries) {
    if (entries.length && window.confirm('Remove these senders?\\n\\n' + entries.join('\\n'))) {
      post('sender-remove', {entries: entries.join(' '), confirm: 'yes'});
    }
  }
  function open(list, needle) {
    name = list; page = 0; chosen = {}; search.value = needle || '';
    document.getElementById('sender-title').textContent = {allow: 'Allowed senders', block: 'Blocked senders', rules: 'Sender rules'}[list];
    document.getElementById('sender-add-box').style.display = list === 'rules' ? 'none' : '';
    box.showModal();
    fetch(box.getAttribute('data-url'), {credentials: 'same-origin'}).then(function (reply) { return reply.json(); }).then(function (json) {
      data = json; draw();
    });
  }
  document.querySelectorAll('[data-manage]').forEach(function (button) {
    button.addEventListener('click', function () {
      var quick = document.getElementById('quick-' + button.getAttribute('data-manage'));
      open(button.getAttribute('data-manage'), quick.value);
    });
  });
  search.addEventListener('input', function () { page = 0; draw(); });
  box.querySelectorAll('th[data-sort]').forEach(function (head) {
    head.addEventListener('click', function () {
      var key = head.getAttribute('data-sort');
      ascending = sortBy === key ? !ascending : true; sortBy = key; draw();
    });
  });
  document.getElementById('sender-prev').addEventListener('click', function () { page = Math.max(0, page - 1); draw(); });
  document.getElementById('sender-next').addEventListener('click', function () { page += 1; draw(); });
  document.getElementById('sender-close').addEventListener('click', function () { box.close(); });
  document.getElementById('sender-remove').addEventListener('click', function () {
    removeEntries(Object.keys(chosen).filter(function (key) { return chosen[key]; }));
  });
  function addNow(entries, comment) {
    if (entries.trim()) post('sender-add', {list: name, entries: entries, comment: comment});
  }
  document.getElementById('sender-add').addEventListener('click', function () {
    addNow(document.getElementById('sender-new').value, document.getElementById('sender-comment').value);
  });
  // Formula characters at the start would run as code when a spreadsheet opens the file.
  function cell(text) {
    text = String(text || '');
    if (/^[=+@-]/.test(text)) text = "'" + text;
    return '"' + text.replace(/"/g, '""') + '"';
  }
  document.getElementById('sender-export').addEventListener('click', function () {
    var lines = ['entry,type,comment,added'].concat(rows().map(function (row) {
      return [row.entry, row.type, row.comment, row.added].map(cell).join(',');
    }));
    var link = document.createElement('a');
    link.href = URL.createObjectURL(new Blob([lines.join('\\n') + '\\n'], {type: 'text/csv'}));
    link.download = 'senders-' + name + '.csv';
    link.click();
  });
  document.getElementById('sender-import').addEventListener('change', function (event) {
    var reader = new FileReader();
    reader.onload = function () {
      var entries = reader.result.split(/\\r?\\n/).slice(1).map(function (line) {
        return line.split(',')[0].replace(/^"'?|"$/g, '').trim();
      }).filter(Boolean);
      if (entries.length && window.confirm('Add these senders?\\n\\n' + entries.join('\\n'))) addNow(entries.join(' '), '');
    };
    reader.readAsText(event.target.files[0]);
  });
})();"""
COPY_JS = """document.addEventListener('DOMContentLoaded', function () {
  var left = document.querySelector('[data-countdown]');
  if (!left) return;
  var end = Date.now() + parseInt(left.getAttribute('data-countdown'), 10) * 1000;
  function tick() {
    var seconds = Math.max(0, Math.round((end - Date.now()) / 1000));
    left.textContent = Math.floor(seconds / 60) + ':' + ('0' + seconds % 60).slice(-2) + ' min';
    if (seconds === 0) { window.location.reload(); return; }
    setTimeout(tick, 1000);
  }
  tick();
});
document.addEventListener('click', function (event) {
  var question = event.target.getAttribute('data-confirm');
  if (question && !window.confirm(question)) { event.preventDefault(); return; }
  var id = event.target.getAttribute('data-copy');
  if (!id) return;
  var box = document.getElementById(id);
  box.select();
  navigator.clipboard.writeText(box.value).then(function () { event.target.textContent = 'Copied'; });
});
setInterval(function () {
  var card = document.getElementById('load-card');
  if (!card || document.hidden) return;
  fetch(card.getAttribute('data-url'), {credentials: 'same-origin'}).then(function (reply) {
    if (reply.ok && !reply.redirected) reply.text().then(function (html) { card.innerHTML = html; });
  });
}, 30000);"""
RUF_WARNING = ('Privacy: failure reports (ruf) can contain personal data such as message headers, addresses and parts '
               'of message content. Under the GDPR a legal basis and a processing agreement with the report receiver '
               'may be needed. Many receivers do not send them at all.')
SOLO = '<main class="solo">' + BRAND
FAILED = PAGE.replace(BLOCK, SOLO + """<div class="card"><p class="err" role="alert">{{ error }}</p></div></main>""")
LOGIN = PAGE.replace(BLOCK, SOLO + """<div class="card">
{% if portal %}<p class="err" role="alert">{{ _('This account logs in at the user portal.') }} <a href="/portal/login">{{ _('To the user portal') }}</a></p>{% endif %}
{% if error %}<p class="err" role="alert">{{ error }}</p>{% endif %}<form method="post">
<input type="hidden" name="csrf" value="{{ csrf }}"><div class="row"><label for="username">{{ _('Mail address') if portal_mode else _('User name, empty for the main admin') }}</label>
<input type="text" id="username" name="username" autocomplete="username"></div><div class="row"><label for="password">Password</label>
<input type="password" id="password" name="password" autofocus required></div>
<div class="btns"><button class="p">Log in</button></div></form>{% if sso or tenant_sso %}<form method="get" action="{{ url_for('oidc_login') }}">
{% if tenant_sso %}<div class="row"><label for="sso-domain">Single sign-on: your mail domain</label><input type="text" id="sso-domain" name="domain" autocomplete="off"></div>{% endif %}
<div class="btns"><button>Log in with single sign-on</button></div></form>{% endif %}
{% if not portal_mode %}<p class="sub">{{ _('Quarantine of your own mailbox:') }} <a href="/portal/login">{{ _('user portal') }}</a></p>{% endif %}</div></main>""")
# 5y: the legal texts, open without a login; with accept, the page every admin page waits for after a new version of them.
LEGAL_PAGE = PAGE.replace(BLOCK, SOLO + """<div class="card"><h2>{{ _('Legal texts') }} / Legal</h2>
<p>{{ legal.summary.de if lang == 'de' else legal.summary.en }}</p>
<p class="h">eFa-next {{ legal.version }} · SHA-256 (16): <code>{{ legal.digest }}</code></p>
<ul>{% for name, pdf in files %}<li><a href="{{ url_for('legal_file', name=pdf) }}">{{ name }} (PDF)</a> · <a href="{{ url_for('legal_file', name=name) }}">{{ _('text') }}</a></li>{% endfor %}
<li><a href="{{ url_for('legal_file', name=all_pdf) }}">{{ _('All legal texts') }} (PDF)</a></li></ul>
{% if accept %}{% if error %}<p class="err" role="alert">{{ error }}</p>{% endif %}<form method="post" action="{{ url_for('legal_accept') }}"><input type="hidden" name="csrf" value="{{ csrf }}">
<p class="h">{{ _('The legal texts of this version are not confirmed yet. Admin pages open after the confirmation; the user portal and the mail flow are not affected.') }}</p>
<div class="row"><label><input type="checkbox" name="confirm" value="yes" required> {{ legal.confirm.de if lang == 'de' else legal.confirm.en }}</label></div>
<div class="btns"><button class="p">{{ _('Confirm') }}</button></div></form>{% endif %}</div></main>""")
MAIL_PAGE = PAGE.replace(BLOCK, """<script src="{{ url_for('copy_js') }}"></script><main><p><a href="{{ back }}">Back</a></p>
<h1>Mail {{ view.mail.id }}</h1><p class="sub">{{ view.mail.ts }} · {{ view.mail.sender }} → {{ view.mail.rcpt }}</p>
<div class="card"><h2>{{ _('Overview') }}</h2><table>{% for key, label in (('subject', 'Subject'), ('action', 'Result'), ('score', 'Score'), ('spf', 'SPF'), ('dkim', 'DKIM'), ('dmarc', 'DMARC'), ('ip', 'Client IP'),
                      ('qid', 'Queue ID'), ('message_id', 'Message-ID'), ('header_from', 'From header'), ('reply_to', 'Reply-To'), ('return_path', 'Return-Path'), ('x_mailer', 'X-Mailer')) %}
<tr><td>{{ label }}</td><td>{{ view.mail[key] if view.mail[key] is not none else '' }}</td></tr>{% endfor %}</table></div>
<details class="section" open><summary>{{ _('Why this result') }}</summary><div class="card">{% if view.verdict %}<table><tr><th>Check</th><th>Score</th><th>Meaning</th></tr>
{% for item in view.verdict %}<tr><td>{{ item.symbol }}</td><td>{{ item.score }}</td><td>{{ (item.text_de if lang == 'de' and item.text_de else item.text) or '' }}</td></tr>{% endfor %}</table>
{% else %}<p class="h">No checks stored for this mail: mail before this version has none.</p>{% endif %}</div></details>
<details class="section" open><summary>{{ _('Path over the servers') }}</summary><div class="card">{% if view.received %}<table><tr><th>Hop</th><th>Time</th><th>Seconds</th></tr>
{% for hop in view.received %}<tr><td>{{ hop.hop }}</td><td>{{ hop.time }}</td><td>{{ hop.seconds if hop.seconds is not none else '' }}</td></tr>{% endfor %}</table>
{% else %}<p class="h">{{ view.headers_note or 'No Received lines.' }}</p>{% endif %}</div></details>
<details class="section" open><summary>{{ _('Checks: authentication, ARC, DKIM') }}</summary><div class="card">{% for item in view.checks %}<p><b>{{ item.name }}</b>: {{ item.value }}</p>
{% else %}<p class="h">None in the stored headers.</p>{% endfor %}{% for item in view.spam %}<p class="h">{{ item.name }}: {{ item.value }}</p>{% endfor %}</div></details>
<details class="section"><summary>{{ _('DNS evidence') }}</summary><div class="card">{% if view.evidence %}
<p class="h">{{ view.evidence.note }} Asked {{ view.evidence.asked }} at {{ view.evidence.resolver }}.{% if view.evidence.fcrdns is not none %} Forward-confirmed reverse DNS: {{ 'yes' if view.evidence.fcrdns else 'no' }}.{% endif %}</p>
<table><tr><th>Check</th><th>Query</th><th>Answer</th><th>TTL</th><th>DNSSEC</th><th>ms</th></tr>{% for item in view.evidence.checks %}<tr><td>{{ item.check }}</td><td>{{ item.query }} {{ item.type }}</td>
<td>{% for answer in item.answers %}{{ answer[2] }}<br>{% else %}{{ item.error or ('no record' if item.rcode == 3 else 'empty') }}{% endfor %}{% if item.key %}<span class="pill">{{ item.key.type }} {{ item.key.bits or '' }}</span>{% endif %}</td>
<td>{{ item.ttl if item.ttl is not none else '' }}</td><td>{{ 'validated' if item.ad else '' }}</td><td>{{ item.ms }}</td></tr>{% endfor %}</table>
{% for check, verdicts in view.evidence.results.items() %}{% if verdicts %}<p class="h">{{ check|upper }}: {{ verdicts|join(', ') }}</p>{% endif %}{% endfor %}
{% for item in view.evidence.blocklists %}<p class="h">Blocklist {{ item.symbol }}: {{ item.matched|join(', ') }}</p>{% endfor %}
{% if can_download %}<div class="btns"><a class="btn" href="{{ url_for('mail_evidence', mail_id=view.mail.id) }}">Download as JSON</a></div>{% endif %}
{% else %}<p class="h">No DNS evidence stored for this mail.</p>{% endif %}</div></details>
<details class="section"><summary>{{ _('Headers') }}</summary><div class="card">{% if view.headers %}{% if view.headers_note %}<p class="warnbox">{{ view.headers_note }}</p>{% endif %}
<pre id="raw-headers">{{ view.headers }}</pre><div class="btns"><button type="button" data-copy="raw-headers">Copy</button>
{% if can_download %}<a class="btn" href="{{ url_for('mail_headers', mail_id=view.mail.id) }}">Download</a>{% endif %}</div>
{% else %}<p class="h">{{ view.headers_note }}</p>{% endif %}</div></details>
<details class="section"><summary>{{ _('Content') }}</summary><div class="card"><p class="h">{{ view.content }}</p></div></details></main>""")
LOAD_CARD = """<h2>{{ _('Load') }}</h2>{% if not rows %}<p class="h">{{ _('Collecting: the first value comes after a minute.') }}</p>{% else %}
<table><tr><th></th><th>{{ _('Now') }}</th><th>15 min</th><th>{{ _('24 h max') }}</th><th>{{ _('Last hour') }}</th></tr>{% for row in rows %}<tr><td>{{ row.label }}</td><td>{{ row.now }}%</td><td>{{ row.avg }}%</td><td>{{ row.top }}%</td>
<td><svg viewBox="0 0 100 20" width="100" height="20" role="img" aria-label="{{ row.label }}, last hour"><polyline points="{{ row.points }}" fill="none" stroke="#646563" stroke-width="1"/></svg></td></tr>{% endfor %}</table>
<p class="h">Load average {{ extra.load|join(' / ') }} (1, 5, 15 min, {{ extra.cpus }} CPUs). Network: in {{ last.rx }} Mbit/s, out {{ last.tx }} Mbit/s.</p>
<p class="h">{% for disk in extra.disks %}{{ disk.mount }}: {{ disk.free }} GB free of {{ disk.size }} GB ({{ disk.used }}% used). {% endfor %}</p>
{% for text in advice %}<p class="warnbox">{{ text }}</p>{% endfor %}{% endif %}"""
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
    {%- elif value|reject('string')|list or value|select('string')|map('length')|max > 40 -%}{% for item in value %}<div>{{ show(item) }}</div>{% endfor %}
    {%- else -%}{#- Short words such as file endings: chips in one wrapping line, from 12 on the rest folded. -#}
      <div class="chips">{% for item in value[:12] %}<span class="chip">{{ item }}</span>{% endfor %}</div>
      {%- if value|length > 12 %}<details class="more"><summary>{{ _('Show all') }} ({{ value|length }})</summary><div class="chips">{% for item in value[12:] %}<span class="chip">{{ item }}</span>{% endfor %}</div></details>{% endif -%}
    {%- endif -%}
  {%- else -%}{{ value }}{%- endif -%}
{%- endmacro -%}
{%- macro viewform(target, label=none) -%}
  {#- Standard | Expert, one click, kept in My settings of the login; target set: one button to that view. -#}
  <form method="post" action="{{ url_for('set_view') }}" class="view"><input type="hidden" name="csrf" value="{{ csrf }}">
  {%- if target %}<button name="view" value="{{ target }}">{{ label }}</button>
  {%- else %}<span class="seg" role="group" aria-label="{{ _('View') }}"><button name="view" value="standard"{% if not expert %} class="cur" aria-pressed="true"{% endif %}>{{ _('Standard') }}</button><button name="view" value="expert"{% if expert %} class="cur" aria-pressed="true"{% endif %}>{{ _('Expert') }}</button></span>{% endif %}</form>
{%- endmacro -%}
{%- macro toggle(name, cmd, on) -%}
  {#- One click in the head of the card: the form of the card with only the switch changed, the other fields as they are now. -#}
  {%- set sw = switch_arg(name, cmd) -%}{%- set ns = namespace(ok=sw is not none) -%}
  {%- if sw %}{% for arg in cmd.args if arg.required and arg.name != 'mode' and current(name, arg) in ('', none) %}{% set ns.ok = false %}{% endfor %}{% endif -%}
  {%- if ns.ok -%}<form method="post" action="{{ url_for('run', name=name) }}" class="toggle"><input type="hidden" name="csrf" value="{{ csrf }}">
  {%- for arg in cmd.args if arg.name != 'mode' and arg.web is not sameas false %}{% set v = current(name, arg) %}<input type="hidden" name="{{ arg.name }}" value="{{ 'on' if v is sameas true else ('off' if v is sameas false else v) }}">{% endfor -%}
  <input type="hidden" name="mode" value="{{ 'off' if on else 'on' }}"><button class="badge{{ ' on' if on }}" aria-pressed="{{ 'true' if on else 'false' }}" title="{{ _('Turn off') if on else _('Turn on') }}">{{ 'On' if on else 'Off' }}</button></form>
  {%- else -%}<span class="badge{{ ' on' if on }}">{{ 'On' if on else 'Off' }}</span>{%- endif -%}
{%- endmacro -%}
{%- macro post(name, label, fields, cls='') -%}
  <form method="post" action="{{ url_for('run', name=name) }}"><input type="hidden" name="csrf" value="{{ csrf }}">
  {%- for k, v in fields.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor -%}
  <button{% if cls %} class="{{ cls }}"{% endif %}{% if cls == 'd' %} data-confirm="{{ label }}?"{% endif %}>{{ label }}</button></form>
{%- endmacro -%}
{%- macro copybox(id, text) -%}
  <textarea id="{{ id }}" rows="{{ 2 if text|length < 120 else 5 }}" readonly>{{ text }}</textarea>
  <button type="button" data-copy="{{ id }}">Copy</button>
{%- endmacro -%}
{%- macro keytable() -%}
  {%- set rows = (values.get('keys') or [])|selectattr('type', 'in', ['rsa', 'ed25519'])|list -%}
  {%- if rows -%}<table><tr><th>Domain</th><th>Type</th><th>Selector</th><th>Size</th><th>State</th><th>DNS record</th><th></th></tr>
  {%- for key in rows -%}<tr><td>{{ key.domain }}</td><td>{{ 'Ed25519' if key.type == 'ed25519' else 'RSA' }}</td><td>{{ key.selector }}</td><td>{{ key.bits or '' }}</td><td>{{ key.state }}</td>
  <td>{{ copybox('dns-' ~ loop.index, key.selector ~ '._domainkey.' ~ key.domain ~ '. IN TXT ' ~ key.dns) }}</td>
  <td><a class="btn d" href="{{ url_for('show_page', slug='dkim', domain=key.domain, selector=key.selector) }}#dkim-remove">Remove</a></td></tr>{%- endfor -%}
  </table>{%- endif -%}
{%- endmacro -%}
{%- macro field(name, arg) -%}
  {%- set id = name ~ '-' ~ arg.name -%}{%- set value = current(name, arg) -%}
  {%- if arg.hint %}<div class="row {{ arg.group }}box"><p class="warnbox" role="alert">{{ arg.hint }}</p></div>{% endif -%}
  <div class="row{% if arg.group %} {{ arg.group }}box{% endif %}">
  {%- if arg.ack -%}
    <label for="{{ id }}">{{ arg.label|t }}</label>
    <div><input type="checkbox" id="{{ id }}" name="{{ arg.name }}" value="yes"></div>
  {%- elif arg.label.endswith('on or off') -%}
    <label for="{{ id }}">{{ 'Active' if arg.label == 'on or off' else arg.label|replace(': on or off', '') }}</label>
    {#- The hidden field comes second: a ticked switch sends on first, an unticked one only off. -#}
    <div><label class="sw"><input type="checkbox" id="{{ id }}" name="{{ arg.name }}" value="on"
    {%- if value is sameas true or value == 'on' %} checked{% endif %}><i></i></label>
    <input type="hidden" name="{{ arg.name }}" value="off"></div>
  {%- elif arg.secret -%}
    <label for="{{ id }}">{{ arg.label|t }}</label>
    <input type="password" id="{{ id }}" name="{{ arg.name }}" autocomplete="new-password">
  {%- elif arg.kind == 'confirm' -%}
    <label for="{{ id }}">{{ _('Confirm') }}</label>
    <div><label><input type="checkbox" id="{{ id }}" name="{{ arg.name }}" value="yes"{% if arg.required %} required{% endif %}> {% if arg.name == 'accept_terms' %}{{ arg.label|t }}{% else %}{{ arg.label|replace('Type yes to confirm the take-over', _('Yes, take it over'))|replace('Type yes to confirm', _('Yes, do it'))|replace('To remove: type yes', _('Yes, remove'))|replace('Type yes to accept the reboot risk', _('Yes, I accept the reboot risk'))|replace('Type yes to accept the terms of service', _('Yes, I accept the terms of service')) }}{% endif %}</label></div>
  {%- elif arg.choices -%}
    <label for="{{ id }}">{{ arg.label|t }}</label>
    {%- set chosen = value if value != '' else (arg.preselect or '') %}
    <select id="{{ id }}" name="{{ arg.name }}">{% for item in arg.choices %}<option value="{{ item.value }}"{% if item.value == chosen %} selected{% endif %}>{{ item.text }}</option>{% endfor %}</select>
    {%- set now = shown_now(name, arg) %}{% if now is not none %}<small class="now">{{ _('Current:') }} {% for item in arg.choices if item.value == now %}{{ item.text }}{% endfor %}</small>{% endif %}
  {%- elif arg.name == 'tenant' and pick.tenants -%}
    <label for="{{ id }}">Tenant</label>
    <select id="{{ id }}" name="tenant">{% if not arg.required %}<option value="">None</option>{% endif %}{% for item in pick.tenants %}<option{% if item == value %} selected{% endif %}>{{ item }}</option>{% endfor %}</select>
  {%- elif arg.name == 'domain' and name in pick_domain_commands and pick.domains -%}
    <label for="{{ id }}">Domain</label>
    <select id="{{ id }}" name="domain">{% if not arg.required %}<option value="">None</option>{% endif %}{% for item in pick.domains %}<option{% if item == value %} selected{% endif %}>{{ item }}</option>{% endfor %}</select>
  {%- elif arg.name == 'groups' and name == 'user-set' and pick.groups -%}
    <label for="{{ id }}">Groups</label>
    <select id="{{ id }}" name="groups" multiple size="{{ [pick.groups|length, 8]|min }}">{% for item in pick.groups %}<option{% if item in value.split(',') %} selected{% endif %}>{{ item }}</option>{% endfor %}</select>
  {%- elif arg.label in choices -%}
    <label for="{{ id }}">{{ choices[arg.label][0] }}</label>
    <select id="{{ id }}" name="{{ arg.name }}">{% for option in choices[arg.label][1] %}<option value="{{ option }}"
    {%- if option == value %} selected{% endif %}>{{ option_text.get(option, option) }}</option>{% endfor %}</select>
  {%- else -%}
    <label for="{{ id }}">{{ arg.label|t }}</label>
    <input type="text" id="{{ id }}" name="{{ arg.name }}" value="{{ value }}"{% if arg.placeholder %} placeholder="{{ arg.placeholder }}"{% endif %}{% if arg.required %} required{% endif %}>
  {%- endif -%}
  </div>
{%- endmacro -%}
<script src="{{ url_for('copy_js') }}"></script><aside>""" + BRAND + """
{% if session.brand %}<div class="tenantbrand"{% if session.brand.color %} style="border-left:4px solid {{ session.brand.color }};padding-left:8px"{% endif %}>
{% if session.brand.logo %}<img src="{{ url_for('brand_logo') }}" alt="" style="max-width:160px;max-height:60px"><br>{% endif %}<b>{{ session.brand.name }}</b></div>{% endif %}
{% for group, pages in nav %}<h4>{{ group|t }}</h4>{% for p in pages %}<a class="nav{% if p.slug == page.slug %} on{% endif %}"
{%- if p.slug == page.slug %} aria-current="page"{% endif %} href="{{ url_for('show_page', slug=p.slug) }}">{{ p.title|t }}</a>{% endfor %}{% endfor %}
{% if values.get('rspamd_sso') == 'read-only' and session.get('role', 'super') == 'super' %}<h4>Tools</h4><a class="nav" href="{{ url_for('rspamd_open') }}" target="_blank" rel="noopener noreferrer">rspamd web interface <span aria-hidden="true">&#8599;</span><span class="sr">(opens in a new window)</span></a><p class="h">{{ _('read only, until') }} {{ values.get('rspamd_sso_until') }}</p>{% endif %}
<form method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><button>Log out</button></form>
</aside><main>{% if not portal_mode %}<div class="viewbar">{{ viewform(none) }}</div>{% endif %}{% if values.get('firewall_pending_seconds') is not none and 'firewall-confirm' in commands %}<div class="pending" role="alert">
<span><b>Firewall change not confirmed.</b> Check that you still have access. It is taken back in <span data-countdown="{{ values.firewall_pending_seconds }}">{{ values.firewall_pending_seconds // 60 }} min</span>.</span>
<span class="pending-buttons">{{ post('firewall-confirm', 'Keep the change', {}, 'p') }}{% if 'firewall-revert' in commands %}{{ post('firewall-revert', 'Discard', {}, 'd') }}{% endif %}</span></div>{% endif %}
{% if values.get('cluster_managed_by') %}<div class="card"><p>{{ 'Managed by'|t }} <b>{{ values.cluster_managed_by }}</b>: {{ 'this node is a client in master/client mode, settings are changed on the master.'|t }}</p></div>{% endif %}
<h1>{{ page.title|t }}</h1><p class="sub">{{ page.sub|t }}</p>
{% if error %}<div class="card"><p class="err" role="alert">{{ error }}</p></div>{% endif %}
{% if result is not none and result_name in short_results %}<div class="card done"><p>{{ short_results[result_name] }}</p></div>
{% elif result is not none and not result.tests %}<div class="card done"><h2>Result: {{ result_title }}</h2><p class="h">Done.</p>
{% if result.mails is defined and result.mails and result.mails[0].id is defined %}<table><tr><th>Time</th><th>Sender</th><th>Recipient</th><th>Subject</th><th>Result</th><th></th></tr>
{% for mail in result.mails %}<tr><td>{{ mail.ts }}</td><td>{{ mail.sender }}</td><td>{{ mail.rcpt }}</td><td>{{ mail.subject }}</td><td>{{ mail.action }}</td>
<td><a class="btn" href="{{ url_for('mail_page', mail_id=mail.id) }}">Details</a></td></tr>{% endfor %}</table>
{% elif result.job is defined %}<p>{{ result.count }} mails. {% if result.state == 'done' %}<a class="btn p" href="{{ url_for('export_file', job=result.job) }}">Download ZIP</a>
{% else %}{{ result.note }} <a class="btn" href="{{ url_for('export_file', job=result.job) }}">Download ZIP</a>{% endif %}</p>
{% elif result.text is defined %}{% if result.cut %}<p class="warnbox">Only the first part is shown.
{{ post(result_name, 'Show more', {'id': result.id, 'more': 'yes'}) }}</p>{% endif %}<p class="h">Shown as plain text from {{ result.source }}. Links are not clickable, nothing is loaded.</p>
<pre>{{ result.text }}</pre>{% if result.attachments %}<table><tr><th>Attachment</th><th>Type</th><th>Size</th></tr>{% for item in result.attachments %}<tr><td>{{ item.name }}</td><td>{{ item.type }}</td>
<td>{{ item.size|filesizeformat }}</td></tr>{% endfor %}</table>{% endif %}
{% else %}{{ show(result) }}{% endif %}</div>{% endif %}
{% if flow_picture %}<div class="card flowcard">{{ flow_picture|safe }}</div>{% endif %}
{% if tiles %}{% set load_link = 'load-set' in commands %}{% if load_link %}<a class="cardlink" href="{{ url_for('show_page', slug='maint') }}#load-set" aria-label="Load: limits and alerts">{% endif %}
<div class="card" id="load-card" data-url="{{ url_for('load_card') }}">{{ load_html|safe }}</div>{% if load_link %}</a>{% endif %}<div class="tiles">
{% for t in tiles %}{% set inner %}<b>{{ t.label|t }}</b><div class="v">{% if t.dot is not none %}<span class="dot {{ t.dot }}"></span>{% endif %}{{ t.value }}</div>
{% if t.note %}<div class="note">{{ t.note }}</div>{% endif %}{% endset %}
{% if t.slug and t.anchor in commands %}<a class="tile" href="{{ url_for('show_page', slug=t.slug) }}#{{ t.anchor }}">{{ inner }}</a>
{% elif t.detail %}<details class="tile"><summary>{{ inner }}</summary><p>{{ t.detail }}</p></details>{% else %}<div class="tile">{{ inner }}</div>{% endif %}{% endfor %}</div>
{% if chart %}<div class="card"><h2>{{ _('Last hour per minute') }}</h2><p class="h">{{ chart.summary }}</p>{{ chart.svg|safe }}
<p class="legend"><span class="key m"></span>Mails <span class="key s"></span>Spam <span class="key v"></span>Viruses<span class="span">{{ chart.first }} to {{ chart.last }}</span></p></div>{% endif %}
{% if attention %}<div class="card"><h2>{{ _('Needs attention') }}</h2><table class="att">{% for text, slug, anchor in attention %}<tr><td><span class="dot w"></span>{{ text }}</td>
<td>{% if slug and anchor in commands %}<a href="{{ url_for('show_page', slug=slug) }}#{{ anchor }}">{{ _('Open') }} {{ pages_by_slug[slug].title|t }}</a>{% endif %}</td></tr>{% endfor %}</table></div>{% endif %}{% endif %}
{% for key in page.show or [] %}{% if key in values %}{% set info = current_info[key] %}<div class="card"><h2>{{ info[0] }}</h2>
{% if info|length == 1 %}{{ show(values[key]) }}
{% elif not values[key] %}<span class="pill">none</span>
{% else %}<table>{% for entry in values[key] %}<tr><td>{{ entry }}</td>{% if values[key] is mapping %}<td>{{ show(values[key][entry]) }}</td>{% endif %}
<td>{{ post(info[1], 'Remove', dict(info[3], action='remove', **{info[2]: entry}), 'd') }}</td></tr>{% endfor %}</table>{% endif %}</div>{% endif %}{% endfor %}
{% macro card(name) %}{% set cmd = commands[name] %}
{#- subject-get only fills the form of subject-set. The history is part of the record list. -#}
{% if name not in hidden_cards and name not in merged %}<div class="card" id="{{ name }}">
{%- set status = status_of.get(name) if status_of.get(name) in loaded else None %}
{%- if status %}{% set sok, sout = loaded[status] %}<h2>{{ commands[status].title }}{% if sok and badge(sout) is not none %}{{ toggle(name, cmd, badge(sout)) }}{% endif %}</h2>
  {% if sok %}{% if expert %}{{ show(without_badge(sout)) }}{% else %}{% for text in warnings_of(loaded[status]) %}<p class="warnbox" role="alert">{{ text }}</p>{% endfor %}{% endif %}{% else %}<p class="err">{{ sout.error }}</p>{% endif %}<h3>{{ cmd.title|t }}</h3>
{%- else %}<h2>{{ cmd.title|t }}</h2>{% endif %}
{% if page.notes and name in page.notes %}{% if page.notes[name]|length <= note_short %}<p class="h">{{ page.notes[name] }}</p>
{% else %}<details class="help"><summary>Help</summary><p>{{ page.notes[name] }}</p></details>{% endif %}{% endif %}
{% if name == 'api-status' and page.slug == 'export' %}{% set aok, aout = loaded[name] %}<p class="h">Prometheus reads <code>{{ request.host_url }}metrics</code> with the header
Authorization: Bearer &lt;token&gt;. The token belongs to a user who may read the settings of the whole system.</p>
<p>REST API: <span class="badge{{ ' on' if aok and aout.api }}">{{ 'On' if aok and aout.api else 'Off' }}</span> Turn it on and make the token on the page Users.</p>
{% else %}
{% if name == 'maillog-search' %}<button type="button" class="p" id="live-open">Live log</button>
<dialog id="live-log" data-url="{{ url_for('maillog_live') }}"><div class="live-head"><h2>Live log</h2><span id="live-count"></span>
<button type="button" id="live-pause">Pause</button><button type="button" id="live-reset">Reset filters</button><button type="button" id="live-close">Close</button></div>
<div class="live-filters"><input type="text" id="live-domain" placeholder="Domain" aria-label="Domain"><input type="text" id="live-email" placeholder="Email address" aria-label="Email address">
<select id="live-action" aria-label="Result"><option value="">Result: all</option>{% for option in ('no action', 'add header', 'rewrite subject', 'greylist', 'soft reject', 'reject', 'virus') %}<option>{{ option }}</option>{% endfor %}</select>
{% for check in ('spf', 'dkim', 'dmarc') %}<select id="live-{{ check }}" aria-label="{{ check|upper }}"><option value="">{{ check|upper }}: all</option>{% for option in ('pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror') %}<option>{{ option }}</option>{% endfor %}</select>{% endfor %}
<input type="text" id="live-search" placeholder="Search" aria-label="Search"></div>
<div class="live-table"><table><thead><tr><th>Time</th><th>Sender</th><th>Recipient</th><th class="subj">Subject</th><th>Result</th><th>SPF</th><th>DKIM</th><th>DMARC</th><th>Score</th><th>Queue ID</th></tr></thead><tbody id="live-rows"></tbody></table></div>
<pre id="live-detail"></pre></dialog><script src="{{ url_for('live_js') }}"></script>{% endif %}
{% if name == 'dkim-check' %}{% set ok, output = loaded[name] %}{% if not ok %}<p class="err">{{ output.error }}</p>
  {% elif output.warnings or output.notes %}{{ show(output.warnings + output.notes) }}{% else %}<p class="h">No problems found.</p>{% endif %}
{% elif name == 'arc-show' %}{% set ok, output = loaded[name] %}{% if not ok %}<p class="err">{{ output.error }}</p>
  {% elif output.arc_domains %}<table><tr><th>Domain</th><th>Active</th><th>From</th><th>Key</th><th>Selector</th><th>Size</th><th>DNS record</th><th></th></tr>
  {% for row in output.arc_domains %}<tr><td>{{ row.domain }}</td><td>{{ show(row.active) }}</td><td>{{ row.settings_from }}</td><td>{{ option_text.get(row.key, row.key) }}</td><td>{{ row.selector }}</td><td>{{ row.bits or '' }}</td>
  <td>{% if row.dns %}{{ copybox('arc-' ~ loop.index, row.selector ~ '._domainkey.' ~ row.domain ~ '. IN TXT ' ~ row.dns) }}{% endif %}{% if row.note %}<p class="h">{{ row.note }}</p>{% endif %}</td>
  <td><a class="btn" href="{{ url_for('show_page', slug='dkim', domain=row.domain, key='dkim' if row.has_dkim_rsa else 'own') }}#arc-set">Change</a></td></tr>{% endfor %}</table>
  {% else %}<span class="pill">none</span>{% endif %}
{% elif name == 'dmarc-record-show' %}{% set ok, output = loaded[name] %}{% if not ok %}<p class="err">{{ output.error }}</p>
  {% elif output.dmarc_records %}{% for item in output.dmarc_records %}{% set outer = loop.index %}<h3>{{ item.domain }}</h3>
  <p class="h">Name: {{ item.name }}</p>{{ copybox('dmarc-' ~ outer, item.record) }}
  {% for auth in item.authorization %}<p class="h">Reports go to another domain. It must publish this record: {{ auth }} IN TXT "v=DMARC1"</p>{% endfor %}
  {% if item.ruf %}<p class="warnbox">{{ ruf_warning }}</p>{% endif %}
  <table><tr><th>Saved</th><th>By</th><th>Record</th><th></th></tr>{% for version in item.history %}<tr><td>{{ version.when }}</td><td>{{ version.who }}</td>
  <td>{{ copybox('dmarc-' ~ outer ~ '-' ~ loop.index, version.record) }}</td>
  <td><a class="btn" href="{{ url_for('show_page', slug='dkim', domain=item.domain, ruf_enable='on' if version.fields.ruf else 'off', **version.fields) }}#dmarc-record-set">Into form</a></td></tr>{% endfor %}</table>{% endfor %}
  {% else %}<span class="pill">none</span>{% endif %}
{% elif name == 'sender-list' %}{% set ok, output = loaded[name] %}{% if not ok %}<p class="err">{{ output.error }}</p>{% else %}
  <div class="tiles">{% for list, label in (('allow', 'Allowed senders'), ('block', 'Blocked senders'), ('rules', 'Sender rules')) %}<div class="tile"><b>{{ label }}</b>
  <div class="v">{{ output[list]|length }}</div><div class="btns"><input type="text" id="quick-{{ list }}" placeholder="Search" aria-label="Search {{ label }}"><button type="button" class="p" data-manage="{{ list }}">Manage</button></div></div>{% endfor %}</div>
  <dialog id="sender-box" class="popup" data-url="{{ url_for('senders_data') }}" data-run="{{ url_for('run', name='') }}" data-csrf="{{ csrf }}"><div class="live-head"><h2 id="sender-title"></h2><span id="sender-info"></span>
  <button type="button" id="sender-export">Export CSV</button><label class="btn" for="sender-import">Import CSV</label><input type="file" id="sender-import" accept=".csv,text/csv" hidden><button type="button" id="sender-close">Close</button></div>
  <div class="live-filters"><input type="text" id="sender-search" placeholder="Search" aria-label="Search"><button type="button" class="d" id="sender-remove">Remove selected</button></div>
  <div class="live-filters" id="sender-add-box"><textarea id="sender-new" rows="2" placeholder="Add one or several: sender@example.org example.org 192.0.2.1" aria-label="New senders"></textarea><input type="text" id="sender-comment" placeholder="Comment, optional" aria-label="Comment"><button type="button" class="p" id="sender-add">Add</button></div>
  <div class="live-table"><table><thead><tr><th></th><th data-sort="entry">Entry</th><th data-sort="type">Type</th><th data-sort="comment">Comment</th><th data-sort="added">Added</th><th>Scope</th><th></th></tr></thead><tbody id="sender-rows"></tbody></table></div>
  <div class="btns"><button type="button" id="sender-prev">Previous</button><button type="button" id="sender-next">Next</button></div></dialog><script src="{{ url_for('senders_js') }}"></script>{% endif %}
{% elif name == 'relay-networks-list' %}{% set ok, output = loaded[name] %}{% if not ok %}<p class="err">{{ output.error }}</p>{% else %}
  <table><tr><th>Network</th><th>Type</th><th>Description</th><th>State</th><th></th></tr>{% for row in output.networks %}<tr><td>{{ row.network }}</td><td><span class="pill">{{ row.family }}</span></td><td>{{ row.description }}</td>
  <td><span class="pill{{ ' g' if row.state == 'active' else ' w' }}">{{ row.state }}</span></td><td>{% if not row.locked and row.state != 'to remove' %}{{ post('relay-networks-remove', 'Remove', {'network': row.network}, 'd') }}{% endif %}</td></tr>{% endfor %}</table>
  {% for warning in output.warnings %}<p class="warnbox">{{ warning }}</p>{% endfor %}{% if output.unknown %}<p class="err">mynetworks holds entries eFa cannot read: {{ output.unknown|join(' ') }}</p>{% endif %}
  {% if output.pending %}<div class="warnbox"><b>Not active yet.</b> Added: {{ output.added|join(', ') or 'none' }}. Removed: {{ output.removed|join(', ') or 'none' }}.</div>
  <form method="post" action="{{ url_for('run', name='relay-networks-apply') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><div class="row"><label for="relay-confirm">Type yes to confirm</label><input type="text" id="relay-confirm" name="confirm" required></div><div class="btns"><button class="p">Apply</button></div></form>
  <div class="btns">{{ post('relay-networks-discard', 'Discard changes', {}) }}</div>{% endif %}{% endif %}
{% elif name == 'firewall-test' %}{% if result and result.tests %}<table><tr><th>Test</th><th>Result</th><th>ms</th><th>Hint</th></tr>{% for row in result.tests %}<tr><td>{{ row.test }}</td>
  <td><span class="pill{{ ' g' if row.result == 'ok' else ' w' }}">{{ row.result }}</span></td><td>{{ row.ms }}</td><td>{{ row.hint }}</td></tr>{% endfor %}</table>{% if result.outside_check %}<p class="h">{{ result.outside_check }}</p>{% endif %}{{ copybox('fwtest-text', result.text) }}{% endif %}
  <form method="post" action="{{ url_for('run', name=name) }}"><input type="hidden" name="csrf" value="{{ csrf }}">{% for arg in cmd.args %}{{ field(name, arg) }}{% endfor %}<div class="btns"><button class="p">Run</button></div></form>
{% elif name == 'dkim-export' %}{% set domains = values['export_domains'] or [] %}
  {% if domains %}<table>{% for domain in domains %}<tr><td>{{ domain }}</td>
  <td><a class="btn" href="{{ url_for('export_dkim', domain=domain) }}">Export</a></td></tr>{% endfor %}</table>
  <div class="btns"><a class="btn p" href="{{ url_for('export_dkim') }}">Export all</a></div>
  {% else %}<p class="h">{{ _('No DKIM keys yet: generate them above.') }}</p>{% endif %}
{% elif name in loaded %}{% set ok, output = loaded[name] %}
  {% if not ok %}<p class="err">{{ output.error }}</p>
  {% elif name == 'uq-list' %}<table class="stack"><tr><th>{{ _('Time') }}</th><th>{{ _('Sender') }}</th><th>{{ _('Recipient') }}</th><th>{{ _('Subject') }}</th><th>{{ _('Score') }}</th><th></th></tr>{% for row in output.mails %}<tr><td>{{ row.ts }}</td><td>{{ row.sender }}</td><td>{{ row.rcpt }}</td><td>{{ row.subject }}</td><td>{{ row.score }}</td>
    <td>{% if row.malware %}<span class="pill">virus</span>{% endif %}{% if row.state == 'requested' %}<span class="pill">asked</span>{% endif %}
    {{ post('uq-show', 'Headers', {'id': row.id}) }}{% if 'uq-content' in commands %}{{ post('uq-content', 'Text', {'id': row.id}) }}{% endif %}{% if not row.malware or session.get('role', 'super') == 'super' %}{{ post('uq-release', 'Release', {'id': row.id}, 'p') }}{% endif %}{% if row.state != 'requested' %}{{ post('uq-request', 'Ask an admin', {'id': row.id}) }}{% endif %}
    {{ post('uq-sender', 'Allow sender', {'id': row.id, 'list': 'allow'}) }}{{ post('uq-sender', 'Block sender', {'id': row.id, 'list': 'block'}) }}</td></tr>{% else %}<tr><td colspan="6">{{ _('Nothing held.') }}</td></tr>{% endfor %}</table>
  {% elif name == 'ssh-root-status' %}{% for warning in output.warnings %}<p class="warnbox">{{ warning }}</p>{% endfor %}
    <p>PermitRootLogin: {{ output.ssh_root_login }}</p>{% if output.ssh_admins %}<p>Can take over: {{ output.ssh_admins|join(', ') }}</p>{% endif %}
    {% for user, why in output.ssh_refused.items() %}<p class="h">{{ user }}: {{ why }}</p>{% endfor %}
  {% elif name == 'rbl-show' %}{% for warning in output.warnings %}<p class="warnbox">{{ warning }}</p>{% endfor %}
    <table><tr><th>ID</th><th>List</th><th>Type</th><th>Score</th><th>Hits</th><th>Errors</th><th>Terms</th><th></th></tr>{% for row in output.lists %}<tr><td>{{ row.id }}</td><td>{{ row.list }}{% if row.url and row.url.startswith('https://') %} <a href="{{ row.url }}" target="_blank" rel="noopener noreferrer">Website</a>{% endif %}{% if row.terms_published and row.terms_url.startswith('https://') %} · <a href="{{ row.terms_url }}" target="_blank" rel="noopener noreferrer">{{ _('Terms of use') }}</a>{% elif not row.terms_published %} · {{ _('no published terms') }}{% endif %}<br><small>{{ row.accepted }}</small></td><td>{{ row.type }}</td><td>{{ row.score }}</td><td>{{ row.hits }}</td><td>{{ row.errors }}</td><td>{{ row.terms }}</td>
    <td>{{ post('rbl-set', 'Turn off' if row.active else 'Turn on', {'id': row.id, 'mode': 'off' if row.active else 'on'}, '' if row.active else 'p') }}</td></tr>{% endfor %}</table>
  {% elif name == 'rotation-status' %}{% if output.rotation_warnings %}<p class="warnbox">{{ output.rotation_warnings|join(' ') }}</p>{% endif %}
  <p class="h">All domains: {{ 'on' if output.rotation_all else 'off' }}. Last check: {{ output.last_run or 'not yet' }}. Next check: {{ output.next_check or 'unknown' }}.</p>{{ show(output.domains) }}
  {% if output.remove_from_dns %}<h3>Remove these DNS records</h3>{{ show(output.remove_from_dns) }}{% endif %}
  {% elif name == 'quarantine-list' %}{% if output.quarantine %}<table class="stack"><tr><th>Received</th><th>From</th><th>To</th><th>Size</th><th>Queue ID</th><th></th></tr>
    {% for mail in output.quarantine %}<tr><td>{{ show(mail.arrived, 'arrived') }}</td><td>{{ show(mail.sender) }}</td><td>{{ show(mail.recipients) }}</td>
    <td>{{ (mail.size or 0)|filesizeformat }}</td><td>{{ mail.id }}</td><td>{{ post('quarantine-release', 'Deliver', {'id': mail.id}) }}
    {{ post('quarantine-show', 'Headers', {'id': mail.id}) }}{% if 'quarantine-content' in commands %}{{ post('quarantine-content', 'Text', {'id': mail.id}) }}{% endif %}
    <a class="btn d" href="{{ url_for('show_page', slug='quar', id=mail.id) }}#quarantine-delete">Delete</a></td></tr>{% endfor %}</table>
    {% else %}<span class="pill">empty</span>{% endif %}
  {% elif name == 'security-status' %}<p class="h">Last check: {{ output.checked or 'not yet' }}. Every day: {{ 'on' if output.daily else 'off' }}.</p>
    {% if output.findings %}<table class="stack"><tr><th></th><th>Finding</th><th>Detail</th><th>What to do</th></tr>{% for item in output.findings %}
    <tr><td><span class="dot {{ 'b' if item.level == 'problem' else 'w' }}"></span></td><td>{{ item.title }}</td><td>{{ item.detail }}</td><td>{{ item.fix }}</td></tr>{% endfor %}</table>
    {% elif output.checked %}<p>No findings.</p>{% endif %}
  {% elif name == 'group-list' %}<table><tr><th>Group</th><th>Description</th><th>Scope</th><th>Members</th><th>Permissions</th></tr>{% for item in output.groups %}
    <tr><td>{{ item.name }}{% if item.predefined %} <span class="pill">predefined</span>{% endif %}{% if item.disabled %} <span class="pill w">off</span>{% endif %}</td>
    <td>{{ item.description }}</td><td>{{ item.scope }}</td><td>{{ item.members }}</td>
    <td><details class="help"><summary>{{ item.permissions|length }}</summary>{{ item.permissions|join(', ') }}</details></td></tr>{% endfor %}</table>
  {% elif name == 'tenant-list' %}{{ show(output) }}
    <form method="post" enctype="multipart/form-data" action="{{ url_for('brand_upload') }}"><input type="hidden" name="csrf" value="{{ csrf }}">
    <div class="row"><label for="brand-tenant">Logo for tenant</label><input type="text" id="brand-tenant" name="tenant" required></div>
    <div class="row"><label for="brand-logo">PNG, up to 200 KB and 1024 pixels</label><input type="file" id="brand-logo" name="logo" accept="image/png" required></div><div class="btns"><button>Upload</button></div></form>
  {% elif name == 'backup-list' %}{% if output.backups %}<table><tr><th>Backup</th><th>Date</th><th>Size</th><th></th><th></th></tr>{% for backup in output.backups %}<tr><td>{{ backup.name }}</td><td>{{ backup.date }}</td><td>{{ backup.size_mb }} MB</td>
    <td>{% if backup.encrypted %}<span class="pill w">&#128274; encrypted</span>{% endif %}</td>
    <td><form method="post" action="{{ url_for('backup_download') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="name" value="{{ backup.name }}">
    <input type="password" name="password" placeholder="Admin password" aria-label="Admin password" autocomplete="current-password" required style="width:150px"> <button>Download</button></form>
    <a class="btn" href="{{ url_for('show_page', slug='bak', name=backup.name) }}#restore">Restore</a></td></tr>{% endfor %}</table>
    {% else %}<span class="pill">none</span>{% endif %}
    <form method="post" enctype="multipart/form-data" action="{{ url_for('backup_upload') }}"><input type="hidden" name="csrf" value="{{ csrf }}">
    <div class="row"><label for="backup-file">Upload a backup (.tar.gz or .tar.gz.gpg, up to 64 MB)</label><input type="file" id="backup-file" name="file" required></div><div class="btns"><button>Upload</button></div></form>
  {% elif name == 'autoupdate-status' %}<p class="h">Installed: {{ output.installed }}. Newest: {{ output.latest or 'not checked yet' }}. Operating system updates: {{ output.os_updates }}.</p>
    {% if output.update_available %}<p class="warnbox">Update available: {{ output.latest }}</p><pre>{{ output.release_notes }}</pre>{% endif %}
    <p class="h">Last check: {{ output.last_check or 'not yet' }}. Last result: {{ output.last_result or 'none' }}</p>
  {% else %}{{ show(output) }}{% endif %}
{% else %}<form method="post" action="{{ url_for('run', name=name) }}"><input type="hidden" name="csrf" value="{{ csrf }}">
  {% if name == 'dkim-create' %}{{ keytable() }}{% endif %}
  {% for arg in cmd.args if arg.web is not sameas false %}{{ field(name, arg) }}{% endfor %}
  {% if name in reauth_commands %}<div class="row"><label for="{{ name }}-reauth">{{ _('Your password, to confirm') }}</label><input type="password" id="{{ name }}-reauth" name="reauth" autocomplete="current-password"></div>{% endif %}
  <div class="btns"><button class="{{ 'd' if name in danger else 'p' }}"{% if name in danger %} data-confirm="{{ cmd.title|t }}?"{% endif %}>{{ (_('Run') if not cmd.args else _('Apply')) if cmd.writes else _('Show') }}</button>{% if name == 'hardening-report' %} <button class="p" formaction="{{ url_for('hardening_pdf') }}">{{ _('Download PDF') }}</button>{% endif %}</div></form>
{% endif %}{% endif %}</div>{% endif %}{% endmacro %}
{% set ns = namespace(hidden=0) %}
{% for section in page.sections %}{% set all = section[1]|select('in', names)|reject('in', hidden_cards)|reject('in', merged)|list %}
{% set shown = [] %}{% set warned = [] %}{% for name in all %}{% if expert or card_level(name, commands[name], section, page.slug) == 'standard' %}{% set ignored = shown.append(name) %}
{%- else %}{% set ns.hidden = ns.hidden + 1 %}{% if warnings_of(loaded.get(name)) %}{% set ignored = warned.append(name) %}{% endif %}{% endif %}{% endfor %}
{% if shown or warned %}{% if section[0] %}<details class="section"{% if section|length < 3 or not expert %} open{% endif %}><summary>{{ section[0]|t }}</summary>{% endif %}
{#- Values are for the expert view, but what asks for an action shows in the standard view too, as a short message. -#}
{% for name in warned %}<div class="card warncard" id="{{ name }}">{% for text in warnings_of(loaded.get(name)) %}<p class="warnbox" role="alert">{{ text }}</p>{% endfor %}</div>{% endfor %}
{% for name in shown %}{{ card(name) }}{% endfor %}{% if section[0] %}</details>{% endif %}{% endif %}{% endfor %}
{% set others = names|reject('in', page.commands)|reject('in', hidden_cards)|list %}{% if others %}{% if expert %}<details class="section"><summary>Other</summary>
{% for name in others %}{{ card(name) }}{% endfor %}</details>{% else %}{% set ns.hidden = ns.hidden + others|length %}{% endif %}{% endif %}
{% if page.slug == 'log' and 'mail-check' in commands %}<div class="card" id="mail-check"><h2>{{ _('Check a mail') }}</h2>
<p class="h">{{ _('The verdict of rspamd for one .eml file: action, score and every rule that counted. Nothing is stored or learned.') }}</p>
<form method="post" enctype="multipart/form-data" action="{{ url_for('mail_check') }}"><input type="hidden" name="csrf" value="{{ csrf }}">
<div class="row"><label for="mail-check-file">{{ _('Mail (.eml, up to 10 MB)') }}</label><input type="file" id="mail-check-file" name="mail" accept=".eml,message/rfc822" required></div>
<div class="btns"><button class="p">{{ _('Check') }}</button></div></form></div>{% endif %}
{% if page.slug == 'disclaimer' and 'disclaimer-import' in commands %}<div class="card" id="disclaimer-import"><h2>{{ _('Disclaimer: import a ZIP') }}</h2>
<p class="h">{{ _('manifest.json, body.html and/or body.txt, media/ and attachments/. Checked whole before anything changes.') }}</p>
<form method="post" enctype="multipart/form-data" action="{{ url_for('disclaimer_import') }}"><input type="hidden" name="csrf" value="{{ csrf }}">
<div class="row"><label for="disclaimer-zip">{{ _('ZIP, up to 5 MB') }}</label><input type="file" id="disclaimer-zip" name="zip" accept=".zip,application/zip" required></div>
<div class="row"><label><input type="checkbox" name="dry_run" value="on" checked> {{ _('Only check and show') }}</label></div>
<div class="btns"><button class="p">{{ _('Import') }}</button></div></form>
{% set dok, dout = loaded.get('disclaimer-status') or (False, {}) %}{% set templates = (dout.get('templates') if dok else []) or [] %}{% if templates and 'disclaimer-export' in commands %}
<form method="post" action="{{ url_for('disclaimer_export') }}"><input type="hidden" name="csrf" value="{{ csrf }}">
<div class="row"><label for="disclaimer-export-id">{{ _('Export as ZIP') }}</label><select id="disclaimer-export-id" name="id">{% for item in templates %}<option>{{ item.id }}</option>{% endfor %}</select></div>
<div class="btns"><button>{{ _('Download ZIP') }}</button></div></form>{% endif %}</div>{% endif %}
{% if ns.hidden %}<p class="h expert-note">{{ _('More on this page in the expert view:') }} {{ ns.hidden }} {{ viewform('expert', _('Show')) }}</p>{% endif %}</main>""")


def acting_as():
    """Tells efactl who works: it holds the rights of the roles and limits the results. The main admin has no user entry."""
    if not has_request_context():
        return []
    user = g.get('api_user') or session.get('user')
    client = request.headers.get('X-Real-IP', request.remote_addr or '')
    # A token bound to one tenant reaches only that tenant.
    limit = [f"--limit-tenant={g.api_tenant}"] if g.get('api_user') and g.get('api_tenant') else []
    sid = session.get('sid')
    return [f'--client={client}'] + limit + ([f'--as={user}'] if user else []) + ([f'--session={session_sha(sid)}'] if sid else [])


STRICT_FILE = os.environ.get('EFA_ETC', '/etc') + '/eFa/audit-strict.json'
strict_cache = {'mtime': None, 'on': False}
# Polled by the pages themselves, or files without a meaning of their own.
STRICT_SKIP = {'copy_js', 'live_js', 'load_card', 'static', 'logo', 'brand_logo', 'favicon', 'icon'}


def reader_language():
    """The language of My settings, kept in the session from the login on, or the one the browser asks for."""
    if 'lang' not in session and session.get('admin'):
        ok, prefs = efactl('my-settings')
        session['lang'] = prefs.get('language', 'auto') if ok else 'auto'
        session['view'] = prefs.get('view', 'standard') if ok else 'standard'
    return efa_i18n.pick(session.get('lang', 'auto'), request.headers.get('Accept-Language'))


def translate(text):
    """A text of the interface in the language of the reader. Texts without a translation stay English."""
    if not text or not has_request_context():
        return text
    if 'lang' not in g:
        g.lang = reader_language()
    return efa_i18n.catalog(g.lang).gettext(text) if g.lang != 'en' else text


# Also for the texts made in Python: scripts/i18n_extract.py collects every quoted text in a call of _ in this file.
_ = translate
app.jinja_env.filters['t'] = translate
app.jinja_env.globals['_'] = translate
app.jinja_env.globals['portal_mode'] = PORTAL
# The pages are fixed strings: compiled once, not on every request (that took 0.2 s a page).
app.jinja_env.from_string = functools.lru_cache(maxsize=64)(app.jinja_env.from_string)


def strict_on():
    """Strict audit mode, read again only when its file changed."""
    try:
        mtime = os.stat(STRICT_FILE).st_mtime
    except OSError:
        return False
    if mtime != strict_cache['mtime']:
        try:
            with open(STRICT_FILE) as f:
                strict_cache.update(mtime=mtime, on=bool(json.load(f).get('on')))
        except (OSError, ValueError):
            strict_cache.update(mtime=mtime, on=False)
    return strict_cache['on']


def strict_object(path, values):
    """Path and parameters of a request for the audit log, secrets masked."""
    shown = {key: '***' if re.search(r'pass|secret|token|key|csrf', key, re.I) else value[:200] for key, value in values.items()}
    return (path + (' ' + json.dumps(shown, sort_keys=True) if shown else ''))[:500]


def portal_who():
    """Session and address of the request, for portal calls made outside it."""
    return request.headers.get('X-Real-IP', request.remote_addr or ''), session.get('sid')


def portal_call(args, secrets_in=None, who=None):
    """The portal: one request to efa-portal-helper, which knows the login of the session and runs efactl for it."""
    client, sid = who or (portal_who() if has_request_context() else ('', None))
    line = json.dumps({'args': list(args), 'secrets': list(secrets_in or []), 'sid': sid, 'client': client}).encode() + b'\n'
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(130)
            sock.connect(PORTAL_SOCKET)
            sock.sendall(line)
            reply = sock.makefile('rb').readline()
        answer = json.loads(reply)
        return bool(answer['ok']), answer['answer']
    except (OSError, ValueError, KeyError) as err:
        app.logger.error('efa-portal-helper %s failed: %s', args[:1], err)
        return False, {'error': 'The portal service does not answer, try again later.'}


def runner_call(args, secrets_in):
    """efactl through efactl-runner. None when the runner is not there (then sudo); False when the call itself broke off:
    never again through sudo, a change could run twice."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(130)
        try:
            sock.connect(RUNNER_SOCKET)
        except OSError:
            return None
        try:
            sock.sendall(json.dumps({'args': list(args), 'secrets': list(secrets_in or [])}).encode() + b'\n')
            reply = json.loads(sock.makefile('rb').readline())
            return subprocess.CompletedProcess(args, reply['code'], reply['stdout'], reply['stderr'])
        except (OSError, ValueError, KeyError, TypeError) as err:
            app.logger.error('efactl-runner %s failed: %s', args[:1], err)
            return False
    finally:
        sock.close()


# Jobs and checks that work or take seconds: they run from their button, never just by opening a page.
ON_BUTTON = {'security-check', 'form-check', 'cluster-dkim-apply', 'cluster-content-apply'}


def on_button_only(name):
    return name in ON_BUTTON or name in HIDDEN_CARDS or name.endswith('-run')


# Reads that are slow or change seldom, kept this many seconds per login. An older answer is shown at once and renewed in the
# background; every change made through this web interface empties the cache. Strict audit mode reads every time.
READ_CACHE_SECONDS = {'schema': 300, 'bayes-status': 600, 'ssh-root-status': 300, 'rotation-status': 300, 'dkim-check': 300, 'rbl-show': 300,
                      'security-status': 60, 'backup-list': 60, 'dash-stats': 20, 'update-pending': 300, 'neural-status': 60,
                      'firewall-show': 30, 'settings': 10, 'status': 10, 'switches-status': 10, 'harvest-status': 30, 'tenant-list': 30, 'group-list': 30,
                      'dane-status': 60, 'ml-status': 60, 'audit-strict-status': 60, 'audit-verify': 60, 'user-list': 10, 'session-list': 10}
read_cache = {}
read_cache_lock = threading.Lock()


# Reads of seconds (rspamd answers rspamc stat in about 4 s): a page never waits for them. They show from the cache when it
# has them, else their card has its button and loads on demand (Hans: "soll nachladen bei bedarf").
ON_DEMAND = {'bayes-status', 'update-pending', 'neural-status', 'ml-status', 'symbol-scores'}


def read_key(who, name):
    # The login, not the address or session: those only go into the audit.
    return tuple(item for item in who if item.startswith(('--as=', '--limit-tenant='))), name


def efactl_read(name, who=None, cached_only=False):
    """A read without arguments, through the cache of READ_CACHE_SECONDS. who: acting_as() of the request, so this runs in a
    thread of its own too (then without the request); the portal always reads directly, in the request. cached_only: the
    answer of the cache while it is fresh, else None, and efactl is not called."""
    seconds = READ_CACHE_SECONDS.get(name)
    who = acting_as() if who is None else who
    if cached_only:
        with read_cache_lock:
            cached = read_cache.get(read_key(who, name))
        return cached[1] if cached and seconds and not strict_on() and time.time() - cached[0] < seconds else None
    if PORTAL and name == 'schema' and has_request_context() and session.get('sid') and not strict_on():
        # The portal: what this session may do, kept per session; the helper checks every call again anyway.
        key = (('portal', session['sid']), name)
        with read_cache_lock:
            cached = read_cache.get(key)
        return cached[1] if cached and time.time() - cached[0] < seconds else _read_store(key, efactl(name))
    if PORTAL or not seconds or strict_on() or (has_request_context() and request.method != 'GET'):
        return efactl(name, who=who)
    key = read_key(who, name)
    with read_cache_lock:
        cached = read_cache.get(key)
        if cached and time.time() - cached[0] >= seconds:
            # Renewed once, in the background; until then the older answer.
            read_cache[key] = (time.time(), cached[1])
            threading.Thread(target=lambda: _read_store(key, efactl(name, who=who)), daemon=True).start()
    if cached:
        return cached[1]
    return _read_store(key, efactl(name, who=who))


def _read_store(key, answer):
    if answer[0]:
        with read_cache_lock:
            read_cache[key] = (time.time(), answer)
    return answer


def efactl(*args, secrets_in=None, who=None):
    """Runs efactl without a shell, so form input stays a plain argument. Passwords go over stdin. who: acting_as(), given
    when this runs outside the request."""
    who = acting_as() if who is None else who
    if PORTAL:
        return portal_call(args, secrets_in)
    done = runner_call(who + list(args), secrets_in)
    if done is False:
        return False, {'error': 'efactl failed, see the log.'}
    try:
        done = done or subprocess.run(EFACTL + who + list(args), capture_output=True, text=True, timeout=120,
                                      input=''.join(line + '\n' for line in secrets_in or []))
    except subprocess.TimeoutExpired:
        app.logger.error('efactl %s timed out', args[:1])
        return False, {'error': 'efactl timed out, see the log.'}
    try:
        return done.returncode == 0, json.loads(done.stdout)
    except ValueError:
        app.logger.error('efactl %s failed: %s', args[:1], done.stderr)
        return False, {'error': 'efactl failed, see the log.'}


LOAD_FILE = os.environ.get('EFA_ETC', '/etc') + '/eFa/load.json'
LOAD_MOUNTS = ('/', '/var')
# Shown with their free space if they are mounts of their own.
LOAD_SHOWN_MOUNTS = ('/', '/var', '/boot', '/tmp', '/home', '/var/log', '/var/lib/mysql')
LOAD_LABELS = {'cpu': 'CPU', 'ram': 'RAM', 'swap': 'Swap', 'disk': 'Disk used', 'io': 'Disk I/O busy', 'nic': 'Network'}
LOAD_ADVICE = {
    'cpu': 'Reduce rspamd workers or Bayes and neural load, check the ClamAV scan limits, or add vCPUs.',
    'ram': 'Check the memory of ClamAV and rspamd, set redis maxmemory, add RAM, and avoid swap.',
    'disk': 'Shorten quarantine and log retention, and remove old backups.',
    'io': 'Use faster storage, or move the redis and rspamd databases.',
    'nic': 'Check the mail volume and possible attacks: Fail2Ban and rate limits.'}
load_samples = collections.deque(maxlen=1440)
load_mailed = {}


def load_settings():
    try:
        with open(LOAD_FILE) as f:
            data = json.load(f)
        return int(data['percent']), int(data['minutes'])
    except (OSError, ValueError, KeyError):
        return 80, 30


def load_read_raw():
    """Counters from /proc only, cheap enough for once a minute."""
    with open('/proc/stat') as f:
        cpu = [int(value) for value in f.readline().split()[1:9]]
    memory = {}
    with open('/proc/meminfo') as f:
        for line in f:
            key, value = line.split(':')
            memory[key] = int(value.split()[0])
    busy = 0
    with open('/proc/diskstats') as f:
        for line in f:
            parts = line.split()
            # Whole devices only, partitions would count twice.
            if re.match(r'^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+)$', parts[2]):
                busy = max(busy, int(parts[12]))
    received = sent = 0
    speed = 0
    with open('/proc/net/dev') as f:
        for line in f.readlines()[2:]:
            name, values = line.split(':')
            name, values = name.strip(), values.split()
            if name != 'lo':
                received += int(values[0])
                sent += int(values[8])
                try:
                    with open(f'/sys/class/net/{name}/speed') as link:
                        speed = max(speed, int(link.read()))
                except (OSError, ValueError):
                    pass
    return {'time': time.time(), 'cpu': cpu, 'memory': memory, 'busy': busy, 'received': received, 'sent': sent, 'speed': speed}


def load_sample(before, now, disks):
    """One sample in percent and Mbit/s, from two readings of the counters."""
    seconds = max(now['time'] - before['time'], 1)
    total = sum(now['cpu']) - sum(before['cpu'])
    idle = now['cpu'][3] + now['cpu'][4] - before['cpu'][3] - before['cpu'][4]
    memory = now['memory']
    rx = (now['received'] - before['received']) * 8 / 1e6 / seconds
    tx = (now['sent'] - before['sent']) * 8 / 1e6 / seconds
    return {'time': now['time'], 'cpu': round(100 * (total - idle) / total, 1) if total > 0 else 0,
            'ram': round(100 * (1 - memory['MemAvailable'] / memory['MemTotal']), 1),
            'swap': round(100 * (1 - memory['SwapFree'] / memory['SwapTotal']), 1) if memory.get('SwapTotal') else 0,
            'disk': max(disks.values()) if disks else 0, 'disks': disks,
            'io': round(min(100, (now['busy'] - before['busy']) / (seconds * 10)), 1), 'rx': round(rx, 2), 'tx': round(tx, 2),
            'nic': round(100 * max(rx, tx) / now['speed'], 1) if now['speed'] > 0 else 0}


def load_disks():
    used = {}
    for mount in LOAD_MOUNTS:
        stat = os.statvfs(mount)
        if stat.f_blocks:
            used[mount] = round(100 * (1 - stat.f_bavail / stat.f_blocks), 1)
    return used


def load_extra():
    """Load average and free space per own mount, at the time the card is shown."""
    disks = []
    for mount in LOAD_SHOWN_MOUNTS:
        if mount == '/' or os.path.ismount(mount):
            stat = os.statvfs(mount)
            if stat.f_blocks:
                disks.append({'mount': mount, 'free': round(stat.f_bavail * stat.f_frsize / 1e9, 1), 'size': round(stat.f_blocks * stat.f_frsize / 1e9, 1),
                              'used': round(100 * (1 - stat.f_bavail / stat.f_blocks), 1)})
    return {'load': [f'{value:.2f}' for value in os.getloadavg()], 'cpus': os.cpu_count() or 1, 'disks': disks}


def load_sustained(samples, resource, percent, minutes):
    """True if the 15-minute average stayed at the limit for the set time. Needs that many samples."""
    values = [sample[resource] for sample in samples]
    if len(values) < minutes:
        return False
    for end in range(len(values) - minutes + 1, len(values) + 1):
        window = values[max(0, end - 15):end]
        if sum(window) / len(window) < percent:
            return False
    return True


def load_loop():
    before = load_read_raw()
    while True:
        time.sleep(60)
        try:
            now = load_read_raw()
            load_samples.append(load_sample(before, now, load_disks()))
            before = now
            percent, minutes = load_settings()
            today = time.strftime('%Y-%m-%d')
            for resource in LOAD_ADVICE:
                if load_sustained(load_samples, resource, percent, minutes) and load_mailed.get(resource) != today:
                    load_mailed[resource] = today
                    efactl('load-notify', f'--text={LOAD_LABELS[resource]} is at {percent}% or more. {LOAD_ADVICE[resource]}')
        except (OSError, ValueError, KeyError, ZeroDivisionError) as err:
            app.logger.warning('load sample failed: %s', err)


def load_view(samples, percent, minutes):
    rows, advice = [], []
    if not samples:
        return rows, advice
    day, recent = list(samples), list(samples)[-15:]
    for resource in ('cpu', 'ram', 'swap', 'disk', 'io', 'nic'):
        values = [sample[resource] for sample in day]
        last = values[-60:]
        top = max(max(last), 1)
        width = max(len(last) - 1, 1)
        points = ' '.join(f'{i * 100 / width:.1f},{20 - value * 19 / top:.1f}' for i, value in enumerate(last))
        rows.append({'label': LOAD_LABELS[resource], 'now': values[-1], 'avg': round(sum(sample[resource] for sample in recent) / len(recent), 1),
                     'top': max(values), 'points': points})
        if resource in LOAD_ADVICE and load_sustained(day, resource, percent, minutes):
            advice.append(f'{LOAD_LABELS[resource]} is at {percent}% or more for {minutes} minutes. {LOAD_ADVICE[resource]}')
    return rows, advice


def csrf_token():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_urlsafe(32)
    return session['csrf']


def session_sha(sid):
    return hashlib.sha256(sid.encode()).hexdigest()


def session_active():
    sid = session.get('sid')
    expiry = active_sessions.get(sid)
    now = time.time()
    if not session.get('admin') or expiry is None or expiry < now:
        if session.get('admin') and expiry is not None and strict_on():
            g.audit_action = 'session_timeout'
        return False
    if now - session_checked.setdefault(sid, now) > SESSION_CHECK_SECONDS:
        ok, state = efactl('session-check', f'--session={session_sha(sid)}')
        # A slow or broken efactl must not log everyone out; an ended session or a locked user does.
        if (ok and not state.get('active')) or (not ok and state.get('error') in ('This user is disabled.', 'Unknown user.')):
            active_sessions.pop(sid, None)
            session_checked.pop(sid, None)
            return False
        session_checked[sid] = now
        if ok and state.get('role'):
            session['role'] = state['role']
    active_sessions[sid] = now + SESSION_MAX_AGE
    return True


def session_start(user=None, role='super', sid=None):
    now = time.time()
    for sid in [sid for sid, expiry in active_sessions.items() if expiry < now]:
        active_sessions.pop(sid, None)
    session.clear()
    session.permanent = True
    session['admin'] = True
    session['role'] = role
    if user:
        session['user'] = user
    # In the portal the helper gives the id: it binds the login to it.
    session['sid'] = sid or secrets.token_urlsafe(32)
    active_sessions[session['sid']] = now + SESSION_MAX_AGE
    session_checked[session['sid']] = now
    for sid in [sid for sid in session_checked if sid not in active_sessions]:
        session_checked.pop(sid, None)
    if has_request_context():
        efactl('session-open', f'--session={session_sha(session["sid"])}', f"--agent={request.headers.get('User-Agent', '')[:200]}")
        if user:
            ok, who = efactl('whoami')
            brand = who.get('brand') if ok else None
            if brand:
                session['brand'] = {'name': brand['name'], 'color': brand['color'], 'logo': brand['logo'], 'tenant': brand['tenant_id']}


# 5q: the right of each route, in one place. efactl: every call there checks the right of the login for that command; super: what
# the route hands out goes beyond the rights in efactl; open: before a login or with a token of its own. A new route without an
# entry here fails the self test.
ROUTE_RIGHTS = {
    'login': 'open', 'logout': 'efactl', 'post_only': 'open', 'oidc_login': 'open', 'oidc_callback': 'open', 'quarantine_link': 'open',
    'link_check': 'open', 'api': 'open', 'api_schema': 'open', 'metrics': 'open', 'copy_js': 'open', 'favicon': 'open', 'live_js': 'open', 'senders_js': 'open',
    'index': 'efactl', 'show_page': 'efactl', 'set_view': 'efactl', 'mail_check': 'efactl', 'disclaimer_import': 'efactl', 'disclaimer_export': 'efactl', 'legal': 'open', 'legal_file': 'open', 'legal_accept': 'efactl', 'hardening_pdf': 'efactl', 'run': 'efactl', 'mail_page': 'efactl', 'mail_headers': 'efactl', 'mail_evidence': 'efactl',
    'export_file': 'efactl', 'brand_logo': 'efactl', 'brand_upload': 'efactl', 'maillog_live': 'efactl', 'load_card': 'efactl',
    'backup_download': 'super', 'backup_upload': 'super', 'rspamd_auth': 'super', 'rspamd_open': 'super', 'export_dkim': 'super',
    'senders_data': 'super', 'static': 'open'}
SUPER_ONLY = {name for name, right in ROUTE_RIGHTS.items() if right == 'super'}
# 5q: changes that need the password of the admin again, at most every 5 minutes.
REAUTH_COMMANDS = {'user-set', 'user-state', 'group-set', 'group-map-set', 'tenant-group-map-set', 'token-create', 'firewall-set', 'firewall-guard-set',
                   'ssh-root-set', 'web-allowlist-set', 'restore', 'dkim-remove', 'dkim-import', 'backup-password-set', 'admin-password', 'audit-mode',
                   'cluster-init', 'cluster-token', 'cluster-leave', 'oidc-set', 'ldap-set', 'api-set'}
REAUTH_SECONDS = 300


def reauth_ok(form):
    """The password of the logged-in admin, again, for a critical change; good for five minutes."""
    if time.time() - session.get('reauth', 0) < REAUTH_SECONDS:
        return True
    password = form.get('reauth', '')
    if not password:
        return False
    # Counted as failed logins: a taken-over session must not try passwords without end.
    client = request.headers.get('X-Real-IP', request.remote_addr)
    count, since = login_failures.get(client, (0, 0))
    if count >= MAX_LOGIN_FAILURES and time.time() - since < LOCKOUT_SECONDS:
        return False
    if session.get('user'):
        ok, _who = efactl('user-verify', f"--username={session['user']}", secrets_in=[password])
    else:
        try:
            with open(PASSWORD_FILE) as f:
                ok = password_ok(f.read().strip(), password)
        except OSError:
            ok = False
    if ok:
        session['reauth'] = time.time()
        login_failures.pop(client, None)
    else:
        login_failures[client] = (count + 1, time.time())
        app.logger.warning('efa-web login failed from %s', client)
    return ok


WEB_ALLOW_FILE = os.environ.get('EFA_ETC', '/etc') + '/eFa/web-allowlist.json'
web_allow_cache = {'mtime': None, 'networks': None}


def admin_address_ok(client):
    """5p: the admin interface answers only the allowed networks, when that is on. Read again only when the file changed."""
    try:
        mtime = os.stat(WEB_ALLOW_FILE).st_mtime
    except OSError:
        return True
    if mtime != web_allow_cache['mtime']:
        try:
            with open(WEB_ALLOW_FILE) as f:
                state = json.load(f)
            networks = [ipaddress.ip_network(item['network']) for item in state.get('entries', [])] if state.get('mode') == 'allowed' else None
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            networks = []  # a broken file refuses: the console switches it off (efactl web-allowlist-set --mode off)
        web_allow_cache.update(mtime=mtime, networks=networks)
    networks = web_allow_cache['networks']
    if networks is None:
        return True
    try:
        address = ipaddress.ip_address(client)
    except ValueError:
        return False
    return any(address in network for network in networks)


@app.before_request
def forget_reads():
    # Every form and button posts: what was read before may be out of date now.
    if request.method == 'POST':
        with read_cache_lock:
            read_cache.clear()


@app.before_request
def protect():
    if not PORTAL and not admin_address_ok(request.headers.get('X-Real-IP', request.remote_addr or '')):
        # Fail2Ban reads this line.
        app.logger.warning('efa-web admin address refused from %s', request.headers.get('X-Real-IP', request.remote_addr))
        abort(403)
    if request.endpoint in ('api', 'api_schema', 'metrics', 'quarantine_link', 'link_check'):
        return None  # Token instead of cookie, so no CSRF risk.
    if request.endpoint in ('legal', 'legal_file', 'favicon') and request.method == 'GET':
        return None  # open to everyone, like the texts in the repository (and the icon of the login page)
    if request.method == 'POST' and not hmac.compare_digest(request.form.get('csrf', ''), session.get('csrf', '')
                                                            or secrets.token_urlsafe(8)):
        abort(403)
    if request.endpoint in ('login', 'rspamd_auth', 'oidc_login', 'oidc_callback', 'post_only') and not request.method == 'POST':
        return None
    if request.endpoint != 'login' and not session_active():
        return redirect(url_for('login'))
    if request.endpoint in SUPER_ONLY and session.get('role', 'super') != 'super':
        abort(403)
    if PORTAL and request.endpoint not in ('login', 'quarantine_link', 'link_check') and session.get('role') != 'user':
        abort(403)
    if not PORTAL and request.endpoint not in ('login', 'logout', 'legal_accept', 'static', 'post_only') and not legal_confirmed():
        return redirect(url_for('legal_accept'))


def legal_info():
    """The summary of the installed legal texts, read again when the package changes it; None in a checkout without them."""
    path = os.path.join(efa_legal.FOLDER, 'summary.json')
    try:
        stamp = os.stat(path).st_mtime_ns
    except OSError:
        return None
    if legal_cache.get('info', (None,))[0] != stamp:
        with open(path, encoding='utf-8') as f:
            legal_cache['info'] = (stamp, json.load(f))
    return legal_cache['info'][1]


def legal_confirmed():
    """Whether the installed legal texts are confirmed; a checkout without them asks nothing. Two stat calls per page."""
    info = legal_info()
    if not info:
        return True
    try:
        stamp = os.stat(efa_legal.ACCEPTED).st_mtime_ns
    except OSError:
        return False
    if legal_cache.get('accepted', (None,))[0] != (stamp, info['digest']):
        legal_cache['accepted'] = ((stamp, info['digest']), bool(efa_legal.accepted(efa_legal.ACCEPTED, info['digest'])))
    return legal_cache['accepted'][1]


legal_cache = {}


@app.after_request
def strict_audit(response):
    """In strict audit mode every request is logged: page views, searches with their filters, downloads, API calls, refusals."""
    if not strict_on() or g.get('audit_done') or request.endpoint in STRICT_SKIP:
        return response
    path = re.sub(r'[^\w./-]', '_', request.path)[:100]
    action = g.get('audit_action') or f"{'api_call' if request.endpoint in ('api', 'api_schema', 'metrics') else 'request'}:{request.method} {path}"
    values = {key: value for key, value in (request.args if request.method == 'GET' else request.form).items()}
    efactl('audit-note', f'--action={action}', f'--object={g.get("audit_object") or strict_object(request.path, values)}', f'--result={response.status_code}')
    return response


@app.after_request
def harden(response):
    response.headers.update({'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff',
                             'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; base-uri 'self'; "
                                                        "form-action 'self'; frame-ancestors 'none'",
                             'Referrer-Policy': 'same-origin',
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
            username = request.form.get('username', '').strip()
            if username:
                ok, who = efactl('user-verify', f'--username={username}', secrets_in=[request.form.get('password', '')])
                if ok and not PORTAL and who['role'] == 'user':
                    # Users have their own portal, in a process without rights: the admin interface takes no user login.
                    return render_template_string(LOGIN, csrf=csrf_token(), error=None, sso=False, tenant_sso=False, portal=True)
                if ok:
                    login_failures.pop(client, None)
                    session_start(who['username'], who['role'], sid=who.get('sid'))
                    # The event collector of efactl reads this line.
                    app.logger.warning('efa-web login ok user %s from %s', who['username'], client)
                    g.audit_action = 'login_ok'
                    return redirect(url_for('index'))
            elif stored and not PORTAL and password_ok(stored, request.form.get('password', '')):
                login_failures.pop(client, None)
                session_start()
                app.logger.warning('efa-web login ok user admin from %s', client)
                g.audit_action = 'login_ok'
                return redirect(url_for('index'))
            # Every address that fails stays in memory, so forget those silent for a day.
            for old in [key for key, (_count, last) in login_failures.items() if time.time() - last > 86400]:
                login_failures.pop(old, None)
            login_failures[client] = (count + 1, time.time())
            # Fail2Ban reads this line.
            app.logger.warning('efa-web login failed from %s', client)
            g.audit_action, g.audit_object = 'login_failed', 'user ' + (username or 'admin')
            error = 'Wrong password.'
    # shortcut: no single sign-on in the portal yet, its address would need its own redirect address at the provider; later.
    ok, sso = (False, {}) if PORTAL else efactl('oidc-status')
    return render_template_string(LOGIN, csrf=csrf_token(), error=error or session.pop('sso_error', None), sso=ok and sso.get('oidc'),
                                  tenant_sso=ok and sso.get('tenant_sso'), portal=False)


OIDC_COOKIE = 'efa_oidc'
OIDC_SECONDS = 600
# The session cookie is SameSite=Strict: a browser does not send it on the way back from the provider,
# nor on a redirect in that chain. So the login state has its own cookie, and the last step is a page that moves on by itself.
MOVE_ON = '<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url={url}"><title>eFa-next</title><a href="{url}">Continue</a>'


def oidc_signer():
    return URLSafeTimedSerializer(app.secret_key, salt='efa-oidc')


def move_on(endpoint):
    response = Response(MOVE_ON.format(url=url_for(endpoint)), mimetype='text/html')
    response.delete_cookie(OIDC_COOKIE, path='/login/oidc')
    return response


LINK_PAGE = PAGE.replace(BLOCK, SOLO + """<div class="card">{% if error %}<p class="err" role="alert">{{ error }}</p>{% elif done %}<p>Done: {{ done }}.</p>
{% else %}<p><b>{{ view.question }}</b></p>{% if view.sender %}<p>From {{ view.sender }}: {{ view.subject }}</p>{% endif %}<form method="post"><div class="btns"><button class="p">Yes</button></div></form>{% endif %}</div></main>""")


CONTENT_FILE = os.environ.get('EFA_ETC', '/etc') + '/efa-web/content.json'
RSPAMD_CHECK = 'http://127.0.0.1:11333/checkv2'
LINK_CACHE_SECONDS = 300
link_cache = {}
LINK_WARNING = PAGE.replace(BLOCK, SOLO + """<div class="card">{% if reasons is none %}<h2>{{ _('The link could not be checked just now') }}</h2>
<p>{{ _('It leads to this address:') }}</p><p class="h">{{ target }}</p>{% else %}<h2>{{ _('This link may be dangerous') }}</h2>
<p>{{ _('The address is listed as dangerous or as phishing:') }}</p><p class="h">{{ target }}</p><p class="h">{{ reasons|join(', ') }}</p>{% endif %}
{% if allow %}<p><a class="btn" href="{{ target }}" rel="noopener noreferrer">{{ _('Go on anyway') }}</a></p>{% endif %}
<p>{{ _('If you did not expect this mail, delete it.') }}</p></div></main>""")


def link_verdict(url, now=None):
    """What rspamd thinks of an address now: its URL lists and rules, on a mail with only this address. Cached for a few minutes."""
    now = now or time.time()
    found = link_cache.get(url)
    if found and now - found[1] < LINK_CACHE_SECONDS:
        return found[0]
    message = f'From: link-check@localhost\r\nTo: link-check@localhost\r\nSubject: link check\r\n\r\n{url}\r\n'.encode('utf-8')
    request_ = urllib.request.Request(RSPAMD_CHECK, data=message, headers={'IP': '127.0.0.1', 'Pass': 'all'})
    try:
        with urllib.request.urlopen(request_, timeout=10) as reply:
            verdict = efa_links.dangerous(json.loads(reply.read()).get('symbols', {}))
    except (OSError, ValueError):
        # rspamd does not answer: None, and nothing is cached. The setting decides what the reader gets.
        return None
    if len(link_cache) > 10000:
        link_cache.clear()
    link_cache[url] = (verdict, now)
    return verdict


@app.route('/l/<token>')
def link_check(token):
    """A link of a mail: checked again on each click, then followed, or a warning. Only signed links of this server."""
    try:
        with open(CONTENT_FILE) as f:
            links = json.load(f).get('links', {})
    except (OSError, ValueError):
        links = {}
    target = efa_links.link_target(token, bytes.fromhex(links['key'])) if links.get('key') else None
    if PORTAL:
        # The link key stays with the helper.
        ok, found = efactl('link-target', token)
        links, target = (found, found.get('target')) if ok else ({}, None)
    if not target:
        abort(404)
    reasons = link_verdict(target)
    if reasons is None:
        # The event collector of efactl reads this line and sends it on to the SIEM.
        app.logger.warning('efa-web link unchecked %s', target[:200])
        unchecked = links.get('unchecked', 'page')
        if unchecked == 'follow':
            return redirect(target, code=302)
        return render_template_string(LINK_WARNING, target=target, reasons=None, allow=unchecked == 'page'), 200
    app.logger.warning('efa-web link %s %s', 'blocked' if reasons else 'followed', target[:200])
    if not reasons:
        return redirect(target, code=302)
    return render_template_string(LINK_WARNING, target=target, reasons=reasons, allow=links.get('continue', True)), 200


@app.route('/q/<token>', methods=['GET', 'POST'])
def quarantine_link(token):
    """A link from a digest. Opening it only asks: mail scanners open links too. The token is the secret, so no CSRF risk."""
    if request.method == 'GET':
        ok, view = efactl('uq-link-view', secrets_in=[token])
        return render_template_string(LINK_PAGE, view=view if ok else {}, error=None if ok else view.get('error'), done=None)
    ok, result = efactl('uq-link-use', secrets_in=[token])
    if not ok:
        return render_template_string(LINK_PAGE, view={}, error=result.get('error'), done=None)
    if result['purpose'] == 'login':
        if not PORTAL:
            abort(404)
        session_start(result['username'], result['role'], sid=result.get('sid'))
        return redirect(url_for('show_page', slug=USER_PAGE))
    return render_template_string(LINK_PAGE, view={}, error=None, done=result['done'])


@app.route('/login/oidc')
def oidc_login():
    domain = request.args.get('domain', '').strip()[:253]
    ok, output = efactl('oidc-start', f'--domain={domain}')
    if not ok:
        session['sso_error'] = output.get('error')
        return redirect(url_for('login'))
    response = redirect(output['url'])
    response.set_cookie(OIDC_COOKIE, oidc_signer().dumps([output['state'], output['nonce'], output['verifier'], output.get('tenant', '')]), max_age=OIDC_SECONDS,
                        path='/login/oidc', secure=True, httponly=True, samesite='Lax')
    return response


@app.route('/login/oidc/callback')
def oidc_callback():
    """The state ties this answer to the browser that started the login."""
    try:
        expected, nonce, verifier, tenant = (oidc_signer().loads(request.cookies.get(OIDC_COOKIE, ''), max_age=OIDC_SECONDS) + [''])[:4]
    except (BadSignature, ValueError, TypeError):
        expected, nonce, verifier, tenant = '', '', '', ''
    code = request.args.get('code', '')
    if not expected or not code or not hmac.compare_digest(request.args.get('state', ''), expected):
        session['sso_error'] = 'The login could not be finished, please try again.'
        return move_on('login')
    ok, who = efactl('oidc-finish', f'--code={code}', f'--nonce={nonce}', f'--verifier={verifier}', f'--tenant={tenant}')
    if not ok:
        app.logger.warning('efa-web login failed from %s', request.headers.get('X-Real-IP', request.remote_addr))
        session['sso_error'] = who.get('error')
        return move_on('login')
    session_start(who['username'], who['role'])
    return move_on('index')


@app.route('/logout', methods=['POST'])
def logout():
    if strict_on():
        efactl('audit-note', '--action=logout', '--result=ok')
        g.audit_done = True
    if session.get('sid') in active_sessions:
        efactl('session-end', f"--session={session_sha(session['sid'])}")
    active_sessions.pop(session.get('sid'), None)
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
    # Each tile names the page and the command card it opens, or a short detail where no page fits.
    # The template links only if the reader may use that command.
    def tile(label, value, dot=None, slug=None, anchor=None, detail=None, note=None):
        return {'label': label, 'value': value, 'dot': dot, 'slug': slug, 'anchor': anchor, 'detail': detail, 'note': note}
    stats = loaded['dash-stats'][1] if loaded.get('dash-stats', (False,))[0] else None
    processes = (stats or {}).get('processes')
    counted = ' · '.join(f'{name} {count}' for name, count in processes.items()) if processes else None
    tiles = [tile('Mail system', 'Unknown', 'w', 'dash', 'status') if not status else
             tile('Mail system', f'{len(services)} down', 'b', 'dash', 'status', 'Down: ' + ', '.join(services), counted) if services else
             tile('Mail system', 'Running', '', 'dash', 'status', 'All services run.', counted),
             tile('Milters', 'Unknown', 'w', 'maint', 'milter-chain-set') if not status else
             tile('Milters', f'{len(milters)} not answering', 'b', 'maint', 'milter-chain-set', 'Not answering: ' + ', '.join(name[7:] for name in milters))
             if milters else tile('Milters', 'All answering', '', 'maint', 'milter-chain-set', 'All milters of the chain answer.')]
    if stats:
        today = stats['today']
        share = today['percent']
        tiles.append(tile('Today', f"{today['processed']} mails, {today['megabytes']} MB", None, 'log', 'message-search', None,
                          f"clean {share['clean']}% · spam {share['spam']}% · high score {share['high_spam']}% · viruses {today['viruses']} · "
                          f"blocked files {today['blocked_files']}" + (f" · top virus {today['top_virus']}" if today['top_virus'] else '')))
        if 'queues' in stats:
            counts = stats['queues']['counts']
            total = {name: sum(way.values()) for name, way in counts.items()}
            tiles.append(tile('Queues', f"{total.get('active', 0)} active, {total.get('deferred', 0)} deferred, {total.get('hold', 0)} held",
                              'w' if stats['queues']['warn'] else '', None, None,
                              '; '.join(f"{name}: {way['in']} inbound, {way['out']} outbound" for name, way in sorted(counts.items())) or 'All queues are empty.'))
    if settings and not settings['quarantine']:
        tiles.append(tile('Quarantine', 'Off', None, 'quar', 'quarantine-set'))
    else:
        count = len(held['quarantine']) if held else 0
        tiles.append(tile('Quarantine', f"{count} message{'' if count == 1 else 's'}" if held else 'Unknown',
                          None if held else 'w', 'quar', 'quarantine-list'))
    names = backups['backups'] if backups else []
    if backups is not None:
        # Only for whoever may see the backups.
        tiles.append(tile('Last backup', names[-1]['date'] if names else 'None', '' if names else 'w', 'bak', 'backup-list'))
    rotation = loaded.get('rotation-status', (False, None))
    if rotation[0]:
        tiles.append(tile('DKIM rotation check', rotation[1]['last_run'] or 'not yet', None, 'dkim', 'rotation-status'))
        tiles.append(tile('Next rotation check', rotation[1]['next_check'] or 'unknown', None, 'dkim', 'rotation-status'))
    check = loaded.get('security-status', (False, None))
    if check[0] and check[1].get('checked'):
        counts = {level: len([item for item in check[1]['findings'] if item['level'] == level]) for level in ('problem', 'warning')}
        tiles.append(tile('Security check', f"{counts['problem']} problems, {counts['warning']} warnings" if any(counts.values()) else 'ok',
                          'b' if counts['problem'] else 'w' if counts['warning'] else '', 'sec', 'security-status'))
    bayes = loaded.get('bayes-status', (False, None))
    if bayes[0]:
        state = 'counts' if bayes[1]['active'] else f"counts from {bayes[1]['min_learns']} each"
        tiles.append(tile('Bayes', f"{bayes[1]['spam_learned']} spam, {bayes[1]['ham_learned']} ham learned; {state}", None, 'spam', 'bayes-status'))
    attention = [(_('{} is down').format(name), 'dash', 'status') for name in down]
    check = loaded.get('security-status', (False, None))
    problems = len([item for item in check[1]['findings'] if item['level'] == 'problem']) if check[0] and check[1].get('checked') else 0
    if problems:
        attention.append((_('Security self check: {} problems').format(problems), 'sec', 'security-status'))
    if backups and not names:
        attention.append((_('No backup yet'), 'bak', 'backup-now'))
    if settings and not settings['auto_backup']:
        attention.append((_('Automatic backup is off'), 'bak', 'backup-set'))
    if settings and settings['maintenance_mode']:
        attention.append((_('Maintenance mode is on'), 'maint', 'maintenance-set'))
    attention += [(warning, 'dkim', 'dkim-check') for warning in (dkim or {}).get('warnings', [])]
    attention += [(warning, 'sec', 'ssh-root-status') for warning in loaded.get('ssh-root-status', (False, {}))[1].get('warnings', [])]
    attention += [(warning, 'dkim', 'rotation-status') for warning in (status or {}).get('dkim_rotation', [])]
    attention += [(notice, 'maint', 'update-status') for notice in (status or {}).get('system_notices', [])]
    if stats and stats.get('queues', {}).get('warn'):
        attention.append(('Many mails wait in the queues', 'dash', 'status'))
    attention += [(warning, 'rbl', 'rbl-set') for warning in loaded.get('rbl-show', (False, {}))[1].get('warnings', []) if warning.startswith('Terms of use not yet')]
    flow = loaded.get('flow-status', (False, None))
    picture = flow_svg(flow[1], (stats or {}).get('last_hour')) if flow[0] else None
    return tiles, attention, minute_chart(stats['last_hour']) if stats else None, picture


# 9l: the setup as a picture on the start page. Own flat drawings, eFa in the colours of the logo, the rest neutral. Text only in
# the tooltips (title). The letters run at one slow pace; only how many run follows the mail of the last 10 minutes.
FLOW_STYLE = """<style>
.flow{--fl-ink:#3b3d3a;--fl-soft:#eef0ec;--fl-mid:#c9ccc4;--fl-efa:#646563;--fl-green:#c0cf48;--fl-ok:#7f8a3a;--fl-q:#d39a2c;--fl-x:#c2553f;--fl-path:#b9bcb4}
@media (prefers-color-scheme: dark){.flow{--fl-ink:#e6e7e3;--fl-soft:#2e302d;--fl-mid:#50534d;--fl-efa:#8d8f8b;--fl-ok:#c0cf48;--fl-path:#5c5f58}}
.flow .ink{stroke:var(--fl-ink);stroke-width:3;stroke-linejoin:round;stroke-linecap:round}
.flow .soft{fill:var(--fl-soft)}.flow .mid{fill:var(--fl-mid)}.flow .efa{fill:var(--fl-efa)}.flow .green{fill:var(--fl-green)}
.flow .route{fill:none;stroke:var(--fl-path);stroke-width:4;stroke-linecap:round}.flow .route.out{stroke-dasharray:2 9}
.flow .ghost{opacity:.35}.flow .led.ok{fill:var(--fl-green)}.flow .led.bad{fill:var(--fl-x)}
.flow .mail{color:var(--fl-ok)}.flow .mail.q{color:var(--fl-q)}.flow .mail.x{color:var(--fl-x)}.flow .lock.ok{fill:var(--fl-ok)}.flow .lock.warn{fill:var(--fl-q)}.flow .lock.bad{fill:var(--fl-x)}
.flow .here{fill:var(--fl-green);stroke:var(--fl-ink);stroke-width:2}
@media (prefers-reduced-motion: reduce){.flow .mail,.flow .shield{display:none}}
</style>"""

FLOW_DEFS = """<defs>
<g id="fl-env"><g transform="rotate(-14)"><rect x="-13" y="-9" width="26" height="18" rx="3" fill="#fff" stroke="currentColor" stroke-width="2.5"/>
<path d="M-12-8 0 1 12-8" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linejoin="round"/></g></g>
<g id="fl-lock"><rect x="-6" y="-2" width="12" height="9" rx="2"/><path d="M-3.5-2v-3a3.5 3.5 0 0 1 7 0v3" fill="none" stroke="currentColor" stroke-width="2"/></g>
<g id="fl-key"><circle cx="-5" r="4" fill="none" stroke-width="2.5"/><path d="M-1 0h9m-3 0v3m-3-3v2" fill="none" stroke-width="2.5"/></g>
</defs>"""


def _flow_cloud(x, y):
    return (f'<g transform="translate({x} {y})" tabindex="0"><title>Internet</title>'
            '<path class="soft ink" d="M-58 22a24 24 0 0 1 4-46a32 32 0 0 1 58-10a26 26 0 0 1 44 16a22 22 0 0 1 2 40z"/></g>')


def _flow_server(down=False):
    """The eFa-next server as drawn by the project: dark frame with a lighter ring, white panel with the word mark."""
    frame = '#c2553f' if down else '#4b4d4c'
    return (f'<rect x="-52" y="-19" width="104" height="38" rx="9" fill="{frame}"/>'
            '<rect x="-49.5" y="-16.5" width="99" height="33" rx="7" fill="#6b6d6c"/>'
            '<rect x="-47.5" y="-14.5" width="95" height="29" rx="5.5" fill="#3e403f"/>'
            '<rect x="-46" y="-13" width="92" height="26" rx="4" fill="#fff"/>'
            '<text x="0" y="3.5" text-anchor="middle" font-family="Segoe UI, Helvetica, Arial, sans-serif" font-size="15" fill="#646563">'
            '<tspan font-weight="800" letter-spacing="-.5">e<tspan fill="#c0cf48">F</tspan>a</tspan><tspan font-weight="300" dx="2">next</tspan></text>'
            '<text x="0" y="10" text-anchor="middle" font-family="Segoe UI, Helvetica, Arial, sans-serif" font-size="4.6" letter-spacing=".4" fill="#646563">'
            'email <tspan font-weight="700">FILTER</tspan> appliance</text>')


def _flow_node(x, y, node, ghost=0):
    """An eFa server in the colours of the logo, with its own key and a status light; the own one with a green marker."""
    if ghost:
        return (f'<g class="ghost" transform="translate({x} {y})" tabindex="0"><title>{ghost} more eFa nodes</title>{_flow_server()}'
                f'<text x="0" y="-26" text-anchor="middle" font-size="20" fill="currentColor">…</text>'
                f'<text x="0" y="38" text-anchor="middle" font-size="15" font-weight="700" fill="currentColor">+{ghost}</text></g>')
    tip = f"{node['name']} ({node['role']}, {node['state']})"
    if node.get('fingerprint'):
        tip += f"; own key {node['fingerprint']}…" + (f", until {node['until']}" if node.get('until') else '')
    here = ('<path class="here" d="M0-36l9 11h-18z"/>' if node.get('self') else '')
    return (f'<g class="node" transform="translate({x} {y})" tabindex="0"><title>{html_escape(tip)}'
            f'{" – you are here" if node.get("self") else ""}</title>{here}{_flow_server(node["state"] == "down")}'
            '<g class="green" transform="translate(44 -28) scale(.8)" stroke="var(--fl-ink)"><use href="#fl-key"/></g></g>')


def _flow_target(x, y, target):
    if target['kind'] == 'cloud':
        shape = ('<path class="soft ink" d="M-34 14a15 15 0 0 1 3-29a20 20 0 0 1 36-6a16 16 0 0 1 27 10a14 14 0 0 1 1 25z"/>'
                 '<rect class="mid ink" x="-10" y="-4" width="20" height="18" rx="2"/>')
    else:
        shape = ('<rect class="soft ink" x="-24" y="-30" width="48" height="60" rx="6"/>'
                 '<path class="ink" d="M-14-16h28M-14-6h28M-14 4h18" fill="none"/>')
    return f'<g transform="translate({x} {y})" tabindex="0"><title>{html_escape(target["name"])}</title>{shape}</g>'


def _flow_printer(x, y, count):
    return (f'<g transform="translate({x} {y})" tabindex="0"><title>Relay senders: {count} network{"s" if count != 1 else ""} '
            '(scanners, printers, applications)</title><rect class="soft ink" x="-26" y="-10" width="52" height="26" rx="5"/>'
            '<rect class="mid ink" x="-16" y="-24" width="32" height="14" rx="2"/><rect class="soft ink" x="-14" y="10" width="28" height="14"/></g>')


def flow_svg(flow, minutes):
    """The picture of the setup with the mail of the last 10 minutes: never a sender, subject or address."""
    recent = (minutes or [])[-10:]
    mails, spam, virus = (sum(item.get(key, 0) for item in recent) for key in ('mails', 'spam', 'virus'))
    shown = sorted(flow['nodes'], key=lambda n: not n.get('self'))
    visible, rest = shown[:3], max(0, len(shown) - 3)
    columns = visible + ([{'ghost': rest}] if rest else [])
    # 64 between the centres: about 26 px free between two servers.
    step = 64
    width, height = 960, max(300, step * len(columns) + 140)
    first = height / 2 - step * (len(columns) - 1) / 2
    node_at = [(470, round(first + step * i)) for i in range(len(columns))]
    targets = flow['targets'][:4] or [{'name': 'internal mail server', 'kind': 'server'}]
    tgap = (height - 70) / (len(targets) + 1)
    target_at = [(830, round(tgap * (i + 1))) for i in range(len(targets))]
    cloud = (120, height // 2)
    # Two junctions keep the picture calm: the internet meets the nodes at one point, the nodes the targets at another.
    hub_in, hub_out = (290, height // 2), (650, height // 2)
    parts, routes = [], []
    for i, (nx, ny) in enumerate(node_at):
        routes.append((f'in{i}', f'M{cloud[0] + 52} {cloud[1]} L{hub_in[0]} {hub_in[1]} C{hub_in[0] + 90} {hub_in[1]} {nx - 110} {ny} {nx - 52} {ny}', ''))
        for j, (tx, ty) in enumerate(target_at):
            routes.append((f'd{i}_{j}', f'M{nx + 52} {ny} C{nx + 110} {ny} {hub_out[0] - 90} {hub_out[1]} {hub_out[0]} {hub_out[1]} '
                                        f'C{hub_out[0] + 80} {hub_out[1]} {tx - 110} {ty} {tx - 30} {ty}', ''))
    # Outgoing mail of the internal servers: through the own node back to the internet.
    routes.append(('out', f'M{node_at[0][0] - 52} {node_at[0][1] + 10} C{node_at[0][0] - 110} {node_at[0][1] + 14} {hub_in[0] + 90} {hub_in[1] + 14} '
                          f'{hub_in[0]} {hub_in[1] + 14} L{cloud[0] + 52} {cloud[1] + 14}', 'out'))
    if flow.get('relay_networks'):
        px, py = 830, height - 30
        nx, ny = node_at[0]
        routes.append(('r0', f'M{px - 28} {py} C{px - 160} {py} {nx + 160} {ny + 22} {nx + 52} {ny + 12}', 'out'))
    parts += [f'<path id="fl-{name}" class="route {kind}" d="{d}"/>' for name, d, kind in routes]
    # mTLS between the nodes: a lock on the line, its colour from the own certificate.
    own = next((n for n in flow['nodes'] if n.get('self')), {})
    for (ax, ay), (bx, by) in zip(node_at, node_at[1:]):
        parts.append(f'<path class="route" d="M{ax} {ay + 19}L{bx} {by - 19}"/>')
        state = 'bad' if any(n['state'] == 'down' for n in visible) else 'warn' if own.get('expiring') else 'ok'
        parts.append(f'<g class="lock {state}" transform="translate({ax + 14} {(ay + by) // 2})" color="var(--fl-ink)"><title>Mutual TLS 1.3 between the nodes'
                     f'{": a node is not reached" if state == "bad" else ": own certificate ends soon" if state == "warn" else ""}</title><use href="#fl-lock"/></g>')
    parts.append(_flow_cloud(*cloud))
    for (x, y), node in zip(node_at, columns):
        parts.append(_flow_node(x, y, node, node.get('ghost', 0)))
    for (x, y), target in zip(target_at, targets):
        parts.append(_flow_target(x, y, target))
        parts.append(f'<g class="lock ok" transform="translate({x - 60} {y - 14})" color="var(--fl-ink)"><title>Delivery with TLS where the server offers it</title>'
                     '<use href="#fl-lock"/></g>')
    if flow.get('relay_networks'):
        parts.append(_flow_printer(830, height - 30, flow['relay_networks']))
    if flow.get('animation', 'on') == 'on' and mails:
        letters = min(6, 1 + mails // 20)
        kinds = (['x'] * min(letters, round(letters * virus / mails)) + ['q'] * round(letters * spam / mails))[:letters]
        kinds += ['ok'] * (letters - len(kinds))
        ins = [name for name, _d, _kind in routes if name.startswith('in')]
        outs = [name for name, _d, _kind in routes if name.startswith('d')]
        good = ins + outs
        for k, css in enumerate(kinds):
            begin = f'-{k * 9 / letters:.1f}s'
            if css == 'ok':
                # Always the same slow pace, staggered so they never bunch up.
                parts.append(f'<g class="mail ok"><use href="#fl-env"/><animateMotion dur="9s" begin="{begin}" repeatCount="indefinite">'
                             f'<mpath href="#fl-{good[k % len(good)]}"/></animateMotion></g>')
                continue
            # Spam and viruses: up to the server, where a shield rises; the letter bounces off and fades, the shield goes down.
            index = k % len(ins)
            nx, ny = node_at[index]
            parts.append(f'<g class="shield" transform="translate({nx - 68} {ny})" opacity="0"><title>Held off by eFa-next</title>'
                         '<path d="M0-15 11-10v10c0 8-5 12-11 15-6-3-11-7-11-15v-10z" fill="#646563" stroke="#c0cf48" stroke-width="3" stroke-linejoin="round"/>'
                         '<path d="M-5 0l4 4 7-8" fill="none" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>'
                         f'<animate attributeName="opacity" values="0;0;1;1;0" keyTimes="0;.62;.7;.9;1" dur="9s" begin="{begin}" repeatCount="indefinite"/>'
                         f'<animateTransform attributeName="transform" type="translate" additive="sum" values="0 14;0 14;0 0;0 0;0 14" '
                         f'keyTimes="0;.62;.7;.9;1" dur="9s" begin="{begin}" repeatCount="indefinite"/></g>')
            parts.append(f'<g class="mail {css}"><use href="#fl-env"/>'
                         f'<animateMotion dur="9s" begin="{begin}" repeatCount="indefinite" keyPoints="0;.88;.78" keyTimes="0;.72;1" calcMode="linear">'
                         f'<mpath href="#fl-{ins[index]}"/></animateMotion>'
                         f'<animate attributeName="opacity" values="1;1;0" keyTimes="0;.74;1" dur="9s" begin="{begin}" repeatCount="indefinite"/></g>')
    label = (f"Mail flow: {len(shown)} eFa node{'s' if len(shown) != 1 else ''} ({flow['mode']}), {len(flow['targets'])} delivery target"
             f"{'s' if len(flow['targets']) != 1 else ''}; last 10 minutes {mails} mails, {spam} spam, {virus} viruses.")
    return (f'<svg class="flow" viewBox="0 0 {width} {height}" role="img" aria-label="{html_escape(label)}">{FLOW_STYLE}{FLOW_DEFS}'
            f'{"".join(parts)}</svg>')

def minute_chart(minutes):
    """The last hour per minute as a small SVG: mails as bars, spam and viruses on top. No script, the numbers are also in the text."""
    top = max([item['mails'] for item in minutes] + [1])
    bars = []
    for index, item in enumerate(minutes):
        x = index * 10
        for value, css in ((item['mails'], 'm'), (item['spam'] + item['virus'], 's'), (item['virus'], 'v')):
            if value:
                height = max(1, round(60 * value / top))
                bars.append(f'<rect class="{css}" x="{x}" y="{60 - height}" width="8" height="{height}"><title>{item["minute"]}: {item["mails"]} mails, '
                            f'{item["spam"]} spam, {item["virus"]} viruses</title></rect>')
    total = {key: sum(item[key] for item in minutes) for key in ('mails', 'spam', 'virus')}
    summary = _('Last hour: {} mails, {} spam, {} viruses; most in one minute: {}.').format(total['mails'], total['spam'], total['virus'], top if total['mails'] else 0)
    return {'svg': f'<svg class="chart" viewBox="0 0 600 62" role="img" aria-label="{summary}">{"".join(bars)}'
                   '<line x1="0" y1="61" x2="600" y2="61"/></svg>', 'summary': summary, 'first': minutes[0]['minute'], 'last': minutes[-1]['minute']}


# Commands whose domain field names one of the known domains; elsewhere a new domain is typed in.
PICK_DOMAIN_COMMANDS = {'domain-settings-show', 'domain-spam-set', 'domain-quarantine-set', 'domain-routing-set', 'domain-general-set', 'user-set',
                        'tenant-group-map-set', 'dkim-create', 'dkim-remove', 'dkim-export', 'rotation-set', 'rotation-pregenerate', 'arc-set', 'dmarc-record-history'}


# Actions whose result needs one line, not a card of values.
SHORT_RESULTS = {'firewall-confirm': 'Firewall change kept.', 'firewall-revert': 'Firewall change taken back.'}


BADGE_KEYS = ('enabled', 'siem', 'api', 'oidc', 'ldap', 'mode', 'running', 'active', 'guard')


def badge_key(output):
    return next((key for key in BADGE_KEYS if isinstance(output, dict) and isinstance(output.get(key), bool)), None)


def status_badge(output):
    """True or False for a status that is on or off, None when the status has no such value."""
    key = badge_key(output)
    return output[key] if key else None


def warnings_of(answer):
    """The warnings of a read, (ok, output) as efactl gives it: texts that ask for an action."""
    ok, output = answer if isinstance(answer, tuple) else (False, None)
    found = output.get('warnings') if ok and isinstance(output, dict) else None
    return [str(text) for text in found] if isinstance(found, list) else []


def without_badge(output):
    """The status without the value the switch in the head of the card already shows."""
    key = badge_key(output)
    return {k: v for k, v in output.items() if k != key} if key else output


# Standard shows what an admin needs every day: what can be set, and warnings that ask for an action. Expert adds the values
# without a setting, the sections marked advanced and the fine tuning (Hans: "die ganzen anzeigen die nur werte anzeigen aber
# keine einstellungsoption bieten haben idr nichts in der standard ansicht zu suchen").
WARNING_CARDS = {'dkim-check'}
# The lists of every day: their rows carry the actions.
DAILY_LISTS = {'uq-list', 'queue-list', 'quarantine-list', 'dkim-export', 'sender-list'}


def card_level(name, cmd, section, slug):
    if name in WARNING_CARDS or name in DAILY_LISTS or (slug == 'dash' and len(section) < 3):
        return 'standard'
    if len(section) >= 3 and section[2] == 'advanced':
        return 'expert'
    # A read with arguments is a search or a tool with its form, unless the page fills it in by itself.
    if cmd['writes'] or (cmd['args'] and name not in PAGES[slug].get('autoload', ())):
        return 'standard'
    return 'expert'


def reader_view():
    if 'view' not in session and session.get('admin'):
        reader_language()
    return session.get('view', 'standard')


def switch_arg(name, cmd):
    """The on/off argument of a command that one click in the head of its card may set, or None. Not for commands that ask
    for a password, a confirmation or show a risk first: those keep their form."""
    if name in REAUTH_COMMANDS or name in DANGER or any(arg.get('secret') or arg.get('kind') == 'confirm' or arg.get('ack') or arg.get('hint')
                                                         for arg in cmd['args']):
        return None
    return next((arg for arg in cmd['args'] if arg['name'] == 'mode' and arg['label'].endswith('on or off')), None)


def form_picks(names, commands):
    """The tenants, domains and groups this login may choose in the forms of the page. Only read when a form needs them."""
    fields = {arg['name'] for name in names for arg in commands[name]['args']}
    pick = {'tenants': [], 'domains': [], 'groups': []}
    if fields & {'tenant', 'domain'} and 'tenant-list' in commands:
        ok, found = efactl_read('tenant-list')
        if ok:
            pick['tenants'] = [item['name'] for item in found.get('tenants', [])]
            pick['domains'] = sorted({domain for item in found.get('tenants', []) for domain in item.get('domains', [])})
    if 'user-set' in names and 'group-list' in commands:
        ok, found = efactl_read('group-list')
        if ok:
            pick['groups'] = [item['name'] for item in found.get('groups', []) if not item.get('disabled')]
    return pick


def page_view(slug, result=None, result_title=None, error=None, result_name=None):
    page = PAGES[slug]
    ok, commands = efactl_read('schema')
    if not ok:
        return render_template_string(FAILED, error=commands.get('error')), 500
    names = [name for name in page['commands'] if name in commands]
    if slug == FALLBACK_PAGE:
        listed = {name for other in PAGES.values() for name in other['commands']}
        names += [name for name in commands if name not in listed]
    if not names:
        abort(403)
    wanted = ['settings']
    # The same reads in both views: the view only hides cards, the visible ones (and the tiles) need the same values.
    shown = names
    for name in shown + page.get('load', []) + (['flow-status'] if FLOW_PICTURE and slug == 'dash' else []):
        if name not in wanted and name in commands and not commands[name]['writes'] and (not commands[name]['args'] or name in page.get('autoload', ())) \
                and not on_button_only(name):
            wanted.append(name)
    # What the forms show now: their sources, read even when they have no card of their own.
    wanted += [source for source in dict.fromkeys(FORM_SOURCE[name][0] for name in shown if name in FORM_SOURCE)
               if source not in wanted and source in commands and not commands[source]['writes']]
    # All at once: each is its own efactl call, the page waits for the slowest instead of the sum.
    if PORTAL:
        who = portal_who()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            loaded = dict(zip(wanted, pool.map(lambda name: portal_call([name], None, who), wanted)))
    else:
        who = acting_as()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(efactl_read, name, who, name in ON_DEMAND) for name in wanted]
            loaded = {name: future.result() for name, future in zip(wanted, futures) if future.result() is not None}
    if not loaded['settings'][0] and slug != USER_PAGE:
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
        found = shown_now(name, arg)
        if found is not None:
            return found
        if name in FORM_SOURCE:
            ok, output = loaded.get(FORM_SOURCE[name][0], (False, None))
            found = form_value(output, FORM_SOURCE[name][1].get(arg['name'])) if ok else None
            return '' if found is None else found
        value = values.get(PREFILL.get(name, {}).get(arg['name']), arg.get('default') or '')
        return ' '.join(value) if isinstance(value, list) else value

    def shown_now(name, arg):
        """A pulldown: the value its read command shows now, never the first choice; None when it shows none."""
        status, keys = FORM_SOURCE.get(name, (None, {}))
        ok, output = loaded.get(status, (False, None))
        found = form_value(output, keys.get(arg['name'])) if ok and arg.get('choices') else None
        return found if found in [item['value'] for item in arg.get('choices', [])] else None

    tiles, attention, chart, flow_picture = dashboard(loaded) if slug == 'dash' else (None, None, None, None)
    running = loaded.get('update-status', (False, {}))[1].get('state') in ('running', 'rebooting')
    percent, minutes = load_settings()
    rows, advice = load_view(load_samples, percent, minutes)
    load_html = render_template_string(LOAD_CARD, rows=rows, advice=advice, last=load_samples[-1] if load_samples else None, extra=load_extra() if rows else None)
    # The portal serves only the page of the role user (show_page), so it lists no other.
    allowed = [(group, [p for p in pages if set(p['commands']) & set(commands) and (not PORTAL or p['slug'] == USER_PAGE)]) for group, pages in NAV]
    merged = {STATUS_OF[name] for name in names if name in STATUS_OF and STATUS_OF[name] in names}
    pick = form_picks(names, commands)
    html = render_template_string(MAIN, load_html=load_html, nav=[(group, pages) for group, pages in allowed if pages], page=page, names=names, commands=commands, loaded=loaded, values=values,
                                  hidden_cards=HIDDEN_CARDS, current=current, choices=CHOICES, option_text=OPTION_TEXT, ruf_warning=RUF_WARNING, current_info=CURRENT, danger=DANGER, tiles=tiles,
                                  attention=attention, chart=chart, flow_picture=flow_picture, pages_by_slug=PAGES, csrf=csrf_token(), result=result, result_name=result_name, merged=merged, status_of=STATUS_OF,
                                  badge=status_badge, without_badge=without_badge, switch_arg=switch_arg, card_level=card_level, warnings_of=warnings_of, expert=PORTAL or reader_view() == 'expert', note_short=NOTE_SHORT, short_results=SHORT_RESULTS, pick=pick, pick_domain_commands=PICK_DOMAIN_COMMANDS,
                                  result_title=result_title, error=error, shown_now=shown_now, reauth_commands=REAUTH_COMMANDS)
    # Shows the progress of a running update without a script.
    return Response(html, headers={'Refresh': '10'}) if running else html


@app.route('/')
def index():
    return redirect(url_for('show_page', slug=USER_PAGE)) if session.get('role') == 'user' else page_view('dash')


@app.route('/p/<slug>')
def show_page(slug):
    if PORTAL and slug != USER_PAGE:
        abort(404)
    if slug in MOVED:
        return redirect(url_for('show_page', slug=MOVED[slug], **request.args), code=301)
    if slug not in PAGES:
        abort(404)
    sid, _since, found = results.pop(request.args.get('r', ''), (None, 0, {}))
    # A result belongs to the session that ran the action.
    if found and sid == session.get('sid'):
        return page_view(slug, **found)
    return page_view(slug)


@app.route('/rspamd-auth')
def rspamd_auth():
    """nginx asks here on every request to /rspamd/: a logged in main admin while the read access is open (9n). The time
    is checked here too, so it closes even if its timer did not run."""
    if not session_active() or session.get('role', 'super') != 'super':
        return '', 401
    ok, settings = efactl_read('settings')
    return ('', 204) if ok and settings.get('rspamd_sso') == 'read-only' else ('', 401)


@app.route('/rspamd-open')
def rspamd_open():
    efactl('audit-rspamd', f"--client={request.headers.get('X-Real-IP', request.remote_addr)}")
    return redirect('/rspamd/')


@app.route('/backup/download', methods=['POST'])
def backup_download():
    """A backup holds the database and private keys, so the admin password is asked again."""
    client = request.headers.get('X-Real-IP', request.remote_addr)
    count, since = login_failures.get(client, (0, 0))
    if count >= MAX_LOGIN_FAILURES and time.time() - since < LOCKOUT_SECONDS:
        return page_view('bak', error='Too many failed logins, try again later.')
    try:
        with open(PASSWORD_FILE) as f:
            stored = f.read().strip()
    except OSError:
        stored = ''
    if not stored or not password_ok(stored, request.form.get('password', '')):
        login_failures[client] = (count + 1, time.time())
        app.logger.warning('efa-web login failed from %s', client)
        return page_view('bak', error='Wrong password, the backup was not downloaded.')
    login_failures.pop(client, None)
    name = request.form.get('name', '')
    ok, info = efactl('backup-download', f'--name={name}')
    if not ok:
        return page_view('bak', error=info.get('error'))
    app.logger.warning('backup %s downloaded from %s', name, client)
    reader = subprocess.Popen(EFACTL + acting_as() + ['backup-read', f'--name={name}'], stdout=subprocess.PIPE)

    def chunks():
        try:
            while True:
                chunk = reader.stdout.read(65536)
                if not chunk:
                    return
                yield chunk
        finally:
            reader.stdout.close()
            reader.wait()
    return Response(chunks(), mimetype='application/octet-stream', headers={
        'Content-Disposition': f'attachment; filename="{name}"', 'Content-Length': str(info['size'])})


@app.route('/mail/<int:mail_id>')
def mail_page(mail_id):
    """One mail of the log. Everything comes escaped; headers are never shown as HTML."""
    ok, view = efactl('mail-show', f'--id={mail_id}')
    if not ok:
        return render_template_string(FAILED, error=view.get('error')), 404
    ok, commands = efactl('schema')
    can_download = ok and bool(view.get('headers')) and efactl('whoami')[1].get('permissions', {}).get('export') is not None
    lang = reader_language()
    return render_template_string(MAIL_PAGE, view=view, back=url_for('show_page', slug='log'), can_download=can_download, lang=lang)


@app.route('/mail/<int:mail_id>/headers.txt')
def mail_headers(mail_id):
    """The raw header block as a file, with its line ends. efactl checks the permission export."""
    ok, found = efactl('mail-show', f'--id={mail_id}', '--format=raw')
    if not ok:
        return Response(found.get('error', 'Not found') + '\n', status=403 if 'Not allowed' in found.get('error', '') else 404, mimetype='text/plain')
    return Response(found['raw'], mimetype='text/plain; charset=utf-8', headers={'Content-Disposition': f'attachment; filename="{found["filename"]}"'})


@app.route('/mail/<int:mail_id>/evidence.json')
def mail_evidence(mail_id):
    """The DNS evidence as JSON. efactl checks the permission export."""
    ok, found = efactl('mail-show', f'--id={mail_id}', '--format=evidence')
    if not ok:
        return Response(found.get('error', 'Not found') + '\n', status=403 if 'Not allowed' in found.get('error', '') else 404, mimetype='text/plain')
    return Response(json.dumps(found['evidence'], indent=1), mimetype='application/json', headers={'Content-Disposition': f'attachment; filename="{found["filename"]}"'})


@app.route('/exports/<job>')
def export_file(job):
    """A finished export, only for the login that made it."""
    if not re.fullmatch(r'[0-9a-f]{32}', job):
        abort(404)
    try:
        with open(f'/var/lib/efa-exports/{job}.json') as f:
            meta = json.load(f)
    except (OSError, ValueError):
        return Response('The export is not ready yet, or it is gone. Try again in a moment.\n', status=404, mimetype='text/plain')
    if meta.get('user', '') != (session.get('user') or ''):
        abort(404)
    with open(f'/var/lib/efa-exports/{job}.zip', 'rb') as f:
        data = f.read()
    return Response(data, mimetype='application/zip', headers={'Content-Disposition': f'attachment; filename="headers-{job[:8]}.zip"'})


@app.route('/brand/logo')
def brand_logo():
    """The logo of the tenant of this login. Only PNG gets stored, and it is sent as such."""
    tenant = (session.get('brand') or {}).get('tenant')
    path = f'/var/lib/efa-brand/{int(tenant)}.png' if tenant is not None else ''
    if not path or not os.path.exists(path):
        abort(404)
    with open(path, 'rb') as f:
        return Response(f.read(), mimetype='image/png', headers={'Cache-Control': 'private, max-age=300'})


@app.route('/brand/upload', methods=['POST'])
def brand_upload():
    """A logo for a tenant. efactl checks it is a small PNG and that the tenant is in the scope of this login."""
    upload = request.files.get('logo')
    tenant = request.form.get('tenant', '').strip()
    if not upload or not tenant:
        return page_view('tenants', error='Choose a tenant and a PNG file.')
    done = subprocess.run(EFACTL + acting_as() + ['tenant-brand-set', f'--tenant={tenant}', '--logo_file=-'], input=upload.read(210 * 1024),
                          capture_output=True, timeout=60)
    try:
        output = json.loads(done.stdout)
    except ValueError:
        return page_view('tenants', error='The upload failed, see the log.')
    if done.returncode != 0:
        return page_view('tenants', error=output.get('error'))
    return page_view('tenants', result=output, result_title='Logo stored')


@app.route('/mail-check', methods=['POST'])
def mail_check():
    """9n: one .eml through rspamd, its verdict shown; the mail is neither stored nor learned (efactl mail-check)."""
    upload = request.files.get('mail')
    data = upload.read(10 * 1024 * 1024 + 1) if upload else b''
    if not data or len(data) > 10 * 1024 * 1024:
        return page_view('log', error=translate('Choose an .eml file of up to 10 MB.'))
    ok, output = efactl('mail-check', secrets_in=[base64.b64encode(data).decode()])
    if not ok:
        return page_view('log', error=output.get('error'))
    return page_view('log', result=output, result_title=translate('Check a mail: the verdict of rspamd, nothing is kept or learned'), result_name='mail-check')


def legal_page(accept, error=None):
    info = legal_info()
    if not info:
        abort(404)
    files = [(name, efa_legal.PDF_NAMES[name]) for name in efa_legal.NAMES]
    return render_template_string(LEGAL_PAGE, legal=info, files=files, all_pdf=efa_legal.ALL_PDF, accept=accept, error=error, csrf=csrf_token(),
                                  lang=reader_language())


@app.route('/legal', methods=['GET'])
def legal():
    return legal_page(False)


@app.route('/legal/<name>', methods=['GET'])
def legal_file(name):
    """One of the legal texts or PDFs of the package, by its fixed name."""
    if name not in (*efa_legal.NAMES, *efa_legal.PDF_NAMES.values(), efa_legal.ALL_PDF):
        abort(404)
    try:
        with open(os.path.join(efa_legal.FOLDER, name), 'rb') as f:
            data = f.read()
    except OSError:
        abort(404)
    return Response(data, mimetype='application/pdf' if name.endswith('.pdf') else 'text/plain; charset=utf-8')


@app.route('/legal/accept', methods=['GET', 'POST'])
def legal_accept():
    """5y: the confirmation of the legal texts by an admin: checkbox, then efactl notes who, when and from where."""
    if request.method == 'POST':
        info = legal_info()
        if request.form.get('confirm') != 'yes' or not info:
            return legal_page(True, translate('Tick the box to confirm.'))
        ok, output = efactl('legal-accept', f"--digest={info['digest']}", '--confirm=yes')
        if not ok:
            return legal_page(True, output.get('error'))
        return redirect(url_for('index'), code=303)
    return legal_page(not legal_confirmed())


@app.route('/disclaimer/import', methods=['POST'])
def disclaimer_import():
    """8k: a disclaimer as ZIP, checked whole by efactl; with "only check" nothing changes."""
    upload = request.files.get('zip')
    data = upload.read(5 * 1024 * 1024 + 1) if upload else b''
    if not data or len(data) > 5 * 1024 * 1024:
        return page_view('disclaimer', error=translate('Choose a .zip file of up to 5 MB.'))
    dry = '--dry_run=on' if request.form.get('dry_run') == 'on' else '--dry_run=off'
    ok, output = efactl('disclaimer-import', dry, secrets_in=[base64.b64encode(data).decode()])
    if not ok:
        return page_view('disclaimer', error=output.get('error'))
    forget_reads()
    return page_view('disclaimer', result=output, result_title=translate('Disclaimer: import a ZIP'), result_name='disclaimer-import')


@app.route('/disclaimer/export', methods=['POST'])
def disclaimer_export():
    """8k: one disclaimer as ZIP, as the import takes it."""
    template_id = request.form.get('id', '')
    ok, output = efactl('disclaimer-export', f'--id={template_id}')
    if not ok or 'zip' not in output:
        return page_view('disclaimer', error=output.get('error') or 'No ZIP.')
    return Response(base64.b64decode(output['zip']), mimetype='application/zip',
                    headers={'Content-Disposition': f'attachment; filename="disclaimer-{output["id"]}.zip"'})


@app.route('/backup/upload', methods=['POST'])
def backup_upload():
    upload = request.files.get('file')
    if not upload:
        return page_view('bak', error='Choose a backup file.')
    # Streamed to efactl in chunks, never read whole into memory; MAX_UPLOAD is the second guard behind MAX_CONTENT_LENGTH.
    importer = subprocess.Popen(EFACTL + acting_as() + ['backup-import'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    total = 0
    try:
        while True:
            chunk = upload.stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD:
                importer.stdin.close()
                importer.kill()
                importer.wait()
                return page_view('bak', error='The backup is larger than allowed.')
            importer.stdin.write(chunk)
        importer.stdin.close()
    except (BrokenPipeError, OSError):
        importer.kill()
    out, _err = importer.communicate(timeout=120)
    try:
        output = json.loads(out)
    except ValueError:
        return page_view('bak', error='The upload failed, see the log.')
    if importer.returncode != 0:
        return page_view('bak', error=output.get('error'))
    return page_view('bak', result=output, result_title='Backup stored, it can be restored from the list')


@app.route('/senders.js')
def senders_js():
    return Response(SENDERS_JS, mimetype='text/javascript')


@app.route('/senders/data')
def senders_data():
    ok, output = efactl('sender-list')
    if not ok:
        abort(502)
    return Response(json.dumps(output), mimetype='application/json')


@app.route('/live.js')
def live_js():
    return Response(LIVE_JS, mimetype='text/javascript')


@app.route('/maillog/live')
def maillog_live():
    ok, output = efactl('maillog-live', f"--after_id={request.args.get('after', '')}")
    if not ok:
        abort(502)
    return Response(json.dumps(output), mimetype='application/json')


@app.route('/load-card')
def load_card():
    percent, minutes = load_settings()
    rows, advice = load_view(load_samples, percent, minutes)
    return render_template_string(LOAD_CARD, rows=rows, advice=advice, last=load_samples[-1] if load_samples else None, extra=load_extra() if rows else None)


# Same drawing as assets/icon.svg. A file, because the security header forbids data: images.
ICON = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128"><rect width="128" height="128" rx="26" fill="#646563"/>'
        '<g transform="rotate(-14 64 56)"><rect x="30" y="30" width="68" height="50" rx="6" fill="none" stroke="#fff" stroke-width="6"/>'
        '<path d="M33 34 64 58l31-24" fill="none" stroke="#fff" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/></g></svg>')


@app.route('/favicon.svg')
def favicon():
    return Response(ICON, mimetype='image/svg+xml')


@app.route('/copy.js')
def copy_js():
    # A file of its own, because the security header forbids inline scripts.
    return Response(COPY_JS, mimetype='text/javascript')


@app.route('/export/dkim')
def export_dkim():
    domain = request.args.get('domain', '')
    ok, output = efactl('dkim-export', f'--domain={domain}', '--format=zone')
    if not ok:
        return page_view('dkim', error=output.get('error'))
    # efactl has checked the domain, so it is safe in the header.
    return Response(output['text'], mimetype='text/plain', headers={
        'Content-Disposition': f'attachment; filename="dkim-{domain or "all"}.txt"'})


def call_command(command, values):
    """The way in for the web forms and the REST API: same schema, same rights in efactl, same audit log."""
    args, secret_lines = [command['name']], []
    for arg in command['args']:
        if arg.get('web') is False:
            continue
        value = values.get(arg['name'], '')
        if arg['name'] == 'groups' and command['name'] == 'user-set' and hasattr(values, 'getlist') and len(values.getlist('groups')) > 1:
            value = ','.join(values.getlist('groups'))
        if arg.get('secret'):
            secret_lines.append(value)
        else:
            args += [f"--{arg['name']}={value}"]
    return efactl(*args, secrets_in=secret_lines)


# Binary streams with their own route and password check. The others are for the web interface itself.
NOT_CALLABLE = ('audit-note', 'backup-read', 'backup-import', 'user-verify', 'token-check', 'oidc-start', 'oidc-finish', 'uq-link-view', 'uq-link-use', 'session-open', 'session-check')


# Results of actions, until the page after the redirect shows them: a reload then shows the page, it does not run the action again.
results = {}
RESULT_SECONDS = 600
RESULT_KEEP = 200
CSV_NAMES = {'message-search': 'messages.csv', 'tenant-usage': 'tenant-usage.csv'}
JSON_NAMES = {'message-search': 'messages.json', 'tenant-usage': 'tenant-usage.json', 'report-show': 'report.json'}


def result_store(slug, **found):
    now = time.time()
    for key in [key for key, (_sid, since, _found) in results.items() if since < now - RESULT_SECONDS] + list(results)[:-RESULT_KEEP]:
        results.pop(key, None)
    key = secrets.token_urlsafe(12)
    results[key] = (session.get('sid'), now, found)
    return redirect(url_for('show_page', slug=slug, r=key), code=303)


@app.route('/run/<name>', methods=['GET', 'POST'])
def run(name):
    ok, commands = efactl('schema')
    if not ok or name not in commands or name in NOT_CALLABLE:
        abort(404)
    if request.method == 'GET':
        # A reload, a link or the back button: show the form with its button, never run the action.
        return redirect(url_for('show_page', slug=page_of(name)) + '#' + name, code=303)
    if name in REAUTH_COMMANDS and not reauth_ok(request.form):
        return result_store(page_of(name), error='Confirm this change with your password.')
    ok, output = call_command({**commands[name], 'name': name}, request.form)
    if ok and name == 'my-settings-set':
        session['lang'] = output.get('language', 'auto')
    if ok and name == 'report-show' and 'html' in output:
        return Response(output['html'], mimetype='text/html')
    if ok and name in JSON_NAMES and 'json' in output:
        return Response(output['json'], mimetype='application/json', headers={'Content-Disposition': f'attachment; filename="{JSON_NAMES[name]}"'})
    if ok and name in CSV_NAMES and 'csv' in output:
        return Response(output['csv'], mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename="{CSV_NAMES[name]}"'})
    if not ok:
        return result_store(page_of(name), error=output.get('error'))
    if not commands[name]['writes'] and name in READ_CACHE_SECONDS and not strict_on():
        # Loaded by its button: the pages after this show it from the cache.
        _read_store(read_key(acting_as(), name), (True, output))
    return result_store(page_of(name), result=output, result_title=commands[name]['title'], result_name=name)


@app.route('/hardening.pdf', methods=['POST'])
def hardening_pdf():
    """Q5b: the hardening report as PDF, made when asked for; efactl checks the same right as for the table."""
    ok, output = efactl('hardening-report', '--format=pdf')
    if not ok or 'pdf' not in output:
        return result_store(page_of('hardening-report'), error=output.get('error') or 'No PDF.')
    return Response(base64.b64decode(output['pdf']), mimetype='application/pdf',
                    headers={'Content-Disposition': f'attachment; filename="{output.get("name") or "hardening-report.pdf"}"'})


@app.route('/view', methods=['POST'])
def set_view():
    """Standard or Expert, in My settings of the login; back to the page it came from."""
    view = request.form.get('view', '')
    if view in ('standard', 'expert'):
        ok, _output = efactl('my-settings-set', f'--view={view}')
        if ok:
            session['view'] = view
    back = urllib.parse.urlsplit(request.referrer or '')
    path = back.path if back.netloc in ('', request.host) else ''
    return redirect(path if path.startswith('/') and not path.startswith('//') else url_for('index'), code=303)


@app.route('/logout', methods=['GET'])
@app.route('/backup/download', methods=['GET'])
@app.route('/backup/upload', methods=['GET'])
@app.route('/brand/upload', methods=['GET'])
def post_only():
    """These only act on POST with the form token; a GET goes to the page with the form."""
    target = {'/logout': 'index', '/backup/download': 'bak', '/backup/upload': 'bak', '/brand/upload': 'tenants'}[request.path]
    return redirect(url_for('index') if target == 'index' else url_for('show_page', slug=target), code=303)


# shortcut: a revoked token still works for up to a minute, make this shorter if that ever matters.
TOKEN_CACHE_SECONDS = 60
token_cache = {}


def api_user():
    """The user of the bearer token, with a short memory: each check would start a process and open the database."""
    header = request.headers.get('Authorization', '')
    if not header.startswith('Bearer '):
        return None
    token = header[len('Bearer '):].strip()
    key = hashlib.sha256(token.encode()).hexdigest()
    user, until, tenant = token_cache.get(key, (None, 0, None))
    if until > time.time():
        g.api_tenant = tenant
        return user
    client = request.headers.get('X-Real-IP', request.remote_addr)
    count, since = login_failures.get(client, (0, 0))
    if count >= MAX_LOGIN_FAILURES and time.time() - since < LOCKOUT_SECONDS:
        return None
    ok, output = efactl('token-check', secrets_in=[token])
    if not ok:
        login_failures[client] = (count + 1, time.time())
        # Fail2Ban reads this line.
        app.logger.warning('efa-web login failed from %s', client)
        return None
    for old in [item for item, (_user, expiry, _tenant) in token_cache.items() if expiry < time.time()]:
        token_cache.pop(old, None)
    token_cache[key] = (output['username'], time.time() + TOKEN_CACHE_SECONDS, output.get('tenant_id'))
    g.api_tenant = output.get('tenant_id')
    return output['username']


def api_schema_for_user():
    user = api_user()
    if not user:
        return None
    g.api_user = user
    ok, commands = efactl('schema')
    return commands if ok else None


METRICS_CACHE_SECONDS = 15
metrics_cache = (0, '')


@app.route('/metrics')
def metrics():
    """For Prometheus. The answer stays for some seconds, so a short scrape interval starts no extra processes."""
    global metrics_cache
    commands = api_schema_for_user()
    if commands is None:
        return Response('Missing or invalid token, or the API is off.\n', status=401, mimetype='text/plain')
    if 'metrics' not in commands:
        return Response('Not allowed for your role.\n', status=403, mimetype='text/plain')
    if metrics_cache[0] < time.time():
        ok, output = efactl('metrics')
        if not ok:
            return Response(output.get('error', 'failed') + '\n', status=502, mimetype='text/plain')
        metrics_cache = (time.time() + METRICS_CACHE_SECONDS, output['text'])
    return Response(metrics_cache[1], mimetype='text/plain; version=0.0.4')


@app.route('/api/v1/schema')
def api_schema():
    commands = api_schema_for_user()
    if commands is None:
        return jsonify(error='Missing or invalid token, or the API is off.'), 401
    return jsonify({name: command for name, command in commands.items() if name not in NOT_CALLABLE})


@app.route('/api/v1/<name>', methods=['GET', 'POST'])
def api(name):
    """GET runs a command that reads, POST one that changes something. Arguments as query or JSON, as in the schema."""
    commands = api_schema_for_user()
    if commands is None:
        return jsonify(error='Missing or invalid token, or the API is off.'), 401
    if name not in commands or name in NOT_CALLABLE:
        return jsonify(error='Unknown command, or not allowed for your role.'), 404
    if commands[name]['writes'] != (request.method == 'POST'):
        return jsonify(error='Use POST for commands that change something, GET for the others.'), 405
    values = request.args if request.method == 'GET' else (request.get_json(silent=True) or {})
    if not all(isinstance(value, str) for value in values.values()):
        return jsonify(error='Arguments must be strings.'), 400
    ok, output = call_command({**commands[name], 'name': name}, values)
    return jsonify(output), 200 if ok else 400


def m_login_redirect_path(path):
    return app.test_client().get(path, base_url='https://localhost').status_code


def m_login_redirect(flask_app):
    return flask_app.test_client().get('/maillog/live', base_url='https://localhost').status_code


def password_ok(stored, password):
    """efa-apply stores pbkdf2_sha256$rounds$salt$hash in base64, efactl admin-password the Werkzeug form."""
    if not stored.startswith('pbkdf2_sha256$'):
        return check_password_hash(stored, password)
    try:
        _, rounds, salt, digest = stored.split('$')
        expected = base64.b64decode(digest)
        return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256', password.encode(), base64.b64decode(salt), int(rounds)), expected)
    except ValueError:
        return False


def portal_self_test():
    """5q, run with EFA_WEB_MODE=portal: only the routes of the users exist, admin logins and admin sessions get nowhere."""
    global portal_call
    calls, answers = [], {}

    def fake(args, secrets_in=None, who=None):
        calls.append(list(args))
        return answers.get(args[0], (True, {}))
    portal_call = fake
    app.secret_key = b'portal-test'
    app.config.update(TESTING=True)
    assert {rule.endpoint for rule in app.url_map.iter_rules()} == set(PORTAL_ROUTES), 'no admin route in the portal'
    assert app.config['SESSION_COOKIE_NAME'] == 'efa_portal' and set(app.view_functions) == set(PORTAL_ROUTES)
    client, https = app.test_client(), {'base_url': 'https://localhost'}
    for path in ('/p/sec', '/portal/p/sec', '/portal/p/dash', '/backup/download', '/api/v1/status', '/run/transport-set', '/login', '/rspamd-open', '/export/dkim'):
        assert client.get(path, **https).status_code in (302, 404), path
    login = client.get('/portal/login', **https).get_data(as_text=True)
    assert 'Mail address' in login and 'main admin' not in login and 'single sign-on' not in login
    csrf = re.search(r'name="csrf" value="([^"]+)"', login).group(1)
    answers['user-verify'] = (False, {'error': 'Use the admin interface for this account.'})
    reply = client.post('/portal/login', data={'csrf': csrf, 'username': 'boss', 'password': 'x'}, **https)
    assert reply.status_code == 200 and 'Wrong password' in reply.get_data(as_text=True)
    answers['user-verify'] = (True, {'username': 'a@x.example', 'role': 'user', 'sid': 'helper-sid'})
    answers['schema'] = (True, {'uq-list': {'title': 'Held mail', 'args': [], 'writes': False}})
    reply = client.post('/portal/login', data={'csrf': csrf, 'username': 'a@x.example', 'password': 'x'}, **https)
    assert reply.status_code == 302 and 'efa_portal=' in reply.headers['Set-Cookie'] and 'SameSite=Strict' in reply.headers['Set-Cookie']
    with client.session_transaction(**https) as sess:
        assert sess['sid'] == 'helper-sid' and sess['role'] == 'user', 'the helper names the session'
    assert client.get('/portal/p/held', **https).status_code == 200 and ['uq-list'] in calls
    assert client.get('/portal/p/sec', **https).status_code == 404
    with client.session_transaction(**https) as sess:
        sess['role'] = 'super'
    assert client.get('/portal/p/held', **https).status_code == 403, 'no admin session in the portal'
    print('self-test ok')


def self_test():
    if PORTAL:
        return portal_self_test()
    routes = {rule.endpoint for rule in app.url_map.iter_rules()}
    assert routes <= set(ROUTE_RIGHTS), f'routes without a right in ROUTE_RIGHTS: {sorted(routes - set(ROUTE_RIGHTS))}'
    import tempfile
    legal_tmp = tempfile.mkdtemp(prefix='efa-web-legal-')
    # The legal texts of this host never take part: without them no page waits for a confirmation, until the test below.
    efa_legal.FOLDER, efa_legal.ACCEPTED = legal_tmp + '/legal', legal_tmp + '/accepted.json'
    salt = base64.b64encode(b'0123456789abcdef').decode()
    digest = base64.b64encode(hashlib.pbkdf2_hmac('sha256', b'pw', b'0123456789abcdef', 1000)).decode()
    assert password_ok(f'pbkdf2_sha256$1000${salt}${digest}', 'pw') and not password_ok(f'pbkdf2_sha256$1000${salt}${digest}', 'no')
    assert not password_ok('pbkdf2_sha256$bad', 'pw')
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
            'dkim-create': {'title': 'DKIM keys: generate', 'writes': True,
                            'args': [{'name': 'domain', 'label': 'Domain', 'required': True},
                                     {'name': 'kind', 'label': 'Key type', 'required': False, 'preselect': 'both',
                                      'choices': [{'value': 'both', 'text': 'RSA and Ed25519'}, {'value': 'rsa', 'text': 'RSA only'}]},
                                     {'name': 'bits', 'label': 'RSA bits', 'required': False, 'default': '2048', 'group': 'rsa'},
                                     {'name': 'ed_selector', 'label': 'Ed25519 selector', 'required': False, 'group': 'ed'}]},
            'dkim-check': {'title': 'DKIM keys', 'args': [], 'writes': False},
            'dkim-export': {'title': 'DKIM: export', 'writes': False,
                            'args': [{'name': 'domain', 'label': 'Domain', 'required': False}]},
            'backup-read': {'title': 'Backup: raw', 'writes': False, 'args': [{'name': 'name', 'label': 'Name', 'required': True}]},
            'backup-now': {'title': 'Back up now', 'writes': True, 'args': [
                {'name': 'encrypt', 'label': 'Encrypt: on or off', 'required': False},
                {'name': 'password', 'label': 'Password', 'required': False, 'secret': True},
                {'name': 'password2', 'label': 'Repeat', 'required': False, 'secret': True}]},
            'maillog-search': {'title': 'Mail log: search', 'writes': False, 'args': []},
            'sender-list': {'title': 'Sender lists', 'args': [], 'writes': False},
            'relay-networks-list': {'title': 'Relay networks', 'args': [], 'writes': False},
            'maillog-live': {'title': 'Mail log: live', 'writes': False, 'args': []},
            'dkim-remove': {'title': 'DKIM: remove a key', 'writes': True, 'args': []},
            'arc-show': {'title': 'ARC sealing', 'args': [], 'writes': False},
            'arc-set': {'title': 'ARC for one domain', 'writes': True,
                        'args': [{'name': 'key', 'label': 'ARC key', 'required': False, 'default': 'dkim'}]},
            'rotation-status': {'title': 'Rotation: status', 'args': [], 'writes': False},
            'ssh-root-status': {'title': 'Root login through SSH', 'args': [], 'writes': False},
            'ssh-root-set': {'title': 'Root login through SSH: switch', 'writes': True,
                             'args': [{'name': 'mode', 'label': 'Root login', 'required': True, 'preselect': 'key-only',
                                       'choices': [{'value': 'key-only', 'text': 'With an SSH key only'}, {'value': 'on', 'text': 'With a password or a key'},
                                                   {'value': 'off', 'text': 'Off'}]},
                                      {'name': 'confirm', 'label': 'Type yes to confirm', 'required': True, 'kind': 'confirm'}]},
            'rbl-show': {'title': 'Blocklists', 'args': [], 'writes': False},
            'uq-list': {'title': 'Held mail', 'args': [], 'writes': False},
            'message-search': {'title': 'Message search', 'args': [{'name': 'format', 'label': 'Empty, or csv'}], 'writes': False},
            'token-check': {'title': 'Check an API token', 'args': [{'name': 'token', 'secret': True}], 'writes': False},
            'rotation-all-set': {'title': 'Auto-rotate all domains', 'writes': True, 'args': []},
            'dmarc-record-show': {'title': 'Saved DMARC records', 'args': [], 'writes': False},
            'dmarc-record-set': {'title': 'DMARC generator', 'writes': True, 'args': [
                {'name': 'domain', 'label': 'Domain', 'required': True},
                {'name': 'p', 'label': 'Policy (p)', 'required': False, 'default': 'none'},
                {'name': 'ruf_enable', 'label': 'Failure reports (ruf): on or off', 'required': False},
                {'name': 'ruf', 'label': 'Failure report addresses (ruf)', 'required': False, 'group': 'ruf',
                 'hint': 'Privacy: failure reports contain personal data'},
                {'name': 'ruf_ack', 'label': 'I have read the privacy warning', 'required': False, 'group': 'ruf', 'ack': True}]},
            'dmarc-record-check': {'title': 'Check an existing DMARC record', 'writes': False, 'args': []},
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
        'backup-list': {'backups': [{'name': 'efa-backup-20261101-020000.tar.gz.gpg', 'date': '2026-11-01 02:00', 'size_mb': 1.5,
                                     'encrypted': True}]},
        'dkim-check': {'keys': [{'domain': 'a.example', 'selector': 'a-sel', 'type': 'rsa', 'state': 'active', 'bits': 2048,
                                 'dns': 'v=DKIM1; k=rsa; p=AA'}], 'warnings': ['a.example: no ED25519 key.'], 'notes': [],
                       'export_domains': ['a.example']},
        'rotation-status': {'rotation_all': True, 'rotation_interval': '6', 'domains': [{'domain': 'a.example', 'settings_from': 'override'}],
                            'rotation_warnings': ['a.example rsa: record not visible on: 192.0.2.1'], 'remove_from_dns': [], 'last_run': None,
                            'next_check': 'soon'},
        'arc-show': {'arc_all': False, 'arc_domains': [{'domain': 'a.example', 'active': True, 'settings_from': 'default', 'key': 'dkim',
                                                        'selector': 'a-sel', 'bits': 2048, 'dns': 'v=DKIM1; k=rsa; p=AA', 'note': '',
                                                        'has_dkim_rsa': True}]},
        'dmarc-record-show': {'dmarc_records': [{'domain': 'd.example', 'name': '_dmarc.d.example', 'record': 'v=DMARC1; p=none',
                                                 'authorization': [], 'ruf': False,
                                                 'history': [{'when': 'now', 'who': 'console', 'record': 'v=DMARC1; p=none',
                                                              'fields': {'p': 'none', 'ruf': ''}}]}]},
        'dkim-export': {'text': '; zone\n'},
        'uq-list': {'mails': [{'id': 5, 'rcpt': 'a@x.example', 'state': 'requested', 'ts': 'now', 'sender': '<b>s@y.example', 'subject': 'Hi', 'score': 16, 'malware': 1}]},
        'rbl-show': {'warnings': [], 'lists': [
            {'id': 'a', 'list': 'Good', 'type': 'ip', 'active': True, 'score': 3, 'hits': 0, 'errors': 0, 'terms': '', 'url': 'https://a.example/?x=1&y=2'},
            {'id': 'b', 'list': 'Old file', 'type': 'ip', 'active': True, 'score': 3, 'hits': 0, 'errors': 0, 'terms': '', 'url': 'javascript:alert(1)'},
            {'id': 'c', 'list': 'None', 'type': 'ip', 'active': True, 'score': 3, 'hits': 0, 'errors': 0, 'terms': '', 'url': ''}]},
        'ssh-root-status': {'ssh_root_login': 'yes', 'mode': 'on', 'ssh_admins': ['efaadmin'], 'ssh_refused': {'bob': 'no full sudo rights'},
                            'warnings': ['Root can log in through SSH (PermitRootLogin yes).']},
        'maillog-live': {'mails': [{'id': 7, 'sender': 'a@example.org'}]},
        'sender-list': {'allow': [{'entry': 'a@example.org'}], 'block': [], 'rules': []},
        'relay-networks-list': {'networks': [{'network': '127.0.0.0/8', 'family': 'IPv4', 'description': 'system', 'state': 'active', 'locked': True},
                                             {'network': '192.0.2.0/24', 'family': 'IPv4', 'description': '', 'state': 'to add', 'locked': False}],
                                'added': ['192.0.2.0/24'], 'removed': [], 'pending': True, 'warnings': [], 'unknown': []},
    }
    failing = []

    stdin_seen = []

    def fake(*args, secrets_in=None, who=None):
        calls.append(args)
        if secrets_in:
            stdin_seen.append(''.join(line + '\n' for line in secrets_in))
        if args[0] in failing:
            return False, {'error': f'{args[0]} failed'}
        return True, outputs.get(args[0], {'done': True})

    efactl = fake
    # The read cache: per login, emptied by every change; the request address and session do not split it.
    read_cache.clear()
    with app.test_request_context('/'):
        before = len(calls)
        efactl_read('bayes-status', ['--client=1', '--as=a'])
        efactl_read('bayes-status', ['--client=2', '--as=a', '--session=x'])
        assert len(calls) == before + 1
        efactl_read('bayes-status', ['--as=b'])
        efactl_read('quarantine-list', ['--as=a'])
        efactl_read('quarantine-list', ['--as=a'])
        assert len(calls) == before + 4, 'another login and an uncached read call efactl'
        # On demand: from the cache or not at all, never a call while the page is built.
        assert efactl_read('bayes-status', ['--as=z'], cached_only=True) is None and len(calls) == before + 4
        assert efactl_read('bayes-status', ['--as=a'], cached_only=True) == (True, {'done': True})
    with app.test_request_context('/', method='POST'):
        efactl_read('bayes-status', ['--as=a'])
        assert len(calls) == before + 5, 'reads of a change are not cached'
        forget_reads()
        assert not read_cache, 'a change empties the cache'
    # The checks below change the answers of efactl between requests: from here on without the cache.
    READ_CACHE_SECONDS.clear()
    outputs['session-check'] = {'active': True}
    app.secret_key = b'self-test'
    client = app.test_client()
    https = {'base_url': 'https://localhost'}
    assert client.get('/', **https).status_code == 302
    login_page = client.get('/login', **https).get_data(as_text=True)
    assert 'Source code' in login_page and 'THIRD-PARTY-NOTICES.md' in login_page and 'DISCLAIMER.md' in login_page
    assert 'Made in Europe, Austria' in login_page and REPO_URL in login_page and 'aria-label="eFa-next"' in login_page
    assert all('<footer>' in template and 'Third-party notices' in template for template in (PAGE, LOGIN, FAILED, LINK_PAGE, MAIL_PAGE, MAIN))
    with client.session_transaction(**https) as sess:
        sess.update(admin=True, csrf='token', sid='test')
    active_sessions['test'] = time.time() + 60
    # Standard and Expert: a new login starts in Standard; the switch keeps the choice in My settings and goes back.
    outputs['schema']['my-settings-set'] = {'title': 'My settings: change', 'writes': True, 'args': [{'name': 'view', 'label': 'View', 'required': False}]}
    standard = client.get('/p/dkim', **https).get_data(as_text=True)
    assert 'class="viewbar"' in standard and 'value="standard" class="cur"' in standard and 'id="dkim-check"' in standard
    assert 'id="dkim-export"' in standard and 'id="arc-show"' not in standard and 'More on this page in the expert view' in standard
    answer = client.post('/view', data={'csrf': 'token', 'view': 'expert'}, headers={'Referer': 'https://localhost/p/dkim'}, **https)
    assert answer.status_code == 303 and answer.headers['Location'].endswith('/p/dkim') and ('my-settings-set', '--view=expert') in calls
    expert_page = client.get('/p/dkim', **https).get_data(as_text=True)
    assert 'id="arc-show"' in expert_page and 'value="expert" class="cur"' in expert_page and 'More on this page' not in expert_page
    answer = client.post('/view', data={'csrf': 'token', 'view': 'expert'}, headers={'Referer': 'https://evil.example/p/x'}, **https)
    assert answer.headers['Location'].endswith('/'), 'back only to this host'
    assert client.post('/view', data={'view': 'expert'}, **https).status_code == 403, 'the form token is needed'
    assert card_level('x', {'writes': False, 'args': []}, ('S', ['x']), 'spam') == 'expert'
    assert card_level('x', {'writes': True, 'args': []}, ('S', ['x'], 'advanced'), 'spam') == 'expert'
    assert card_level('dkim-check', {'writes': False, 'args': []}, ('S', ['x']), 'dkim') == 'standard'
    assert warnings_of((True, {'warnings': ['Do this']})) == ['Do this'] and warnings_of((False, {'warnings': ['x']})) == [] and warnings_of(None) == []
    assert client.post('/run/greylisting-set', data={'mode': 'on'}, **https).status_code == 403
    assert client.get('/p/nope', **https).status_code == 404

    dash = client.get('/', **https).get_data(as_text=True)
    assert '1 down' in dash and '1 not answering' in dash and '1 message<' in dash and '2026-11-01 02:00' in dash
    # Every tile and attention link points to a page and a command card that exist; only commands of the reader are linked.
    import re as re_test
    links = re_test.findall(r'href="/p/([a-z]+)#([a-z0-9-]+)"', dash)
    assert links and all(slug in PAGES and anchor in PAGES[slug]['commands'] for slug, anchor in links), links
    stats = {'today': {'processed': 10, 'megabytes': 1.5, 'clean': 6, 'spam': 2, 'high_spam': 1, 'viruses': 1, 'blocked_files': 0, 'other': 0,
                       'percent': {'clean': 60.0, 'spam': 20.0, 'high_spam': 10.0, 'viruses': 10.0, 'blocked_files': 0, 'other': 0}, 'top_virus': 'Eicar'},
             'last_hour': [{'minute': f'10:{m:02d}', 'mails': m % 3, 'spam': 1 if m == 5 else 0, 'virus': 1 if m == 7 else 0} for m in range(60)],
             'queues': {'counts': {'deferred': {'in': 1, 'out': 2}}, 'warn': True}, 'processes': {'Postfix': 9, 'rspamd': 4}}
    flow = {'mode': 'ha', 'animation': 'on', 'relay_networks': 2, 'targets': [{'name': 'mx.example.org', 'kind': 'server'}, {'name': 'x.mail.protection.outlook.com', 'kind': 'cloud'}],
            'nodes': [{'name': f'mx-{n}', 'self': n == 2, 'role': 'client', 'state': 'down' if n == 4 else 'ok', 'fingerprint': 'AA:BB'} for n in range(1, 6)]}
    tiles_all, attention_all, chart, picture = dashboard({**{name: (True, outputs.get(name, {})) for name in ('status', 'settings', 'quarantine-list', 'backup-list', 'dkim-check')},
                                                          'dash-stats': (True, stats), 'flow-status': (True, flow)})
    # 9l: three nodes and a shadow with +2, the own node shown and marked, letters for the mail of the last minutes, no address.
    assert picture.count('class="node') == 3 and '+2' in picture and 'mx-2' in picture and 'you are here' in picture and 'animateMotion' in picture
    assert 'mx-5' not in picture and 'x.mail.protection.outlook.com' in picture and 'Relay senders: 2 networks' in picture and '<script' not in picture
    assert 'animateMotion' not in flow_svg({**flow, 'animation': 'off'}, stats['last_hour']) and 'animateMotion' not in flow_svg(flow, [])
    assert all(t['slug'] in PAGES and t['anchor'] in PAGES[t['slug']]['commands'] for t in tiles_all if t['slug'])
    assert [t['value'] for t in tiles_all if t['label'] == 'Queues'] == ['0 active, 3 deferred, 0 held'] and 'Postfix 9 · rspamd 4' in tiles_all[0]['note']
    assert 'top virus Eicar' in [t['note'] for t in tiles_all if t['label'] == 'Today'][0] and ('Many mails wait in the queues', 'dash', 'status') in attention_all
    assert chart['summary'] == 'Last hour: 60 mails, 1 spam, 1 viruses; most in one minute: 2.' and chart['svg'].count('<rect') == 43, chart
    assert load_extra()['disks'][0]['mount'] == '/' and len(load_extra()['load']) == 3
    assert all(slug in PAGES and anchor in PAGES[slug]['commands'] for _text, slug, anchor in attention_all)
    assert '<footer>' in dash and 'Third-party notices' in dash
    import tempfile as tempfile_links
    global CONTENT_FILE, link_verdict
    saved_links = (CONTENT_FILE, link_verdict)
    CONTENT_FILE = tempfile_links.mkstemp()[1]
    with open(CONTENT_FILE, 'w') as f:
        json.dump({'links': {'key': '6b' * 32, 'continue': False}}, f)
    good, bad = efa_links.link_token('https://shop.example/a', b'k' * 32), efa_links.link_token('https://evil.example/', b'k' * 32)
    link_verdict = lambda url, now=None: None if 'down' in url else (['DBL_SPAM'] if 'evil' in url else [])
    assert client.get('/l/' + good).headers['Location'] == 'https://shop.example/a'
    warning = client.get('/l/' + bad).get_data(as_text=True)
    assert 'DBL_SPAM' in warning and 'href="https://evil.example/"' not in warning and client.get('/l/' + good[:-3] + 'AAA').status_code == 404
    down = efa_links.link_token('https://down.example/', b'k' * 32)
    page = client.get('/l/' + down).get_data(as_text=True)
    assert 'could not be checked' in page and 'href="https://down.example/"' in page
    for mode, expected in (('follow', 302), ('block', 200)):
        with open(CONTENT_FILE, 'w') as f:
            json.dump({'links': {'key': '6b' * 32, 'unchecked': mode}}, f)
        reply = client.get('/l/' + down)
        assert reply.status_code == expected and (mode == 'follow' or 'href="https://down.example/"' not in reply.get_data(as_text=True)), mode
    os.remove(CONTENT_FILE)
    CONTENT_FILE, link_verdict = saved_links
    german = client.get('/', headers={'Accept-Language': 'de-AT,de;q=0.9'}, **https).get_data(as_text=True)
    assert 'Mailsystem' in german and 'Hinweise zu Fremdsoftware' in german and 'Braucht Aufmerksamkeit' in german, 'German interface'
    import tempfile
    global STRICT_FILE
    saved_strict_file, STRICT_FILE = STRICT_FILE, tempfile.mkstemp()[1]
    with open(STRICT_FILE, 'w') as f:
        f.write('{"on": true}')
    calls_before = len(calls)
    client.get('/p/log?sender=a@b.example&password=x', **https)
    notes = [call for call in calls[calls_before:] if call[0] == 'audit-note']
    assert len(notes) == 1 and '--action=request:GET /p/log' in notes[0] and '--result=200' in notes[0], notes
    assert '"sender": "a@b.example"' in notes[0][2] and '"password": "***"' in notes[0][2] and 'x"' not in notes[0][2], notes
    assert strict_object('/p/x', {'token': 'abc', 'q': 'y'}) == '/p/x {"q": "y", "token": "***"}'
    os.remove(STRICT_FILE)
    STRICT_FILE = saved_strict_file
    strict_cache.update(mtime=None, on=False)
    assert 'service:rspamd is down' in dash and 'no ED25519 key' in dash and 'European Union' in dash

    # The REST API: no token, a wrong one, then a good one for a limited user.
    assert client.get('/api/v1/status', **https).status_code == 401
    failing.append('token-check')
    assert client.get('/api/v1/status', headers={'Authorization': 'Bearer wrong'}, **https).status_code == 401
    failing.remove('token-check')
    login_failures.clear()
    # Re-auth counts as failed logins: after five wrong passwords even the right one waits.
    failing.append('user-verify')
    with app.test_request_context('/', environ_base={'REMOTE_ADDR': '198.51.100.77'}):
        session['user'] = 'helper'
        assert not any([reauth_ok({'reauth': 'wrong'}) for _ in range(MAX_LOGIN_FAILURES)])
        failing.remove('user-verify')
        assert not reauth_ok({'reauth': 'right'}) and login_failures['198.51.100.77'][0] == MAX_LOGIN_FAILURES
    login_failures.clear()
    outputs['token-check'] = {'username': 'helper'}
    bearer = {'Authorization': 'Bearer good'}
    assert client.get('/api/v1/status', headers=bearer, **https).get_json()['status'] == outputs['status']['status']
    calls_before = len(calls)
    assert client.get('/api/v1/status', headers=bearer, **https).status_code == 200
    assert not [call for call in calls[calls_before:] if call[0] == 'token-check'], 'the token check is remembered'
    assert client.post('/api/v1/status', headers=bearer, **https).status_code == 405
    assert client.get('/api/v1/nope', headers=bearer, **https).status_code == 404
    assert client.get('/api/v1/token-check', headers=bearer, **https).status_code == 404
    assert client.post('/api/v1/greylisting-set', headers=bearer, json={'mode': 1}, **https).status_code == 400
    assert client.post('/api/v1/greylisting-set', headers=bearer, json={'mode': 'on'}, **https).status_code == 200
    assert ('greylisting-set', '--mode=on') in calls
    assert 'status' in client.get('/api/v1/schema', headers=bearer, **https).get_json()
    assert client.get('/metrics', headers=bearer, **https).status_code == 403
    outputs['schema']['metrics'] = {'title': 'Values', 'args': [], 'writes': False}
    outputs['metrics'] = {'text': 'efa_up 1\n'}
    scraped = client.get('/metrics', headers=bearer, **https)
    assert scraped.get_data(as_text=True) == 'efa_up 1\n' and scraped.mimetype == 'text/plain'
    assert client.get('/metrics', **https).status_code == 401
    token_cache.clear()
    stdin_seen.clear()
    # A limited login: no backup or rspamd, and only pages it has commands for.
    with client.session_transaction(**https) as sess:
        sess.update(role='helpdesk', user='helper')
    assert client.get('/export/dkim', **https).status_code == 403
    outputs['schema-saved'] = outputs['schema']
    outputs['schema'] = {name: outputs['schema'][name] for name in ('status', 'settings', 'quarantine-list')}
    assert client.get('/p/spam', **https).status_code == 403
    limited = client.get('/p/quar', **https).get_data(as_text=True)
    assert '/p/quar' in limited and '/p/spam' not in limited
    outputs['schema'] = outputs.pop('schema-saved')
    with client.session_transaction(**https) as sess:
        sess.update(role='user', user='plain')
    assert client.get('/', **https).status_code == 302
    with client.session_transaction(**https) as sess:
        sess.update(role='super')
        sess.pop('user')
    # An unticked switch posts only the hidden off, a ticked one posts on first.
    assert 'Root can log in through SSH' in client.get('/p/dash', **https).get_data(as_text=True)
    security = client.get('/p/sec', **https).get_data(as_text=True)
    assert 'Root can log in through SSH' in security and 'efaadmin' in security and '<th>bob</th><td>no full sudo rights</td>' in security
    # The pulldown shows what sshd takes now, not its first choice, and says so; the confirmation stays empty.
    assert '<option value="on" selected>' in security and '<option value="key-only" selected>' not in security, 'prefilled from the status'
    assert 'Current: With a password or a key' in security and 'id="ssh-root-set-confirm" name="confirm" value="yes" required>' in security
    outputs['message-search'] = {'csv': 'ts,qid\n', 'rows': 0}
    download = client.post('/run/message-search', data={'csrf': 'token', 'format': 'csv'}, **https)
    assert download.mimetype == 'text/csv' and 'attachment' in download.headers['Content-Disposition']
    saved_search = outputs.get('message-search')
    outputs['message-search'] = {'json': '[{"id": 1}]', 'rows': 1}
    as_json = client.post('/run/message-search', data={'csrf': 'token', 'format': 'json'}, **https)
    assert as_json.mimetype == 'application/json' and 'messages.json' in as_json.headers['Content-Disposition'] and as_json.get_json() == [{'id': 1}]
    outputs.pop('message-search') if saved_search is None else outputs.update({'message-search': saved_search})
    outputs['message-search'] = {'mails': []}
    # Single sign-on: a wrong state goes nowhere, the right one logs in with the role from efactl.
    sso_client = app.test_client()
    outputs['oidc-status'] = {'oidc': True}
    assert 'single sign-on' in sso_client.get('/login', **https).get_data(as_text=True)
    outputs['oidc-start'] = {'url': 'https://idp.example/auth?x=1', 'state': 'st', 'nonce': 'no', 'verifier': 've'}
    assert sso_client.get('/login/oidc', **https).headers['Location'] == 'https://idp.example/auth?x=1'
    wrong = sso_client.get('/login/oidc/callback?code=c&state=wrong', **https)
    assert 'url=/login' in wrong.get_data(as_text=True) and 'The login could not be finished' in sso_client.get('/login', **https).get_data(as_text=True)
    assert sso_client.get('/p/dash', **https).status_code == 302
    started = sso_client.get('/login/oidc', **https)
    assert 'SameSite=Lax' in started.headers['Set-Cookie'] and 'Secure' in started.headers['Set-Cookie'] and 'HttpOnly' in started.headers['Set-Cookie']
    assert 'evil' not in client.get('/login?sso_error=evil', **https).get_data(as_text=True)
    outputs['oidc-finish'] = {'username': 'anna', 'role': 'helpdesk'}
    finished = sso_client.get('/login/oidc/callback?code=c&state=st', **https)
    assert finished.status_code == 200 and 'url=/' in finished.get_data(as_text=True), 'a redirect would lose the Strict cookie'
    assert ('oidc-finish', '--code=c', '--nonce=no', '--verifier=ve', '--tenant=') in calls
    with sso_client.session_transaction(**https) as sess:
        assert sess['user'] == 'anna' and sess['role'] == 'helpdesk'
    tampered = app.test_client()
    tampered.get('/login/oidc/callback?code=c&state=st', headers={'Cookie': 'efa_oidc=forged'}, **https)
    with tampered.session_transaction(**https) as sess:
        assert 'user' not in sess
    outputs['oidc-status'] = {'oidc': False}
    assert 'single sign-on' not in app.test_client().get('/login', **https).get_data(as_text=True)
    outputs['schema']['report-show'] = {'title': 'Report', 'args': [{'name': 'period', 'label': 'day or week'}, {'name': 'format', 'label': 'html'}], 'writes': False}
    outputs['report-show'] = {'html': '<h1>Report</h1>'}
    printable = client.post('/run/report-show', data={'csrf': 'token', 'period': 'week', 'format': 'html'}, **https)
    assert printable.mimetype == 'text/html' and printable.get_data(as_text=True) == '<h1>Report</h1>'
    assert ('report-show', '--period=week', '--format=html') in calls
    # A link from a digest asks first. Only the button does it.
    link_client = app.test_client()
    outputs['uq-link-view'] = {'purpose': 'release', 'question': 'Release this mail', 'rcpt': 'a@x.example', 'sender': '<b>s</b>@y.example', 'subject': 'Hi'}
    before = len(calls)
    opened = link_client.get('/q/tok', **https).get_data(as_text=True)
    assert 'Release this mail' in opened and '&lt;b&gt;s' in opened and not [c for c in calls[before:] if c[0] == 'uq-link-use']
    outputs['uq-link-use'] = {'purpose': 'release', 'done': 'Release this mail'}
    assert 'Done: Release this mail' in link_client.post('/q/tok', **https).get_data(as_text=True)
    failing.append('uq-link-view')
    assert 'uq-link-view failed' in link_client.get('/q/bad', **https).get_data(as_text=True)
    failing.remove('uq-link-view')
    outputs['uq-link-use'] = {'purpose': 'login', 'done': 'x', 'username': 'a@x.example', 'role': 'user'}
    # A login link of a digest opens a session only in the user portal (5q), never in the admin interface.
    assert link_client.post('/q/tok', **https).status_code == 404
    with link_client.session_transaction(**https) as sess:
        assert 'user' not in sess
    # 5p: the admin interface refuses addresses outside the list once it is on; a broken file refuses too.
    global WEB_ALLOW_FILE
    tmp_allow = os.path.join(tempfile.mkdtemp(), 'web-allowlist.json')
    saved_allow, WEB_ALLOW_FILE = WEB_ALLOW_FILE, tmp_allow
    assert admin_address_ok('198.51.100.7'), 'no file: all addresses'
    with open(tmp_allow, 'w') as f:
        json.dump({'mode': 'allowed', 'entries': [{'network': '192.0.2.0/24', 'comment': 'office'}]}, f)
    assert admin_address_ok('192.0.2.9') and not admin_address_ok('198.51.100.7') and not admin_address_ok('x')
    assert client.get('/p/dash', headers={'X-Real-IP': '198.51.100.7'}, **https).status_code == 403
    assert client.get('/p/dash', headers={'X-Real-IP': '192.0.2.9'}, **https).status_code == 200
    with open(tmp_allow, 'w') as f:
        json.dump({'mode': 'all', 'entries': [{'network': '192.0.2.0/24', 'comment': 'office'}]}, f)
    os.utime(tmp_allow, (1, 1))
    assert admin_address_ok('198.51.100.7'), 'switched to all: the list is kept, it does not act'
    WEB_ALLOW_FILE = saved_allow
    stdin_seen.clear()
    outputs['schema'].update({name: {'title': name, 'args': [{'name': 'id'}], 'writes': True} for name in ('uq-release', 'uq-request', 'uq-show', 'uq-sender')})
    held = client.get('/p/held', **https).get_data(as_text=True)
    assert 'a@x.example' in held and '&lt;b&gt;s@y.example' in held and 'virus' in held and 'asked' in held and 'uq-release' in held
    lists = client.get('/p/rbl', **https).get_data(as_text=True)
    # Links out of eFa, the rspamd interface among them, open in a window of their own; links inside eFa do not.
    outputs['settings'], kept_settings = {**(outputs.get('settings') or {}), 'rspamd_sso': 'read-only', 'rspamd_sso_until': '09:30'}, outputs.get('settings')
    for slug in PAGES:
        html = client.get(f'/p/{slug}', **https).get_data(as_text=True)
        for tag in re.findall(r'<a [^>]*>', html):
            href = re.search(r'href="([^"]*)"', tag)
            if href and (href.group(1).startswith(('http://', 'https://', '/rspamd'))):
                assert 'target="_blank"' in tag and 'rel="noopener noreferrer"' in tag, (slug, tag)
    assert 'href="/rspamd-open" target="_blank" rel="noopener noreferrer"' in client.get('/p/dash', **https).get_data(as_text=True)
    outputs['settings'] = kept_settings
    assert '<a href="https://a.example/?x=1&amp;y=2" target="_blank" rel="noopener noreferrer">Website</a>' in lists
    assert 'javascript:alert' not in lists and lists.count('>Website</a>') == 1
    spam = client.get('/p/spam', **https).get_data(as_text=True)
    assert 'value="7"' in spam and ' checked' in spam and spam.index('value="on"') < spam.index('value="off"')
    client.post('/run/greylisting-set', data={'csrf': 'token', 'mode': ['on', 'off']}, **https)
    assert ('greylisting-set', '--mode=on') in calls
    client.post('/run/greylisting-set', data={'csrf': 'token', 'mode': 'off'}, **https)
    assert ('greylisting-set', '--mode=off') in calls

    flow = client.get('/p/flow', **https).get_data(as_text=True)
    assert 'a.example' in flow and '/run/transport-set' in flow and '<option value="add">add</option>' in flow
    # The switch in the head of a card: one click posts the form of the card with only mode changed, the rest as it is now.
    outputs['schema'].update({'attachment-status': {'title': 'Attachments', 'args': [], 'writes': False},
                              'attachment-set': {'title': 'Attachments: settings', 'writes': True,
                                                 'args': [{'name': 'mode', 'label': 'Attachment checks of eFa: on or off', 'required': True},
                                                          {'name': 'action', 'label': 'Dangerous endings', 'required': False}]}})
    outputs['attachment-status'] = {'enabled': False, 'action': 'reject', 'endings': [f'e{number}' for number in range(20)]}
    card = client.get('/p/spam', **https).get_data(as_text=True).split('id="attachment-set"')[1].split('<div class="card"')[0]
    assert card.count('<form method="post" action="/run/attachment-set" class="toggle">') == 1, card
    assert '<input type="hidden" name="mode" value="on">' in card and '<input type="hidden" name="action" value="reject">' in card
    assert '>enabled<' not in card, 'no second line for what the switch shows'
    assert card.count('<span class="chip">') == 20 and 'Show all' in card and '(20)' in card
    outputs['attachment-status']['enabled'] = True
    card = client.get('/p/spam', **https).get_data(as_text=True).split('id="attachment-set"')[1].split('<div class="card"')[0]
    assert '<input type="hidden" name="mode" value="off">' in card and 'aria-pressed="true"' in card
    assert switch_arg('x', {'args': [{'name': 'mode', 'label': 'on or off'}, {'name': 'confirm', 'kind': 'confirm', 'label': 'Type yes'}]}) is None
    # Q5b: the hardening report as a PDF download, its name from efactl.
    outputs['schema']['hardening-report'] = {'title': 'Hardening report', 'writes': False, 'args': [{'name': 'format', 'label': 'Format', 'required': False}]}
    outputs['hardening-report'] = {'pdf': base64.b64encode(b'%PDF-1.7 test').decode(), 'name': 'efa-hardening-mx.example-20261107-0010.pdf'}
    sec_page = client.get('/p/sec', **https).get_data(as_text=True)
    assert 'formaction="/hardening.pdf">Download PDF</button>' in sec_page, 'the PDF button next to Show'
    answer = client.post('/hardening.pdf', data={'csrf': 'token'}, **https)
    assert answer.mimetype == 'application/pdf' and answer.data == b'%PDF-1.7 test', answer.status_code
    assert 'filename="efa-hardening-mx.example-20261107-0010.pdf"' in answer.headers['Content-Disposition']
    del outputs['hardening-report']
    dkim = client.get('/p/dkim', **https).get_data(as_text=True)
    assert '<option value="2048" selected>2048</option><option value="3072">3072</option><option value="4096">4096</option>' in dkim
    assert 'copy.js' in dkim and 'data-copy' in dkim and 'DKIM keys: generate' in dkim and 'a-sel' in dkim
    # One form, the domain once: the RSA fields go away with Ed25519 only, the Ed25519 field with RSA only (CSS, no script).
    assert dkim.count('id="dkim-create-domain"') == 1 and '<option value="both" selected>' in dkim and 'class="row rsabox"' in dkim
    assert 'class="row edbox"' in dkim and 'option[value=ed25519]:checked) .rsabox' in dkim and '<span class="pill">none</span>' not in dkim
    assert 'Use DKIM RSA key' in dkim and 'RFC 8617' in dkim and 'd.example' not in dkim.split('/export/dkim?domain=')[0]
    assert '/p/dkim?domain=a.example&amp;selector=a-sel#dkim-remove' in dkim
    assert client.get('/copy.js', **https).mimetype == 'text/javascript'
    assert client.get('/p/dmarcrec', **https).status_code == 301, 'old addresses go to the page they are part of now'
    rec = client.get('/p/dmarcrec', follow_redirects=True, **https).get_data(as_text=True)
    assert 'Privacy: failure reports' in rec and 'name="ruf_ack"' in rec and 'v=DMARC1; p=none' in rec and 'Into form' in rec
    assert 'name="ruf_enable" value="on"><i>' in rec.replace('\n', '') or ' checked' not in rec.split('name="ruf_enable"')[1][:40]
    assert 'pct' not in rec.split('Check an existing')[0].replace('deprecated', '')
    restored = client.get('/p/dmarcrec?domain=d.example&p=reject&ruf_enable=on', follow_redirects=True, **https).get_data(as_text=True)
    assert 'value="d.example"' in restored and '<option value="reject" selected>' in restored
    senders = client.get('/p/senders', **https).get_data(as_text=True)
    assert 'data-manage="block"' in senders and 'senders.js' in senders and 'Remove selected' in senders
    assert client.get('/senders/data', **https).get_json()['allow'][0]['entry'] == 'a@example.org'
    relay = client.get('/p/relay', follow_redirects=True, **https).get_data(as_text=True)
    assert 'Not active yet' in relay and 'Added: 192.0.2.0/24' in relay and relay.count('/run/relay-networks-remove') == 1
    log = client.get('/p/log', **https).get_data(as_text=True)
    assert 'id="live-open"' in log and 'live.js' in log and 'Result: all' in log
    assert '<title>eFa-next: open source mail server protection</title>' in log and 'Live log' in log
    live = client.get('/maillog/live?after=5', **https)
    assert live.mimetype == 'application/json' and live.get_json()['mails'][0]['id'] == 7
    assert ('maillog-live', '--after_id=5') in calls and client.get('/live.js', **https).mimetype == 'text/javascript'
    assert m_login_redirect(app) == 302
    bak = client.get('/p/bak', **https).get_data(as_text=True)
    assert '1.5 MB' in bak and 'encrypted' in bak and 'Download' in bak and 'multipart/form-data' in bak
    assert client.post('/backup/download', data={'csrf': 'token', 'name': 'x', 'password': 'wrong'}, **https).status_code == 200
    assert ('backup-read',) not in [call[:1] for call in calls]
    # A3: the interface has a hard upload cap (Werkzeug refuses a larger body with 413), so no upload reads unbounded.
    assert app.config['MAX_CONTENT_LENGTH'] == MAX_UPLOAD and MAX_UPLOAD > 0
    # A password goes over stdin, never into the arguments.
    client.post('/run/backup-now', data={'csrf': 'token', 'encrypt': 'on', 'password': 'pw-secret', 'password2': 'pw-secret'}, **https)
    assert not [call for call in calls if 'pw-secret' in ' '.join(call)] and stdin_seen == ['pw-secret\npw-secret\n']
    # 9n: rspamd only while its read access is open, and only for the main admin.
    outputs['settings'] = {**(outputs.get('settings') or {}), 'rspamd_sso': 'off'}
    assert client.get('/rspamd-auth', **https).status_code == 401, 'closed: no rspamd, even when logged in'
    outputs['settings']['rspamd_sso'] = 'read-only'
    assert client.get('/rspamd-auth', **https).status_code == 204
    with client.session_transaction(**https) as sess:
        sess['role'] = 'domain'
    assert client.get('/rspamd-auth', **https).status_code == 401, 'not for a domain admin'
    with client.session_transaction(**https) as sess:
        sess['role'] = 'super'
    assert m_login_redirect_path('/rspamd-auth') == 401 and m_login_redirect_path('/rspamd-open') == 302
    assert client.post('/run/backup-read', data={'csrf': 'token'}, **https).status_code == 404
    # 5y: the legal texts, open without a login; admin pages wait for the confirmation of their digest, the portal does not.
    for name in efa_legal.NAMES:
        with open(os.path.join(legal_tmp, name), 'w', encoding='utf-8') as f:
            f.write(f'{name} text\n')
    legal_digest = efa_legal.build(legal_tmp, efa_legal.FOLDER, '9.9.9')
    anonymous = app.test_client()
    public = anonymous.get('/legal', **https)
    assert public.status_code == 200 and legal_digest in public.get_data(as_text=True) and 'name="confirm"' not in public.get_data(as_text=True)
    assert anonymous.get('/legal/license.pdf', **https).data.startswith(b'%PDF-') and anonymous.get('/legal/LICENSE', **https).status_code == 200
    assert anonymous.get('/legal/summary.json', **https).status_code == 404 and anonymous.get('/legal/..%2Fx', **https).status_code in (302, 404)
    waiting = client.get('/p/dkim', **https)
    assert waiting.status_code == 302 and waiting.headers['Location'].endswith('/legal/accept'), 'no admin page before the confirmation'
    assert 'name="confirm"' in client.get('/legal/accept', **https).get_data(as_text=True)
    assert 'name="confirm"' in client.post('/legal/accept', data={'csrf': 'token'}, **https).get_data(as_text=True), 'the box must be ticked'
    outputs['legal-accept'] = {'accepted': True}
    assert client.post('/legal/accept', data={'csrf': 'token', 'confirm': 'yes'}, **https).status_code == 303
    assert ('legal-accept', f'--digest={legal_digest}', '--confirm=yes') in calls
    with open(efa_legal.ACCEPTED, 'w') as f:
        json.dump({'digest': legal_digest, 'who': 'admin'}, f)
    assert client.get('/p/dkim', **https).status_code == 200, 'confirmed: the pages open'
    with open(efa_legal.ACCEPTED, 'w') as f:
        json.dump({'digest': '0' * 16, 'who': 'admin'}, f)
    os.utime(efa_legal.ACCEPTED, ns=(1, 1))
    assert client.get('/p/dkim', **https).status_code == 302, 'a new version of the texts asks again'
    import shutil
    shutil.rmtree(legal_tmp)
    headers = client.get('/login', **https).headers
    assert "frame-ancestors 'none'" in headers['Content-Security-Policy'] and headers['Referrer-Policy'] == 'same-origin'
    # After logout a copy of the cookie no longer works.
    copy = app.test_client()
    with copy.session_transaction(**https) as sess:
        sess.update(admin=True, csrf='token2', sid='copied')
    active_sessions['copied'] = time.time() + 60
    assert copy.get('/rspamd-auth', **https).status_code == 204
    active_sessions.pop('copied')
    assert copy.get('/rspamd-auth', **https).status_code == 401 and copy.get('/', **https).status_code == 302
    outputs['schema']['update-status'] = {'title': 'Last system update', 'args': [], 'writes': False}
    outputs['update-status'] = {'state': 'running', 'log': []}
    assert client.get('/p/maint', **https).headers['Refresh'] == '10'
    outputs['update-status'] = {'state': 'done', 'log': []}
    assert 'Refresh' not in client.get('/p/maint', **https).headers
    # Sustained means the 15-minute average at the limit for the whole time, and not one peak.
    high, low = {'cpu': 90}, {'cpu': 10}
    assert load_sustained([high] * 45, 'cpu', 80, 30) and not load_sustained([high] * 20, 'cpu', 80, 30)
    assert not load_sustained([low] * 44 + [high], 'cpu', 80, 30) and not load_sustained([high] * 44 + [low] * 20, 'cpu', 80, 30)
    before = {'time': 0, 'cpu': [0] * 8, 'memory': {}, 'busy': 0, 'received': 0, 'sent': 0, 'speed': 1000}
    after = {'time': 60, 'cpu': [50, 0, 0, 50, 0, 0, 0, 0], 'busy': 30000, 'received': 750000000, 'sent': 0, 'speed': 1000,
             'memory': {'MemAvailable': 25, 'MemTotal': 100, 'SwapFree': 50, 'SwapTotal': 100}}
    one = load_sample(before, after, {'/': 40.0})
    assert (one['cpu'], one['ram'], one['swap'], one['disk'], one['io'], one['rx']) == (50.0, 75.0, 50.0, 40.0, 50.0, 100.0)
    assert one['nic'] == 10.0 and load_sample(after, after, {})['cpu'] == 0
    assert 'Collecting' in client.get('/load-card', **https).get_data(as_text=True)
    load_samples.extend([one] * 45)
    card = client.get('/load-card', **https).get_data(as_text=True)
    assert 'Reduce rspamd workers' not in card and 'polyline' in card
    load_samples.clear()
    load_samples.extend([dict(one, cpu=95.0)] * 45)
    assert 'Reduce rspamd workers' in client.get('/load-card', **https).get_data(as_text=True) and 'id="load-card"' in client.get('/', **https).get_data(as_text=True)
    load_samples.clear()
    rot = client.get('/p/rot', follow_redirects=True, **https).get_data(as_text=True)
    assert 'Auto-rotate all domains' in rot and 'override' in rot and 'not visible' in rot
    assert '/export/dkim?domain=a.example' in dkim and 'Export all' in dkim
    export = client.get('/export/dkim?domain=a.example', **https)
    assert export.get_data(as_text=True) == '; zone\n' and 'dkim-a.example.txt' in export.headers['Content-Disposition']
    assert 'dkim-all.txt' in client.get('/export/dkim', **https).headers['Content-Disposition']
    quarantine = client.get('/p/quar', **https).get_data(as_text=True)
    assert '<b>x' not in quarantine and '&lt;b&gt;x' in quarantine
    assert 'id="quarantine-delete-id" name="id" value="ABC"' in client.get('/p/quar?id=ABC', **https).get_data(as_text=True)
    # A command nobody put on a page stays reachable, and its result lands on that page.
    assert 'Brand new command' in client.get('/p/maint', **https).get_data(as_text=True)
    assert 'Done.' in client.post('/run/brand-new', data={'csrf': 'token'}, follow_redirects=True, **https).get_data(as_text=True)
    # Post/Redirect/Get: the POST answers 303, a reload of the page does not run it again, a GET on any action never runs it.
    answer = client.post('/run/greylisting-set', data={'csrf': 'token', 'mode': 'on'}, **https)
    assert answer.status_code == 303 and '/p/spam?r=' in answer.headers['Location']
    before = len(calls)
    assert 'Done' in client.get(answer.headers['Location'], **https).get_data(as_text=True)
    assert 'Done' not in client.get(answer.headers['Location'], **https).get_data(as_text=True), 'the result shows once'
    assert not [call for call in calls[before:] if call[:1] == ('greylisting-set',)]
    ok, schema = fake('schema')
    for name in schema:
        reply = client.get(f'/run/{name}', **https)
        assert reply.status_code in (303, 404) and reply.status_code != 405, (name, reply.status_code)
        if reply.status_code == 303:
            assert '/p/' in reply.headers['Location'], name
    assert not [call for call in calls[before:] if call[:1] not in (('schema',), ('settings',), ('session-check',))
                and call[:1][0] in schema and schema[call[:1][0]].get('writes')], 'a GET ran an action'
    for path in ('/logout', '/backup/download', '/backup/upload', '/brand/upload'):
        assert client.get(path, **https).status_code == 303, path
    # A firewall change that waits: every page says so at the top, with keep and discard; the result afterwards is one line.
    saved_settings = outputs.get('settings')
    outputs['schema'].update({'firewall-confirm': {'title': 'Firewall: keep the change', 'args': [], 'writes': True},
                              'firewall-revert': {'title': 'Firewall: take back', 'args': [], 'writes': True}})
    outputs['settings'] = {**(saved_settings or {}), 'firewall_pending_seconds': 241}
    for path in ('/p/sec', '/p/maint', '/'):
        page = client.get(path, **https).get_data(as_text=True)
        assert 'class="pending"' in page and 'data-countdown="241"' in page and '/run/firewall-confirm' in page and '/run/firewall-revert' in page, path
    outputs['settings'] = {**(saved_settings or {}), 'firewall_pending_seconds': None}
    assert 'class="pending"' not in client.get('/p/sec', **https).get_data(as_text=True)
    outputs['settings'] = saved_settings
    outputs['firewall-confirm'] = {'confirmed': True}
    kept = client.post('/run/firewall-confirm', data={'csrf': 'token'}, follow_redirects=True, **https).get_data(as_text=True)
    assert 'Firewall change kept.' in kept and 'Confirmed' not in kept
    # The detail view escapes the headers and offers the download only with the permission export.
    outputs['mail-show'] = {'mail': {'id': 7, 'ts': '2026-11-05 21:00:00', 'sender': 'a@x.example', 'rcpt': 'b@y.example', 'subject': '<b>hi</b>', 'action': 'no action'},
                            'headers': 'Subject: <script>x</script>\r\n', 'headers_note': '', 'received': [{'hop': 'from a by b', 'time': 't', 'seconds': 3}],
                            'checks': [{'name': 'Authentication-Results', 'value': 'dkim=pass'}], 'spam': [], 'content': 'Content not stored.',
                            'verdict': [{'symbol': 'BAYES_SPAM', 'score': 5.1, 'text': 'Message probably spam <x>', 'text_de': 'Bayes: Spam.'}]}
    outputs['whoami'] = {'permissions': {'export': 'global'}}
    detail = client.get('/mail/7', **https).get_data(as_text=True)
    assert 'Why this result' in detail and 'Message probably spam &lt;x&gt;' in detail
    assert 'Bayes: Spam.' in client.get('/mail/7', headers={'Accept-Language': 'de-AT,de;q=0.9'}, **https).get_data(as_text=True)
    assert '&lt;script&gt;x&lt;/script&gt;' in detail and '<script>x' not in detail and '&lt;b&gt;hi' in detail and '/mail/7/headers.txt' in detail
    outputs['whoami'] = {'permissions': {}}
    assert '/mail/7/headers.txt' not in client.get('/mail/7', **https).get_data(as_text=True)
    outputs['mail-show'] = {'raw': 'Subject: x\r\n', 'filename': '2026-11-05_ABC.headers.txt'}
    raw = client.get('/mail/7/headers.txt', **https)
    assert raw.get_data() == b'Subject: x\r\n' and 'ABC.headers.txt' in raw.headers['Content-Disposition']
    failing.append('mail-show')
    assert client.get('/mail/8', **https).status_code == 404 and client.get('/mail/8/headers.txt', **https).status_code == 404
    failing.remove('mail-show')
    assert page_of('brand-new') == FALLBACK_PAGE and page_of('transport-set') == 'flow'
    # Sessions: checked again after 15 seconds; ended elsewhere means logged out, efactl failing does not.
    with client.session_transaction(**https) as sess:
        sid = sess['sid']
    outputs['session-check'] = {'active': True, 'role': 'super'}
    session_checked[sid] = 0
    assert client.get('/p/maint', **https).status_code == 200 and ('session-check', f'--session={session_sha(sid)}') in calls
    failing.append('session-check')
    session_checked[sid] = 0
    assert client.get('/p/maint', **https).status_code == 200, 'efactl failing keeps the session'
    failing.remove('session-check')
    outputs['session-check'] = {'active': False}
    session_checked[sid] = 0
    assert client.get('/p/maint', **https).status_code == 302 and sid not in active_sessions
    with client.session_transaction(**https) as sess:
        sess.update(admin=True, csrf='token', sid='test')
    active_sessions['test'] = time.time() + 60
    outputs['session-check'] = {'active': True}

    failing += ['settings', 'status']
    assert 'settings failed' in client.get('/p/flow', **https).get_data(as_text=True)
    assert 'Unknown' in client.get('/', **https).get_data(as_text=True)
    print('self-test ok')


def portal_only(flask_app):
    """The portal keeps only the routes of the users, under /portal/; the code of the others is not reachable at all."""
    methods = {}
    for rule in flask_app.url_map.iter_rules():
        if rule.endpoint in PORTAL_ROUTES and not (rule.endpoint == 'logout' and rule.methods == {'GET', 'HEAD', 'OPTIONS'}):
            methods.setdefault(rule.endpoint, set()).update(rule.methods)
    flask_app.url_map = flask_app.url_map_class()
    for endpoint, path in PORTAL_ROUTES.items():
        flask_app.url_map.add(flask_app.url_rule_class(path, endpoint=endpoint, methods=methods[endpoint]))
    for endpoint in [name for name in flask_app.view_functions if name not in PORTAL_ROUTES]:
        flask_app.view_functions.pop(endpoint)


if PORTAL:
    portal_only(app)


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
        sys.exit(0)
    with open(PORTAL_SECRET if PORTAL else SECRET_FILE, 'rb') as secret:
        app.secret_key = secret.read()
    # The templates compiled before the first request: that took 0.2 to 0.3 s on the first page after a start.
    for template in (MAIN, LOGIN, FAILED, LINK_PAGE, LINK_WARNING, MAIL_PAGE, LOAD_CARD):
        app.jinja_env.from_string(template)
    if not PORTAL:
        threading.Thread(target=load_loop, daemon=True).start()
        # The slow reads of the main admin once at the start, so the first dashboard does not wait for them.
        threading.Thread(target=lambda: concurrent.futures.ThreadPoolExecutor(max_workers=4).map(
            lambda name: efactl_read(name, []), [name for name in READ_CACHE_SECONDS if name not in ON_DEMAND]), daemon=True).start()
    serve(app, host='127.0.0.1', port=8081 if PORTAL else 8080, threads=8)
