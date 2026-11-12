#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""eFa-next web interface. Holds no eFa-next logic: forms come from `efactl schema`, actions call efactl.

Runs as user efa-web behind nginx on 127.0.0.1:8080, without sudo: efactl only through efactl-runner.
"""
from html import escape as html_escape
import base64
import collections
import concurrent.futures
import datetime
import functools
import hashlib
import hmac
import ipaddress
import json
import math
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
# The language chosen in the setup wizard (efa-apply): the login page speaks it before anyone has logged in.
LANGUAGE_FILE = WEB_DIR + '/language'
SECRET_FILE = WEB_DIR + '/secret.key'
# efactl-runner: the only way to efactl (no sudo rule, so efa-web.service runs with NoNewPrivileges); one fork per call.
RUNNER_SOCKET = os.environ.get('EFA_RUNNER_SOCKET', '/run/efactl-runner/runner.sock')
# A download or upload through a pipe (backup, logo): as long as a slow browser needs, the runner ends it then.
STREAM_SECONDS = 1800
# 5q: the same program runs a second time as the user portal (efa-portal.service): its own system user, no sudo, its own
# session key and cookie, only the routes of the users, and efactl only through efa-portal-helper with a few fixed commands.
PORTAL = os.environ.get('EFA_WEB_MODE') == 'portal'
PORTAL_SOCKET = os.environ.get('EFA_PORTAL_SOCKET', '/run/efa-portal-helper/helper.sock')
PORTAL_SECRET = os.environ.get('EFA_ETC', '/etc') + '/efa-portal/secret.key'
PORTAL_ROUTES = {'login': '/portal/login', 'logout': '/portal/logout', 'index': '/portal/', 'show_page': '/portal/p/<slug>', 'run': '/portal/run/<name>',
                 'copy_js': '/portal/copy.js', 'favicon': '/portal/favicon.svg', 'brand_logo': '/portal/brand/logo', 'quarantine_link': '/q/<token>', 'link_check': '/l/<token>',
                 'oidc_login': '/portal/login/oidc', 'oidc_callback': '/portal/login/oidc/callback'}
SESSION_MAX_AGE = 3600
MAX_LOGIN_FAILURES = 5
LOCKOUT_SECONDS = 300
# A3: the largest upload the interface takes. A backup (database, keys, config, gpg) is the biggest; every other upload checks
# its own smaller limit. The hard cap stops an endless upload from filling memory or disk.
MAX_UPLOAD = 8 * 1024 * 1024 * 1024

app = Flask(__name__)
# Location relative on every Werkzeug: an absolute one would carry http (what waitress sees behind nginx), and form-action 'self' blocks it.
app.response_class.autocorrect_location_header = False
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
                  PERMANENT_SESSION_LIFETIME=SESSION_MAX_AGE, SESSION_COOKIE_NAME='__Host-efa-portal' if PORTAL else '__Host-efa-admin',
                  MAX_CONTENT_LENGTH=MAX_UPLOAD)
login_failures = {}
# The session cookie is only signed, so logout could not end it without this list. A restart logs everyone out.
active_sessions = {}
# When each session was last checked with efactl: ended or locked elsewhere means out within this time.
session_checked = {}
SESSION_CHECK_SECONDS = 15

REPO_URL = 'https://github.com/MarkusLorber/eFa-next'
# A plain link to the form of the project: nothing of this host goes with it (no version, no host name).
FEATURE_URL = REPO_URL + '/issues/new?template=feature_request.yml'
# The source tree first, so a self test there uses its own libraries, not the installed ones.
sys.path[:0] = [os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../lib/eFa/python'), '/usr/lib/eFa/python']
import efa_style  # noqa: E402  the logo and colours, shared with efa-init
# Same drawing as assets/logo.svg (efa_style), inline: the login page shows it too.
LOGO = efa_style.LOGO
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
from efa_nav import FORM_NEW, FORM_SOURCE, MOVED, NAV, NOTE_SHORT, PAGES, STATUS_OF, form_value  # noqa: E402  the menu, shared with efa-tui
import efa_help  # noqa: E402  the help texts of cards and fields, shared with efa-tui
import efa_i18n  # noqa: E402
import efa_legal  # noqa: E402
import efa_setup  # noqa: E402
import efa_wizard  # noqa: E402  the guided wizards of some pages
import efa_harden  # noqa: E402  what the security standards ask of the system and of eFa-next
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
                    'gateway': 'ipv4.gateway', 'ipv6_method': 'ipv6.method'},
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
HIDDEN_CARDS = {'clam-source-set', 'clam-securiteinfo-set', 'sender-action', 'sender-action-check', 'admin-2fa-verify', 'resetup', 'setup-variant-apply', 'totp-import', 'console-2fa-verify', 'passkey-login', 'passkey-login-options', 'passkey-register-options', 'mail-check', 'disclaimer-import', 'disclaimer-export', 'flow-status', 'flow-set', 'threat-run', 'neural-settings', 'ml-settings', 'dkim-generate', 'dkim-generate-ed25519', 'audit-note', 'refusal-note', 'mail-show', 'uq-content', 'quarantine-content', 'session-open', 'session-check', 'events-run', 'uq-link-view', 'uq-link-use', 'uq-show', 'uq-release', 'uq-request', 'uq-sender', 'oidc-start', 'oidc-finish', 'user-verify', 'token-check', 'audit-purge', 'metrics', 'subject-get', 'dmarc-record-history', 'maillog-live', 'relay-networks-set', 'relay-networks-remove',
                'relay-networks-apply', 'relay-networks-discard', 'load-notify', 'firewall-revert', 'firewall-guard-run', 'web-harden', 'audit-rspamd', 'update-system-run', 'update-post-boot', 'update-now', 'backup-download', 'backup-read', 'backup-import', 'update-run', 'sender-add', 'sender-remove', 'sender-move', 'sender-list-set', 'sanesecurity-run', 'rbl-apply', 'mailreport-run'}
DANGER = {'gdpr-delete', 'dkim-remove', 'reboot', 'halt', 'restore', 'release-upgrade', 'update-rollback', 'quarantine-delete', 'quarantine-purge', 'maillog-purge'}

BLOCK = '{% block %}{% endblock %}'
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>eFa-next: open source mail server protection</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><link rel="icon" href="{{ url_for('favicon') }}" type="image/svg+xml">
<style>
""" + efa_style.TOKENS + """*{box-sizing:border-box}
body{margin:0;font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--ink);display:flex;min-height:100vh;flex-direction:column}
.wrap{display:flex;flex:1}
aside{width:260px;background:var(--side);color:#e9ebe4;padding:18px 0;flex-shrink:0}
.brand{display:block;padding:0 22px 12px;background:var(--side)}
.brand svg{display:block;width:100%;height:auto}
.brand .text{fill:#f2f2f2}.brand .line{stroke:#f2f2f2}
aside .search{margin:0 22px 8px;position:relative}aside .search input{width:100%;padding:6px 8px;border:1px solid var(--border);border-radius:6px;background:var(--field);color:var(--ink)}
aside h4{margin:18px 22px 6px;font-size:11px;text-transform:uppercase;letter-spacing:1.2px;color:#b4baa3}
aside a.nav{display:block;padding:8px 22px;color:#e9ebe4;text-decoration:none;border-left:3px solid transparent}
aside a.nav:hover{background:rgba(255,255,255,.06)}
.suggest{position:absolute;left:0;top:100%;z-index:80;width:min(28rem,92vw);max-height:70vh;overflow:auto;margin:4px 0 0;padding:6px;list-style:none;background:var(--card);color:var(--ink);border:1px solid var(--line);border-radius:10px;box-shadow:0 12px 32px rgba(0,0,0,.25)}
.suggest[hidden]{display:none}.sg-head{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--gray);padding:8px 8px 2px}
.sg{display:grid;gap:1px;padding:6px 8px;border-radius:6px;cursor:pointer}.sg[aria-selected=true],.sg:hover{background:var(--hover)}.sg b{font-weight:600}
.sg-page{font-size:12px;color:var(--gray)}.sg small{font-size:12px;line-height:1.35;color:var(--gray)}
details.navmenu>summary{display:none}
@media(max-width:760px){details.navmenu>summary{display:block;margin:4px 22px 0;padding:8px 12px;border:1px solid rgba(255,255,255,.25);border-radius:8px;cursor:pointer;list-style:none;font-weight:600}
details.navmenu>summary::-webkit-details-marker{display:none}details.navmenu>summary::after{content:" \\25BE"}details.navmenu[open]>summary::after{content:" \\25B4"}}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
small.now{grid-column:2;color:var(--muted);margin-top:-4px}
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
svg.chart,svg.flow{width:100%;height:auto;display:block}svg.flow{max-height:340px}svg.chart rect.m{fill:var(--chart)}svg.chart rect.s{fill:var(--warn)}svg.chart rect.v{fill:var(--bad)}svg.chart line{stroke:var(--line)}
.legend{font-size:12px;color:var(--gray);margin:6px 0 0}.legend .key{display:inline-block;width:10px;height:10px;margin:0 4px 0 10px;border-radius:2px}
.legend .key.m{background:var(--chart);margin-left:0}.legend .key.s{background:var(--warn)}.legend .key.v{background:var(--bad)}.legend .span{float:right}
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
table.stack td form{margin:4px 4px 0 0}table.stack td[data-label]::before{content:attr(data-label) ": ";color:var(--gray)}table.rbl td.n{width:auto}}
.pending{position:sticky;top:0;z-index:20;display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center;justify-content:space-between;margin:-28px -36px 18px;
padding:12px 36px;background:var(--pend);border-bottom:2px solid var(--warn);color:var(--pend-ink)}.pending form{display:inline}.pending-buttons{display:flex;gap:8px}
@media (max-width:600px){.pending{margin:-16px -16px 14px;padding:10px 16px}}
.badge{float:right;font-size:12px;font-weight:600;padding:2px 10px;border-radius:10px;background:var(--line)}.badge.on{background:var(--ok);color:#fff}
.viewbar{position:sticky;top:0;z-index:5;display:flex;justify-content:flex-end;align-items:center;gap:12px;padding:6px 0;background:var(--bg)}form.view{display:inline;margin:0}
details.usermenu{position:relative}details.usermenu>summary{cursor:pointer;list-style:none;padding:3px 12px;border:1px solid var(--line);border-radius:14px;background:var(--card);white-space:nowrap}
details.usermenu>summary::-webkit-details-marker{display:none}details.usermenu>summary:focus-visible{outline:2px solid var(--ink)}details.usermenu .role{color:var(--gray);font-size:13px}
details.usermenu .menu{position:absolute;right:0;top:calc(100% + 4px);min-width:220px;padding:10px 12px;background:var(--card);border:1px solid var(--line);border-radius:10px;box-shadow:0 4px 16px rgba(0,0,0,.15)}
details.usermenu .menu a{display:block;margin:0 0 8px}details.usermenu .menu form{margin:0}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:14px;overflow:hidden}.seg button{border:0;border-radius:0;padding:3px 12px;background:var(--card);cursor:pointer}
.seg button.cur{background:var(--lime);color:#2a2e22;font-weight:600}
.langs{float:right}.langs a{padding:3px 12px;text-decoration:none;color:var(--ink)}.langs a.cur{background:var(--lime);color:#2a2e22;font-weight:600}
form.toggle{display:inline;margin:0}
.switch{display:inline-flex;align-items:center;gap:6px;min-width:4.5em;white-space:nowrap;border:0;border-radius:14px;padding:3px 10px;background:var(--line);color:var(--ink);font-weight:600;font-size:13px;cursor:pointer;list-style:none}
.switch.on{background:var(--ok);color:#fff}.switch .knob{width:10px;height:10px;border-radius:50%;background:#fff;flex:none}.switch:hover,.switch:focus-visible{outline:2px solid var(--lime)}
details.rblterms summary::-webkit-details-marker{display:none}details.rblterms[open]{white-space:normal;min-width:16rem;max-width:28rem}details.rblterms form{margin-top:6px}label.tick{display:block;font-size:13px}
table.clam{table-layout:fixed;min-width:640px}table.clam th{overflow-wrap:normal;word-break:keep-all}table.clam td{overflow-wrap:break-word}table.clam .pill,table.clam .switch{white-space:nowrap}table.clam col.state{width:10em}table.clam col.files{width:13em}table.clam col.acc{width:9.5em}table.clam .file{display:block;white-space:nowrap}form.clamid{margin-top:4px;font-size:13px}form.clamid input{width:12em;max-width:100%}form.clamsi{margin-top:4px;font-size:13px;display:grid;gap:4px}form.clamsi textarea{width:100%;font-family:monospace;font-size:12px}form.clamsi button{justify-self:start}
@media (max-width:600px){table.clam{min-width:0;table-layout:auto}}
table.rbl th.n,table.rbl td.n{white-space:nowrap;width:1%}form.dqs{margin-top:4px;font-size:13px}form.dqs input{width:12em}button.badge{border:0;cursor:pointer;color:var(--ink)}button.badge.on,.badge.on{color:#fff}button.badge.on{color:#fff}button.badge:hover{outline:2px solid var(--lime)}
.chips{display:flex;flex-wrap:wrap;gap:4px}.chip{background:var(--line);border-radius:8px;padding:1px 8px;font-size:13px}details.more summary{cursor:pointer;font-size:13px;margin-top:4px}
.card p.h{margin:0 0 14px;color:var(--gray);font-size:13px}
.card.done{border-color:var(--lime);border-width:2px}
.err{color:var(--bad);font-weight:500;overflow-wrap:anywhere}
.row{display:grid;grid-template-columns:230px 1fr;gap:6px 18px;align-items:center;margin:10px 0}
.row label{font-weight:500}
input[type=text],input[type=password],select{width:100%;max-width:380px;padding:8px 10px;border:1px solid var(--border);border-radius:8px;font:inherit;background:var(--field);color:var(--ink)}
input:focus,select:focus{outline:2px solid var(--ink);border-color:var(--ink)}
.sw{position:relative;width:44px;height:24px;display:inline-block}
.sw input{position:absolute;opacity:0;width:0;height:0}
.sw i{position:absolute;inset:0;background:var(--chart);border-radius:24px;transition:.15s}
.sw i:before{content:"";position:absolute;width:18px;height:18px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.15s}
.sw input:checked+i{background:var(--lime)}
.sw input:checked+i:before{transform:translateX(20px)}
.rufbox,.ownbox,.encryptbox,.rebootbox{display:none}
form:has(input[name=reboot]:checked) .rebootbox{display:grid}
form:has(input[name=encrypt]:checked) .encryptbox{display:grid}
dialog#live-log,dialog.popup{width:min(1400px,96vw);height:90vh;border:1px solid var(--line);border-radius:12px;padding:16px;color:var(--ink);background:var(--card)}
dialog#live-log[open],dialog.popup[open]{display:flex;flex-direction:column;gap:10px}
dialog::backdrop{background:rgba(0,0,0,.45)}
.live-head{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.live-head h2{margin:0;font-size:17px}.live-head span{flex:1;color:var(--gray);font-size:13px}
.live-filters{display:flex;gap:8px;flex-wrap:wrap}.live-filters input,.live-filters select{width:auto;flex:1 1 130px;max-width:none}
.live-table{flex:1;overflow:auto;border:1px solid var(--line);border-radius:8px}.live-table th{position:sticky;top:0;background:var(--card)}.live-table tr:hover td{background:var(--hover);cursor:pointer}
#live-detail{max-height:22vh}#live-detail:empty{display:none}
main.wide{max-width:none}
.tablewrap{overflow:auto;max-height:75vh;border:1px solid var(--line);border-radius:8px}
table.log{font-size:13px}table.log th{position:sticky;top:0;z-index:1;background:var(--card);white-space:nowrap;text-align:left}
table.log td,table.log th{padding:4px 6px}table.log tbody tr:hover td,table.log tbody tr:focus-within td{background:var(--hover)}table.log tr[data-mail]{cursor:pointer}
td.nw{white-space:nowrap;width:1%}td.cut{max-width:max(8rem,9vw);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}td.cut.subj{max-width:max(9rem,12vw)}
@media (min-width:901px) and (max-width:1440px){table.log .opt{display:none}}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
button.chip{display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:middle;font-size:13px;padding:1px 8px;border-radius:12px;border:1px solid var(--line);background:var(--field);color:var(--ink);cursor:pointer}
td.nw button.chip{max-width:none}button.chip:hover,button.chip:focus-visible{border-color:var(--lime);outline:2px solid var(--lime);outline-offset:0}
.st{display:inline-block;margin-right:2px;font-size:11px;font-weight:600;line-height:1.6;padding:0 5px;border-radius:9px;background:var(--line);color:var(--ink);white-space:nowrap}
.st.g{background:var(--ok);color:#fff}.st.w{background:var(--warn);color:#2a2e22}.st.b{background:var(--bad);color:#fff}
.popover{position:fixed;z-index:60;min-width:13rem;max-width:min(22rem,92vw);background:var(--card);color:var(--ink);border:1px solid var(--line);border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.18);padding:6px;display:flex;flex-direction:column}
.popover[hidden]{display:none}.popover .pop-head{font-size:12px;color:var(--gray);padding:6px 8px 2px;overflow-wrap:anywhere}
.popover button{border:0;background:none;text-align:left;padding:6px 10px;border-radius:6px}.popover button:hover,.popover button:focus-visible{background:var(--hover);outline:none}
.toasts{position:fixed;right:16px;bottom:16px;z-index:70;display:flex;flex-direction:column;gap:8px;max-width:min(28rem,92vw)}
.toast{display:flex;gap:10px;align-items:center;background:var(--side);color:#f2f2f2;border-radius:10px;padding:10px 12px;box-shadow:0 8px 24px rgba(0,0,0,.25)}
.toast span{flex:1;overflow-wrap:anywhere}.toast.bad{background:var(--bad)}.toast button{padding:3px 10px;background:transparent;color:inherit;border-color:rgba(255,255,255,.5)}.toast button.x{border:0;font-size:18px;padding:0 4px}
dialog.confirm{max-width:min(34rem,92vw);border:1px solid var(--line);border-radius:12px;padding:18px 20px;background:var(--card);color:var(--ink)}dialog.confirm h2{margin:0 0 8px;font-size:17px}dialog.confirm p{overflow-wrap:anywhere;margin:4px 0}
dialog.drawer{margin:0 0 0 auto;height:100vh;max-height:100vh;width:min(30rem,100vw);border:0;border-left:1px solid var(--line);border-radius:0;padding:16px 18px;background:var(--card);color:var(--ink);overflow:auto}
dialog.drawer dl{display:grid;grid-template-columns:8rem minmax(0,1fr);gap:4px 12px;font-size:14px}dialog.drawer dt{color:var(--gray)}dialog.drawer dd{margin:0;overflow-wrap:anywhere}dialog.drawer pre{max-height:40vh;overflow:auto}
.skel{height:14px;margin:8px 0;border-radius:6px;background:linear-gradient(90deg,var(--line),var(--hover),var(--line));background-size:200% 100%;animation:skel 1.2s infinite}
@keyframes skel{to{background-position:-200% 0}}@media (prefers-reduced-motion:reduce){.skel{animation:none}}
p.empty,td.empty{color:var(--gray);text-align:center;padding:24px 8px}.chips.filters{margin:0 0 8px}
.bulk{position:sticky;top:44px;z-index:4;display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:8px 10px;margin-bottom:8px;border:1px solid var(--lime);border-radius:10px;background:var(--card)}.bulk[hidden]{display:none}.bulk span{flex:1}
td.acts{white-space:nowrap;width:1%;text-align:right}td.acts form{display:inline}button.icon{padding:2px 8px;font-size:14px;line-height:1.4}
table.quar .icons{visibility:hidden}table.quar tr:hover .icons,table.quar tr:focus-within .icons{visibility:visible}@media (hover:none){table.quar .icons{visibility:visible}}
details.rowmenu{display:inline-block;position:relative}details.rowmenu>summary{list-style:none;cursor:pointer;padding:2px 10px;border:1px solid var(--line);border-radius:8px;display:inline-block}details.rowmenu>summary::-webkit-details-marker{display:none}
details.rowmenu .menulist{position:absolute;right:0;z-index:30;display:flex;flex-direction:column;gap:4px;padding:6px;background:var(--card);border:1px solid var(--line);border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.18)}
details.rowmenu .menulist form,details.rowmenu .menulist button,details.rowmenu .menulist a.btn{display:block;width:100%;text-align:left}
@media (max-width:900px){table.log,table.log tbody,table.log tr,table.log td{display:block;width:100%}table.log thead{display:none}
table.log tr{border-bottom:1px solid var(--line);padding:8px 4px}table.log td{border:0;padding:2px 0;max-width:none}table.log td:empty{display:none}
table.log td[data-label]::before{content:attr(data-label) ": ";color:var(--gray);font-size:12px}td.acts{text-align:left}table.quar .icons{visibility:visible}.tablewrap{max-height:none}}
form:has(input[name=ruf_enable]:checked) .rufbox{display:grid}
form:has(select[name=key] option[value=own]:checked) .ownbox,form:has(input[name=key][value=own]:checked) .ownbox{display:grid}
form:has(select[name=kind] option[value=own]:checked) .feedbox,form:has(select[name=kind] option[value=ed25519]:checked) .rsabox,form:has(select[name=kind] option[value=rsa]:checked) .edbox,
form:has(input[name=kind][value=own]:checked) .feedbox,form:has(input[name=kind][value=ed25519]:checked) .rsabox,form:has(input[name=kind][value=rsa]:checked) .edbox{display:none}
.warnbox{grid-column:1/-1;background:var(--note);color:var(--note-ink);border-radius:8px;padding:8px 12px;margin:0;font-size:13px}
textarea{width:100%;font:13px/1.4 monospace;padding:8px 10px;border:1px solid var(--border);border-radius:8px;background:var(--area);color:var(--ink);resize:vertical}
.sw input:focus-visible+i{outline:2px solid var(--ink);outline-offset:2px}
.btns{display:flex;gap:10px;margin-top:14px;flex-wrap:wrap}
button,a.btn{font:inherit;padding:8px 18px;border-radius:8px;border:1px solid var(--line);background:var(--field);color:var(--ink);cursor:pointer;text-decoration:none;display:inline-block}
button.p,a.btn.p{background:var(--lime);border-color:var(--lime);color:#2a2e22;font-weight:600}
button.d,a.btn.d{color:var(--bad);border-color:var(--danger-line)}
td form{display:inline}td button,td a.btn{padding:4px 12px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:var(--gray);padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:9px 8px;border-bottom:1px solid var(--line);overflow-wrap:break-word}
pre{background:var(--soft);padding:10px;border-radius:8px;overflow:auto;font-size:13px;margin:0}
.pill{display:inline-block;padding:1px 9px;border-radius:12px;font-size:12px;background:var(--pill)}
.pill.g{background:var(--pill-g);color:var(--pill-g-ink)}
.pill.w{background:var(--note);color:var(--note-ink)}
footer{position:sticky;bottom:0;z-index:15;background:var(--card);border-top:1px solid var(--line);padding:8px 36px;display:flex;gap:18px;
align-items:center;flex-wrap:wrap;font-size:13px;color:var(--gray)}
footer .mie{display:flex;align-items:center;gap:8px;font-weight:600;color:var(--ink)}
footer svg{height:20px;width:auto;border-radius:2px;box-shadow:0 0 0 1px #0002}
footer a{color:var(--ink)}
.att td{overflow-wrap:normal;hyphens:auto}
@media(max-width:760px){.wrap{flex-direction:column}aside{width:100%}main{padding:20px 16px}.row{grid-template-columns:1fr}
footer{padding:6px 12px;gap:10px;font-size:11px;flex-wrap:nowrap;white-space:nowrap;overflow-x:auto}footer .long{display:none}footer svg{height:14px}
#load-card th:last-child,#load-card td:last-child{display:none}#load-card td,#load-card th{padding:6px 4px;overflow-wrap:normal}}
@media print{footer{position:static}.pending{position:static}}
/* 6.0.0.6: the attack banner on every page (sticky under the top bar) and the lamps and gauges of the dashboard. */
.threat{position:sticky;top:0;z-index:21;display:flex;gap:12px 16px;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;margin:0 0 18px;padding:12px 16px;
border-radius:10px;border:2px solid var(--warn);background:var(--pend);color:var(--pend-ink)}.threat.alert{border-color:var(--bad);background:var(--bad);color:#fff}
.threat.alert a{color:#fff}.threat .tb-text{flex:1;min-width:14rem}.threat ul{margin:4px 0 0;padding-left:18px}.threat li{margin:2px 0}.threat small{opacity:.9;overflow-wrap:anywhere}
.threat .tb-since{opacity:.85;white-space:nowrap}.threat .btn{margin:0}.threat .pill{color:var(--ink)}
.beacon{flex:none;width:14px;height:14px;margin-top:4px;border-radius:50%;background:var(--warn);box-shadow:0 0 0 0 var(--warn);animation:beacon 1.6s infinite}
.threat.alert .beacon{background:#fff;box-shadow:0 0 0 0 rgba(255,255,255,.8)}
@keyframes beacon{0%{box-shadow:0 0 0 0 rgba(255,255,255,.7)}70%{box-shadow:0 0 0 10px rgba(255,255,255,0)}100%{box-shadow:0 0 0 0 rgba(255,255,255,0)}}
@media (prefers-reduced-motion: reduce){.beacon{animation:none}}
ul.lamps{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px 14px;list-style:none;margin:0 0 16px;padding:0}
.lamp{display:flex;align-items:center;gap:8px;padding:6px 10px;border:1px solid var(--line);border-radius:8px;background:var(--area)}
.lamp .led{flex:none;width:14px;height:14px;border-radius:50%;background:var(--ok);box-shadow:0 0 6px var(--ok)}
.lamp.w .led{background:var(--warn);box-shadow:0 0 6px var(--warn)}.lamp.b .led{background:var(--bad);box-shadow:0 0 8px var(--bad)}.lamp.u .led{background:var(--chart);box-shadow:none}
.lamp.b{border-color:var(--bad);font-weight:600}
.gauges{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:10px;margin:0 0 8px}
figure.gauge{margin:0;text-align:center}figure.gauge svg{width:100%;max-width:150px;height:auto;display:block;margin:0 auto}
.gauge .z{fill:none;stroke-width:10}.gauge .z.g{stroke:var(--ok)}.gauge .z.w{stroke:var(--warn)}.gauge .z.b{stroke:var(--bad)}
.gauge .needle{stroke:var(--ink);stroke-width:3;stroke-linecap:round}.gauge .hub{fill:var(--ink)}
.gauge figcaption{display:grid;line-height:1.25}.gauge figcaption b{font-size:18px}.gauge figcaption span{font-size:12px;color:var(--gray)}
.gauge.b figcaption b{color:var(--bad)}.gauge.w figcaption b{color:var(--warn)}.gauge.u figcaption b{color:var(--gray)}
.lb{display:flex;align-items:center;gap:6px;min-width:0}
button.info{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;min-width:18px;padding:0;margin:0 0 0 6px;border:1px solid var(--border);border-radius:50%;background:transparent;color:var(--gray);font:italic 600 12px/1 Georgia,serif;cursor:help;vertical-align:middle}
.lb button.info{margin:0}button.info:hover,button.info:focus-visible{color:var(--ink);border-color:var(--ink)}
[popover].pop{max-width:min(440px,calc(100vw - 32px));padding:14px 16px;border:1px solid var(--line);border-radius:12px;background:var(--card);color:var(--ink);font:400 14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;box-shadow:0 12px 32px #0003}
[popover].pop::backdrop{background:#0001}
.row label.clr{display:inline-flex;align-items:center;gap:4px;margin-top:4px;font-size:13px;color:var(--gray);font-weight:400}
/* 6.0.0.6, UI 2026 (docs/ui-guidelines.md): one look for every page, from the tokens only, so dark mode follows. */
.card{border-radius:14px;box-shadow:0 1px 2px rgba(0,0,0,.04),0 2px 10px rgba(0,0,0,.03)}
.card h2{font-size:16px;font-weight:650;letter-spacing:-.01em}
.card td,.card th{padding:7px 12px 7px 0;border-bottom:1px solid var(--line);vertical-align:top}
.card th{font-size:12.5px;font-weight:600;color:var(--gray);text-align:left;overflow-wrap:normal;word-break:normal}
.card tr:last-child>td{border-bottom:0}.card tr:hover>td{background:var(--hover)}
.card table.log td,.card table.log th{padding:4px 6px}
table.data th{white-space:nowrap}
button,a.btn{border-radius:9px;line-height:1.3;transition:background .12s,border-color .12s,color .12s}
button:hover,a.btn:hover{border-color:var(--border)}button.p:hover,a.btn.p:hover{filter:brightness(.95)}
button.d:hover,a.btn.d:hover{background:var(--bad);border-color:var(--bad);color:#fff}
button:focus-visible,a.btn:focus-visible,summary:focus-visible,a:focus-visible{outline:2px solid var(--lime);outline-offset:2px}
input[type=text]:hover,input[type=password]:hover,select:hover,textarea:hover{border-color:var(--ink)}
.pill{border-radius:999px;padding:1px 9px;font-size:12px;font-weight:600;white-space:nowrap}.st,.badge,.switch{white-space:nowrap}
aside a.nav{margin:1px 10px;padding:7px 12px;border-left:0;border-radius:8px}aside a.nav.on{box-shadow:inset 3px 0 0 var(--lime)}
details.section>summary{list-style:none;display:flex;align-items:center;gap:10px}details.section>summary::-webkit-details-marker{display:none}
details.section>summary::before{content:"";width:7px;height:7px;border-right:2px solid var(--gray);border-bottom:2px solid var(--gray);transform:rotate(-45deg);transition:transform .15s}
details.section[open]>summary::before{transform:rotate(45deg)}
.card.done{border-width:1px;border-left:4px solid var(--ok)}
.segpick{display:inline-flex;flex-wrap:wrap;border:1px solid var(--border);border-radius:999px;overflow:hidden;background:var(--field);justify-self:start}
.segpick label{position:relative;margin:0;font-weight:500}.segpick input{position:absolute;opacity:0;width:1px;height:1px;margin:0}
.segpick span{display:block;padding:5px 14px;cursor:pointer;white-space:nowrap;font-size:13.5px}.segpick label+label span{border-left:1px solid var(--line)}
.segpick input:checked+span{background:var(--lime);color:#2a2e22;font-weight:600}.segpick input:focus-visible+span{outline:2px solid var(--ink);outline-offset:-2px}
.segpick span:hover{background:var(--hover)}.segpick input:checked+span:hover{background:var(--lime)}
@media(max-width:760px){.segpick{display:flex;width:100%}.segpick label{flex:1;text-align:center}}
.tile{border-radius:14px;box-shadow:0 1px 2px rgba(0,0,0,.04);transition:border-color .12s,box-shadow .12s}a.tile:hover,details.tile:hover{box-shadow:0 4px 14px rgba(0,0,0,.08)}
.tile b{font-size:11.5px;letter-spacing:.8px}.tile .v{font-size:22px;font-weight:650;letter-spacing:-.01em}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
main{max-width:1240px}
/* Settings forms: fields of one card in two columns on wide screens, label above its field; one column and full width on phones. */
@media (min-width:1360px){.card form:has(>.row:nth-of-type(6)){display:grid;grid-template-columns:repeat(2,minmax(0,1fr));column-gap:32px;align-items:start}
.card form:has(>.row:nth-of-type(6))>*{grid-column:1/-1}.card form:has(>.row:nth-of-type(6))>.row:not(.warnbox){grid-column:auto;grid-template-columns:1fr;gap:4px;margin:8px 0}
.card form:has(>.row:nth-of-type(6))>.row small.now{grid-column:1;margin-top:0}.card form:has(>.row:nth-of-type(6))>.row input,.card form:has(>.row:nth-of-type(6))>.row select{max-width:none}}
@media (max-width:760px){.row input[type=text],.row input[type=password],.row select{max-width:none}}
.card form:has(.row:nth-of-type(7))>.btns{position:sticky;bottom:44px;z-index:3;margin:14px -20px -18px;padding:10px 20px;background:var(--card);border-top:1px solid var(--line);border-radius:0 0 14px 14px}
@media (max-width:760px){table.data,table.data tbody,table.data tr,table.data td{display:block;width:100%}table.data tr:first-child{display:none}
table.data tr{border-bottom:1px solid var(--line);padding:6px 0}table.data td{border:0;padding:2px 0}table.data td:empty{display:none}
table.data td[data-label]::before{content:attr(data-label) ": ";color:var(--gray);font-size:12px}
table.kv,table.kv tbody,table.kv tr,table.kv th,table.kv td{display:block;width:100%}table.kv th{border:0;padding:6px 0 0}table.kv td{padding:0 0 6px}}
@media (max-width:600px){table.rbl td.n{width:auto}}table.rbl td:last-child{min-width:11rem}
</style></head><body data-yes="{{ _('Yes, do it') }}" data-no="{{ _('Cancel') }}"><div class="wrap">{% block %}{% endblock %}</div>
<footer><span class="mie">""" + FLAG_AT + FLAG_EU + """ {{ _('Made in Europe, Austria') }}</span>
<span><span class="long">{{ _('eFa-next is a private open source project:') }} </span><a target=\"_blank\" rel=\"noopener noreferrer\" href=\"""" + REPO_URL + """\">{{ _('Source code') }}</a> · <a target=\"_blank\" rel=\"noopener noreferrer\" href=\"""" + REPO_URL + """/blob/master/docs/README.md\">{{ _('Documentation') }}</a> ·
{{ _('For qualified administrators, not for consumers. No warranty or liability, to the maximum extent permitted by law:') }} <a target=\"_blank\" rel=\"noopener noreferrer\" href=\"""" + REPO_URL + """/blob/master/DISCLAIMER.md\">{{ _('Disclaimer') }}</a> · <a target=\"_blank\" rel=\"noopener noreferrer\" href=\"""" + REPO_URL + """/blob/master/AUTHORS.md\">{{ _('Authors') }}</a> ·
<a target=\"_blank\" rel=\"noopener noreferrer\" href=\"""" + REPO_URL + """/blob/master/THIRD-PARTY-NOTICES.md\">{{ _('Third-party notices') }}</a></span></footer>
</body></html>"""
LIVE_JS = """(function () {
  var box = document.getElementById('live-log'), rows = [], timer = null, paused = false, now = '';
  if (!box) return;
  var body = document.getElementById('live-rows'), t = JSON.parse(box.getAttribute('data-texts'));
  var count = document.getElementById('live-count'), pause = document.getElementById('live-pause');
  var columns = ['ts', 'sender', 'rcpt', 'subject', 'action', 'auth', 'score', 'ip', 'qid'];
  var tone = {'pass': 'g', 'no action': 'g', 'fail': 'b', 'reject': 'b', 'virus': 'b', 'permerror': 'b', 'softfail': 'w', 'add header': 'w',
              'rewrite subject': 'w', 'greylist': 'w', 'soft reject': 'w', 'temperror': 'w'};
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
  function badge(text, label) {
    var span = document.createElement('span');
    span.className = 'st ' + (tone[String(text).toLowerCase()] || '');
    span.textContent = label || text;
    if (label) span.title = label + ': ' + text;
    return span;
  }
  // Both times are of the server, so the age is right whatever the time zone of the browser.
  function ago(ts) {
    var seconds = (Date.parse(now.replace(' ', 'T')) - Date.parse(String(ts).replace(' ', 'T'))) / 1000;
    if (!(seconds >= 0)) return String(ts);
    if (seconds < 60) return t.now;
    if (seconds < 3600) return Math.floor(seconds / 60) + ' min';
    if (seconds < 86400) return Math.floor(seconds / 3600) + ' h';
    return String(ts).slice(0, 10);
  }
  function chip(text, kind, mail) {
    var button = document.createElement('button');
    button.type = 'button';
    button.className = 'chip' + (kind === 'ip' ? ' mono' : '');
    button.textContent = text;
    button.title = text;
    button.setAttribute('data-sender', text);
    button.setAttribute('data-kind', kind);
    button.setAttribute('data-rcpt', mail.rcpt || '');
    button.setAttribute('data-qid', mail.qid || '');
    if (kind !== 'ip' && mail.ip) button.setAttribute('data-ip', mail.ip);
    button.setAttribute('aria-haspopup', 'menu');
    return button;
  }
  function draw() {
    // Not while a menu or the details are open: the rows under them would change.
    if (paused || box.querySelector('.popover:not([hidden])') || document.querySelector('dialog.drawer[open], dialog.confirm[open]')) return;
    body.textContent = '';
    var list = rows.filter(shown);
    list.forEach(function (mail) {
      var tr = document.createElement('tr');
      tr.tabIndex = 0;
      tr.setAttribute('data-mail', JSON.stringify(mail));
      columns.forEach(function (c) {
        var td = document.createElement('td'), text = mail[c] === null || mail[c] === undefined ? '' : String(mail[c]);
        td.setAttribute('data-label', t.columns[c]);
        if (c === 'ts') {
          var time = document.createElement('time');
          time.textContent = ago(text);
          time.title = text;
          td.className = 'nw';
          td.appendChild(time);
        } else if (c === 'sender') {
          td.className = 'cut';
          if (text) td.appendChild(chip(text, text.indexOf('@') >= 0 ? 'address' : 'domain', mail));
          if (mail.subject) {
            // On a phone the subject is a second line under the sender, not a column.
            var line = document.createElement('div');
            line.className = 'sub2';
            line.textContent = mail.subject;
            td.appendChild(line);
          }
        } else if (c === 'action') {
          td.className = 'nw';
          if (text) td.appendChild(badge(text));
        } else if (c === 'auth') {
          td.className = 'nw';
          ['spf', 'dkim', 'dmarc'].forEach(function (k) { if (mail[k]) td.appendChild(badge(mail[k], k.toUpperCase())); });
        } else if (c === 'ip') {
          td.className = 'nw';
          if (text) td.appendChild(chip(text, 'ip', mail));
        } else {
          td.textContent = c === 'score' && typeof mail.score === 'number' ? mail.score.toFixed(1) : text;
          td.className = c === 'qid' ? 'nw mono opt' : c === 'score' ? 'nw' : 'cut' + (c === 'subject' ? ' subj' : '');
          if (c === 'rcpt' || c === 'subject') td.title = text;
        }
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    if (!list.length) {
      var empty = document.createElement('tr'), cell = document.createElement('td');
      cell.colSpan = columns.length;
      cell.className = 'empty';
      cell.textContent = rows.length ? t.none_match : t.none_yet;
      empty.appendChild(cell);
      body.appendChild(empty);
    }
    count.textContent = list.length + ' / ' + rows.length;
  }
  function skeleton() {
    body.textContent = '';
    for (var i = 0; i < 8; i++) {
      var tr = document.createElement('tr'), td = document.createElement('td');
      td.colSpan = columns.length;
      td.innerHTML = '<div class="skel"></div>';
      tr.appendChild(td);
      body.appendChild(tr);
    }
  }
  function load() {
    var after = rows.length ? rows[0].id : '';
    fetch(box.getAttribute('data-url') + '?after=' + after, {credentials: 'same-origin'}).then(function (reply) {
      if (!reply.ok || reply.redirected) throw new Error('reply');
      return reply.json();
    }).then(function (data) {
      now = data.now || now;
      rows = data.mails.concat(rows).slice(0, 1000);
      draw();
    }).catch(function () { count.textContent = t.failed; });
  }
  document.getElementById('live-open').addEventListener('click', function () {
    box.showModal();
    if (!rows.length) skeleton();
    load();
    timer = setInterval(function () { if (!paused) load(); }, 5000);
  });
  box.addEventListener('close', function () { clearInterval(timer); timer = null; });
  document.getElementById('live-close').addEventListener('click', function () { box.close(); });
  pause.addEventListener('click', function () {
    paused = !paused;
    pause.textContent = paused ? t.resume : t.pause;
    pause.setAttribute('aria-pressed', paused ? 'true' : 'false');
    if (!paused) { load(); }
  });
  document.getElementById('live-reset').addEventListener('click', function () {
    box.querySelectorAll('.live-filters input, .live-filters select').forEach(function (field) { field.value = ''; });
    draw();
  });
  box.querySelectorAll('.live-filters input, .live-filters select').forEach(function (field) {
    field.addEventListener('input', function () { var was = paused; paused = false; draw(); paused = was; });
  });
})();"""
MAILUI_JS = """(function () {
  // 6.0.0.6: sender chips with a menu (allow, block, search all mails), confirm dialog, toasts with undo, the details drawer,
  // the search in the address (only after #, never sent to the server or logged) and the bulk bar of the quarantine.
  var root = document.getElementById('mail-ui');
  if (!root) return;
  var t = JSON.parse(root.getAttribute('data-texts'));
  var csrf = root.getAttribute('data-csrf'), run = root.getAttribute('data-run'), check = root.getAttribute('data-check');
  var canAct = root.hasAttribute('data-can-act'), canIp = root.hasAttribute('data-super');
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function layer(near) { return (near && near.closest && near.closest('dialog[open]')) || document.body; }
  function post(url, fields) {
    var body = new URLSearchParams();
    body.set('csrf', csrf); body.set('json', '1');
    Object.keys(fields).forEach(function (key) { body.set(key, fields[key]); });
    return fetch(url, {method: 'POST', credentials: 'same-origin', body: body}).then(function (reply) {
      if (!reply.ok || reply.redirected) throw new Error(t.failed);
      return reply.json();
    }).then(function (data) {
      if (!data.ok) throw new Error(data.error || t.failed);
      return data.result;
    });
  }
  function call(command, fields) { return post(run + command, fields); }
  var toasts = el('div', 'toasts');
  toasts.setAttribute('role', 'status');
  toasts.setAttribute('aria-live', 'polite');
  function toast(text, undo, bad, near) {
    var box = el('div', 'toast' + (bad ? ' bad' : ''));
    box.appendChild(el('span', '', text));
    if (undo) {
      var again = el('button', '', t.undo);
      again.type = 'button';
      again.addEventListener('click', function () { box.remove(); undo(); });
      box.appendChild(again);
    }
    var shut = el('button', 'x', '×');
    shut.type = 'button';
    shut.setAttribute('aria-label', t.close);
    shut.addEventListener('click', function () { box.remove(); });
    box.appendChild(shut);
    layer(near).appendChild(toasts);
    toasts.appendChild(box);
    setTimeout(function () { box.remove(); }, undo ? 20000 : 8000);
  }
  var ask = el('dialog', 'confirm');
  document.body.appendChild(ask);
  function confirmBox(title, lines, warnings, label, danger) {
    return new Promise(function (done) {
      ask.textContent = '';
      ask.appendChild(el('h2', '', title));
      lines.forEach(function (line) { ask.appendChild(el('p', '', line)); });
      warnings.forEach(function (text) { var p = el('p', 'warnbox', text); p.setAttribute('role', 'alert'); ask.appendChild(p); });
      var row = el('div', 'btns'), yes = el('button', danger ? 'd' : 'p', label), no = el('button', '', t.cancel);
      yes.type = no.type = 'button';
      yes.addEventListener('click', function () { done(true); ask.close(); });
      no.addEventListener('click', function () { ask.close(); });
      ask.onclose = function () { done(false); };
      row.appendChild(yes); row.appendChild(no); ask.appendChild(row);
      ask.showModal();
      no.focus();
    });
  }
  function fields(value, list, info) { return {value: value, list: list, recipients: info.rcpt || '', qid: info.qid || ''}; }
  function undoOf(entries, near) {
    return function () {
      Promise.all(entries.map(function (item) { return call('sender-action', Object.assign({}, item, {action: 'remove'})); })).then(function (list) {
        toast(list.map(function (done) { return done.entry; }).join(', ') + ': ' + t.undone, null, false, near);
      }, function (err) { toast(err.message, null, true, near); });
    };
  }
  // Several senders, one confirmation: each is checked first, the dialog names every entry, its list and the warnings.
  function act(items, list, near) {
    Promise.all(items.map(function (item) {
      return post(check, item).then(function (plan) { return {item: item, plan: plan}; }, function (err) { return {item: item, error: err.message}; });
    })).then(function (found) {
      var good = found.filter(function (x) { return x.plan; }), bad = found.filter(function (x) { return x.error; });
      if (!good.length) { toast(bad.map(function (x) { return x.error; }).join(' '), null, true, near); return; }
      var lines = good.map(function (x) { return x.plan.entry + ' → ' + x.plan.target_text; });
      var warnings = [].concat.apply([], good.map(function (x) { return x.plan.warnings; })).concat(bad.map(function (x) { return x.item.value + ': ' + x.error; }));
      confirmBox(list === 'allow' ? t.allow_title : t.block_title, lines, warnings, list === 'allow' ? t.allow : t.block, list === 'block').then(function (yes) {
        if (!yes) return;
        var sent = good.map(function (x) { return Object.assign({action: 'add', confirm: x.plan.warnings.length ? 'yes' : ''}, x.item); });
        Promise.all(sent.map(function (item) { return call('sender-action', item); })).then(function (list) {
          toast(list.map(function (done) { return done.entry; }).join(', ') + ': ' + t.added + ' ' + list[0].target_text, undoOf(sent, near), false, near);
        }, function (err) { toast(err.message, null, true, near); });
      });
    });
  }
  function searchAll(token) {
    var target = root.getAttribute('data-log') + '#q=' + encodeURIComponent(token);
    if (location.pathname === root.getAttribute('data-log')) {
      var open = document.querySelector('dialog[open]');
      if (open) open.close();
      location.hash = '#q=' + encodeURIComponent(token);
    } else {
      location.href = target;
    }
  }
  var pop = el('div', 'popover'), opener = null;
  pop.setAttribute('role', 'menu');
  pop.hidden = true;
  function closePop(back) {
    if (pop.hidden) return;
    pop.hidden = true;
    if (back && opener) opener.focus();
    opener = null;
  }
  function item(label, run, cls) {
    var button = el('button', cls || '', label);
    button.type = 'button';
    button.setAttribute('role', 'menuitem');
    button.addEventListener('click', function () { closePop(false); run(); });
    pop.appendChild(button);
  }
  function openPop(chip) {
    var value = chip.getAttribute('data-sender'), kind = chip.getAttribute('data-kind');
    var info = {rcpt: chip.getAttribute('data-rcpt'), qid: chip.getAttribute('data-qid')};
    // The sender, its domain and the IP the mail came from (data-ip, from the same log entry).
    var targets = kind === 'address' ? [[value, 'from:', 'address'], [value.split('@').pop(), 'domain:', 'domain']] : [[value, kind === 'ip' ? 'ip:' : 'domain:', kind]];
    var ip = chip.getAttribute('data-ip');
    if (ip && kind !== 'ip') targets.push([ip, 'ip:', 'ip']);
    pop.textContent = '';
    targets.forEach(function (target) {
      pop.appendChild(el('div', 'pop-head', target[0]));
      if (canAct && (target[2] !== 'ip' || canIp)) {
        item(t.allow, function () { act([fields(target[0], 'allow', info)], 'allow', chip); });
        item(t.block, function () { act([fields(target[0], 'block', info)], 'block', chip); }, 'd');
      }
      item(t.search_all, function () { searchAll(target[1] + target[0]); });
    });
    layer(chip).appendChild(pop);
    opener = chip;
    pop.hidden = false;
    var box = chip.getBoundingClientRect();
    pop.style.top = Math.max(8, Math.min(box.bottom + 4, window.innerHeight - pop.offsetHeight - 8)) + 'px';
    pop.style.left = Math.max(8, Math.min(box.left, window.innerWidth - pop.offsetWidth - 8)) + 'px';
    pop.querySelector('button').focus();
  }
  document.addEventListener('click', function (event) {
    var chip = event.target.closest && event.target.closest('[data-sender]');
    if (chip) {
      event.preventDefault();
      event.stopPropagation();
      if (opener === chip) { closePop(true); } else { openPop(chip); }
      return;
    }
    if (!pop.contains(event.target)) closePop(false);
    var row = event.target.closest && event.target.closest('tr[data-mail]');
    if (row && !event.target.closest('button, a, input, form, details')) drawer(JSON.parse(row.getAttribute('data-mail')), row);
  }, true);
  document.addEventListener('keydown', function (event) {
    if (!pop.hidden) {
      var items = Array.prototype.slice.call(pop.querySelectorAll('button')), at = items.indexOf(document.activeElement);
      if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); closePop(true); }
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        items[(at + (event.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length].focus();
      }
      if (event.key === 'Tab') closePop(false);
      return;
    }
    var row = event.target.closest && event.target.closest('tr[data-mail]');
    if (row && event.target === row && event.key === 'Enter') drawer(JSON.parse(row.getAttribute('data-mail')), row);
  }, true);
  // The details of one mail at the side; the raw values under a fold.
  var side = el('dialog', 'drawer');
  side.setAttribute('aria-label', t.details);
  document.body.appendChild(side);
  function drawer(mail, near) {
    side.textContent = '';
    var head = el('div', 'live-head');
    head.appendChild(el('h2', '', t.details));
    head.appendChild(el('span', ''));
    var shut = el('button', '', t.close);
    shut.type = 'button';
    shut.addEventListener('click', function () { side.close(); });
    head.appendChild(shut);
    side.appendChild(head);
    var list = el('dl');
    t.order.forEach(function (key) {
      var value = mail[key];
      if (value === null || value === undefined || value === '') return;
      list.appendChild(el('dt', '', t.fields[key]));
      var cell = el('dd', key === 'qid' || key === 'ip' || key === 'id' ? 'mono' : '');
      if (key === 'sender' || key === 'ip') {
        var chip = el('button', 'chip' + (key === 'ip' ? ' mono' : ''), String(value));
        chip.type = 'button';
        chip.setAttribute('data-sender', value);
        chip.setAttribute('data-kind', key === 'ip' ? 'ip' : (String(value).indexOf('@') >= 0 ? 'address' : 'domain'));
        chip.setAttribute('data-rcpt', mail.rcpt || '');
        chip.setAttribute('data-qid', mail.qid || '');
        if (key === 'sender' && mail.ip) chip.setAttribute('data-ip', mail.ip);
        chip.setAttribute('aria-haspopup', 'menu');
        cell.appendChild(chip);
      } else {
        cell.textContent = Array.isArray(value) ? value.join(', ') : String(value);
      }
      list.appendChild(cell);
    });
    side.appendChild(list);
    if (mail.id && /^[0-9]+$/.test(String(mail.id))) {
      var link = el('a', 'btn', t.open_mail);
      link.href = root.getAttribute('data-mail') + encodeURIComponent(mail.id);
      side.appendChild(link);
    }
    var fold = el('details'), raw = el('pre');
    fold.appendChild(el('summary', '', t.raw));
    raw.textContent = JSON.stringify(mail, null, 2);
    fold.appendChild(raw);
    side.appendChild(fold);
    side.showModal();
    shut.focus();
  }
  window.efaMailDrawer = drawer;
  // The search in the address: #q=... fills the search field and runs it (posted, so the terms are in no server log).
  var form = document.querySelector('form[action$="/run/maillog-search"]'), shown = document.getElementById('log-result');
  var text = form && form.querySelector('[name=text]');
  function skeleton() {
    var place = shown || form;
    if (!place) return;
    var box = el('div', 'card skel-card');
    box.setAttribute('aria-busy', 'true');
    box.appendChild(el('span', 'sr', t.loading));
    for (var i = 0; i < 6; i++) box.appendChild(el('div', 'skel'));
    place.parentNode.insertBefore(box, place.nextSibling);
    if (shown) shown.hidden = true;
  }
  function fromHash() {
    var found = /^#q=(.*)$/.exec(location.hash);
    if (!found || !form) return;
    var wanted = decodeURIComponent(found[1]);
    if (shown && shown.getAttribute('data-q') === wanted) return;
    text.value = wanted;
    ['domain', 'ip'].forEach(function (name) { var field = form.querySelector('[name=' + name + ']'); if (field) field.value = ''; });
    skeleton();
    form.submit();
  }
  if (form) form.addEventListener('submit', skeleton);
  if (shown && text) {
    text.value = shown.getAttribute('data-q');
    history.replaceState(null, '', location.pathname + (text.value ? '#q=' + encodeURIComponent(text.value) : ''));
  }
  fromHash();
  window.addEventListener('hashchange', fromHash);
  // Quarantine: select rows, then deliver, delete or block their senders at once.
  var bar = document.getElementById('bulk');
  if (bar) {
    var picks = Array.prototype.slice.call(document.querySelectorAll('input.pick')), all = document.getElementById('pick-all');
    var chosen = function () { return picks.filter(function (box) { return box.checked; }); };
    var update = function () {
      var count = chosen().length;
      bar.hidden = !count;
      document.getElementById('bulk-count').textContent = count + ' ' + t.selected;
      if (all) all.checked = count === picks.length;
    };
    picks.forEach(function (box) { box.addEventListener('change', update); });
    if (all) all.addEventListener('change', function () { picks.forEach(function (box) { box.checked = all.checked; }); update(); });
    bar.addEventListener('click', function (event) {
      var what = event.target.getAttribute('data-bulk'), rows = chosen();
      if (!what || !rows.length) return;
      if (what === 'block') {
        var seen = {}, items = [];
        rows.forEach(function (box) {
          var sender = (box.getAttribute('data-from') || '').toLowerCase();
          if (sender && !seen[sender]) { seen[sender] = 1; items.push(fields(sender, 'block', {rcpt: box.getAttribute('data-rcpt'), qid: box.getAttribute('data-id')})); }
        });
        if (items.length) act(items, 'block', bar);
        return;
      }
      var ids = rows.map(function (box) { return box.getAttribute('data-id'); });
      var del = what === 'delete';
      confirmBox(del ? t.delete_title : t.deliver_title, [ids.join(', ')], del ? [t.delete_warn] : [], del ? t.delete : t.deliver, del).then(function (yes) {
        if (!yes) return;
        var next = Promise.resolve();
        ids.forEach(function (id) { next = next.then(function () { return call(del ? 'quarantine-delete' : 'quarantine-release', del ? {id: id, confirm: 'yes'} : {id: id}); }); });
        next.then(function () { location.reload(); }, function (err) { toast(err.message, null, true); setTimeout(function () { location.reload(); }, 3000); });
      });
    });
  }
})();"""
SENDERS_JS = """(function () {
  var box = document.getElementById('sender-box');
  if (!box) return;
  var data = null, name = 'allow', page = 0, size = 50, sortBy = 'entry', ascending = true, chosen = {};
  var csrf = box.getAttribute('data-csrf'), body = document.getElementById('sender-rows'), t = JSON.parse(box.getAttribute('data-texts'));
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
      tick.setAttribute('aria-label', t.select + ' ' + row.entry);
      tick.addEventListener('change', function () { chosen[row.entry] = tick.checked; });
      td.appendChild(tick); tr.appendChild(td);
      var entry = document.createElement('td'), kind = {address: 'address', domain: 'domain', IP: 'ip'}[row.type];
      entry.className = 'cut';
      entry.title = row.entry;
      if (kind && row.entry.indexOf('/') < 0) {
        // The menu of the mail views: search all mails of this sender, or put it on the other list.
        var chip = document.createElement('button');
        chip.type = 'button'; chip.className = 'chip' + (kind === 'ip' ? ' mono' : ''); chip.textContent = row.entry;
        chip.setAttribute('data-sender', row.entry); chip.setAttribute('data-kind', kind); chip.setAttribute('aria-haspopup', 'menu');
        entry.appendChild(chip);
      } else {
        entry.textContent = row.entry;
      }
      tr.appendChild(entry);
      var type = document.createElement('td'), badge = document.createElement('span');
      badge.className = 'st'; badge.textContent = t.types[row.type] || row.type; type.className = 'nw'; type.appendChild(badge); tr.appendChild(type);
      [row.comment, row.added, name === 'rules' ? (row.list === 'allow' ? t.allow : t.block) + ', ' + t.for_ + ' ' + row.recipient : ''].forEach(function (text, index) {
        var cell = document.createElement('td'); cell.textContent = text; cell.className = index === 1 ? 'nw' : 'cut'; cell.title = text; tr.appendChild(cell);
      });
      var actions = document.createElement('td'), move = document.createElement('button');
      actions.className = 'acts';
      move.type = 'button'; move.textContent = other(row) === 'allow' ? t.to_allow : t.to_block;
      move.addEventListener('click', function () { post('sender-move', {entry: row.entry, to: other(row)}); });
      var remove = document.createElement('button');
      remove.type = 'button'; remove.textContent = t.remove; remove.className = 'd';
      remove.addEventListener('click', function () { removeEntries([row.entry]); });
      actions.appendChild(move); actions.appendChild(remove); tr.appendChild(actions);
      body.appendChild(tr);
    });
    if (!list.length) {
      var empty = document.createElement('tr'), cell = document.createElement('td');
      cell.colSpan = 7; cell.className = 'empty'; cell.textContent = t.none; empty.appendChild(cell); body.appendChild(empty);
    }
    info.textContent = t.info.replace('{count}', list.length).replace('{page}', page + 1).replace('{pages}', pages);
  }
  function removeEntries(entries) {
    if (entries.length) {
      efaConfirm(t.remove_q + '\\n' + entries.join(', '), function () { post('sender-remove', {entries: entries.join(' '), confirm: 'yes'}); }, box);
    }
  }
  function open(list, needle) {
    name = list; page = 0; chosen = {}; search.value = needle || '';
    document.getElementById('sender-title').textContent = t.titles[list];
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
      if (entries.length) efaConfirm(t.add_q + '\\n' + entries.join(', '), function () { addNow(entries.join(' '), ''); }, box);
    };
    reader.readAsText(event.target.files[0]);
  });
})();"""
COPY_JS = """// UI 2026: on a phone the menu starts folded, under one button; on a wide screen it stays open.
document.addEventListener('DOMContentLoaded', function () {
  var menu = document.querySelector('details.navmenu');
  if (menu && window.matchMedia('(max-width: 760px)').matches) menu.open = false;
});
// UI 2026: a list table (table.data) becomes cards on a phone; each cell gets the name of its column, from the head row.
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('table.data').forEach(function (table) {
    var head = table.querySelector('tr'), names = head ? Array.prototype.map.call(head.children, function (cell) { return cell.textContent.trim(); }) : [];
    Array.prototype.forEach.call(table.querySelectorAll('tr'), function (row, index) {
      if (!index || row.parentNode.closest('table') !== table) return;
      Array.prototype.forEach.call(row.children, function (cell, at) {
        if (cell.tagName === 'TD' && !cell.hasAttribute('data-label') && names[at]) cell.setAttribute('data-label', names[at]);
      });
    });
  });
});
// The small confirm dialog of the page (UI 2026), for data-confirm buttons and the scripts of the pages; lines stay lines.
function efaConfirm(question, yes, near) {
  var ask = document.createElement('dialog'), row = document.createElement('div');
  var ok = document.createElement('button'), no = document.createElement('button');
  ask.className = 'confirm';
  ask.setAttribute('role', 'alertdialog');
  String(question).split('\\n').forEach(function (line) { var text = document.createElement('p'); text.textContent = line; ask.appendChild(text); });
  row.className = 'btns';
  ok.type = no.type = 'button';
  ok.className = 'd';
  ok.textContent = document.body.getAttribute('data-yes') || 'OK';
  no.textContent = document.body.getAttribute('data-no') || 'Cancel';
  ok.addEventListener('click', function () { ask.close(); yes(); });
  no.addEventListener('click', function () { ask.close(); });
  ask.addEventListener('close', function () { ask.remove(); });
  row.appendChild(ok); row.appendChild(no); ask.appendChild(row);
  ((near && near.closest && near.closest('dialog[open]')) || document.body).appendChild(ask);
  ask.showModal();
  no.focus();
}
document.addEventListener('DOMContentLoaded', function () {
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
  var asking = event.target.closest && event.target.closest('[data-confirm]');
  if (asking && !asking.hasAttribute('data-confirmed')) {
    event.preventDefault();
    efaConfirm(asking.getAttribute('data-confirm'), function () {
      asking.setAttribute('data-confirmed', '');
      asking.click();
      asking.removeAttribute('data-confirmed');
    }, asking);
    return;
  }
  var id = event.target.getAttribute('data-copy');
  if (!id) return;
  var box = document.getElementById(id);
  box.select();
  navigator.clipboard.writeText(box.value).then(function () { event.target.textContent = 'Copied'; });
});
// 9f: "/" goes to the search field.
document.addEventListener('keydown', function (event) {
  var field = document.getElementById('search-q');
  var typing = /^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName) || event.target.isContentEditable;
  if (field && event.key === '/' && !typing) { event.preventDefault(); field.focus(); }
});
// 6.0.0.6: suggestions while typing in the search, from one index per login and language that the browser keeps
// (search/index.json); matched here, so no keystroke goes to the server. Enter without a choice posts the search as before.
// copy.js comes before the menu in the page: the field exists only once the page is read.
document.addEventListener('DOMContentLoaded', function () {
  var field = document.getElementById('search-q'), box = document.getElementById('search-list');
  if (!field || !box) return;
  var t = JSON.parse(field.getAttribute('data-texts')), data = null, loading = null, items = [], at = -1;
  function norm(text) {
    return String(text || '').toLowerCase().replace(/ä/g, 'ae').replace(/ö/g, 'oe').replace(/ü/g, 'ue')
      .replace(/ß/g, 'ss').normalize('NFKD').replace(/[̀-ͯ]/g, '');
  }
  function load() {
    if (data) return Promise.resolve(data);
    if (!loading) {
      loading = fetch(field.getAttribute('data-index'), {credentials: 'same-origin'}).then(function (reply) {
        return reply.ok && !reply.redirected ? reply.json() : {items: [], syn: {}};
      }).then(function (found) {
        found.items.forEach(function (item) { item.n = norm(item.t); item.all = item.k + ' ' + norm(item.e); });
        data = found;
        return found;
      }, function () { loading = null; return {items: [], syn: {}}; });
    }
    return loading;
  }
  // One letter wrong, missing or too many: "quarantne" still finds the quarantine.
  function near(a, b) {
    if (Math.abs(a.length - b.length) > 1) return false;
    var i = 0, j = 0, miss = 0;
    while (i < a.length && j < b.length) {
      if (a[i] === b[j]) { i++; j++; continue; }
      if (++miss > 1) return false;
      if (a.length > b.length) { i++; } else if (b.length > a.length) { j++; } else { i++; j++; }
    }
    return miss + (a.length - i) + (b.length - j) <= 1;
  }
  function options(word) {
    var found = [word];
    Object.keys(data.syn).forEach(function (key) {
      var group = [key].concat(data.syn[key]).map(norm);
      if (group.indexOf(word) >= 0) found = found.concat(group);
    });
    return found;
  }
  function score(item, groups) {
    var total = 0;
    for (var g = 0; g < groups.length; g++) {
      var best = 0;
      groups[g].forEach(function (word) {
        if ((' ' + item.n).indexOf(' ' + word) >= 0) best = Math.max(best, 6);
        else if (item.n.indexOf(word) >= 0) best = Math.max(best, 4);
        else if ((' ' + item.all).indexOf(' ' + word) >= 0) best = Math.max(best, 3);
        else if (item.all.indexOf(word) >= 0) best = Math.max(best, 2);
        else if (word.length >= 5 && (item.n + ' ' + item.all).split(/[^a-z0-9]+/).some(function (part) { return near(part, word); })) best = Math.max(best, 1);
      });
      if (!best) return 0;
      total += best;
    }
    return total + (item.g === 'page' ? 1 : 0);
  }
  // What looks like an address, a domain, an IP or a queue ID: straight into the mail log with that filter.
  function mailItems(text) {
    var value = text.trim(), filter = '', label = '';
    if (!data.mail || !value || /\\s/.test(value)) return [];
    if (/^[^@]+@[^@]+\\.[a-z]{2,}$/i.test(value)) { filter = 'from:' + value; label = t.from; }
    else if (/^(\\d{1,3}\\.){3}\\d{1,3}$/.test(value) || (/^[0-9a-f:]+$/i.test(value) && value.split(':').length > 2)) { filter = 'ip:' + value; label = t.ip; }
    else if (/^([a-z0-9-]+\\.)+[a-z]{2,}$/i.test(value)) { filter = 'domain:' + value; label = t.domain; }
    else if (/^[0-9A-Za-z]{10,20}$/.test(value) && /[0-9]/.test(value) && /[A-Z]/.test(value)) { filter = value; label = t.qid; }
    return filter ? [{g: 'mail', t: label.replace('{x}', value), e: t.mail_hint, u: data.log + '#q=' + encodeURIComponent(filter)}] : [];
  }
  function close() {
    box.hidden = true;
    field.setAttribute('aria-expanded', 'false');
    field.removeAttribute('aria-activedescendant');
    at = -1;
  }
  function draw() {
    var words = norm(field.value).split(/\\s+/).filter(Boolean).slice(0, 6);
    box.textContent = '';
    items = [];
    at = -1;
    if (!words.length || !data) { close(); return; }
    var groups = words.map(options), shown = {mail: mailItems(field.value), page: [], action: [], setting: []};
    data.items.map(function (item) { return [score(item, groups), item]; }).filter(function (pair) { return pair[0]; })
      .sort(function (a, b) { return b[0] - a[0] || a[1].t.localeCompare(b[1].t); })
      .forEach(function (pair) { var list = shown[pair[1].g]; if (list && list.length < (pair[1].g === 'page' ? 4 : 5)) list.push(pair[1]); });
    ['mail', 'page', 'action', 'setting'].forEach(function (group) {
      if (!shown[group].length) return;
      var head = document.createElement('li');
      head.className = 'sg-head';
      head.setAttribute('role', 'presentation');
      head.textContent = t.groups[group];
      box.appendChild(head);
      shown[group].forEach(function (item) {
        var li = document.createElement('li'), title = document.createElement('b');
        li.id = 'sg-' + items.length;
        li.className = 'sg';
        li.setAttribute('role', 'option');
        li.setAttribute('aria-selected', 'false');
        title.textContent = item.t;
        li.appendChild(title);
        if (item.p) { var where = document.createElement('span'); where.className = 'sg-page'; where.textContent = item.p; li.appendChild(where); }
        if (item.e) { var line = document.createElement('small'); line.textContent = item.e; li.appendChild(line); }
        li.addEventListener('mousedown', function (event) { event.preventDefault(); go(item); });
        box.appendChild(li);
        items.push(item);
      });
    });
    if (!items.length) {
      var none = document.createElement('li');
      none.className = 'sg-head';
      none.setAttribute('role', 'presentation');
      none.textContent = t.none;
      box.appendChild(none);
    }
    box.hidden = false;
    field.setAttribute('aria-expanded', 'true');
  }
  function move(step) {
    at = (at + step + items.length) % items.length;
    Array.prototype.forEach.call(box.querySelectorAll('.sg'), function (li, index) { li.setAttribute('aria-selected', index === at ? 'true' : 'false'); });
    var current = document.getElementById('sg-' + at);
    field.setAttribute('aria-activedescendant', current.id);
    current.scrollIntoView({block: 'nearest'});
  }
  function go(item) {
    close();
    location.href = item.u;
  }
  field.addEventListener('focus', load);
  field.addEventListener('input', function () { load().then(draw); });
  field.addEventListener('keydown', function (event) {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      if (box.hidden) draw();
      if (items.length) { event.preventDefault(); move(event.key === 'ArrowDown' ? 1 : -1); }
    } else if (event.key === 'Enter' && at >= 0) {
      event.preventDefault();
      go(items[at]);
    } else if (event.key === 'Escape') {
      if (!box.hidden) { event.preventDefault(); close(); } else { field.blur(); }
    }
  });
  field.addEventListener('blur', function () { setTimeout(close, 150); });
});
setInterval(function () {
  // The load card, the status board and the attack banner: renewed only while the page is visible.
  ['load-card', 'status-board', 'threat-banner'].forEach(function (id) {
    var card = document.getElementById(id);
    if (!card || document.hidden) return;
    fetch(card.getAttribute('data-url'), {credentials: 'same-origin'}).then(function (reply) {
      if (!reply.ok || reply.redirected) return;
      reply.text().then(function (html) {
        if (id !== 'threat-banner') { card.innerHTML = html; return; }
        var box = document.createElement('div');
        box.innerHTML = html;
        if (box.firstElementChild) card.innerHTML = box.firstElementChild.innerHTML;
      });
    });
  });
}, 30000);"""
RUF_WARNING = ('Privacy: failure reports (ruf) can contain personal data such as message headers, addresses and parts '
               'of message content. Under the GDPR a legal basis and a processing agreement with the report receiver '
               'may be needed. Many receivers do not send them at all.')
SOLO = '<main class="solo">' + BRAND
FAILED = PAGE.replace(BLOCK, SOLO + """<div class="card"><p class="err" role="alert">{{ error }}</p></div></main>""")
LOGIN = PAGE.replace(BLOCK, SOLO + """<div class="card"><nav class="seg langs" aria-label="{{ _('Language') }}"><a href="?lang=en" lang="en"{% if lang == 'en' %} class="cur"{% endif %}>English</a><a href="?lang=de" lang="de"{% if lang == 'de' %} class="cur"{% endif %}>Deutsch</a></nav><h1>{{ _('Log in') }}</h1>
{% if portal %}<p class="err" role="alert">{{ _('This account logs in at the user portal.') }} <a href="/portal/login">{{ _('To the user portal') }}</a></p>{% endif %}
{% if error %}<p class="err" role="alert">{{ error }}</p>{% endif %}<form method="post">
<input type="hidden" name="csrf" value="{{ csrf }}"><div class="row"><label for="username">{{ _('Mail address') if portal_mode else _('User name, empty for the main admin') }}</label>
<input type="text" id="username" name="username" autocomplete="username" value="{{ username or '' }}"></div><div class="row"><label for="password">{{ _('Password') }}</label>
<input type="password" id="password" name="password" autofocus></div>
<div class="row"><label for="code">{{ _('2FA code, if you set one up') }}</label><input type="text" id="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="20"></div>
<input type="hidden" name="assertion" value="">
<div class="btns"><button class="p">{{ _('Log in') }}</button><button type="button" id="passkey-login" hidden>{{ _('Use a passkey') }}</button></div>
<p class="err" id="passkey-error" hidden>{{ _('The passkey did not work. Log in with password and code.') }}</p></form><script src="/passkey.js"></script>{% if sso or tenant_sso %}<form method="get" action="{{ url_for('oidc_login') }}">
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
<details class="section" open><summary>{{ _('Why this result') }}</summary><div class="card">{% if view.verdict %}<table class="data"><tr><th>Check</th><th>Score</th><th>Meaning</th></tr>
{% for item in view.verdict %}<tr><td>{{ item.symbol }}</td><td>{{ item.score }}</td><td>{{ (item.text_de if lang == 'de' and item.text_de else item.text) or '' }}</td></tr>{% endfor %}</table>
{% else %}<p class="h">No checks stored for this mail: mail before this version has none.</p>{% endif %}</div></details>
<details class="section" open><summary>{{ _('Path over the servers') }}</summary><div class="card">{% if view.received %}<table class="data"><tr><th>Hop</th><th>Time</th><th>Seconds</th></tr>
{% for hop in view.received %}<tr><td>{{ hop.hop }}</td><td>{{ hop.time }}</td><td>{{ hop.seconds if hop.seconds is not none else '' }}</td></tr>{% endfor %}</table>
{% else %}<p class="h">{{ view.headers_note or 'No Received lines.' }}</p>{% endif %}</div></details>
<details class="section" open><summary>{{ _('Checks: authentication, ARC, DKIM') }}</summary><div class="card">{% for item in view.checks %}<p><b>{{ item.name }}</b>: {{ item.value }}</p>
{% else %}<p class="h">None in the stored headers.</p>{% endfor %}{% for item in view.spam %}<p class="h">{{ item.name }}: {{ item.value }}</p>{% endfor %}</div></details>
<details class="section"><summary>{{ _('DNS evidence') }}</summary><div class="card">{% if view.evidence %}
<p class="h">{{ view.evidence.note }} Asked {{ view.evidence.asked }} at {{ view.evidence.resolver }}.{% if view.evidence.fcrdns is not none %} Forward-confirmed reverse DNS: {{ 'yes' if view.evidence.fcrdns else 'no' }}.{% endif %}</p>
<table class="data"><tr><th>Check</th><th>Query</th><th>Answer</th><th>TTL</th><th>DNSSEC</th><th>ms</th></tr>{% for item in view.evidence.checks %}<tr><td>{{ item.check }}</td><td>{{ item.query }} {{ item.type }}</td>
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
THREAT_BANNER = """{% set threat = threat_view(commands, session.get('role', 'super')) %}<div id="threat-banner" data-url="{{ url_for('threat_banner') }}">
{%- if threat %}<div class="threat {{ threat.level }}" role="alert"><span class="beacon" aria-hidden="true"></span><div class="tb-text"><b>{{ threat.head }}</b>
<ul>{% for item in threat.entries %}<li class="{{ item.level }}">{% if item.href %}<a href="{{ item.href }}">{{ item.name }}</a>{% else %}{{ item.name }}{% endif %}: {{ item.line }}
{%- if item.since %} <span class="tb-since">{{ _('since') }} {{ item.since }}</span>{% endif %}{% if item.easing %} <span class="pill">{{ _('easing') }}</span>{% endif %}
{%- if item.top %}<br><small>{{ _('Most from') }}: {% for address, count in item.top %}{{ address }} ({{ count }}){{ ', ' if not loop.last }}{% endfor %}</small>{% endif %}</li>{% endfor %}</ul></div>
{% if page is not defined or page.slug != 'dash' %}<a class="btn s" href="{{ url_for('show_page', slug='dash') }}">{{ _('Dashboard') }}</a>{% endif %}</div>{% endif %}</div>"""
STATUS_BOARD = """<h2>{{ _('Status at a glance') }}</h2><ul class="lamps">{% for lamp in board.lamps %}<li class="lamp {{ lamp.state }}"{% if lamp.title %} title="{{ lamp.title }}"{% endif %}>
<span class="led" aria-hidden="true"></span>{{ lamp.label }}<span class="sr"> {{ {'g': _('ok'), 'w': _('warning'), 'b': _('fault'), 'u': _('unknown')}[lamp.state] }}</span></li>{% endfor %}</ul>
<div class="gauges">{% for gauge in board.gauges %}{{ gauge|safe }}{% endfor %}</div>
<p class="h">{% if board.checked %}{{ _('Attack check at') }} {{ board.checked }}. {% else %}{{ _('The attack check has no current result yet.') }} {% endif %}{{ _('Green: normal. Amber: unusual. Red: attack or fault.') }}</p>"""
LOAD_CARD = """<h2>{{ _('Load') }}</h2>{% if not rows %}<p class="h">{{ _('Collecting: the first value comes after a minute.') }}</p>{% else %}
<table><tr><th></th><th>{{ _('Now') }}</th><th>15 min</th><th>{{ _('24 h max') }}</th><th>{{ _('Last hour') }}</th></tr>{% for row in rows %}<tr><td>{{ row.label }}</td><td>{{ row.now }}%</td><td>{{ row.avg }}%</td><td>{{ row.top }}%</td>
<td><svg viewBox="0 0 100 20" width="100" height="20" role="img" aria-label="{{ row.label }}, last hour"><polyline points="{{ row.points }}" fill="none" stroke="#646563" stroke-width="1"/></svg></td></tr>{% endfor %}</table>
<p class="h">Load average {{ extra.load|join(' / ') }} (1, 5, 15 min, {{ extra.cpus }} CPUs). Network: in {{ last.rx }} Mbit/s, out {{ last.tx }} Mbit/s.</p>
<p class="h">{% for disk in extra.disks %}{{ disk.mount }}: {{ disk.free }} GB free of {{ disk.size }} GB ({{ disk.used }}% used). {% endfor %}</p>
{% for text in advice %}<p class="warnbox">{{ text }}</p>{% endfor %}{% endif %}"""
MAIN = PAGE.replace(BLOCK, """
{%- macro show(value, key='') -%}
  {%- if value is none or value == '' -%}<span class="pill">{{ _('none') }}</span>
  {%- elif value is sameas true -%}<span class="pill g">yes</span>
  {%- elif value is sameas false -%}<span class="pill w">no</span>
  {%- elif key in ('arrived', 'checked_at') and value is number -%}{{ value|when }}
  {%- elif value is string -%}{% if value.count('\\n') %}<pre>{{ value }}</pre>{% else %}{{ value }}{% endif %}
  {%- elif value is mapping -%}
    {%- if not value -%}<span class="pill">{{ _('none') }}</span>{%- else -%}<table class="kv">
    {%- for k, v in value.items() -%}<tr><th>{{ k|replace('_', ' ') }}</th><td>{{ show(v, k) }}</td></tr>{%- endfor -%}
    </table>{%- endif -%}
  {%- elif value is sequence -%}
    {%- if not value -%}<span class="pill">{{ _('none') }}</span>
    {%- elif value[0] is mapping -%}<table class="data"><tr>{% for k in value[0] %}<th>{{ k|replace('_', ' ') }}</th>{% endfor %}</tr>
      {%- for item in value -%}<tr>{% for k in value[0] %}<td data-label="{{ k|replace('_', ' ') }}">{{ show(item.get(k), k) }}</td>{% endfor %}</tr>{%- endfor -%}
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
  <input type="hidden" name="mode" value="{{ 'off' if on else 'on' }}"><button class="badge{{ ' on' if on }}" aria-pressed="{{ 'true' if on else 'false' }}" title="{{ _('Turn off') if on else _('Turn on') }}">{{ _('On') if on else _('Off') }}</button></form>
  {%- else -%}<span class="badge{{ ' on' if on }}">{{ _('On') if on else _('Off') }}</span>{%- endif -%}
{%- endmacro -%}
{%- macro rblswitch(row) -%}
  {#- UI-RBL: the switch shows the state in effect. Off with unconfirmed terms: the terms and their tick box first. -#}
  {%- set accept = (commands.get('rbl-set', {}).get('args', [])|selectattr('name', 'equalto', 'accept_terms')|map(attribute='label')|first) or '' -%}
  {%- if 'rbl-set' not in commands -%}{#- Read only: the state, no switch to press. -#}<span class="switch{{ ' on' if row.active }}"><span class="knob" aria-hidden="true"></span>{{ _('On') if row.active else _('Off') }}</span>
  {%- elif row.active or row.terms_accepted -%}
  <form method="post" action="{{ url_for('run', name='rbl-set') }}" class="toggle"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="id" value="{{ row.id }}">
  <input type="hidden" name="mode" value="{{ 'off' if row.active else 'on' }}"><input type="hidden" name="score" value=""><input type="hidden" name="key" value="">
  <button class="switch{{ ' on' if row.active }}" role="switch" aria-checked="{{ 'true' if row.active else 'false' }}" aria-label="{{ row.list }}" title="{{ _('Turn off') if row.active else _('Turn on') }}"><span class="knob" aria-hidden="true"></span>{{ _('On') if row.active else _('Off') }}</button></form>
  {%- endif -%}
  {%- if not row.terms_accepted and 'rbl-set' in commands -%}
  <details class="rblterms"><summary{% if not row.active %} class="switch" role="switch" aria-checked="false" aria-label="{{ row.list }}"{% endif %}>{% if row.active %}{{ _('Confirm the terms') }}{% else %}<span class="knob" aria-hidden="true"></span>{{ _('Off') }}{% endif %}</summary>
  <form method="post" action="{{ url_for('run', name='rbl-set') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="id" value="{{ row.id }}"><input type="hidden" name="mode" value="on"><input type="hidden" name="score" value="">
  {%- if row.terms_published and row.terms_url.startswith('https://') %}<p><a href="{{ row.terms_url }}" target="_blank" rel="noopener noreferrer">{{ _('Terms of use') }}: {{ row.list }}</a></p>{% else %}<p>{{ _('no published terms') }}</p>{% endif %}
  <label class="tick"><input type="checkbox" name="accept_terms" value="yes" required> {{ accept|t if accept else _('I have read and accept the terms of use of this list.') }}</label>
  <input type="hidden" name="key" value="">
  <button class="p">{{ _('Turn on') }}</button></form></details>
  {%- endif -%}
{%- endmacro -%}
{%- macro clamswitch(row) -%}
  {#- UI-CLAM: as UI-RBL. The switch shows the state in effect; without accepted terms the terms, their tick box and (SecuriteInfo)
  the account ID first. The ID goes to efactl on stdin, never into the page. -#}
  {%- if 'clam-source-set' not in commands -%}<span class="switch{{ ' on' if row.active }}"><span class="knob" aria-hidden="true"></span>{{ _('On') if row.active else _('Off') }}</span>
  {%- elif row.active or row.terms_accepted -%}
  <form method="post" action="{{ url_for('run', name='clam-source-set') }}" class="toggle"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="source" value="{{ row.source }}">
  <input type="hidden" name="mode" value="{{ 'off' if row.active else 'on' }}"><input type="hidden" name="accept_terms" value="">
  <button class="switch{{ ' on' if row.active }}" role="switch" aria-checked="{{ 'true' if row.active else 'false' }}" aria-label="{{ row.name }}" title="{{ _('Turn off') if row.active else _('Turn on') }}"{% if not row.active and row.needs_id and not row.id_set %} disabled{% endif %}><span class="knob" aria-hidden="true"></span>{{ _('On') if row.active else _('Off') }}</button></form>
  {%- else -%}
  <details class="rblterms"><summary class="switch" role="switch" aria-checked="false" aria-label="{{ row.name }}"><span class="knob" aria-hidden="true"></span>{{ _('Off') }}</summary>
  <form method="post" action="{{ url_for('run', name='clam-source-set') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="source" value="{{ row.source }}"><input type="hidden" name="mode" value="on">
  {%- if row.terms_url.startswith('https://') %}<p><a href="{{ row.terms_url }}" target="_blank" rel="noopener noreferrer">{{ _('Terms of use') }}: {{ row.name }}</a></p>{% else %}<p>{{ _('no published terms') }}</p>{% endif %}
  <p><small>{{ row.terms }}</small></p>
  {%- if row.needs_id %}<label>{{ _('Account ID (SecuriteInfo)') }} <input type="password" name="id" autocomplete="off" spellcheck="false" maxlength="200" required></label>{% endif %}
  <label class="tick"><input type="checkbox" name="accept_terms" value="yes" required> {{ _('I have read and accept the terms of this source: type yes')|replace(': type yes', '') }}</label>
  <button class="p">{{ _('Turn on') }}</button></form></details>
  {%- endif -%}
{%- endmacro -%}
{%- macro post(name, label, fields, cls='') -%}
  <form method="post" action="{{ url_for('run', name=name) }}"><input type="hidden" name="csrf" value="{{ csrf }}">
  {%- for k, v in fields.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor -%}
  <button{% if cls %} class="{{ cls }}"{% endif %}{% if cls == 'd' %} data-confirm="{{ label }}?"{% endif %}>{{ label }}</button></form>
{%- endmacro -%}
{%- macro st(value, label='') -%}
  {%- if value -%}{%- set v = value|lower -%}<span class="st {{ 'g' if v in ('pass', 'no action') else 'b' if v in ('fail', 'reject', 'virus', 'permerror') else 'w' if v in ('softfail', 'add header', 'rewrite subject', 'greylist', 'soft reject', 'temperror') else '' }}"{% if label %} title="{{ label }}: {{ value }}"{% endif %}>{{ label or value }}</span>{%- endif -%}
{%- endmacro -%}
{%- macro chip(value, kind, qid, rcpt, ip='') -%}
  {#- 6.0.0.6: a sender, a domain or an IP: its menu has allow, block and search all mails (mailui.js). -#}
  {%- if value -%}<button type="button" class="chip{{ ' mono' if kind == 'ip' }}" data-sender="{{ value }}" data-kind="{{ kind }}" data-qid="{{ qid or '' }}" data-rcpt="{{ rcpt or '' }}"{% if ip %} data-ip="{{ ip }}"{% endif %} title="{{ value }}" aria-haspopup="menu">{{ value }}</button>{%- endif -%}
{%- endmacro -%}
{%- macro iconpost(name, icon, label, fields) -%}
  <form method="post" action="{{ url_for('run', name=name) }}"><input type="hidden" name="csrf" value="{{ csrf }}">
  {%- for k, v in fields.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor -%}
  <button class="icon" title="{{ label }}" aria-label="{{ label }}"><span aria-hidden="true">{{ icon }}</span></button></form>
{%- endmacro -%}
{%- macro mailui() -%}
  {%- set ui = {'allow': _('Allow'), 'block': _('Block'), 'search_all': _('Search all mails'), 'allow_title': _('Always allow this sender?'),
               'block_title': _('Always block this sender?'), 'added': _('added to'), 'undone': _('taken out again'), 'undo': _('Undo'), 'close': _('Close'),
               'cancel': _('Cancel'), 'failed': _('That did not work, log in again if needed.'), 'details': _('Mail details'), 'open_mail': _('Details and headers'),
               'raw': _('Raw values (JSON)'), 'loading': _('Loading'), 'selected': _('selected'), 'deliver': _('Deliver'), 'deliver_title': _('Deliver these mails?'),
               'delete': _('Delete'), 'delete_title': _('Delete these mails for good?'), 'delete_warn': _('Deleted mail cannot be brought back.'),
               'fields': {'ts': _('Time'), 'sender': _('Sender'), 'rcpt': _('Recipient'), 'subject': _('Subject'), 'action': _('Result'), 'score': _('Score'),
                          'spf': 'SPF', 'dkim': 'DKIM', 'dmarc': 'DMARC', 'ip': _('IP address'), 'qid': _('Queue ID'), 'message_id': 'Message-ID'},
               'order': ['ts', 'sender', 'rcpt', 'subject', 'action', 'score', 'spf', 'dkim', 'dmarc', 'ip', 'qid', 'message_id']} -%}
  <div id="mail-ui" hidden data-texts='{{ ui|tojson }}' data-csrf="{{ csrf }}" data-run="{{ url_for('run', name='') }}" data-check="{{ url_for('senders_check') }}"
  data-log="{{ url_for('show_page', slug='log') }}" data-mail="{{ url_for('mail_page', mail_id=0)[:-1] }}"{% if 'sender-action' in commands %} data-can-act{% endif %}
  {%- if session.get('role', 'super') == 'super' %} data-super{% endif %}></div><script defer src="{{ url_for('mailui_js') }}"></script>
{%- endmacro -%}
{%- macro blocklist_table(sout) -%}
{% for text in sout.warnings or [] %}<p class="warnbox" role="alert">{{ text }}</p>{% endfor %}
    <p class="h">{{ _('Firewall table') }}: <span class="pill{{ ' g' if sout.loaded else ' w' }}">{{ _('loaded') if sout.loaded else _('not loaded') }}</span></p>
    {% if sout.blocklists %}<table class="data"><tr><th>{{ _('List') }}</th><th>{{ _('Kind') }}</th><th>{{ _('State') }}</th><th>{{ _('Ports') }}</th><th>{{ _('Addresses') }}</th><th>{{ _('Fetched') }}</th></tr>
    {% for item in sout.blocklists %}<tr><td data-label="{{ _('List') }}"><b>{{ item.name }}</b>{% if item.error %} <span class="st b" title="{{ item.error }}">{{ _('error') }}</span>{% endif %}</td>
    <td class="nw" data-label="{{ _('Kind') }}"><span class="st">{{ _('feed') if item.kind == 'feed' else _('own list') }}</span></td>
    <td class="nw" data-label="{{ _('State') }}"><span class="pill{{ ' g' if item.enabled else '' }}">{{ _('On') if item.enabled else _('Off') }}</span>{% if item.kind == 'feed' and not item.terms_accepted %} <span class="pill w">{{ _('terms open') }}</span>{% endif %}</td>
    <td class="nw mono" data-label="{{ _('Ports') }}">{{ item.ports }}</td><td class="nw" data-label="{{ _('Addresses') }}">{{ item.feed_addresses + item.own_addresses }}</td>
    <td class="nw" data-label="{{ _('Fetched') }}">{% if item.fetched %}<time title="{{ item.fetched }}">{{ item.fetched|ago }}</time>{% endif %}</td></tr>{% endfor %}</table>
    {% else %}<p class="empty">{{ _('No IP blocklist yet: add a feed or an own list below.') }}</p>{% endif %}
    {% if sout.known_feeds %}<details class="help"><summary>{{ _('Known feeds') }} ({{ sout.known_feeds|length }})</summary><table class="data"><tr><th>{{ _('Feed') }}</th><th>{{ _('Terms') }}</th></tr>
    {% for feed in sout.known_feeds %}<tr><td data-label="{{ _('Feed') }}"><b>{{ feed.name }}</b> {{ feed.title }}</td><td data-label="{{ _('Terms') }}">{{ feed.terms }}</td></tr>{% endfor %}</table></details>{% endif %}
{%- endmacro -%}
{%- macro copybox(id, text) -%}
  <textarea id="{{ id }}" rows="{{ 2 if text|length < 120 else 5 }}" readonly>{{ text }}</textarea>
  <button type="button" data-copy="{{ id }}">Copy</button>
{%- endmacro -%}
{%- macro keytable() -%}
  {%- set rows = (values.get('keys') or [])|selectattr('type', 'in', ['rsa', 'ed25519'])|list -%}
  {%- if rows -%}<table class="data"><tr><th>Domain</th><th>Type</th><th>Selector</th><th>Size</th><th>State</th><th>DNS record</th><th></th></tr>
  {%- for key in rows -%}<tr><td>{{ key.domain }}</td><td>{{ 'Ed25519' if key.type == 'ed25519' else 'RSA' }}</td><td>{{ key.selector }}</td><td>{{ key.bits or '' }}</td><td>{{ key.state }}</td>
  <td>{{ copybox('dns-' ~ loop.index, key.selector ~ '._domainkey.' ~ key.domain ~ '. IN TXT ' ~ key.dns) }}</td>
  <td><a class="btn d" href="{{ url_for('show_page', slug='dkim', domain=key.domain, selector=key.selector) }}#dkim-remove">Remove</a></td></tr>{%- endfor -%}
  </table>{%- endif -%}
{%- endmacro -%}
{%- macro info(id, text) -%}
  {#- The (i) of a card or a field: the whole help text in a popup of the browser, without script. -#}
  {%- if text %}<button type="button" class="info" popovertarget="i-{{ id }}" aria-label="{{ _('Explanation') }}" title="{{ _('Explanation') }}">i</button><span popover id="i-{{ id }}" class="pop">{{ text }}</span>{% endif -%}
{%- endmacro -%}
{%- macro pickone(id, argname, items, chosen) -%}
  {#- UI 2026: on/off (yes/no) as a pill switch, two to four short choices as pills, more or longer ones stay a list. Without a
  current value the first choice counts, as in a list. -#}
  {%- set values = items|map(attribute=0)|list -%}{%- set chosen = chosen if chosen in values else values[0] -%}
  {%- if values|sort in (['off', 'on'], ['no', 'yes']) -%}{%- set yes = 'on' if 'on' in values else 'yes' -%}
    <div><label class="sw"><input type="checkbox" role="switch" id="{{ id }}" name="{{ argname }}" value="{{ yes }}"{% if chosen == yes %} checked{% endif %}><i></i></label>
    <input type="hidden" name="{{ argname }}" value="{{ 'off' if yes == 'on' else 'no' }}"></div>
  {%- elif 2 <= items|length <= 4 and items|map(attribute=1)|map('length')|max <= 18 -%}
    <div class="segpick" role="radiogroup" aria-labelledby="{{ id }}-l">{% for v, text in items %}<label><input type="radio"{% if loop.first %} id="{{ id }}"{% endif %} name="{{ argname }}" value="{{ v }}"{% if v == chosen %} checked{% endif %}><span>{{ text }}</span></label>{% endfor %}</div>
  {%- else -%}
    <select id="{{ id }}" name="{{ argname }}">{% for v, text in items %}<option value="{{ v }}"{% if v == chosen %} selected{% endif %}>{{ text }}</option>{% endfor %}</select>
  {%- endif -%}
{%- endmacro -%}
{%- macro clearbox(id, arg, wl) -%}
  {#- M5: the console empties a list with "-"; here a tick box Clear does it (call_command sends - for it). -#}
  {%- if wl['clear'] %}<label class="clr"><input type="checkbox" name="{{ arg.name }}__clear" value="on"> {{ _('Clear') }}</label>{% endif -%}
{%- endmacro -%}
{%- macro field(name, arg) -%}
  {%- set id = name ~ '-' ~ arg.name -%}{%- set value = current(name, arg) -%}{%- set fh = help_text(name, arg.name) -%}{%- set wl = web_label(arg.label, arg.kind) -%}
  {%- if arg.hint %}<div class="row {{ arg.group }}box"><p class="warnbox" role="alert">{{ arg.hint }}</p></div>{% endif -%}
  <div class="row{% if arg.group %} {{ arg.group }}box{% endif %}">
  {%- if arg.ack -%}
    <span class="lb"><label for="{{ id }}">{{ wl.label|t }}</label>{{ info(id, fh) }}</span>
    <div><input type="checkbox" id="{{ id }}" name="{{ arg.name }}" value="yes"></div>
  {%- elif 'I accept the transfer outside the EU' in arg.label and eu_locked() -%}
    <span class="lb"><label for="{{ id }}">{{ wl.label|t }}</label>{{ info(id, fh) }}</span>
    <input type="text" id="{{ id }}" name="{{ arg.name }}" disabled aria-describedby="{{ id }}-why"><small class="now" id="{{ id }}-why">{{ _('Locked: with the EU link of the setup only services in the EU (Security, Setup variant).') }}</small>
  {%- elif arg.label.endswith('on or off') -%}
    <span class="lb"><label for="{{ id }}">{{ _('Active') if arg.label in ('on or off', 'On or off') else arg.label|replace(': on or off', '')|t }}</label>{{ info(id, fh) }}</span>
    {#- The hidden field comes second: a ticked switch sends on first, an unticked one only off. -#}
    <div><label class="sw"><input type="checkbox" role="switch" id="{{ id }}" name="{{ arg.name }}" value="on"
    {%- if value is sameas true or value == 'on' %} checked{% endif %}><i></i></label>
    <input type="hidden" name="{{ arg.name }}" value="off"></div>
  {%- elif arg.secret -%}
    <span class="lb"><label for="{{ id }}">{{ wl.label|t }}</label>{{ info(id, fh) }}</span>
    <input type="password" id="{{ id }}" name="{{ arg.name }}" autocomplete="new-password">
  {%- elif arg.kind == 'confirm' -%}
    <label for="{{ id }}">{{ _('Confirm') }}</label>
    <div><label><input type="checkbox" id="{{ id }}" name="{{ arg.name }}" value="yes"{% if arg.required %} required{% endif %}> {{ wl.label|t }}</label></div>
  {%- elif wl.yes and not arg.choices -%}
    {#- M5: the console asks to type yes; here it is a tick box that sends yes. -#}
    <span class="lb"><label for="{{ id }}">{{ wl.label|t }}</label>{{ info(id, fh) }}</span>
    <div><input type="checkbox" id="{{ id }}" name="{{ arg.name }}" value="yes"{% if value == 'yes' %} checked{% endif %}></div>
{%- elif arg.choices -%}
    <span class="lb"><label for="{{ id }}" id="{{ id }}-l">{{ wl.label|t }}</label>{{ info(id, fh) }}</span>
    {%- set chosen = value if value != '' else (arg.preselect or '') %}{% set items = [] %}{% for item in arg.choices %}{% set ignored = items.append((item.value, item.text|t)) %}{% endfor %}
    {{- pickone(id, arg.name, items, chosen) }}
    {%- set now = shown_now(name, arg) %}{% if now is not none %}<small class="now">{{ _('Current:') }} {% for item in arg.choices if item.value == now %}{{ item.text|t }}{% endfor %}</small>{% endif %}
  {%- elif arg.name == 'tenant' and pick.tenants -%}
    <span class="lb"><label for="{{ id }}">{{ _('Tenant') }}</label>{{ info(id, fh) }}</span>
    <select id="{{ id }}" name="tenant">{% if not arg.required %}<option value="">{{ _('None') }}</option>{% endif %}{% for item in pick.tenants %}<option{% if item == value %} selected{% endif %}>{{ item }}</option>{% endfor %}</select>
  {%- elif arg.name == 'domain' and name in pick_domain_commands and pick.domains -%}
    <span class="lb"><label for="{{ id }}">{{ _('Domain') }}</label>{{ info(id, fh) }}</span>
    <select id="{{ id }}" name="domain">{% if not arg.required %}<option value="">{{ _('None') }}</option>{% endif %}{% for item in pick.domains %}<option{% if item == value %} selected{% endif %}>{{ item }}</option>{% endfor %}</select>
  {%- elif arg.name == 'groups' and name == 'user-set' and pick.groups -%}
    <span class="lb"><label for="{{ id }}">{{ _('Groups') }}</label>{{ info(id, fh) }}</span>
    <select id="{{ id }}" name="groups" multiple size="{{ [pick.groups|length, 8]|min }}">{% for item in pick.groups %}<option{% if item in value.split(',') %} selected{% endif %}>{{ item }}</option>{% endfor %}</select>
  {%- elif arg.label in choices -%}
    <span class="lb"><label for="{{ id }}" id="{{ id }}-l">{{ choices[arg.label][0]|t }}</label>{{ info(id, fh) }}</span>
    {%- set items = [] %}{% for option in choices[arg.label][1] %}{% set ignored = items.append((option, option_text.get(option, option)|t)) %}{% endfor %}
    {{- pickone(id, arg.name, items, value) }}
  {%- elif arg.multiline -%}
    <span class="lb"><label for="{{ id }}">{{ wl.label|t }}</label>{{ info(id, fh) }}</span>
    {% if wl['clear'] %}<div>{% endif %}<textarea id="{{ id }}" name="{{ arg.name }}" rows="6"{% if wl.placeholder %} placeholder="{{ wl.placeholder|t }}"{% endif %}{% if arg.required %} required{% endif %}>{{ value }}</textarea>{% if wl['clear'] %}{{ clearbox(id, arg, wl) }}</div>{% endif %}
  {%- else -%}
    <span class="lb"><label for="{{ id }}">{{ wl.label|t }}</label>{{ info(id, fh) }}</span>
    {% if wl['clear'] %}<div>{% endif %}<input type="text" id="{{ id }}" name="{{ arg.name }}" value="{{ value }}"{% if arg.placeholder or wl.placeholder %} placeholder="{{ arg.placeholder or wl.placeholder|t }}"{% endif %}{% if arg.required %} required{% endif %}>{% if wl['clear'] %}{{ clearbox(id, arg, wl) }}</div>{% endif %}
  {%- endif -%}
  </div>
{%- endmacro -%}
<script src="{{ url_for('copy_js') }}"></script><aside>""" + BRAND + """
{% if not portal_mode %}<form class="search" method="post" action="{{ url_for('search') }}" role="search"><input type="hidden" name="csrf" value="{{ csrf }}">
<label class="sr" for="search-q">{{ _('Search') }}</label><input type="search" id="search-q" name="q" placeholder="{{ _('Search') }} ( / )" autocomplete="off"
role="combobox" aria-autocomplete="list" aria-expanded="false" aria-controls="search-list" data-index="{{ suggest_url(commands) }}"
data-texts='{{ {'groups': {'mail': _('Mail search'), 'page': _('Pages'), 'action': _('Actions'), 'setting': _('Settings')}, 'none': _('No suggestion; Enter searches everywhere.'),
'from': _('Search mails from {x}'), 'domain': _('Search mails of the domain {x}'), 'ip': _('Search mails from the IP {x}'), 'qid': _('Search the mail with the queue ID {x}'),
'mail_hint': _('Opens the mail log with this filter.')}|tojson }}'><ul id="search-list" class="suggest" role="listbox" aria-label="{{ _('Suggestions') }}" hidden></ul></form>{% endif %}
{% if session.brand %}<div class="tenantbrand"{% if session.brand.color %} style="border-left:4px solid {{ session.brand.color }};padding-left:8px"{% endif %}>
{% if session.brand.logo %}<img src="{{ url_for('brand_logo') }}" alt="" style="max-width:160px;max-height:60px"><br>{% endif %}<b>{{ session.brand.name }}</b></div>{% endif %}
<details class="navmenu" open><summary>{{ _('Menu') }}: {{ page.title|t }}</summary>
{% for group, pages in nav %}<h4>{{ group|t }}</h4>{% for p in pages %}<a class="nav{% if p.slug == page.slug %} on{% endif %}"
{%- if p.slug == page.slug %} aria-current="page"{% endif %} href="{{ url_for('show_page', slug=p.slug) }}">{{ p.title|t }}</a>{% endfor %}{% endfor %}
{% if values.get('rspamd_sso') == 'read-only' and session.get('role', 'super') == 'super' %}<h4>Tools</h4><a class="nav" href="{{ url_for('rspamd_open') }}" target="_blank" rel="noopener noreferrer">rspamd web interface <span aria-hidden="true">&#8599;</span><span class="sr">(opens in a new window)</span></a><p class="h">{{ _('read only, until') }} {{ values.get('rspamd_sso_until') }}</p>{% endif %}
</details>
</aside><main{% if page.slug in ('log', 'quar', 'held') %} class="wide"{% endif %}><div class="viewbar">{% if not portal_mode %}{{ viewform(none) }}{% endif %}{% set me = account_view() %}<details class="usermenu"><summary><span class="sr">{{ _('Logged in as') }} </span><b>{{ me.login }}</b> <span class="role">{{ me.role }}</span></summary><div class="menu"><a class="account" href="{{ url_for('show_page', slug='held' if portal_mode else 'account') }}{{ '#account-show' if portal_mode else '' }}">{{ _('My account') }}</a><a class="feature" target="_blank" rel="noopener noreferrer" href=\"""" + FEATURE_URL + """\">{{ _('Request or improve a feature') }}</a><form method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><button>{{ _('Log out') }}</button></form></div></details></div>
{% if not portal_mode %}""" + THREAT_BANNER + """{% endif %}
{% if session.no_2fa and page.slug in ('dash', 'held') %}<div class="pending" role="status"><span>{{ _('Your login has no 2FA: a stolen password alone is enough to log in. Set it up under My account.') }}</span>
<span class="pending-buttons"><a href="{{ url_for('show_page', slug='held' if portal_mode else 'account') }}#totp-setup">{{ _('Set up 2FA') }}</a></span></div>{% endif %}{% if values.get('firewall_pending_seconds') is not none and 'firewall-confirm' in commands %}<div class="pending" role="alert">
<span><b>Firewall change not confirmed.</b> Check that you still have access. It is taken back in <span data-countdown="{{ values.firewall_pending_seconds }}">{{ values.firewall_pending_seconds // 60 }} min</span>.</span>
<span class="pending-buttons">{{ post('firewall-confirm', 'Keep the change', {}, 'p') }}{% if 'firewall-revert' in commands %}{{ post('firewall-revert', 'Discard', {}, 'd') }}{% endif %}</span></div>{% endif %}
{% if values.get('cluster_managed_by') %}<div class="card"><p>{{ 'Managed by'|t }} <b>{{ values.cluster_managed_by }}</b>: {{ 'this node is a client in master/client mode, settings are changed on the master.'|t }}</p></div>{% endif %}
<h1>{{ page.title|t }}</h1><p class="sub">{{ page.sub|t }}</p>
{% if error %}<div class="card"><p class="err" role="alert">{{ error }}</p></div>{% endif %}
{#- Guided wizards: the switch to the manual cards and back, then the wizard of the page. Only here, under the title. -#}
{% if wizard_name %}<style>#wizard{scroll-margin-top:104px}.wizmode{margin:0 0 12px}.wizsteps{display:flex;flex-wrap:wrap;gap:4px 14px;list-style:none;padding:0;margin:0 0 10px;color:var(--muted);font-size:.9em}
.wizsteps li.cur{color:var(--ink);font-weight:600}.wizsteps li::before{content:counter(list-item) ". "}.wizard textarea{min-height:7em}
.wizard pre.wizpre{white-space:pre-wrap;margin:0}.wizard iframe{width:100%;min-height:10em;border:1px solid var(--border);background:#fff}
.wizard td.wiztext{white-space:pre-wrap;word-break:break-word;max-width:28rem}</style>
<form method="post" action="{{ url_for('wizard_mode') }}" class="wizmode"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="page" value="{{ page.slug }}">
<span class="seg" role="group" aria-label="{{ _('Wizard or manual view') }}"><button name="mode" value="wizard"{% if wizard %} class="cur" aria-pressed="true"{% endif %}>{{ _('Wizard') }}</button><button name="mode" value="manual"{% if not wizard %} class="cur" aria-pressed="true"{% endif %}>{{ _('Manual') }}</button></span></form>{% endif %}
{% if wizard %}{% set w = wizard %}<div class="card wizard" id="wizard"><h2>{{ w.title|t }}{{ info('wizard-' ~ w.name, w.help) }}</h2>
<ol class="wizsteps" aria-label="{{ _('Step') }}">{% for s in w.steps %}<li{% if s.id == w.step.id and not w.result %} class="cur" aria-current="step"{% endif %}>{{ s.title|t }}</li>{% endfor %}</ol>
{% if w.result is not none %}<p class="h">{{ _('Done.') }}</p>{% if w.name == 'hardening' %}<p>{{ _('Changed:') }} {{ (w.result.get('changed') or [])|map('t')|join(', ') or _('none') }}</p>
{% if w.result.get('ssh_note') %}<p class="warnbox" role="alert">{{ w.result.ssh_note|t }}</p>{% endif %}
<p>{{ _('Check of the chosen standards:') }}</p><ul>{% for sid, item in (w.result.get('check') or {}).items() if sid in w.result.get('selected', []) %}<li><b>{{ item.title }}</b>: {{ {'fulfilled': _('fulfilled'), 'over': _('over-fulfilled'), 'needs': _('needs DNS records or a mailbox'), 'not': _('not fulfilled')}.get(item.status, item.status) }}</li>{% endfor %}</ul>
<p class="h">{{ _('Back to the settings before: the card "Security standards: back to the settings before" in the manual view.') }}</p>
<p><a href="{{ url_for('show_page', slug='sec') }}#hardening-report">{{ _('The hardening report') }}</a></p>{% elif w.name == 'dkim' %}<p>{{ _('Add these records to the DNS of the domain:') }}</p>{% for key in w.result.get('keys', []) %}<pre>{{ key.dns_record }}</pre>{% endfor %}{% else %}{{ show(w.result) }}{% endif %}
<div class="btns"><form method="post" action="{{ url_for('wizard_step', name=w.name) }}"><input type="hidden" name="csrf" value="{{ csrf }}"><button name="go" value="restart">{{ _('Start again') }}</button></form>
<form method="post" action="{{ url_for('wizard_mode') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="page" value="{{ page.slug }}"><button name="mode" value="manual">{{ _('Open the manual view') }}</button></form></div>
{% else %}<form method="post" action="{{ url_for('wizard_step', name=w.name) }}"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="step" value="{{ w.step.id }}">
<h3>{{ _('Step') }} {{ w.steps.index(w.step) + 1 }} {{ _('of') }} {{ w.steps|length }}: {{ w.step.title|t }}{{ info('wizard-step-' ~ w.step.id, w.step_help) }}</h3>
{% if w.problem %}<p class="err" role="alert">{{ w.problem|t }}</p>{% endif %}
{% if w.name == 'disclaimer' and w.step.id == 'scope' %}<p class="h">{{ _('A disclaimer is added to outgoing mail only, at its end.') }}</p>{% endif %}
{% if w.name == 'dkim' and w.step.id == 'key' %}<p class="h">{{ _('Keys this domain has now:') }} {{ w.now.get('keys') or _('none') }}</p>{% endif %}
{% for f in w.fields if f.kind != 'tick' %}{% set id = 'wz-' ~ f.name %}<div class="row"><span class="lb"><label for="{{ id }}" id="{{ id }}-l">{{ f.label|t }}</label>{{ info(id, f.help) }}</span>
{%- if f.kind == 'pick' %}{{ pickone(id, f.name, f.options, f.value) }}
{%- elif f.kind == 'select' %}<select id="{{ id }}" name="{{ f.name }}">{% for v, text in f.options %}<option value="{{ v }}"{% if v == f.value %} selected{% endif %}>{{ text }}</option>{% endfor %}</select>
{%- elif f.kind == 'multi' %}<select id="{{ id }}" name="{{ f.name }}" multiple size="{{ [[f.options|length, 2]|max, 8]|min }}">{% for v, text in f.options %}<option value="{{ v }}"{% if v in f.value.split(',') %} selected{% endif %}>{{ text }}</option>{% endfor %}</select>
{%- elif f.kind == 'checks' %}<div class="wizchecks" id="{{ id }}" role="group" aria-labelledby="{{ id }}-l">{% for g in f.groups %}<fieldset><legend>{{ g.title }}</legend>
{% for o in g.opts %}<label class="wizcheck"><input type="checkbox" name="{{ f.name }}" value="{{ o.value }}"{% if o.value in f.value.split(',') %} checked{% endif %}> <b>{{ o.text }}</b> <span class="h">{{ o.version }}{% if o.status %} · {{ _('Last check') }}: {{ {'fulfilled': _('fulfilled'), 'over': _('over-fulfilled'), 'needs': _('needs DNS records or a mailbox'), 'not': _('not fulfilled')}.get(o.status, o.status) }}{% endif %}</span><br><span class="h">{{ o.summary }}</span></label>{% endfor %}</fieldset>{% endfor %}</div>
{%- elif f.kind == 'textarea' %}<textarea id="{{ id }}" name="{{ f.name }}" rows="6">{{ f.value }}</textarea>
{%- else %}<input type="text" id="{{ id }}" name="{{ f.name }}" value="{{ f.value }}"{% if not f.optional %} required{% endif %}>{% endif %}
{%- if f.state is not none %} <span class="h">{{ _('now') }}: {{ _('on') if f.state else _('off') }}</span>{% endif %}{% if f.warn %}<p class="h err">{{ f.warn }}</p>{% endif %}</div>{% endfor %}
{% if w.name == 'hardening' %}{% set x = w.extra %}
{%- if w.step.id == 'standards' %}<p class="h">{{ _('Choosing none removes no hardening; a standard only ever makes a setting stricter.') }}</p>
{%- elif w.step.id == 'port25' %}<p class="h">{{ _('Sessions on port 25 without TLS in the last 7 days:') }} {{ x.port25_plain }} / {{ x.port25_sessions }}</p>
{%- elif w.step.id == 'os' %}<h4>{{ _('Hints, never switched here') }}</h4><ul>{% for h in x.hints if h.id not in ('console-2fa', 'admin-access') %}<li>{{ h.text|t }}{% if h.on %} ({{ _('on') }}){% endif %}</li>{% endfor %}</ul>
<h4>{{ _('Services that are not part of eFa-next or the operating system') }}</h4><p class="h">{{ _('eFa-next runs alone on its server: a foreign service is only named here, never stopped or removed.') }}</p>
{% if x.foreign %}<ul>{% for item in x.foreign %}<li class="mono">{{ item }}</li>{% endfor %}</ul>{% else %}<p class="h">{{ _('none found') }}</p>{% endif %}
{%- elif w.step.id == 'efa' %}<h4>{{ _('Hints, never switched here') }}</h4><ul>{% for h in x.hints if h.id in ('console-2fa', 'admin-access') %}<li>{{ h.text|t }}{% if h.on %} ({{ _('on') }}){% endif %}</li>{% endfor %}</ul>
<p class="h"><a href="{{ url_for('show_page', slug='sec') }}">{{ _('Admin access and firewall: Security page (a wrong address locks you out).') }}</a></p>{% endif %}
{%- if w.step.id in ('preview', 'summary') %}{% if x.preview %}<table class="data"><tr><th>{{ _('Setting') }}</th><th>{{ _('Now') }}</th><th>{{ _('Then') }}</th><th>{{ _('Because') }}</th></tr>
{% for r in x.preview.changes %}<tr><th>{{ r.setting|t }}</th><td>{{ r.now|t }}</td><td><b>{{ r.then|t }}</b></td><td>{{ r.because|t }}</td></tr>{% endfor %}</table>
{% if not x.preview.changes %}<p class="h">{{ _('Nothing changes.') }}</p>{% endif %}
{% if x.preview.warnings %}<h4>{{ _('Warnings') }}</h4>{% for text in x.preview.warnings %}<p class="warnbox">{{ text|t }}</p>{% endfor %}{% endif %}
{% else %}<p class="err">{{ _('Open the preview first.') }}</p>{% endif %}
{% if w.step.id == 'preview' and x.untouched %}<h4>{{ _('What this wizard does not change') }}</h4><ul>{% for setting, now, wanted, where in x.untouched %}<li><b>{{ setting }}</b>: {{ now }} &rarr; {{ wanted }}. {{ where|t }}</li>{% endfor %}</ul>{% endif %}{% endif %}{% endif %}
{#- A tick box confirms what stands above it (the warnings), so it comes after the blocks of the step. -#}
{% for f in w.fields if f.kind == 'tick' %}{% set id = 'wz-' ~ f.name %}<div class="row"><label><input type="checkbox" id="{{ id }}" name="{{ f.name }}" value="yes"{% if f.value == 'yes' %} checked{% endif %} required> {{ f.label|t }}</label>{{ info(id, f.help) }}</div>{% endfor %}
{% if w.last and w.reauth %}{% if reauth_left() >= 60 %}<p class="h reauth-ok">{{ _('Your password still counts for {} minutes: no new entry needed.').format((reauth_left() // 60)|int) }}</p>
{% else %}<div class="row"><label for="wz-reauth">{{ _('Your password, to confirm') }}</label><input type="password" id="wz-reauth" name="reauth" autocomplete="current-password"></div>
<div class="row"><label for="wz-reauth-code">{{ _('2FA code, if you set one up') }}</label><input type="text" id="wz-reauth-code" name="reauth_code" inputmode="numeric" autocomplete="one-time-code" maxlength="20"></div>{% endif %}{% endif %}
{% if w.step.preview is sameas true %}<div class="row"><span class="lb">{{ _('Text version') }}</span><pre class="wizpre">{{ w.draft.text }}</pre></div>
{% if w.draft.format == 'html' %}<div class="row"><span class="lb">{{ _('HTML version') }}</span><iframe sandbox="" srcdoc="{{ w.draft.html }}" title="{{ _('HTML version') }}"></iframe></div>{% endif %}
<p class="h">{{ _('The preview shows no pictures and runs no scripts.') }}</p>{% endif %}
{% if w.test %}{% set t = w.tested %}{% if t and t.state == 'running' %}<script src="{{ url_for('wizard_js') }}" defer></script><p class="h" data-poll="{{ url_for('wizard_test', name=w.name) }}" role="status">{{ _('The test runs ...') }} <a href="{{ url_for('show_page', slug=page.slug, w=w.step.id) }}#wizard">{{ _('Load the result') }}</a></p>
{% elif t %}<table class="kv" role="status"><tr><th>{{ _('Connected') }}</th><td>{{ show(t.output.get('connect', false)) }}</td></tr><tr><th>{{ _('STARTTLS offered') }}</th><td>{{ show(t.output.get('starttls', false)) }}</td></tr>
<tr><th>{{ _('Certificate valid') }}</th><td>{{ show(t.output.get('verified', false)) }}</td></tr>{% if t.output.get('error') %}<tr><th></th><td class="err">{{ t.output.error }}</td></tr>{% endif %}</table>{% endif %}{% endif %}
{% if w.last and not w.summary %}<table class="data"><tr><th></th><th>{{ _('Now') }}</th><th>{{ _('New') }}</th></tr>{% for r in w.rows %}<tr><th>{{ r.label|t }}</th><td class="wiztext">{{ r.now|t if r.now else _('not set') }}</td><td class="wiztext">{% if r.changed %}<b>{{ r.after|t }}</b>{% else %}{{ r.after|t }}{% endif %}</td></tr>{% endfor %}</table>
{% if not w.rows|selectattr('changed')|list %}<p class="h">{{ _('Nothing changes.') }}</p>{% endif %}{% endif %}
<div class="btns">{% if w.last %}<button class="p" name="go" value="apply">{{ _('Apply') }}</button>{% else %}<button class="p" name="go" value="next">{{ _('Next') }}</button>{% endif %}
{% if w.test %}<button name="go" value="test">{{ _('Test the connection') }}</button>{% endif %}{% if not w.first %}<button name="go" value="back" formnovalidate>{{ _('Back') }}</button><button name="go" value="restart" formnovalidate>{{ _('Start again') }}</button>{% endif %}</div></form>{% endif %}</div>{% endif %}
{% if page.slug == 'sec' and hardening_link %}<p class="h"><a href="{{ url_for('show_page', slug='standards') }}#wizard">{{ _('Hardening wizard') }}</a></p>{% endif %}
{% if not wizard %}
{% if result is not none and result_name in short_results %}<div class="card done"><p>{{ short_results[result_name] }}</p></div>
{% elif result is not none and result_name == 'maillog-search' %}<div class="card" id="log-result" data-q="{{ result.query or '' }}"><div class="live-head"><h2>{{ _('Mail log') }}</h2>
<span>{{ result.mails|length }} {{ _('mails') }}</span></div>{% if result.filters %}<div class="chips filters" aria-label="{{ _('Filters') }}">{% for item in result.filters %}<span class="chip">{{ item }}</span>{% endfor %}</div>{% endif %}
{% if result.mails %}<div class="tablewrap"><table class="log"><thead><tr><th>{{ _('Time') }}</th><th>{{ _('Sender') }}</th><th>{{ _('Recipient') }}</th><th>{{ _('Subject') }}</th><th>{{ _('Result') }}</th>
<th>{{ _('Checks') }}</th><th>{{ _('Score') }}</th><th>{{ _('IP address') }}</th><th class="opt">{{ _('Queue ID') }}</th></tr></thead><tbody>
{% for mail in result.mails %}<tr tabindex="0" data-mail='{{ mail|tojson }}'><td class="nw" data-label="{{ _('Time') }}"><time title="{{ mail.ts }}">{{ mail.ts|ago }}</time></td>
<td class="cut" data-label="{{ _('Sender') }}">{{ chip(mail.sender, 'address' if '@' in (mail.sender or '') else 'domain', mail.qid, mail.rcpt, mail.ip) }}</td>
<td class="cut" data-label="{{ _('Recipient') }}" title="{{ mail.rcpt or '' }}">{{ mail.rcpt or '' }}</td><td class="cut subj" data-label="{{ _('Subject') }}" title="{{ mail.subject or '' }}">{{ mail.subject or '' }}</td>
<td class="nw" data-label="{{ _('Result') }}">{{ st(mail.action) }}</td><td class="nw" data-label="{{ _('Checks') }}">{{ st(mail.spf, 'SPF') }}{{ st(mail.dkim, 'DKIM') }}{{ st(mail.dmarc, 'DMARC') }}</td>
<td class="nw" data-label="{{ _('Score') }}">{{ '%.1f'|format(mail.score) if mail.score is number else '' }}</td><td class="nw" data-label="{{ _('IP address') }}">{{ chip(mail.ip, 'ip', mail.qid, mail.rcpt) }}</td>
<td class="nw mono opt" data-label="{{ _('Queue ID') }}">{{ mail.qid or '' }}</td></tr>{% endfor %}</tbody></table></div>
{% else %}<p class="empty">{{ _('No mail matches. Fewer filters or a shorter text find more.') }}</p>{% endif %}</div>
{% elif result is not none and result_name == 'sender-action' %}<div class="card done" role="status"><p>{{ result.entry }}: {{ _('added to') if result.action == 'add' else _('taken out again') }} {{ result.target_text|rt }}</p>
{% if result.action == 'add' %}<div class="btns">{{ post('sender-action', _('Undo'), {'value': result.entry, 'list': result.list, 'action': 'remove', 'recipients': result.recipients, 'qid': result.qid}) }}</div>{% endif %}</div>
{% elif result is not none and not result.tests %}<div class="card done"><h2>Result: {{ result_title }}</h2><p class="h">Done.</p>
{% if result.mails is defined and result.mails and result.mails[0].id is defined %}<table class="data"><tr><th>Time</th><th>Sender</th><th>Recipient</th><th>Subject</th><th>Result</th><th></th></tr>
{% for mail in result.mails %}<tr><td>{{ mail.ts }}</td><td>{{ mail.sender }}</td><td>{{ mail.rcpt }}</td><td>{{ mail.subject }}</td><td>{{ mail.action }}</td>
<td><a class="btn" href="{{ url_for('mail_page', mail_id=mail.id) }}">Details</a></td></tr>{% endfor %}</table>
{% elif result.job is defined %}<p>{{ result.count }} mails. {% if result.state == 'done' %}<a class="btn p" href="{{ url_for('export_file', job=result.job) }}">Download ZIP</a>
{% else %}{{ result.note }} <a class="btn" href="{{ url_for('export_file', job=result.job) }}">Download ZIP</a>{% endif %}</p>
{% elif result.text is defined %}{% if result.cut %}<p class="warnbox">Only the first part is shown.
{{ post(result_name, 'Show more', {'id': result.id, 'more': 'yes'}) }}</p>{% endif %}<p class="h">Shown as plain text from {{ result.source }}. Links are not clickable, nothing is loaded.</p>
<pre>{{ result.text }}</pre>{% if result.attachments %}<table class="data"><tr><th>Attachment</th><th>Type</th><th>Size</th></tr>{% for item in result.attachments %}<tr><td>{{ item.name }}</td><td>{{ item.type }}</td>
<td>{{ item.size|filesizeformat }}</td></tr>{% endfor %}</table>{% endif %}
{% else %}{{ show(result) }}{% endif %}</div>{% endif %}
{% if board_html %}<div class="card board" id="status-board" data-url="{{ url_for('status_board') }}">{{ board_html|safe }}</div>{% endif %}
{% if flow_picture %}<div class="card flowcard">{{ flow_picture|safe }}</div>{% endif %}
{% if tiles %}{% set load_link = 'load-set' in commands %}{% if load_link %}<a class="cardlink" href="{{ url_for('show_page', slug='maint') }}#load-set" aria-label="Load: limits and alerts">{% endif %}
<div class="card" id="load-card" data-url="{{ url_for('load_card') }}">{{ load_html|safe }}</div>{% if load_link %}</a>{% endif %}<div class="tiles">
{% for t in tiles %}{% set inner %}<b>{{ t.label|t }}</b><div class="v">{% if t.dot is not none %}<span class="dot {{ t.dot }}"></span>{% endif %}{{ t.value }}</div>
{% if t.note %}<div class="note">{{ t.note }}</div>{% endif %}{% endset %}
{% if t.slug and t.anchor in commands %}<a class="tile" href="{{ url_for('show_page', slug=t.slug) }}#{{ t.anchor }}">{{ inner }}</a>
{% elif t.detail %}<details class="tile"><summary>{{ inner }}</summary><p>{{ t.detail }}</p></details>{% else %}<div class="tile">{{ inner }}</div>{% endif %}{% endfor %}</div>
{% if chart %}<div class="card"><h2>{{ _('Last hour per minute') }}</h2><p class="h">{{ chart.summary }}</p>{{ chart.svg|safe }}
<p class="legend"><span class="key m"></span>Mails <span class="key s"></span>Spam <span class="key v"></span>Viruses<span class="span">{{ chart.first }} to {{ chart.last }}</span></p></div>{% endif %}
{% if cve_banner %}<div class="card" role="alert">{% for text in cve_banner %}<p class="err">{{ text }}</p>{% endfor %}</div>{% endif %}{% if attention %}<div class="card"><h2>{{ _('Needs attention') }}</h2><table class="att">{% for text, slug, anchor, query in attention %}<tr><td><span class="dot w"></span>{{ text }}</td>
<td>{% if slug and anchor in commands %}<a href="{{ notice_href(slug, anchor, query, expert, commands[anchor]) }}">{{ pages_by_slug[slug].title|t }} &rarr; {{ (commands[anchor].title|t).split(':')[0] }}</a>{% endif %}</td></tr>{% endfor %}</table></div>{% endif %}{% endif %}
{% for key in page.show or [] %}{% if key in values %}{% set info = current_info[key] %}<div class="card"><h2>{{ info[0] }}</h2>
{% if info|length == 1 %}{{ show(values[key]) }}
{% elif not values[key] %}<span class="pill">{{ _('none') }}</span>
{% else %}<table>{% for entry in values[key] %}<tr><td>{{ entry }}</td>{% if values[key] is mapping %}<td>{{ show(values[key][entry]) }}</td>{% endif %}
<td>{% if info[1] in commands %}{{ post(info[1], _('Remove'), dict(info[3], action='remove', **{info[2]: entry}), 'd') }}{% endif %}</td></tr>{% endfor %}</table>{% endif %}</div>{% endif %}{% endfor %}
{% macro card(name) %}{% set cmd = commands[name] %}
{#- subject-get only fills the form of subject-set. The history is part of the record list. -#}
{% if name not in hidden_cards and name not in merged %}<div class="card" id="{{ name }}">
{%- set status = status_of.get(name) if status_of.get(name) in loaded else None %}
{#- One title per card (that of its status, else that of the command, without its tail such as ": switch"), its (i) and the first sentence of its help. -#}
{%- set help = help_text(name) %}{% set title = short_title(commands[status].title if status else cmd.title)|t %}
{%- if status %}{% set sok, sout = loaded[status] %}<h2>{{ title }}{{ info(name, help) }}{% if sok and badge(sout) is not none %}{{ toggle(name, cmd, badge(sout)) }}{% endif %}</h2>
  {% if help %}<p class="h">{{ first_sentence(help) }}</p>{% endif %}
  {% if sok %}{% if status == 'blocklist-show' %}{{ blocklist_table(sout) }}{% elif expert %}{{ show(without_badge(sout)) }}{% else %}{% for text in warnings_of(loaded[status]) %}<p class="warnbox" role="alert">{{ text|rt }}</p>{% endfor %}{% endif %}{% else %}<p class="err">{{ sout.error }}</p>{% endif %}
{%- else %}<h2>{{ title }}{{ info(name, help) }}</h2>{% if help %}<p class="h">{{ first_sentence(help) }}</p>{% endif %}{% endif %}
{% if not help and page.notes and name in page.notes %}{% if page.notes[name]|length <= note_short %}<p class="h">{{ page.notes[name]|t }}</p>
{% else %}<details class="help"><summary>{{ _('Help') }}</summary><p>{{ page.notes[name]|t }}</p></details>{% endif %}{% endif %}
{% if name == 'api-status' and page.slug == 'export' %}{% set aok, aout = loaded[name] %}<p class="h">Prometheus reads <code>{{ request.host_url }}metrics</code> with the header
Authorization: Bearer &lt;token&gt;. The token belongs to a user who may read the settings of the whole system.</p>
<p>REST API: <span class="badge{{ ' on' if aok and aout.api }}">{{ 'On' if aok and aout.api else 'Off' }}</span> Turn it on and make the token on the page Users.</p>
{% else %}
{% if name == 'maillog-search' %}{{ mailui() }}<button type="button" class="p" id="live-open">{{ _('Live log') }}</button>
{%- set lt = {'columns': {'ts': _('Time'), 'sender': _('Sender'), 'rcpt': _('Recipient'), 'subject': _('Subject'), 'action': _('Result'), 'auth': _('Checks'), 'score': _('Score'),
              'ip': _('IP address'), 'qid': _('Queue ID')}, 'now': _('just now'), 'failed': _('Live log not available, log in again if needed.'), 'pause': _('Pause'),
              'resume': _('Resume'), 'none_match': _('No mail matches the filters.'), 'none_yet': _('No mail yet.')} %}
<dialog id="live-log" data-url="{{ url_for('maillog_live') }}" data-texts='{{ lt|tojson }}' aria-labelledby="live-title"><div class="live-head"><h2 id="live-title">{{ _('Live log') }}</h2><span id="live-count" aria-live="polite"></span>
<button type="button" id="live-pause" aria-pressed="false">{{ _('Pause') }}</button><button type="button" id="live-reset">{{ _('Reset filters') }}</button><button type="button" id="live-close">{{ _('Close') }}</button></div>
<div class="live-filters"><input type="text" id="live-domain" placeholder="{{ _('Domain') }}" aria-label="{{ _('Domain') }}"><input type="text" id="live-email" placeholder="{{ _('Email address') }}" aria-label="{{ _('Email address') }}">
<select id="live-action" aria-label="{{ _('Result') }}"><option value="">{{ _('Result') }}: {{ _('all') }}</option>{% for option in ('no action', 'add header', 'rewrite subject', 'greylist', 'soft reject', 'reject', 'virus') %}<option>{{ option }}</option>{% endfor %}</select>
{% for check in ('spf', 'dkim', 'dmarc') %}<select id="live-{{ check }}" aria-label="{{ check|upper }}"><option value="">{{ check|upper }}: {{ _('all') }}</option>{% for option in ('pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror') %}<option>{{ option }}</option>{% endfor %}</select>{% endfor %}
<input type="text" id="live-search" placeholder="{{ _('Search') }}" aria-label="{{ _('Search') }}"></div>
<div class="live-table"><table class="log"><thead><tr><th>{{ _('Time') }}</th><th>{{ _('Sender') }}</th><th>{{ _('Recipient') }}</th><th class="subj">{{ _('Subject') }}</th><th>{{ _('Result') }}</th><th>{{ _('Checks') }}</th><th>{{ _('Score') }}</th><th>{{ _('IP address') }}</th><th class="opt">{{ _('Queue ID') }}</th></tr></thead><tbody id="live-rows"></tbody></table></div>
</dialog><script src="{{ url_for('live_js') }}"></script>{% endif %}
{% if name == 'dkim-check' %}{% set ok, output = loaded[name] %}{% if not ok %}<p class="err">{{ output.error }}</p>
  {% elif output.warnings or output.notes %}{{ show(output.warnings + output.notes) }}{% else %}<p class="h">No problems found.</p>{% endif %}
{% elif name == 'arc-show' %}{% set ok, output = loaded[name] %}{% if not ok %}<p class="err">{{ output.error }}</p>
  {% elif output.arc_domains %}<table class="data"><tr><th>Domain</th><th>Active</th><th>From</th><th>Key</th><th>Selector</th><th>Size</th><th>DNS record</th><th></th></tr>
  {% for row in output.arc_domains %}<tr><td>{{ row.domain }}</td><td>{{ show(row.active) }}</td><td>{{ row.settings_from }}</td><td>{{ option_text.get(row.key, row.key) }}</td><td>{{ row.selector }}</td><td>{{ row.bits or '' }}</td>
  <td>{% if row.dns %}{{ copybox('arc-' ~ loop.index, row.selector ~ '._domainkey.' ~ row.domain ~ '. IN TXT ' ~ row.dns) }}{% endif %}{% if row.note %}<p class="h">{{ row.note }}</p>{% endif %}</td>
  <td><a class="btn" href="{{ url_for('show_page', slug='dkim', domain=row.domain, key='dkim' if row.has_dkim_rsa else 'own') }}#arc-set">Change</a></td></tr>{% endfor %}</table>
  {% else %}<span class="pill">{{ _('none') }}</span>{% endif %}
{% elif name == 'dmarc-record-show' %}{% set ok, output = loaded[name] %}{% if not ok %}<p class="err">{{ output.error }}</p>
  {% elif output.dmarc_records %}{% for item in output.dmarc_records %}{% set outer = loop.index %}<h3>{{ item.domain }}</h3>
  <p class="h">Name: {{ item.name }}</p>{{ copybox('dmarc-' ~ outer, item.record) }}
  {% for auth in item.authorization %}<p class="h">Reports go to another domain. It must publish this record: {{ auth }} IN TXT "v=DMARC1"</p>{% endfor %}
  {% if item.ruf %}<p class="warnbox">{{ ruf_warning }}</p>{% endif %}
  <table class="data"><tr><th>Saved</th><th>By</th><th>Record</th><th></th></tr>{% for version in item.history %}<tr><td>{{ version.when }}</td><td>{{ version.who }}</td>
  <td>{{ copybox('dmarc-' ~ outer ~ '-' ~ loop.index, version.record) }}</td>
  <td><a class="btn" href="{{ url_for('show_page', slug='dkim', domain=item.domain, ruf_enable='on' if version.fields.ruf else 'off', **version.fields) }}#dmarc-record-set">Into form</a></td></tr>{% endfor %}</table>{% endfor %}
  {% else %}<span class="pill">{{ _('none') }}</span>{% endif %}
{% elif name == 'sender-list' %}{% set ok, output = loaded[name] %}{% if not ok %}<p class="err">{{ output.error }}</p>{% else %}{{ mailui() }}
  {%- set titles = {'allow': _('Allowed senders'), 'block': _('Blocked senders'), 'rules': _('Sender rules')} %}
  <div class="tiles">{% for list in ('allow', 'block', 'rules') %}<div class="tile"><b>{{ titles[list] }}</b>
  <div class="v">{{ output[list]|length }}</div><div class="btns"><input type="text" id="quick-{{ list }}" placeholder="{{ _('Search') }}" aria-label="{{ _('Search') }}: {{ titles[list] }}"><button type="button" class="p" data-manage="{{ list }}">{{ _('Manage') }}</button></div></div>{% endfor %}</div>
  {%- set st = {'titles': titles, 'types': {'address': _('address'), 'domain': _('domain'), 'IP': 'IP', 'pattern': _('pattern')}, 'select': _('Select'), 'allow': _('Allow'), 'block': _('Block'),
                'for_': _('for'), 'to_allow': _('To allow list'), 'to_block': _('To block list'), 'remove': _('Remove'), 'none': _('No entry matches.'),
                'info': _('{count} entries, page {page} of {pages}'), 'remove_q': _('Remove these senders?'), 'add_q': _('Add these senders?')} %}
  <dialog id="sender-box" class="popup" data-url="{{ url_for('senders_data') }}" data-run="{{ url_for('run', name='') }}" data-csrf="{{ csrf }}" data-texts='{{ st|tojson }}' aria-labelledby="sender-title"><div class="live-head"><h2 id="sender-title"></h2><span id="sender-info" aria-live="polite"></span>
  <button type="button" id="sender-export">{{ _('Export CSV') }}</button><label class="btn" for="sender-import">{{ _('Import CSV') }}</label><input type="file" id="sender-import" accept=".csv,text/csv" hidden><button type="button" id="sender-close">{{ _('Close') }}</button></div>
  <div class="live-filters"><input type="text" id="sender-search" placeholder="{{ _('Search') }}" aria-label="{{ _('Search') }}"><button type="button" class="d" id="sender-remove">{{ _('Remove selected') }}</button></div>
  <div class="live-filters" id="sender-add-box"><textarea id="sender-new" rows="2" placeholder="{{ _('Add one or several: sender@example.org example.org 192.0.2.1') }}" aria-label="{{ _('New senders') }}"></textarea><input type="text" id="sender-comment" placeholder="{{ _('Comment, optional') }}" aria-label="{{ _('Comment') }}"><button type="button" class="p" id="sender-add">{{ _('Add') }}</button></div>
  <div class="live-table"><table class="log"><thead><tr><th><span class="sr">{{ _('Select') }}</span></th><th data-sort="entry">{{ _('Entry') }}</th><th data-sort="type">{{ _('Type') }}</th><th data-sort="comment">{{ _('Comment') }}</th><th data-sort="added">{{ _('Added') }}</th><th>{{ _('Scope') }}</th><th><span class="sr">{{ _('Actions') }}</span></th></tr></thead><tbody id="sender-rows"></tbody></table></div>
  <div class="btns"><button type="button" id="sender-prev">{{ _('Previous') }}</button><button type="button" id="sender-next">{{ _('Next') }}</button></div></dialog><script src="{{ url_for('senders_js') }}"></script>{% endif %}
{% elif name == 'relay-networks-list' %}{% set ok, output = loaded[name] %}{% if not ok %}<p class="err">{{ output.error }}</p>{% else %}
  <table class="data"><tr><th>Network</th><th>Type</th><th>Description</th><th>State</th><th></th></tr>{% for row in output.networks %}<tr><td>{{ row.network }}</td><td><span class="pill">{{ row.family }}</span></td><td>{{ row.description }}</td>
  <td><span class="pill{{ ' g' if row.state == 'active' else ' w' }}">{{ row.state }}</span></td><td>{% if not row.locked and row.state != 'to remove' %}{{ post('relay-networks-remove', 'Remove', {'network': row.network}, 'd') }}{% endif %}</td></tr>{% endfor %}</table>
  {% for warning in output.warnings %}<p class="warnbox">{{ warning }}</p>{% endfor %}{% if output.unknown %}<p class="err">mynetworks holds entries eFa-next cannot read: {{ output.unknown|join(' ') }}</p>{% endif %}
  {% if output.pending %}<div class="warnbox"><b>Not active yet.</b> Added: {{ output.added|join(', ') or 'none' }}. Removed: {{ output.removed|join(', ') or 'none' }}.</div>
  <form method="post" action="{{ url_for('run', name='relay-networks-apply') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><div class="row"><label for="relay-confirm">Type yes to confirm</label><input type="text" id="relay-confirm" name="confirm" required></div><div class="btns"><button class="p">Apply</button></div></form>
  <div class="btns">{{ post('relay-networks-discard', 'Discard changes', {}) }}</div>{% endif %}{% endif %}
{% elif name == 'firewall-test' %}{% if result and result.tests %}<table class="data"><tr><th>Test</th><th>Result</th><th>ms</th><th>Hint</th></tr>{% for row in result.tests %}<tr><td>{{ row.test }}</td>
  <td><span class="pill{{ ' g' if row.result == 'ok' else ' w' }}">{{ row.result }}</span></td><td>{{ row.ms }}</td><td>{{ row.hint }}</td></tr>{% endfor %}</table>{% if result.outside_check %}<p class="h">{{ result.outside_check }}</p>{% endif %}{{ copybox('fwtest-text', result.text) }}{% endif %}
  <form method="post" action="{{ url_for('run', name=name) }}"><input type="hidden" name="csrf" value="{{ csrf }}">{% for arg in cmd.args %}{{ field(name, arg) }}{% endfor %}<div class="btns"><button class="p">Run</button></div></form>
{% elif name == 'dkim-export' %}{% set domains = values['export_domains'] or [] %}
  {% if domains %}<table>{% for domain in domains %}<tr><td>{{ domain }}</td>
  <td><a class="btn" href="{{ url_for('export_dkim', domain=domain) }}">Export</a></td></tr>{% endfor %}</table>
  <div class="btns"><a class="btn p" href="{{ url_for('export_dkim') }}">Export all</a></div>
  {% else %}<p class="h">{{ _('No DKIM keys yet: generate them above.') }}</p>{% endif %}
{% elif name in loaded %}{% set ok, output = loaded[name] %}
  {% if not ok %}<p class="err">{{ output.error }}</p>
  {% elif name == 'release-upgrade-status' %}<table class="stack"><tr><th>{{ _('State') }}</th><td><span class="badge">{{ output.state }}</span></td></tr>
  {% if output.request %}<tr><th>{{ _('Step waiting') }}</th><td>{{ output.request }}</td></tr>{% endif %}
  <tr><th>{{ _('Updated') }}</th><td>{{ output.updated or _('not yet') }}</td></tr>
  <tr><th>{{ _('Last message') }}</th><td>{{ (output.log or [_('none')])[-1] }}</td></tr></table>
  {% if output.error %}<p class="err" role="alert">{{ output.error }}</p>{% endif %}{% for text in output.warnings or [] %}<p class="warnbox" role="alert">{{ text }}</p>{% endfor %}
  <details class="help"><summary>{{ _('Details') }}</summary>{{ show(output) }}</details>
  {% elif name == 'uq-list' %}{% if output.mails %}<div class="tablewrap"><table class="log quar"><thead><tr><th>{{ _('Time') }}</th><th>{{ _('Sender') }}</th><th>{{ _('Recipient') }}</th><th>{{ _('Subject') }}</th><th>{{ _('Score') }}</th><th><span class="sr">{{ _('Actions') }}</span></th></tr></thead><tbody>
    {% for row in output.mails %}{% set may_release = not row.malware or session.get('role', 'super') == 'super' %}<tr><td class="nw" data-label="{{ _('Time') }}"><time title="{{ row.ts }}">{{ row.ts|ago }}</time></td>
    <td class="cut" data-label="{{ _('Sender') }}" title="{{ row.sender }}">{{ row.sender }}</td><td class="cut" data-label="{{ _('Recipient') }}" title="{{ row.rcpt }}">{{ row.rcpt }}</td>
    <td class="cut subj" data-label="{{ _('Subject') }}" title="{{ row.subject }}">{{ row.subject }}</td>
    <td class="nw" data-label="{{ _('Score') }}">{{ '%.1f'|format(row.score) if row.score is number else row.score }}{% if row.malware %} <span class="st b">{{ _('virus') }}</span>{% endif %}{% if row.state == 'requested' %} <span class="st w">{{ _('asked') }}</span>{% endif %}</td>
    <td class="acts"><span class="icons">{% if may_release %}{{ iconpost('uq-release', '✓', _('Release'), {'id': row.id}) }}{% endif %}{{ iconpost('uq-show', '☰', _('Headers'), {'id': row.id}) }}</span>
    <details class="rowmenu"><summary title="{{ _('More actions') }}"><span aria-hidden="true">…</span><span class="sr">{{ _('More actions') }}</span></summary><div class="menulist">
    {%- if may_release %}{{ post('uq-release', _('Release'), {'id': row.id}, 'p') }}{% endif %}{{ post('uq-show', _('Headers'), {'id': row.id}) }}{% if 'uq-content' in commands %}{{ post('uq-content', _('Text'), {'id': row.id}) }}{% endif %}
    {%- if row.state != 'requested' %}{{ post('uq-request', _('Ask an admin'), {'id': row.id}) }}{% endif %}{{ post('uq-sender', _('Allow sender'), {'id': row.id, 'list': 'allow'}) }}{{ post('uq-sender', _('Block sender'), {'id': row.id, 'list': 'block'}) }}</div></details></td></tr>{% endfor %}</tbody></table></div>
    {% else %}<p class="empty">{{ _('Nothing held.') }}</p>{% endif %}
  {% elif name == 'threat-status' and output.alerts is sequence %}<p class="h">{{ _('Last check') }}: {{ output.checked|when if output.checked else _('not yet') }}</p>
    {% for item in threat_items(output.alerts, commands, session.get('role', 'super')) %}<p class="{{ 'err' if item.level == 'alert' else 'warnbox' }}">{{ item.name }}: {{ item.line }}{% if item.since %} ({{ _('since') }} {{ item.since }}){% endif %}</p>
    {% else %}<p><span class="dot"></span>{{ _('No attack and no problem found.') }}</p>{% endfor %}
  {% elif name == 'ssh-root-status' %}{% for warning in output.warnings %}<p class="warnbox">{{ warning }}</p>{% endfor %}
    <p>PermitRootLogin: {{ output.ssh_root_login }}</p>{% if output.ssh_admins %}<p>Can take over: {{ output.ssh_admins|join(', ') }}</p>{% endif %}
    {% for user, why in output.ssh_refused.items() %}<p class="h">{{ user }}: {{ why }}</p>{% endfor %}
  {% elif name in ('standards-show', 'standards-check') and output.standards is mapping %}<p class="h">{{ _('Checked') }}: {{ output.checked }}</p>
    <table class="stack"><tr><th>{{ _('Standard') }}</th><th>{{ _('Result') }}</th><th>{{ _('Findings') }}</th></tr>{% for sid, item in output.standards.items() %}
    <tr><td><b>{{ item.title }}</b><br><small>{{ item.version }}{% if not item.verified %} · {{ _('not verified against the current text') }}{% endif %}</small></td>
    <td><span class="pill">{{ {'fulfilled': _('fulfilled'), 'over': _('over-fulfilled'), 'needs': _('needs DNS records or a mailbox'), 'not': _('not fulfilled')}[item.status] }}</span>{% if sid in output.selected %} <small>{{ _('chosen') }}</small>{% endif %}</td>
    <td>{% for row in item.rows if row.status in ('not', 'needs') %}<div><b>{{ row.setting }}</b>: {{ row.now }} &rarr; {{ row.wanted }}<br><small>{{ row.why }}</small></div>{% else %}{{ _('nothing open') }}{% endfor %}</td></tr>{% endfor %}</table>
  {% elif name == 'clam-source-status' and output.sources is sequence %}
    <table class="clam stack"><colgroup><col class="state"><col><col class="files"><col class="acc"></colgroup>
    <tr><th>{{ _('State') }}</th><th>{{ _('Source') }}</th><th>{{ _('Files') }}</th><th>{{ _('Accepted') }}</th></tr>
    {% for row in output.sources %}<tr><td>{{ clamswitch(row) }}</td><td data-label="{{ _('Source') }}"><b>{{ row.name }}</b>{% if row.terms_url.startswith('https://') %} · <a href="{{ row.terms_url }}" target="_blank" rel="noopener noreferrer">{{ _('Terms of use') }}</a>{% else %} · {{ _('no published terms') }}{% endif %}<br><small>{{ row.terms }}</small>
    {%- if row.needs_id and row.terms_accepted and 'clam-source-set' in commands and row.cluster != 'client' %}<form method="post" action="{{ url_for('run', name='clam-source-set') }}" class="clamid"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="source" value="{{ row.source }}"><input type="hidden" name="mode" value="on"><input type="hidden" name="accept_terms" value="">
    <label>{{ _('Account ID (SecuriteInfo)') }} <input type="password" name="id" autocomplete="off" spellcheck="false" maxlength="200" placeholder="{{ _('set, empty keeps it') if row.id_set else _('not set') }}"{% if not row.id_set and not row.urls %} required{% endif %}></label> <button>{{ _('Save') if row.active else _('Save and turn on') }}</button></form>{% endif %}
    {#- 6.0.0.6: the tier in effect and the pasted DatabaseCustomURL lines. They hold the key: the page shows only how many. -#}
    {%- if row.cluster == 'client' %}
    {#- 6.0.0.6: a cluster node never asks SecuriteInfo and keeps no key: the master sets tier and URLs and hands on the files. -#}
    <p class="clamsi"><small>{% if row.waiting %}<span class="pill">{{ _('waiting for the master') }}</span>{% elif row.received %}{{ _('Signatures from the master, last received') }} {{ row.received }}{% endif %}
    &middot; {{ _('Account tier and URLs are set on the master.') }}</small></p>
    {%- elif row.tiers %}{% set tier = (row.tiers|selectattr(0, 'equalto', row.tier)|list or row.tiers)[0] %}
    <p class="clamsi"><small>{{ _('Account tier in effect') }}: <b>{{ tier[1] }}</b> &middot; {{ _('at most one download every %(minutes)s minutes, at most %(rate)s kB/s')|format(minutes=tier[2], rate=tier[3]) }} &middot; {{ _('%(count)s URLs stored')|format(count=row.urls) if row.urls else _('no URLs stored') }}{% if row.last_contact %} &middot; {{ _('last asked') }} {{ row.last_contact }}{% endif %}</small></p>
    {%- if 'clam-securiteinfo-set' in commands %}<form method="post" action="{{ url_for('run', name='clam-securiteinfo-set') }}" class="clamsi"><input type="hidden" name="csrf" value="{{ csrf }}">
    <span class="lb"><label for="clam-si-tier">{{ _('SecuriteInfo account tier') }}</label></span> <select id="clam-si-tier" name="tier">{% for key, name, minutes, rate in row.tiers %}<option value="{{ key }}"{% if key == tier[0] %} selected{% endif %}>{{ name }}</option>{% endfor %}</select>
    <span class="lb"><label for="clam-si-urls">{{ _('DatabaseCustomURL lines of SecuriteInfo') }}</label>{{ info('clam-si-urls', _('Log in at SecuriteInfo and open the setup page of your account. Copy all lines that begin with DatabaseCustomURL and paste them here. They hold your subscription key: eFa-next keeps them for root only and never shows them again. Basic allows at most one download every 30 minutes and 300 kB/s; eFa-next keeps to the tier chosen here by itself.')) }}</span>
    <textarea id="clam-si-urls" name="urls" rows="4" autocomplete="off" spellcheck="false" placeholder="{{ _('replace: paste all lines; empty keeps them') if row.urls else 'DatabaseCustomURL https://www.securiteinfo.com/...' }}"></textarea>
    {%- if row.urls %}<label class="tick"><input type="checkbox" name="delete_urls" value="yes"> {{ _('Delete the stored URLs') }}</label>{% endif %}
    {%- if reauth_left() >= 60 %}<p class="h reauth-ok">{{ _('Your password still counts for {} minutes: no new entry needed.').format((reauth_left() // 60)|int) }}</p>
    {%- else %}<label>{{ _('Your password, to confirm') }} <input type="password" name="reauth" autocomplete="current-password"></label>
    <label>{{ _('2FA code, if you set one up') }} <input type="text" name="reauth_code" inputmode="numeric" autocomplete="one-time-code" maxlength="20"></label>{% endif %}
    <button>{{ _('Save') }}</button></form>{% endif %}{% endif %}</td>
    <td data-label="{{ _('Files') }}"><small>{% for file in ([row.files] if row.files is string else row.files) %}<span class="file">{{ file }}</span>{% endfor %}</small></td><td data-label="{{ _('Accepted') }}">{% if row.accepted %}<small>{{ row.accepted.at }}<br>{{ row.accepted.by }}</small>{% else %}<span class="pill">{{ _('not yet') }}</span>{% endif %}</td></tr>{% endfor %}</table>
  {% elif name == 'rbl-show' %}{% for warning in output.warnings %}<p class="warnbox">{{ warning }}</p>{% endfor %}
    <table class="rbl stack"><tr><th class="n">{{ _('State') }}</th><th class="n">ID</th><th>{{ _('List') }}</th><th class="n">{{ _('Type') }}</th><th class="n">{{ _('Score') }}</th><th class="n">{{ _('Hits') }}</th><th class="n">{{ _('Errors') }}</th><th>{{ _('Terms') }}</th></tr>
    {% for row in output.lists %}<tr><td class="n">{{ rblswitch(row) }}</td><td class="n" data-label="ID">{{ row.id }}</td><td>{{ row.list }}{% if row.url and row.url.startswith('https://') %} <a href="{{ row.url }}" target="_blank" rel="noopener noreferrer">Website</a>{% endif %}{% if row.terms_published and row.terms_url.startswith('https://') %} · <a href="{{ row.terms_url }}" target="_blank" rel="noopener noreferrer">{{ _('Terms of use') }}</a>{% elif not row.terms_published %} · {{ _('no published terms') }}{% endif %}<br><small>{{ row.accepted }}</small>
    {%- if row.dqs and 'rbl-set' in commands %}<form method="post" action="{{ url_for('run', name='rbl-set') }}" class="dqs"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="id" value="{{ row.id }}"><input type="hidden" name="mode" value="{{ 'on' if row.active else 'off' }}"><input type="hidden" name="score" value="">
    <label>{{ _('Spamhaus DQS key') }} <input name="key" autocomplete="off" spellcheck="false" maxlength="64" placeholder="{{ _('set, empty keeps it') if row.key_set else _('not set') }}"></label> <button>{{ _('Save') }}</button></form>{% endif %}</td>
    <td class="n" data-label="{{ _('Type') }}">{{ row.type }}</td><td class="n" data-label="{{ _('Score') }}">{{ row.score }}</td><td class="n" data-label="{{ _('Hits') }}">{{ row.hits }}</td><td class="n" data-label="{{ _('Errors') }}">{{ row.errors }}</td><td><small>{{ row.terms }}</small></td></tr>{% endfor %}</table>
  {% elif name == 'rotation-status' %}{% if output.rotation_warnings %}<p class="warnbox">{{ output.rotation_warnings|join(' ') }}</p>{% endif %}
  <p class="h">All domains: {{ 'on' if output.rotation_all else 'off' }}. Last check: {{ output.last_run or 'not yet' }}. Next check: {{ output.next_check or 'unknown' }}.</p>{{ show(output.domains) }}
  {% if output.remove_from_dns %}<h3>Remove these DNS records</h3>{{ show(output.remove_from_dns) }}{% endif %}
  {% elif name == 'quarantine-list' %}{{ mailui() }}{% if output.quarantine %}<div class="bulk" id="bulk" hidden role="region" aria-label="{{ _('Selected mails') }}"><span id="bulk-count" aria-live="polite"></span>
    {% if 'quarantine-release' in commands %}<button type="button" data-bulk="deliver">{{ _('Deliver') }}</button>{% endif %}{% if 'sender-action' in commands %}<button type="button" data-bulk="block">{{ _('Block senders') }}</button>{% endif %}
    {%- if 'quarantine-delete' in commands %}<button type="button" class="d" data-bulk="delete">{{ _('Delete') }}</button>{% endif %}</div>
    <div class="tablewrap"><table class="log quar"><thead><tr><th><input type="checkbox" id="pick-all" aria-label="{{ _('Select all') }}"></th><th>{{ _('Received') }}</th><th>{{ _('From') }}</th><th>{{ _('To') }}</th><th>{{ _('Size') }}</th><th>{{ _('Queue ID') }}</th><th><span class="sr">{{ _('Actions') }}</span></th></tr></thead><tbody>
    {% for mail in output.quarantine %}{% set rcpt = mail.recipients if mail.recipients is string else (mail.recipients or [])|join(', ') %}<tr>
    <td><input type="checkbox" class="pick" data-id="{{ mail.id }}" data-from="{{ mail.sender or '' }}" data-rcpt="{{ rcpt }}" aria-label="{{ _('Select') }} {{ mail.id }}"></td>
    <td class="nw" data-label="{{ _('Received') }}"><time title="{{ mail.arrived|when if mail.arrived is number else mail.arrived }}">{{ mail.arrived|ago }}</time></td>
    <td class="cut" data-label="{{ _('From') }}">{{ chip(mail.sender, 'address' if '@' in (mail.sender or '') else 'domain', mail.id, rcpt) }}</td>
    <td class="cut" data-label="{{ _('To') }}" title="{{ rcpt }}">{{ rcpt }}</td><td class="nw" data-label="{{ _('Size') }}">{{ (mail.size or 0)|filesizeformat }}</td><td class="nw mono" data-label="{{ _('Queue ID') }}">{{ mail.id }}</td>
    <td class="acts"><span class="icons">{{ iconpost('quarantine-release', '✓', _('Deliver'), {'id': mail.id}) }}{{ iconpost('quarantine-show', '☰', _('Headers'), {'id': mail.id}) }}</span>
    <details class="rowmenu"><summary title="{{ _('More actions') }}"><span aria-hidden="true">…</span><span class="sr">{{ _('More actions') }}</span></summary><div class="menulist">{{ post('quarantine-release', _('Deliver'), {'id': mail.id}) }}
    {{- post('quarantine-show', _('Headers'), {'id': mail.id}) }}{% if 'quarantine-content' in commands %}{{ post('quarantine-content', _('Text'), {'id': mail.id}) }}{% endif %}
    <a class="btn d" href="{{ url_for('show_page', slug='quar', id=mail.id) }}#quarantine-delete">{{ _('Delete') }}</a></div></details></td></tr>{% endfor %}</tbody></table></div>
    {% else %}<p class="empty">{{ _('The quarantine is empty.') }}</p>{% endif %}
  {% elif name == 'security-status' %}<p class="h">Last check: {{ output.checked or 'not yet' }}. Every day: {{ 'on' if output.daily else 'off' }}.</p>
    {% if output.findings %}<table class="stack"><tr><th></th><th>Finding</th><th>Detail</th><th>What to do</th></tr>{% for item in output.findings %}
    <tr><td><span class="dot {{ 'b' if item.level == 'problem' else 'w' }}"></span></td><td>{{ item.title }}</td><td>{{ item.detail }}</td><td>{{ item.fix }}</td></tr>{% endfor %}</table>
    {% elif output.checked %}<p>No findings.</p>{% endif %}
  {% elif name == 'blocklist-show' %}{{ blocklist_table(output) }}
  {% elif name == 'group-list' %}<table class="data"><tr><th>{{ _('Group') }}</th><th>{{ _('Description') }}</th><th>{{ _('Scope') }}</th><th>{{ _('Members') }}</th><th>{{ _('Permissions') }}</th></tr>{% for item in output.groups %}
    <tr><td data-label="{{ _('Group') }}"><b>{{ item.name }}</b>{% if item.predefined %} <span class="pill">{{ _('predefined') }}</span>{% endif %}{% if item.disabled %} <span class="pill w">{{ _('off') }}</span>{% endif %}</td>
    <td data-label="{{ _('Description') }}">{{ item.description }}</td><td data-label="{{ _('Scope') }}">{{ item.scope }}</td><td class="nw" data-label="{{ _('Members') }}">{{ item.members }}</td>
    <td data-label="{{ _('Permissions') }}"><details class="help"><summary>{{ item.permissions|length }}</summary><div class="chips">{% for permission in item.permissions %}<span class="chip">{{ permission }}</span>{% endfor %}</div></details></td></tr>{% endfor %}</table>
  {% elif name == 'tenant-list' %}{{ show(output) }}
    <form method="post" enctype="multipart/form-data" action="{{ url_for('brand_upload') }}"><input type="hidden" name="csrf" value="{{ csrf }}">
    <div class="row"><label for="brand-tenant">Logo for tenant</label><input type="text" id="brand-tenant" name="tenant" required></div>
    <div class="row"><label for="brand-logo">PNG, up to 200 KB and 1024 pixels</label><input type="file" id="brand-logo" name="logo" accept="image/png" required></div><div class="btns"><button>Upload</button></div></form>
  {% elif name == 'backup-list' %}{% if output.backups %}<table class="data"><tr><th>Backup</th><th>Date</th><th>Size</th><th></th><th></th></tr>{% for backup in output.backups %}<tr><td>{{ backup.name }}</td><td>{{ backup.date }}</td><td>{{ backup.size_mb }} MB</td>
    <td>{% if backup.encrypted %}<span class="pill w">&#128274; encrypted</span>{% endif %}</td>
    <td><form method="post" action="{{ url_for('backup_download') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="name" value="{{ backup.name }}">
    <input type="password" name="password" placeholder="Admin password" aria-label="Admin password" autocomplete="current-password" required style="width:150px"> <button>Download</button></form>
    <a class="btn" href="{{ url_for('show_page', slug='bak', name=backup.name) }}#restore">Restore</a></td></tr>{% endfor %}</table>
    {% else %}<span class="pill">{{ _('none') }}</span>{% endif %}
    <form method="post" enctype="multipart/form-data" action="{{ url_for('backup_upload') }}"><input type="hidden" name="csrf" value="{{ csrf }}">
    <div class="row"><label for="backup-file">Upload a backup (.tar.gz or .tar.gz.gpg, up to 64 MB)</label><input type="file" id="backup-file" name="file" required></div><div class="btns"><button>Upload</button></div></form>
  {% elif name == 'autoupdate-status' %}<p class="h">Installed: {{ output.installed }}. Newest: {{ output.latest or 'not checked yet' }}. Operating system updates: {{ output.os_updates }}.</p>
    {% if output.update_available %}<p class="warnbox">Update available: {{ output.latest }}</p><pre>{{ output.release_notes }}</pre>{% endif %}
    <p class="h">Last check: {{ output.last_check or 'not yet' }}. Last result: {{ output.last_result or 'none' }}</p>
  {% else %}{{ show(output) }}{% endif %}
{% else %}{% if name == 'release-upgrade' %}<p class="err" role="alert">{{ _('No way back: the upgrade to EL10 cannot be undone, only a VM snapshot of this host leads back. About 30 to 60 minutes without mail (new mail gets 421), several reboots.') }}</p>
<p class="err" role="alert">{{ _('Started with the sentence "without backup, snapshot only", no backup is made and nothing of this host is kept anywhere else: the VM snapshot is then the only way back.') }}</p>{% endif %}
<form method="post" action="{{ url_for('run', name=name) }}"><input type="hidden" name="csrf" value="{{ csrf }}">
  {% if name == 'dkim-create' %}{{ keytable() }}{% endif %}
  {% for arg in cmd.args if arg.web is not sameas false %}{{ field(name, arg) }}{% endfor %}
  {% if name == 'passkey-register' %}<div class="btns"><button type="button" id="passkey-add" hidden>{{ _('Make the passkey now') }}</button></div>
  <p class="err" id="passkey-error" hidden>{{ _('The passkey did not work. Log in with password and code.') }}</p><script src="/passkey.js"></script>{% endif %}
  {% if name in reauth_commands and reauth_left() >= 60 %}<p class="h reauth-ok">{{ _('Your password still counts for {} minutes: no new entry needed.').format((reauth_left() // 60)|int) }}</p>
  {% elif name in reauth_commands %}<div class="row"><label for="{{ name }}-reauth">{{ _('Your password, to confirm') }}</label><input type="password" id="{{ name }}-reauth" name="reauth" autocomplete="current-password"></div>
  <div class="row"><label for="{{ name }}-reauth-code">{{ _('2FA code, if you set one up') }}</label><input type="text" id="{{ name }}-reauth-code" name="reauth_code" inputmode="numeric" autocomplete="one-time-code" maxlength="20"></div>{% endif %}
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
{% if ns.hidden %}<p class="h expert-note">{{ _('More on this page in the expert view:') }} {{ ns.hidden }} {{ viewform('expert', _('Show')) }}</p>{% endif %}{% endif %}</main>""")


# nginx sends the address of the browser in X-Real-IP, with this key in X-Efa-Proxy (efactl web-harden writes both): another
# local process that talks to 127.0.0.1:8080 itself gets its own address, so it cannot forge one for the audit, the lockout
# and the admin allowlist.
PROXY_KEY_FILE = WEB_DIR + '/proxy.key' if not os.environ.get('EFA_WEB_MODE') == 'portal' else os.environ.get('EFA_ETC', '/etc') + '/efa-portal/proxy.key'


def _proxy_key():
    try:
        with open(PROXY_KEY_FILE, 'rb') as f:
            return f.read().strip()
    except OSError:
        return b''


PROXY_KEY = _proxy_key()


def client_address():
    """The address of the browser: X-Real-IP only from nginx (its key in X-Efa-Proxy), else the peer of the socket."""
    sent = request.headers.get('X-Efa-Proxy', '').encode()
    if PROXY_KEY and hmac.compare_digest(sent, PROXY_KEY):
        return request.headers.get('X-Real-IP', request.remote_addr or '')
    return request.remote_addr or ''


def acting_as():
    """Tells efactl who works: it holds the rights of the roles and limits the results. The main admin has no user entry."""
    if not has_request_context():
        return []
    user = g.get('api_user') or session.get('user')
    client = client_address()
    # A token bound to one tenant reaches only that tenant.
    limit = [f"--limit-tenant={g.api_tenant}"] if g.get('api_user') and g.get('api_tenant') else []
    sid = session.get('sid')
    return [f'--client={client}'] + limit + ([f'--as={user}'] if user else []) + ([f'--session={session_sha(sid)}'] if sid else [])


STRICT_FILE = os.environ.get('EFA_ETC', '/etc') + '/eFa/audit-strict.json'
strict_cache = {'mtime': None, 'on': False}
# Polled by the pages themselves, or files without a meaning of their own.
STRICT_SKIP = {'copy_js', 'live_js', 'wizard_js', 'wizard_test', 'load_card', 'threat_banner', 'status_board', 'static', 'logo', 'brand_logo', 'favicon', 'icon'}


def reader_language():
    """The language of My settings, kept in the session from the login on, or the one the browser asks for."""
    if 'lang' not in session and session.get('admin'):
        ok, prefs = efactl('my-settings')
        session['lang'] = prefs.get('language', 'auto') if ok else 'auto'
        session['view'] = prefs.get('view', 'standard') if ok else 'standard'
    return efa_i18n.pick(session.get('lang') or system_language(), request.headers.get('Accept-Language'))


def system_language():
    try:
        with open(LANGUAGE_FILE) as f:
            found = f.read().strip()
    except OSError:
        return 'auto'
    return found if found in efa_i18n.LANGUAGES else 'auto'


def translate(text):
    """A text of the interface in the language of the reader. Texts without a translation stay English."""
    if not text or not has_request_context():
        return text
    if 'lang' not in g:
        g.lang = reader_language()
    return efa_i18n.catalog(g.lang).gettext(text) if g.lang != 'en' else text


def runtime_text(text):
    """A text efactl built from a template with values (UI-1), in the language of the reader."""
    if not text or not has_request_context():
        return text
    if 'lang' not in g:
        g.lang = reader_language()
    return efa_i18n.runtime(text, g.lang)


# Also for the texts made in Python: scripts/i18n_extract.py collects every quoted text in a call of _ in this file.
_ = translate
app.jinja_env.filters['t'] = translate
app.jinja_env.filters['rt'] = lambda text: runtime_text(text)


def ago(value):
    """A time as its age (just now, 5 min, 3 h, else the day); the full time goes into the title. A text of the database or seconds since 1970."""
    try:
        then = value if isinstance(value, (int, float)) else datetime.datetime.fromisoformat(str(value)[:19]).timestamp()
    except ValueError:
        return value
    seconds = time.time() - then
    if seconds < 60:
        return _('just now')
    if seconds < 3600:
        return f'{int(seconds // 60)} min'
    if seconds < 86400:
        return f'{int(seconds // 3600)} h'
    return time.strftime('%Y-%m-%d', time.localtime(then))


app.jinja_env.filters['ago'] = ago
app.jinja_env.globals['_'] = translate
app.jinja_env.globals['portal_mode'] = PORTAL


def help_text(name, arg=None):
    """The help of a card (arg None) or of one of its fields, in the language of the reader; empty when there is none."""
    text = efa_help.FIELD.get(name, {}).get(arg) if arg else efa_help.CARD.get(name)
    return translate(text) if text else ''


app.jinja_env.globals['help_text'] = help_text
app.jinja_env.globals['first_sentence'] = efa_help.first_sentence
app.jinja_env.globals['short_title'] = efa_help.short_title
app.jinja_env.globals['web_label'] = efa_help.web_label
SETUP_VARIANT_FILE = os.environ.get('EFA_ETC', '/etc') + '/eFa/setup-variant.json'
setup_variant_seen = {'mtime': None, 'locked': False}


def eu_locked():
    """6.0.0.5: with the EU link of the setup the EU rules apply hard (efa_setup). Read again only when the file changed."""
    try:
        mtime = os.stat(SETUP_VARIANT_FILE).st_mtime
    except OSError:
        return False
    if mtime != setup_variant_seen['mtime']:
        try:
            with open(SETUP_VARIANT_FILE) as f:
                state = json.load(f)
        except (OSError, ValueError):
            state = {}
        setup_variant_seen.update(mtime=mtime, locked=efa_setup.eu_locked(state))
    return setup_variant_seen['locked']


app.jinja_env.globals['eu_locked'] = eu_locked
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
    return client_address(), session.get('sid')


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


RUNNER_CONNECT_TRIES = 6


def runner_call(args, secrets_in):
    """efactl through efactl-runner. None when the runner is not there; False when the call itself broke off."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(130)
        for attempt in range(RUNNER_CONNECT_TRIES):
            try:
                sock.connect(RUNNER_SOCKET)
                break
            except BlockingIOError:
                # The backlog is full for a moment (EAGAIN): a short wait, then again with a new socket.
                sock.close()
                time.sleep(0.05 * (attempt + 1))
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(130)
            except OSError as err:
                app.logger.error('efactl-runner does not answer: %s', err)
                return None
        else:
            app.logger.error('efactl-runner does not answer: its backlog stayed full')
            return None
        try:
            # b'N': no pipe goes with this call (the protocol of efactl-runner).
            sock.sendall(b'N' + json.dumps({'args': list(args), 'secrets': list(secrets_in or [])}).encode() + b'\n')
            reply = json.loads(sock.makefile('rb').readline())
            return subprocess.CompletedProcess(args, reply['code'], reply['stdout'], reply['stderr'])
        except (OSError, ValueError, KeyError, TypeError) as err:
            app.logger.error('efactl-runner %s failed: %s', args[:1], err)
            return False
    finally:
        sock.close()


def runner_stream(args, stdin=None, stdout=None):
    """Starts an efactl call whose stdin or stdout is a pipe end of efa-web, handed to efactl-runner over the socket. The
    caller closes its copy of that end, moves the data through the other end, then reads the answer with stream_reply.
    None when the runner does not answer."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(STREAM_SECONDS + 10)
    try:
        sock.connect(RUNNER_SOCKET)
        socket.send_fds(sock, [b'F'], [fd for fd in (stdin, stdout) if fd is not None])
        sock.sendall(json.dumps({'args': list(args), 'secrets': [], 'stdin_fd': stdin is not None,
                                 'stdout_fd': stdout is not None}).encode() + b'\n')
    except OSError as err:
        sock.close()
        app.logger.error('efactl-runner %s failed: %s', args[-1:], err)
        return None
    return sock


def stream_reply(sock):
    """(ok, answer) of a call started with runner_stream; the answer is {} when its output went into the pipe."""
    try:
        reply = json.loads(sock.makefile('rb').readline())
        code, out, err = reply['code'], reply['stdout'], reply['stderr']
    except (OSError, ValueError, KeyError, TypeError) as error:
        app.logger.error('efactl-runner stream failed: %s', error)
        return False, {'error': 'efactl failed, see the log.'}
    finally:
        sock.close()
    try:
        return code == 0, json.loads(out) if out else {}
    except ValueError:
        app.logger.error('efactl failed: %s', err)
        return False, {'error': 'efactl failed, see the log.'}


# Jobs and checks that work or take seconds: they run from their button, never just by opening a page.
ON_BUTTON = {'security-check', 'standards-check', 'form-check', 'cluster-dkim-apply', 'cluster-content-apply'}


def on_button_only(name):
    return name in ON_BUTTON or name in HIDDEN_CARDS or name.endswith('-run')


# Reads that are slow or change seldom, kept this many seconds per login. An older answer is shown at once and renewed in the
# background; every change made through this web interface empties the cache. Strict audit mode reads every time.
READ_CACHE_SECONDS = {'schema': 300, 'bayes-status': 600, 'ssh-root-status': 300, 'rotation-status': 300, 'dkim-check': 300, 'rbl-show': 300,
                      'security-status': 60, 'backup-list': 60, 'dash-stats': 20, 'update-pending': 300, 'neural-status': 60,
                      'firewall-show': 30, 'settings': 10, 'status': 10, 'switches-status': 10, 'harvest-status': 30, 'tenant-list': 30, 'group-list': 30,
                      'dane-status': 60, 'ml-status': 60, 'audit-strict-status': 60, 'audit-verify': 60, 'user-list': 10, 'session-list': 10,
                      # About 70 ms (postconf and systemd): it set the time of the spam page (budget 100 ms).
                      'cdr-status': 30,
                      # The Security page: postconf, sshd -T and fail2ban-client per jail; up to 211 ms right after a restart (budget 100 ms).
                      'tls-profile-status': 60, 'ssh-profile-status': 60, 'os-harden-status': 60, 'milter-health-status': 60, 'login-lockout-status': 30,
                      # The rest of the Security page: history 57 ms, firewall guard 45 ms, the others 2 to 15 ms each (measured for 6.0.0.6); read
                      # in parallel they kept the page at 99 to 108 ms. A change through the interface clears the cache anyway.
                      'history-list': 30, 'firewall-guard-status': 30, 'service-harden-status': 60, 'floor-status': 60,
                      'setup-variant-status': 60, 'cve-watch-status': 60, 'four-eyes-list': 10, 'web-allowlist-show': 30,
                      # The Spam page of 6.0.0.5: systemctl, the database and file reads, 50 to 100 ms each, 116 to 147 ms the page.
                      'ole-status': 30, 'retro-status': 60, 'qr-status': 30, 'unlock-status': 30, 'scan-status': 30, 'own-block-status': 30,
                      'sandbox-status': 30,
                      # The users page: up to 150 ms. totp-status and passkey-status are not kept: a change on the console must show at once.
                      'incident-list': 30,
                      # The held mail page: 8 reads, up to 172 ms (budget 100 ms). A form of this interface clears the cache at once.
                      'uq-status': 30, 'graymail-status': 30, 'user-spam-status': 30, 'recall-list': 30}
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
    if done is None:
        return False, {'error': 'The service efactl-runner does not answer, see the log.'}
    if done is False:
        return False, {'error': 'efactl failed, see the log.'}
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
    try:
        threat_refresh()
    except (OSError, ValueError, KeyError, TypeError) as err:
        app.logger.warning('attack check failed: %s', err)
    while True:
        time.sleep(60)
        try:
            threat_refresh()
        except (OSError, ValueError, KeyError, TypeError) as err:
            app.logger.warning('attack check failed: %s', err)
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
    'passkey_js': 'open', 'passkey_options': 'open', 'passkey_register_options': 'efactl',
    'link_check': 'open', 'api': 'open', 'api_schema': 'open', 'metrics': 'open', 'copy_js': 'open', 'favicon': 'open', 'live_js': 'open', 'senders_js': 'open', 'mailui_js': 'open', 'senders_check': 'efactl',
    'index': 'efactl', 'show_page': 'efactl', 'search': 'efactl', 'search_suggest': 'efactl', 'set_view': 'efactl', 'mail_check': 'efactl', 'disclaimer_import': 'efactl', 'disclaimer_export': 'efactl', 'legal': 'open', 'legal_file': 'open', 'legal_accept': 'efactl', 'hardening_pdf': 'efactl', 'run': 'efactl', 'mail_page': 'efactl', 'mail_headers': 'efactl', 'mail_evidence': 'efactl',
    'export_file': 'efactl', 'brand_logo': 'efactl', 'brand_upload': 'efactl', 'maillog_live': 'efactl', 'load_card': 'efactl', 'threat_banner': 'efactl', 'status_board': 'efactl',
    'backup_download': 'super', 'backup_upload': 'super', 'rspamd_auth': 'super', 'rspamd_open': 'super', 'export_dkim': 'super',
    'senders_data': 'super', 'resetup_view': 'super', 'static': 'open',
    'wizard_step': 'efactl', 'wizard_test': 'efactl', 'wizard_mode': 'efactl', 'wizard_js': 'open'}
SUPER_ONLY = {name for name, right in ROUTE_RIGHTS.items() if right == 'super'}
# 5q: changes that need the password of the admin again, at most every 5 minutes.
REAUTH_COMMANDS = {'user-set', 'user-2fa-reset', 'user-state', 'group-set', 'group-map-set', 'tenant-group-map-set', 'token-create', 'firewall-set', 'firewall-guard-set',
                   'ssh-root-set', 'web-allowlist-set', 'restore', 'dkim-remove', 'dkim-import', 'backup-password-set', 'admin-password', 'audit-mode',
                   'cluster-init', 'cluster-token', 'cluster-leave', 'oidc-set', 'ldap-set', 'api-set', 'resetup', 'console-2fa-set', 'release-upgrade',
                   'dns-share-add', 'dns-share-del', 'dns-share-secondary-set', 'standards-set', 'standards-rollback', 'os-harden-set', 'clam-securiteinfo-set'}
REAUTH_SECONDS = 300
REAUTH_FAILED = 'Password or 2FA code wrong, nothing changed.'
# What ends a control or a record: four eyes, the audit rules and the days of the logs, a whole tenant, a file taken back.
REAUTH_COMMANDS |= {'four-eyes-set', 'audit-rules-set', 'retention-set', 'tenant-delete', 'history-undo'}
def account_view():
    """6.0.0.6: who works, for the menu at the top right: the login name and its role. The main admin has no user entry."""
    user = session.get('user')
    roles = {'super': _('Super admin'), 'tenant': _('Tenant admin'), 'domain': _('Domain admin'), 'manager': _('Domain manager'), 'helpdesk': _('Helpdesk'),
             'user': _('User'), 'readonly': _('Read only'), 'auditor': _('Auditor'), 'custom': _('Own groups')}
    role = session.get('role', 'super')
    return {'login': user or 'admin', 'role': roles.get(role, role) if user else _('Main admin')}


app.jinja_env.globals['account_view'] = account_view


# The release upgrade, the security standards and the extra ClamAV sources: super admins only (efactl decides, SUPER_COMMANDS
# there); other logins and tokens get 403, not 404.
SUPER_COMMANDS = {'release-upgrade', 'release-upgrade-status', 'standards-set', 'standards-rollback', 'os-harden-set', 'clam-source-set', 'clam-securiteinfo-set', 'threat-set'}


def reauth_left():
    """M4: seconds the last password confirmation still holds; the forms ask for the password only when it is under a minute."""
    return max(0, int(REAUTH_SECONDS - (time.time() - session.get('reauth', 0))))


app.jinja_env.globals['reauth_left'] = reauth_left


def reauth_ok(form):
    """The password of the logged-in admin, again, for a critical change; good for five minutes."""
    if time.time() - session.get('reauth', 0) < REAUTH_SECONDS:
        return True
    password = form.get('reauth', '')
    if not password:
        return False
    # Counted as failed logins: a taken-over session must not try passwords without end.
    client = client_address()
    count, since = login_failures.get(client, (0, 0))
    if count >= MAX_LOGIN_FAILURES and time.time() - since < LOCKOUT_SECONDS:
        return False
    if session.get('user'):
        ok, _who = efactl('user-verify', f"--username={session['user']}", secrets_in=[password, form.get('reauth_code', '').strip()[:20]])
    else:
        try:
            with open(PASSWORD_FILE) as f:
                ok = password_ok(f.read().strip(), password) and admin_second_factor(form.get('reauth_code', '').strip()[:20])
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
    # The host itself (the health check of the updater after an update), as in the list of nginx.
    return address.is_loopback or any(address in network for network in networks)


@app.before_request
def forget_reads():
    # Every form and button posts: what was read before may be out of date now.
    if request.method == 'POST' and request.endpoint != 'search':
        with read_cache_lock:
            read_cache.clear()


# Werkzeug 2.0 of EL9 parses multipart bodies without a limit on their parts (CVE-2023-25577, CVE-2023-46136, CVE-2024-49767):
# only the four uploads take them, only from a login, and before anything reads the body. Other forms are small.
MULTIPART_ENDPOINTS = {'brand_upload', 'mail_check', 'disclaimer_import', 'backup_upload'}
MAX_FORM = 4 * 1024 * 1024


@app.before_request
def body_limits():
    if request.mimetype == 'multipart/form-data':
        if PORTAL or request.endpoint not in MULTIPART_ENDPOINTS or not session_active():
            abort(415)
    elif (request.content_length or 0) > MAX_FORM:
        abort(413)


@app.before_request
def protect():
    if not PORTAL and not admin_address_ok(client_address()):
        # Fail2Ban reads this line.
        app.logger.warning('efa-web admin address refused from %s', client_address())
        abort(403)
    if request.endpoint in ('api', 'api_schema', 'metrics', 'quarantine_link', 'link_check'):
        return None  # Token instead of cookie, so no CSRF risk.
    if request.endpoint in ('legal', 'legal_file', 'favicon') and request.method == 'GET':
        return None  # open to everyone, like the texts in the repository (and the icon of the login page)
    if request.method == 'POST' and not hmac.compare_digest(request.form.get('csrf', ''), session.get('csrf', '')
                                                            or secrets.token_urlsafe(8)):
        if request.endpoint == 'login':
            # The page was open too long (or the cookie is gone): not a wrong password, so no lockout count; the code stays unused.
            app.logger.warning('efa-web login form expired from %s', client_address())
            g.audit_action = 'csrf_expired'
            session['login_note'] = 'expired'
            session['login_user'] = request.form.get('username', '').strip()[:120]
            return redirect(url_for('login'))
        abort(403)
    if request.endpoint in ('passkey_js',):
        return None
    if request.endpoint == 'passkey_options':
        return None  # before the login; the CSRF token was checked above
    if request.endpoint in ('login', 'rspamd_auth', 'oidc_login', 'oidc_callback', 'post_only') and not request.method == 'POST':
        return None
    if request.endpoint != 'login' and not session_active():
        return redirect(url_for('login'))
    if request.endpoint in SUPER_ONLY and session.get('role', 'super') != 'super':
        abort(403)
    if session.get('totp_setup') and request.endpoint not in TOTP_SETUP_ENDPOINTS:
        if request.endpoint == 'run' and (request.view_args or {}).get('name') in TOTP_SETUP_COMMANDS:
            return None
        home = USER_PAGE if PORTAL else 'account'
        if not (request.endpoint == 'show_page' and (request.view_args or {}).get('slug') == home):
            return redirect(url_for('show_page', slug=home) + '#totp-setup')
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


ERROR_PAGE = PAGE.replace(BLOCK, SOLO + """<div class="card"><h1>{{ title }}</h1><p>{{ text }}</p>
<div class="btns"><a class="p" href="/">{{ _('To the start page') }}</a></div></div></main>""")
# _() outside a request keeps the English text (translated when shown); here it marks the texts for i18n_extract.py.
ERROR_TEXTS = {400: (_('Bad request'), _('The request was not understood. Load the page again.')),
               403: (_('Access denied'), _('You have no access to this page, or the page was open too long. Load it again.')),
               404: (_('Not found'), _('This page does not exist.')),
               405: (_('Not possible'), _('This action is not possible here. Go back and use the button of the page.')),
               500: (_('Error'), _('Something went wrong. The details are in the log of the server.'))}


def error_page(error):
    code = getattr(error, 'code', 500) if getattr(error, 'code', 500) in ERROR_TEXTS else 500
    title, text = ERROR_TEXTS[code]
    if code == 500:
        app.logger.error('efa-web error on %s: %r', request.path, getattr(error, 'original_exception', error))
    return render_template_string(ERROR_PAGE, title=_(title), text=_(text)), code


for _code in ERROR_TEXTS:
    app.register_error_handler(_code, error_page)


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
    if request.method == 'GET' and request.args.get('lang') in efa_i18n.LANGUAGES:
        session['lang'] = request.args['lang']
    if session.pop('login_note', None):
        error = _('The page was open too long. Please log in again.')
    if request.method == 'POST':
        client = client_address()
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
            code = request.form.get('code', '').strip()[:20]
            assertion = request.form.get('assertion', '').strip()[:16000].replace('\n', ' ')
            if assertion and not request.form.get('password'):
                # 5s: a passkey alone, for the roles that allow it; efactl checks the challenge, the key and the role.
                ok, who = efactl('passkey-login', secrets_in=[assertion])
                if ok and not (PORTAL and who['role'] != 'user') and (PORTAL or who['role'] != 'user'):
                    login_failures.pop(client, None)
                    session_start(who['username'], who['role'], sid=who.get('sid'))
                    app.logger.warning('efa-web login ok user %s from %s', who['username'], client)
                    g.audit_action = 'login_ok'
                    return redirect(url_for('index'))
            elif username:
                ok, who = efactl('user-verify', f'--username={username}', secrets_in=[request.form.get('password', ''), code, assertion])
                if ok and not PORTAL and who['role'] == 'user':
                    # Users have their own portal, in a process without rights: the admin interface takes no user login.
                    return render_template_string(LOGIN, csrf=csrf_token(), error=None, sso=False, tenant_sso=False, portal=True)
                if ok:
                    login_failures.pop(client, None)
                    session_start(who['username'], who['role'], sid=who.get('sid'))
                    if who.get('totp_setup_needed'):
                        session['totp_setup'] = True
                    if who.get('no_2fa'):
                        session['no_2fa'] = True
                    # The event collector of efactl reads this line.
                    app.logger.warning('efa-web login ok user %s from %s', who['username'], client)
                    g.audit_action = 'login_ok'
                    return redirect(url_for('index'))
            elif stored and not PORTAL and password_ok(stored, request.form.get('password', '')) and admin_second_factor(code):
                login_failures.pop(client, None)
                session_start()
                if main_admin_needs_setup():
                    session['totp_setup'] = True
                if g.get('no_2fa'):
                    session['no_2fa'] = True
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
            error = _('Wrong password or 2FA code. With 2FA set up, enter the code of the app too.')
    # The portal has single sign-on only with its own redirect address at the provider (portal in oidc-status).
    ok, sso = efactl('oidc-status')
    return render_template_string(LOGIN, csrf=csrf_token(), error=error or session.pop('sso_error', None),
                                  sso=ok and sso.get('portal' if PORTAL else 'oidc'), tenant_sso=ok and sso.get('tenant_portal_sso' if PORTAL else 'tenant_sso'),
                                  portal=False, username=session.pop('login_user', ''), lang=reader_language())


def admin_second_factor(code):
    """5r: the main admin (console password) with a second factor needs its code; without one this is true."""
    ok, answer = efactl('admin-2fa-verify', secrets_in=[code])
    g.no_2fa = ok and bool(answer.get('no_2fa'))
    return ok


def main_admin_needs_setup():
    ok, status = efactl('totp-status')
    return ok and status.get('required_for_my_role') and not status.get('active')


# 5r: a login whose role asks for 2FA and has none sets it up first; only these pages and commands until then.
TOTP_SETUP_ENDPOINTS = {'login', 'logout', 'static', 'post_only', 'favicon', 'legal', 'legal_file'}
TOTP_SETUP_COMMANDS = {'totp-setup', 'totp-confirm', 'totp-status'}


OIDC_COOKIE = 'efa_oidc'
OIDC_SECONDS = 600
# The login state cookie only goes to the single sign-on paths of this interface.
OIDC_PATH = '/portal/login/oidc' if PORTAL else '/login/oidc'
# The session cookie is SameSite=Strict: a browser does not send it on the way back from the provider,
# nor on a redirect in that chain. So the login state has its own cookie, and the last step is a page that moves on by itself.
MOVE_ON = '<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url={url}"><title>eFa-next</title><a href="{url}">Continue</a>'


def oidc_signer():
    return URLSafeTimedSerializer(app.secret_key, salt='efa-oidc')


def move_on(endpoint):
    response = Response(MOVE_ON.format(url=url_for(endpoint)), mimetype='text/html')
    response.delete_cookie(OIDC_COOKIE, path=OIDC_PATH)
    return response


LINK_PAGE = PAGE.replace(BLOCK, SOLO + """<div class="card"><h1>{{ view.question or _('Your link') }}</h1>{% if error %}<p class="err" role="alert">{{ error }}</p>{% elif done %}<p>Done: {{ done }}.</p>
{% else %}{% if view.to %}<p>To {{ view.to }}: {{ view.subject }}</p>{% elif view.sender %}<p>From {{ view.sender }}: {{ view.subject }}</p>{% endif %}<form method="post"><div class="btns"><button class="p">Yes</button></div></form>{% endif %}</div></main>""")


CONTENT_FILE = os.environ.get('EFA_ETC', '/etc') + '/efa-web/content.json'
RSPAMD_CHECK = 'http://127.0.0.1:11333/checkv2'
LINK_CACHE_SECONDS = 300
link_cache = {}
LINK_WARNING = PAGE.replace(BLOCK, SOLO + """<div class="card">{% if reasons is none %}<h2>{{ _('The link could not be checked just now') }}</h2>
<p>{{ _('It leads to this address:') }}</p><p class="h">{{ target }}</p>{% else %}<h2>{{ _('This link may be dangerous') }}</h2>
<p>{{ _('The address is listed as dangerous or as phishing:') }}</p><p class="h">{{ target }}</p><p class="h">{{ reasons|join(', ') }}</p>{% endif %}
{% if allow %}<p><a class="btn" href="{{ target }}" rel="noopener noreferrer">{{ _('Go on anyway') }}</a></p>{% endif %}
<p>{{ _('If you did not expect this mail, delete it.') }}</p></div>
{% if reasons %}<div class="card"><h2>{{ _('How to spot such links') }}</h2><ul>
<li>{{ _('Look at the address above, not at the text of the link: does it really belong to the sender?') }}</li>
<li>{{ _('Watch for small changes: an extra letter, a digit for a letter, another ending such as .co for .com.') }}</li>
<li>{{ _('Urgency, threats or a prize are the usual tricks: banks and shops never ask for passwords by mail.') }}</li>
<li>{{ _('In doubt, open the website yourself or call the sender on a number you know.') }}</li></ul>
{% if hint %}<p>{{ hint }}</p>{% endif %}</div>{% endif %}</main>""")


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
    tenant = efa_links.link_tenant(token, bytes.fromhex(links['key'])) if links.get('key') else ''
    if PORTAL:
        # The link key stays with the helper.
        ok, found = efactl('link-target', token)
        links, target = (found, found.get('target')) if ok else ({}, None)
        tenant = found.get('tenant', '') if ok else ''
    hint = (links.get('hints') or {}).get(tenant) or (links.get('hints') or {}).get('all', '')
    if not target:
        abort(404)
    reasons = link_verdict(target)
    if reasons is None:
        # The event collector of efactl reads this line and sends it on to the SIEM.
        app.logger.warning('efa-web link unchecked %s', target[:200])
        unchecked = links.get('unchecked', 'page')
        if unchecked == 'follow':
            return redirect(target, code=302)
        return render_template_string(LINK_WARNING, target=target, reasons=None, allow=unchecked == 'page', hint=''), 200
    app.logger.warning('efa-web link %s %s', 'blocked' if reasons else 'followed', target[:200])
    if not reasons:
        return redirect(target, code=302)
    return render_template_string(LINK_WARNING, target=target, reasons=reasons, allow=links.get('continue', True), hint=hint), 200


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
                        path=OIDC_PATH, secure=True, httponly=True, samesite='Lax')
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
        app.logger.warning('efa-web login failed from %s', client_address())
        session['sso_error'] = who.get('error')
        return move_on('login')
    if not PORTAL and who.get('role') == 'user':
        # A user of the portal: never a session of the admin interface.
        session['sso_error'] = 'This account logs in at the user portal.'
        return move_on('login')
    # In the portal the helper gives the session id (it binds the login to it).
    session_start(who['username'], who['role'], sid=who.get('sid'))
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


# 6.0.0.6 (Hans): "bei einem problem/angriff aktiv optisch auf jeder seite informiert werden". efactl threat-run judges the
# host once a minute from this load thread (journal, kernel counters, mail log, queue); every page only reads the kept answer,
# so the banner costs no call per page. The dashboard shows the same answer as lamps and gauges.
threat_now = {'result': None}
# Older than this, the answer is not shown: a stopped check must not show an old attack, nor an old all clear.
THREAT_STALE = 300


def threat_refresh():
    ok, output = efactl('threat-run', who=[])
    if ok:
        threat_now['result'] = output
    else:
        app.logger.warning('attack check failed: %s', output.get('error'))


def threat_current():
    found = threat_now['result']
    return found if found and time.time() - (found.get('checked') or 0) <= THREAT_STALE else None


def threat_texts():
    """The name of each kind and its value line, in the language of the reader."""
    return {'smtp_flood': (_('SMTP connection flood (possible DDoS)'), _('{value} connections per minute, normally {normal}')),
            'syn_flood': (_('SYN flood on the network (DDoS)'), _('{value} dropped or SYN cookie connections per minute')),
            'password_attack': (_('Password guessing on mail or web logins'), _('{value} failed logins in 10 minutes')),
            'spam_wave': (_('Spam wave'), _('{value} spam mails in 10 minutes ({share}%), normally {normal}')),
            'virus_wave': (_('Virus wave'), _('{value} viruses in 10 minutes, normally {normal}')),
            'reject_wave': (_('Many rejected connections'), _('{value} rejected per minute, normally {normal}')),
            'ban_wave': (_('Many addresses banned by Fail2Ban'), _('{value} bans in 10 minutes')),
            'queue_flood': (_('Mail queue filling up'), _('{value} mails in the queue')),
            'service_down': (_('Service down'), '{names}'),
            'disk_full': (_('Disk almost full'), _('{value}% used')),
            'memory_low': (_('Memory almost used up'), _('{value}% used')),
            'load_high': (_('Very high system load'), _('Load at {value}% of the CPUs'))}


def threat_view(commands, role):
    """The banner of every admin page, or None: only for a login that may read the attack check. The addresses that cause
    an attack only for super admins and the main admin (efactl gives a tenant admin none anyway)."""
    found = threat_current() if commands and 'threat-status' in commands and not PORTAL else None
    if not found or not found.get('alerts'):
        return None
    items = threat_items(found['alerts'], commands, role)
    attack = [item for item in items if item['group'] == 'attack']
    level = 'alert' if any(item['level'] == 'alert' for item in items) else 'warn'
    if attack and any(item['level'] == 'alert' for item in attack):
        head = _('Attack on this server')
    elif attack:
        head = _('Possible attack on this server')
    else:
        head = _('Problem on this server')
    # 'entries', not 'items': in Jinja threat.items would be the method of the dict.
    return {'level': level, 'head': head, 'entries': items}


def threat_items(alerts, commands, role):
    """Each found kind as the banner and the card show it: its name, its value line, since when, the link to its page."""
    names = threat_texts()
    items = []
    for alert in alerts:
        name, line = names.get(alert['kind'], (alert['kind'], ''))
        values = {'value': alert.get('value', ''), 'normal': alert.get('normal', 0), 'share': alert.get('share', ''),
                  'names': ', '.join(item.split(':', 1)[-1] for item in alert.get('names', []))}
        items.append({'kind': alert['kind'], 'level': alert['level'], 'group': alert['group'], 'name': name, 'line': line.format(**values),
                      'since': time.strftime('%H:%M', time.localtime(alert['since'])) if alert.get('since') else '',
                      'easing': alert.get('easing', False), 'top': alert.get('top', []) if role == 'super' else [],
                      'href': url_for('show_page', slug=alert['slug']) + '#' + alert['anchor'] if alert['slug'] in PAGES and alert['anchor'] in commands else None})
    return items


app.jinja_env.globals['threat_view'] = threat_view
app.jinja_env.globals['threat_items'] = threat_items


def gauge_svg(label, value, top, warn, alert, unit=''):
    """A gauge as a half circle: green up to warn, amber up to alert, red above; the needle at the value. No script; the value
    is also the text below it and the label of the picture."""
    def point(share, radius):
        angle = math.pi * (1 - max(0.0, min(1.0, share)))
        return 60 + radius * math.cos(angle), 62 - radius * math.sin(angle)

    def arc(start, end, css):
        (x1, y1), (x2, y2) = point(start, 48), point(end, 48)
        return f'<path class="{css}" d="M{x1:.1f} {y1:.1f}A48 48 0 0 1 {x2:.1f} {y2:.1f}"/>' if end > start else ''

    top = max(top, 1)
    known = value is not None
    shown = round(value) if known else '–'
    zones = arc(0, warn / top, 'z g') + arc(warn / top, min(alert / top, 1), 'z w') + arc(min(alert / top, 1), 1, 'z b')
    nx, ny = point(value / top if known else 0, 40)
    state = 'b' if known and value >= alert else 'w' if known and value >= warn else 'g' if known else 'u'
    needle = f'<line class="needle" x1="60" y1="62" x2="{nx:.1f}" y2="{ny:.1f}"/><circle class="hub" cx="60" cy="62" r="4"/>' if known else ''
    return (f'<figure class="gauge {state}"><svg viewBox="0 0 120 70" role="img" aria-label="{html_escape(label)}: {shown}{unit}">{zones}{needle}</svg>'
            f'<figcaption><b>{shown}{unit}</b><span>{html_escape(label)}</span></figcaption></figure>')


def board_view(status, threat, samples):
    """The lamps and gauges of the dashboard from the status read, the attack check and the load samples of this process."""
    checks = (status or {}).get('checks', {})
    services = (('service:postfix', _('Mail server')), ('service:rspamd', _('Spam filter')), ('service:clamd@scan', _('Virus scanner')),
                ('service:mariadb', _('Database')), ('service:redis', _('Cache')), ('service:valkey', _('Cache')), ('service:unbound', _('DNS resolver')),
                ('service:nginx', _('Web server')), ('service:fail2ban', 'Fail2Ban'), ('service:firewalld', _('Firewall')))
    lamps = [{'label': label, 'state': ('g' if checks[key] else 'b') if status else 'u', 'title': key.split(':', 1)[1]}
             for key, label in services if key in checks or (not status and key != 'service:valkey')]
    milters = [ok for key, ok in checks.items() if key.startswith('milter:')]
    if milters:
        lamps.append({'label': _('Milters'), 'state': 'g' if all(milters) else 'b', 'title': f'{milters.count(True)}/{len(milters)}'})
    others = [key.split(':', 1)[1] for key, ok in checks.items() if key.startswith(('extra:', 'unit:')) and not ok]
    if others:
        lamps.append({'label': _('Other services'), 'state': 'b', 'title': ', '.join(others)})
    kinds = {alert['kind']: alert for alert in (threat or {}).get('alerts', [])}

    def lamp_of(names):
        levels = [kinds[name]['level'] for name in names if name in kinds]
        return 'u' if threat is None else 'b' if 'alert' in levels else 'w' if levels else 'g'

    lamps.append({'label': _('Attacks'), 'state': lamp_of(('smtp_flood', 'syn_flood', 'password_attack', 'reject_wave', 'ban_wave')), 'title': ''})
    lamps.append({'label': _('Spam and viruses'), 'state': lamp_of(('spam_wave', 'virus_wave')), 'title': ''})
    lamps.append({'label': _('Mail queue'), 'state': lamp_of(('queue_flood',)), 'title': ''})
    lamps.append({'label': _('Resources'), 'state': lamp_of(('disk_full', 'memory_low', 'load_high')), 'title': ''})
    last = samples[-1] if samples else {}
    percent, _minutes = load_settings()
    gauges = [gauge_svg(_('CPU'), last.get('cpu'), 100, percent, 95, '%'), gauge_svg(_('RAM'), last.get('ram'), 100, percent, 95, '%'),
              gauge_svg(_('Disk used'), last.get('disk'), 100, 90, 95, '%')]
    values = (threat or {}).get('gauges', {})
    mails, normal = values.get('mails_10'), values.get('mails_normal') or 0
    gauges.append(gauge_svg(_('Mails in 10 min'), mails, max(normal * 4, (mails or 0) * 1.2, 50), max(normal * 2, 40), max(normal * 3, 80)))
    spam = values.get('spam_10')
    gauges.append(gauge_svg(_('Spam share'), round(100 * spam / mails) if mails else (0 if mails == 0 else None), 100, 50, 80, '%'))
    connections, usual = values.get('connections'), values.get('connections_normal') or 0
    gauges.append(gauge_svg(_('SMTP connections per minute'), connections, max(usual * 10, 400, (connections or 0) * 1.2), max(120, usual * 4), max(300, usual * 8)))
    gauges.append(gauge_svg(_('Failed logins in 10 min'), values.get('auth_failed_10'), 150, 30, 100))
    return {'lamps': lamps, 'gauges': gauges, 'checked': time.strftime('%H:%M', time.localtime(threat['checked'])) if threat else None}


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
    standards = loaded.get('standards-show', (False, None))
    if standards[0] and standards[1].get('summary'):
        summary = standards[1]['summary']
        tiles.append(tile('Security standards', f"{summary['fulfilled'] + summary['over']} met, {summary['not']} not",
                          'w' if summary['not'] else '', 'standards', 'standards-show', None, f"checked {standards[1]['checked']}"))
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
    # UI-LINK: each notice of efactl names the page and card of its setting (and a field to fill in, such as the domain).
    attention += [tuple(notice) for notice in (status or {}).get('system_notices', [])]
    # MIG-GREY: each with the card that switches it on.
    attention += [(text, slug, anchor) for text, slug, anchor in (status or {}).get('feature_notices', [])]
    if stats and stats.get('queues', {}).get('warn'):
        attention.append(('Many mails wait in the queues', 'dash', 'status'))
    attention += [(warning, 'rbl', 'rbl-set') for warning in loaded.get('rbl-show', (False, {}))[1].get('warnings', []) if warning.startswith('Terms of use not yet')]
    # UI-1: the texts efactl built with values, in the language of the reader.
    attention = [(runtime_text(item[0]), item[1], item[2], item[3] if len(item) > 3 else {}) for item in attention]
    flow = loaded.get('flow-status', (False, None))
    picture = flow_svg(flow[1], (stats or {}).get('last_hour')) if flow[0] else None
    return tiles, attention, minute_chart(stats['last_hour']) if stats else None, picture


# 9l: the setup as a picture on the start page. Own flat drawings, eFa-next in the colours of the logo, the rest neutral. Text only in
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
    """An eFa-next server in the colours of the logo, with its own key and a status light; the own one with a green marker."""
    if ghost:
        return (f'<g class="ghost" transform="translate({x} {y})" tabindex="0"><title>{ghost} more eFa-next nodes</title>{_flow_server()}'
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
    label = (f"Mail flow: {len(shown)} eFa-next node{'s' if len(shown) != 1 else ''} ({flow['mode']}), {len(flow['targets'])} delivery target"
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


def notice_href(slug, anchor, query, expert, cmd):
    """UI-LINK: the address of a card from a dashboard notice. A card only the expert view shows opens that view."""
    section = next((section for section in PAGES[slug].get('sections', []) if anchor in section[1]), ('', [anchor]))
    hidden = not expert and card_level(anchor, cmd, section, slug) != 'standard'
    return url_for('show_page', slug=slug, **query, **({'view': 'expert'} if hidden else {})) + '#' + anchor


def card_level(name, cmd, section, slug):
    if name in WARNING_CARDS or name in DAILY_LISTS or (slug == 'dash' and len(section) < 3):
        return 'standard'
    # The release upgrade in the standard view too (Hans: the button for every super admin, with the warning). Only super
    # admins have it in their schema at all (efactl SUPER_COMMANDS); every other login gets 403.
    if name in SUPER_COMMANDS:
        return 'standard'
    if len(section) >= 3 and section[2] == 'advanced':
        return 'expert'
    # A read with arguments is a search or a tool with its form, unless the page fills it in by itself.
    if cmd['writes'] or (cmd['args'] and name not in PAGES[slug].get('autoload', ())):
        return 'standard'
    # 6.0.0.6 (Hans): the lists without arguments (users, groups, tenants, sessions, tokens, blocklists ...) in the standard view too.
    if name.endswith(('-list', '-show')):
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
    # A page with its wizard on reads only what the wizard needs; the manual cards stay behind the switch.
    wizard_name = wizard_for(slug, commands)
    wizard_on = bool(wizard_name) and slug not in manual_pages()
    # The same reads in both views: the view only hides cards, the visible ones (and the tiles) need the same values.
    shown = [] if wizard_on else names
    for name in (wizard_reads(wizard_name, commands) if wizard_on else shown + page.get('load', []) + (['flow-status'] if FLOW_PICTURE and slug == 'dash' else [])):
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
    # 9o: the red banner of the CVE watch, in the standard view too.
    cve_banner = [runtime_text(text) for text in (loaded.get('status', (False, {}))[1] or {}).get('cve_banner', [])] if slug == 'dash' else []
    running = loaded.get('update-status', (False, {}))[1].get('state') in ('running', 'rebooting')
    percent, minutes = load_settings()
    rows, advice = load_view(load_samples, percent, minutes)
    load_html = render_template_string(LOAD_CARD, rows=rows, advice=advice, last=load_samples[-1] if load_samples else None, extra=load_extra() if rows else None)
    board_html = render_template_string(STATUS_BOARD, board=board_view(loaded['status'][1] if loaded.get('status', (False,))[0] else None, threat_current(), load_samples)) \
        if slug == 'dash' and not PORTAL and 'threat-status' in commands else None
    # The portal serves only the page of the role user (show_page), so it lists no other.
    allowed = [(group, [p for p in pages if set(p['commands']) & set(commands) and (not PORTAL or p['slug'] == USER_PAGE)]) for group, pages in NAV]
    merged = {STATUS_OF[name] for name in names if name in STATUS_OF and STATUS_OF[name] in names}
    pick = form_picks(shown, commands)
    wizard = wizard_view(wizard_name, loaded, commands) if wizard_on else None
    html = render_template_string(MAIN, wizard=wizard, wizard_name=wizard_name, load_html=load_html, board_html=board_html, nav=[(group, pages) for group, pages in allowed if pages], page=page, names=names, commands=commands, loaded=loaded, values=values,
                                  hidden_cards=HIDDEN_CARDS, current=current, choices=CHOICES, option_text=OPTION_TEXT, ruf_warning=RUF_WARNING, current_info=CURRENT, danger=DANGER, tiles=tiles,
                                  attention=attention, cve_banner=cve_banner, chart=chart, flow_picture=flow_picture, pages_by_slug=PAGES, csrf=csrf_token(), result=result, result_name=result_name, merged=merged, status_of=STATUS_OF,
                                  badge=status_badge, without_badge=without_badge, switch_arg=switch_arg, card_level=card_level, notice_href=notice_href, warnings_of=warnings_of, expert=PORTAL or reader_view() == 'expert', note_short=NOTE_SHORT, short_results=SHORT_RESULTS, pick=pick, pick_domain_commands=PICK_DOMAIN_COMMANDS,
                                  result_title=result_title, error=error, shown_now=shown_now, reauth_commands=REAUTH_COMMANDS,
                                  hardening_link=slug == 'sec' and wizard_for('standards', commands) == 'hardening')
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
    if request.args.get('view') == 'expert' and not PORTAL:
        # 9f: a hit of the search in a section of the expert view opens that view.
        session['view'] = 'expert'
    sid, _since, found = results.pop(request.args.get('r', ''), (None, 0, {}))
    # A result belongs to the session that ran the action.
    if found and sid == session.get('sid'):
        return page_view(slug, **found)
    return page_view(slug)


# 9f: the search of the admin interface over pages, cards, fields, help texts and the values of pulldowns, in English and in
# the language of the reader. Only what the rights of the reader show. The terms are posted, so they appear in no log.
SEARCH_SYNONYMS = {'allow': ('whitelist', 'allowlist', 'erlauben', 'zulassen'), 'block': ('blacklist', 'denylist', 'sperren', 'sperrliste'),
                   'release': ('freigeben', 'deliver', 'zustellen'), 'sender': ('absender',), 'spam': ('junk',), 'virus': ('malware', 'antivirus', 'clamav'), 'quarantine': ('held', 'quarantaene'),
                   'password': ('passwort', 'kennwort'), 'user': ('benutzer', 'account', 'login'), 'backup': ('sicherung',),
                   'certificate': ('zertifikat', 'tls', 'lets encrypt'), 'firewall': ('ports',), 'signature': ('dkim', 'disclaimer'),
                   'mail log': ('maillog', 'protokoll'), 'tenant': ('mandant',), 'domain': ('domains',)}
SEARCH_LIMIT = 30


def search_norm(text):
    """Lower case, the umlauts and ß spelt out, other accents gone: Größe, groesse and GROSSE find each other."""
    import unicodedata
    text = str(text or '').lower().replace('ä', 'ae').replace('ö', 'oe').replace('ü', 'ue').replace('ß', 'ss')
    return ''.join(char for char in unicodedata.normalize('NFKD', text) if not unicodedata.combining(char))


def search_index(commands, nav, notes_of, tr):
    """(page, card, label, weight, text) of everything the reader may see: page, section and card titles, field labels, choices
    and notes, each in English and translated."""
    entries = []
    for _group, pages in nav:
        for page in pages:
            entries.append((page['slug'], None, page['title'], 3, search_norm(f"{page['title']} {tr(page['title'])} {page.get('sub', '')} {tr(page.get('sub', ''))}")))
            for section in page.get('sections') or [(page['title'], page.get('commands', []))]:
                for name in section[1]:
                    cmd = commands.get(name)
                    if not cmd or name in HIDDEN_CARDS:
                        continue
                    text = f"{page['title']} {tr(page['title'])} {section[0]} {tr(section[0])} {cmd['title']} {tr(cmd['title'])} {name} {notes_of(page).get(name, '')}"
                    entries.append((page['slug'], name, cmd['title'], 2, search_norm(text)))
                    for arg in cmd.get('args', []):
                        labels = ' '.join(f"{item.get('label', '')} {tr(item.get('label', ''))}" for item in arg.get('choices', []))
                        entries.append((page['slug'], name, f"{cmd['title']}: {arg.get('label', arg['name'])}", 1,
                                        search_norm(f"{arg.get('label', '')} {tr(arg.get('label', ''))} {labels}")))
    return entries


def search_hits(query, entries):
    """The entries that hold every word of the query (or a synonym), best first; parts of words count."""
    words = [word for word in search_norm(query).split() if word][:6]
    if not words:
        return []
    options = []
    for word in words:
        found = (word,)
        for key, synonyms in SEARCH_SYNONYMS.items():
            group = tuple(search_norm(item) for item in (key,) + synonyms)
            if word in group:
                found += group
        options.append(found)
    hits, seen = [], set()
    for slug, card, label, weight, text in entries:
        score, spaced = 0, ' ' + text
        for group in options:
            if not any(option in text for option in group):
                break
            score += weight * (2 if any(' ' + option in spaced for option in group) else 1)
        else:
            if (slug, card, label) not in seen:
                seen.add((slug, card, label))
                hits.append((score, slug, card, label))
    hits.sort(key=lambda hit: (-hit[0], hit[1], hit[3]))
    return [{'slug': slug, 'card': card, 'label': label} for _score, slug, card, label in hits[:SEARCH_LIMIT]]


search_cache = {}
# The address of the index changes with the code, the language and the rights.
SUGGEST_CODE = str(int(os.path.getmtime(os.path.abspath(__file__))))


def readable_nav(commands):
    """The menu as the reader sees it: only pages with a command the schema of the reader holds."""
    return [(group, [p for p in pages if set(p['commands']) & set(commands)]) for group, pages in NAV]


def suggest_index(commands, nav, tr):
    """6.0.0.6: the suggestions of the search: the pages, settings and actions the reader may open, each with one line that
    explains it (the page line, or the first sentence of its help text in efa_help) and the words it is found by."""
    items = []
    for _group, pages in nav:
        for page in pages:
            title, sub = tr(page['title']), tr(page.get('sub', ''))
            items.append({'g': 'page', 't': title, 'e': sub, 'u': url_for('show_page', slug=page['slug']),
                          'k': search_norm(f"{page['title']} {title} {page.get('sub', '')} {page['slug']}")})
            for section in page.get('sections') or [(page['title'], page.get('commands', []))]:
                for name in section[1]:
                    cmd = commands.get(name)
                    if not cmd or name in HIDDEN_CARDS:
                        continue
                    help_text = efa_help.CARD.get(name, '')
                    labels = ' '.join(f"{arg.get('label', '')} {tr(arg.get('label', ''))}" for arg in cmd.get('args', []))
                    items.append({'g': 'action' if name in FORM_NEW else 'setting', 't': efa_help.short_title(tr(cmd['title'])), 'p': title,
                                  'e': efa_help.first_sentence(tr(help_text)) if help_text else '',
                                  'u': url_for('show_page', slug=page['slug'], **({} if card_level(name, cmd, section, page['slug']) == 'standard' else {'view': 'expert'})) + '#' + name,
                                  'k': search_norm(f"{cmd['title']} {section[0]} {tr(section[0])} {name} {labels} {help_text}")})
    return items


def suggest_key(commands):
    return hashlib.sha256(f"{SUGGEST_CODE} {reader_language()} {' '.join(sorted(commands))}".encode()).hexdigest()[:20]


def suggest_url(commands):
    return url_for('search_suggest', v=suggest_key(commands)) if commands else ''


app.jinja_env.globals['suggest_url'] = suggest_url


@app.route('/search/index.json')
def search_suggest():
    """The suggestions of the search for this login and language, one file the browser keeps; nothing per keystroke."""
    if PORTAL:
        abort(404)
    ok, commands = efactl_read('schema')
    if not ok:
        abort(503)
    key = ('suggest', suggest_key(commands))
    if key not in search_cache:
        if len(search_cache) > 50:
            search_cache.clear()
        search_cache[key] = json.dumps({'items': suggest_index(commands, readable_nav(commands), _), 'syn': SEARCH_SYNONYMS,
                                        'mail': 'maillog-search' in commands, 'log': url_for('show_page', slug='log')}, separators=(',', ':'))
    # Built once per rights and language here; the page fetches it once, at the first focus. Like every page: no-store (harden).
    return Response(search_cache[key], mimetype='application/json')


SEARCH_PAGE = PAGE.replace(BLOCK, SOLO + """<div class="card"><h2>{{ _('Search') }}: {{ query }}</h2>{% if hits %}<ul>{% for hit in hits %}
<li><a href="{{ url_for('show_page', slug=hit.slug, view='expert') }}{% if hit.card %}#{{ hit.card }}{% endif %}">{{ pages[hit.slug].title|t }}{% if hit.card %} &rsaquo; {{ hit.label|t }}{% endif %}</a></li>
{% endfor %}</ul>{% else %}<p>{{ _('Nothing found.') }}</p>{% endif %}<p><a href="{{ url_for('show_page', slug='dash') }}">{{ _('Back') }}</a></p></div></main>""")


@app.route('/search', methods=['POST'])
def search():
    if PORTAL:
        abort(404)
    ok, commands = efactl_read('schema')
    if not ok:
        abort(503)
    nav = readable_nav(commands)
    query = request.form.get('q', '')[:200]
    # The index of a language and a set of rights, built once: the search itself then takes a few milliseconds.
    key = (reader_language(), hashlib.sha256(' '.join(sorted(commands)).encode()).hexdigest())
    if key not in search_cache:
        if len(search_cache) > 50:
            search_cache.clear()
        search_cache[key] = search_index(commands, nav, lambda page: page.get('notes', {}), _)
    hits = search_hits(query, search_cache[key])
    if len(hits) == 1:
        hit = hits[0]
        return redirect(url_for('show_page', slug=hit['slug'], view='expert') + (f"#{hit['card']}" if hit['card'] else ''), code=303)
    return render_template_string(SEARCH_PAGE, query=query, hits=hits, pages=PAGES)


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
    efactl('audit-rspamd', f"--client={client_address()}")
    return redirect('/rspamd/')


@app.route('/backup/download', methods=['POST'])
def backup_download():
    """A backup holds the database and private keys, so the admin password is asked again."""
    client = client_address()
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
    read_end, write_end = os.pipe()
    sock = runner_stream(acting_as() + ['backup-read', f'--name={name}'], stdout=write_end)
    os.close(write_end)
    if sock is None:
        os.close(read_end)
        return page_view('bak', error='The service efactl-runner does not answer, see the log.')
    reader = os.fdopen(read_end, 'rb')

    def chunks():
        try:
            while True:
                chunk = reader.read(65536)
                if not chunk:
                    return
                yield chunk
        finally:
            reader.close()
            ok, out = stream_reply(sock)
            if not ok:
                app.logger.error('backup %s download failed: %s', name, out.get('error'))
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
    try:
        export = open(f'/var/lib/efa-exports/{job}.zip', 'rb')
    except OSError:
        abort(404)

    def chunks():
        # Streamed: an export of many mails never sits in memory as a whole.
        with export:
            while chunk := export.read(65536):
                yield chunk
    return Response(chunks(), mimetype='application/zip', headers={'Content-Disposition': f'attachment; filename="headers-{job[:8]}.zip"',
                                                                    'Content-Length': str(os.fstat(export.fileno()).st_size)})


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
    data = upload.read(210 * 1024)
    read_end, write_end = os.pipe()
    sock = runner_stream(acting_as() + ['tenant-brand-set', f'--tenant={tenant}', '--logo_file=-'], stdin=read_end)
    os.close(read_end)
    if sock is None:
        os.close(write_end)
        return page_view('tenants', error='The service efactl-runner does not answer, see the log.')
    try:
        with os.fdopen(write_end, 'wb') as pipe:
            pipe.write(data)
    except BrokenPipeError:
        pass  # efactl read what it takes; its answer says why
    ok, output = stream_reply(sock)
    if not ok:
        return page_view('tenants', error=output.get('error') or 'The upload failed, see the log.')
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
    # The size first (Werkzeug keeps the upload in a temp file): a call that has started would store a cut-off backup.
    # MAX_UPLOAD is the second guard behind MAX_CONTENT_LENGTH.
    upload.stream.seek(0, os.SEEK_END)
    if upload.stream.tell() > MAX_UPLOAD:
        return page_view('bak', error='The backup is larger than allowed.')
    upload.stream.seek(0)
    read_end, write_end = os.pipe()
    sock = runner_stream(acting_as() + ['backup-import'], stdin=read_end)
    os.close(read_end)
    if sock is None:
        os.close(write_end)
        return page_view('bak', error='The service efactl-runner does not answer, see the log.')
    # Streamed to efactl in chunks, never read whole into memory.
    try:
        with os.fdopen(write_end, 'wb') as pipe:
            while True:
                chunk = upload.stream.read(1024 * 1024)
                if not chunk:
                    break
                pipe.write(chunk)
    except (BrokenPipeError, OSError):
        pass  # efactl stopped reading; its answer says why
    ok, output = stream_reply(sock)
    if not ok:
        return page_view('bak', error=output.get('error') or 'The upload failed, see the log.')
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
    # The time of the server: the live log shows the age of each mail from it, in any time zone of the browser.
    return Response(json.dumps({**output, 'now': time.strftime('%Y-%m-%d %H:%M:%S')}), mimetype='application/json')


@app.route('/mailui.js')
def mailui_js():
    return Response(MAILUI_JS, mimetype='text/javascript')


@app.route('/senders/check', methods=['POST'])
def senders_check():
    """What Allow or Block would do, for the confirm dialog of the mail views. Posted: the address is in no log."""
    ok, output = efactl('sender-action-check', *[f"--{key}={request.form.get(key, '')}" for key in ('value', 'list', 'recipients', 'qid')])
    if not ok:
        return Response(json.dumps({'ok': False, 'error': output.get('error')}), mimetype='application/json')
    output = {**output, 'target_text': runtime_text(output.get('target_text', '')), 'warnings': [runtime_text(text) for text in output.get('warnings', [])]}
    return Response(json.dumps({'ok': True, 'result': output}), mimetype='application/json')


@app.route('/threat-banner')
def threat_banner():
    """The banner alone, for the page to renew it every minute while it is visible; it reads only the kept answer."""
    ok, commands = efactl_read('schema')
    return render_template_string(THREAT_BANNER, commands=commands if ok else {})


@app.route('/status-board')
def status_board():
    ok, commands = efactl_read('schema')
    if not ok or 'threat-status' not in commands:
        abort(403)
    status = efactl_read('status')
    return render_template_string(STATUS_BOARD, board=board_view(status[1] if status[0] else None, threat_current(), load_samples))


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


PASSKEY_JS = """(function () {
  // 5s: the own small script of the passkeys. Without it the login with password and TOTP works as before.
  if (!window.PublicKeyCredential) return;
  function bytes(text) { var s = atob(text.replace(/-/g, '+').replace(/_/g, '/')); var a = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) a[i] = s.charCodeAt(i); return a.buffer; }
  function text(buffer) { var a = new Uint8Array(buffer), s = ''; for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
    return btoa(s).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, ''); }
  function post(url, data) { var body = new URLSearchParams(data);
    return fetch(url, {method: 'POST', body: body, credentials: 'same-origin'}).then(function (r) { if (!r.ok) throw new Error('refused'); return r.json(); }); }
  var login = document.getElementById('passkey-login');
  if (login) {
    login.hidden = false;
    login.addEventListener('click', function () {
      var form = login.form;
      post('/passkey/options', {csrf: form.csrf.value, username: form.username.value}).then(function (options) {
        var key = options.publicKey;
        key.challenge = bytes(key.challenge);
        key.allowCredentials = (key.allowCredentials || []).map(function (c) { return {type: c.type, id: bytes(c.id)}; });
        return navigator.credentials.get({publicKey: key}).then(function (cred) {
          form.assertion.value = JSON.stringify({handle: options.handle, id: cred.id, client_data: text(cred.response.clientDataJSON),
            auth_data: text(cred.response.authenticatorData), signature: text(cred.response.signature)});
          form.submit();
        });
      }).catch(function () { var e = document.getElementById('passkey-error'); if (e) e.hidden = false; });
    });
  }
  var add = document.getElementById('passkey-add');
  if (add) {
    add.hidden = false;
    add.addEventListener('click', function () {
      var form = add.form;
      post('/passkey/register-options', {csrf: form.csrf.value}).then(function (options) {
        var key = options.publicKey;
        key.challenge = bytes(key.challenge);
        key.user.id = bytes(key.user.id);
        key.excludeCredentials = (key.excludeCredentials || []).map(function (c) { return {type: c.type, id: bytes(c.id)}; });
        return navigator.credentials.create({publicKey: key}).then(function (cred) {
          form.attestation.value = text(cred.response.attestationObject);
          form.client_data.value = text(cred.response.clientDataJSON);
          form.submit();
        });
      }).catch(function () { var e = document.getElementById('passkey-error'); if (e) e.hidden = false; });
    });
  }
})();
"""


@app.route('/copy.js')
def copy_js():
    # A file of its own, because the security header forbids inline scripts.
    return Response(COPY_JS, mimetype='text/javascript')


@app.route('/passkey.js')
def passkey_js():
    return Response(PASSKEY_JS, mimetype='text/javascript')


@app.route('/passkey/options', methods=['POST'])
def passkey_options():
    """5s: before a login, the challenge for a passkey; the CSRF token of the login page is checked like any form."""
    ok, options = efactl('passkey-login-options', f"--username={request.form.get('username', '').strip()[:100]}")
    return (jsonify(options), 200) if ok else (jsonify(error=options.get('error')), 400)


@app.route('/passkey/register-options', methods=['POST'])
def passkey_register_options():
    ok, options = efactl('passkey-register-options')
    return (jsonify(options), 200) if ok else (jsonify(error=options.get('error')), 400)


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
        if values.get(arg['name'] + '__clear') == 'on' and efa_help.web_label(arg.get('label', ''), arg.get('kind'))['clear']:
            value = '-'  # M5: the tick box Clear of the form, the - of the console
        if arg['name'] == 'groups' and command['name'] == 'user-set' and hasattr(values, 'getlist') and len(values.getlist('groups')) > 1:
            value = ','.join(values.getlist('groups'))
        if arg.get('secret'):
            # A secret is one line on stdin: one of several lines (the URLs of SecuriteInfo) goes in base64.
            secret_lines.append(base64.b64encode(value.encode()).decode() if arg.get('multiline') and value else value)
        else:
            # A text area of the browser sends CRLF; efactl takes lines only where its table allows them (arg_lines_problem).
            args += [f"--{arg['name']}=" + str(value).replace('\r\n', '\n')]
    return efactl(*args, secrets_in=secret_lines)


# Binary streams with their own route and password check. The others are for the web interface itself.
NOT_CALLABLE = ('audit-note', 'refusal-note', 'threat-run', 'backup-read', 'backup-import', 'user-verify', 'admin-2fa-verify', 'setup-variant-apply', 'totp-import', 'console-2fa-verify', 'passkey-login', 'passkey-login-options', 'passkey-register-options', 'token-check', 'oidc-start', 'oidc-finish', 'uq-link-view', 'uq-link-use', 'session-open', 'session-check')


# Results of actions, until the page after the redirect shows them: a reload then shows the page, it does not run the action again.
results = {}
RESULT_SECONDS = 600
RESULT_KEEP = 200
CSV_NAMES = {'message-search': 'messages.csv', 'tenant-usage': 'tenant-usage.csv', 'dkim-selectors': 'dkim-selectors.csv'}
TEXT_NAMES = {'mta-sts-text': 'mta-sts.txt', 'security-txt': 'security.txt', 'outlook-addin': 'efa-next-report-manifest.xml'}
JSON_NAMES = {'message-search': 'messages.json', 'tenant-usage': 'tenant-usage.json', 'report-show': 'report.json', 'dkim-selectors': 'dkim-selectors.json'}


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
    if ok and name in SUPER_COMMANDS and name not in commands:
        if request.method == 'POST':
            efactl('refusal-note', f'--command={name}')  # into the audit log, without the values; a GET never runs anything
        abort(403)
    if not ok or name not in commands or name in NOT_CALLABLE:
        abort(404)
    if request.method == 'GET':
        # A reload, a link or the back button: show the form with its button, never run the action.
        return redirect(url_for('show_page', slug=page_of(name)) + '#' + name, code=303)
    if name in REAUTH_COMMANDS and not reauth_ok(request.form):
        return result_store(page_of(name), error='Confirm this change with your password.')
    own_reauth = any(arg['name'] == 'reauth' for arg in commands[name]['args'])
    client = client_address()
    count, since = login_failures.get(client, (0, 0))
    if own_reauth and count >= MAX_LOGIN_FAILURES and time.time() - since < LOCKOUT_SECONDS:
        return result_store(page_of(name), error='Too many failed logins, try again later.')
    ok, output = call_command({**commands[name], 'name': name}, request.form)
    if own_reauth and not ok and output.get('error') == REAUTH_FAILED:
        login_failures[client] = (count + 1, time.time())
        # Fail2Ban reads this line.
        app.logger.warning('efa-web login failed from %s', client)
    if request.form.get('json') == '1' and name in JSON_RUN:
        # 6.0.0.6: the mail views stay on the page; the answer feeds the toast with its undo.
        if ok and name == 'sender-action':
            output = {**output, 'target_text': runtime_text(output.get('target_text', ''))}
        return Response(json.dumps({'ok': ok, 'result': output if ok else None, 'error': None if ok else output.get('error')}), mimetype='application/json')
    if ok and name == 'totp-confirm':
        session.pop('no_2fa', None)
    if ok and name == 'totp-disable':
        session['no_2fa'] = True
    if ok and name == 'my-settings-set':
        session['lang'] = output.get('language', 'auto')
    if ok and name == 'report-show' and 'html' in output:
        return Response(output['html'], mimetype='text/html')
    if ok and name in JSON_NAMES and 'json' in output:
        return Response(output['json'], mimetype='application/json', headers={'Content-Disposition': f'attachment; filename="{JSON_NAMES[name]}"'})
    if ok and name in TEXT_NAMES and 'text' in output:
        return Response(output['text'], mimetype='text/plain', headers={'Content-Disposition': f'attachment; filename="{TEXT_NAMES[name]}"'})
    if ok and name in CSV_NAMES and 'csv' in output:
        return Response(output['csv'], mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename="{CSV_NAMES[name]}"'})
    if not ok:
        return result_store(page_of(name), error=output.get('error'))
    if name == 'totp-setup' and 'qr_svg' in output:
        # The SVG is made by efa_qr from the otpauth address: only rects and a path, nothing of the user in it.
        return Response(TOTP_PAGE.format(title=html_escape(_('2FA: set up the app')), svg=output['qr_svg'], secret=html_escape(output['secret']),
                                         hint=html_escape(_('Scan the code with the app, or type the key. Then confirm with the first code it shows.')),
                                         back=url_for('show_page', slug=USER_PAGE if PORTAL else 'account') + '#totp-confirm', more=html_escape(_('Back, to confirm'))),
                        mimetype='text/html')
    if ok and name == 'totp-confirm':
        session.pop('totp_setup', None)
    if ok and name in FILE_COMMANDS and isinstance(output.get('file'), str):
        safe = re.sub(r'[^\w.\-]', '_', str(output.get('name', 'file')))[:100] or 'file'
        return Response(base64.b64decode(output['file']), mimetype='application/octet-stream',
                        headers={'Content-Disposition': f'attachment; filename="{safe}"', 'X-Content-Type-Options': 'nosniff'})
    if isinstance(output.get('pdf'), str) and str(output.get('name', '')).endswith('.pdf') and name in PDF_COMMANDS:
        return Response(base64.b64decode(output['pdf']), mimetype='application/pdf', headers={'Content-Disposition': f'attachment; filename="{output["name"]}"'})
    if not commands[name]['writes'] and name in READ_CACHE_SECONDS and not strict_on():
        # Loaded by its button: the pages after this show it from the cache.
        _read_store(read_key(acting_as(), name), (True, output))
    return result_store(page_of(name), result=output, result_title=commands[name]['title'], result_name=name)


# Answered as JSON when the page asks for it (json=1): the actions of the mail log, the live log and the quarantine.
JSON_RUN = {'sender-action', 'quarantine-release', 'quarantine-delete'}
# Commands whose output can be a PDF to download.
PDF_COMMANDS = {'incident-report', 'privacy-evidence', 'report-show'}
# Commands whose output is a file to save (5n): always as a download, never shown in the browser.
FILE_COMMANDS = {'emergency-file'}
TOTP_PAGE = ('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title>'
             '<style>body{{font:15px/1.5 system-ui,sans-serif;max-width:32rem;margin:2rem auto;padding:0 1rem}}svg{{width:16rem;height:auto}}'
             'code{{font-size:1.1rem;letter-spacing:1px}}</style></head><body><h1>{title}</h1><p>{hint}</p><p>{svg}</p><p><code>{secret}</code></p>'
             '<p><a href="{back}">{more}</a></p></body></html>')


# 6.0.0.5: Re-Setup, the questions of the setup for a running system (efactl resetup): first the comparison of old and new, then
# apply with the password and the 2FA code; from guided to manual both are asked anew. The texts are those of the setup wizard.
RESETUP_CSS = ('body{font:15px/1.5 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;background:#fff;color:#1d1d1b}'
               'input:not([type]),input[type=password]{display:block;width:100%;max-width:24rem;padding:.3rem}button{margin:.5rem .5rem 0 0;padding:.4rem 1rem}'
               '.err{color:#b00}th{text-align:left;padding-right:1rem}@media (prefers-color-scheme: dark){body{background:#1e1f1d;color:#e6e7e3}'
               'a{color:#c0cf48}.err{color:#ff8f7a}}')


def resetup_page(body, error=None):
    error_html = f'<p class="err" role="alert">{html_escape(error)}</p>' if error else ''
    back = url_for('show_page', slug='sec') + '#setup-variant-status'
    return Response(f'<!doctype html><html lang="{g.lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
                    f'<title>{html_escape(_("Re-Setup: EU link, frameworks and 2FA"))}</title><style>{RESETUP_CSS}{efa_setup.CHIPS_CSS}</style></head><body>'
                    f'<h1>{html_escape(_("Re-Setup: EU link, frameworks and 2FA"))}</h1>{error_html}{body}<p><a href="{back}">{html_escape(_("Back"))}</a></p>'
                    '</body></html>', mimetype='text/html')


def resetup_rows(rows):
    return ''.join(f'<tr><th>{html_escape(str(key))}</th><td>{html_escape(str(old))}</td><td>{html_escape(str(new))}</td></tr>' for key, old, new in rows)


@app.route('/resetup', methods=['GET', 'POST'])
def resetup_view():
    if 'lang' not in g:
        g.lang = reader_language()
    ok, state = efactl('setup-variant-status')
    if not ok:
        return resetup_page('', state.get('error'))
    form, posted = request.form, request.method == 'POST'
    variant = form.get('variant', state['variant']) if posted else state['variant']
    eulink = form.get('eulink', state['eulink']) if posted else state['eulink']
    frameworks = efa_setup.frameworks_clean(form.getlist('frameworks') if posted else state['frameworks'])
    note = (form.get('note', '') if posted else state['note']).strip()
    error, result, applied = None, None, posted and form.get('apply') == 'yes'
    if posted:
        if form.get('notice') != 'yes':
            error = _('Please confirm the note to go on.')
        elif eulink == 'no' and (form.get('noeu') != 'yes' or not efa_setup.phrase_ok(form.get('phrase', ''))):
            error = _('Tick the box and type the phrase to confirm.')
        elif applied:
            if state['variant'] == 'guided' and variant == 'manual':
                session.pop('reauth', None)  # guided to manual: password and 2FA code anew, not the five minutes of before
            if not reauth_ok(form):
                error = _('Wrong password or 2FA code. With 2FA set up, enter the code of the app too.')
        if error is None:
            args = ['resetup', f'--variant={variant}', f'--eulink={eulink}', '--notice=' + efa_setup.confirmation(efa_setup.notice_digest(_)),
                    f'--lang={g.lang}', '--frameworks=' + ','.join(frameworks), f'--note={note}']
            if eulink == 'no':
                args.append('--noeu=' + efa_setup.confirmation(efa_setup.noeu_digest(_, g.lang)))
            ok, result = efactl(*(args + (['--apply=yes'] if applied else [])))
            if not ok:
                error, result = result.get('error'), None
    body = (f'<form method="post" action="{url_for("resetup_view")}"><input type="hidden" name="csrf" value="{csrf_token()}">'
            + efa_setup.notice_html(_, posted and form.get('notice') == 'yes') + efa_setup.variant_html(_, variant) + efa_setup.eulink_html(_, eulink)
            + efa_setup.noeu_html(_, g.lang, required=False, checked=posted and form.get('noeu') == 'yes', typed=form.get('phrase', '') if posted else '')
            + efa_setup.frameworks_html(_, frameworks, note))
    if result and applied:
        body += (f'<h2>{html_escape(_("Done"))}</h2><table>{resetup_rows(result.get("raised", []))}</table>'
                 + ''.join(f'<p>{html_escape(text)}</p>' for text in result.get('notes', [])) + f'<p>Backup: {html_escape(str(result.get("backup", "")))}</p>')
    elif result:
        body += (f'<h2>{html_escape(_("Old and new"))}</h2><table>{resetup_rows(result.get("compare", []))}{resetup_rows(result.get("raised", []))}</table>'
                 + ''.join(f'<p>{html_escape(text)}</p>' for text in result.get('notes', []))
                 + f'<label>{html_escape(_("Your password, to confirm"))} <input type="password" name="reauth" autocomplete="current-password"></label>'
                 f'<label>{html_escape(_("2FA code, if you set one up"))} <input name="reauth_code" inputmode="numeric" autocomplete="one-time-code" maxlength="20"></label>'
                 f'<button name="apply" value="yes">{html_escape(_("Apply"))}</button>')
    return resetup_page(body + f'<button>{html_escape(_("Compare"))}</button></form>', error)


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


# Guided wizards (efa_wizard): a page with a wizard shows it first, under its title; "Manual" opens the full cards. The choice
# is kept per login and page in My settings (my-settings-set --manual). A wizard ends in one efactl call of the manual cards,
# with the same checks and rights; its draft stays here, bound to the session, until it is applied.
wizard_drafts = {}
wizard_lock = threading.Lock()
WIZARD_SECONDS = 3600
WIZARD_KEEP = 200
WIZARD_JS = """(function () {
  // The connection test of a wizard runs in the background: ask for its state, show the page again when it is done.
  var box = document.querySelector('[data-poll]'), tries = 0;
  if (!box) { return; }
  (function ask() {
    fetch(box.getAttribute('data-poll'), {credentials: 'same-origin'}).then(function (answer) { return answer.json(); }).then(function (state) {
      if (state.state !== 'running') { location.reload(); } else if (++tries < 20) { setTimeout(ask, 500); }
    }).catch(function () {});
  })();
})();
"""


def manual_pages():
    """The pages with a wizard where this login wants the manual cards, from My settings, kept in the session."""
    if 'manual' not in session and session.get('admin'):
        ok, prefs = efactl('my-settings')
        session['manual'] = prefs.get('manual', []) if ok and isinstance(prefs.get('manual'), list) else []
    return session.get('manual', [])


def wizard_for(slug, commands):
    """The wizard of a page this login may use (its command is in its schema), or None. A command that needs the password again
    only in a wizard that asks for it (reauth) on its last step, as the manual card does."""
    name = efa_wizard.PAGES.get(slug)
    return name if name and not PORTAL and efa_wizard.WIZARDS[name]['command'] in commands \
        and (efa_wizard.WIZARDS[name].get('reauth') or efa_wizard.WIZARDS[name]['command'] not in REAUTH_COMMANDS) else None


def wizard_reads(name, commands):
    return [read for read in ['settings', 'tenant-list'] + efa_wizard.WIZARDS[name]['reads'] if read in commands or read == 'settings']


def wizard_draft(name):
    now = time.time()
    with wizard_lock:
        for key in [key for key, draft in wizard_drafts.items() if draft['at'] < now - WIZARD_SECONDS] + list(wizard_drafts)[:-WIZARD_KEEP]:
            wizard_drafts.pop(key, None)
        draft = wizard_drafts.setdefault((session.get('sid'), name), {'values': {}})
        draft['at'] = now
    return draft


def wizard_context(loaded):
    """What the fields of a wizard may choose: the domains and tenants of this login, its disclaimers and archive targets."""
    status = lambda read: loaded[read][1] if loaded.get(read) and loaded[read][0] and isinstance(loaded[read][1], dict) else {}  # noqa: E731
    tenants = status('tenant-list').get('tenants', [])
    domains = sorted({domain for item in tenants for domain in item.get('domains', [])} | set(status('settings').get('transports') or {}))
    return {'loaded': loaded, 'settings': status('settings'), 'domains': [(item, item) for item in domains],
            'tenants': [(item['name'], item['name']) for item in tenants],
            'templates': [(efa_wizard.NEW, _('New disclaimer'))] + [(item['id'], f"{item['id']}: {item.get('name') or item.get('scope')}")
                                                                   for item in status('disclaimer-status').get('templates', []) if item.get('scope') != 'group'],
            'targets': [(efa_wizard.NEW, _('New archive target'))] + [(item['name'], f"{item['name']}: {item.get('host')}")
                                                                     for item in status('archive-status').get('targets', [])],
            'fetch': lambda *args: efactl(*args)}


def wizard_now(name, draft, context):
    """What is set now for the object of the draft, read once per object."""
    key = json.dumps([draft['values'].get(field['name']) for field in efa_wizard.fields(name) if field.get('resets')] + sorted(draft.get('fetched', {})))
    if draft.get('now_key') != key:
        draft['now'], draft['now_key'] = efa_wizard.current(name, draft['values'], context), key
    return draft['now']


def wizard_view(name, loaded, commands):
    """One step of the wizard, filled from its draft and the configuration, for the template."""
    wizard, draft = efa_wizard.WIZARDS[name], wizard_draft(name)
    # What the steps before read for this draft (wizard_fetch), so the page itself reads only the reads of the wizard.
    loaded = {**{read: found[:2] for read, found in draft.get('fetched', {}).items()}, **loaded}
    context = wizard_context(loaded)
    ids = efa_wizard.step_ids(name)
    step = next((item for item in wizard['steps'] if item['id'] == request.args.get('w')), wizard['steps'][0])
    # A step after the first only with its object chosen: an old link starts at the beginning.
    if step['id'] != ids[0] and not all(field['name'] in draft['values'] for field in efa_wizard.fields(name, ids[0])):
        step = wizard['steps'][0]
    now = wizard_now(name, draft, context)
    draft['values'] = efa_wizard.prefill(name, draft['values'], context, now)
    values = draft['values']
    helps = efa_help.WIZARD.get(name, {})
    shown = []
    for field in step['fields']:
        if efa_wizard.visible(field, values):
            items = [(value, translate(text)) for value, text in efa_wizard.choices(field, context)]
            extra = {}
            if field.get('source') == 'standards':
                rows = efa_wizard._std_choices(context)
                extra['groups'] = [{'title': translate(group), 'opts': [{'value': sid, 'text': title, 'version': version, 'status': status,
                                                                         'summary': translate(efa_harden.SUMMARY.get(sid, ''))}
                                                                        for sid, title, version, in_group, status in rows if in_group == group]}
                                   for group, _ids in efa_harden.GROUPS]
            if field.get('item'):
                table = efa_harden.OS_ITEMS if field['name'].startswith('os_') else efa_harden.EFA_ITEMS
                extra.update(state=efa_wizard._harden_state(context, table, field['item']), warn=translate(table[field['item']].get('warn', '')))
            shown.append({'state': None, 'warn': '', **field, **extra, 'options': items, 'value': values.get(field['name'], ''),
                          'help': translate(helps.get(field['name'], ''))})
    test = wizard.get('test') if step.get('test') and wizard.get('test') in commands else None
    return {'name': name, 'title': wizard['title'], 'help': translate(helps.get('', '')), 'steps': wizard['steps'], 'step': step,
            'step_help': translate(helps.get('step:' + step['id'], '')), 'fields': shown, 'draft': values, 'first': step['id'] == ids[0],
            'last': step['id'] == ids[-1], 'problem': draft.pop('problem', None), 'result': draft.get('result'), 'test': test,
            'tested': draft.get('test'), 'now': now, 'rows': efa_wizard.changes(name, values, context, now) if step['id'] == ids[-1] else [],
            'reauth': bool(wizard.get('reauth')), 'summary': wizard.get('summary'), 'extra': wizard_extra(name, values, context, draft)}


def wizard_extra(name, values, context, draft):
    """What the steps of a wizard show besides their fields: for the hardening wizard the counts of port 25, the hints, the foreign
    services and the preview of this very draft."""
    if name != 'hardening':
        return {}
    status = loaded_ok(context['loaded'], 'standards-status')
    harden = loaded_ok(context['loaded'], 'os-harden-status')
    preview = draft.get('fetched', {}).get('standards-preview')
    return {'port25_plain': status.get('port25_without_tls_7d', 0), 'port25_sessions': status.get('port25_sessions_7d', 0),
            'hints': harden.get('hints', []), 'foreign': harden.get('foreign', []),
            'preview': preview[1] if preview and preview[0] and preview[2] == efa_wizard.preview_call(name, values) else None,
            'untouched': efa_wizard.untouched(values, context)}


def loaded_ok(loaded, read):
    found = loaded.get(read)
    return found[1] if found and found[0] and isinstance(found[1], dict) else {}


def wizard_fetch(name, draft, step_id, commands):
    """Before a step: its reads (fetch) and the preview of the draft (preview), kept in the draft; the page then reads nothing slow."""
    step = next(item for item in efa_wizard.WIZARDS[name]['steps'] if item['id'] == step_id)
    fetched = draft.setdefault('fetched', {})
    for read in step.get('fetch', []):
        if read in commands:
            ok, output = efactl_read(read)
            fetched[read] = (ok, output, [read])
    if step.get('preview') in commands:
        args = efa_wizard.preview_call(name, draft['values'])
        ok, output = efactl(*args)
        fetched[step['preview']] = (ok, output, args)
        draft['values']['_warn'] = 'yes' if ok and output.get('warnings') else ''
        if not ok:
            draft['problem'] = output.get('error') or 'efactl failed, see the log.'


def wizard_test_run(draft, who, args):
    ok, output = efactl(*args, who=who)
    draft['test'] = {'state': 'done', 'ok': ok and not output.get('error'), 'output': output}


@app.route('/wizard/<name>', methods=['POST'])
def wizard_step(name):
    """A step of a wizard: its values into the draft, then the next or the step before; the last applies the draft."""
    if name not in efa_wizard.WIZARDS:
        abort(404)
    wizard = efa_wizard.WIZARDS[name]
    ok, commands = efactl_read('schema')
    if not ok or wizard_for(wizard['page'], commands) != name:
        abort(403)
    back = lambda step: redirect(url_for('show_page', slug=wizard['page'], w=step) + '#wizard', code=303)  # noqa: E731
    draft, ids, step, go = wizard_draft(name), efa_wizard.step_ids(name), request.form.get('step', ''), request.form.get('go', 'next')
    if go == 'restart' or step not in ids:
        draft.clear()
        draft.update(values={}, at=time.time())
        return back(ids[0])
    draft.pop('result', None)
    loaded = {read: efactl_read(read) for read in wizard_reads(name, commands)}
    loaded.update({read: found[:2] for read, found in draft.get('fetched', {}).items()})
    context = wizard_context(loaded)
    values, problem = efa_wizard.take(name, step, draft['values'], request.form, context)
    at = ids.index(step)
    if go == 'back':
        draft['values'] = draft['values'] if problem else values
        wizard_fetch(name, draft, ids[max(at - 1, 0)], commands)
        return back(ids[max(at - 1, 0)])
    if problem:
        draft['problem'] = problem
        return back(step)
    more = efa_wizard.opened(name, step, draft['values'], values)
    draft['values'] = efa_wizard.prefill(name, values, context, wizard_now(name, {**draft, 'values': values}, context))
    if more and go == 'next':
        return back(step)  # a choice of this step opened more of its fields: they come first
    if go == 'test' and wizard.get('test') in commands:
        if draft.get('test', {}).get('state') == 'running':
            return back(step)  # one test at a time per draft: a held button never starts a thread per click
        draft['test'] = {'state': 'running'}
        args = [wizard['test'], f"--host={draft['values'].get('host', '')}", f"--port={draft['values'].get('port', '')}"]
        # In the background with about one second per step: the page never waits for the other host.
        threading.Thread(target=wizard_test_run, args=(draft, acting_as(), args), daemon=True).start()
        return back(step)
    if go == 'apply' and step == ids[-1]:
        problem = efa_wizard.ready(name, draft['values'], draft.get('fetched', {}))
        if problem:
            draft['problem'] = problem
            return back(step)
        # The password and the 2FA code as on the manual card (same check, same five minutes); they never go into the draft.
        if wizard.get('reauth') and wizard['command'] in REAUTH_COMMANDS and not reauth_ok(request.form):
            draft['problem'] = REAUTH_FAILED
            return back(step)
        ok, output = efactl(*efa_wizard.call(name, draft['values']))
        if not ok:
            draft['problem'] = output.get('error') or 'efactl failed, see the log.'
            return back(step)
        draft.clear()
        draft.update(values={}, at=time.time(), result=output)
        return back(ids[-1])
    wizard_fetch(name, draft, ids[min(at + 1, len(ids) - 1)], commands)
    return back(ids[min(at + 1, len(ids) - 1)])


@app.route('/wizard/<name>/test')
def wizard_test(name):
    found = wizard_drafts.get((session.get('sid'), name), {}).get('test') or {'state': 'none'}
    return jsonify(state=found['state'])


@app.route('/wizard.js')
def wizard_js():
    return Response(WIZARD_JS, mimetype='text/javascript')


@app.route('/wizard-mode', methods=['POST'])
def wizard_mode():
    """Wizard or the manual cards of a page, kept in My settings of the login."""
    page, mode = request.form.get('page', ''), request.form.get('mode', '')
    if page not in efa_wizard.PAGES or mode not in ('wizard', 'manual'):
        abort(400)
    ok, output = efactl('my-settings-set', f"--manual={page}:{'on' if mode == 'manual' else 'off'}")
    if ok and isinstance(output.get('manual'), list):
        session['manual'] = output['manual']
    return redirect(url_for('show_page', slug=page), code=303)


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
    client = client_address()
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
    if name in SUPER_COMMANDS and name not in commands:
        return jsonify(error='Not allowed for your role: super admins only.'), 403
    if name not in commands or name in NOT_CALLABLE:
        return jsonify(error='Unknown command, or not allowed for your role.'), 404
    if name in REAUTH_COMMANDS:
        # A token has no password to ask again: what the web interface confirms with the password (logins, firewall, SSH, restore,
        # four eyes, audit, standards) is never done with a token alone, so a leaked token cannot take over or blind the host.
        app.logger.warning('efa-web API refused %s for token user %s from %s: needs the password', name, g.get('api_user') or '-', client_address())
        return jsonify(error='Not allowed with an API token: this change needs the password of an admin in the web interface.'), 403
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
    assert app.config['SESSION_COOKIE_NAME'] == '__Host-efa-portal' and set(app.view_functions) == set(PORTAL_ROUTES)
    client, https = app.test_client(), {'base_url': 'https://localhost'}
    for path in ('/p/sec', '/portal/p/sec', '/portal/p/dash', '/backup/download', '/api/v1/status', '/run/transport-set', '/login', '/rspamd-open', '/export/dkim'):
        assert client.get(path, **https).status_code in (302, 404), path
    login = client.get('/portal/login', **https).get_data(as_text=True)
    assert 'Mail address' in login and 'main admin' not in login and 'single sign-on' not in login
    # Single sign-on in the portal: only with its own redirect address (portal in oidc-status), under /portal/login/oidc.
    answers['oidc-status'] = (True, {'oidc': True, 'portal': True})
    assert 'action="/portal/login/oidc"' in client.get('/portal/login', **https).get_data(as_text=True)
    answers['oidc-start'] = (True, {'url': 'https://idp.example/auth?x=1', 'state': 'st', 'nonce': 'no', 'verifier': 've'})
    started = client.get('/portal/login/oidc', **https)
    assert started.headers['Location'] == 'https://idp.example/auth?x=1' and 'Path=/portal/login/oidc' in started.headers['Set-Cookie']
    answers['oidc-finish'] = (True, {'username': 'c@x.example', 'role': 'user', 'sid': 'helper-sso'})
    client.get('/portal/login/oidc/callback?code=c&state=st', **https)
    assert ['oidc-finish', '--code=c', '--nonce=no', '--verifier=ve', '--tenant='] in calls
    with client.session_transaction() as sess:
        assert sess['sid'] == 'helper-sso' and sess['user'] == 'c@x.example' and sess['role'] == 'user'
    answers.pop('oidc-status'), answers.pop('oidc-start'), answers.pop('oidc-finish')
    client = app.test_client()
    login = client.get('/portal/login', **https).get_data(as_text=True)
    # P5: the pages of users meet the own WCAG checks: names of fields and buttons, language, a heading.
    import efa_a11y
    assert efa_a11y.page_problems(login) == [], efa_a11y.page_problems(login)
    csrf = re.search(r'name="csrf" value="([^"]+)"', login).group(1)
    answers['user-verify'] = (False, {'error': 'Use the admin interface for this account.'})
    reply = client.post('/portal/login', data={'csrf': csrf, 'username': 'boss', 'password': 'x'}, **https)
    assert reply.status_code == 200 and 'Wrong password' in reply.get_data(as_text=True)
    answers['user-verify'] = (True, {'username': 'a@x.example', 'role': 'user', 'sid': 'helper-sid'})
    answers['schema'] = (True, {'uq-list': {'title': 'Held mail', 'args': [], 'writes': False}})
    reply = client.post('/portal/login', data={'csrf': csrf, 'username': 'a@x.example', 'password': 'x'}, **https)
    assert reply.status_code == 302 and '__Host-efa-portal=' in reply.headers['Set-Cookie'] and 'SameSite=Strict' in reply.headers['Set-Cookie']
    assert 'Path=/' in reply.headers['Set-Cookie'] and 'Secure' in reply.headers['Set-Cookie'] and 'Domain' not in reply.headers['Set-Cookie'], '__Host- rules'
    with client.session_transaction(**https) as sess:
        assert sess['sid'] == 'helper-sid' and sess['role'] == 'user', 'the helper names the session'
    held_page = client.get('/portal/p/held', **https)
    assert held_page.status_code == 200 and ['uq-list'] in calls
    assert efa_a11y.page_problems(held_page.get_data(as_text=True)) == [], efa_a11y.page_problems(held_page.get_data(as_text=True))
    held_text = held_page.get_data(as_text=True)
    assert 'class="usermenu"' in held_text and 'action="/portal/logout"' in held_text, 'the portal shows who is logged in, with Log out, at the top right'
    assert FEATURE_URL in held_text[held_text.index('class="usermenu"'):held_text.index('</details>', held_text.index('class="usermenu"'))], 'the portal user menu has the feature form too'
    assert client.get('/portal/p/sec', **https).status_code == 404
    with client.session_transaction(**https) as sess:
        sess['role'] = 'super'
    assert client.get('/portal/p/held', **https).status_code == 403, 'no admin session in the portal'
    print('self-test ok')


def self_test():
    # P5: the colours of text on their backgrounds 4.5:1, of borders, status marks and the focus 3:1, light and dark; a visible focus.
    import efa_a11y
    css = PAGE[:PAGE.index('</style>')]
    text_pairs = [('--ink', '--bg'), ('--ink', '--card'), ('--muted', '--card'), ('--muted', '--bg'), ('--note-ink', '--note'), ('--pill-g-ink', '--pill-g'),
                  ('--bad', '--card'), ('--pend-ink', '--pend'), ('--ink', '--field'), ('--ink', '--soft')]
    ui_pairs = [('--border', '--card'), ('--border', '--field'), ('--ok', '--card'), ('--warn', '--card'), ('--bad', '--card')]
    assert efa_a11y.contrast_problems(css, text_pairs, ui_pairs) == [], efa_a11y.contrast_problems(css, text_pairs, ui_pairs)
    assert efa_a11y.focus_problems(css) == []
    with app.test_request_context('/q/x', base_url='https://localhost'):
        for page in (render_template_string(LINK_PAGE, view={'question': 'Release this mail', 'sender': 's@x.example', 'subject': 'Hi'}, error=None, done=None),
                     render_template_string(LINK_WARNING, target='https://bad.example/', reasons=['listed'], allow=True, hint='')):
            assert efa_a11y.page_problems(page) == [], efa_a11y.page_problems(page)
    for name in ('taskpane.html',):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'share', 'eFa', 'outlook', name)
        if os.path.exists(path):
            assert efa_a11y.page_problems(open(path, encoding='utf-8').read()) == [], name
    # 9f: umlauts and ß, parts of words and synonyms; only what the reader may see; the expert cards open their view.
    assert search_norm('Größe Ärger') == 'groesse aerger' and search_norm('Café') == 'cafe'
    nav = [('G', [{'slug': 'spam', 'title': 'Spam & virus', 'sub': '', 'commands': ['qr-set', 'secret-set'],
                   'sections': [('QR codes', ['qr-set', 'secret-set'], 'advanced')], 'notes': {'qr-set': 'zbar reads them'}}])]
    commands = {'qr-set': {'title': 'QR codes in mail: switch', 'args': [{'name': 'mode', 'label': 'Read QR codes', 'choices': [{'value': 'on', 'label': 'on'}]}]}}
    entries = search_index(commands, nav, lambda page: page.get('notes', {}), lambda text: {'QR codes': 'QR-Codes'}.get(text, text))
    assert search_hits('zbar', entries)[0] == {'slug': 'spam', 'card': 'qr-set', 'label': 'QR codes in mail: switch'}
    assert search_hits('QR-Code', entries) and search_hits('junk', entries)[0]['slug'] == 'spam', 'junk finds spam'
    assert not search_hits('secret', entries), 'a card the schema of the reader does not have is not found'
    # 6.0.0.6: the suggestions hold every page the reader may open and none other, each card with the line of its help text.
    full = {name: {'title': name, 'args': [], 'writes': False} for _group, pages in NAV for page in pages for name in page['commands']}
    with app.test_request_context('/'):
        items = suggest_index(full, readable_nav(full), lambda text: text)
        assert {item['u'] for item in items if item['g'] == 'page'} == {url_for('show_page', slug=page['slug']) for _group, pages in NAV for page in pages
                                                                          if page['commands']}, 'a page is missing in the suggestions'
        tenant = {name: full[name] for name in ('maillog-search', 'quarantine-list', 'uq-list')}
        opened = {item['u'].split('#')[0].split('?')[0] for item in suggest_index(tenant, readable_nav(tenant), lambda text: text)}
        assert url_for('show_page', slug='log') in opened and not opened & {url_for('show_page', slug=slug) for slug in ('senders', 'ipblock', 'bak', 'users')}
        assert suggest_key(full) != suggest_key(tenant) and suggest_url({}) == ''
        release = next(item for item in items if item['u'].endswith('#quarantine-release'))
        assert release['g'] == 'action' and release['e'] == efa_help.first_sentence(efa_help.CARD['quarantine-release']), release
    assert search_hits('', entries) == [] and search_hits('nothing here', entries) == []
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
            'rbl-set': {'title': 'Blocklists: set', 'writes': True, 'args': [{'name': key, 'label': key} for key in ('id', 'mode', 'score', 'key')]
                        + [{'name': 'accept_terms', 'label': 'I have read and accept the terms of use of this list.'}]},
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
            {'id': 'c', 'list': 'None', 'type': 'ip', 'active': True, 'score': 3, 'hits': 0, 'errors': 0, 'terms': '', 'url': '', 'terms_accepted': True},
            {'id': 'spamhaus', 'list': 'Spamhaus ZEN', 'type': 'ip', 'active': False, 'score': 3, 'hits': 0, 'errors': 0, 'terms': '', 'url': '',
             'terms_accepted': False, 'dqs': True, 'terms_published': True, 'terms_url': 'https://www.spamhaus.org/x'}]},
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
    # An expired login form: back to the login with a note and the user name; no 403, no failed login, the code stays unused.
    failures = dict(login_failures)
    reply = client.post('/login', data={'csrf': 'old-token', 'username': 'anna', 'password': 'secret-pw', 'code': '123456'}, **https)
    assert reply.status_code == 302 and reply.headers['Location'] == '/login' and login_failures == failures
    again = client.get('/login', **https).get_data(as_text=True)
    assert 'open too long' in again and 'value="anna"' in again and 'secret-pw' not in again and '123456' not in again
    assert 'open too long' not in client.get('/login', **https).get_data(as_text=True), 'the note shows once'
    # A cookie of the setup wizard on the same address does not touch the login (own cookie names).
    try:
        client.set_cookie('__Host-efa-init', 'left-from-the-wizard', domain='localhost')
    except TypeError:
        client.set_cookie('localhost', '__Host-efa-init', 'left-from-the-wizard')
    token = re.search(r'name="csrf" value="([^"]+)"', client.get('/login', **https).get_data(as_text=True)).group(1)
    tried = client.post('/login', data={'csrf': token, 'password': 'wrong'}, **https).get_data(as_text=True)
    assert 'open too long' not in tried and 'Wrong password' in tried
    login_failures.clear()
    login_failures.update(failures)
    # The language switch of the login page, and German error pages in the look of the interface.
    german_login = client.get('/login?lang=de', **https).get_data(as_text=True)
    assert efa_i18n.catalog('de').gettext('Password') in german_login and 'lang="de" class="cur"' in german_login
    missing = client.get('/legal/nope.txt', **https)
    assert missing.status_code == 404 and 'class="card"' in missing.get_data(as_text=True) and efa_i18n.catalog('de').gettext('This page does not exist.') in missing.get_data(as_text=True)
    with client.session_transaction(**https) as sess:
        sess.pop('lang', None)  # the switch of the login page ends with the login (session_start); here the test session goes on
    assert all('<footer>' in template and 'Third-party notices' in template for template in (PAGE, LOGIN, FAILED, LINK_PAGE, MAIL_PAGE, MAIN))
    with client.session_transaction(**https) as sess:
        # The manual cards of the pages with a wizard (the wizards: tests/test_wizards.py).
        sess.update(admin=True, csrf='token', sid='test', manual=sorted(efa_wizard.PAGES))
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
    assert card_level('user-list', {'writes': False, 'args': []}, ('Users', ['user-list']), 'users') == 'standard', 'lists in the standard view'
    assert card_level('group-list', {'writes': False, 'args': []}, ('Groups', ['group-list'], 'advanced'), 'groups') == 'expert', 'advanced stays expert'
    assert card_level('x', {'writes': True, 'args': []}, ('S', ['x'], 'advanced'), 'spam') == 'expert'
    assert card_level('dkim-check', {'writes': False, 'args': []}, ('S', ['x']), 'dkim') == 'standard'
    # 6.0.0.6: the attack banner on every admin page and the lamps and gauges of the dashboard, both from the kept answer only.
    outputs['schema']['threat-status'] = {'title': 'Attack alert', 'writes': False, 'args': []}
    now = time.time()
    threat_now['result'] = {'level': 'alert', 'checked': int(now), 'gauges': {'connections': 900, 'connections_normal': 20, 'auth_failed_10': 3, 'syn': 0,
                                                                            'queue': 5, 'mails_10': 400, 'spam_10': 320, 'virus_10': 0, 'mails_normal': 30},
                            'alerts': [{'kind': 'smtp_flood', 'group': 'attack', 'slug': 'sec', 'anchor': 'firewall-show', 'level': 'alert', 'value': 900,
                                        'normal': 20, 'since': now - 120, 'top': [['203.0.113.9', 700]]},
                                       {'kind': 'disk_full', 'group': 'problem', 'slug': 'maint', 'anchor': 'load-set', 'level': 'warn', 'value': 91, 'normal': 0,
                                        'since': now - 60, 'easing': True}]}
    before = len(calls)
    shown = client.get('/p/dkim', **https).get_data(as_text=True)
    assert 'class="threat alert"' in shown and 'Attack on this server' in shown and 'SMTP connection flood' in shown and '900 connections per minute' in shown
    assert '203.0.113.9 (700)' in shown and 'Disk almost full' in shown and 'easing' in shown, 'the addresses for the main admin'
    assert shown.index('id="threat-banner"') < shown.index('<h1>'), 'right under the top bar, before the title of the page'
    assert not [call for call in calls[before:] if call[0] in ('threat-run', 'threat-status')], 'a page reads only the kept answer'
    dash = client.get('/p/dash', **https).get_data(as_text=True)
    assert 'id="status-board"' in dash and 'class="lamps"' in dash and dash.count('<figure class="gauge') == 7, 'lamps and seven gauges'
    assert 'class="lamp b"' in dash and 'aria-label="SMTP connections per minute: 900"' in dash
    assert 'class="threat alert"' in client.get('/threat-banner', **https).get_data(as_text=True)
    assert 'class="lamps"' in client.get('/status-board', **https).get_data(as_text=True)
    # Without a login neither the banner nor the board gives anything away; the check itself is no command of a form or the API.
    nobody = app.test_client()
    for path in ('/threat-banner', '/status-board'):
        answer = nobody.get(path, **https)
        assert answer.status_code in (302, 303, 401, 403) and b'threat' not in answer.data and b'lamps' not in answer.data, (path, answer.status_code)
    assert 'threat-run' in NOT_CALLABLE and 'threat-set' in SUPER_COMMANDS
    with client.session_transaction(**https) as sess:
        sess['role'] = 'tenant'
    assert '203.0.113.9' not in client.get('/p/dkim', **https).get_data(as_text=True), 'no addresses for other roles'
    with client.session_transaction(**https) as sess:
        sess.pop('role')
    threat_now['result']['checked'] = int(now) - THREAT_STALE - 1
    assert 'class="threat' not in client.get('/p/dkim', **https).get_data(as_text=True), 'an old answer shows nothing'
    threat_now['result']['checked'] = int(now)
    del outputs['schema']['threat-status']
    assert 'class="threat' not in client.get('/p/dkim', **https).get_data(as_text=True), 'only for logins that may read the check'
    assert client.get('/status-board', **https).status_code == 403
    threat_now['result'] = None
    assert '<svg' in gauge_svg('X', None, 100, 50, 80) and 'class="gauge u"' in gauge_svg('X', None, 100, 50, 80)
    for name in SUPER_COMMANDS:
        assert card_level(name, {'writes': name == 'release-upgrade', 'args': []}, ('Release-Upgrade', [name], 'advanced'), 'maint') == 'standard'
    # The release upgrade in the standard view for a super admin: the state first, the record folded away, the red warning.
    outputs['schema']['release-upgrade-status'] = {'title': 'Release upgrade to EL10: status and log', 'writes': False, 'args': []}
    outputs['schema']['release-upgrade'] = {'title': 'Release upgrade to EL10', 'writes': True, 'args': [{'name': 'action', 'label': 'Step', 'required': True}]}
    outputs['release-upgrade-status'] = {'state': 'upgrading', 'request': None, 'updated': '2026-11-10 19:38:02', 'error': None,
                                         'warnings': ['600 MB free on /boot: tight'], 'log': ['2026-11-10 19:37:58 maintenance', '2026-11-10 19:38:02 leapp upgrade'],
                                         'preflight': {'ready': True, 'checks': []}}
    with client.session_transaction(**https) as sess:
        view_before, sess['view'] = sess.get('view'), 'standard'
    maint = client.get('/p/maint', **https).get_data(as_text=True)
    card = maint[maint.index('id="release-upgrade-status"'):]
    assert card.index('<span class="badge">upgrading</span>') < card.index('<summary>Details</summary>'), 'the state before the details'
    assert '2026-11-10 19:38:02 leapp upgrade' in card[:card.index('<summary>Details</summary>')] and '600 MB free on /boot: tight' in card
    assert 'action="/run/release-upgrade"' in maint and 'No way back: the upgrade to EL10 cannot be undone' in maint
    assert maint.index('No way back') < maint.index('action="/run/release-upgrade"')
    for name in SUPER_COMMANDS:
        outputs['schema'].pop(name, None)
    # Not a super admin: efactl leaves both out of the schema, so neither card shows.
    other = client.get('/p/maint', **https).get_data(as_text=True)
    assert 'id="release-upgrade-status"' not in other and 'action="/run/release-upgrade"' not in other and 'No way back' not in other
    # UI-CLAM: without clam-source-set in the schema (read only): a POST is refused with 403 after efactl refused and logged it,
    # a GET gets 403 and runs nothing.
    calls_clam = len(calls)
    assert client.post('/run/clam-source-set', data={'csrf': 'token', 'source': 'urlhaus', 'mode': 'on'}, **https).status_code == 403
    assert [call for call in calls[calls_clam:] if call[0] != 'schema'] == [('refusal-note', '--command=clam-source-set')], calls[calls_clam:]
    calls_clam = len(calls)
    assert client.get('/run/clam-source-set?source=urlhaus&mode=on', **https).status_code == 403
    assert [call[0] for call in calls[calls_clam:] if call[0] != 'schema'] == [], 'a GET runs nothing'
    with client.session_transaction(**https) as sess:
        sess['view'] = view_before
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
    assert 'top virus Eicar' in [t['note'] for t in tiles_all if t['label'] == 'Today'][0] and ('Many mails wait in the queues', 'dash', 'status', {}) in attention_all
    assert chart['summary'] == 'Last hour: 60 mails, 1 spam, 1 viruses; most in one minute: 2.' and chart['svg'].count('<rect') == 43, chart
    assert load_extra()['disks'][0]['mount'] == '/' and len(load_extra()['load']) == 3
    assert all(slug in PAGES and anchor in PAGES[slug]['commands'] for _text, slug, anchor, _query in attention_all)
    # UI-LINK: every target of a notice of efactl, as the dashboard links it, opens a page with that card (its anchor), for a
    # card of the standard view and for one only the expert view shows; the link names page and card; a domain is filled in.
    import html as html_links
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'sbin', 'efactl'), encoding='utf-8') as f:
        targets = sorted(set(re_test.findall(r"_notice_at\('([a-z]+)', '([a-z0-9-]+)'", f.read())))
    assert len(targets) >= 20 and ('domset', 'application-set') in targets and all(anchor in PAGES[slug]['commands'] for slug, anchor in targets), targets
    saved_notices = (dict(outputs['schema']), dict(outputs['status']))
    with client.session_transaction(**https) as sess:
        view_links = sess.get('view')
    seen_views = set()
    for writes in (True, False):
        for slug, anchor in (target for target in targets if target[1] not in saved_notices[0]):
            outputs['schema'][anchor] = {'title': f'{anchor}: the card', 'writes': writes,
                                         'args': [{'name': 'domain', 'label': 'Domain', 'required': False}] if anchor == 'application-set' else []}
        outputs['status'] = {**saved_notices[1], 'system_notices': [[f'notice {anchor}', slug, anchor, {'domain': 'b.example'}] if anchor == 'application-set'
                                                                    else [f'notice {anchor}', slug, anchor] for slug, anchor in targets]}
        with client.session_transaction(**https) as sess:
            sess['view'] = 'standard'
        dash_notices = client.get('/', **https).get_data(as_text=True)
        for slug, anchor in targets:
            found = re_test.search(re_test.escape(f'notice {anchor}</td>') + r'\s*<td><a href="([^"]+)">([^<]+)</a>', dash_notices)
            assert found, (anchor, 'no link')
            href = html_links.unescape(found.group(1))
            assert found.group(2) == f"{html_links.escape(PAGES[slug]['title'])} &rarr; {html_links.escape(outputs['schema'][anchor]['title'].split(':')[0])}", found.group(2)
            section = next(section for section in PAGES[slug]['sections'] if anchor in section[1])
            expert_only = card_level(anchor, outputs['schema'][anchor], section, slug) != 'standard'
            assert href.startswith(f'/p/{slug}') and href.endswith('#' + anchor) and ('view=expert' in href) == expert_only, href
            seen_views.add(expert_only)
            with client.session_transaction(**https) as sess:
                sess['view'] = 'standard'
            shown = client.get(href.split('#')[0], **https).get_data(as_text=True)
            assert f'id="{anchor}"' in shown, (slug, anchor, writes, href)
            if anchor == 'application-set':
                assert 'domain=b.example' in href and 'value="b.example"' in shown, href
    assert seen_views == {True, False}, 'cards of both views were linked'
    outputs['schema'], outputs['status'] = saved_notices
    with client.session_transaction(**https) as sess:
        sess.pop('view', None) if view_links is None else sess.update(view=view_links)
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
    # 5r: the code of the second factor goes with the password as the second secret; a role that asks for 2FA sets it up first.
    with app.test_request_context('/', environ_base={'REMOTE_ADDR': '198.51.100.78'}):
        session['user'] = 'helper'
        stdin_seen.clear()
        assert reauth_ok({'reauth': 'right', 'reauth_code': '123456'}) and stdin_seen[-1] == 'right\n123456\n'
    login_failures.clear()
    with client.session_transaction(**https) as sess:
        sess.update(totp_setup=True)
    blocked = client.get('/p/dkim', **https)
    assert blocked.status_code == 302 and blocked.headers['Location'].endswith('/p/account#totp-setup')
    assert client.get('/p/account', **https).status_code == 200
    outputs['schema']['totp-setup'] = {'title': '2FA: set up the app', 'writes': True, 'args': []}
    outputs['totp-setup'] = {'secret': 'ABCD EFGH', 'otpauth': 'otpauth://totp/x', 'qr_svg': '<svg id="qr"></svg>'}
    setup_page = client.post('/run/totp-setup', data={'csrf': 'token'}, **https).get_data(as_text=True)
    assert '<svg id="qr"></svg>' in setup_page and 'ABCD EFGH' in setup_page and '/p/account#totp-confirm' in setup_page
    with client.session_transaction(**https) as sess:
        sess.pop('totp_setup', None)
    # ACC-1: My account top right for every login; a login without 2FA sees the warning on the dashboard only; the own re-auth
    # of efactl gets password and code first, and a wrong one counts as a failed login.
    outputs['schema']['password-change'] = {'title': 'My account: password', 'writes': True, 'args': [
        {'name': 'reauth', 'label': 'Your password', 'secret': True}, {'name': 'reauth_code', 'label': 'Code', 'secret': True},
        {'name': 'password', 'label': 'New', 'secret': True}, {'name': 'password2', 'label': 'Again', 'secret': True}]}
    shown_users = client.get('/p/account', **https)
    assert 'class="account"' in shown_users.get_data(as_text=True), (shown_users.status_code, shown_users.headers.get('Location'), shown_users.get_data(as_text=True)[:300])
    # 6.0.0.6: the top right shows who works, with its role, My account and the one Log out.
    shown = shown_users.get_data(as_text=True)
    bar = shown[shown.index('<div class="viewbar">'):shown.index('</details>', shown.index('<div class="viewbar">'))]
    assert 'class="usermenu"' in bar and 'action="/logout"' in bar and 'href="/p/account"' in bar, bar
    assert f'<a class="feature" target="_blank" rel="noopener noreferrer" href="{FEATURE_URL}">' in bar and '?' not in FEATURE_URL.split('template=')[1], 'the feature form in the user menu, no data of the host'
    assert FEATURE_URL not in shown[shown.index('<footer>'):] and all(FEATURE_URL not in template for template in (LOGIN, FAILED, LINK_PAGE, MAIL_PAGE)), 'only in the user menu'
    assert 'action="/logout"' not in shown[shown.index('<aside>'):shown.index('</aside>')], 'one Log out, at the top right'
    with app.test_request_context():
        session['user'], session['role'] = '<x>', 'helpdesk'
        assert account_view() == {'login': '<x>', 'role': 'Helpdesk'}
        session.pop('user')
        assert account_view()['login'] == 'admin' and account_view()['role'] == 'Main admin'
    with client.session_transaction(**https) as sess:
        sess['no_2fa'] = True
    assert 'Set up 2FA' in client.get('/p/dash', **https).get_data(as_text=True)
    assert 'Set up 2FA' not in client.get('/p/account', **https).get_data(as_text=True)
    login_failures.clear()
    plain = efactl
    efactl = lambda *a, secrets_in=None, who=None: (False, {'error': REAUTH_FAILED}) if a[0] == 'password-change' else plain(*a, secrets_in=secrets_in, who=who)
    client.post('/run/password-change', data={'csrf': 'token', 'reauth': 'wrong', 'reauth_code': '', 'password': 'x', 'password2': 'x'}, **https)
    assert sum(count for count, _since in login_failures.values()) == 1, 'a wrong password of the own re-auth counts as a failed login'
    efactl = plain
    login_failures.clear()
    stdin_seen.clear()
    client.post('/run/password-change', data={'csrf': 'token', 'reauth': 'right', 'reauth_code': '123456', 'password': 'New', 'password2': 'New'}, **https)
    assert stdin_seen[-1] == 'right\n123456\nNew\nNew\n', stdin_seen
    assert not login_failures
    outputs['schema']['totp-confirm'] = {'title': '2FA: switch on', 'writes': True, 'args': [{'name': 'code', 'label': 'Code'}]}
    client.post('/run/totp-confirm', data={'csrf': 'token', 'code': '123456'}, **https)
    with client.session_transaction(**https) as sess:
        assert 'no_2fa' not in sess, 'with 2FA on the warning goes'
    # 6.0.0.5: Re-Setup shows the real values, compares first and applies only with the password; guided to manual asks it anew.
    outputs['setup-variant-status'] = {'variant': 'guided', 'eulink': 'yes', 'frameworks': 'nis2', 'note': ''}
    outputs['resetup'] = {'compare': [['variant', 'guided', 'manual']], 'raised': [['tls_profile', 'rfc9325', 'bsi']], 'notes': []}
    page_text = client.get('/resetup', **https).get_data(as_text=True)
    assert 'name="notice"' in page_text and 'value="guided" required checked' in page_text and 'value="nis2" checked' in page_text
    assert 'Please confirm' in client.post('/resetup', data={'csrf': 'token', 'variant': 'manual', 'eulink': 'yes'}, **https).get_data(as_text=True)
    compared = client.post('/resetup', data={'csrf': 'token', 'notice': 'yes', 'variant': 'manual', 'eulink': 'yes'}, **https).get_data(as_text=True)
    assert 'name="apply"' in compared and 'rfc9325' in compared and calls[-1][0] == 'resetup' and '--apply=yes' not in calls[-1]
    assert calls[-1][3].startswith('--notice=' + efa_setup.notice_digest(lambda text: text) + '/')
    with client.session_transaction(**https) as sess:
        sess['reauth'] = time.time()
    refused = client.post('/resetup', data={'csrf': 'token', 'notice': 'yes', 'variant': 'manual', 'eulink': 'yes', 'apply': 'yes'}, **https)
    assert 'Wrong password' in refused.get_data(as_text=True) and '--apply=yes' not in calls[-1], 'guided to manual: the password anew'
    assert 'Tick the box' in client.post('/resetup', data={'csrf': 'token', 'notice': 'yes', 'variant': 'guided', 'eulink': 'no', 'noeu': 'yes',
                                                            'phrase': 'x'}, **https).get_data(as_text=True)
    outputs['setup-variant-status']['variant'] = 'manual'
    with client.session_transaction(**https) as sess:
        sess['reauth'] = time.time()
    done = client.post('/resetup', data={'csrf': 'token', 'notice': 'yes', 'variant': 'guided', 'eulink': 'no', 'noeu': 'yes', 'phrase': 'auf eigenes Risiko',
                                         'frameworks': ['nis2', 'x'], 'apply': 'yes'}, **https).get_data(as_text=True)
    assert '--apply=yes' in calls[-1] and '--frameworks=nis2' in calls[-1] and [arg for arg in calls[-1] if arg.startswith('--noeu=')] and 'bsi' in done
    with app.test_request_context('/'):
        globals()['SETUP_VARIANT_FILE'] = legal_tmp + '/setup-variant.json'
        assert not eu_locked()
        with open(SETUP_VARIANT_FILE, 'w') as f:
            json.dump({'variant': 'manual', 'eulink': 'yes'}, f)
        assert eu_locked()
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
    assert admin_address_ok('127.0.0.1') and admin_address_ok('::1'), 'the host itself is never refused'
    # A multipart body before a login, or to a page that takes no upload: refused before it is parsed.
    multipart = {'data': b'--b\r\nContent-Disposition: form-data; name="csrf"\r\n\r\nx\r\n--b--\r\n',
                 'content_type': 'multipart/form-data; boundary=b'}
    assert app.test_client().post('/login', **multipart, **https).status_code == 415
    assert app.test_client().post('/backup/upload', **multipart, **https).status_code == 415, 'an upload only after a login'
    assert app.test_client().post('/login', data=b'a=' + b'x' * (MAX_FORM + 1), content_type='application/x-www-form-urlencoded', **https).status_code == 413
    global PROXY_KEY
    saved_key, PROXY_KEY = PROXY_KEY, b'proxy-key-1'
    assert client.get('/p/dash', headers={'X-Real-IP': '198.51.100.7', 'X-Efa-Proxy': 'proxy-key-1'}, **https).status_code == 403
    assert client.get('/p/dash', headers={'X-Real-IP': '192.0.2.9', 'X-Efa-Proxy': 'proxy-key-1'}, **https).status_code == 200
    # The peer from outside (the host itself is always allowed): without the key of nginx its address counts, not the header.
    assert client.get('/p/dash', headers={'X-Real-IP': '192.0.2.9', 'X-Efa-Proxy': 'wrong'}, environ_base={'REMOTE_ADDR': '198.51.100.8'},
                      **https).status_code == 403, 'without the key of nginx the address is the peer, not the one in the header'
    assert client.get('/p/dash', headers={'X-Real-IP': '127.0.0.1', 'X-Efa-Proxy': 'proxy-key-1'}, **https).status_code == 200, 'the host itself'
    PROXY_KEY = saved_key
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
    # Links out of eFa-next, the rspamd interface among them, open in a window of their own; links inside eFa-next do not.
    outputs['settings'], kept_settings = {**(outputs.get('settings') or {}), 'rspamd_sso': 'read-only', 'rspamd_sso_until': '09:30'}, outputs.get('settings')
    pills_seen = set()
    for slug in PAGES:
        html = client.get(f'/p/{slug}', **https).get_data(as_text=True)
        # 6.0.0.6: every field keeps its label in span.lb and, where efa_help.FIELD has a text, its (i), as a pill switch or group too.
        for field_id in re.findall(r'<label for="([a-z0-9_-]+)"(?: id="[^"]+")?>', html):
            name = next((n for n in sorted(outputs['schema'], key=len, reverse=True) if field_id.startswith(n + '-')), None)
            arg = next((a for a in (outputs['schema'][name].get('args', []) if name else []) if a['name'] == field_id[len(name) + 1:]), None)
            if not arg or arg.get('kind') == 'confirm':
                continue
            assert re.search(r'<span class="lb"><label for="' + re.escape(field_id) + '"', html), (slug, field_id, 'label without span.lb')
            if efa_help.FIELD.get(name, {}).get(arg['name']):
                assert f'popovertarget="i-{field_id}"' in html, (slug, field_id, 'help without its (i)')
            pills_seen.update(kind for kind, mark in (('group', f'role="radiogroup" aria-labelledby="{field_id}-l"'),
                                                      ('switch', f'role="switch" id="{field_id}"')) if mark in html)
        for tag in re.findall(r'<a [^>]*>', html):
            href = re.search(r'href="([^"]*)"', tag)
            if href and (href.group(1).startswith(('http://', 'https://', '/rspamd'))):
                assert 'target="_blank"' in tag and 'rel="noopener noreferrer"' in tag, (slug, tag)
    assert 'href="/rspamd-open" target="_blank" rel="noopener noreferrer"' in client.get('/p/dash', **https).get_data(as_text=True)
    outputs['settings'] = kept_settings
    assert pills_seen == {'group', 'switch'}, ('the label and help check saw no pill switch or group', pills_seen)
    assert '<a href="https://a.example/?x=1&amp;y=2" target="_blank" rel="noopener noreferrer">Website</a>' in lists
    # SEC-STD: the last check, each standard with its result and the open findings.
    outputs['schema']['standards-show'] = {'title': 'Security standards: the last check', 'args': [], 'writes': False}
    outputs['standards-show'] = {'checked': '2026-11-11 10:00:00', 'selected': ['bsi-02102-2'], 'summary': {'fulfilled': 1, 'over': 0, 'needs': 0, 'not': 1},
                                 'standards': {'bsi-02102-2': {'title': 'BSI TR-02102-2 (TLS)', 'version': '2026-01', 'verified': True, 'status': 'not',
                                                               'rows': [{'setting': 'web', 'status': 'not', 'now': 'X25519', 'wanted': 'not X25519', 'why': 'table 10'}]},
                                               'cis-el': {'title': 'CIS', 'version': '2.0', 'verified': False, 'status': 'fulfilled', 'rows': []}}}
    shown_std = client.get('/p/standards', **https).get_data(as_text=True)
    assert 'BSI TR-02102-2 (TLS)' in shown_std and 'not fulfilled' in shown_std and 'not verified against the current text' in shown_std and 'nothing open' in shown_std
    assert 'javascript:alert' not in lists and lists.count('>Website</a>') == 1
    # UI-RBL: the switch shows the state in effect; off with unconfirmed terms opens them with the tick box, the DQS key in its row.
    assert 'role="switch" aria-checked="true" aria-label="None"' in lists and '>On</button>' in lists
    assert '<details class="rblterms"><summary class="switch" role="switch" aria-checked="false" aria-label="Spamhaus ZEN">' in lists
    # The DQS key: one field, in its row (the card of rbl-set names it too, in its help).
    assert 'name="accept_terms" value="yes" required' in lists and lists.count('class="dqs"') == 1 and 'https://www.spamhaus.org/x' in lists
    assert '>Turn on</button>' not in lists.split('<details')[0], 'no action as a label: the state'
    # UI-CLAM: the switch shows the value in effect; terms first, with the link and the tick box; the ID field, never its value.
    outputs['schema']['clam-source-status'] = {'title': 'More ClamAV signatures', 'args': [], 'writes': False}
    outputs['schema']['clam-source-set'] = {'title': 'More ClamAV signatures: a source on or off', 'writes': True, 'args': [
        {'name': 'source', 'label': 'Source', 'required': True}, {'name': 'mode', 'label': 'On or off', 'required': True},
        {'name': 'id', 'label': 'Account ID (SecuriteInfo)', 'required': False, 'secret': True},
        {'name': 'accept_terms', 'label': 'I have read and accept the terms of this source: type yes', 'required': False}]}
    outputs['clam-source-status'] = {'sources': [
        {'source': 'urlhaus', 'name': 'URLhaus (abuse.ch, Switzerland)', 'terms': 'abuse.ch, free', 'active': True, 'files': 'urlhaus.ndb',
         'accepted': {'by': 'admin', 'at': '2026-11-11 10:00'}, 'terms_accepted': True, 'terms_url': 'https://abuse.ch/terms-of-use/', 'needs_id': False, 'id_set': False},
        {'source': 'interserver', 'name': 'InterServer (USA)', 'terms': 'InterServer, free', 'active': False, 'files': 'shell.ldb',
         'accepted': None, 'terms_accepted': False, 'terms_url': '', 'needs_id': False, 'id_set': False},
        {'source': 'securiteinfo', 'name': 'SecuriteInfo (France)', 'terms': 'needs an ID', 'active': False, 'files': 'securiteinfo.hdb',
         'accepted': {'by': 'admin', 'at': '2026-11-11 10:01'}, 'terms_accepted': True, 'terms_url': 'https://www.securiteinfo.com/legal/x', 'needs_id': True, 'id_set': True}]}
    clam = client.get('/p/spam', **https).get_data(as_text=True)
    clam = clam[clam.index('id="clam-source-status"'):]
    clam = clam[:clam.index('</table>')]
    assert 'role="switch" aria-checked="true" aria-label="URLhaus (abuse.ch, Switzerland)"' in clam and clam.count('name="csrf"') >= 4
    assert '<details class="rblterms"><summary class="switch" role="switch" aria-checked="false" aria-label="InterServer (USA)">' in clam
    assert 'no published terms' in clam and 'name="accept_terms" value="yes" required' in clam and 'href="https://abuse.ch/terms-of-use/"' in clam
    assert 'aria-label="SecuriteInfo (France)"' in clam and 'type="password" name="id"' in clam and 'set, empty keeps it' in clam
    assert 'Save and turn on' in clam and 'class="clam stack"' in clam and 'action="/run/clam-source-set"' in clam
    assert 'id="clam-source-set"' not in client.get('/p/spam', **https).get_data(as_text=True), 'no second form: the rows have it'
    outputs['clam-source-status']['sources'][0]['files'] = ['interserver256.hdb', 'interservertopline.db']
    kept_clam_set = outputs['schema'].pop('clam-source-set')
    readonly = client.get('/p/spam', **https).get_data(as_text=True)
    readonly = readonly[readonly.index('id="clam-source-status"'):]
    readonly = readonly[:readonly.index('</table>')]
    assert 'action="/run/clam-source-set"' not in readonly and 'role="switch"' not in readonly and 'name="id"' not in readonly
    assert '<span class="switch on"><span class="knob" aria-hidden="true"></span>On</span>' in readonly
    assert '<span class="file">interserver256.hdb</span><span class="file">interservertopline.db</span>' in readonly
    outputs['schema']['clam-source-set'] = kept_clam_set
    # 6.0.0.6: the tier in effect and how many URLs are stored, never a URL; the pasted lines go to efactl on stdin in base64.
    outputs['schema']['clam-securiteinfo-set'] = {'title': 'More ClamAV signatures: account tier and URLs of SecuriteInfo', 'writes': True, 'args': [
        {'name': 'tier', 'label': 'SecuriteInfo account tier', 'required': True},
        {'name': 'urls', 'label': 'DatabaseCustomURL lines of SecuriteInfo, empty keeps them', 'required': False, 'secret': True, 'multiline': True},
        {'name': 'delete_urls', 'label': 'Delete the stored URLs: type yes', 'required': False}]}
    outputs['clam-source-status']['sources'][2].update(tier='basic', tiers=[['basic', 'Basic', 30, 300]], urls=3, last_contact='2026-11-11 10:30')
    with client.session_transaction(**https) as sess:
        sess.pop('reauth', None)
    clam = client.get('/p/spam', **https).get_data(as_text=True)
    assert 'id="clam-securiteinfo-set"' not in clam, 'no card of its own: the row has the form'
    clam = clam[clam.index('id="clam-source-status"'):]
    clam = clam[:clam.index('</table>')]
    assert 'Account tier in effect: <b>Basic</b>' in clam and 'at most one download every 30 minutes, at most 300 kB/s' in clam, clam
    assert '3 URLs stored' in clam and 'last asked 2026-11-11 10:30' in clam and '<option value="basic" selected>Basic</option>' in clam
    assert 'action="/run/clam-securiteinfo-set"' in clam and 'name="delete_urls" value="yes"' in clam and 'popovertarget="i-clam-si-urls"' in clam
    assert re.search(r'<textarea id="clam-si-urls" name="urls"[^>]*></textarea>', clam) and 'EXAMPLEKEY' not in clam
    assert 'name="reauth"' in clam and 'name="reauth_code"' in clam, 'step-up: password and 2FA code in the row'
    calls_si = len(calls)
    client.post('/run/clam-securiteinfo-set', data={'csrf': 'token', 'tier': 'basic', 'urls': '', 'delete_urls': ''}, **https)
    assert not [call for call in calls[calls_si:] if call[0] == 'clam-securiteinfo-set'], 'no change without the password'
    with client.session_transaction(**https) as sess:
        sess['reauth'] = time.time()
    assert 'reauth-ok' in client.get('/p/spam', **https).get_data(as_text=True).split('action="/run/clam-securiteinfo-set"')[1].split('</form>')[0]
    pasted = 'DatabaseCustomURL https://www.securiteinfo.com/get/signatures/EXAMPLEKEY/securiteinfo.hdb\r\nDatabaseCustomURL https://www.securiteinfo.com/get/signatures/EXAMPLEKEY/javascript.ndb'
    client.post('/run/clam-securiteinfo-set', data={'csrf': 'token', 'tier': 'basic', 'urls': pasted, 'delete_urls': ''}, **https)
    sent = [call for call in calls[calls_si:] if call[0] == 'clam-securiteinfo-set']
    assert sent and '--tier=basic' in sent[0] and not any('EXAMPLEKEY' in part for part in sent[0]), sent
    assert base64.b64decode(stdin_seen[-1].strip()).decode() == pasted
    stdin_seen.clear()
    outputs['clam-source-status']['sources'][2].update(urls=0, last_contact='')
    clam = client.get('/p/spam', **https).get_data(as_text=True)
    assert 'no URLs stored' in clam and 'name="delete_urls"' not in clam and 'last asked' not in clam
    # On a cluster node: no tier, no URL field, no ID field; "waiting for the master" until the first checked transfer.
    outputs['clam-source-status']['sources'][2].update(cluster='client', waiting=True, received='', active=False)
    node = client.get('/p/spam', **https).get_data(as_text=True)
    node = node[node.index('id="clam-source-status"'):]
    node = node[:node.index('</table>')]
    assert 'waiting for the master' in node and 'Account tier and URLs are set on the master.' in node, node
    assert 'name="urls"' not in node and 'name="tier"' not in node and 'type="password" name="id"' not in node
    outputs['clam-source-status']['sources'][2].update(waiting=False, received='2026-11-12 03:00', active=True)
    node = client.get('/p/spam', **https).get_data(as_text=True)
    assert 'Signatures from the master, last received 2026-11-12 03:00' in node and 'waiting for the master' not in node
    # The Sanesecurity card of a node: the state as a text, no raw values.
    kept_sane = outputs.get('sanesecurity-status')
    kept_schema = {name: outputs['schema'].get(name) for name in ('sanesecurity-status', 'sanesecurity-set')}
    outputs['schema']['sanesecurity-status'] = {'title': 'Sanesecurity signatures', 'args': [], 'writes': False}
    outputs['schema']['sanesecurity-set'] = {'title': 'Sanesecurity signatures: switch', 'writes': True, 'args': [{'name': 'mode', 'label': 'Sanesecurity signatures: on or off', 'required': True}]}
    outputs['sanesecurity-status'] = {'active': False, 'warnings': ['ClamAV signatures: waiting for the master; this cluster node does not download them itself.']}
    node = client.get('/p/spam', **https).get_data(as_text=True)
    node = node[node.index('id="sanesecurity-set"'):]
    node = node[:node.index('class="card"')] if 'class="card"' in node else node
    assert 'ClamAV signatures: waiting for the master; this cluster node does not download them itself.' in node and 'from master' not in node, node[:3000]
    outputs['sanesecurity-status'] = kept_sane
    for name, item in kept_schema.items():
        if item is None:
            outputs['schema'].pop(name, None)
        else:
            outputs['schema'][name] = item
    if kept_sane is None:
        del outputs['sanesecurity-status']
    outputs['clam-source-status']['sources'][2].update(cluster='none', waiting=False, received='')
    del outputs['schema']['clam-securiteinfo-set']
    spam = client.get('/p/spam', **https).get_data(as_text=True)
    assert 'value="7"' in spam and ' checked' in spam and spam.index('value="on"') < spam.index('value="off"')
    client.post('/run/greylisting-set', data={'csrf': 'token', 'mode': ['on', 'off']}, **https)
    assert ('greylisting-set', '--mode=on') in calls
    client.post('/run/greylisting-set', data={'csrf': 'token', 'mode': 'off'}, **https)
    assert ('greylisting-set', '--mode=off') in calls

    flow = client.get('/p/flow', **https).get_data(as_text=True)
    assert 'a.example' in flow and '/run/transport-set' in flow and 'name="action" value="add"' in flow
    # The switch in the head of a card: one click posts the form of the card with only mode changed, the rest as it is now.
    outputs['schema'].update({'attachment-status': {'title': 'Attachments', 'args': [], 'writes': False},
                              'attachment-set': {'title': 'Attachments: settings', 'writes': True,
                                                 'args': [{'name': 'mode', 'label': 'Attachment checks of eFa-next: on or off', 'required': True},
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
    assert 'value="2048" checked><span>2048</span>' in dkim and 'value="3072"><span>3072</span>' in dkim and 'value="4096"><span>4096</span>' in dkim
    assert 'copy.js' in dkim and 'data-copy' in dkim and 'DKIM keys: generate' in dkim and 'a-sel' in dkim
    # One form, the domain once: the RSA fields go away with Ed25519 only, the Ed25519 field with RSA only (CSS, no script).
    assert dkim.count('id="dkim-create-domain"') == 1 and 'value="both" checked' in dkim and 'class="row rsabox"' in dkim
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
    assert 'value="d.example"' in restored and 'value="reject" checked' in restored
    senders = client.get('/p/senders', **https).get_data(as_text=True)
    assert 'data-manage="block"' in senders and 'senders.js' in senders and 'Remove selected' in senders
    assert client.get('/senders/data', **https).get_json()['allow'][0]['entry'] == 'a@example.org'
    relay = client.get('/p/relay', follow_redirects=True, **https).get_data(as_text=True)
    assert 'Not active yet' in relay and 'Added: 192.0.2.0/24' in relay and relay.count('/run/relay-networks-remove') == 1
    log = client.get('/p/log', **https).get_data(as_text=True)
    index_url = re.search(r'data-index="([^"]+)"', log).group(1).replace('&amp;', '&')
    suggest = client.get(index_url, **https)
    assert suggest.mimetype == 'application/json' and suggest.headers['Cache-Control'] == 'no-store' and 'role="combobox"' in log, index_url
    assert suggest.get_json()['mail'] is True and any(item['g'] == 'page' for item in suggest.get_json()['items'])
    assert 'id="live-open"' in log and 'live.js' in log and 'Result: all' in log
    assert '<title>eFa-next: open source mail server protection</title>' in log and 'Live log' in log
    live = client.get('/maillog/live?after=5', **https)
    assert live.mimetype == 'application/json' and live.get_json()['mails'][0]['id'] == 7
    assert ('maillog-live', '--after_id=5') in calls and client.get('/live.js', **https).mimetype == 'text/javascript'
    # 6.0.0.6: the mail views. Chips with their menu, the age of each mail, the check and the action as JSON for the toast with undo.
    assert 'mailui.js' in log and "data-texts='" in log and client.get('/mailui.js', **https).mimetype == 'text/javascript' and live.get_json()['now']
    assert ago('2001-01-01 10:00:00') == '2001-01-01' and ago(time.time() - 120) == '2 min' and ago('not a time') == 'not a time'
    outputs['schema'].update({'sender-action': {'title': 'Sender of a mail: allow or block', 'writes': True,
                                                'args': [{'name': key, 'label': key} for key in ('value', 'list', 'action', 'recipients', 'qid', 'confirm')]},
                              'sender-action-check': {'title': 'Sender check', 'writes': False, 'args': [{'name': key, 'label': key} for key in ('value', 'list', 'recipients', 'qid')]},
                              'quarantine-release': {'title': 'Quarantine: deliver', 'writes': True, 'args': [{'name': 'id', 'label': 'Queue ID'}]},
                              'quarantine-show': {'title': 'Quarantine: headers', 'writes': False, 'args': [{'name': 'id', 'label': 'Queue ID'}]}})
    outputs['sender-action-check'] = {'entry': 'x@example.net', 'kind': 'address', 'list': 'block', 'target_text': 'the global block list',
                                      'warnings': ['x@example.net is on the allow list: the new entry clashes with it.']}
    checked = client.post('/senders/check', data={'csrf': 'token', 'value': 'x@example.net', 'list': 'block', 'qid': 'ABC123'}, **https).get_json()
    assert checked['ok'] and checked['result']['warnings'] and ('sender-action-check', '--value=x@example.net', '--list=block', '--recipients=', '--qid=ABC123') in calls
    assert client.post('/senders/check', data={'value': 'x@example.net', 'list': 'block'}, **https).status_code == 403
    outputs['sender-action'] = {'action': 'add', 'entry': 'x@example.net', 'list': 'block', 'target_text': 'the global block list', 'qid': 'ABC123', 'recipients': ''}
    done = client.post('/run/sender-action', data={'csrf': 'token', 'json': '1', 'value': 'x@example.net', 'list': 'block'}, **https).get_json()
    assert done['ok'] and done['result']['entry'] == 'x@example.net', done
    failing.append('sender-action')
    refused = client.post('/run/sender-action', data={'csrf': 'token', 'json': '1', 'value': 'x@example.net', 'list': 'block'}, **https).get_json()
    assert refused == {'ok': False, 'result': None, 'error': 'sender-action failed'}, refused
    failing.remove('sender-action')
    undo = client.post('/run/sender-action', data={'csrf': 'token', 'value': 'x@example.net', 'list': 'block'}, follow_redirects=True, **https).get_data(as_text=True)
    assert 'x@example.net: added to the global block list' in undo and 'name="action" value="remove"' in undo
    outputs['maillog-search'] = {'mails': [{'id': 3, 'ts': '2026-11-11 10:00:00', 'qid': 'ABC123', 'sender': 'a@example.net', 'rcpt': 'b@example.org', 'ip': '192.0.2.5',
                                            'action': 'reject', 'score': 12.5, 'subject': 'Hi', 'spf': 'fail', 'dkim': 'none', 'dmarc': 'fail'}],
                                 'query': 'domain:example.net', 'filters': ['domain:example.net']}
    found = client.post('/run/maillog-search', data={'csrf': 'token'}, follow_redirects=True, **https).get_data(as_text=True)
    assert 'id="log-result" data-q="domain:example.net"' in found and 'data-kind="ip"' in found and 'class="st b"' in found and '12.5' in found, found[-3000:]
    assert '<main class="wide">' in found and 'data-sender="a@example.net" data-kind="address" data-qid="ABC123" data-rcpt="b@example.org" data-ip="192.0.2.5"' in found
    outputs['maillog-search'] = {'mails': [], 'query': 'x', 'filters': []}
    assert 'No mail matches' in client.post('/run/maillog-search', data={'csrf': 'token'}, follow_redirects=True, **https).get_data(as_text=True)
    quar = client.get('/p/quar', **https).get_data(as_text=True)
    assert 'data-sender="&lt;b&gt;x"' in quar and 'id="bulk"' in quar and 'class="log quar"' in quar and 'data-bulk="block"' in quar and 'data-can-act' in quar
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
        # The manual cards of the pages with a wizard (the wizards: tests/test_wizards.py).
        sess.update(admin=True, csrf='token', sid='test', manual=sorted(efa_wizard.PAGES))
    active_sessions['test'] = time.time() + 60
    outputs['session-check'] = {'active': True}

    # M4: the password fields only when the last confirmation is (almost) over. M5: the tick box Clear sends the - of the console.
    with client.session_transaction(**https) as sess:
        sess['reauth'] = time.time()
    fresh = client.get('/p/sec', **https).get_data(as_text=True)
    with client.session_transaction(**https) as sess:
        sess.pop('reauth', None)
    stale = client.get('/p/sec', **https).get_data(as_text=True)
    assert 'reauth-ok' in fresh and 'reauth-ok' not in stale and fresh.count('name="reauth"') < stale.count('name="reauth"'), 'M4'
    # M4: hidden fields change nothing on the server: after the five minutes a protected change without the password is
    # refused and efactl is not called; inside them it runs.
    outputs['schema']['api-set'] = {'title': 'REST API: switch', 'writes': True, 'args': [{'name': 'mode', 'label': 'on or off', 'required': True}]}
    assert 'api-set' in REAUTH_COMMANDS
    for age, runs in ((REAUTH_SECONDS + 1, False), (REAUTH_SECONDS - 30, True)):
        with client.session_transaction(**https) as sess:
            sess['reauth'] = time.time() - age
        calls_m4 = len(calls)
        page_m4 = client.post('/run/api-set', data={'csrf': 'token', 'mode': 'on'}, follow_redirects=True, **https).get_data(as_text=True)
        assert any(call[0] == 'api-set' for call in calls[calls_m4:]) == runs, (age, calls[calls_m4:])
        assert runs or 'Confirm this change with your password.' in page_m4
    with client.session_transaction(**https) as sess:
        sess.pop('reauth', None)
    outputs['schema'].pop('api-set')
    with app.test_request_context('/'):
        call_command({'name': 'x-set', 'args': [{'name': 'senders', 'label': 'Senders; - for none'}, {'name': 'note', 'label': 'Note'}]},
                     {'senders': 'a.example', 'senders__clear': 'on', 'note': '', 'note__clear': 'on'})
    assert calls[-1] == ('x-set', '--senders=-', '--note='), calls[-1]
    # Only "- for none" and "- empties ..." clear; another use of - on the console gets no tick box.
    assert efa_help.web_label('Allowed admin networks, each with a comment; - empties the list')['clear']
    assert efa_help.web_label('PDF file to write, - for stdout (command line)') == {'label': 'PDF file to write', 'placeholder': '', 'clear': False, 'yes': False}

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
