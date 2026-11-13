#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""eFa-next first-run wizard. Collects settings, then runs efa-apply --all and hands the answers over on stdin.

Runs as efa-init on 127.0.0.1:8080 behind nginx, only until the system is configured.
"""
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zoneinfo

from flask import Flask, Response, abort, redirect, render_template_string, request, session, url_for
from markupsafe import escape
from waitress import serve

# The libraries of eFa-next: installed, or next to this file in the source tree.
for folder in ('/usr/lib/eFa/python', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'lib', 'eFa', 'python')):
    if os.path.isdir(folder) and folder not in sys.path:
        sys.path.insert(0, folder)
import efa_i18n  # noqa: E402
import efa_pdf  # noqa: E402
import efa_qr  # noqa: E402
import efa_setup  # noqa: E402
import efa_style  # noqa: E402  the look of the web interface
import efa_totp  # noqa: E402

EFA_APPLY = ['sudo', '-n', '/usr/sbin/efa-apply', '--verbose', '--answers', '-', '--all']
# The time servers and the clock set now, before the 2FA step (its codes fit only within 30 s).
EFA_TIME_SYNC = ['sudo', '-n', '/usr/sbin/efa-apply']
HOST_RE = re.compile(r'^[-a-zA-Z0-9]{1,63}$')
DOMAIN_RE = re.compile(r'^[a-zA-Z0-9]+([\-.][a-zA-Z0-9-]+)*$')
EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
CLI_USER_RE = re.compile(r'^[a-z_][a-z0-9_-]{0,31}$')
SERVER_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$')
MIN_PASSWORD = 12


def ntp_servers_clean(value):
    """1 to 4 host names or IP addresses, separated by commas or spaces, as 'a, b'; '' if one is not."""
    servers = [part for part in re.split(r'[,\s]+', value) if part]
    good = 0 < len(servers) <= 4 and all(is_ip(4)(server) or is_ip(6)(server) or ('.' in server and DOMAIN_RE.match(server)) for server in servers)
    return ', '.join(servers) if good else ''


def time_sync(servers):
    """efa-apply --time-sync: (synchronized, offset after in seconds or None)."""
    try:
        done = subprocess.run(EFA_TIME_SYNC + ['--time-sync=' + servers], capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as err:
        log.info('time sync failed: %s', err)
        return False, None
    line = next((line.split() for line in done.stdout.splitlines() if line.startswith('TIMESYNC ')), [])
    log.info('time sync: %s', ' '.join(line[1:]) or (done.stderr.strip()[-200:] or 'no answer'))
    try:
        after = float(line[3])
    except (IndexError, ValueError):
        after = None
    return line[1:2] == ['yes'], after


def is_ip(version):
    def check(value):
        try:
            return ipaddress.ip_address(value).version == version
        except ValueError:
            return False
    return check


def in_range(low, high):
    return lambda value: value.isdigit() and low <= int(value) <= high


def netmask_prefix(value):
    """An IPv4 netmask as its prefix: 24, /24 and 255.255.255.0 give '24'; a mask that is not contiguous (255.0.255.0) None."""
    value = value.strip().lstrip('/')
    if value.isdigit():
        return str(int(value)) if 1 <= int(value) <= 32 else None
    try:
        return str(ipaddress.IPv4Network(f'0.0.0.0/{value}').prefixlen) if is_ip(4)(value) and value != '0.0.0.0' else None
    except ValueError:
        return None


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


ROOT_SERVERS = ('198.41.0.4', '193.0.14.129')  # a. and k.root-servers.net
root_cache = []


def roots_answer():
    """MIG-DNS: whether the root servers answer from here over UDP and TCP; then this server resolves itself (once per run)."""
    if not root_cache:
        found = set()
        for server in ROOT_SERVERS:
            for proto in ('udp', 'tcp'):
                try:
                    done = subprocess.run(['dig', '+norecurse', '+time=3', '+tries=1', *(['+tcp'] if proto == 'tcp' else []), f'@{server}', '.', 'NS'],
                                          capture_output=True, text=True, timeout=15)
                except (subprocess.SubprocessError, OSError):
                    continue
                if 'status: NOERROR' in done.stdout:
                    found.add(proto)
        root_cache.append(found >= {'udp', 'tcp'})
    return root_cache[0]


def internal_dns_server(value):
    """A DNS server of your own network, and only when this server cannot reach the root servers: a public resolver (8.8.8.8)
    makes the free blocklists stop answering, and every mail domain would go to it."""
    if not is_ip(4)(value) or ipaddress.ip_address(value).is_global:
        return False
    return not roots_answer()


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
# Each step: a title, one sentence what is asked, the label of the field, and the message after a wrong entry. All English
# here and translated when shown (tr, de.po). 'now' is the value in effect on this host, shown until the admin changes it.
STEPS = [
    {'slug': 'hostname', 'title': 'Host name', 'help': 'The name of this server without the domain, as it appears in mail headers.',
     'label': 'Host name', 'error': 'Letters, digits and hyphens only, such as mx1.', 'check': HOST_RE.match, 'now': 'hostname'},
    {'slug': 'domainname', 'title': 'Domain', 'help': 'The domain of this server; host name and domain make its full name.',
     'label': 'Domain', 'error': 'A domain such as example.com.', 'check': DOMAIN_RE.match, 'now': 'domainname'},
    {'slug': 'email', 'title': 'Notifications', 'help': 'Important notifications of this server go to this address.',
     'label': 'Email address', 'error': 'A mail address such as admin@example.com.', 'check': EMAIL_RE.match},
    {'slug': 'interface', 'title': 'Network interface', 'help': 'The network interface this server receives mail on.',
     'label': 'Interface', 'error': 'Choose one of the interfaces.', 'choices': interfaces, 'now': 'interface'},
    {'slug': 'configipv4', 'title': 'IPv4 address', 'help': 'A mail server needs a fixed address; without one it keeps the address DHCP gives it.',
     'label': 'Set a static IPv4 address?', 'error': 'Choose yes or no.', 'yesno': True, 'now': 'configipv4'},
    {'slug': 'ipv4address', 'title': 'IPv4 address', 'help': 'The IPv4 address of this server.',
     'label': 'IPv4 address', 'error': 'An IPv4 address such as 192.0.2.10.', 'check': is_ip(4), 'if': 'configipv4', 'now': 'ipv4address'},
    {'slug': 'ipv4netmask', 'title': 'IPv4 netmask', 'help': 'The size of the network of this address, as a prefix (24 is 255.255.255.0).',
     'label': 'Prefix', 'error': 'A prefix from 1 to 32, such as 24, or a netmask such as 255.255.255.0.', 'if': 'configipv4',
     'choices': lambda: [str(n) for n in range(32, 0, -1)], 'normalize': netmask_prefix,
     'shown': lambda n: f'/{n} ({ipaddress.IPv4Network(f"0.0.0.0/{n}").netmask})', 'now': 'ipv4netmask'},
    {'slug': 'ipv4gateway', 'title': 'IPv4 gateway', 'help': 'The router this server sends to other networks through.',
     'label': 'Gateway', 'error': 'An IPv4 address such as 192.0.2.1.', 'check': is_ip(4), 'if': 'configipv4', 'now': 'ipv4gateway'},
    {'slug': 'ipv6dns', 'title': 'IPv6 for DNS', 'help': 'Whether the resolver of this server also asks over IPv6; only with IPv6 in your network.',
     'label': 'Use IPv6 for DNS?', 'error': 'Choose yes or no.', 'yesno': True, 'now': 'ipv6'},
    {'slug': 'configipv6', 'title': 'IPv6 address', 'help': 'A fixed IPv6 address for this server, if your network has IPv6.',
     'label': 'Set a static IPv6 address?', 'error': 'Choose yes or no.', 'yesno': True, 'default': 'no'},
    {'slug': 'ipv6address', 'title': 'IPv6 address', 'help': 'The IPv6 address of this server.',
     'label': 'IPv6 address', 'error': 'An IPv6 address such as 2001:db8::10.', 'check': is_ip(6), 'if': 'configipv6', 'now': 'ipv6address'},
    {'slug': 'ipv6prefix', 'title': 'IPv6 prefix', 'help': 'The size of the network of this address (mostly 64).',
     'label': 'Prefix', 'error': 'A prefix from 1 to 128.', 'check': in_range(1, 128), 'if': 'configipv6', 'default': '64'},
    {'slug': 'ipv6gateway', 'title': 'IPv6 gateway', 'help': 'The router this server sends to other networks through over IPv6.',
     'label': 'Gateway', 'error': 'An IPv6 address such as 2001:db8::1.', 'check': is_ip(6), 'if': 'configipv6', 'now': 'ipv6gateway'},
    {'slug': 'configrecursion', 'title': 'DNS', 'help': 'This server resolves names itself through the root servers (recommended: the free '
     'blocklists answer only then). Own DNS servers are an exception, only when the root servers cannot be reached from here.',
     'label': 'Resolve names itself?', 'error': 'Choose yes or no.', 'yesno': True, 'default': 'yes'},
    {'slug': 'dns1', 'title': 'First DNS server', 'help': 'Exception: the DNS server of your network this server asks first. The free blocklists '
     'then often do not answer.',
     'label': 'DNS server', 'error': 'An IPv4 address in your own network, such as 192.168.1.53, and only when the root servers cannot be reached '
     'from here (they answer now: go back and let this server resolve names itself). A public resolver such as 8.8.8.8 is not offered.',
     'check': internal_dns_server, 'unless': 'configrecursion', 'now': 'dns1'},
    {'slug': 'dns2', 'title': 'Second DNS server', 'help': 'The DNS server of your network this server asks when the first does not answer.',
     'label': 'DNS server', 'error': 'An IPv4 address in your own network, such as 192.168.1.54, and only when the root servers cannot be reached '
     'from here. A public resolver such as 8.8.8.8 is not offered.', 'check': internal_dns_server, 'unless': 'configrecursion', 'now': 'dns2'},
    {'slug': 'webpassword', 'title': 'Web admin password', 'help': 'The password of the main admin of the web interface.',
     'label': 'Password', 'error': 'At least 12 characters.', 'password': True},
    {'slug': 'cliusername', 'title': 'Console admin', 'help': 'The user for the admin console over SSH; root cannot log in for it.',
     'label': 'User name', 'error': 'Small letters, digits, - and _, not root.', 'check': lambda v: CLI_USER_RE.match(v) and v != 'root'},
    {'slug': 'clipassword', 'title': 'Console admin password', 'help': 'The password of the console admin.',
     'label': 'Password', 'error': 'At least 12 characters.', 'password': True},
    {'slug': 'rootssh', 'title': 'Root login through SSH',
     'help': 'Off or with an SSH key only is recommended. Off also stops the SSH keys of root: then only the console admin of the '
             'steps before (sudo, password) can log in over SSH, so check that login before you close this session. Shown is what '
             'is in effect now; it stays like that unless you choose another value.',
     'label': 'Root login through SSH', 'error': 'Choose off, with an SSH key only, or on.', 'choices': lambda: ['off', 'key-only', 'on'],
     'shown': lambda value: {'off': tr('Off'), 'key-only': tr('With an SSH key only'), 'on': tr('On, also with a password')}.get(value, value),
     'now': 'rootssh'},
    {'slug': 'configvirtual', 'title': 'Hypervisor tools', 'help': 'The guest tools of the hypervisor this server runs on, if it is a virtual machine.',
     'label': 'Install the hypervisor tools?', 'error': 'Choose yes or no.', 'yesno': True, 'now': 'virtual'},
    {'slug': 'configutc', 'title': 'Hardware clock', 'help': 'Whether the clock of the hardware runs on UTC (recommended; Windows on the same machine uses local time).',
     'label': 'Hardware clock on UTC?', 'error': 'Choose yes or no.', 'yesno': True, 'default': 'yes'},
    {'slug': 'timezone', 'title': 'Time zone', 'help': 'The time zone the reports and the mail log show their times in.',
     'label': 'Time zone', 'error': 'Choose a time zone.', 'choices': timezones, 'now': 'timezone'},
    {'slug': 'ntpservers', 'title': 'Time servers', 'help': 'The NTP servers this server sets its clock from, separated by commas; '
                                                            'the 2FA codes need the right time. Next sets the clock now.',
     'label': 'NTP servers', 'error': 'One to four host names or IP addresses, separated by commas.', 'normalize': ntp_servers_clean,
     'check': bool, 'now': 'ntpservers'},
    {'slug': 'mailserver', 'title': 'Mail server', 'help': 'The mail server of your domain that gets the filtered mail: its IP address or name.',
     'label': 'IP address or name', 'error': 'An IP address or a host name such as mail.example.com.', 'check': SERVER_RE.match},
    {'slug': 'mailserverdns', 'if': 'mailserverunresolved', 'title': 'DNS server for the mail server',
     'help': 'This system cannot resolve the name of the mail server, and mail to it would bounce. Enter the internal DNS server '
             'that knows the name, or go back and enter the IP address of the mail server.',
     'label': 'Internal DNS server', 'error': 'An IP address of a DNS server that knows the name of the mail server.',
     'check': lambda v: '.' in answers['mailserver'] and (is_ip(4)(v) or is_ip(6)(v)) and resolves(answers['mailserver'], v)},
]


def system_now():
    """What is in effect on this host now, read once: names, the interface of the default route, its address, gateway and DNS."""
    if 'system' in answers:
        return answers['system']
    found = {}
    full = socket.gethostname()
    if '.' in full and full.split('.')[0] != 'localhost':
        found.update(hostname=full.split('.')[0], domainname=full.split('.', 1)[1])
    try:
        route = json.loads(subprocess.run(['ip', '-j', '-4', 'route', 'show', 'default'], capture_output=True, text=True, timeout=10).stdout or '[]')
        if route:
            found.update(interface=route[0].get('dev', ''), ipv4gateway=route[0].get('gateway', ''))
            addrs = json.loads(subprocess.run(['ip', '-j', 'addr', 'show', 'dev', route[0].get('dev', '')], capture_output=True, text=True,
                                              timeout=10).stdout or '[]')
            for item in (addrs[0].get('addr_info', []) if addrs else []):
                if item.get('family') == 'inet' and 'ipv4address' not in found:
                    found.update(ipv4address=item.get('local', ''), ipv4netmask=str(item.get('prefixlen', '')),
                                 configipv4='no' if item.get('dynamic') else 'yes')
                elif item.get('family') == 'inet6' and item.get('scope') == 'global' and 'ipv6address' not in found:
                    found['ipv6address'] = item.get('local', '')
        route6 = json.loads(subprocess.run(['ip', '-j', '-6', 'route', 'show', 'default'], capture_output=True, text=True, timeout=10).stdout or '[]')
        if route6:
            found['ipv6gateway'] = route6[0].get('gateway', '')
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    found['ipv6'] = 'yes' if found.get('ipv6address') else 'no'  # a global IPv6 address on the interface of the default route
    try:
        servers = [line.split()[1] for line in open('/etc/resolv.conf') if line.startswith('nameserver') and is_ip(4)(line.split()[1])]
        servers = [server for server in servers if not server.startswith('127.')]
        found.update({f'dns{n}': server for n, server in enumerate(servers[:2], 1)})
    except OSError:
        pass
    try:
        found['timezone'] = os.path.realpath('/etc/localtime').split('/zoneinfo/', 1)[1]
    except (OSError, IndexError):
        pass
    virt = subprocess.run(['systemd-detect-virt', '-q'], capture_output=True, timeout=10).returncode == 0 if shutil.which('systemd-detect-virt') else False
    found['virtual'] = 'yes' if virt else 'no'
    try:
        synced = subprocess.run(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value'], capture_output=True, text=True, timeout=10).stdout.strip()
        found['ntp'] = synced if synced in ('yes', 'no') else ''
    except (OSError, subprocess.SubprocessError):
        found['ntp'] = ''
    try:
        with open('/etc/chrony.conf') as f:
            found['ntpservers'] = ', '.join(line.split()[1] for line in f if line.split()[:1] in (['server'], ['pool']) and len(line.split()) > 1)
    except OSError:
        pass
    try:
        # What sshd takes now; the wizard cannot run sshd -T itself, efa-apply answers through its sudo rule.
        done = subprocess.run(EFA_TIME_SYNC + ['--root-ssh-status'], capture_output=True, text=True, timeout=30)
        line = next((line.split() for line in done.stdout.splitlines() if line.startswith('ROOTSSH ')), [])
        if line[1:2] and line[1] in ('off', 'key-only', 'on'):
            found['rootssh'] = line[1]
    except (OSError, subprocess.SubprocessError):
        pass
    answers['system'] = found
    return found
BY_SLUG = {step['slug']: step for step in STEPS}
# The progress list and the summary show the steps in these groups; first the legal notice and the choices, at the end 2FA and the check.
GROUPS = [('Server', ('hostname', 'domainname', 'email')),
          ('Network', ('interface', 'configipv4', 'ipv4address', 'ipv4netmask', 'ipv4gateway', 'ipv6dns', 'configipv6', 'ipv6address',
                       'ipv6prefix', 'ipv6gateway')),
          ('DNS', ('configrecursion', 'dns1', 'dns2')),
          ('Admins', ('webpassword', 'cliusername', 'clipassword', 'rootssh')),
          ('System', ('configvirtual', 'configutc', 'timezone', 'ntpservers')),
          ('Mail server', ('mailserver', 'mailserverdns'))]
GROUP_OF = {slug: group for group, slugs in GROUPS for slug in slugs}
# Examples in the empty fields, and a pattern the browser checks while typing (the server checks again with the step's check).
EXAMPLES = {'hostname': 'mx1', 'domainname': 'example.com', 'email': 'admin@example.com', 'ipv4address': '192.0.2.10',
            'ipv4gateway': '192.0.2.1', 'ipv6address': '2001:db8::10', 'ipv6prefix': '64', 'ipv6gateway': '2001:db8::1',
            'dns1': '192.0.2.53', 'dns2': '192.0.2.54', 'cliusername': 'efaadmin', 'mailserver': 'mail.example.com',
            'mailserverdns': '192.0.2.53', 'ntpservers': '0.pool.ntp.org, 192.0.2.123'}
IPV4_PATTERN = r'((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)'
PATTERNS = {'hostname': r'[a-zA-Z0-9\-]{1,63}', 'domainname': r'[a-zA-Z0-9]+([\-.][a-zA-Z0-9\-]+)*', 'cliusername': r'[a-z_][a-z0-9_\-]{0,31}',
            'ipv4address': IPV4_PATTERN, 'ipv4gateway': IPV4_PATTERN, 'dns1': IPV4_PATTERN, 'dns2': IPV4_PATTERN, 'ipv6prefix': r'[0-9]{1,3}',
            'ipv6address': r'[0-9a-fA-F:.]{2,45}', 'ipv6gateway': r'[0-9a-fA-F:.]{2,45}'}

app = Flask(__name__)
# Location relative (/first/notice), on every Werkzeug: an absolute one is built from the scheme waitress sees (http behind
# nginx), and form-action 'self' of the https page then blocks the redirect after the form: the page seemed to hang.
app.response_class.autocorrect_location_header = False
# One line per step in the journal (journalctl -u efa-init), never a value or a secret.
log = logging.getLogger('efa-init')
# Its own cookie name: the web interface on the same address has its own (__Host-: Secure, Path=/, no Domain), so neither
# overwrites the other after the setup.
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict', SESSION_COOKIE_SECURE=True,
                  SESSION_COOKIE_NAME='__Host-efa-init')
# shortcut: one wizard state for all visitors, fine because a host is set up once by one admin.
answers = {}
# The answers survive a restart of efa-init (RuntimeDirectoryPreserve=restart): tmpfs, 0600, removed once the setup is done.
STATE_FILE = '/run/efa-init/answers.json'


def answers_save(path=None):
    data = dict(answers)
    for key in ('totp_secret', 'ctotp_secret'):
        if key in data:
            data[key] = efa_totp.secret_text(data[key])
    path = path or STATE_FILE
    try:
        fd = os.open(path + '.new', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f)
        os.replace(path + '.new', path)
    except OSError:
        pass  # without the folder (self-test, a manual start) the answers stay in memory only


def answers_load(path=None):
    try:
        with open(path or STATE_FILE) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return
    if isinstance(data, dict):
        for key in ('totp_secret', 'ctotp_secret'):
            if key in data:
                data[key] = efa_totp.secret_from_text(data[key])
        answers.update(data)


def answers_drop(path=None):
    answers.clear()
    try:
        os.unlink(path or STATE_FILE)
    except OSError:
        pass
commit = {'state': 'idle', 'log': ''}

PAGE = """<!doctype html><html lang="{{ lang }}"><head><meta charset="utf-8"><title>{{ title }} - {{ suffix }}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">{% if refresh %}
<meta http-equiv="refresh" content="{{ refresh }}{% if refresh_to %};url={{ refresh_to }}{% endif %}">{% endif %}
<style>{{ css|safe }}{{ chips|safe }}</style><script src="/wizard.js" defer></script></head><body>
<main class="solo"><header class="brand bar">{{ logo|safe }}
<nav class="seg" aria-label="{{ language }}"><a href="?lang=en" lang="en"{% if lang == 'en' %} class="cur" aria-current="true"{% endif %}>English</a><a href="?lang=de" lang="de"{% if lang == 'de' %} class="cur" aria-current="true"{% endif %}>Deutsch</a></nav></header>
<div class="card">{% if number %}<p class="step">{{ step_text }}</p><div class="prog" role="progressbar" aria-valuemin="1" aria-valuemax="{{ total }}" aria-valuenow="{{ number }}" aria-label="{{ step_text }}"><i style="width:{{ (100 * number / total)|round }}%"></i></div>
<ol class="groups">{% for name, state in groups %}<li class="{{ state }}"{% if state == 'cur' %} aria-current="step"{% endif %}>{{ name }}</li>{% endfor %}</ol>{% endif %}
{% if note %}<p class="ok" role="status">{{ note }}</p>{% endif %}{% if error %}<p class="err" role="alert">{{ error }}</p>{% endif %}{{ body|safe }}</div></main></body></html>"""


def page(body, error=None, refresh=False, where=None, refresh_to=None):
    """One page of the wizard in the look of the web interface (efa_style); where: (kind, slug) for the step number and the progress."""
    number = total = None
    groups = []
    if where:
        number, total, _back = position(*where)
        pages = journey()
        names = []
        for kind, slug in pages:
            name = 'Start' if kind == 'first' else GROUP_OF.get(slug) if kind == 'step' else '2FA' if kind == 'twofactor' else 'Check'
            if not names or names[-1] != name:
                names.append(name)
        current = 'Start' if where[0] == 'first' else GROUP_OF.get(where[1]) if where[0] == 'step' else '2FA' if where[0] == 'twofactor' else 'Check'
        seen = False
        for name in names:
            state = 'cur' if name == current else 'next' if seen else 'done'
            seen = seen or name == current
            groups.append((tr(name), state))
    title = re.search(r'<h2>(.*?)</h2>', body)
    return render_template_string(PAGE, body=body, error=tr(error) if error else None, refresh=refresh, refresh_to=refresh_to,
                                  lang=session.get('lang', 'en'), css=efa_style.TOKENS + efa_style.BASE, logo=efa_style.LOGO,
                                  chips=efa_setup.CHIPS_CSS, number=number, total=total, groups=groups,
                                  title=re.sub('<[^>]+>', '', title.group(1)) if title else 'eFa-next',
                                  step_text=tr('Step {number} of {total}').format(number=number, total=total), note=session.pop('note', None), suffix=tr('eFa-next setup'), language=tr('Language'))


def actions(where, label='Next', link=None):
    """Back on the left (not on the first page), the main button on the right; link: the main action as a link instead of a button."""
    back = position(*where)[2]
    left = f'<a class="btn s" href="{back}">{te("Back")}</a>' if back else ''
    right = f'<a class="btn next" href="{link}">{te(label)}</a>' if link else f'<button class="next">{te(label)}</button>'
    return f'<div class="actions">{left}{right}</div>'


def tr(text):
    """English is the default, German the alternative (efa_i18n, de.po)."""
    return efa_i18n.catalog(session.get('lang', 'en')).gettext(text)


def te(text, **values):
    """tr, escaped for HTML; values filled in after the translation."""
    return str(escape(tr(text).format(**values) if values else tr(text)))


def csrf_token():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_urlsafe(32)
    return session['csrf']


# Werkzeug 2.0.3 of EL9 (CVE-2023-46136, CVE-2024-49767): the wizard is open without login before the setup, and protect()
# reads the form of every POST. It has text forms only: no multipart, and a body far below this cap.
MAX_FORM = 1024 * 1024
app.config['MAX_CONTENT_LENGTH'] = MAX_FORM


@app.before_request
def body_limits():
    if request.mimetype == 'multipart/form-data':
        abort(415)
    if (request.content_length or 0) > MAX_FORM:
        abort(413)


@app.before_request
def protect():
    if request.method == 'POST' and not hmac.compare_digest(request.form.get('csrf', ''), session.get('csrf') or secrets.token_urlsafe(8)):
        abort(403)
    wanted = request.args.get('lang')
    changed = wanted in efa_i18n.LANGUAGES and wanted != session.get('lang', 'en')
    if changed:
        session['lang'] = wanted
    if request.endpoint not in ('unlock', 'wizard_js') and session.get('setup') not in setup['unlocked']:
        return redirect(url_for('unlock'))
    if changed:
        # The language stays for the rest of the wizard and becomes the admin's language; a confirmation keeps the digest
        # of the text as it was shown (answers['lang']), so a switch does not ask it again and does not start the walk anew.
        answers['uilang'] = wanted
        answers_save()


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
            log.info('setup code accepted')
            return redirect(url_for('language'))
        else:
            setup['failed'] += 1
            error = 'Wrong setup code.'
            log.info('wrong setup code (%d of %d tries)', setup['failed'], SETUP_TRIES)
    return page(f"""<h2>{te('Setup code')}</h2><p>{te('Enter the setup code. On the console of this server:')} <code>cat {SETUP_CODE_FILE}</code></p>
<form method="post"><input type="hidden" name="csrf" value="{csrf_token()}"><label>{te('Setup code')} <input name="code" required autofocus
autocomplete="off"></label><button>{te('Next')}</button></form>""", error=error)


WIZARD_JS = """'use strict';
document.querySelectorAll('[data-error]').forEach(function (field) {
  var shown = document.getElementById(field.getAttribute('aria-describedby'));
  var again = document.querySelector('input[name=repeat]');
  function check() {
    if (again && field.name === 'value') { again.setCustomValidity(again.value && again.value !== field.value ? field.dataset.same : ''); }
    var bad = field.value !== '' && !field.checkValidity();
    field.setAttribute('aria-invalid', bad ? 'true' : 'false');
    if (shown && !shown.dataset.server) { shown.textContent = bad ? field.dataset.error : ''; }
  }
  field.addEventListener('input', function () { if (shown) { delete shown.dataset.server; } check(); });
  field.addEventListener('blur', check);
  if (again) { again.addEventListener('input', check); }
});
var follow = document.getElementById('follow');
if (follow) {
  // The server comes back at its new address: the icon of the web interface loads there once it runs and the browser trusts it.
  var target = follow.dataset.url, tries = 0, started = Date.now(), wait = 3;
  var shown = follow.querySelector('span');
  var tick = function () {
    if (wait > 0) { shown.textContent = follow.dataset.next.replace('{s}', wait); wait -= 1; setTimeout(tick, 1000); return; }
    shown.textContent = follow.dataset.checking;
    var probe = new Image();
    probe.onload = function () { location.href = target; };
    probe.onerror = function () {
      tries += 1;
      wait = Math.min(Math.round(3 * Math.pow(1.5, tries)), 30);
      if (Date.now() - started > 300000) { document.getElementById('hint').open = true; }
      tick();
    };
    probe.src = target + 'favicon.svg?' + Date.now();
  };
  tick();
}
document.querySelectorAll('input[name=browser_time]').forEach(function (field) {
  field.form.addEventListener('submit', function () { field.value = Date.now() / 1000; });
});
document.querySelectorAll('button[data-copy]').forEach(function (button) {
  button.hidden = false;
  button.addEventListener('click', function () {
    var text = Array.prototype.map.call(document.querySelectorAll('.codes code'), function (c) { return c.textContent; }).join('\\n');
    navigator.clipboard.writeText(text).then(function () { button.textContent = button.dataset.done; });
  });
});
"""


@app.route('/wizard.js')
def wizard_js():
    return Response(WIZARD_JS, mimetype='text/javascript')


@app.after_request
def harden(response):
    # The page that follows the server to its new address allows exactly that origin for its check (img-src), no other.
    follow = getattr(request, 'follow_origin', '')
    response.headers.update({'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff',
                             'Content-Security-Policy': f"default-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:{' ' + follow if follow else ''}; "
                                                        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
                             'Cache-Control': 'no-store'})
    if request.method == 'POST' and commit['state'] != 'done':
        answers_save()
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
    """(value, None), or (None, the message for a wrong entry), in English: the page translates it."""
    if step.get('yesno'):
        value = form.get('value', '')
        return (value, None) if value in ('yes', 'no') else (None, step['error'])
    value = form.get('value', '').strip()
    if any(char in value for char in '\r\n\0'):
        # The answers go to efa-apply as KEY:value lines.
        return None, step['error']
    if step.get('password'):
        if len(value) < MIN_PASSWORD:
            return None, step['error']
        if value != form.get('repeat', ''):
            return None, 'The two entries are not the same. Please enter the password again.'
        return value, None
    if step.get('normalize'):
        value = step['normalize'](value) or ''
    if 'choices' in step:
        return (value, None) if value in step['choices']() else (None, step['error'])
    return (value, None) if step['check'](value) else (None, step['error'])


def journey():
    """Every page of the wizard in order, with the answers given so far: the first steps, the settings, 2FA (guided), the check."""
    return ([('first', slug) for slug in first_steps()] + [('step', item['slug']) for item in active_steps()]
            + ([('twofactor', None)] if answers.get('variant') == 'guided' else []) + [('verify', None)])


def journey_url(where):
    kind, slug = where
    return url_for(kind, slug=slug) if slug else url_for(kind)


def position(kind, slug=None):
    """(number, total, url of the page before or None) of a page in journey()."""
    pages = journey()
    index = pages.index((kind, slug)) if (kind, slug) in pages else 0
    return index + 1, len(pages), journey_url(pages[index - 1]) if index else None


@app.route('/')
def language():
    return redirect(url_for('verify') if 'notice' in answers else url_for('first', slug='notice'))


# 6.0.0.5: before the settings the note on presets (Text A), the setup variant (B), the EU link (C, in both variants), without EU
# link the typed confirmation (D), and only guided the frameworks (E). Each confirmation keeps the digest of the text as shown.
# HARD-W: the step of the frameworks also holds the security standards, in both variants (manual: the standards only).
FIRST = ('notice', 'variant', 'eulink', 'noeu', 'frameworks')


def first_steps():
    return [slug for slug in FIRST if slug != 'noeu' or answers.get('eulink') == 'no']


def first_form(slug):
    lang = session.get('lang', 'en')
    if slug == 'notice':
        return efa_setup.notice_html(tr, 'notice' in answers)
    if slug == 'variant':
        return efa_setup.variant_html(tr, answers.get('variant', ''))
    if slug == 'eulink':
        return efa_setup.eulink_html(tr, answers.get('eulink', ''))
    if slug == 'noeu':
        return efa_setup.noeu_html(tr, lang)
    standards = efa_setup.standards_html(tr, answers.get('standards', []))
    return efa_setup.frameworks_html(tr, answers.get('frameworks', []), answers.get('note', '')) + standards if answers.get('variant') == 'guided' else standards


def first_take(slug, form):
    """Stores the answer of one first step; returns an error text or None."""
    lang = session.get('lang', 'en')
    if slug == 'notice':
        if form.get('notice') != 'yes':
            return tr('Please confirm the note to go on.')
        answers.update(notice=efa_setup.confirmation(efa_setup.notice_digest(tr)), lang=lang)
    elif slug == 'variant':
        if form.get('variant') not in efa_setup.VARIANTS:
            return tr(efa_setup.VARIANT_TITLE)
        if answers.get('variant') != form['variant']:
            answers.pop('frameworks', None)  # the page of the frameworks asks again: guided shows the frameworks too
        answers['variant'] = form['variant']
    elif slug == 'eulink':
        if form.get('eulink') not in ('yes', 'no'):
            return tr(efa_setup.EULINK_TITLE)
        answers['eulink'] = form['eulink']
        if form['eulink'] == 'yes':
            answers.pop('noeu', None)
    elif slug == 'noeu':
        if form.get('noeu') != 'yes' or not efa_setup.phrase_ok(form.get('phrase', '')):
            return tr('Tick the box and type the phrase to confirm.')
        answers['noeu'] = efa_setup.confirmation(efa_setup.noeu_digest(tr, lang))
    else:
        guided = answers.get('variant') == 'guided'
        note = form.get('note', '').strip() if guided else ''
        if not efa_setup.NOTE_RE.match(note):
            return tr(efa_setup.FRAMEWORKS_OTHER)
        frameworks = efa_setup.frameworks_clean(form.getlist('frameworks')) if guided else []
        # The same standards as the hardening wizard; a framework with a documented mapping adds its standards.
        answers.update(frameworks=frameworks, note=note, standards=efa_setup.standards_taken(form.getlist('standards'), frameworks))
    return None


@app.route('/first/<slug>', methods=['GET', 'POST'])
def first(slug):
    if slug not in first_steps():
        return redirect(url_for('verify'))
    error = None
    if request.method == 'POST':
        error = first_take(slug, request.form)
        log.info('first step %s %s', slug, 'done' if error is None else 'refused')
        if error is None:
            steps = first_steps()
            following = steps[steps.index(slug) + 1] if slug in steps[:-1] else None
            return redirect(url_for('first', slug=following) if following else url_for('step', slug=STEPS[0]['slug']))
    return page(f'<form method="post"><input type="hidden" name="csrf" value="{csrf_token()}">{first_form(slug)}{actions(("first", slug))}</form>',
                error=error, where=('first', slug))


def first_missing():
    keys = {'notice': 'notice', 'variant': 'variant', 'eulink': 'eulink', 'noeu': 'noeu', 'frameworks': 'frameworks'}
    return next((slug for slug in first_steps() if keys[slug] not in answers), None)


def main_admin_label():
    return 'admin@' + '.'.join(part for part in (answers.get('hostname'), answers.get('domainname')) if part)


# The recovery codes in clear text, in memory only and only until the admin confirms they are saved (never in answers.json).
shown_codes = {'codes': None}
# Every user has an own 2FA (owner's rule): the main admin (web) first, then the console admin (SSH), each its own secret,
# code and recovery codes. Keys of the console admin start with c.
TOTP_KEYS = ('totp_secret', 'totp_step', 'totp_recovery', 'totp_saved')


def totp_phase():
    """'' while the 2FA of the main admin is not done, 'c' for the console admin, None when both are."""
    if 'totp_saved' not in answers:
        return ''
    return 'c' if 'ctotp_saved' not in answers and answers.get('cliusername') else None


def totp_label(phase):
    """The account in the app: who and which host, so two entries of this server are told apart."""
    host = '.'.join(part for part in (answers.get('hostname'), answers.get('domainname')) if part)
    return main_admin_label() if phase == '' else f'{answers.get("cliusername", "")}@{host}'


def totp_heading(phase):
    return te('Main admin (web interface)') if phase == '' else te('Console admin {name} (SSH)', name=answers.get('cliusername', ''))


def codes_form(phase=''):
    token = f'<input type="hidden" name="csrf" value="{csrf_token()}">'
    codes = ''.join(f'<code>{escape(code)}</code>' for code in shown_codes['codes'])
    return (f'<h2>{te(efa_setup.TOTP_TITLE)}</h2><h3>{totp_heading(phase)}</h3>'
            f'<p class="help">{te("Keep these codes safe, each works once. They are not shown again.")}</p>'
            f'<div class="codes" aria-label="{te("2FA recovery codes")}">{codes}</div>'
            f'<form method="post" action="{url_for("codes_pdf")}">{token}<button class="s">{te("Download as PDF")}</button>'
            f'<button type="button" class="s" data-copy hidden data-done="{te("Copied")}">{te("Copy")}</button></form>'
            f'<form method="post">{token}<label><input type="checkbox" name="saved" value="yes" required> {te("I have saved the codes")}</label>'
            f'{actions(("twofactor", None))}</form>')


@app.route('/twofactor', methods=['GET', 'POST'])
def twofactor():
    """Guided: the 2FA (Text F) before the setup runs, for each user its own: the main admin, then the console admin (SSH)."""
    if answers.get('variant') != 'guided':
        return redirect(url_for('verify'))
    error, offer_sync = None, False
    if request.method == 'POST' and request.form.get('again') == 'yes':
        for key in TOTP_KEYS + tuple('c' + key for key in TOTP_KEYS):
            answers.pop(key, None)
        shown_codes['codes'] = None
    if request.method == 'POST' and request.form.get('sync') == 'yes':
        synced, after = time_sync(answers.get('ntpservers') or '')
        session['note'] = (tr('Clock synchronized, {ms} ms off.').format(ms=round(abs(after or 0) * 1000)) if synced
                           else tr('The clock could not be synchronized: UDP port 123 to the time servers blocked, a name that does not resolve, '
                                   'or no network. Next again goes on without.'))
        return redirect(url_for('twofactor'))
    phase = totp_phase()
    if phase is None:
        return page(f'<p>{totp_heading("")}: OK</p>' + (f'<p>{totp_heading("c")}: OK</p>' if answers.get('cliusername') else '')
                    + f'<form method="post"><input type="hidden" name="csrf" value="{csrf_token()}"><input type="hidden" name="again" value="yes">'
                    f'<button class="s">{te("2FA: set up the app")}</button></form>'
                    f'{actions(("twofactor", None), link=url_for("verify"))}', where=('twofactor', None))
    key = lambda name: phase + name
    if request.method == 'POST' and 'saved' in request.form and shown_codes['codes']:
        if request.form.get('saved') == 'yes':
            answers[key('totp_saved')] = 'yes'
            shown_codes['codes'] = None
            return redirect(url_for('twofactor') if totp_phase() is not None else url_for('verify'))
    if key('totp_step') in answers and shown_codes['codes']:
        return page(codes_form(phase), where=('twofactor', None))
    if key('totp_step') in answers:
        # The codes were lost (a restart) before they were saved: the app checks a new code, which gives new codes.
        answers.pop(key('totp_step'), None)
        answers.pop(key('totp_recovery'), None)
    if key('totp_secret') not in answers:
        answers[key('totp_secret')] = os.urandom(20)
    secret = answers[key('totp_secret')]
    if request.method == 'POST' and 'code' in request.form:
        step_now = efa_totp.totp_step(secret, request.form.get('code', ''), 0)
        if step_now is None:
            # The code fits only within 30 s of this server's clock: the time shown lets the admin compare (a new VM is often off).
            # Local time with its zone first, like the phone shows it; UTC alone read as an hour off. tzset: the zone may have changed since the start.
            time.tzset()
            now = time.time()
            error = (tr('Wrong code: check the time of the phone and try the next code.') + ' '
                     + tr('Time on this server: {time} ({utc} UTC)').format(time=time.strftime('%H:%M:%S %Z', time.localtime(now)),
                                                                           utc=time.strftime('%H:%M:%S', time.gmtime(now))))
            skew = clock_skew(request.form.get('browser_time', ''))
            if skew is not None:
                error += ' ' + tr('The clock of this server is {minutes} minutes off; on its console: {command}').format(
                    minutes=round(skew / 60, 1), command='chronyc -a makestep')
            log.info('2FA code wrong%s', f', clock {skew:+.0f} s against the browser' if skew is not None else '')
            offer_sync = skew is not None
        else:
            codes = efa_totp.recovery_codes()
            answers.update({key('totp_step'): step_now, key('totp_recovery'): [efa_totp.recovery_hash(code) for code in codes]})
            shown_codes['codes'] = codes
            return redirect(url_for('twofactor'))
    uri = efa_totp.uri(secret, totp_label(phase))
    sync = (f'<form method="post"><input type="hidden" name="csrf" value="{csrf_token()}"><button class="s" name="sync" value="yes">'
            f'{te("Synchronize the clock now")}</button></form>' if offer_sync else '')
    who = (te('Each admin has an own 2FA: this one is for the login of the main admin in the web interface; the console admin follows.')
           if phase == '' else te('An own app entry for the login of {name} over SSH; the code of the main admin does not count there.',
                                  name=answers.get('cliusername', '')))
    return page(sync + f'<h2>{te(efa_setup.TOTP_TITLE)}</h2><h3>{totp_heading(phase)}</h3><p>{te(efa_setup.TOTP_TEXT)}</p>'
                f'<p class="help">{who}</p><p>{efa_qr.svg(uri)}</p><p><code>{efa_totp.grouped(secret)}</code> · {escape(totp_label(phase))}</p>'
                f'<form method="post"><input type="hidden" name="csrf" value="{csrf_token()}"><label>{te("Code of the app (6 digits)")} <input name="code" '
                f'required autofocus inputmode="numeric" autocomplete="one-time-code" maxlength="8"></label><input type="hidden" name="browser_time">'
                f'{actions(("twofactor", None))}</form>',
                error=error, where=('twofactor', None))


def clock_skew(browser_time, now=None):
    """Seconds this server is ahead of the browser (wizard.js sends its time), None within 30 s (the window of a code) or without a time."""
    try:
        skew = (time.time() if now is None else now) - float(browser_time)
    except ValueError:
        return None
    return skew if 30 < abs(skew) < 86400 * 365 else None


@app.route('/twofactor/codes.pdf', methods=['POST'])
def codes_pdf():
    """The recovery codes as PDF, made in memory while the codes page is valid; gone once they are confirmed as saved."""
    if answers.get('variant') != 'guided' or not shown_codes['codes']:
        abort(404)
    host = '.'.join(part for part in (answers.get('hostname'), answers.get('domainname')) if part)
    phase = totp_phase() or ''
    lines = ['eFa-next: ' + tr('2FA recovery codes'), '', f'{tr("Host")}: {host}', f'{tr("User")}: {totp_label(phase)}',
             f'{tr("Created")}: {time.strftime("%Y-%m-%d %H:%M %Z")}', ''] + shown_codes['codes'] + [
             '', tr('Each code logs in once instead of the code of the app.'),
             tr('Keep this page offline and locked away; anyone with a code and the password can log in.')]
    body = efa_pdf.build(lines, info={'Title': 'eFa-next 2FA recovery codes', 'Producer': 'eFa-next', 'Creator': 'eFa-next'})
    name = 'main-admin' if phase == '' else 'console-' + answers.get('cliusername', '')
    return Response(body, mimetype='application/pdf', headers={'Content-Disposition': f'attachment; filename="efa-next-recovery-codes-{name}.pdf"'})


@app.route('/step/<slug>', methods=['GET', 'POST'])
def step(slug):
    current = BY_SLUG.get(slug)
    if current is None:
        abort(404)
    # The legal notice and the EU and risk choices come first: going to a step does not skip them.
    if first_missing():
        return redirect(url_for('first', slug=first_missing()))
    error = None
    if request.method == 'POST':
        value, error = validate(current, request.form)
        if error is None:
            if slug == 'ntpservers':
                synced, after = time_sync(value)
                if synced:
                    session['note'] = tr('Clock synchronized, {ms} ms off.').format(ms=round(abs(after or 0) * 1000))
                elif answers.get('ntp_failed') != value:
                    # Once more with the same servers goes on: the clock may be right already, the 2FA step shows it.
                    answers['ntp_failed'] = value
                    return page(step_form(current, tr('The clock could not be synchronized: UDP port 123 to the time servers blocked, '
                                                      'a name that does not resolve, or no network. Next again goes on without.'), value),
                                where=('step', slug))
            answers[slug] = value
            log.info('step %s done', slug)
            if slug == 'mailserver':
                answers['mailserverunresolved'] = 'no' if mail_server_resolves(value) else 'yes'
            following = next_slug(slug)
            return redirect(url_for('step', slug=following) if following else url_for('verify'))
    return page(step_form(current, error, request.form.get('value', '') if error else None), where=('step', slug))


def step_form(current, error=None, typed=None):
    """Title, one sentence what is asked, the field with the value in effect (or the one given before), the error below it."""
    token = csrf_token()
    slug = current['slug']
    now = system_now().get(current.get('now', ''), '') if current.get('now') else ''
    value = typed if typed is not None else answers.get(slug, now or current.get('default', ''))
    saved = '' if current.get('password') else str(escape(value))
    label = te(current['label'])
    live = f'aria-describedby="err-{slug}" data-error="{te(current["error"])}"'
    if current.get('yesno'):
        field = ''.join(f'<label><input type="radio" name="value" value="{v}" {"checked" if saved == v else ""} required> '
                        f'{te(t)}</label>' for v, t in (('yes', 'Yes'), ('no', 'No')))
        field = f'<fieldset class="field"><legend>{label}</legend>{field}</fieldset>'
    elif 'choices' in current:
        shown = current.get('shown', lambda c: c)
        options = ''.join(f'<option value="{escape(c)}" {"selected" if saved == c else ""}>{escape(shown(c))}</option>' for c in current['choices']())
        field = f'<label class="field">{label} <select name="value" required>{options}</select></label>'
    elif current.get('password'):
        field = (f'<label class="field">{label} <span class="hint">{te("At least {n} characters.", n=MIN_PASSWORD)}</span><input type="password" '
                 f'name="value" minlength="{MIN_PASSWORD}" required autofocus autocomplete="new-password" {live} '
                 f'data-same="{te("The two entries are not the same. Please enter the password again.")}"></label>'
                 f'<label class="field">{te("Repeat the password")} <input type="password" name="repeat" required autocomplete="new-password"></label>')
    else:
        example = f' placeholder="{escape(EXAMPLES[slug])}"' if slug in EXAMPLES else ''
        pattern = f' pattern="{escape(PATTERNS[slug])}"' if slug in PATTERNS else ''
        kind = 'email' if slug == 'email' else 'text'
        field = (f'<label class="field">{label} <input type="{kind}" name="value" value="{saved}" required autofocus spellcheck="false" '
                 f'autocapitalize="off"{example}{pattern} {live}></label>')
    wrong = (f'<p class="err" id="err-{slug}" data-server="1" role="alert">{te(error)}</p>' if error
             else f'<p class="err" id="err-{slug}" role="alert"></p>')
    if slug == 'timezone' and system_now().get('ntp'):
        # 2FA codes fit only within 30 s of this clock.
        state = te('Yes') if system_now()['ntp'] == 'yes' else te('No') + ' - chronyc -a makestep'
        field += f'<p class="help">{te("Clock synchronized (NTP):")} {state}</p>'
    return (f'<h2>{te(current["title"])}</h2><p class="help">{te(current["help"])}</p>'
            f'<form method="post"><input type="hidden" name="csrf" value="{token}">{field}{wrong}{actions(("step", slug))}</form>')


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if first_missing():
        return redirect(url_for('first', slug=first_missing()))
    missing = [s['slug'] for s in active_steps() if s['slug'] not in answers]
    if missing:
        return redirect(url_for('step', slug=missing[0]))
    if answers.get('variant') == 'guided' and totp_phase() is not None:
        # Text F: in the guided setup 2FA of the main admin is a must, before anything is set.
        return redirect(url_for('twofactor'))
    if request.method == 'POST':
        if request.form.get('accept') != 'yes':
            return redirect(url_for('verify'))
        # 5y: the digest of the legal texts that were confirmed with the box.
        answers['legal'] = legal_digest()
        if commit['state'] != 'running':
            commit.update(state='running', log='', target=new_address(), fqdn='.'.join((answers['hostname'], answers['domainname'])),
                          ssh_later=any(title == 'SSH' for title, _shown in efa_setup.standards_summary(tr, answers.get('standards', []))))
            log.info('setup started')
            threading.Thread(target=run_commit, daemon=True).start()
        return redirect(url_for('progress'))
    row = '<tr><th scope="row">{{ l }}</th><td>{{ v }}</td></tr>'
    change = te('Edit')
    chosen = [efa_setup.FRAMEWORKS[key][0] for key in answers.get('frameworks', [])]
    rows = ''
    for slug, label, shown in (('variant', tr(efa_setup.VARIANT_TITLE), tr(efa_setup.VARIANT_TEXT[answers['variant']][0])),
                               ('eulink', tr(efa_setup.EULINK_TITLE), tr('Yes') if answers['eulink'] == 'yes' else tr('No')),
                               ('frameworks', tr(efa_setup.FRAMEWORKS_TITLE), ', '.join(chosen + ([answers['note']] if answers.get('note') else [])))):
        if slug in first_steps() and (slug != 'frameworks' or answers.get('variant') == 'guided'):
            rows += render_template_string(row, l=label, v=shown)
    for title, note in efa_setup.notes(answers.get('frameworks', [])):
        rows += render_template_string(row, l=title, v=f'{tr(note)} ({tr(efa_setup.NONBINDING)})')
    for title, shown in efa_setup.standards_summary(tr, answers.get('standards', [])):
        rows += render_template_string(row, l=title, v=shown)
    summary = f'<h3>{te("Start")} <a href="{url_for("first", slug="variant")}">{change}</a></h3><table>{rows}</table>'
    active = {item['slug'] for item in active_steps()}
    for group, slugs in GROUPS:
        items = [BY_SLUG[slug] for slug in slugs if slug in active]
        if not items:
            continue
        rows = ''
        for item in items:
            value = answers[item['slug']]
            if item.get('password'):
                value = '********'
            elif item.get('yesno'):
                value = tr('Yes') if value == 'yes' else tr('No')
            elif 'shown' in item:
                value = item['shown'](value)
            rows += render_template_string(row, l=tr(item['title'] if item.get('password') else item['label']), v=value)
        summary += f'<h3>{te(group)} <a href="{url_for("step", slug=items[0]["slug"])}">{change}</a></h3><table>{rows}</table>'
    if answers.get('variant') == 'guided':
        summary += f'<h3>2FA <a href="{url_for("twofactor")}">{change}</a></h3><table>{render_template_string(row, l=tr("2FA of my login"), v="OK")}</table>'
    return page(f"""<h2>{te('Check the settings')}</h2><p class="help">{te('Nothing is changed yet. Check each group; the setup starts with the button below.')}</p>
{summary}
<form method="post"><input type="hidden" name="csrf" value="{csrf_token()}">
<p><label><input type="checkbox" name="accept" value="yes" required> {te(DISCLAIMER_SHORT)}
(<a href="https://github.com/MarkusLorber/eFa-next/blob/master/DISCLAIMER.md" target="_blank" rel="noopener noreferrer">DISCLAIMER.md</a>)</label></p>
{actions(('verify', None), 'Start the setup')}</form>""", where=('verify', None))


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
             'ROOTSSH': a.get('rootssh', ''),
             'VMTOOLS': yes_no(a['configvirtual']), 'ISUTC': yes_no(a['configutc']), 'TZONE': a['timezone'],
             'MAILSERVER': a['mailserver']}
    if a.get('mailserverunresolved') == 'yes':
        lines['MAILSERVERDNS'] = a['mailserverdns']
    if a.get('legal'):
        lines['LEGALACCEPTED'] = a['legal']
    if a.get('variant'):
        lines.update(SETUPVARIANT=a['variant'], EULINK=a['eulink'], NOTICEACCEPTED=a['notice'], SETUPLANG=a.get('uilang', a.get('lang', 'en')))
        if a.get('noeu'):
            lines['EULINKCONFIRM'] = a['noeu']
        if a.get('frameworks'):
            lines['FRAMEWORKS'] = ','.join(a['frameworks'])
        if a.get('note'):
            lines['FRAMEWORKNOTE'] = a['note']
        if a.get('standards'):
            lines['STANDARDS'] = ','.join(a['standards'])
        if a.get('totp_step'):
            lines.update(TOTPSECRET=efa_totp.secret_text(a['totp_secret']), TOTPSTEP=a['totp_step'], TOTPRECOVERY=','.join(a['totp_recovery']))
            if a.get('ctotp_saved'):
                lines.update(CONSOLETOTPSECRET=efa_totp.secret_text(a['ctotp_secret']), CONSOLETOTPSTEP=a['ctotp_step'],
                             CONSOLETOTPRECOVERY=','.join(a['ctotp_recovery']))
    return ''.join(f'{key}:{value}\n' for key, value in lines.items())


def run_commit():
    try:
        done = subprocess.run(EFA_APPLY, input=commit_answers(), capture_output=True, text=True, timeout=3600)
        commit.update(state='done' if done.returncode == 0 else 'failed', log=(done.stdout + done.stderr)[-4000:])
        log.info('setup %s', commit['state'])
        if commit['state'] == 'done':
            answers_drop()
    except (subprocess.SubprocessError, OSError) as err:
        commit.update(state='failed', log=str(err))
    finally:
        # Plain-text passwords and the 2FA secret are no longer needed.
        answers.pop('webpassword', None)
        answers.pop('clipassword', None)
        for key in TOTP_KEYS + tuple('c' + key for key in TOTP_KEYS):
            answers.pop(key, None)
        if commit['state'] != 'done':
            answers_save()


def new_address():
    """The address the browser finds the server at after the setup: the new static IPv4 address if the wizard was opened by IP."""
    host = urllib.parse.urlsplit(request.host_url).hostname or ''
    static = answers.get('ipv4address') if answers.get('configipv4') == 'yes' else ''
    try:
        by_ip = bool(ipaddress.ip_address(host))
    except ValueError:
        by_ip = False
    target = static if static and by_ip and host != static else host
    return f'https://[{target}]/' if ':' in target else f'https://{target}/'


def follow_page(moving):
    """Big: the new address, a countdown to the next check, the status; without the script a refresh to it and the link."""
    target, fqdn = commit.get('target') or new_address(), commit.get('fqdn', '')
    if commit['state'] == 'done':
        session.clear()  # the wizard is over: its cookie goes, the web interface has its own
    request.follow_origin = target.rstrip('/')
    title = te('The server moves to its new address') if moving and commit['state'] != "done" else te('The server restarts')
    text = (te('The settings are applied now; the connection to the old address ends. This page opens the new one as soon as it answers.')
            if moving and commit['state'] != "done" else te('Configuration complete. The system restarts now; this page opens the login as soon as the server answers.'))
    name = f'<p>{te("By name, once DNS knows it:")} <code>https://{escape(fqdn)}/</code></p>' if fqdn else ''
    if commit.get('ssh_later'):
        name += f'<p class="warn" role="note">{te(efa_setup.SSH_LATER)}</p>'
    return page(f"""<h2>{title}</h2><p class="help">{text}</p>
<p class="addr"><a class="btn next" href="{escape(target)}">{escape(target)}</a></p>{name}
<p id="follow" role="status" data-url="{escape(target)}" data-next="{te('Next check in {s} s')}" data-checking="{te('Checking...')}">
<span>{te('Waiting for the server...')}</span></p>
<p class="help">{te('The browser warns once about the certificate at the new address: it is the self-signed certificate of this server.')}</p>
<details id="hint"><summary>{te('Not reachable after 5 minutes?')}</summary><ul>
<li>{te('This computer is not in the network of the new address (another VLAN or subnet).')}</li>
<li>{te('The gateway or the netmask is wrong, or a firewall blocks port 443.')}</li>
<li>{te('The browser has not accepted the certificate of the new address yet: open the link above.')}</li></ul>
<p>{te('The address the server really has, on its console:')} <code>ip -brief address</code></p></details>""",
                refresh=300, refresh_to=target)


@app.route('/progress')
def progress():
    state = commit['state']
    if state == 'idle':
        return redirect(url_for('language'))
    if state == 'failed':
        log = render_template_string('{{ t }}', t=commit['log'])
        return page(f'<pre>{log}</pre><div class="actions"><a class="btn s" href="{url_for("language")}">{te("Back")}</a></div>',
                    error='Configuration failed.')
    moving = bool(commit.get('target')) and commit['target'] != f'https://{request.host}/'
    if state == 'done' or moving:
        return follow_page(moving)
    return page(f'<h2>{te("Setting up")}</h2><p>{te("Configuring the system, this takes several minutes...")}</p>', refresh=5)



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
                   clipassword='cli-password-1', rootssh='on', configvirtual='no', configutc='yes', timezone='UTC', ntpservers='192.0.2.123',
                   mailserver='10.0.0.5')
    lines = commit_answers().splitlines()
    # S30: the choice of root login goes to efa-apply as given; a fresh install keeps on unless the admin picks another value.
    assert 'ROOTSSH:on' in lines
    assert 'RECURSION:YES' in lines and 'IPV4ADDRESS:' in lines and 'WEBADMINPASSWORD:web-password-1' in lines and 'ISUTC:YES' in lines
    assert not [line for line in lines if line.startswith('MAILSERVERDNS')]
    answers.update(mailserver='mail.corp.example', mailserverunresolved='yes', mailserverdns='10.0.0.53')
    assert 'MAILSERVERDNS:10.0.0.53' in commit_answers().splitlines()
    # The setup runs only once the disclaimer is accepted.
    app.config.update(TESTING=True, SECRET_KEY=b'test')
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['csrf'] = 'token'
    # Body limits before protect() reads the form: no multipart at all, no body over MAX_FORM.
    assert [f.__name__ for f in app.before_request_funcs[None]][:2] == ['body_limits', 'protect']
    assert client.post('/unlock', data={'csrf': 'token', 'code': 'x'}, content_type='multipart/form-data').status_code == 415
    assert client.post('/unlock', data=b'csrf=token&code=' + b'x' * MAX_FORM, content_type='application/x-www-form-urlencoded').status_code == 413
    assert app.config['MAX_CONTENT_LENGTH'] == MAX_FORM
    # Nothing opens without the setup code of the console, and only so many wrong tries.
    with tempfile.TemporaryDirectory() as folder:
        setup_code_write(folder + '/code')
        assert oct(os.stat(folder + '/code').st_mode)[-3:] == '600' or os.name != 'posix'
    assert app.response_class.autocorrect_location_header is False
    assert client.get('/verify', headers={'Host': '192.0.2.9'}).headers['Location'] == '/unlock', 'relative, never built from the host'
    assert client.get('/verify').headers['Location'].endswith('/unlock') and client.get('/step/hostname').status_code == 302
    assert 'Wrong setup code' in client.post('/unlock', data={'csrf': 'token', 'code': 'nope'}).get_data(as_text=True)
    assert client.post('/unlock', data={'csrf': 'token', 'code': setup['code'].lower()}).status_code == 302
    setup['failed'] = SETUP_TRIES
    assert 'Too many' in client.post('/unlock', data={'csrf': 'token', 'code': setup['code']}).get_data(as_text=True)
    setup['failed'] = 0
    assert validate(BY_SLUG['webpassword'], {'value': 'long-enough-pass\nMAILSERVER:x', 'repeat': 'long-enough-pass\nMAILSERVER:x'})[0] is None
    # 6.0.0.5: the first steps. Without the box no note on presets, without the typed phrase no setup without EU link.
    assert client.get('/verify').headers['Location'].endswith('/first/notice')
    assert 'name="notice"' in client.get('/first/notice').get_data(as_text=True)
    assert 'Please confirm' in client.post('/first/notice', data={'csrf': 'token'}).get_data(as_text=True) and 'notice' not in answers
    assert client.post('/first/notice', data={'csrf': 'token', 'notice': 'yes'}).headers['Location'].endswith('/first/variant')
    assert answers['notice'].split('/')[0] == efa_setup.notice_digest(lambda text: text) and efa_setup.confirmation_ok(answers['notice'])
    client.post('/first/variant', data={'csrf': 'token', 'variant': 'manual'})
    assert client.post('/first/eulink', data={'csrf': 'token', 'eulink': 'no'}).headers['Location'].endswith('/first/noeu')
    assert 'Tick the box' in client.post('/first/noeu', data={'csrf': 'token', 'noeu': 'yes', 'phrase': 'at my risk'}).get_data(as_text=True)
    assert 'Tick the box' in client.post('/first/noeu', data={'csrf': 'token', 'phrase': 'at my own risk'}).get_data(as_text=True) and 'noeu' not in answers
    assert client.post('/first/noeu', data={'csrf': 'token', 'noeu': 'yes', 'phrase': 'At my own risk'}).headers['Location'].endswith('/first/frameworks')
    manual = client.get('/first/frameworks').get_data(as_text=True)
    assert 'name="standards"' in manual and 'name="frameworks"' not in manual, 'manual: the standards, no frameworks'
    client.post('/first/frameworks', data={'csrf': 'token', 'frameworks': ['nis2'], 'standards': ['rfc9325']})
    assert answers['frameworks'] == [] and answers['standards'] == ['rfc9325']
    lines = commit_answers().splitlines()
    assert 'SETUPVARIANT:manual' in lines and 'EULINK:no' in lines and [line for line in lines if line.startswith('EULINKCONFIRM:')]
    assert not [line for line in lines if line.startswith(('TOTP', 'FRAMEWORKS'))] and 'STANDARDS:rfc9325' in lines
    # Guided: the frameworks, then the 2FA of the main admin is a must before the setup runs.
    client.post('/first/variant', data={'csrf': 'token', 'variant': 'guided'})
    assert client.get('/verify').headers['Location'].endswith('/first/frameworks')
    client.post('/first/frameworks', data={'csrf': 'token', 'frameworks': ['pci-dss', 'nis2', 'bogus'], 'note': 'own rules'})
    assert answers['frameworks'] == ['nis2', 'pci-dss'] and client.get('/verify').headers['Location'].endswith('/twofactor')
    assert answers['standards'] == [] and 'name="standards" value="cis-el"' in client.get('/first/frameworks').get_data(as_text=True)
    assert not [line for line in commit_answers().splitlines() if line.startswith('STANDARDS')], 'none chosen: no STANDARDS for efa-apply'
    # HARD-W: the standards of the hardening wizard; BSI TR-02102 as a framework leads to its parts.
    client.post('/first/frameworks', data={'csrf': 'token', 'frameworks': ['pci-dss', 'nis2', 'bsi-tr02102'], 'note': 'own rules',
                                           'standards': ['rfc9325', 'cis-el', 'evil']})
    assert answers['standards'] == ['bsi-02102-1', 'bsi-02102-2', 'rfc9325', 'bsi-02102-4', 'cis-el'], answers['standards']
    client.post('/first/frameworks', data={'csrf': 'token', 'frameworks': ['pci-dss', 'nis2'], 'note': 'own rules', 'standards': ['bsi-02102-2', 'rfc9325', 'cis-el']})
    assert answers['standards'] == ['bsi-02102-2', 'rfc9325', 'cis-el']
    setup_page = client.get('/twofactor').get_data(as_text=True)
    assert '<svg' in setup_page and 'name="code"' in setup_page and efa_totp.grouped(answers['totp_secret']) in setup_page
    window = {efa_totp.hotp(answers['totp_secret'], int(time.time() // 30) + delta) for delta in (-1, 0, 1, 2)}
    wrong = next(code for code in ('000000', '111111', '222222', '333333', '444444') if code not in window)
    wrong_page = client.post('/twofactor', data={'csrf': 'token', 'code': wrong}).get_data(as_text=True)
    assert 'Wrong code' in wrong_page and 'totp_step' not in answers
    assert re.search(r'\d\d:\d\d:\d\d \S+ \(\d\d:\d\d:\d\d UTC\)', wrong_page), 'server time: local with its zone, then UTC'
    skewed = client.post('/twofactor', data={'csrf': 'token', 'code': wrong, 'browser_time': str(time.time() - 420)}).get_data(as_text=True)
    assert 'minutes off' in skewed and 'name="sync"' in skewed, '7 minutes off: the page says so and offers to set the clock'
    assert 'name="sync"' not in client.post('/twofactor', data={'csrf': 'token', 'code': wrong, 'browser_time': str(time.time())}).get_data(as_text=True)
    assert client.post('/twofactor', data={'csrf': 'token', 'code': efa_totp.hotp(answers['totp_secret'], int(time.time() // 30))}).headers['Location'].endswith('/twofactor')
    codes_page = client.get('/twofactor').get_data(as_text=True)
    assert len(re.findall(r'[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}', codes_page)) == 10 and len(answers['totp_recovery']) == 10
    assert 'name="saved"' in codes_page and client.get('/verify').headers['Location'].endswith('/twofactor'), 'the codes are confirmed as saved first'
    # The codes as PDF: made in memory, not stored, only while the page with the codes is valid.
    answers.update(hostname='mx1', domainname='example.org')
    pdf = client.post('/twofactor/codes.pdf', data={'csrf': 'token'})
    text = b''.join(efa_pdf.page_streams(pdf.get_data()))
    assert pdf.status_code == 200 and pdf.mimetype == 'application/pdf' and pdf.headers['Cache-Control'] == 'no-store'
    assert 'attachment' in pdf.headers['Content-Disposition'] and shown_codes['codes'][0].encode() in text and b'mx1.example.org' in text
    assert 'main-admin' in pdf.headers['Content-Disposition']
    # Each user its own 2FA: after the main admin the console admin, with an own secret; the code of the main admin does not count.
    answers['cliusername'] = 'efaadmin'
    assert client.post('/twofactor', data={'csrf': 'token', 'saved': 'yes'}).headers['Location'].endswith('/twofactor') and shown_codes['codes'] is None
    assert client.post('/twofactor/codes.pdf', data={'csrf': 'token'}).status_code == 404, 'no PDF after the codes are confirmed'
    assert client.get('/verify').headers['Location'].endswith('/twofactor'), 'the console admin is set up too before the setup runs'
    console_page = client.get('/twofactor').get_data(as_text=True)
    assert 'efaadmin@mx1.example.org' in console_page and answers['ctotp_secret'] != answers['totp_secret']
    main_code = efa_totp.hotp(answers['totp_secret'], int(time.time() // 30))
    if main_code not in {efa_totp.hotp(answers['ctotp_secret'], int(time.time() // 30) + delta) for delta in (-1, 0, 1)}:
        assert 'Wrong code' in client.post('/twofactor', data={'csrf': 'token', 'code': main_code}).get_data(as_text=True), 'not the code of the main admin'
    client.post('/twofactor', data={'csrf': 'token', 'code': efa_totp.hotp(answers['ctotp_secret'], int(time.time() // 30))})
    assert len(answers['ctotp_recovery']) == 10 and 'console-efaadmin' in client.post('/twofactor/codes.pdf', data={'csrf': 'token'}).headers['Content-Disposition']
    assert client.post('/twofactor', data={'csrf': 'token', 'saved': 'yes'}).headers['Location'].endswith('/verify')
    lines = commit_answers().splitlines()
    assert 'SETUPVARIANT:guided' in lines and 'FRAMEWORKS:nis2,pci-dss' in lines and 'FRAMEWORKNOTE:own rules' in lines and 'SETUPLANG:en' in lines
    assert 'STANDARDS:bsi-02102-2,rfc9325,cis-el' in lines
    assert efa_totp.secret_from_text(next(line for line in lines if line.startswith('TOTPSECRET:'))[11:]) == answers['totp_secret']
    assert efa_totp.secret_from_text(next(line for line in lines if line.startswith('CONSOLETOTPSECRET:'))[18:]) == answers['ctotp_secret']
    # German from the catalog. A switch keeps the confirmations (each keeps the digest of the text as shown) and becomes the admin's language.
    german = client.get('/first/notice?lang=de').get_data(as_text=True)
    assert 'notice' in answers and efa_i18n.catalog('de').gettext(efa_setup.NOTICE_TITLE) in german
    assert efa_i18n.catalog('de').gettext(efa_setup.NOTICE_TITLE) != efa_setup.NOTICE_TITLE, 'Text A in de.po'
    assert 'SETUPLANG:de' in commit_answers().splitlines()
    client.post('/first/notice', data={'csrf': 'token', 'notice': 'yes'})
    assert answers['lang'] == 'de' and answers['notice'].split('/')[0] == efa_setup.notice_digest(efa_i18n.catalog('de').gettext)
    client.get('/first/notice?lang=en')
    client.post('/first/eulink', data={'csrf': 'token', 'eulink': 'yes'})
    page_text = client.get('/verify').get_data(as_text=True)
    assert 'name="accept"' in page_text and 'IT-World ITW GmbH' in page_text and 'DISCLAIMER.md' in page_text
    reply = client.post('/verify', data={'csrf': 'token'})
    assert reply.status_code == 302 and reply.headers['Location'].endswith('/verify') and commit['state'] != 'running'

    # Netmask: 255.255.255.0, /24 and 24 are the same; only a mask that is not contiguous is wrong.
    for given, prefix in (('255.255.255.0', '24'), ('/24', '24'), ('24', '24'), ('255.255.0.0', '16'), ('255.255.255.255', '32'), ('128.0.0.0', '1')):
        assert netmask_prefix(given) == prefix and validate(BY_SLUG['ipv4netmask'], {'value': given}) == (prefix, None), given
    for given in ('255.0.255.0', '0.0.0.0', '33', '0', 'x', '255.255.255.1', '/'):
        assert validate(BY_SLUG['ipv4netmask'], {'value': given})[0] is None, given
    assert not is_ip(4)('192.0.2.256') and not is_ip(4)('192.0.2') and is_ip(6)('2001:db8::1') and not is_ip(6)('2001:db8::g')

    # The time servers: a list of names or addresses; Next sets the clock (efa-apply --time-sync), once more goes on without.
    assert ntp_servers_clean('0.pool.ntp.org,192.0.2.123  2001:db8::1') == '0.pool.ntp.org, 192.0.2.123, 2001:db8::1'
    for wrong in ('', 'a;id', 'host', 'a.example b.example c.example d.example e.example', '-x.example'):
        assert ntp_servers_clean(wrong) == '', wrong
    global time_sync
    real_sync, synced_runs = time_sync, []
    time_sync = lambda servers: (synced_runs.append(servers) or True, 0.0042)
    pages = [kind for kind, _slug in journey()]
    assert [slug for _kind, slug in journey()].index('ntpservers') < len(pages), 'the time step is a step'
    # MIG-DNS: an own DNS server only of the own network and only when the root servers do not answer from here.
    root_cache[:] = [True]
    assert not internal_dns_server('192.168.1.53'), 'the root servers answer: this server resolves itself'
    root_cache[:] = [False]
    assert internal_dns_server('192.168.1.53') and not internal_dns_server('8.8.8.8') and not internal_dns_server('1.1.1.1')
    # One walk forward through all steps and back again: the values stay, each step after the first has Back, the number counts.
    values = {'hostname': 'mx1', 'domainname': 'example.org', 'email': 'a@example.org', 'interface': 'eth0', 'configipv4': 'yes',
              'ipv4address': '192.0.2.10', 'ipv4netmask': '255.255.255.0', 'ipv4gateway': '192.0.2.1', 'ipv6dns': 'no', 'configipv6': 'no',
              'configrecursion': 'no', 'dns1': '192.0.2.53', 'dns2': '192.0.2.54', 'webpassword': long_enough, 'cliusername': 'efaadmin',
              'clipassword': long_enough, 'rootssh': 'on', 'configvirtual': 'no', 'configutc': 'yes', 'timezone': 'UTC', 'ntpservers': '192.0.2.123',
              'mailserver': '192.0.2.25'}
    BY_SLUG['interface']['choices'] = lambda: ['eth0']
    BY_SLUG['timezone']['choices'] = lambda: ['Europe/Vienna', 'UTC']

    def walk(lang_switch_at=None, back_at=None):
        """From the notice to the page after the last step; returns the paths of the pages shown."""
        seen = []
        location = '/first/notice'
        firsts = {'notice': {'notice': 'yes'}, 'variant': {'variant': answers.get('want', 'manual')}, 'eulink': {'eulink': 'yes'},
                  'frameworks': {'frameworks': ['nis2']}}
        while location.startswith(('/first/', '/step/')):
            slug = location.rsplit('/', 1)[1]
            shown = client.get(location).get_data(as_text=True)
            seen.append(location)
            assert ('class="btn s"' in shown) == (location != '/first/notice'), location
            if slug == lang_switch_at:
                client.get(location + '?lang=de')
                client.get(location + '?lang=en')
            if slug == back_at:
                back = re.search(r'<a class="btn s" href="([^"]+)"', shown).group(1)
                client.get(back)
                seen.append(back)
            form = dict(firsts[slug]) if location.startswith('/first/') else {'value': values[slug], 'repeat': values[slug]}
            form['csrf'] = 'token'
            reply = client.post(location, data=form)
            assert reply.status_code == 302, (location, reply.get_data(as_text=True)[-300:])
            location = urllib.parse.urlsplit(reply.headers['Location']).path
        return seen, location

    commit.update(state='idle')
    answers.clear()
    answers['system'] = {'hostname': 'old', 'interface': 'eth0', 'timezone': 'UTC'}
    seen, end = walk()
    assert end == '/verify' and '/step/ipv4address' in seen and '/step/dns1' in seen and answers['ipv4netmask'] == '24'
    # Not synchronized: the step says why; Next again goes on.
    time_sync = lambda servers: (False, None)
    answers.pop('ntpservers', None)
    answers.pop('ntp_failed', None)
    refused = client.post('/step/ntpservers', data={'csrf': 'token', 'value': '192.0.2.123'})
    assert refused.status_code == 200 and 'UDP port 123' in refused.get_data(as_text=True) and 'ntpservers' not in answers
    assert client.post('/step/ntpservers', data={'csrf': 'token', 'value': '192.0.2.123'}).status_code == 302 and answers['ntpservers']
    time_sync = lambda servers: (synced_runs.append(servers) or True, 0.0042)
    summary = client.get('/verify').get_data(as_text=True)
    assert 'Check the settings' in summary and summary.count('>Edit<') >= 6 and '/24 (255.255.255.0)' in summary and long_enough not in summary
    location, back_walk = '/verify', []
    while True:
        shown = client.get(location).get_data(as_text=True)
        back = re.search(r'<a class="btn s" href="([^"]+)"', shown)
        if not back:
            break
        location = back.group(1)
        back_walk.append(location)
        if location.startswith('/step/') and not BY_SLUG[location.rsplit('/', 1)[1]].get('password'):
            slug = location.rsplit('/', 1)[1]
            again = client.get(location).get_data(as_text=True)
            stored = answers[slug]
            assert any(f in again for f in (f'value="{stored}" checked', f'value="{stored}" selected', f'name="value" value="{stored}"')), slug
    assert back_walk[-1] == '/first/notice' and len(back_walk) == len(seen), 'Back leads through every page shown on the way'
    assert [answers[key] for key in ('hostname', 'ipv4address', 'dns2')] == ['mx1', '192.0.2.10', '192.0.2.54'], 'the walk back keeps the values'

    # German: no English text of the wizard left on the pages, the buttons included.
    client.get('/verify?lang=de')
    catalog = efa_i18n.catalog('de')
    for location in seen + ['/verify']:
        shown = client.get(location).get_data(as_text=True)
        for english in ('>Next<', '>Back<', '>Edit<', 'Step ', 'Check the settings', 'eFa-next setup', '"Language"'):
            assert english not in shown, (location, english)
        if location.startswith('/step/'):
            item = BY_SLUG[location.rsplit('/', 1)[1]]
            for key in ('title', 'help', 'label'):
                assert catalog.gettext(item[key]) != item[key] or item[key] in ('DNS', 'Domain', 'Gateway'), (location, item[key])
                assert str(escape(catalog.gettext(item[key]))) in shown, (location, key)
    client.get('/verify?lang=en')

    # Hans: once through in the guided setup, with a switch of the language and a step back on the way, leads to 2FA; nothing twice.
    answers.clear()
    answers.update(system={'interface': 'eth0', 'timezone': 'UTC'}, want='guided')
    seen, end = walk(lang_switch_at='hostname', back_at='email')
    assert end == '/verify' and seen.count('/first/notice') == 1 and seen.count('/step/hostname') == 1
    assert client.get('/verify').headers['Location'].endswith('/twofactor'), 'one pass reaches 2FA'

    # The answers survive a restart: 0600, the 2FA secret as text; gone once the setup is done.
    with tempfile.TemporaryDirectory() as folder:
        answers['totp_secret'] = os.urandom(20)
        before = dict(answers)
        answers_save(folder + '/answers.json')
        assert oct(os.stat(folder + '/answers.json').st_mode)[-3:] == '600' or os.name != 'posix'
        answers.clear()
        answers_load(folder + '/answers.json')
        assert answers == before
        answers_drop(folder + '/answers.json')
        assert not answers and not os.path.exists(folder + '/answers.json')

    # After the start the browser follows the server to its new address; the page allows exactly that origin.
    answers.update(configipv4='yes', ipv4address='192.0.2.10')
    with app.test_request_context('/progress', base_url='https://192.0.2.9'):
        assert new_address() == 'https://192.0.2.10/'
        commit.update(state='running', target=new_address(), fqdn='mx1.example.org')
        shown = follow_page(True)
        policy = harden(app.make_response(shown)).headers['Content-Security-Policy']
        assert "img-src 'self' data: https://192.0.2.10;" in policy and policy.count('https://') == 1
        assert 'data-url="https://192.0.2.10/"' in shown and 'url=https://192.0.2.10/' in shown and 'ip -brief address' in shown
        commit['state'] = 'done'
        session['setup'] = 'x'
        assert 'Configuration complete' in follow_page(True), 'scripts/fresh_wizard.py waits for this text'
        assert not session, 'the last page removes the cookie of the wizard'
        # scripts/fresh_wizard.py reads the error of a step after role="alert">.
        assert re.search(r'role="alert">([^<]+)<', step_form(BY_SLUG['hostname'], 'Letters, digits and hyphens only, such as mx1.', 'a b'))
    with app.test_request_context('/progress', base_url='https://efa.example.org'):
        assert new_address() == 'https://efa.example.org/', 'opened by name: the name stays'
    commit.update(state='idle', target='', fqdn='')
    answers.clear()
    assert synced_runs and synced_runs[0] == '192.0.2.123', 'Next on the time step sets the clock'
    with app.test_request_context('/'):
        pages = journey()
    assert pages.index(('step', 'ntpservers')) < pages.index(('verify', None)), 'the clock is set before 2FA and the check'
    time_sync = real_sync
    assert clock_skew('1000', now=1420) == 420 and clock_skew('1000', now=1030) is None and clock_skew('', now=1) is None
    assert clock_skew('x') is None and clock_skew('0', now=1e10) is None, 'no time or nonsense: no hint'
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
        sys.exit(0)
    with open('/etc/efa-web/secret.key', 'rb') as secret:
        app.secret_key = secret.read()
    logging.basicConfig(level=logging.INFO, format='%(name)s: %(message)s')
    setup_code_write()
    answers_load()
    log.info('wizard ready, %d answers kept from before', len(answers))
    serve(app, host='127.0.0.1', port=8080, threads=4, max_request_body_size=MAX_FORM)
