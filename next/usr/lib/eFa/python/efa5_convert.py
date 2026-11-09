# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Reads an original eFa 5.0 and converts its settings for eFa-next. Shared by efa-migrate (in place) and efa5-export
(settings file for a fresh host), so both carry over the same way. Only the Python standard library: it runs on eFa 5.0.
"""
import glob
import ipaddress
import json
import os
import re
import subprocess

CONFIG = '/etc/eFa/eFa-Config'
MYSQL_CONFIG = '/etc/eFa/MySQL-Config'
POSTFIX = '/etc/postfix'
MAILSCANNER_CONF = '/etc/MailScanner/MailScanner.conf'
MAILSCANNER_DEFAULTS = '/etc/MailScanner/defaults'
KEY_TABLE = '/etc/opendkim/KeyTable'
# Milters of the old filter stack; everything else in the chain is site-specific and stays.
OLD_MILTER_PORTS = {33333, 8891, 8893}
RSPAMD_PORT, HEALTH_PORT = 11332, 8999
TABLES = ('transport', 'virtual', 'sender_access', 'recipient_access', 'helo_access', 'access', 'canonical',
          'generic', 'relocated', 'sender_canonical', 'recipient_canonical', 'sasl_passwd', 'relay_recipients')
KEPT_POSTCONF = ('smtp_sasl_auth_enable', 'smtp_sasl_password_maps', 'smtp_sasl_security_options',
                 'smtp_sasl_tls_security_options', 'error_notice_recipient', 'smtpd_tls_cert_file',
                 'smtpd_tls_key_file')
# Set by the new eFa-next itself; the system decides, not the old main.cf.
# master_service_disable: a migration that stopped before may have left the intake off; it is never carried over.
MANAGED_POSTCONF = ('smtpd_milters', 'non_smtpd_milters', 'myhostname', 'mydomain', 'master_service_disable')
# A fresh host sets these through efactl, or has its own: certificate, network and addresses.
FRESH_MANAGED_POSTCONF = MANAGED_POSTCONF + ('mynetworks', 'relayhost', 'message_size_limit', 'smtpd_tls_cert_file',
                                             'smtpd_tls_key_file', 'inet_interfaces', 'inet_protocols', 'myorigin',
                                             'mydestination', 'myhostname')
REMOVED_REF = re.compile(r'mailscanner|mailwatch|amavis|sqlgrey|opendkim|opendmarc|spamassassin|:(10023|10024|10025|33333|8891|8893|2501)\b', re.I)
SQLGREY_POLICY = r'check_policy_service\s+inet:127\.0\.0\.1:2501\s*,?\s*'
MAP_PACKAGES = {'ldap': 'postfix-ldap', 'pcre': 'postfix-pcre', 'mysql': 'postfix-mysql'}
# freshclam: hand-made unit on some systems, doubles clamav-freshclam
OLD_SERVICES = ('freshclam', 'amavisd', 'clamd@amavisd', 'mailscanner', 'msmilter', 'httpd', 'php-fpm', 'opendkim', 'opendmarc', 'sqlgrey', 'adcc', 'spamassassin',
                'postfix', 'dovecot', 'fail2ban', 'mariadb', 'clamd@scan', 'clamav-freshclam',
                'clamav-unofficial-sigs')
NOT_MIGRATED = ('spam score thresholds: rspamd scores differ from SpamAssassin, the rspamd defaults apply',
                'MailWatch users: there is one web admin now',
                'MailWatch trusted networks, SpamAssassin Bayes data and sqlgrey history',
                'mail in the old quarantine: it is kept in the backup but cannot be released from the new interface')
# What a settings file for a fresh host cannot take, in addition to the above.
NOT_ON_FRESH = ('the mail log and the quarantine stay on the old host',
                'the mail queue: let the old host deliver it before it is switched off')
# The settings file inside an eFa-next backup. efactl restore applies it once and renames it.
IMPORT_DIR = 'etc/eFa/efa5-import'


class Failed(Exception):
    pass


def run(cmd, **kwargs):
    done = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
    if done.returncode != 0:
        raise Failed(f"{' '.join(cmd)}: {(done.stderr or done.stdout)[-400:]}")
    return done.stdout


def old_settings_file(path):
    with open(path) as f:
        return f.read()


def key_values(text, sep=':'):
    values = {}
    for line in text.splitlines():
        if sep in line and not line.lstrip().startswith('#'):
            key, value = line.split(sep, 1)
            values[key.strip()] = value.strip()
    return values


def parse_senders(rows):
    """MailWatch list rows to entries for the new lists, which are global and hold addresses or domains."""
    usable, skipped = [], []
    for to_address, from_address in rows:
        entry = from_address.strip().lower()
        if entry.startswith('*@'):
            entry = entry[2:]
        if to_address != 'default' or not re.fullmatch(r'([a-z0-9._%+-]+@)?([a-z0-9-]+\.)+[a-z]{2,}', entry):
            skipped.append(f'{from_address} for {to_address}')
        else:
            usable.append(entry)
    return sorted(set(usable)), skipped


def sender_rules(name, rows):
    """What the plain lists cannot hold goes to the rules: IPs, patterns, single recipients."""
    usable = parse_senders(rows)[0]
    rules = []
    for to_address, from_address in rows:
        entry = from_address.strip().lower()
        entry = entry[2:] if entry.startswith('*@') and '*' not in entry[2:] else entry
        if to_address == 'default' and entry in usable or entry in ('', '::1', '127.0.0.1'):
            continue
        rules.append({'list': name, 'sender': entry, 'recipient': to_address.strip().lower()})
    return rules


def parse_key_table(text):
    keys = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 2 and not line.startswith('#') and fields[1].count(':') == 2:
            domain, selector, path = fields[1].split(':')
            keys.append({'domain': domain, 'selector': selector, 'path': path})
    return keys


def new_chain(milters):
    """Keeps site-specific milters in place, rspamd takes the place of the first old filter, health comes last."""
    ports = [int(p) for p in re.findall(r':(\d+)(?=[\s,]|$)', milters)]
    chain = []
    for port in ports:
        if port in OLD_MILTER_PORTS:
            if RSPAMD_PORT not in chain:
                chain.append(RSPAMD_PORT)
        elif port != HEALTH_PORT:
            chain.append(port)
    if RSPAMD_PORT not in chain:
        chain.append(RSPAMD_PORT)
    return chain + [HEALTH_PORT]


def relay_networks(mynetworks):
    return [n for n in mynetworks.replace(',', ' ').split() if n not in ('127.0.0.0/8', '[::1]/128')]


def size_megabytes(limit):
    return max(1, int(limit) // (1024 * 1024))


def lost_postconf(old, new):
    """Old main.cf settings the new system does not have with the same value."""
    return sorted(name for name, value in old.items() if new.get(name) != value)


CIPHER_GRADES = ('export', 'low', 'medium', 'high', 'null')
CIPHER_SETTINGS = ('smtpd_tls_ciphers', 'smtpd_tls_mandatory_ciphers', 'smtp_tls_ciphers', 'smtp_tls_mandatory_ciphers')


def cipher_grades(values):
    """A cipher list where Postfix wants a grade ("invalid cipher grade", STARTTLS breaks): the grade high, the list in
    tls_high_cipherlist. A second, different list is left to the report."""
    fixed = dict(values)
    for name in CIPHER_SETTINGS:
        value = fixed.get(name, '').strip()
        if value and value.lower() not in CIPHER_GRADES:
            fixed[name] = 'high'
            fixed.setdefault('tls_high_cipherlist', value)
    return fixed


def carried_postconf(old):
    """The old main.cf for the new system. What names a removed service is dropped and shows up in the report."""
    carried = {}
    for name, value in old.items():
        value = re.sub(SQLGREY_POLICY, '', value).rstrip(', ')
        if name not in MANAGED_POSTCONF and not REMOVED_REF.search(value):
            carried[name] = value
    return cipher_grades(carried)


def fresh_postconf(old, exists=os.path.exists, own=()):
    """The carried main.cf settings a fresh host can take: not what it sets itself (own: its postconf -n names), and nothing
    naming a file it lacks. Returns the settings and the names left out."""
    taken, left = {}, []
    for name, value in carried_postconf(old).items():
        files = re.findall(r'(?:^|[\s,:])(/[^\s,]+)', value)
        if name in FRESH_MANAGED_POSTCONF or name in own or any(not exists(path) for path in files):
            left.append(name)
        else:
            taken[name] = value
    return taken, sorted(left)


def carried_master(text):
    """The old master.cf without the services and options of the removed filters."""
    kept, dropped, drop_block = [], [], False
    for line in text.splitlines():
        if line.lstrip().startswith('#') or not line.strip():
            kept.append(line)
            continue
        if not line[0].isspace():
            drop_block = bool(REMOVED_REF.search(line))
        if drop_block or REMOVED_REF.search(line):
            dropped.append(line.strip())
        else:
            kept.append(line)
    return '\n'.join(kept) + '\n', dropped


def carried_milters(milters, unit_of):
    """Site-specific non_smtpd_milters stay if a service outside the old stack still listens there."""
    kept = []
    for milter in re.split(r'[\s,]+', milters.strip()):
        match = re.search(r':(\d+)$', milter)
        if match and int(match.group(1)) not in OLD_MILTER_PORTS:
            unit = unit_of(int(match.group(1)))
            if unit and unit not in OLD_SERVICES:
                kept.append(milter)
    return ', '.join(kept)


def dns_zones(config):
    """The new eFa-next resolves on its own: public forwarders get DNS blocklists blocked. Internal servers keep the mail server's zone."""
    servers = [ip for ip in (config.get('DNSIP1'), config.get('DNSIP2'))
               if ip and ipaddress.ip_address(ip).is_private]
    mailserver = config.get('MAILSERVER', '')
    if not servers or '.' not in mailserver or re.fullmatch(r'[0-9.]+', mailserver):
        return {}
    return {mailserver.split('.', 1)[1]: servers}


def live_config(config, hostname, address, timezone):
    """eFa-Config can be stale on cloned or renamed systems, the running system decides."""
    values = dict(config)
    values['HOSTNAME'] = hostname.split('.')[0]
    if '.' in hostname:
        values['DOMAINNAME'] = hostname.split('.', 1)[1]
    values['IPV4ADDRESS'] = address.split('/')[0] if address else ''
    values['IPV4NETMASK'] = address.split('/')[1] if address else ''
    values['TZONE'] = values.get('TZONE') or timezone
    return values


def mysql_env():
    env = dict(os.environ)
    env['MYSQL_PWD'] = key_values(old_settings_file(MYSQL_CONFIG))['MYSQLROOTPWD']
    return env


def postconf(name):
    return run(['postconf', '-h', name]).strip()


def unit_of_port(port):
    match = re.search(rf':{port}\s.*pid=(\d+)', run(['ss', '-ltnpH']))
    if not match:
        return None
    with open(f'/proc/{match.group(1)}/cgroup') as f:
        unit = re.search(r'/([A-Za-z0-9@_.-]+)\.service', f.read())
    return unit.group(1) if unit else None


def collect():
    """Reads the old system and changes nothing."""
    if os.geteuid() != 0:
        raise Failed('Run as root.')
    config = key_values(old_settings_file(CONFIG))
    if config.get('CONFIGURED') != 'YES' or not os.path.exists(MAILSCANNER_CONF):
        raise Failed('This is no configured original eFa 5.0.')
    device = re.search(r' dev (\S+)', run(['ip', '-4', '-o', 'route', 'get', '1.1.1.1'])).group(1)
    address = re.search(r' inet (\S+)', run(['ip', '-4', '-o', 'addr', 'show', 'dev', device])).group(1)
    config = live_config(config, run(['hostname']).strip(), address,
                         run(['timedatectl', 'show', '-p', 'Timezone', '--value']).strip())
    config['INTERFACE'] = device
    # Passwords must not reach the printed plan or plan.json.
    config = {k: v for k, v in config.items() if not k.endswith('PWD')}
    env = mysql_env()
    lists = {}
    rules = []
    for name, table in (('allow', 'whitelist'), ('block', 'blacklist')):
        out = run(['mysql', '--user=root', '-Ne', f'SELECT to_address, from_address FROM mailscanner.{table}'], env=env)
        rows = [line.split('\t') for line in out.splitlines()]
        lists[name], _ = parse_senders(rows)
        rules += sender_rules(name, rows)
    scanner = key_values(old_settings_file(MAILSCANNER_CONF), '=')
    defaults = key_values(old_settings_file(MAILSCANNER_DEFAULTS), '=') if os.path.exists(MAILSCANNER_DEFAULTS) else {}
    main_cf = old_settings_file(POSTFIX + '/main.cf')
    old_postconf = key_values(run(['postconf', '-n']), '=')
    chain = new_chain(postconf('smtpd_milters'))
    keys = parse_key_table(old_settings_file(KEY_TABLE)) if os.path.exists(KEY_TABLE) else []
    plan = {
        'config': config,
        'ipv6dns': 'do-ip6: no' not in old_settings_file('/etc/unbound/unbound.conf'),
        'dns_zones': dns_zones(config),
        'mynetworks': relay_networks(postconf('mynetworks')),
        'relayhost': postconf('relayhost'),
        'message_size_mb': size_megabytes(postconf('message_size_limit')),
        'postconf': {name: postconf(name) for name in KEPT_POSTCONF},
        'old_postconf': old_postconf,
        'non_smtpd_milters': carried_milters(postconf('non_smtpd_milters'), unit_of_port),
        'map_packages': [package for kind, package in MAP_PACKAGES.items()
                         if f'{kind}:' in main_cf + old_settings_file(POSTFIX + '/master.cf')],
        'greylisting': 'check_policy_service inet:127.0.0.1:2501' in main_cf,
        'recipient_verification': 'reject_unverified_recipient' in postconf('smtpd_recipient_restrictions'),
        'fail2ban': subprocess.run(['systemctl', 'is-enabled', 'fail2ban'], capture_output=True).returncode == 0,
        'quarantine': 'store' in scanner.get('Spam Actions', ''),
        'quarantine_days': defaults.get('q_days', '30'),
        'senders': lists,
        'sender_rules': rules,
        'dkim': [k for k in keys if os.path.exists(k['path'])],
        'dkim_missing': [k['path'] for k in keys if not os.path.exists(k['path'])],
        'milter_chain': chain,
        'extra_services': [u for u in (unit_of_port(p) for p in chain if p not in (RSPAMD_PORT, HEALTH_PORT)) if u],
        'tables': [t for t in TABLES if os.path.exists(f'{POSTFIX}/{t}')],
        'letsencrypt': '/letsencrypt/' in postconf('smtpd_tls_cert_file') and os.path.exists(postconf('smtpd_tls_cert_file')),
        'mailscanner_custom': sorted(f for f in glob.glob('/etc/MailScanner/conf.d/*') if not f.endswith('README')),
        'not_migrated': NOT_MIGRATED,
    }
    # A missing certificate must not be configured again, efa-apply creates a self-signed one.
    for name in ('smtpd_tls_cert_file', 'smtpd_tls_key_file'):
        if not os.path.exists(plan['postconf'][name]):
            del plan['postconf'][name]
    return plan


def dkim_name(key):
    return f"dkim-{key['domain']}.{key['selector']}.key"


def settings_steps(plan, key_dir, fresh):
    """The efactl calls that carry the settings over, in this order. A fresh host has none of the old third-party milters."""
    steps = []
    if plan['mynetworks']:
        steps.append(('relay-networks-set', '--networks', ' '.join(plan['mynetworks'])))
    if plan['relayhost']:
        steps.append(('smarthost-set', '--host', plan['relayhost']))
    # In place, the exact value comes from the old main.cf; whole megabytes would round it.
    if fresh or 'message_size_limit' not in plan['old_postconf']:
        steps.append(('message-size-set', '--megabytes', str(plan['message_size_mb'])))
    steps.append(('greylisting-set', '--mode', 'on' if plan['greylisting'] else 'off'))
    steps.append(('recipient-verification-set', '--mode', 'on' if plan['recipient_verification'] else 'off'))
    steps.append(('fail2ban-set', '--mode', 'on' if plan['fail2ban'] else 'off'))
    steps.append(('quarantine-days-set', '--days', str(plan['quarantine_days'])))
    steps.append(('quarantine-set', '--mode', 'on' if plan['quarantine'] else 'off'))
    for which, entries in plan['senders'].items():
        for entry in entries:
            steps.append(('sender-list-set', '--list', which, '--action', 'add', '--address', entry))
    for rule in plan['sender_rules']:
        steps.append(('sender-rule-set', '--list', rule['list'], '--action', 'add', '--sender', rule['sender'],
                      '--recipient', '' if rule['recipient'] == 'default' else rule['recipient']))
    for key in plan['dkim']:
        steps.append(('dkim-import', '--domain', key['domain'], '--selector', key['selector'],
                      '--key_file', f'{key_dir}/{dkim_name(key)}'))
    for zone, servers in plan['dns_zones'].items():
        steps.append(('dns-zone-set', '--zone', zone, '--action', 'add', '--servers', ' '.join(servers)))
    if not fresh:
        steps.append(('milter-chain-set', '--ports', ' '.join(str(p) for p in plan['milter_chain'])))
    # Filtering must not get weaker: the blocklists rspamd uses stay on, also those with terms the admin has to check.
    steps.append(('rbl-apply', '--keep', 'yes'))
    if not fresh:
        for service in plan['extra_services']:
            steps.append(('extra-service-set', '--name', service, '--action', 'add'))
    return steps


def fresh_report(plan, exists=os.path.exists, own=()):
    """For a fresh host: what is taken over, what is adjusted, what cannot be taken over."""
    cfg = plan['config']
    taken = []
    if plan['mynetworks']:
        taken.append('relay networks: ' + ' '.join(plan['mynetworks']))
    if plan['relayhost']:
        taken.append('smarthost: ' + plan['relayhost'])
    taken.append(f"greylisting {'on' if plan['greylisting'] else 'off'}, recipient verification "
                 f"{'on' if plan['recipient_verification'] else 'off'}, Fail2Ban {'on' if plan['fail2ban'] else 'off'}")
    taken.append(f"quarantine {'on' if plan['quarantine'] else 'off'}, kept {plan['quarantine_days']} days")
    taken.append(f"sender lists: {len(plan['senders'].get('allow', []))} allowed, {len(plan['senders'].get('block', []))} blocked, "
                 f"{len(plan['sender_rules'])} sender rules")
    taken += [f"DKIM key {key['domain']} selector {key['selector']}" for key in plan['dkim']]
    taken += [f'Postfix table {table}' for table in plan['tables']]
    postconf_taken, postconf_left = fresh_postconf(plan['old_postconf'], exists, own)
    if postconf_taken:
        taken.append('Postfix settings: ' + ', '.join(sorted(postconf_taken)))
    adjusted = [f"message size: {plan['message_size_mb']} MB, in whole megabytes",
                'block entries reject instead of marking as spam',
                'the blocklists of rspamd stay on']
    adjusted += [f'DNS zone {zone} stays on {" ".join(servers)}, everything else resolves on its own'
                 for zone, servers in plan['dns_zones'].items()]
    adjusted.append(f"host name, address and time zone stay as set up on the new host (old: {cfg.get('HOSTNAME', '')}."
                    f"{cfg.get('DOMAINNAME', '')}, {cfg.get('IPV4ADDRESS', '')})")
    # The old quarantine is not part of the file: it stays on the old host, see NOT_ON_FRESH.
    not_possible = [item for item in NOT_MIGRATED if not item.startswith('mail in the old quarantine')] + list(NOT_ON_FRESH)
    not_possible += [f'DKIM key file missing: {path}' for path in plan['dkim_missing']]
    if postconf_left:
        not_possible.append('Postfix settings the new host sets itself or whose files it lacks: ' + ', '.join(postconf_left))
    extra = [p for p in plan['milter_chain'] if p not in (RSPAMD_PORT, HEALTH_PORT)]
    if extra or plan['non_smtpd_milters']:
        not_possible.append('third-party milters ' + ' '.join(map(str, extra)) + ' ' + plan['non_smtpd_milters'] +
                            ': install them on the new host, then add them with efactl milter-chain-set')
    if plan['map_packages']:
        not_possible.append('Postfix map types need these packages first: ' + ' '.join(plan['map_packages']))
    if plan['letsencrypt']:
        not_possible.append("Let's Encrypt certificate: get a new one with efactl letsencrypt-set")
    not_possible += [f'own MailScanner rules: {path}' for path in plan['mailscanner_custom']]
    return {'taken': taken, 'adjusted': adjusted, 'not_possible': not_possible}


def report_text(report):
    lines = []
    for title, key in (('Taken over', 'taken'), ('Adjusted', 'adjusted'), ('Not taken over', 'not_possible')):
        lines.append(title + ':')
        lines += [' - ' + item for item in report[key]] or [' - nothing']
    return '\n'.join(lines) + '\n'


def plan_json(plan):
    return json.dumps(plan, indent=2, sort_keys=True)


def self_test():
    listed = 'ECDHE+AESGCM:!ECDHE-ECDSA-CHACHA20-POLY1305'
    assert cipher_grades({'smtpd_tls_ciphers': listed, 'smtp_tls_ciphers': 'high'}) == {
        'smtpd_tls_ciphers': 'high', 'smtp_tls_ciphers': 'high', 'tls_high_cipherlist': listed}
    assert carried_postconf({'smtpd_tls_mandatory_ciphers': listed, 'tls_high_cipherlist': 'X'})['tls_high_cipherlist'] == 'X'
    assert 'master_service_disable' not in carried_postconf({'master_service_disable': 'inet'}), 'a stopped intake is never carried over'
    assert parse_senders([('default', 'A@x.org'), ('default', '*@y.org'), ('default', 'z.org'), ('default', '1.2.3.4'),
                          ('me@x.org', 'b@x.org'), ('default', '*.w.org')]) == (
        ['a@x.org', 'y.org', 'z.org'], ['1.2.3.4 for default', 'b@x.org for me@x.org', '*.w.org for default'])
    assert sender_rules('allow', [('default', 'a@x.org'), ('default', '10.0.0.1'), ('me@x.org', 'y.org'), ('default', '*w*'), ('default', '::1')]) == [
        {'list': 'allow', 'sender': '10.0.0.1', 'recipient': 'default'}, {'list': 'allow', 'sender': 'y.org', 'recipient': 'me@x.org'},
        {'list': 'allow', 'sender': '*w*', 'recipient': 'default'}]
    assert parse_key_table('# c\nd._domainkey.x.org x.org:d:/k/x.private\nbad\n') == [
        {'domain': 'x.org', 'selector': 'd', 'path': '/k/x.private'}]
    assert new_chain('inet:127.0.0.1:33333') == [11332, 8999]
    assert new_chain('inet:127.0.0.1:9901, inet:127.0.0.1:33333, inet:127.0.0.1:8891, inet:127.0.0.1:9899') == [
        9901, 11332, 9899, 8999]
    assert new_chain('') == [11332, 8999]
    assert relay_networks('127.0.0.0/8 [::1]/128 10.0.0.0/8, 192.0.2.1') == ['10.0.0.0/8', '192.0.2.1']
    assert size_megabytes('133169152') == 127 and size_megabytes('0') == 1
    assert lost_postconf({'a': '1', 'b': '2', 'c': '3'}, {'a': '1', 'b': '9'}) == ['b', 'c']
    assert carried_postconf({'smtpd_milters': 'x', 'smtpd_tls_security_level': 'encrypt', 'content_filter': 'smtp-amavis:[127.0.0.1]:10024',
                             'smtpd_recipient_restrictions': 'permit_mynetworks, check_policy_service inet:127.0.0.1:2501, reject'}) == {
        'smtpd_tls_security_level': 'encrypt', 'smtpd_recipient_restrictions': 'permit_mynetworks, reject'}
    assert fresh_postconf({'smtpd_tls_security_level': 'may', 'relayhost': '[m.x.org]', 'header_checks': 'regexp:/etc/postfix/header_checks',
                           'transport_maps': 'hash:/etc/postfix/transport'}, {'/etc/postfix/transport'}.__contains__) == (
        {'smtpd_tls_security_level': 'may', 'transport_maps': 'hash:/etc/postfix/transport'}, ['header_checks', 'relayhost'])
    assert fresh_postconf({'transport_maps': 'hash:/etc/postfix/transport'}, lambda path: True, {'transport_maps'}) == ({}, ['transport_maps'])
    assert carried_master('# c\nsmtp inet n - n - - smtpd\n  -o content_filter=smtp-amavis:127.0.0.1:10024\n  -o a=b\n'
                          'smtp-amavis unix - - y - 2 smtp\n -o c=d\n\nautoreply unix - n n - - pipe\n  flags=\n') == (
        '# c\nsmtp inet n - n - - smtpd\n  -o a=b\n\nautoreply unix - n n - - pipe\n  flags=\n',
        ['-o content_filter=smtp-amavis:127.0.0.1:10024', 'smtp-amavis unix - - y - 2 smtp', '-o c=d'])
    assert carried_milters('inet:127.0.0.1:9899, inet:127.0.0.1:33333, inet:127.0.0.1:7', {9899: 'archiver', 7: 'httpd'}.get) == 'inet:127.0.0.1:9899'
    assert key_values('A:b:c\n# X:y\n') == {'A': 'b:c'}
    assert dns_zones({'DNSIP1': '8.8.8.8', 'DNSIP2': '10.0.0.1', 'MAILSERVER': 'ex.corp.example'}) == {'corp.example': ['10.0.0.1']}
    assert dns_zones({'DNSIP1': '8.8.8.8', 'DNSIP2': '', 'MAILSERVER': 'ex.corp.example'}) == {}
    assert dns_zones({'DNSIP1': '10.0.0.1', 'MAILSERVER': '10.0.0.5'}) == {}
    assert live_config({'HOSTNAME': 'OLD', 'DOMAINNAME': 'x.org', 'TZONE': ''}, 'NEW', '10.0.0.4/24', 'Europe/Vienna') == {
        'HOSTNAME': 'NEW', 'DOMAINNAME': 'x.org', 'IPV4ADDRESS': '10.0.0.4', 'IPV4NETMASK': '24', 'TZONE': 'Europe/Vienna'}
    plan = {'config': {'HOSTNAME': 'mx', 'DOMAINNAME': 'x.org', 'IPV4ADDRESS': '10.0.0.4'}, 'mynetworks': ['10.0.0.0/8'], 'relayhost': '',
            'message_size_mb': 50, 'old_postconf': {'message_size_limit': '52428800'}, 'greylisting': True,
            'recipient_verification': False, 'fail2ban': True, 'quarantine': True, 'quarantine_days': '30',
            'senders': {'allow': ['a@x.org'], 'block': []}, 'sender_rules': [{'list': 'block', 'sender': '10.1.1.1', 'recipient': 'default'}],
            'dkim': [{'domain': 'x.org', 'selector': 's1', 'path': '/k'}], 'dkim_missing': [], 'dns_zones': {},
            'milter_chain': [9901, 11332, 8999], 'extra_services': ['archiver'], 'non_smtpd_milters': '', 'tables': ['transport'],
            'map_packages': [], 'letsencrypt': False, 'mailscanner_custom': []}
    fresh = settings_steps(plan, '/d', True)
    assert ('message-size-set', '--megabytes', '50') in fresh and ('dkim-import', '--domain', 'x.org', '--selector', 's1', '--key_file', '/d/dkim-x.org.s1.key') in fresh
    assert not any(step[0] in ('milter-chain-set', 'extra-service-set') for step in fresh)
    assert ('sender-rule-set', '--list', 'block', '--action', 'add', '--sender', '10.1.1.1', '--recipient', '') in fresh
    in_place = settings_steps(plan, '/d', False)
    assert ('milter-chain-set', '--ports', '9901 11332 8999') in in_place and ('extra-service-set', '--name', 'archiver', '--action', 'add') in in_place
    assert not any(step[0] == 'message-size-set' for step in in_place)
    report = fresh_report(plan, lambda path: False)
    assert 'DKIM key x.org selector s1' in report['taken'] and any(item.startswith('third-party milters 9901') for item in report['not_possible'])
    assert report_text(report).startswith('Taken over:\n - relay networks: 10.0.0.0/8\n')
    print('self-test ok')


if __name__ == '__main__':
    self_test()
