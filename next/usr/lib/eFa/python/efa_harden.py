# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""What the security standards ask of the operating system and of eFa-next, in one place: the hardening wizard of the web
interface preselects with plan_for(), the setup wizard and Re-Setup apply it (efactl standards-set --os --efa). The TLS, SSH,
kernel and DANE part of a standard stays in efactl standards_plan (SEC-STD); here are the items around it. Pure data and logic,
no calls of the system: efactl reads and switches the items (os-harden-status, os-harden-set, standards-set)."""
import json
import os
import re
import sys

# The standards of /usr/share/eFa/standards.json as the wizards group them, each with one sentence.
GROUPS = [
    ('TLS and keys', ['bsi-02102-1', 'bsi-02102-2', 'bsi-03116-4', 'rfc9325', 'moz-modern', 'moz-inter', 'nist-80052']),
    ('Mail transport', ['bsi-03108']),
    ('SSH and operating system', ['bsi-02102-4', 'cis-el']),
]
SUMMARY = {
    'bsi-02102-1': 'Key lengths of the German federal office: RSA from 3000 bits, ECC from 250 bits.',
    'bsi-02102-2': 'TLS after the German federal office: TLS 1.2 and 1.3, only its cipher suites and groups.',
    'bsi-03116-4': 'TLS for federal agencies in Germany: like TR-02102-2, a little stricter.',
    'rfc9325': 'The IETF best practice for TLS (BCP 195): TLS 1.2 and 1.3 with forward secrecy.',
    'moz-modern': 'Mozilla modern for the web interface only: TLS 1.3; logins on port 587 stay at TLS 1.2.',
    'moz-inter': 'Mozilla intermediate: TLS 1.2 and 1.3 with the suites most clients know.',
    'nist-80052': 'The US guideline for TLS: TLS 1.2 and 1.3 with approved suites.',
    'bsi-03108': 'Secure mail transport: TLS between mail servers, DANE, DNSSEC, MTA-STS and TLS reports.',
    'bsi-02102-4': 'SSH after the German federal office: only its key exchange, ciphers and MACs.',
    'cis-el': 'The parts of the CIS benchmark for AlmaLinux that eFa-next touches: sshd, kernel, crypto policy, services.',
}
TLS_STANDARDS = {'bsi-02102-2', 'bsi-03116-4', 'bsi-03108', 'rfc9325', 'moz-modern', 'moz-inter', 'nist-80052'}

# The items of the operating system. via: standards (standards_plan sets it), os-harden (os-harden-set), command (an efactl
# command there is). asks: the standards that ask for it. warn: a warning in the preview when it is switched on.
OS_ITEMS = {
    'ssh-profile': {'title': 'SSH profile BSI TR-02102-4', 'via': 'standards', 'asks': {'bsi-02102-4', 'cis-el'},
                    'why': 'Only the key exchange, ciphers and MACs of TR-02102-4. Goes back after 10 minutes unless a new SSH login confirms it.'},
    'kernel': {'title': 'Kernel network and memory settings', 'via': 'standards', 'asks': {'cis-el'},
               'why': 'No ICMP redirects, no source routing, no core dumps of SUID programs (CIS).'},
    'network-harden': {'title': 'No automatic network profiles', 'via': 'command', 'asks': {'cis-el'},
                       'why': 'A new interface gets no DHCP profile from an unknown network; it stays unused until it has a role.'},
    'firewall-guard': {'title': 'Firewall guard', 'via': 'command', 'asks': {'cis-el'},
                       'why': 'Puts the eFa-next firewall rules back every 5 minutes; it never changes anything else.'},
    'auditd': {'title': 'auditd runs', 'via': 'os-harden', 'asks': {'cis-el'}, 'why': 'The kernel audit log (CIS: logging and auditing).'},
    'chronyd': {'title': 'chronyd runs', 'via': 'os-harden', 'asks': {'cis-el'}, 'why': 'The right time for logs, certificates and 2FA codes.'},
    'sshd-cis': {'title': 'SSH server options after CIS', 'via': 'os-harden', 'asks': {'cis-el'},
                 'why': 'X11Forwarding no, MaxAuthTries 4, PermitEmptyPasswords no, LoginGraceTime 60, ClientAliveInterval 15 and '
                        'ClientAliveCountMax 3, in an own file; a stricter value set now stays. The root login stays as it is.'},
    'encrypt-method': {'title': 'Passwords stored with SHA-512', 'via': 'os-harden', 'asks': {'cis-el'},
                       'why': 'ENCRYPT_METHOD in /etc/login.defs for new passwords; yescrypt stays.'},
    'shadow-mode': {'title': '/etc/shadow readable by root only', 'via': 'os-harden', 'asks': {'cis-el'}, 'why': 'Mode 0000, as the distribution sets it.'},
    'crypto-policy': {'title': 'Crypto policy not LEGACY', 'via': 'os-harden', 'asks': {'cis-el'},
                      'why': 'LEGACY allows SHA-1 and short keys for the whole system; DEFAULT then.'},
    'crypto-future': {'title': 'Crypto policy FUTURE', 'via': 'os-harden', 'asks': set(),
                      'why': 'Only on purpose: RSA from 3072 bits and no SHA-1 for the whole system.',
                      'warn': 'FUTURE refuses RSA keys under 3072 bits system wide: a certificate, a DKIM key or a partner server with RSA 2048 '
                              'then fails, also for outgoing mail. A reboot is best afterwards.'},
}
# The order os-harden-set knows; off puts back what was there before.
OS_HARDEN = [key for key, item in OS_ITEMS.items() if item['via'] == 'os-harden']
# The sshd options of sshd-cis, in their own drop-in before the one of the distribution. Never PermitRootLogin.
SSHD_CIS = [('X11Forwarding', 'no'), ('MaxAuthTries', '4'), ('PermitEmptyPasswords', 'no'), ('LoginGraceTime', '60'),
            ('ClientAliveInterval', '15'), ('ClientAliveCountMax', '3')]

# The switches of eFa-next (submission-pam is hardened by switching system accounts off). once: there is no way back, the
# rollback keeps it and names it.
EFA_ITEMS = {
    'service-harden': {'title': 'Sandbox of the services', 'asks': {'cis-el'},
                       'why': 'The systemd sandbox for the own, tested units only; never for units of the distribution.'},
    'tls-min': {'title': 'SMTP: TLS 1.2 or newer only', 'asks': TLS_STANDARDS, 'once': True,
                'why': 'No TLS 1.0 or 1.1 on any SMTP port; eFa-next no longer offers them again.'},
    'dane': {'title': 'DANE for outgoing mail', 'asks': {'bsi-03108'}, 'why': 'Checks the TLSA records of receiving servers; needs a validating resolver.'},
    'submission-pam': {'title': 'Port 587: no logins of system accounts', 'asks': {'bsi-03108'}, 'once': True,
                       'why': 'Only the submitters log in on port 587.',
                       'warn': 'System accounts can no longer log in on port 587, and this cannot be switched back: each mail system needs a submitter.'},
    'login-lockout': {'title': 'Lockout after failed logins', 'asks': set(), 'why': 'Bans an address after failed logins of web, portal, API and port 587.'},
    'audit-mode': {'title': 'Strict audit mode', 'asks': set(), 'why': 'Every look at mail content is logged, with a signed anchor every day.'},
    'security-oval': {'title': 'CVE check with the OVAL data', 'asks': set(), 'why': 'Checks the installed packages against the open OVAL data of the distribution.'},
    'pwned-check': {'title': 'New passwords against known data breaches', 'asks': set(),
                    'why': 'Only the first 5 characters of the SHA-1 of a new password go to api.pwnedpasswords.com.'},
    'autoupdate': {'title': 'eFa-next updates by themselves', 'asks': set(), 'why': 'Inside the maintenance window that is set; not the updates of the system.'},
}
# Only a hint, never switched by a wizard or the setup.
HINTS = {
    'selinux': 'SELinux enforcing: needs a relabel and a reboot (setenforce 1, SELINUX=enforcing in /etc/selinux/config).',
    'os-updates': 'Automatic updates of the operating system: they may reboot and reload the firewall; Maintenance & update.',
    'host-keys': 'New SSH host keys: every client then sees a changed key; only by hand (ssh-keygen).',
    'console-2fa': 'The 2FA of the console admin is set on the console: efactl console-2fa-set --mode on.',
    'admin-access': 'Admin access only from allowed networks and the firewall: Security page; a wrong address locks you out.',
}
# Frameworks of the setup that lead to standards, only where the mapping is documented (docs/plan-hardening-wizard.md).
FRAMEWORK_STANDARDS = {'bsi-grundschutz': ['bsi-02102-2'], 'bsi-tr02102': ['bsi-02102-1', 'bsi-02102-2', 'bsi-02102-4']}
# The setup never sets these: the SSH profile needs a new SSH login within 10 minutes, nobody does that in the web installer.
SETUP_SKIP = {'ssh-profile'}
TEXTS = ['Security standards', 'Choosing none removes no hardening; a standard only ever makes a setting stricter.', 'Leads to these standards:',
         'TLS profile', 'DANE for outgoing mail']
STANDARDS_JSON = (os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'share', 'eFa', 'standards.json'),
                  '/usr/share/eFa/standards.json')


def titles():
    """{id: title} from standards.json (the source tree first, then the installed one); the ids when it is missing."""
    for path in STANDARDS_JSON:
        try:
            with open(path, encoding='utf-8') as f:
                return {sid: item['title'] for sid, item in json.load(f)['standards'].items()}
        except (OSError, ValueError, KeyError):
            continue
    return {sid: sid for sid in known()}


def what(sid, setup=False):
    """What one standard sets: the TLS profile, DANE and the items it asks for (the titles, to translate)."""
    plan = plan_for([sid], setup)
    found = (['TLS profile'] if sid in TLS_STANDARDS else []) + (['DANE for outgoing mail'] if sid == 'bsi-03108' else [])
    found += [OS_ITEMS[key]['title'] for key in plan['os']] + [EFA_ITEMS[key]['title'] for key in plan['efa'] if key != 'dane' or sid != 'bsi-03108']
    return found


def known():
    return [sid for _title, ids in GROUPS for sid in ids]


def clean(ids):
    """Known standard ids, in the order of GROUPS, from a list or a text with spaces or commas; unknown ones are left out."""
    wanted = set(re.split(r'[\s,]+', ids) if isinstance(ids, str) else ids or ())
    return [sid for sid in known() if sid in wanted]


def items(text, table):
    """Known item ids of OS_ITEMS or EFA_ITEMS from a text with commas, in the order of the table; None for an unknown one."""
    wanted = [item for item in re.split(r'[\s,]+', text or '') if item]
    if any(item not in table for item in wanted):
        return None
    return [key for key in table if key in wanted]


def plan_for(selected, setup=False):
    """Every item the chosen standards ask for, the union of all: {'os': [...], 'efa': [...]}. setup leaves out SETUP_SKIP."""
    chosen = set(clean(selected))
    os_items = [key for key, item in OS_ITEMS.items() if item['asks'] & chosen and not (setup and key in SETUP_SKIP)]
    return {'os': os_items, 'efa': [key for key, item in EFA_ITEMS.items() if item['asks'] & chosen]}


def from_frameworks(frameworks):
    """The standards the chosen frameworks lead to, where documented."""
    return clean([sid for key in frameworks or () for sid in FRAMEWORK_STANDARDS.get(key, [])])


def all_texts():
    found = list(TEXTS) + [title for title, _ids in GROUPS] + list(SUMMARY.values()) + list(HINTS.values())
    for table in (OS_ITEMS, EFA_ITEMS):
        for item in table.values():
            found += [item['title'], item['why']] + ([item['warn']] if item.get('warn') else [])
    return found


def self_test():
    assert set(SUMMARY) == set(known()) and len(known()) == len(set(known()))
    assert clean('cis-el, bsi-02102-2 bogus') == ['bsi-02102-2', 'cis-el'] and clean([]) == []
    found = plan_for(['bsi-02102-2', 'rfc9325', 'cis-el'])
    assert found['os'] == list(OS_ITEMS)[:-1], found
    assert found['efa'] == ['service-harden', 'tls-min'], 'the union of cis-el and the TLS standards'
    assert 'crypto-future' not in plan_for(known())['os'], 'FUTURE only on purpose'
    assert 'ssh-profile' in plan_for(['bsi-02102-4'])['os'] and 'ssh-profile' not in plan_for(['bsi-02102-4'], setup=True)['os']
    assert plan_for(['bsi-03108']) == {'os': [], 'efa': ['tls-min', 'dane', 'submission-pam']}
    assert plan_for([]) == {'os': [], 'efa': []}, 'no standard: nothing changes'
    assert items('auditd,sshd-cis', OS_ITEMS) == ['auditd', 'sshd-cis'] and items('auditd;rm', OS_ITEMS) is None and items('', OS_ITEMS) == []
    assert not any(key.lower() == 'permitrootlogin' for key, _value in SSHD_CIS)
    assert from_frameworks(['nis2', 'bsi-tr02102']) == ['bsi-02102-1', 'bsi-02102-2', 'bsi-02102-4'] and from_frameworks(['nis2']) == []
    assert set(titles()) == set(known()), 'standards.json and the groups name the same standards'
    assert what('bsi-03108') == ['TLS profile', 'DANE for outgoing mail', 'SMTP: TLS 1.2 or newer only', 'Port 587: no logins of system accounts']
    assert 'SSH profile BSI TR-02102-4' in what('bsi-02102-4') and what('bsi-02102-4', setup=True) == []
    assert all(all_texts())
    return 'efa_harden self-test ok'


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        print(self_test())
