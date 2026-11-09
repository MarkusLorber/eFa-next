# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""IP blocklists of eFa-next (9m): feeds and own lists in an nftables table of their own, without firewalld.

The table inet efa_block has one set per list and family, with intervals and a timeout per entry, and one rule per list for
its ports. It is written in one nft transaction, so a list is never half loaded, and firewalld never touches it: a
reload of firewalld, as a package update does, keeps every block. Addresses that must always pass (relay networks, the
admin allowlist, cluster nodes, the own addresses) come first and are never blocked, whatever a list says.

Only the parts without a side effect are here, so they can be tested; efactl reads the files, fetches and runs nft.
"""
import email.utils
import ipaddress
import re
import time

TABLE = 'efa_block'
# Feeds eFa-next knows by name. Each is off until the admin accepts its terms once.
FEEDS = {
    'talos': {'title': 'Cisco Talos IP blocklist', 'url': 'https://snort.org/downloads/ip-block-list',
              'terms': 'Free list of Cisco Talos, published on snort.org under its terms of use. Read them before you switch it on.'},
}
INTERVALS = (60, 120, 240, 720, 1440)
MAX_FEED_BYTES = 20 * 1024 * 1024
MAX_PORTS = 10
NAME = re.compile(r'^[a-z][a-z0-9-]{0,23}$')


def name_problem(name):
    return None if NAME.match(name or '') else 'Name: small letters, digits and -, starting with a letter, at most 24 characters.'


def parse_ports(text):
    """'25' or '25,465,587' to a sorted list of ports, 'all' to [] (every port); ValueError for anything else."""
    if (text or '').strip().lower() == 'all':
        return []
    ports = sorted({int(item) for item in re.split(r'[\s,]+', (text or '25').strip()) if item})
    if not ports or len(ports) > MAX_PORTS or any(not 1 <= port <= 65535 for port in ports):
        raise ValueError(f'Ports: 1 to {MAX_PORTS} numbers from 1 to 65535, such as 25 or 25,465,587.')
    return ports


def parse_entries(text, allow_private=False):
    """Addresses and networks of a feed or a form, one per line or separated by spaces and commas. Comments (# and ;) and
    everything that is not an address are left out; so are private, loopback and other non-public ranges, unless
    allow_private (own lists only). Returns (networks, skipped)."""
    found, skipped = [], 0
    for line in (text or '').splitlines():
        line = re.split(r'[#;]', line, maxsplit=1)[0]
        for item in re.split(r'[\s,]+', line.strip()):
            if not item:
                continue
            try:
                net = ipaddress.ip_network(item, strict=False)
            except ValueError:
                skipped += 1
                continue
            if not allow_private and not net.network_address.is_global:
                skipped += 1
                continue
            found.append(net)
    return found, skipped


def collapsed(networks):
    """Per family, without overlaps: nft refuses overlapping intervals in one set."""
    four = list(ipaddress.collapse_addresses(net for net in networks if net.version == 4))
    six = list(ipaddress.collapse_addresses(net for net in networks if net.version == 6))
    return four, six


def retry_at(header, now):
    """When a feed may be asked again after 429 or 503: Retry-After in seconds or as a date, else in an hour; at most a day."""
    wait = 3600
    if header:
        header = header.strip()
        if header.isdigit():
            wait = int(header)
        else:
            try:
                wait = email.utils.parsedate_to_datetime(header).timestamp() - now
            except (TypeError, ValueError):
                wait = 3600
    return now + min(max(wait, 60), 86400)


def due(entry, now):
    """A feed is due when it is on, its terms are accepted, its interval has passed and the feed did not ask to wait."""
    if not entry.get('enabled') or entry.get('kind') != 'feed' or not entry.get('terms_accepted'):
        return False
    if now < entry.get('retry_at', 0):
        return False
    return now - entry.get('fetched_at', 0) >= int(entry.get('interval', 120)) * 60


def live_entries(entries, now):
    """Own entries {address: expiry (0 for never)} that have not run out, with the seconds they have left (None: never)."""
    return {address: (None if not expiry else int(expiry - now)) for address, expiry in (entries or {}).items() if not expiry or expiry > now + 1}


def _elements(networks, seconds=None):
    if seconds is None:
        return ', '.join(str(net) for net in networks)
    return ', '.join(f'{net} timeout {max(seconds.get(net, 0) or 0, 1)}s' if seconds.get(net) else str(net) for net in networks)


def nft_script(lists, allow, now):
    """The whole table as one nft transaction. lists: {name: {'ports': [...], 'feed': [networks], 'own': {address: expiry}}}
    for the lists that are on; allow: networks that are never blocked."""
    allow4, allow6 = collapsed(allow)
    lines = [f'table inet {TABLE}', f'delete table inet {TABLE}', f'table inet {TABLE} {{']
    lines.append(f'  set allow4 {{ type ipv4_addr; flags interval; {"elements = { " + _elements(allow4) + " }; " if allow4 else ""}}}')
    lines.append(f'  set allow6 {{ type ipv6_addr; flags interval; {"elements = { " + _elements(allow6) + " }; " if allow6 else ""}}}')
    rules = []
    for name in sorted(lists):
        item = lists[name]
        own = live_entries(item.get('own'), now)
        networks = list(item.get('feed') or []) + [ipaddress.ip_network(address, strict=False) for address in own]
        four, six = collapsed(networks)
        # A timeout only for an own entry that stays a network of its own after collapsing; merged ones stay as long as the list.
        seconds = {ipaddress.ip_network(address, strict=False): left for address, left in own.items() if left}
        for family, nets, kind in (('4', four, 'ipv4_addr'), ('6', six, 'ipv6_addr')):
            body = f'elements = {{ {_elements(nets, seconds)} }}; ' if nets else ''
            lines.append(f'  set l_{name.replace("-", "_")}_{family} {{ type {kind}; flags interval, timeout; {body}}}')
        ports = f'tcp dport {{ {", ".join(str(port) for port in item["ports"])} }} ' if item['ports'] else ''
        for family, match in (('4', 'ip'), ('6', 'ip6')):
            rules.append(f'    {ports}{match} saddr @l_{name.replace("-", "_")}_{family} counter drop')
    # Before firewalld (priority filter + 10): a drop here ends the packet; an accept only means "not blocked by eFa-next".
    lines += ['  chain input {', '    type filter hook input priority -5; policy accept;', '    iif "lo" accept',
              '    ip saddr @allow4 accept', '    ip6 saddr @allow6 accept'] + rules + ['  }', '}']
    return '\n'.join(lines) + '\n'


def self_test():
    assert name_problem('talos') is None and name_problem('own-2') is None and name_problem('Bad') and name_problem('x' * 30) and name_problem('')
    assert parse_ports('25') == [25] and parse_ports('587, 25,465') == [25, 465, 587] and parse_ports('') == [25] and parse_ports('all') == []
    for bad in ('0', '70000', 'smtp', ','.join(str(port) for port in range(1, 13))):
        try:
            parse_ports(bad)
            raise AssertionError(bad)
        except ValueError:
            pass
    text = '# Talos\r\n1.2.3.4\r\n5.6.7.0/24 ; comment\n10.0.0.1\n127.0.0.1\nnot-an-ip\n2001:db8::1\n2a00:1450::/32\n5.6.7.8\n'
    nets, skipped = parse_entries(text)
    assert [str(net) for net in nets] == ['1.2.3.4/32', '5.6.7.0/24', '2a00:1450::/32', '5.6.7.8/32'] and skipped == 4, (nets, skipped)
    assert [str(net) for net in parse_entries('10.0.0.1, 192.168.1.0/24', allow_private=True)[0]] == ['10.0.0.1/32', '192.168.1.0/24']
    four, six = collapsed(nets)
    assert [str(net) for net in four] == ['1.2.3.4/32', '5.6.7.0/24'] and [str(net) for net in six] == ['2a00:1450::/32'], 'no overlaps'
    assert retry_at('120', 1000) == 1120 and retry_at('', 1000) == 4600 and retry_at('5', 1000) == 1060 and retry_at('999999', 0) == 86400
    assert abs(retry_at(email.utils.formatdate(2000, usegmt=True), 1000) - 2000) < 2 and retry_at('junk', 0) == 3600
    feed = {'kind': 'feed', 'enabled': True, 'terms_accepted': True, 'interval': 60, 'fetched_at': 0}
    assert due(feed, 3600) and not due({**feed, 'fetched_at': 1000}, 3600) and not due({**feed, 'terms_accepted': False}, 99999)
    assert not due({**feed, 'retry_at': 9000}, 5000) and not due({**feed, 'enabled': False}, 99999) and not due({**feed, 'kind': 'own'}, 99999)
    assert live_entries({'1.1.1.1': 0, '2.2.2.2': 100, '3.3.3.3': 5000}, 1000) == {'1.1.1.1': None, '3.3.3.3': 4000}
    script = nft_script({'talos': {'ports': [25], 'feed': nets, 'own': {}},
                         'own': {'ports': [25, 587], 'feed': [], 'own': {'8.8.4.4': 0, '9.9.9.9': 4600, '7.7.7.7': 10}}},
                        [ipaddress.ip_network('203.0.113.0/24'), ipaddress.ip_network('2001:db8::/32')], 1000)
    assert script.startswith(f'table inet {TABLE}\ndelete table inet {TABLE}\n'), 'one transaction, the old table out'
    assert 'elements = { 203.0.113.0/24 }' in script and 'elements = { 2001:db8::/32 }' in script
    assert 'set l_talos_4 { type ipv4_addr; flags interval, timeout; elements = { 1.2.3.4/32, 5.6.7.0/24 }; }' in script
    assert '9.9.9.9/32 timeout 3600s' in script and '8.8.4.4/32' in script and '7.7.7.7' not in script, 'own entries keep their time, old ones go'
    assert 'tcp dport { 25, 587 } ip saddr @l_own_4 counter drop' in script and 'tcp dport { 25 } ip6 saddr @l_talos_6 counter drop' in script
    assert script.index('@allow4 accept') < script.index('@l_talos_4'), 'the allowed addresses come first'
    empty = nft_script({}, [], 0)
    assert 'set allow4 { type ipv4_addr; flags interval; }' in empty and 'drop' not in empty
    assert nft_script({'a-b': {'ports': [25], 'feed': [], 'own': {}}}, [], 0).count('@l_a_b_') == 2
    assert '    ip saddr @l_all_4 counter drop' in nft_script({'all': {'ports': [], 'feed': [], 'own': {}}}, [], 0), 'every port'
    print('self-test ok')


if __name__ == '__main__':
    import sys
    if '--self-test' in sys.argv:
        self_test()
