# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Let's Encrypt name check with split horizon: the local resolver may give an internal address, Let's Encrypt asks the public DNS.
The public lookup walks from the root servers to the authoritative ones; here the servers are stand-ins (no network)."""
import importlib.machinery
import importlib.util
import ipaddress
import os
import socket
import struct
import sys
import types
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
for name in ('grp', 'pwd', 'fcntl', 'syslog', 'termios', 'resource'):
    sys.modules.setdefault(name, __import__(name) if importlib.util.find_spec(name) else types.ModuleType(name))
for folder in ('next/usr/lib/eFa/python', 'src/eFa/root/usr/lib/eFa/python', 'src/eFa-base/root/usr/lib/eFa/python'):
    if os.path.join(ROOT, folder) not in sys.path:
        sys.path.insert(0, os.path.join(ROOT, folder))
import efa_evidence  # noqa: E402

_loader = importlib.machinery.SourceFileLoader('efactl_le_dns', os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'))
efactl = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_le_dns', _loader))
_loader.exec_module(efactl)

CODES = {'A': 1, 'NS': 2, 'CNAME': 5, 'AAAA': 28}


def _wire(name):
    return b''.join(bytes([len(part)]) + part.encode() for part in name.split('.') if part) + b'\0'


def _record(owner, rtype, value):
    if rtype == 'A':
        data = ipaddress.IPv4Address(value).packed
    elif rtype == 'AAAA':
        data = ipaddress.IPv6Address(value).packed
    else:
        data = _wire(value)
    return _wire(owner) + struct.pack('>HHIH', CODES[rtype], 1, 300, len(data)) + data


def _reply(packet, rcode=0, aa=False, answers=(), authority=(), additional=()):
    qid = packet[:2]
    end = packet.index(b'\0', 12) + 5
    flags = 0x8000 | (0x0400 if aa else 0) | rcode
    head = qid + struct.pack('>HHHHH', flags, 1, len(answers), len(authority), len(additional))
    return head + packet[12:end] + b''.join(_record(*r) for r in (*answers, *authority, *additional))


def _question(packet):
    name, offset = efa_evidence._name(packet, 12)
    return name.lower(), {v: k for k, v in CODES.items()}.get(struct.unpack('>H', packet[offset:offset + 2])[0])


def fake_dns(zone):
    """Root refers to the TLD server, the TLD server to the authoritative one, which answers from zone {(name, type): [values]}."""
    def exchange(packet, server, timeout):
        name, qtype = _question(packet)
        if server[0] in efa_evidence.ROOTS:
            return _reply(packet, authority=[('org', 'NS', 'a0.org-servers.example')], additional=[('a0.org-servers.example', 'A', '199.19.56.1')])
        if server[0] == '199.19.56.1':
            return _reply(packet, authority=[('example.org', 'NS', 'ns1.example.org')], additional=[('ns1.example.org', 'A', '203.0.113.53')])
        if server[0] == '203.0.113.53':
            values = zone.get((name, qtype))
            if values is None and (name, 'CNAME') in zone:
                return _reply(packet, aa=True, answers=[(name, 'CNAME', zone[(name, 'CNAME')][0])])
            if values is None:
                return _reply(packet, rcode=0 if any(key[0] == name for key in zone) else 3, aa=True)
            return _reply(packet, aa=True, answers=[(name, qtype, value) for value in values])
        raise socket.timeout('no answer')
    return exchange


def offline(packet, server, timeout):
    raise socket.timeout('port 53 blocked')


def local(*addresses):
    return lambda name, port, proto=0: [(0, 0, 0, '', (address, port)) for address in addresses]


class PublicLookupTests(unittest.TestCase):
    def test_walks_from_the_roots(self):
        zone = {('mx.example.org', 'A'): ['93.184.215.14'], ('mx.example.org', 'AAAA'): ['2606:2800:21f:cb07:6820:80da:af6b:8b2c']}
        self.assertEqual(efa_evidence.public_addresses('MX.example.org.', exchange=fake_dns(zone)),
                         {'93.184.215.14', '2606:2800:21f:cb07:6820:80da:af6b:8b2c'})

    def test_follows_cname(self):
        zone = {('www.example.org', 'CNAME'): ['mx.example.org'], ('mx.example.org', 'A'): ['93.184.215.14']}
        self.assertEqual(efa_evidence.public_addresses('www.example.org', exchange=fake_dns(zone)), {'93.184.215.14'})

    def test_no_record_is_empty(self):
        self.assertEqual(efa_evidence.public_addresses('gone.example.org', exchange=fake_dns({('mx.example.org', 'A'): ['93.184.215.14']})), set())

    def test_no_way_out_is_none(self):
        self.assertIsNone(efa_evidence.public_addresses('mx.example.org', exchange=offline, budget=2))


class NameCheckTests(unittest.TestCase):
    def check(self, resolve, zone=None, exchange=None):
        notes = []
        public = lambda name: efa_evidence.public_addresses(name, exchange=exchange or fake_dns(zone), budget=2)
        return efactl.acme_name_problem('mx.example.org', local(*resolve) if resolve else offline_resolve, public, notes), notes

    def test_split_horizon_internal_address_ignored(self):
        problem, notes = self.check(['10.0.0.25'], {('mx.example.org', 'A'): ['93.184.215.14']})
        self.assertEqual(problem, '')
        self.assertIn('the internal address (10.0.0.25) is ignored', notes[0])
        self.assertIn('93.184.215.14', notes[0])

    def test_only_private_everywhere_refuses(self):
        problem, _notes = self.check(['10.0.0.25'], {('mx.example.org', 'A'): ['10.0.0.25']})
        self.assertEqual(problem, 'mx.example.org resolves only to addresses that are not public (10.0.0.25)')

    def test_no_public_record_refuses(self):
        problem, _notes = self.check(['10.0.0.25'], {('other.example.org', 'A'): ['93.184.215.14']})
        self.assertEqual(problem, 'mx.example.org resolves only to addresses that are not public (10.0.0.25)')

    def test_public_lookup_timeout_warns_and_proceeds(self):
        problem, notes = self.check(['10.0.0.25'], exchange=offline)
        self.assertEqual(problem, '')
        self.assertIn('the public DNS cannot be asked from here', notes[0])

    def test_public_local_answer_needs_no_lookup(self):
        problem, notes = self.check(['93.184.215.14'], exchange=lambda *a: self.fail('no public lookup needed'))
        self.assertEqual((problem, notes), ('', []))

    def test_internal_only_name_resolves_publicly(self):
        problem, notes = self.check(None, {('mx.example.org', 'A'): ['93.184.215.14']})
        self.assertEqual((problem, notes), ('', []))

    def test_nothing_anywhere(self):
        problem, _notes = self.check(None, exchange=offline)
        self.assertEqual(problem, 'mx.example.org does not resolve')


def offline_resolve(name, port, proto=0):
    raise socket.gaierror('no such name')


if __name__ == '__main__':
    unittest.main()
