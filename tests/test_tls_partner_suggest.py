# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Compliance package 11: TLS with partners suggested for the domains that publish DANE or MTA-STS, never applied by itself;
port 25 stays opportunistic."""
import argparse
import unittest
from unittest import mock

from test_cluster_sync_2fa import load_efactl


class Suggest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def test_candidates(self):
        dns = {'bank.example': (True, False), 'shop.example': (False, True), 'plain.example': (False, False)}
        rows = [('bank.example', 40), ('shop.example', 12), ('plain.example', 90)]
        found = self.efactl.tls_partner_candidates(rows, dns.get, dane_on=True)
        self.assertEqual([(item['domain'], item['suggested']) for item in found], [('bank.example', 'dane-only'), ('shop.example', 'verify')])
        self.assertIn('tls-partner-set --action add --domain bank.example --out dane-only', found[0]['command'])
        found = self.efactl.tls_partner_candidates(rows, dns.get, dane_on=False)
        self.assertEqual(found[0]['suggested'], 'verify', 'dane-only needs DANE on this host')

    def test_suggest_reads_only_and_skips_known(self):
        e = self.efactl

        class Cursor:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def execute(self, sql, params=()):
                assert sql.startswith('SELECT') and params == (7,)

            def fetchall(self):
                return [{'domain': 'own.example', 'n': 99}, {'domain': 'partner.example', 'n': 50}, {'domain': 'new.example', 'n': 5},
                        {'domain': 'bad domain', 'n': 1}]

        class Db:
            def cursor(self):
                return Cursor()

            def close(self):
                pass
        seen = []
        with mock.patch.object(e, '_maillog_db', Db), mock.patch.object(e, '_local_domains', lambda: ['own.example']), \
                mock.patch.object(e, '_tls_partners', lambda: [{'domain': 'partner.example'}]), \
                mock.patch.object(e, '_tls_dns', lambda domain: seen.append(domain) or (False, True)), \
                mock.patch.object(e, '_postconf', lambda name: 'dnssec'), mock.patch.object(e, 'tls25_status', lambda: {'port25_sessions_7d': 10}):
            found = e.tls_partner_suggest(argparse.Namespace(days=''))
        self.assertEqual(seen, ['new.example'])
        self.assertEqual([item['domain'] for item in found['suggestions']], ['new.example'])
        with self.assertRaises(e.EfaError):
            e.tls_partner_suggest(argparse.Namespace(days='90'))
        self.assertFalse(e.COMMANDS['tls-partner-suggest']['writes'])


if __name__ == '__main__':
    unittest.main()
