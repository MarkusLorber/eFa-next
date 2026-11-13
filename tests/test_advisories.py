# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""advisories/advisories.json, published signed with each release: in the form the CVE watch of efactl reads (advisory_items)."""
import json
import os
import re
import unittest

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class AdvisoryTests(unittest.TestCase):
    def test_entries_have_the_form_of_the_cve_watch(self):
        with open(os.path.join(TOP, 'advisories', 'advisories.json'), encoding='utf-8') as fh:
            feed = json.load(fh)
        entries = feed['advisories']
        self.assertTrue(entries)
        self.assertEqual(len({entry['id'] for entry in entries}), len(entries), 'one id per advisory')
        for entry in entries:
            self.assertRegex(entry['id'], r'^EFA-\d{4}-\d{3}$')
            self.assertIn(entry['package'], ('eFa-next', 'eFa-next-base'))
            self.assertTrue(isinstance(entry['fixed'], list) and len(entry['fixed']) == 3 and all(isinstance(p, str) for p in entry['fixed']), entry['id'])
            # One entry for every platform: the release without .el9/.el10, rpm counts 1.el9 and 1.el10 as newer than 1.
            self.assertRegex(entry['fixed'][2], r'^\d+$', entry['id'])
            self.assertIn(entry['severity'], ('Low', 'Moderate', 'Important', 'Critical'))
            self.assertTrue(all(re.fullmatch(r'CVE-\d{4}-\d{4,7}', cve) for cve in entry['cves']), entry['id'])
            self.assertTrue(0 < len(entry['summary']) <= 200, entry['id'])
            self.assertTrue(entry['link'].startswith('https://'), entry['id'])
            self.assertIsInstance(entry['remote'], bool)
            self.assertIsInstance(entry['web_rce'], bool)


if __name__ == '__main__':
    unittest.main()
