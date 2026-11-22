# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The Wazuh rules and the SCA policy of eFa-next: well-formed, rule ids unique in 108000-108099 or 108200-108299, every rule that raises an
alert (level > 0) carries the compliance groups of the Wazuh dashboards (pci_dss_, nist_800_53_, tsc_), every event a rule
matches is one that efactl really writes, and every SCA check names its compliance controls."""
import os
import re
import unittest
import xml.etree.ElementTree as ElementTree

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WAZUH = os.path.join(TOP, 'next', 'usr', 'share', 'eFa', 'wazuh')
EFACTL = os.path.join(TOP, 'next', 'usr', 'sbin', 'efactl')


def rules():
    with open(os.path.join(WAZUH, 'efa-next_rules.xml'), encoding='utf-8') as f:
        return list(ElementTree.fromstring('<root>' + f.read() + '</root>').iter('rule'))


class WazuhRules(unittest.TestCase):
    def test_ids_unique_and_in_range(self):
        ids = [int(rule.get('id')) for rule in rules()]
        self.assertEqual(len(ids), len(set(ids)))
        # 108100-108199 are the checks of the SCA policy.
        self.assertTrue(all(108000 <= i <= 108099 or 108200 <= i <= 108299 for i in ids), ids)

    def test_every_alert_has_compliance_groups(self):
        for rule in rules():
            if int(rule.get('level')) == 0:
                continue
            groups = ','.join(g.text or '' for g in rule.iter('group'))
            for prefix in ('pci_dss_', 'nist_800_53_', 'tsc_'):
                self.assertIn(prefix, groups, f'rule {rule.get("id")} has no {prefix} group')

    def test_parents_exist(self):
        ids = {rule.get('id') for rule in rules()} | {'550', '553', '554'}
        for rule in rules():
            for tag in ('if_sid', 'if_matched_sid'):
                for node in rule.iter(tag):
                    for sid in node.text.replace(' ', '').split(','):
                        self.assertIn(sid, ids, f'rule {rule.get("id")}: {tag} {sid}')

    def test_events_exist(self):
        with open(EFACTL, encoding='utf-8') as f:
            source = f.read()
        written = set(re.findall(r"'([a-z0-9_]+)', '(?:info|notice|warning|error|critical)'", source))
        written |= {f'link_{kind}' for kind in ('blocked', 'unchecked')} if "f'link_{" in source else set()
        commands = set(re.findall(r"^    '([a-z0-9-]+)': \{'func'", source, re.M))
        for rule in rules():
            for field in rule.iter('field'):
                names = re.findall(r'\^([a-z0-9_-]+)\$', field.text or '')
                if field.get('name') == 'event':
                    for name in names:
                        self.assertTrue(name in written, f'rule {rule.get("id")}: efactl never writes the event {name}')
                elif field.get('name') == 'command':
                    for name in names:
                        self.assertTrue(name in commands, f'rule {rule.get("id")}: no efactl command {name}')


class ScaPolicy(unittest.TestCase):
    def test_checks_have_compliance(self):
        with open(os.path.join(WAZUH, 'sca-efa-next.yml'), encoding='utf-8') as f:
            text = f.read()
        try:
            import yaml
        except ImportError:  # the CI hosts have no PyYAML: the same checks on the lines of the file
            blocks = re.split(r'\n  - id: ', text.split('\nchecks:\n', 1)[1])[1:]
            policy = {'checks': [{'id': int(block.split('\n', 1)[0]),
                                  'compliance': [{key: None} for key in re.findall(r'^      - ([a-z0-9_.-]+): \[', block, re.M)]}
                                 for block in blocks]}
            self.assertTrue(all(re.search(r'^    condition: (all|any|none)$', block, re.M) for block in blocks))
        else:
            policy = yaml.safe_load(text)
        ids = [check['id'] for check in policy['checks']]
        self.assertEqual(len(ids), len(set(ids)))
        for check in policy['checks']:
            self.assertTrue(108100 <= check['id'] <= 108199)
            keys = {key for entry in check.get('compliance', []) for key in entry}
            self.assertTrue({'nist_sp_800-53', 'pci_dss_v4.0', 'soc_2'} <= keys, check['id'])


if __name__ == '__main__':
    unittest.main()
