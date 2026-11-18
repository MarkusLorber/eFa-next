# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The leapp vendor maps of the release upgrade against the loader of leapp 0.25 (VMAP-2), and the stop when leapp rejects
a vendor map anyway."""

import glob
import importlib.util
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'next', 'usr', 'lib', 'eFa', 'python'))
import efa_release_upgrade as ru  # noqa: E402

REPO_KEYS = ('repoid', 'channel', 'repo_type', 'arch', 'major_version', 'distro')


def load_2_0_0(data, target_distro='almalinux'):
    """The checks of RepoMapData.load_from_dict and get_mappings of AlmaLinux leapp-repository almalinux-ng-0.25.0
    (repos/system_upgrade/common/libraries/repomaputils.py), without leapp: the format exactly 2.0.0, every repository entry
    with its keys, every target a dict of distributions with a 'default', every PESID of a mapping in the repositories.
    Returns {(source major, target major): {source pesid: targets for target_distro}}; raises KeyError or ValueError as
    leapp does (leapp then calls the map invalid)."""
    if data['version_format'] != '2.0.0':
        raise ValueError(f"unsupported version of format. Get {data['version_format']} required 2.0.0")
    pesids = set()
    for family in data['repositories']:
        pesids.add(family['pesid'])
        for repo in family['entries']:
            for key in REPO_KEYS:
                repo[key]  # noqa: B018  KeyError as in add_repository
    found = {}
    for mapping in data['mapping']:
        for entry in mapping['entries']:
            targets = entry['target']
            if not isinstance(targets, dict):
                raise ValueError('The target field of a mapping entry is not a dict')
            for pesid in [entry['source']] + [pesid for names in targets.values() for pesid in names]:
                if pesid not in pesids:
                    raise ValueError(f'The {pesid} pesid is not related to any repository.')
            chosen = targets.get(target_distro, targets['default'])
            found.setdefault((mapping['source_major_version'], mapping['target_major_version']), {})[entry['source']] = sorted(chosen)
    return found


class VendorMapFormatTests(unittest.TestCase):
    def test_2_0_0_maps_load_as_leapp_0_25_loads_them(self):
        files = ru.vendor_files('almalinux', ru.leapp_map_format({'version_format': '2.0.0', 'provided_data_streams': ['5.0']}))
        for vendor in ('efa-next', 'rspamd'):
            data = json.loads(files[f'{vendor}_map.json'])
            self.assertEqual(load_2_0_0(data), {('9', '10'): {f'{vendor}-el9': [f'{vendor}-el10']}})
            self.assertEqual(json.loads(files[f'{vendor}_pes.json'])['provided_data_streams'], ['5.0'])

    def test_1_3_0_maps_are_what_leapp_0_25_rejects(self):
        files = ru.vendor_files('almalinux', ru.leapp_map_format({}))
        with self.assertRaisesRegex(ValueError, 'unsupported version of format. Get 1.3.0 required 2.0.0'):
            load_2_0_0(json.loads(files['efa-next_map.json']))

    def test_unknown_format_gives_no_data_stream(self):
        self.assertEqual(ru.leapp_map_format({'version_format': '3.0.0'}), ('3.0.0', None))

    def test_installed_leapp_loader_when_present(self):
        # On a host with leapp-upgrade-el9toel10 installed: its own loader on our map (skipped elsewhere, as on the CI VMs).
        found = glob.glob('/usr/share/leapp-repository/repositories/system_upgrade/common/libraries/repomaputils.py')
        if not found:
            self.skipTest('leapp-repository not installed')
        spec = importlib.util.spec_from_file_location('repomaputils', found[0])
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except ImportError as err:
            self.skipTest(f'leapp framework not importable: {err}')
        files = ru.vendor_files('almalinux', ru.leapp_map_format(json.load(open('/etc/leapp/files/repomap.json'))))
        module.RepoMapData.load_from_dict(json.loads(files['efa-next_map.json']))


class MapRejectedInhibitorTests(unittest.TestCase):
    LOG = ('Vendor efa-next found in active list\n'
           'leapp.workflow.FactsCollection.vendor_repositories_mapping: The repository mapping file is invalid: The obtained repomap '
           'data has unsupported version of format. Get 1.3.0 required 2.0.0\n')

    def test_rejected_map_in_the_log_stops(self):
        problems = ru.removal_problems(self.LOG, {})
        self.assertTrue(problems[0].startswith('leapp rejected a vendor map (The repository mapping file is invalid'), problems)

    def test_rejected_map_in_the_report_stops(self):
        report = {'entries': [{'title': 'Upgrade failed', 'summary': 'The repository mapping file is invalid: the JSON is missing a required field'}]}
        problems = ru.removal_problems('Vendor efa-next found in active list\n', report)
        self.assertIn('the JSON is missing a required field', problems[0])

    def test_no_rejection_no_such_problem(self):
        self.assertFalse([p for p in ru.removal_problems('Vendor efa-next found in active list\n', {}) if 'rejected a vendor map' in p])


if __name__ == '__main__':
    unittest.main()
