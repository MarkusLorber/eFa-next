# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""No telemetry: the code of eFa-next names no analytics, crash-report or telemetry service. A check of known names, not a
proof of absence; the outgoing connections of eFa-next are the ones an admin turns on (docs/compliance/README.md)."""
import os
import re
import unittest

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KNOWN = re.compile(r'google-analytics\.com|googletagmanager\.com|analytics\.google|sentry\.io|ingest\.sentry|mixpanel\.com|segment\.(io|com)|'
                   r'amplitude\.com|posthog\.com|plausible\.io|hotjar\.com|datadoghq\.(com|eu)|nr-data\.net|newrelic\.com|statsig|'
                   r'bugsnag\.com|app-measurement\.com|telemetry\.[a-z0-9.-]+\.(com|net|org|io)', re.I)


class NoTelemetry(unittest.TestCase):
    def test_no_known_telemetry_endpoint(self):
        found = []
        for top in ('next', 'src', 'migration', 'build'):
            for folder, _dirs, names in os.walk(os.path.join(TOP, top)):
                for name in names:
                    path = os.path.join(folder, name)
                    try:
                        with open(path, encoding='utf-8') as f:
                            text = f.read()
                    except (UnicodeDecodeError, OSError):
                        continue
                    found += [f'{os.path.relpath(path, TOP)}: {hit.group(0)}' for hit in KNOWN.finditer(text)]
        self.assertEqual(found, [])

    def test_the_check_sees_a_known_name(self):
        self.assertTrue(KNOWN.search('https://o1.ingest.sentry.io/api') and KNOWN.search('www.google-analytics.com'))


if __name__ == '__main__':
    unittest.main()
