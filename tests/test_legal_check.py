# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""scripts/legal_check.py: each rule with a text that keeps it and one that breaks it, and the repository as it is."""
import os
import sys
import unittest

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(TOP, 'scripts'))
sys.dont_write_bytecode = True

import legal_check as lc  # noqa: E402

GOOD = """# Disclaimer / Haftungsausschluss

## English

### Intended use

eFa-next is for qualified administrators, not released for consumers, without any promise, to the maximum extent permitted by
applicable law. The rights under the AGPL are not affected by this.

### Warranty and liability

eFa-next is provided "as is", without warranty, to the maximum extent permitted by applicable law.

To the maximum extent permitted by applicable law, neither Markus Lorber, nor any other author or contributor, nor any sponsor,
including IT-World ITW GmbH, is liable for any damage (RBL).

IT-World ITW GmbH sponsors the project and holds no rights to the code.

This adds to sections 15 and 16 of the GNU Affero General Public License (`LICENSE`).

**Severability.** If a provision is invalid, the rest stays valid.

## Deutsch

### Bestimmungsgemäßer Gebrauch

eFa-next ist für fachkundige Administratoren, für Verbraucher nicht freigegeben, ohne jede Zusage, soweit gesetzlich zulässig.
Die Rechte nach der AGPL bleiben davon unberührt.

### Gewährleistung und Haftung

eFa-next wird ohne jede Gewährleistung bereitgestellt, soweit gesetzlich zulässig.

Soweit gesetzlich zulässig, haften weder Markus Lorber noch andere Autoren oder Mitwirkende noch Sponsoren, darunter die
IT-World ITW GmbH, für Schäden (RBL).

Die IT-World ITW GmbH unterstützt das Projekt als Sponsor und hat keine Rechte am Code.

Dies ergänzt die Abschnitte 15 und 16 der GNU Affero General Public License (`LICENSE`).

**Salvatorische Klausel.** Ist eine Bestimmung unwirksam, bleibt der Rest wirksam.
"""


def rules(found):
    return sorted({item.split()[0] for item in found})


class DisclaimerTests(unittest.TestCase):
    def bad(self, old, new, rule):
        self.assertIn(old, GOOD)
        found = lc.disclaimer_problems(GOOD.replace(old, new))
        self.assertIn(rule, rules(found), found)
        return found

    def test_good_text_has_no_finding(self):
        self.assertEqual(lc.disclaimer_problems(GOOD), [])

    def test_l1_both_languages_and_three_sections(self):
        self.bad('## Deutsch', '## Polski', 'L1')
        self.bad('**Severability.**', 'Severability:', 'L1')
        self.bad('### Gewährleistung und Haftung', '### Haftung', 'L1')

    def test_l2_every_exclusion_qualified(self):
        self.bad('without warranty, to the maximum extent permitted by applicable law.', 'without warranty.', 'L2')
        self.bad('ohne jede Gewährleistung bereitgestellt, soweit gesetzlich zulässig.', 'ohne jede Gewährleistung bereitgestellt.', 'L2')

    def test_l3_protected_parties(self):
        self.bad('nor any other author or contributor,', '', 'L3')
        self.bad('noch Sponsoren', '', 'L3')

    def test_l4_what_the_law_keeps_is_not_excluded(self):
        self.bad('is liable for any damage', 'is liable for any damage, including gross negligence', 'L4')
        self.bad('für Schäden (RBL)', 'für Schäden (RBL), auch bei Vorsatz und Personenschäden', 'L4')
        self.bad('für Schäden (RBL).', 'für Schäden (RBL). Die Haftung nach dem PHG ist ausgeschlossen.', 'L4')
        kept = GOOD.replace('stays valid.', 'stays valid. Liability for intent and gross negligence remains unaffected.') \
            .replace('der Rest wirksam.', 'der Rest wirksam. Die Haftung für Vorsatz und grobe Fahrlässigkeit bleibt unberührt.')
        self.assertEqual(lc.disclaimer_problems(kept), [], 'named as kept is fine')

    def test_l5_no_rights_sentence(self):
        self.bad('and holds no rights to the code', 'and holds the rights to the code', 'L5')

    def test_l6_use_statement_not_a_ban(self):
        self.bad('The rights under the AGPL are not affected by this.', '', 'L6')
        self.bad('not released for consumers', 'prohibited for consumers', 'L6')
        self.bad('für Verbraucher nicht freigegeben', 'für Verbraucher verboten', 'L6')

    def test_l7_agpl_sections_15_and_16(self):
        self.bad('Abschnitte 15 und 16', 'Abschnitte 15', 'L7')

    def test_l8_parity(self):
        self.bad('für Schäden (RBL)', 'für Schäden (DNSBL)', 'L8')


class FileTests(unittest.TestCase):
    def test_l9_license_texts_unmodified(self):
        with open(os.path.join(TOP, 'LICENSE'), encoding='utf-8') as f:
            text = f.read()
        with open(os.path.join(TOP, 'LICENSES', 'GPL-3.0.txt'), 'rb') as f:
            gpl = f.read()
        self.assertEqual(lc.license_problems(text, gpl), [])
        self.assertEqual(lc.license_problems(text.replace('\n\n', '\n'), gpl), [], 'only the words count')
        self.assertEqual(rules(lc.license_problems(text.replace('free software', 'open software', 1), gpl + b' ')), ['L9'])
        self.assertEqual(len(lc.license_problems(text.replace('NO WARRANTY', 'WARRANTY', 1), gpl + b' ')), 2)

    def test_l10_notice(self):
        self.assertEqual(lc.notice_problems(f'{lc.COPYRIGHT}. {lc.AUTHOR}.'), [])
        self.assertEqual(rules(lc.notice_problems('Copyright (C) 2026 IT-World ITW GmbH')), ['L10'])

    def test_l11_no_files_from_efa(self):
        self.assertEqual(lc.efa_files_problems('# x\n\n## Files with code from eFa\n\nNone.\n'), [])
        self.assertEqual(rules(lc.efa_files_problems('## Files with code from eFa\n\n- efa-setup.sh\n')), ['L11'])
        self.assertEqual(rules(lc.efa_files_problems('## Other\n\nNone.\n')), ['L11'])

    def test_l12_required_packages_in_the_notices(self):
        spec = 'Name: eFa\nRequires:       postfix\nRequires: python3-flask >= 2.0\nRequires: eFa-next-base = 1:%{version}\n'
        notices = ('| Component | Version | License (SPDX) |\n| --- | --- | --- |\n| Postfix | 3.5 | IPL-1.0 |\n\n'
                   '| Component | License (SPDX) |\n| --- | --- |\n| Flask, click | BSD-3-Clause |\n')
        self.assertEqual(lc.requires(spec), ['postfix', 'python3-flask'])
        self.assertEqual(lc.sbom_problems([spec], notices), [])
        self.assertEqual(lc.sbom_problems([spec + 'Requires: tar\n'], notices), ['L12 THIRD-PARTY-NOTICES.md: tar (Requires in rpm/) has no row'])
        self.assertEqual(lc.sbom_problems([spec], notices.replace('| BSD-3-Clause |', '|  |')), ['L12 THIRD-PARTY-NOTICES.md: python3-flask has no license'])

    def test_l2_short_forms(self):
        self.assertEqual(lc.short_problems({'x': ('To the maximum extent permitted by applicable law, nobody is liable.', 'en'),
                                            'y': ('Soweit gesetzlich zulässig, haften Autoren für keine Schäden.', 'de')}), [])
        self.assertEqual(rules(lc.short_problems({'x': ('Nobody is liable for it.', 'en')})), ['L2'])

    def test_l13_references(self):
        self.assertEqual(lc.reference_problems({'setup': 'see DISCLAIMER.md'}), [])
        self.assertEqual(lc.reference_problems({'rbl': 'not liable'}), ['L13 rbl: no reference to DISCLAIMER.md'])

    def test_l14_digest_from_the_texts(self):
        names = ('LICENSE', 'DISCLAIMER.md', 'THIRD-PARTY-NOTICES.md')
        self.assertEqual(lc.digest_problems(names, 'efa_legal.build(TOP, out, v)', {'init': "answers['legal'] = legal_digest()"}), [])
        self.assertEqual(rules(lc.digest_problems(names[:1], 'efa_legal.build(', {})), ['L14'])
        self.assertEqual(rules(lc.digest_problems(names, 'copy digest.txt', {})), ['L14'])
        self.assertEqual(lc.digest_problems(names, 'efa_legal.build(', {'init': "LEGAL = '0123456789abcdef'"}), ['L14 init:1: a fixed legal digest'])

    def test_l5_it_world_only_as_sponsor(self):
        self.assertEqual(lc.rights_problems('a', 'IT-World ITW GmbH sponsors the project and holds no rights.\n'
                                                 'not the employer of the author: IT-World'), [])
        self.assertEqual(lc.rights_problems('a', 'x\nCopyright (C) 2026 IT-World ITW GmbH'), ['L5 a:2: IT-World in a copyright line'])
        self.assertEqual(rules(lc.rights_problems('a', 'IT-World ITW GmbH, employer of the author')), ['L5'])

    def test_l15_nothing_internal(self):
        self.assertEqual(lc.internal_problems('a', 'listen on 127.0.0.1:10025\nversion 8.8990'), [])
        # The neutral example of the setup wizard (efa_wizard.py EXAMPLE_TEXT), placeholder register numbers, the sponsor link.
        for line in ('This e-mail and any attachments are confidential and meant only for the addressee. If you got it by mistake, '
                     'please tell the sender and delete it.', 'Example GmbH, FN 000000x, ATU00000000', 'Diese E-Mail ist vertraulich.',
                     'IT-World ITW GmbH, main sponsor of the project: https://it-world.eu'):
            self.assertEqual(lc.internal_problems('a', line), [], line)
        for line in ('inet:127.0.0.1:8899', 'port 8902', 'smtp 8901', 'IT-World ITW GmbH, FN 123456a, Handelsgericht Wien',
                     'This e-mail of IT-World ITW GmbH and any attachments are confidential.', 'Diese Nachricht der ITW ist vertraulich.',
                     'Fragen an support@it-world.eu'):
            self.assertEqual(rules(lc.internal_problems('a', line)), ['L15'], line)


class RepositoryTests(unittest.TestCase):
    def test_repository_has_only_the_open_findings(self):
        found = lc.problems()
        self.assertEqual([item for item in found if item not in lc.OPEN], [])

    def test_constants_are_read(self):
        with open(os.path.join(TOP, 'next/usr/lib/eFa/python/efa_legal.py'), encoding='utf-8') as f:
            legal = f.read()
        self.assertEqual(lc.constant(legal, 'NAMES'), ('LICENSE', 'DISCLAIMER.md', 'THIRD-PARTY-NOTICES.md'))
        self.assertEqual(set(lc.constant(legal, 'SUMMARY')), {'en', 'de'})
        with open(os.path.join(TOP, 'next/usr/local/sbin/efa-init.py'), encoding='utf-8') as f:
            self.assertIn('IT-World ITW GmbH', lc.constant(f.read(), 'DISCLAIMER_SHORT'))
        with open(os.path.join(TOP, 'next/usr/sbin/efactl'), encoding='utf-8') as f:
            self.assertIn('not liable', lc.constant(f.read(), 'RBL_TERMS_TEXT'))


if __name__ == '__main__':
    unittest.main()
