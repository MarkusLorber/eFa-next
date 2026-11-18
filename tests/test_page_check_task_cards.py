# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The standard-view check of the CI (scripts/page_times.py) for task cards: a control or a link into Expert, no dead
anchors, the same values and addresses as the forms of Expert."""

import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('page_times', os.path.join(HERE, '..', 'scripts', 'page_times.py'))
page_times = importlib.util.module_from_spec(spec)
spec.loader.exec_module(page_times)

EXPERT = ('<main><div class="card" id="greylisting-set"><form method="post" action="/run/greylisting-set">'
          '<input type="hidden" name="csrf" value="b"><input type="hidden" name="mode" value="off">'
          '<input type="text" name="minutes" value="5"><select name="days"><option value="1" selected>1</option><option value="3">3</option></select>'
          '<button>Apply</button></form></div><div class="card" id="reboot"><form method="post" action="/run/reboot"><button>Reboot</button></form></div></main>')


def standard(card):
    return f'<main><div class="card task" id="spam-grey">{card}</div><div class="card" id="other"></div></main>'


class TaskCardCheckTests(unittest.TestCase):
    def test_same_values_and_live_anchors_pass(self):
        card = ('<form method="post" action="/run/greylisting-set"><input type="hidden" name="csrf" value="a">'
                '<input type="hidden" name="mode" value="off"><input type="hidden" name="minutes" value="5"><input type="hidden" name="days" value="1">'
                '<button>Off</button></form><a class="btn s" href="/p/maint?view=expert#reboot">Reboot</a>')
        self.assertEqual(page_times.task_card_problems('spam', standard(card), EXPERT), [])

    def test_link_only_card_passes(self):
        self.assertEqual(page_times.task_card_problems('maint', standard('<a href="/p/maint?view=expert#reboot">Reboot</a>'), EXPERT), [])

    def test_dead_anchor_fails(self):
        found = page_times.task_card_problems('maint', standard('<a href="/p/maint?view=expert#halt">Shut down</a>'), EXPERT)
        self.assertEqual(found, ['maint/spam-grey: link to #halt, which the expert view lacks'])

    def test_no_control_and_no_link_fails(self):
        found = page_times.task_card_problems('spam', standard('<p>Greylisting: on</p>'), EXPERT)
        self.assertEqual(found, ['spam/spam-grey: task card without a control or a link to the expert view'])

    def test_other_value_than_expert_fails(self):
        card = ('<form method="post" action="/run/greylisting-set"><input type="hidden" name="mode" value="off">'
                '<input type="hidden" name="minutes" value="10"><button>Off</button></form>')
        found = page_times.task_card_problems('spam', standard(card), EXPERT)
        self.assertEqual(len(found), 1, found)
        self.assertIn("minutes='10', the expert view has ['5']", found[0])

    def test_other_address_than_expert_fails(self):
        card = '<form method="post" action="/run/greylisting-other"><input type="hidden" name="mode" value="off"><button>Off</button></form>'
        found = page_times.task_card_problems('spam', standard(card), EXPERT)
        self.assertEqual(found, ['spam/spam-grey: posts to /run/greylisting-other, no form of the expert view does'])

    def test_switch_compared_by_its_state(self):
        # The switch posts '' (keep the value) where the Expert form shows the default: the state shown counts, not the posting.
        switch = ('<form method="post" action="/run/greylisting-set" class="toggle"><input type="hidden" name="csrf" value="a">'
                  '<input type="hidden" name="minutes" value=""><input type="hidden" name="mode" value="off">'
                  '<button class="badge on" aria-pressed="{}">On</button></form>')
        expert = EXPERT.replace('<div class="card" id="greylisting-set">', '<div class="card" id="greylisting-set"><h2>Greylisting' + switch.format('true') + '</h2>')
        self.assertEqual(page_times.task_card_problems('spam', standard(switch.format('true')), expert), [])
        found = page_times.task_card_problems('spam', standard(switch.format('false')), expert)
        self.assertEqual(len(found), 1, found)
        self.assertIn("switch false, the expert view shows it ['true']", found[0])

    def test_switch_against_the_mode_field_of_expert(self):
        # Expert shows the state as the mode field of its form (a chosen option or a box), not as a switch.
        switch = ('<form method="post" action="/run/greylisting-set" class="toggle"><input type="hidden" name="mode" value="x">'
                  '<button class="badge" aria-pressed="{}">x</button></form>')
        select = ('<main><div class="card" id="greylisting-set"><form method="post" action="/run/greylisting-set"><select name="mode">'
                  '<option value="on"{}>on</option><option value="off"{}>off</option></select></form></div></main>')
        box = ('<main><div class="card" id="greylisting-set"><form method="post" action="/run/greylisting-set">'
               '<input type="checkbox" name="mode" value="on"{}></form></div></main>')
        check = page_times.task_card_problems
        self.assertEqual(check('spam', standard(switch.format('true')), select.format(' selected', '')), [])
        self.assertEqual(check('spam', standard(switch.format('false')), select.format('', ' selected')), [])
        self.assertEqual(check('spam', standard(switch.format('false')), box.format('')), [], 'an unticked box is off')
        self.assertEqual(check('spam', standard(switch.format('true')), box.format(' checked')), [])
        self.assertEqual(len(check('spam', standard(switch.format('true')), select.format('', ' selected'))), 1, 'on against off')
        self.assertEqual(len(check('spam', standard(switch.format('false')), box.format(' checked'))), 1, 'off against a ticked box')

    def test_normal_cards_are_not_task_cards(self):
        self.assertEqual(page_times.task_card_problems('spam', '<main><div class="card" id="x"><p>no control</p></div></main>', EXPERT), [])


if __name__ == '__main__':
    unittest.main()
