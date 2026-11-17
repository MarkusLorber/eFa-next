# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The progress bar of the setup wizard follows the real steps of efa-apply (Hans 2026-11-16).

efa-init.py keeps its own copy of the step order (it runs without the root-only module efa_apply) and reads the line
"INFO: step <name>: start" that efa-apply --verbose writes before each step. Both must stay the same as efa-apply.
"""

import ast
import io
import os
import re
import unittest
from unittest import mock

from efa_testlib import TOP, c

import efa_apply

INIT = os.path.join(TOP, "next", "usr", "local", "sbin", "efa-init.py")


def init_constant(name):
    with open(INIT, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == name for t in node.targets):
            return node.value
    raise AssertionError(name + " not found in efa-init.py")


class SetupProgressTest(unittest.TestCase):
    def test_same_steps_as_efa_apply(self):
        self.assertEqual(ast.literal_eval(init_constant("SETUP_STEPS")), efa_apply.STEP_ORDER)

    def test_start_line_matches(self):
        pattern = re.compile(ast.literal_eval(init_constant("STEP_START_RE").args[0]))
        err = io.StringIO()
        with mock.patch.object(c.env, "verbose", True), mock.patch("sys.stderr", err), \
                mock.patch.object(c, "rp", side_effect=OSError("no log in the test")):
            c.info("step %s: start" % efa_apply.STEP_ORDER[0])
        self.assertEqual(pattern.match(err.getvalue().strip()).group(1), efa_apply.STEP_ORDER[0])

    def test_wizard_runs_efa_apply_verbose(self):
        self.assertIn("--verbose", ast.literal_eval(init_constant("EFA_APPLY")))


if __name__ == "__main__":
    unittest.main()
