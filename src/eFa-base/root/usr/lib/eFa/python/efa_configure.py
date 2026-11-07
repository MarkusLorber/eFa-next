# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""efa-configure: run the service configuration steps of eFa-next.

    efa-configure [-v] STEP [STEP ...]       run single steps
    efa-configure [-v] all                    run every install step
    efa-configure --list                      list the steps
    efa-configure --package-hook PKG MODE --package-version V
                                              called by the package scripts

PKG is eFa-base or eFa, MODE is first-install or upgrade. Exit code 0 when
every step passed, 1 when a step failed, 2 for a usage error.
"""

import argparse
import os
import sys

import efa_common as c
import efa_services as s
from efa_common import P, StepError

PACKAGES = ("eFa-base", "eFa")


def sudoers_text():
    pl = c.platform()
    return (s.HEADER +
            "# eFa: lets the first-run wizard apply its settings.\n"
            "# Made at package install, removed after the first boot.\n"
            "%s ALL=(root) NOPASSWD: %s/efa-apply\n"
            % (pl.account("wizard_user"), P("efa_sbin")))


def _visudo(tmp):
    c.run(["visudo", "-c", "-f", tmp])


def step_wizard_access():
    """Allow the wizard to call efa-apply, only while not configured."""
    pl = c.platform()
    if c.read_kv(P("efa_config")).get("CONFIGURED") == "YES":
        c.info("host is configured; no wizard access")
        return
    c.write_file(P("sudoers_file"), sudoers_text(), mode=0o440, validate=_visudo)
    wizard = pl.service("wizard")
    if pl.service_exists(wizard):
        pl.service_enable(wizard, start=True)


EFA_STEPS = {"wizard-access": step_wizard_access}


def plan(package, mode):
    """Return (steps dict, ordered names) for a package hook."""
    if package == "eFa-base":
        order = s.INSTALL_ORDER if mode == "first-install" else s.UPGRADE_ORDER
        return s.INSTALL_STEPS, order
    return EFA_STEPS, (["wizard-access"] if mode == "first-install" else [])


def state_path(package):
    return "%s/install-state/%s" % (P("state_dir"), package)


def write_state(package, version, failed):
    status = "FAILED " + " ".join(failed) if failed else "OK"
    c.ensure_dir(P("state_dir") + "/install-state", 0o750)
    c.write_file(state_path(package), "%s %s\n" % (version, status), 0o640)


def state_ok(package, version):
    return c.read_text(state_path(package), "").split() == [version, "OK"]


def efa_installed():
    return os.path.exists(c.rp(P("efa_sbin") + "/efa-apply"))


def maybe_write_version(version):
    """Write the version file once every installed package passed."""
    needed = ["eFa-base"] + (["eFa"] if efa_installed() else [])
    if all(state_ok(p, version) for p in needed):
        c.write_file(P("version_file"), "eFa-%s\n" % version, 0o644)
        c.info("version file written: eFa-%s" % version)
        return True
    return False


def after_change(package):
    """Reload the service manager, enable eFa timers, restart running units."""
    pl = c.platform()
    pl.service_manager_reload()
    timers, services = pl.efa_units()
    for timer in timers:
        pl.service_enable(timer, start=True)
    if package == "eFa" and pl.service_exists(pl.service("setup_reboot")):
        pl.service_enable(pl.service("setup_reboot"), start=True)
    for unit in services:
        # never restart the oneshots or the first-run wizard
        if unit in pl.EFA_ONESHOTS or unit.split(".")[0] == pl.service("wizard"):
            continue
        if pl.service_is_active(unit):
            pl.service_try_restart(unit)


def package_hook(package, mode, version):
    steps, order = plan(package, mode)
    failed = c.run_steps(steps, order)
    try:
        after_change(package)
    except StepError as exc:
        c.error("systemd update failed: %s" % exc)
        failed.append("units")
    write_state(package, version, failed)
    maybe_write_version(version)
    if failed:
        print("%s %s %s: FAILED steps: %s (see %s/%s)" % (
            package, version, mode, ", ".join(failed), P("log_dir"), c.env.log_file))
        return 1
    print("%s %s %s: all steps passed" % (package, version, mode))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="efa-configure",
                                 description="Configure the eFa-next services.")
    ap.add_argument("steps", nargs="*", help="steps to run, or 'all'")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--list", action="store_true", help="list the steps")
    ap.add_argument("--package-hook", nargs=2, metavar=("PACKAGE", "MODE"))
    ap.add_argument("--package-version", default="")
    args = ap.parse_args(argv)
    c.env.verbose = args.verbose
    c.env.program = "efa-configure"
    if args.list:
        print("\n".join(s.INSTALL_ORDER))
        return 0
    if c.env.live and os.geteuid() != 0:
        print("efa-configure: must run as root", file=sys.stderr)
        return 2
    try:
        c.platform()
    except StepError as exc:
        print("efa-configure: %s" % exc, file=sys.stderr)
        return 2
    if args.package_hook:
        package, mode = args.package_hook
        if package not in PACKAGES or mode not in ("first-install", "upgrade") \
                or not args.package_version:
            ap.error("--package-hook needs eFa-base|eFa, first-install|upgrade "
                     "and --package-version")
        return package_hook(package, mode, args.package_version)
    names = s.INSTALL_ORDER if args.steps == ["all"] else args.steps
    unknown = [n for n in names if n not in s.INSTALL_STEPS]
    if not names or unknown:
        ap.error("unknown or missing steps: %s (use --list)" % " ".join(unknown))
    failed = c.run_steps(s.INSTALL_STEPS, names)
    for name in names:
        print("%s %s" % ("FAILED" if name in failed else "OK", name))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
