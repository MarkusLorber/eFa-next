# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""efa-firstboot: the steps after the first boot that follows the setup.

    efa-firstboot                once at boot (marker firstboot-pending)
    efa-firstboot --setup-reboot stop the wizard and reboot (marker setup-reboot)

First boot: wait for the network, warn if there is no internet access,
start the local resolver, update the ClamAV signatures, switch content
disarm and the BEC checks on, enable the service monitor and remove what only the setup needed. Warnings do not stop it; a
failed mandatory step keeps the marker, so the job runs again next boot.
"""

import argparse
import os
import socket
import sys
import time

import efa_common as c
import efa_monitor
from efa_apply import firstboot_marker, reboot_marker
from efa_common import P, StepError

NETWORK_WAIT = 120
REBOOT_DELAY = 20
# Neutral reachability check: the DNS port of root name servers
# (a.root-servers.net and k.root-servers.net), not an eFa project server.
INTERNET_PROBES = (("198.41.0.4", 53), ("193.0.14.129", 53),
                   ("2001:503:ba3e::2:30", 53))


def wait_for_network(timeout=NETWORK_WAIT, sleep=time.sleep):
    pl = c.platform()
    end = time.monotonic() + timeout
    while True:
        if pl.has_default_route():
            return True
        if time.monotonic() >= end:
            return False
        sleep(2)


def internet_reachable(probes=INTERNET_PROBES, timeout=5):
    for host, port in probes:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def update_signatures():
    pl = c.platform()
    update = pl.service("avupdate")
    was_active = pl.service_is_active(update)
    if was_active:
        pl.service_stop(update)
    try:
        c.run(["freshclam"])
    finally:
        if was_active:
            pl.service_start(update)
    pl.service_enable(pl.service("av"), start=True)


def content_disarm(tries=12, sleep=time.sleep):
    """Secure by default: content disarm of a new install. Only now, because efactl checks that every milter of the
    chain answers, and before the setup none runs."""
    for _ in range(tries):
        if c.run([c.which("efactl"), "cdr-set", "--mode", "on"], check=False).returncode == 0:
            return
        sleep(5)
    raise StepError("efactl cdr-set --mode on failed; switch it on in the web interface (Attachments)")


def bec_checks():
    """Secure by default: the BEC checks of a new install, now that the wizard has named the domain they protect."""
    # The habits of known senders (times, volume, new recipients) count too on a new install.
    if c.run([c.which("efactl"), "bec-set", "--mode", "on", "--score_pattern", "2"], check=False).returncode != 0:
        raise StepError("efactl bec-set --mode on failed; switch it on in the web interface (Impersonation & BEC)")


def cleanup_setup():
    pl = c.platform()
    c.remove(P("sudoers_file"))
    c.remove(P("setup_dir"))
    wizard = pl.service("wizard")
    if pl.service_exists(wizard):
        pl.service_disable(wizard, stop=True)


def first_boot():
    if not os.path.exists(c.rp(firstboot_marker())):
        c.info("nothing to do: no first-boot marker")
        return 0
    pl = c.platform()
    if not wait_for_network():
        c.warn("no default route after %d seconds" % NETWORK_WAIT)
    if not internet_reachable():
        c.warn("no internet access: updates and signatures will fail")
    failed = []
    for name, func in (("resolver", lambda: pl.service_enable(pl.service("dns"), start=True)),
                       ("signatures", update_signatures),
                       ("content disarm", content_disarm),
                       ("BEC checks", bec_checks),
                       ("monitor", efa_monitor.enable),
                       ("cleanup", cleanup_setup)):
        try:
            func()
            c.info("first boot: %s ok" % name)
        except StepError as exc:
            if name in ("signatures", "content disarm", "BEC checks"):
                c.warn("first boot: %s failed: %s" % (name, exc))
            else:
                c.error("first boot: %s failed: %s" % (name, exc))
                failed.append(name)
    if failed:
        return 1
    c.remove(firstboot_marker())
    pl.service_disable(pl.service("firstboot"))
    return 0


def setup_reboot(delay=REBOOT_DELAY, sleep=time.sleep):
    if not os.path.exists(c.rp(reboot_marker())):
        return 0
    sleep(delay)  # let the wizard show its last page
    c.remove(reboot_marker())
    pl = c.platform()
    wizard = pl.service("wizard")
    if pl.service_exists(wizard) and pl.service_is_active(wizard):
        pl.service_stop(wizard)
    c.info("rebooting to finish the setup")
    pl.reboot()
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="efa-firstboot")
    ap.add_argument("--setup-reboot", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    c.env.verbose = args.verbose
    c.env.program = "efa-firstboot"
    c.env.log_file = "eFa-firstboot.log"
    if c.env.live and os.geteuid() != 0:
        print("efa-firstboot: must run as root", file=sys.stderr)
        return 2
    try:
        return setup_reboot() if args.setup_reboot else first_boot()
    except StepError as exc:
        c.error(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
