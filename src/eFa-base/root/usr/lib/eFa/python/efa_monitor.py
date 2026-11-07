# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""efa-monitor: restart failed services and tell the admin.

    efa-monitor                 one check (run every minute by cron)
    efa-monitor --enable        write the cron file (turns the job on)
    efa-monitor --disable       remove the cron file (turns the job off)
    efa-monitor --reboot-check  record whether a reboot is due (daily timer)

Settings in the monitor settings file (KEY=value, shell style, no
expansion): SERVICES (space separated), MAX_RESTARTS, COUNTER_MINUTES.
A down service is restarted up to MAX_RESTARTS times. After that the
monitor stops trying and mails the admin once. The counter of a service
is dropped COUNTER_MINUTES after its first restart.

efactl maintenance-set turns the job on and off through the cron file.
"""

import argparse
import email.message
import fcntl
import json
import os
import shlex
import sys
import time

import efa_common as c
from efa_common import P, StepError

DEFAULTS = {"SERVICES": "", "MAX_RESTARTS": "3", "COUNTER_MINUTES": "60"}


def cron_text():
    return ("# SPDX-License-Identifier: AGPL-3.0-or-later\n"
            "# Copyright (C) 2026 Markus Lorber and eFa-next contributors\n"
            "# Author: Markus Lorber, Lukasz Galusinski\n"
            "# eFa service monitor, turned on and off by efactl maintenance-set.\n"
            "MAILTO=\"\"\n"
            "* * * * * root %s/efa-monitor\n" % P("efa_sbin"))


def read_settings():
    values = dict(DEFAULTS)
    for line in c.read_text(P("monitor_settings"), "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        try:
            parts = shlex.split(value)
        except ValueError:
            continue
        values[key.strip()] = " ".join(parts)
    try:
        limit = max(0, int(values["MAX_RESTARTS"]))
        minutes = max(1, int(values["COUNTER_MINUTES"]))
    except ValueError:
        raise StepError("MAX_RESTARTS and COUNTER_MINUTES must be numbers")
    return values["SERVICES"].split(), limit, minutes * 60


def state_file():
    return P("state_dir") + "/monitor-state.json"


def load_state():
    try:
        data = json.loads(c.read_text(state_file(), "{}"))
        return data if isinstance(data, dict) else {}
    except ValueError:
        return {}


def mail_admin(subject, body):
    admin = c.read_kv(P("efa_config")).get("ADMINEMAIL", "")
    if not c.valid_email(admin):
        c.warn("no valid ADMINEMAIL; not mailed: %s" % subject)
        return
    msg = email.message.EmailMessage()
    msg["To"] = admin
    msg["From"] = "root@" + c.current_fqdn()
    msg["Subject"] = subject
    msg.set_content(body)
    c.run([P("sendmail"), "-t", "-i"], input_text=msg.as_string())


def check(now=None):
    """One monitor pass. Returns the state that was saved."""
    pl = c.platform()
    services, limit, window = read_settings()
    now = int(now if now is not None else time.time())
    old = load_state()
    state = {}
    host = c.current_fqdn()
    for svc in services:
        entry = old.get(svc)
        if entry and now - entry.get("since", 0) >= window:
            entry = None
        if pl.service_is_active(svc):
            if entry:
                state[svc] = entry
            continue
        if not pl.service_exists(svc):
            c.warn("monitored service %s is not installed" % svc)
            continue
        entry = entry or {"count": 0, "since": now, "gave_up": False}
        if entry["count"] >= limit:
            if not entry["gave_up"]:
                c.error("%s is still down after %d restarts; giving up"
                        % (svc, entry["count"]))
                mail_admin("eFa monitor: %s on %s is down" % (svc, host),
                           "The service %s on %s is down.\n"
                           "The monitor restarted it %d times and stops trying "
                           "for now.\nPlease check the host.\n"
                           % (svc, host, entry["count"]))
                entry["gave_up"] = True
        else:
            entry["count"] += 1
            res = pl.service_restart(svc, check=False)
            ok = res is not None and res.returncode == 0
            c.warn("%s was down; restart %d of %d %s"
                   % (svc, entry["count"], limit, "done" if ok else "failed"))
        state[svc] = entry
    c.write_file(state_file(), json.dumps(state, sort_keys=True) + "\n", 0o640)
    return state


def reboot_check():
    due, reason = c.platform().reboot_required()
    marker = P("state_dir") + "/reboot-due"
    if due:
        c.write_file(marker, time.strftime("%Y-%m-%d") + "\n" + reason + "\n")
        c.warn("a reboot is due")
    elif c.remove(marker):
        c.info("no reboot due any more")
    return due


def enable():
    return c.write_file(P("monitor_cron"), cron_text(), 0o644)


def disable():
    return c.remove(P("monitor_cron"))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="efa-monitor", description="eFa service monitor")
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--enable", action="store_true")
    group.add_argument("--disable", action="store_true")
    group.add_argument("--reboot-check", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    c.env.verbose = args.verbose
    c.env.program = "efa-monitor"
    c.env.log_file = "eFa-Monitor.log"
    if c.env.live and os.geteuid() != 0:
        print("efa-monitor: must run as root", file=sys.stderr)
        return 2
    try:
        if args.enable:
            enable()
        elif args.disable:
            disable()
        elif args.reboot_check:
            reboot_check()
        else:
            lock_path = c.rp(P("state_dir") + "/monitor.lock")
            os.makedirs(os.path.dirname(lock_path), exist_ok=True)
            with open(lock_path, "w") as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    return 0  # the previous run is still busy
                check()
    except StepError as exc:
        c.error(str(exc))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
