<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Markus Lorber and eFa-next contributors -->
<!-- Author: Markus Lorber, Lukasz Galusinski -->
# eFa-next SELinux module

`efa.te` is a placeholder with no rules. The package builds it into
`/usr/share/selinux/packages/eFa/efa.pp`, and the `selinux` step of
`efa-configure` installs it with `semodule -i` whenever the file changes.

Add a rule only when a test in enforcing mode shows that it is needed. A fresh install on
AlmaLinux 9.8 with wizard, first boot, reboot, web pages, mail and backup showed no denial.
Do not copy rules from an older module.

## Find the rules on a host for development

1. Install a fresh AlmaLinux 9 VM, leave SELinux in **enforcing** mode,
   install both eFa-next RPMs and run the whole setup (wizard, reboot,
   first boot), then use every web page, send and receive mail, run
   `efactl status`, a backup and a restore.
2. Collect the denials since the test started:

       ausearch -m AVC,USER_AVC,SELINUX_ERR -ts boot > avc.log

   Use `-ts <date> <time>` when the test spans reboots.
3. Check each denial first. Many have a better fix than a new rule:
   a wrong file label (`restorecon -Rv <path>`, or a file context in the
   package), a boolean (`audit2why -i avc.log` names it, set it with
   `setsebool -P` in the selinux step) or a port label (`semanage port`).
4. Make draft rules for the rest:

       audit2allow -i avc.log -m efa > efa-draft.te

   Copy only the needed `require` entries and `allow` lines into `efa.te`,
   raise the version in the `module` line and add a comment per rule
   saying which test needed it.
5. Rebuild the RPMs, reinstall on a new VM and repeat until
   `ausearch -m AVC -ts boot` shows no denials.

## Build by hand

    checkmodule -M -m -o efa.mod efa.te
    semodule_package -o efa.pp -m efa.mod
    semodule -i efa.pp        # on the development host
