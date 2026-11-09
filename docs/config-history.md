# Configuration history (O1) and four eyes (P2)

## Configuration history

Before each change through efactl (web interface, API, console), eFa-next reads its configuration files. After the change it
keeps those that changed, with their old and new text, in `/var/lib/eFa/config-history` (root only). It keeps 500 changes, at
most 90 days.

- **Which files:** the settings of eFa-next (`/etc/eFa`, `/etc/efa-web`), `main.cf` and `master.cf`, the maps of eFa-next in
  `/etc/postfix`, its rspamd files, its nginx files and its Fail2Ban jails.
- **What it never keeps:** secrets (keys, passwords, tokens), files only root may read, and files over 512 KB.

Security, Configuration history lists each change: when, who, which command, which files. `history-show` shows its diff.

`history-undo --id ... --confirm yes` takes one change back:

1. It refuses while a later change touched the same files; take that one back first.
2. It puts the files of before back, with their mode and owner.
3. Postfix (`postfix check`), rspamd (configtest) and nginx (`nginx -t`) check them, then load them.
4. If a check fails, the files of after come back and nothing changes.

The undo is a change of its own, so it can be taken back too.

What lives in the database (rules, users, groups, the settings of tenants and domains) is not in this history; the audit log
names each such change with its old and new values.

## Four eyes

`efactl four-eyes-set --mode on [--tenant t]` (only a super admin) makes critical changes of admin logins wait for a second
admin. These are:
- rules;
- releases from quarantine and content disarm;
- switching the protection (virus scan, attachments, content disarm, spam scores, BEC, link check, DLP, TLS, firewall, extra
  scanners, admin access);
- rights (groups, user state, 2FA reset, API tokens, strict audit mode).

How it works:

1. The change does not run. It waits under Security, Four eyes, for up to 7 days.
2. A second admin who may run it too confirms it (`four-eyes-decide --decision confirm`). It runs then, with the name of the
   second admin; the audit log names both.
3. The admin who asked, or one who may run it, can reject it.
4. Emergency path: a super admin may push an own change through at once with `--decision urgent` and a reason. This is
   audited.

Commands that take a secret (setting a password) are not held: the secret would have to wait in a file. The console of root is
not affected.
