# Upgrade

An upgrade (for example 6.0.0.3 to 6.0.0.4) comes from the eFa-next repository: by the automatic update in its maintenance
window, on the page System, Maintenance & update, or on the console with `sudo dnf upgrade eFa eFa-base`.

## What stays

- Every login stays as it was: the web admin password, the other users with their groups, API tokens, the console user and
  the SSH settings. An upgrade changes no setting; it only adds what is new.
- New features of the release are off until you switch them on (for example the attachment checks of 6.0.0.4 that look at
  file names and at programs by their content).

## The first login after the upgrade

Log in as before (see [Logging in](install.md#logging-in)). Then:

1. **Terms of use and legal texts**: when they changed with the release, the web interface first shows them and asks you to
   confirm them once. Nothing else opens before that.
2. **Dashboard, "Needs attention"**: notes of the upgrade, each with a link to its page. With 6.0.0.4 for example:
   - "TLS was raised to the profile BSI TR-02102-2 by the update": old TLS versions and weak ciphers are off. Nothing to do,
     unless an old server must still send to you (Security, TLS profile).
   - "Terms of use not yet confirmed for these active blocklists": confirm the terms on the page Blocklists, or switch the
     list off.
3. The new options of the release are on their pages; [CHANGELOG.md](../CHANGELOG.md) lists them.

Five wrong logins from one address lock that address out for five minutes. Forgotten password:
[Forgotten password or locked out](install.md#forgotten-password-or-locked-out).

## After a migration from eFa 5

- **Web admin**: `efa-migrate` makes a new web admin password. It shows it once at the end and writes it to the file
  `web-admin-password` in its backup folder (root only). Store it, then delete that file. Log in at `https://<host name>/login`
  with an empty user name and this password.
- **MailWatch users are not carried over**: eFa-next has one web admin plus its own users. Make the users again on the page
  Users & access, Users, or with `sudo efactl user-set --username <name> --action set --role <role>`.
- **System accounts and SSH** stay as they were on the eFa 5 host: the migration does not run the setup wizard, so it makes no
  console user and does not change the root login.

More: [Migrate from eFa 5](migration.md).
