# 16. Migration from eFa 5

`efa-migrate` turns an eFa 5.0 host into eFa-next in place: MailScanner, MailWatch, SpamAssassin, opendkim, opendmarc, sqlgrey
and amavis are replaced by rspamd, nginx and the web interface of eFa-next. The first run without options only lists what it
would carry over.

**There is no automatic way back. Take a VM snapshot first.**

The guide, step by step with the checks before and after:

- [Migration guide (English)](../migration-guide.md)
- [Migrationsleitfaden (Deutsch)](../migration-guide.de.md)
- Reference of `efa-migrate`: [migration.md](../migration.md)

After the migration:

- The main admin logs in at `https://<host name>/login` with an empty user name and the new password that `efa-migrate`
  shows once at the end (also in the file `web-admin-password` of its backup folder, root only: store it, then delete the file).
- MailWatch users are not carried over: make them again under *Users & access › Users* (chapter 8).
- System accounts and SSH stay as they were on the eFa 5 host.
- Greylisting and BEC are switched on; sender allow and block lists of eFa 5 move to the sender lists.
- *Re-Setup* (chapter 2) is offered once on the dashboard: it asks for the EU link, the frameworks and 2FA for the running
  system.

Details: [upgrade.md](../upgrade.md#after-a-migration-from-efa-5).

Next: [efactl reference](17-efactl.md) · Back: [Manual](README.md)
