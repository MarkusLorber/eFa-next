# Migrate from eFa 5

`efa-migrate` turns an eFa 5.0 host into eFa-next in place: MailScanner, MailWatch, SpamAssassin, opendkim, opendmarc, sqlgrey and amavis are replaced by rspamd, nginx and the web interface of eFa-next. The first run without options lists what it carries over.

**There is no automatic way back. Take a VM snapshot first.**

1. See what would be carried over. This changes nothing:

   ```bash
   ./efa-migrate
   ```

2. Migrate, in a maintenance window: no mail is accepted during the run, and the host reboots at the end.

   ```bash
   ./efa-migrate --execute-i-have-a-snapshot
   ```

3. Store the web admin password it shows once at the end.

4. Check with `efactl status`, read `report.txt` in the backup folder, send a test mail.

The full description, with what to do when a run stops halfway: [migration/README.md](../migration/README.md).
