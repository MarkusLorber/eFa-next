# Migrate from eFa 5

`efa-migrate` turns an eFa 5.0 host into eFa-next in place: MailScanner, MailWatch, SpamAssassin, opendkim, opendmarc, sqlgrey and amavis are replaced by rspamd, nginx and the web interface of eFa-next. The first run without options lists what it carries over.

**There is no automatic way back. Take a VM snapshot first.**

Check first that the root password of the database in `/etc/eFa/MySQL-Config` still works: `efa-migrate` stops at once
if it does not, also when it only lists. The command must show `1`:

```bash
MYSQL_PWD="$(sed -n 's/^MYSQLROOTPWD://p' /etc/eFa/MySQL-Config)" mysql --user=root -Ne 'select 1'
```

If it is refused, put the valid password into the line `MYSQLROOTPWD:` of that file, or set MariaDB to the password there.
`efa-migrate --execute-i-have-a-snapshot --reset-db-root-password` does the second for you: over the socket of root if
MariaDB allows it, else in a short start without grant tables and network (the eFa-next web services pause meanwhile, the
start options always go again); `/root/.my.cnf` follows, the one before stays next to it. The password never appears in
a command line or a log; the report says what was done.

1. As root, get the source of the latest release: `efa-migrate` runs from it, next to the modules it needs. It loads the
   packages itself, only with a valid signature of the eFa-next key. Replace the tag with the latest release.

   ```bash
   curl -fsSL https://github.com/MarkusLorber/eFa-next/archive/refs/tags/v6.0.0.5.1.tar.gz | tar xz
   cd eFa-next-6.0.0.5.1/migration
   ```

2. See what would be carried over. This changes nothing:

   ```bash
   ./efa-migrate
   ```

3. Migrate, in a maintenance window: no mail is accepted during the run, and the host reboots at the end.

   Before it changes anything, `efa-migrate` asks you to accept the legal texts of eFa-next: `LICENSE` (GNU AGPL 3.0 or
   later), `DISCLAIMER.md` (no warranty, for qualified administrators of businesses and organisations, not for consumers) and
   `THIRD-PARTY-NOTICES.md`, in the folder of the source you downloaded. Read them, then type `yes` (or `ja`). Nothing is
   accepted for you: without your answer nothing changes.

   For an unattended run (for example in `screen` or `nohup`), accept by naming the digest of exactly these texts. Show
   the texts, the digest and the command line (this changes nothing):

   ```bash
   ./efa-migrate --legal-digest
   ```

   The digest is the first 16 hex digits of SHA-256 over the name and text of each file. Check it yourself in the folder
   of the source:

   ```bash
   for f in LICENSE DISCLAIMER.md THIRD-PARTY-NOTICES.md; do printf '%s\0' "$f"; cat "$f"; printf '\0'; done | sha256sum | cut -c1-16
   ```

   Then, only after you read and accepted the texts:

   ```bash
   ./efa-migrate --execute-i-have-a-snapshot --accept-legal=<digest>
   ```

   A digest of other texts is refused, and nothing changes.

   The normal, attended run:

   ```bash
   ./efa-migrate --execute-i-have-a-snapshot
   ```

4. Store the web admin password it shows once at the end.

5. Check with `efactl status`, read `report.txt` in the backup folder, send a test mail.

The full description, with what to do when a run stops halfway: [migration/README.md](../migration/README.md).
