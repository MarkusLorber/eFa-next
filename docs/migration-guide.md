# Migration guide: from eFa 5 to eFa-next

This guide takes an eFa 5.0 host to eFa-next 6.0.0.5.2 in place, step by step, with `efa-migrate`. The short version is
[migration.md](migration.md), the technical description [migration/README.md](../migration/README.md).
Deutsch: [migration-guide.de.md](migration-guide.de.md).

**There is no automatic way back.** The only way back is a VM snapshot (or a full image) taken right before the migration.

## 1. Requirements

- **eFa 5.0.x** on **AlmaLinux 9, Rocky Linux 9 or RHEL 9** (x86-64). Older versions (eFa 4 and before) are not supported.
- **A CPU with x86-64-v3** (AVX2) for the later upgrade to EL10 (eFa-next on EL9 runs without it as well). Check:

  ```bash
  /lib64/ld-linux-x86-64.so.2 --help | grep x86-64-v3
  ```

  The line must contain `(supported, searched)`.
- **Free space:** on `/var` at least twice the size of the database (for the backup of the old databases; `efa-migrate`
  checks it and stops before it changes anything otherwise), plus room for the new packages.

  ```bash
  df -h / /var /boot
  du -sh /var/lib/mysql
  ```

- **A snapshot or image** of the VM, right before the start (step 2).
- **A maintenance window** of about an hour: the host accepts no mail during the run and reboots at the end. Mail sent in
  that time is delivered again by the senders later, or goes to another MX.
- **Root access** at the console or over SSH.
- **Greylisting and BEC:** both are on after the migration, as on a new install of eFa-next (greylisting 5 minutes,
  7 days); the report says so and how to switch them off.
- **DNS and certificates:** the host name and the MX records stay as they are. If eFa 5 sent all names to a forwarder
  (a forward-zone "." in unbound), eFa-next resolves itself afterwards when the root servers answer over UDP and TCP port
  53; forwarders for internal zones stay (Internal DNS). Otherwise the forwarder stays and the report says so. Existing Let's Encrypt certificates in
  `/etc/letsencrypt` are carried over. A valid certificate of the host name goes to nginx and Postfix as it is: the same
  key and key type, no new request, so a published TLSA record (DANE) stays right, and renewals keep the key. eFa-next writes the paths
  into its own nginx and Postfix settings; certbot renews through the web server of eFa-next (webroot), the apache
  settings of eFa 5 in the renewal file go (a copy stays as `.efa-takeover.bak`). If it is
  expired or names another host, the report says so and nothing changes: get a new one with `efactl letsencrypt-set`. A
  host migrated before this shows a notice on the dashboard; `efactl letsencrypt-takeover` takes the certificate over then.
  A new key (ECDSA) comes only with `efactl letsencrypt-rollover`, which shows the new TLSA record to publish first.
- **A test run on a clone:** block outgoing mail first (ports 25, 465 and 587), otherwise the clone delivers mail from its
  queue to real recipients.
- **Several MX hosts or a cluster:** migrate one host after the other. Start the next one only when the one before accepts
  and delivers mail again.

## 1a. Dedicated server

eFa-next needs a server or VM of its own. A host that runs other services besides eFa 5 is not a good start: move them first. Only eFa-next and the operating system run on it: no other server services, no other
open ports. Monitoring or backup agents of the admin (such as Wazuh) are possible, at your own risk. eFa-next hardens and checks
the server as a whole; the hardening wizard reports services and open ports that do not belong to eFa-next or the operating
system. It never stops or removes them.

## 2. VM snapshot

Take a snapshot of the host in the hypervisor, for example named `before-efa-next`. Go on only when it is done.

## 3. Check the database

`efa-migrate` reads the old database with the root password in `/etc/eFa/MySQL-Config`. The command must show `1`:

```bash
MYSQL_PWD="$(sed -n 's/^MYSQLROOTPWD://p' /etc/eFa/MySQL-Config)" mysql --user=root -Ne 'select 1'
```

If it shows `ERROR 1045 (28000): Access denied`, the password of the database was changed later without the file. Two ways:

- put the valid password into the line `MYSQLROOTPWD:` of `/etc/eFa/MySQL-Config`, or
- add `--reset-db-root-password` in step 7. `efa-migrate` then sets MariaDB to the password in `MySQL-Config`: over the
  socket of root if MariaDB allows it, else in a short start without grant tables and network. The start options always go
  again, `/root/.my.cnf` follows (the old file stays next to it). The password never appears in a command line or a log.

While the check fails, `efa-migrate` stops at once with a clear message, also when it only lists.

## 4. Get the source of eFa-next

`efa-migrate` runs from the source of the release. It loads the packages itself from `https://repo.efa-next.eu/el9/latest`,
only with a valid signature of the eFa-next key (`1823 D6D3 BB7D 5AEA 286E 836D CFE7 E079 16CC 8046`).

```bash
cd /root
curl -fsSL https://github.com/MarkusLorber/eFa-next/archive/refs/tags/v6.0.0.5.2.tar.gz | tar xz
cd /root/eFa-next-6.0.0.5.2/migration
```

## 5. Dry run: what is carried over

The run without options changes nothing. It shows as JSON what would be carried over:

```bash
./efa-migrate | tee /root/efa-migrate-list.txt | tail -3
```

It ends with `Nothing was changed. Take a VM snapshot, then run again with --execute-i-have-a-snapshot.`
Look in `/root/efa-migrate-list.txt` at:

- `"milter_chain"`: the milter chain afterwards. The milters of eFa 5 (MailScanner, opendkim, opendmarc) are replaced, rspamd
  (11332) and the milters of eFa-next come in. **Third-party milters** that are not part of eFa 5 keep their place.
- `"extra_services"`: third-party services that eFa-next keeps running and includes in its status.
- `"foreign_blockers"`: cron entries and firewalld rules of other blockers. Their addresses go into the IP blocklists of
  eFa-next; the blockers themselves keep running. They are switched off only when you ask for it with
  `--disable-foreign-blockers` (with the migration, or later with the backup folder of the migration).
- `"senders"`, `"sender_rules"`: the sender lists of MailWatch. Entries of `/etc/postfix/sender_access` move into the sender
  lists of eFa-next when the migration runs.
- `"not_migrated"`: what is not carried over, for example the spam scores of SpamAssassin (rspamd has its own), the MailWatch
  users (there is one web admin afterwards), Bayes data and the old quarantine (kept in the backup).

## 6. Legal texts

```bash
./efa-migrate --legal-digest
```

Shows the legal texts of eFa-next (`LICENSE`, `DISCLAIMER.md`, `THIRD-PARTY-NOTICES.md`), their digest and the command line
of an unattended run. Read the texts. You accept them in step 7; nothing is accepted for you.

## 7. Migration

In the maintenance window, best inside `screen` or `tmux`:

```bash
./efa-migrate --execute-i-have-a-snapshot
```

`efa-migrate` asks for the legal texts; type `yes` (or `ja`). If step 3 showed `Access denied`:

```bash
./efa-migrate --execute-i-have-a-snapshot --reset-db-root-password
```

For an unattended run, name the digest of step 6 with `--accept-legal=` (`--legal-digest` shows the full line).

The output shows: `Backup to /root/efa-migration-<date>-<time>`, `Stopping mail intake, waiting for MailScanner`,
`Removing the old stack`, `Installing the new eFa-next`, `Configuring`, `Restoring settings`, the notes and at last
`The system reboots within a minute.`

- **Web admin password:** shown once, and also in `/root/efa-migration-<date>-<time>/web-admin-password` (readable by root
  only). Store it safely, then delete the file:

  ```bash
  rm /root/efa-migration-*/web-admin-password
  ```

- **Stopped before "Removing the old stack":** the old system is unchanged and accepts mail again. Fix the cause, repeat step 7.
- **Stopped after it:** note the message and go on with the backup folder the run named at its start:

  ```bash
  ls -d /root/efa-migration-*
  ./efa-migrate --resume /root/efa-migration-<date>-<time>
  ```

## 8. Checks after the reboot

```bash
efactl status | head -20
systemctl --failed --no-legend
ausearch -m avc -ts boot -if /var/log/audit/audit.log | grep -c denied
cat /etc/eFa-Version; rpm -q eFa-next eFa-next-base
postconf -n | grep -c /etc/postfix/sender_access
postconf -h smtpd_milters
postqueue -p | tail -1
less /root/efa-migration-*/report.txt
```

Expected:

- `efactl status`: `"status": "ok"`; under `checks` rspamd (`milter:11332`), Postfix, Redis, ClamAV and, if there are any,
  the third-party milters and services that were kept.
- No failed units, no SELinux denials (`0`).
- `eFa-6.0.0.5.2`, both packages at 6.0.0.5.2.
- `postconf -n | grep -c /etc/postfix/sender_access` shows `0`: Postfix no longer reads `sender_access`, its entries are in
  the sender lists.
- The queue as before the migration, or empty.
- `report.txt`: what was carried over, replaced or not carried over, lines of `sender_access` to add by hand, and own
  MailScanner rules that are not carried over.

## 9. Web interface and mail

- Log in as described in [9a](#9a-first-login-after-the-migration), and set up 2FA right away.
- The dashboard names allowed senders from the migration that passed every filter in eFa 5: check them and keep only exact
  addresses.
- Send a test mail from outside to an own address and one from inside to the outside; look at the mail log of eFa-next.
- Create the other admins, helpdesk and tenant admins again (the MailWatch users are not carried over), see
  [users-and-access.md](users-and-access.md).

## 9a. First login after the migration

1. Open `https://<host name>/login`, leave the **user name empty** and enter the web admin password (shown once at the end
   of the run, also in `web-admin-password` in the backup folder). This is the main admin of eFa-next.
2. **Set up 2FA right away:** *My account* (top right), section *Two-factor login (2FA)*: *2FA: set up the app* (scan the
   QR code with an authenticator app), then *2FA: switch on with the first code*. Until then the main admin logs in with the
   password alone, and the dashboard warns. Or on the console, as root:

   ```bash
   efactl totp-setup --qr
   efactl totp-confirm --code=123456
   efactl totp-status
   ```

   `totp-setup --qr` shows the QR code in the terminal; `--code` is the code the app shows then (here `123456` stands for
   it). The secret, the QR code and the ten recovery codes that `totp-confirm` shows are secret: never take a screenshot,
   never post or mail them; keep the recovery codes offline. A new web admin password on the console: `efactl
   admin-password` (asked twice); in the web interface: *My account*, *My account: password*.
3. **Every other admin gets an own user** with an own user name, password and own 2FA (*Users*), never the login of the main
   admin. The users of MailWatch are not carried over.

## 10. If something is wrong

- The only way back is the snapshot of step 2: reset the VM, the host is eFa 5 as before.
- The old configuration, the databases and the old quarantine are in `/root/efa-migration-<date>-<time>`.

## 11. Several hosts

Steps 2 to 9 for each host on its own, one after the other. Start the next host only when the one before accepts and
delivers mail again.
