# Migrating from eFa 5.0 (MailScanner) to eFa-next 6.0.0.3

`efa-migrate` converts an existing eFa 5.0 in place. It replaces MailScanner, MailWatch, SpamAssassin, opendkim, opendmarc, sqlgrey and amavis with rspamd, nginx and the Python web interface. Apache, PHP and Perl stay installed on the host. Apache is only stopped, and PHP-FPM is masked because nginx would start it again. If another application on the host needs PHP, run `systemctl unmask php-fpm`.

**There is no automatic way back.** The only way back is a VM snapshot.

## Requirements

- VM snapshot taken right before the run
- Maintenance window: the system accepts no mail during the run and reboots at the end
- Logged in as root, Python 3 and access to the repos over HTTPS
- `/etc/eFa/MySQL-Config` contains the valid MariaDB root password, otherwise the script aborts while reading, without changing anything
- The script downloads the RPMs from the latest release of https://github.com/MarkusLorber/eFa-next, or you pass a folder with `--rpm-dir`
- On clones: block SMTP first, otherwise the clone delivers mail from its queue to real recipients

## Steps

1. Check what would be carried over. This changes nothing:

   ```bash
   ./efa-migrate
   ```

2. Migrate:

   ```bash
   ./efa-migrate --execute-i-have-a-snapshot
   ```

3. Store the web admin password. It is shown once at the end of the run if the script runs in a terminal, and never goes to a log. It is also in `web-admin-password` in the backup folder, readable only by root. Delete that file once you have stored the password. The system reboots within one minute.

4. Check:

   ```bash
   efactl status
   ```

   Then read `report.txt` in the backup folder and send a test mail.

5. Log in for the first time and set up 2FA right away, see [First login after the migration](#first-login-after-the-migration).

If the installation aborts after the old system was removed, continue like this:

```bash
./efa-migrate --resume /root/efa-migration-TIMESTAMP
```

## First login after the migration

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

   On the console: the console admin over SSH (the sudo user of the setup, or any other admin with sudo) has its own 2FA,
   separate from the main admin. Each admin sets up their own, logged in as themselves:

   ```bash
   sudo efactl console-2fa-enroll                 # the key and the otpauth link for the app
   sudo efactl console-2fa-enroll --code 123456   # the first code; shows the ten recovery codes once
   ```

   Lost phone: a recovery code, or on the local console `efactl user-2fa-reset --username @admin`. More in
   [docs/two-factor.md](../docs/two-factor.md).
3. **Every other admin gets an own user** with an own user name, password and own 2FA (*Users*), never the login of the main
   admin. The users of MailWatch are not carried over.

## What is carried over

- Hostname and IP from the running system, not from `eFa-Config`
- All Postfix settings and files, for example restrictions, postscreen, rate limits, TLS levels, recipient maps including LDAP, and the queue. Only the following is replaced or dropped, and the report names each item: the milter chain, settings and `master.cf` lines that belong to the removed filters, HOLD rules for MailScanner, and `non_smtpd_milters` whose service no longer exists
- Relay networks, smarthost, message size, recipient verification
- Greylisting, Fail2Ban, quarantine (on if `Spam Actions` of the old system contains `store`) and retention period
- MailWatch lists: addresses and domains go to the lists, IPs, patterns and per-recipient entries go to the sender rules
- DKIM keys with their selector; weak keys only produce a warning
- Third-party milters keep their position in the chain, their services are monitored
- Mail log from MailWatch

## What changes

- **DNS:** The system resolves on its own, without public forwarding. Only the zone of the internal mail server stays on the internal DNS server. Other internal zones must be added with `efactl dns-zone-set`.
- **Block entries reject** instead of only marking as spam. Private IPs, relay networks and authenticated users are exempt.
- **Allow entries only lower the score**, DMARC and virus scanning still apply.
- **Mail is rejected from score 15.** Copies of normal mail are no longer stored.
- **Dovecot serves no IMAP or POP3.** It only provides the SASL login for port 587.

## What is not carried over

- Spam thresholds: rspamd scores differently from SpamAssassin
- MailWatch users: there is only one web admin now, the main admin with an empty user name; see
  [First login after the migration](#first-login-after-the-migration)
- 2FA: there was none in eFa 5, so none is set up after the migration
- Trusted networks, Bayes data, sqlgrey history
- Custom rules under `/etc/MailScanner/conf.d`: they are named in the report and kept in the backup
- Mail from the old quarantine: it is kept in the backup but cannot be released
- Let's Encrypt: a valid certificate of the host is taken over as it is (same key, a TLSA record stays right); if it is not valid, run `efactl letsencrypt-set` afterwards

## Backup

The script puts everything in `/root/efa-migration-TIMESTAMP`: configuration, a dump of all databases, mail log, queue, old quarantine and the old daily backups from `/var/eFa/backup`. The folder contains passwords and keys and is readable only by root. Delete it only once the system runs reliably.

## Moving to a fresh host instead: efa5-export

`efa5-export` reads the settings of the eFa 5.0 host and writes them as an encrypted eFa-next backup. Nothing on the old host changes. It needs only Python 3 and gpg, and `efa5_convert.py` in the same folder (in the source tree it is in `next/usr/lib/eFa/python`). `efa-migrate` uses the same conversion.

1. See what would be taken over, adjusted and not taken over. This writes nothing:

   ```bash
   ./efa5-export --preview
   ```

2. Write the file. The password is asked twice and must have at least 12 characters:

   ```bash
   ./efa5-export --output /root
   ```

3. On the fresh eFa-next host, upload the file under Backup, then restore it with the same password. The restore first makes a backup of the new host. Then it applies the settings once and shows the same three lists, plus every step that failed. The report stays in `/etc/eFa/efa5-import/report.txt`.

A fresh host keeps its own host name, address, time zone and certificate, and the Postfix settings it sets itself. The mail log, quarantine and queue stay on the old host. Third-party milters must be installed on the new host first. Nothing goes back to the old host.

## Test status

The migration with the 6.0.0.3 packages ran on a clone of a real system restored from a snapshot, and the local checks passed. The first run stopped at a bug that is fixed now, and `--resume` finished it, so a run in one go is not tested with the final packages.

The first install of the packages runs the firewall step and adds `ssh`, `smtp`, `smtp-submission`, `http` and `https`. On hosts with other jobs that change firewalld, run the migration at a time when those jobs do not run.

The mailscanner SELinux module stays, it could not be removed and does nothing without MailScanner. DKIM keys were not tested, because the clone has none. Real mail flow from outside and to the internal mail server is not tested, nor is Let's Encrypt.
