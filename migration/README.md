# Migrating from eFa 5.0 (MailScanner) to eFa-next 6.0.0.0

`efa-migrate` converts an existing eFa 5.0 in place. It replaces MailScanner, MailWatch, SpamAssassin, opendkim, opendmarc, sqlgrey and amavis with rspamd, nginx and the Python web interface. Apache, PHP and Perl stay installed on the host, Apache is only stopped.

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

3. Write down the web admin password. It is shown only at the end of the run. The system then reboots within one minute.

4. Check:

   ```bash
   efactl status
   ```

   Then read `report.txt` in the backup folder and send a test mail.

If the installation aborts after the old system was removed, continue like this:

```bash
./efa-migrate --resume /root/efa-migration-TIMESTAMP
```

## What is carried over

- Hostname and IP from the running system, not from `eFa-Config`
- Postfix tables, relay networks, smarthost, message size, recipient verification, queue
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

## What is not carried over

- Spam thresholds: rspamd scores differently from SpamAssassin
- MailWatch users: there is only one web admin now
- Trusted networks, Bayes data, sqlgrey history
- Custom rules under `/etc/MailScanner/conf.d`: they are named in the report and kept in the backup
- Mail from the old quarantine: it is kept in the backup but cannot be released
- Let's Encrypt for nginx: run `efactl letsencrypt-set` afterwards

## Backup

The script puts everything in `/root/efa-migration-TIMESTAMP`: configuration, a dump of all databases, mail log, queue and old quarantine. The folder contains passwords and keys and is readable only by root. Delete it only once the system runs reliably.

## Test status

A complete run on a clone of a real system took place, but it had to be continued with `--resume` and hit a file permission error. Both are fixed, but the current version of the script has not yet run as a whole. Real mail flow from outside and to the internal mail server is not tested, nor is Let's Encrypt.
