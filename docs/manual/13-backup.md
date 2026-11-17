# 13. Backup and restore

*System › Backup & restore*.

![Backup & restore](../images/manual/bak.png)

## What a backup holds

The database (mail log, users, groups, settings), the settings in `/etc/eFa`, the private keys (DKIM, ARC, TLS, 2FA, held
mail), the Postfix, rspamd, Unbound, fail2ban, ClamAV and SSH settings eFa-next writes. Held mail and the Redis/Valkey data
are kept as data; a restore does not write them back.

Every backup carries a manifest with the SHA-256 of each file, signed with the Ed25519 key of the host. A restore checks the
signature and every file before anything changes ([backup-signature.md](../backup-signature.md)).

## Set it up

1. **Backup password:** *Password for automatic backups* (at least 12 characters). From then on the backups are encrypted
   (AES-256). Keep the password outside this host: without it no backup can be restored anywhere.
2. **Automatic backup:** on or off. Updates and the release upgrade make their own backup first in any case.
3. **Back up now** makes one at once; *Download* asks for your password again.
4. **External targets** (optional): S3 or SFTP, meant for providers in European hands. Only encrypted files leave the host,
   after each backup, with a checksum per file and an alarm on a failure. *Test* checks the target
   ([backup-targets.md](../backup-targets.md)).

```bash
sudo efactl backup-password-set --mode set
sudo efactl backup-now
sudo efactl backup-list
sudo efactl backup-target-list
```

## Restore

*Restore* on a row of the list (or a file on this server, or an uploaded backup):

- an encrypted backup needs its password;
- a backup of another host (for example after moving to new hardware) needs the fingerprint of the host that signed it,
  shown on the old host by *Backups: fingerprint of the signing key* (`efactl backup-key-show`);
- a backup without signature (6.0.0.4 or older, or from `efa5-export`) is restored only with a typed yes, noted in the audit
  log.

```bash
sudo efactl restore --name <file> --confirm yes
```

A restore that was cut off (power cut) is detected and does not block later updates. A backup that holds the settings of
Postfix and nginx is restored only by the main admin (or root on the console).

## Settings from another host

To take only some settings over, not the whole backup: *Settings: export parts for another host* on the old host,
*Settings: take over parts from another host* on the new one (System › Backup & restore, super admin only, password and 2FA
again). Both hosts run the same version of eFa-next.

- **Parts:** `spam` (action scores, symbol scores, greylisting and its exceptions, graymail, BEC), `attachments`
  (attachment rules), `lists` (allow and block lists of senders), `disclaimer` (disclaimers and templates), `reports`
  (reports by mail, daily mail). Domains, tenants and users live in the database: for them use a backup or the migration.
- **Never in the file:** host name, keys, certificates, database passwords, users and 2FA, the cluster role.
- The file is signed with the backup key of the old host and encrypted with a password (at least 12 characters). The new
  host reads it only with that password and the fingerprint of the old host (`efactl backup-key-show` there).
- First a **preview** lists each value that would change (old and new); only `--confirm yes` takes them over. Shared files
  change only in the keys and lines of the chosen part. Postfix and rspamd check the result; if one refuses, everything
  goes back as it was. The change is in the audit log and the configuration history (`history-undo` takes it back).
- Not on a cluster member: there the settings come from the master.

```bash
sudo efactl settings-export --parts spam,lists                     # on the old host; asks for the password twice
sudo efactl settings-import --file /var/tmp/efa-settings-....tar.gz.gpg --parts spam --signer "<fingerprint>" --preview yes
sudo efactl settings-import --file /var/tmp/efa-settings-....tar.gz.gpg --parts spam --signer "<fingerprint>" --confirm yes
```

## Cloning a VM

A copy of a virtual machine keeps the secrets of its origin (SSH host keys, machine id, session and signing keys). Run on the
console of the copy, as root, before it takes mail:

```bash
sudo efactl clone-reset --confirm yes --hostname mx2.example.com
```

It refuses on a member of a cluster. What it renews and what it keeps: [system.md](../system.md#cloning-a-host).

Next: [Updates and release upgrade](14-updates.md) · Back: [Manual](README.md)
