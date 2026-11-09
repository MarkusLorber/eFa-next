# Signed backups

Every backup made by eFa-next 6.0.0.5 or newer carries `efa-manifest.json` (C2): the SHA-256 of each file in it, the host
name, the time and the public key, signed with the Ed25519 key of the host (`/etc/eFa/backup-sign.key`, root only). The
manifest is inside the archive, so it travels with every download and upload to an external target; an encrypted backup
encrypts it too.

## Restore

Before anything changes, the restore checks:

- the signature of the manifest;
- the signer: this host, or the host whose fingerprint you type under "Fingerprint of the host that signed it" (for a backup
  of another host, for example after moving to new hardware). `efactl backup-key-show` (Backup & restore) shows the
  fingerprint of a host;
- every file of the archive: it must be in the signed list with the same SHA-256. A file added or changed afterwards stops
  the restore.

A backup made by 6.0.0.4 or older, or a file of `efa5-export`, has no signature. It is restored only when you type `yes`
under "Restore an unsigned backup"; that is written to the audit log. The rollback of an update restores the backup the update
made itself and accepts it unsigned when the update started on 6.0.0.4.

The key stays on the host. Keep the fingerprint with your documentation: without the key of the old host a new host can still
restore its backups, with the fingerprint typed in. Losing the key means only that the old backups need the fingerprint (it is
also in the error message of the restore).
