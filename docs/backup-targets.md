# External backup targets

Upload the encrypted backups to a second place off the host. Under System › Backup & restore. Off by default.

## What leaves the host

- Only the gpg AES-256 **encrypted** backup files, never anything in the clear. A backup password is required for an external
  target.
- Over **S3** (own code) or **SFTP** (the system ssh/sftp). Credentials are stored for root only and never appear in a log.
- It runs **after** each backup, with a bandwidth limit, as a one-off job — not a steady service.
- Retention per target, a checksum per file, and an alarm on a failure.

## EU note

External targets are meant for providers in European hands. When a domain or the operation has an EU relation, a non-EU
endpoint is refused; see the compliance notes. Compare the SFTP host key shown with the key of your server before the first
backup goes there.

`backup-target-set`, `backup-target-list`, `backup-target-test`.
