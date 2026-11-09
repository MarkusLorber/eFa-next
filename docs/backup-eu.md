# Backup targets only in the EU

External backup targets (Backup & restore) take only providers in European hands (5z):

| Provider | Address of the target | Country |
| --- | --- | --- |
| Hetzner Object Storage, Storage Box | `*.your-objectstorage.com`, `*.your-storagebox.de` | Germany, Finland |
| Scaleway | `*.scw.cloud` | France |
| IONOS | `*.ionoscloud.com` | Germany |
| STACKIT | `*.onstackit.cloud` | Germany |
| Own server (SFTP, or own S3 such as Garage or MinIO) | any, after typing yes: it stands in the EU and its operator is in European hands | EU |

Stand 2026-11-08, from the providers' own pages; Exoscale is left out until its ownership is clear. The address of a target
has to belong to the chosen provider. Known providers outside the EU (AWS, Google, Azure, Cloudflare R2, Backblaze, Wasabi,
DigitalOcean, Oracle, IBM, Alibaba, Linode, Vultr, IDrive, Storj, Dropbox) are refused by the host name and by every CNAME it
points to, also behind an own name. A target needs a backup password first: only encrypted backups (gpg AES-256) leave the host.

After the update to 6.0.0.5, targets at a provider outside the EU are locked: they get no backups, the dashboard and a mail to
the admin say so. Remove them and add a target in the EU.
