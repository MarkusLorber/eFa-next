# System

## Network & certificate

Host name, IPv4 and IPv6 (apply after a reboot), internal DNS zones, and a Let's Encrypt certificate.

![Network & certificate](images/net.png)

## Backup & restore

Backups hold the database and the private keys. Set a password for the automatic backups first: they are then encrypted, and the password is needed to restore them anywhere. *Back up now* makes one at once. *Download* asks for the admin password again.

![Backup & restore](images/bak.png)

On the console: `efactl backup-now`, `efactl backup-list`, `efactl restore --name <file> --confirm yes`.

## Maintenance & update

- **Update system**: first a backup and an export of the configuration, then the operating system and eFa. It starts only between minute 20 and 50 of an hour, and leaves out packages whose scripts reload or restart firewalld (it names them). *Only try it* installs nothing.
- **eFa updates**: notify, or install by itself in the maintenance window with a health check and a rollback if that fails.
- **Maintenance mode** stops the service monitor from restarting services.
- **Reboot** and **Halt** ask for a confirmation.

![Maintenance & update](images/maint.png)

Operating system updates cannot be rolled back automatically; take a VM snapshot before big updates.
