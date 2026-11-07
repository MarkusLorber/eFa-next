# Install

**Intended use:** a mail filter server for qualified administrators in businesses and organisations, with technical knowledge
of Linux, DNS, SMTP and TLS. Not intended for consumers or private persons and not released for that use; see
[DISCLAIMER.md](../DISCLAIMER.md). The setup asks you to confirm this.

For a fresh host with AlmaLinux 9, Rocky Linux 9 or RHEL 9. For an existing eFa 5.0, see [Migrate from eFa 5](migration.md).

## Requirements

- A fixed IP address and a host name in DNS, with a matching PTR record.
- Access to the package repositories over HTTPS.
- Size, from the load test (`scripts/load_test.py`, Q11) on 4 CPUs and 7.5 GB RAM: about 2,700 mails per minute through Postfix
  and all filters (median 0.13 s, 95 % within 0.33 s), the filter alone about 3,600 per minute. ClamAV needs about 1.1 GB and
  rspamd about 0.8 GB of memory, the whole system about 3 GB at that load.

  | Mail per day | CPUs | RAM | Disk |
  |---|---|---|---|
  | up to 50,000 | 2 | 4 GB | 40 GB |
  | up to 500,000 | 4 | 8 GB | 80 GB |
  | more | 8 or several nodes | 16 GB | 160 GB and more |

  Peaks matter more than the daily sum: 500,000 mails a day are about 350 a minute on average, 5 to 10 times that at peak.
  The disk holds the mail log, the headers of all mail and the quarantine for 30 days by default; more days, more disk.

## Steps

1. As root, fetch and run the installer:

   ```bash
   curl -fsSLO https://raw.githubusercontent.com/MarkusLorber/eFa-next/master/build/build.bash
   bash build.bash
   ```

   It loads eFa-next from the latest release and everything else from the distribution, EPEL and rspamd repositories. Each step logs to `/var/log/eFa/eFa-install.log`; it stops at the first failed step.

   eFa-next comes from its own repository `https://repo.efa-next.eu`, or from the GitHub releases as a mirror. From either, the installer, `efa-migrate` and the update check take a release only when its `SHA256SUMS` carry a valid signature of the eFa-next repository key:

   ```
   1823 D6D3 BB7D 5AEA 286E  836D CFE7 E079 16CC 8046
   ```

   To check the key yourself: `curl -fsSL https://repo.efa-next.eu/RPM-GPG-KEY-efa-next | gpg --show-keys`.

2. Open the setup wizard in a browser: `https://<host name or IP>/`. On the first start the host has a self-signed placeholder
   certificate, so the browser warns once; a real certificate comes later (System, Network & certificate, Let's Encrypt).
   The wizard asks for the setup code, which only root on the host can read: `sudo cat /run/efa-init/setup-code`.

3. Answer the wizard: host name and domain, the address for important notifications, the network interface, a static IPv4
   address (address, prefix, gateway) or DHCP, IPv6, DNS (own recursion or two DNS servers), the **web admin password**
   (twice, at least 12 characters), the **console user** (not root) and its password (twice), hypervisor tools, time zone,
   and the mail server of your domain (IP or name; for a name it cannot resolve it asks for the internal DNS server).
   The last page shows all answers and asks you to confirm the terms of use. The host then sets itself up and reboots.

4. Log in, see [Logging in](#logging-in) below.

An eFa 5.0 host is refused: a fresh install stops when it finds `/etc/MailScanner/MailScanner.conf`.

## Logging in

| What | Where | Log in with |
|---|---|---|
| Admin web interface | `https://<host name>/login` | user name **empty**, the web admin password of the wizard |
| Further admins, helpdesk, tenant and domain admins | `https://<host name>/login` | their user name and password (made in Users & access, Users) |
| User portal (own quarantine) | `https://<host name>/portal/login` | the user name and password of the mailbox user |
| Console and SSH | the console, or `ssh <console user>@<host name>` | the console user of the wizard; then `sudo efactl menu` for the text menu |

Root login over SSH is off after the wizard (`/etc/ssh/sshd_config.d/00-efa-root.conf`: `PermitRootLogin no`): log in as the
console user and use `sudo`. Best with an SSH key (`ssh-copy-id <console user>@<host name>`). To allow root with an SSH key
only: `sudo efactl ssh-root-set --mode key-only --confirm yes` (`--mode on` for passwords too, `--mode off` back).

Five wrong logins from one address lock that address out of the web interface for five minutes. Some changes ask for your
password once more ("Your password, to confirm").

### Lost setup code

The code is made new at each start of the wizard: `sudo systemctl restart efa-init`, then `sudo cat /run/efa-init/setup-code`.
After ten wrong codes the wizard refuses all codes until that restart.

### Forgotten password or locked out

On the console, as the console user:

- Web admin: `sudo efactl admin-password` (asks for the new password twice).
- Another user: `sudo efactl user-set --username <name> --action set` (asks for the new password twice).
- A locked user: `sudo efactl user-state --username <name> --mode on`.
- A locked-out address: the lock ends after five minutes.

After an upgrade or a migration from eFa 5: [Upgrade](upgrade.md).

## Unattended

`bash build.bash kickstart` takes the answers from `/root/eFa-kickstart.conf` (`KEY:value` lines) and applies them at the next boot.

Next: [First steps](first-steps.md).
