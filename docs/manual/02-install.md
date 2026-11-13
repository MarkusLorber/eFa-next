# 2. Requirements and install

## Requirements

- **Operating system:** a fresh, minimal AlmaLinux 9, Rocky Linux 9, CentOS Stream 9 or RHEL 9 (tested on AlmaLinux 9).
  AlmaLinux 10 is accepted but not tested yet; RHEL 10 and Rocky Linux 10 are refused until they are tested.
- **Network:** a fixed IP address, a host name in DNS with a matching PTR record, HTTPS access to the package repositories.
- **Size** (load test on 4 CPUs and 7.5 GB RAM: about 2,700 mails per minute through all filters):

  | Mail per day | CPUs | RAM | Disk |
  |---|---|---|---|
  | up to 50,000 | 2 | 4 GB | 40 GB |
  | up to 500,000 | 4 | 8 GB | 80 GB |
  | more | 8 or several nodes | 16 GB | 160 GB and more |

  Peaks matter more than the daily sum. The disk holds the mail log, the headers and the quarantine (30 days by default).
- **A dedicated server:** a server or VM of its own. Only eFa-next and the operating system run on it: no other server services,
  no other open ports. Monitoring or backup agents (such as Wazuh) are possible at your own risk. The hardening wizard reports
  foreign services and open ports; it never stops or removes them.
- An existing eFa 5 host is not installed over: see [Migration from eFa 5](16-migration.md).

## Install in one command

As root on the fresh host, load the installer and compare its SHA256 with the one in the release notes:

```bash
curl -fsSLO https://repo.efa-next.eu/build.bash && sha256sum build.bash
```

Then:

```bash
bash build.bash
```

The installer sets up the clock, checks DNS, adds the EPEL, CRB and rspamd repositories with their keys, updates the system
and installs `eFa-next` and `eFa-next-base` from the signed eFa-next repository. It runs as the systemd unit `efa-install`,
so a lost SSH connection does not stop it (`journalctl -fu efa-install` follows it again); each step logs to
`/var/log/eFa/eFa-install.log`. A second run does no harm.

Releases are taken only when their `SHA256SUMS` carry a valid signature of the eFa-next repository key:

```
1823 D6D3 BB7D 5AEA 286E  836D CFE7 E079 16CC 8046
```

Check it yourself with `curl -fsSL https://repo.efa-next.eu/RPM-GPG-KEY-efa-next | gpg --show-keys`.

Unattended install, test installs from a git branch and the repository file for updates by hand: [install.md](../install.md).

## The setup wizard

Open `https://<host name or IP>/` in a browser. The host has a self-signed placeholder certificate at first, so the browser
warns once. The wizard asks for the **setup code**, which only root can read:

```bash
sudo cat /run/efa-init/setup-code
```

A new code comes with each start of the wizard (`sudo systemctl restart efa-init`); after ten wrong codes it refuses all codes
until that restart.

The wizard starts in English (the link at the top switches to German) and goes through these steps, each with *Back*:

1. **Presets and recommendations:** a note to confirm with a tick.
2. **Setup variant:**
   - *Guided (recommended):* the EU link and the frameworks that apply (several at once) choose secure presets
     ([frameworks](../compliance/frameworks.md)). Two-factor login is required for the main admin and for the console admin,
     each with its own app entry: the wizard shows a QR code, checks the first code and shows ten recovery codes once (copy
     or PDF). *Next* only after "I have saved the codes".
   - *Manual:* you set everything yourself; the EU question is asked too.

   In both variants the same page asks for the **security standards** this server should meet (the list of chapter 9). The
   setup applies the strictest value of all chosen ones, never below the security minimum. Port 25 stays opportunistic, and the
   SSH profile after BSI TR-02102-4 is not set by the setup (it needs a new SSH login within 10 minutes): set it later in the
   hardening wizard. None chosen keeps the defaults of eFa-next.
3. **Root login through SSH:** off, with an SSH key only, or on. Off or key-only is recommended.
4. **EU link:** with an EU link the EU rules apply hard. Without one the wizard asks for a tick and the typed phrase
   `at my own risk`. Each confirmation is kept with time and a digest of the text shown.
5. **Host and network:** host name and domain, the address for notifications, the interface, static IPv4 or DHCP, IPv6,
   DNS (own recursion through the root servers, the default, or two DNS servers).
6. **Accounts:** the **web admin password** (twice, at least 12 characters), the **console user** (not root) and its password.
7. **Time:** hypervisor tools, time zone, time servers (the clock is set at once; 2FA codes need it).
8. **Your mail server:** IP or name of the server that receives the mail of your domain.
9. **Summary:** all answers by group, each with *Edit*, and the terms of use to confirm.

The host then sets itself up and reboots. When it gets a new address, the page shows it and opens it once it answers.

**Re-Setup** asks the same questions later for the running system: *Users & access › Security › Setup variant*, the address
`/resetup`, or `sudo efactl resetup`. It shows old and new values, makes a backup and only ever raises settings. Manual to
guided is free; guided to manual needs password and 2FA code, and 2FA stays on.

Next: [First login, 2FA and My account](03-first-login.md) · Back: [Manual](README.md)
