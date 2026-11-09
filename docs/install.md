# Install

**Intended use:** a mail filter server for qualified administrators in businesses and organisations, with technical knowledge
of Linux, DNS, SMTP and TLS. Not intended for consumers or private persons and not released for that use; see
[DISCLAIMER.md](../DISCLAIMER.md). The setup asks you to confirm this.

For a fresh host with version 9 (EL9) of AlmaLinux, Rocky Linux, CentOS Stream or RHEL; tested on AlmaLinux 9. For an existing eFa 5.0, see [Migrate from eFa 5](migration.md).

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

1. As root on a fresh EL9 host (a minimal install is enough), load the installer and compare its
   SHA256 with the one in the release notes:

   ```bash
   curl -fsSLO https://repo.efa-next.eu/build.bash && sha256sum build.bash
   ```

   Then one command does the whole install:

   ```bash
   bash build.bash
   ```

   It installs the tools it needs itself (curl, gnupg2, dnf-plugins-core, the SELinux tools, chrony), sets the clock, checks
   DNS, sets up the EPEL, CRB and rspamd repositories with their keys, enables the nginx 1.26 module stream, updates the
   system, loads eFa-next from the latest release and installs it. It runs as the systemd unit `efa-install`, so a lost SSH
   connection does not stop it; `journalctl -fu efa-install` follows it again. Each step logs to `/var/log/eFa/eFa-install.log`;
   it stops at the first failed step with what failed. A second run does no harm. The same `build.bash` is attached to each
   release on GitHub.

   **A test installation from the source**, for example a branch before its release, also in one command from a clone:

   ```bash
   REPO=<git address of eFa-next> BRANCH=<branch>; dnf -y install git-core && { [ -d /root/efa-next-src ] || git clone -b "$BRANCH" "$REPO" /root/efa-next-src; } && git -C /root/efa-next-src pull --ff-only && bash /root/efa-next-src/build/build.bash source
   ```

   Set `REPO` to the address of your clone (for example your own Forgejo or GitLab) and `BRANCH` to the branch to test; the
   same line run again updates the clone and installs the newest commit. A minimal install has no git: the command installs it
   from the repositories of the distribution first. Everything else the
   installer needs (curl, gnupg2, dnf-plugins-core, the SELinux tools, chrony) it installs itself in its first step and names
   what was missing.

   On top of the above it installs the build tools (git-core, rpm-build, the BuildRequires of both specs through `dnf builddep`),
   builds the two packages from that clone and installs them, then removes the build tools again (it keeps no Perl
   of them); a second run takes the newest commit of the branch and installs
   it again. These packages carry no signature: only for tests.

   eFa-next comes from its own repository `https://repo.efa-next.eu`, or from the GitHub releases as a mirror. From either, the installer, `efa-migrate` and the update check take a release only when its `SHA256SUMS` carry a valid signature of the eFa-next repository key:

   ```
   1823 D6D3 BB7D 5AEA 286E  836D CFE7 E079 16CC 8046
   ```

   To check the key yourself: `curl -fsSL https://repo.efa-next.eu/RPM-GPG-KEY-efa-next | gpg --show-keys`.

2. Open the setup wizard in a browser: `https://<host name or IP>/`. On the first start the host has a self-signed placeholder
   certificate, so the browser warns once; a real certificate comes later (System, Network & certificate, Let's Encrypt).
   The wizard asks for the setup code, which only root on the host can read: `sudo cat /run/efa-init/setup-code`.

3. The wizard starts in English; the link at the top switches to German. First it shows a note on presets and recommendations
   (Text A, to confirm with a tick), then asks for the **setup variant**:

   - **Guided (recommended):** eFa-next asks for the EU link and the frameworks that apply (chips, several at once) and
     suggests matching, secure presets (docs/compliance/frameworks.md). Two-factor login is a must for the main admin and the
     console admin, each with an own app entry: before the setup runs, the wizard shows a QR code for each, checks the first
     code and shows ten recovery codes once, to copy or download as PDF; "Next" only after "I have saved the codes". The console
     admin logs in by SSH with its own code ([Two-factor login](two-factor.md)).
   - **Manual:** you set everything yourself. The EU question comes here too, without frameworks and suggestions.

   With an EU link the EU rules apply hard (only services in the EU, no typed exception). Without one the wizard asks for a tick
   and the typed phrase `at my own risk` (German: `auf eigenes Risiko`). Each confirmation is kept with the time and the
   digest (SHA-256, 16 hex digits) of the text as it was shown, in the audit log too; a changed text asks again. The
   security minimum (TLS 1.2 or newer, ECDHE, AEAD) applies in both variants and cannot be lowered.

   Then: host name and domain, the address for important notifications, the network interface, a static IPv4
   address (address, prefix, gateway) or DHCP, IPv6, DNS (own recursion or two DNS servers), the **web admin password**
   (twice, at least 12 characters), the **console user** (not root) and its password (twice), hypervisor tools, time zone,
   the **time servers** (NTP; Next sets the clock, the 2FA codes need it), and the mail server of your domain (IP or name;
   for a name it cannot resolve it asks for the internal DNS server). Every step has Back, the values in effect are filled in,
   and the language can be switched on every page.
   The last page shows all answers by group, each with Edit, and asks you to confirm the terms of use. The host then sets itself
   up and reboots; when it gets a new address, the page shows it and opens it as soon as it answers (the browser warns once
   about the certificate at the new address).

4. Log in, see [Logging in](#logging-in) below.

Later, and after an update or a migration from eFa 5 (the dashboard offers it once), **Re-Setup** asks the same questions for
the running system: Security, Setup variant, `/resetup` in the web interface, or `sudo efactl resetup` on the console. It shows
old and new, makes a backup, then raises the settings of the chosen frameworks and never lowers one. Manual to guided is free;
guided to manual needs the password and the 2FA code again, and 2FA stays on.

An eFa 5.0 host is refused: a fresh install stops when it finds `/etc/MailScanner/MailScanner.conf`.

## Installation and updates from the signed repository

eFa-next has its own signed package repository: https://repo.efa-next.eu/el9. The packages, their checksums and the
repository index are signed with the eFa-next key. The packages are `eFa-next` and `eFa-next-base` from 6.0.0.5 on, `eFa` and
`eFa-base` up to 6.0.0.4. Key:

    1823 D6D3 BB7D 5AEA 286E  836D CFE7 E079 16CC 8046

Import the key only if this fingerprint matches. To check it yourself:
`curl -fsSL https://repo.efa-next.eu/RPM-GPG-KEY-efa-next | gpg --show-keys`.

Set up the repository once, then update by hand:

```bash
sudo curl -fsSL -o /etc/yum.repos.d/efa-next.repo https://repo.efa-next.eu/el9/efa-next.repo
sudo dnf --enablerepo=efa-next upgrade eFa-next eFa-next-base
```

The command also replaces the packages `eFa` and `eFa-base` of 6.0.0.4 and older.

dnf asks once to import the key; compare the fingerprint above before you say yes.

If the repository file cannot be downloaded, write `/etc/yum.repos.d/efa-next.repo` by hand:

```ini
[efa-next]
name=eFa-next EL9
baseurl=https://repo.efa-next.eu/el9/
enabled=0
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://repo.efa-next.eu/RPM-GPG-KEY-efa-next
```

The repository is off by default (`enabled=0`): a normal OS update (`dnf upgrade`, dnf-automatic) does not change eFa-next.
eFa-next updates itself through its own update check (System, Maintenance & update), which makes a backup first and keeps to
the maintenance window; `--enablerepo=efa-next` is for an update by hand.

A fresh host is still set up with `build.bash` (above): it also adds the other repositories eFa-next needs (EPEL, rspamd).

**Hosts on 6.0.0.4** must take 6.0.0.5 once by hand, with
`sudo dnf --enablerepo=efa-next upgrade eFa-next eFa-next-base`: their own update looks only for packages named `eFa` and
`eFa-base` and does not install the renamed ones. The command replaces them with `eFa-next` and `eFa-next-base` as an
upgrade: the settings stay. After that the update display and the automatic update work again. (6.0.0.4.1 was not published
as packages.)

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
