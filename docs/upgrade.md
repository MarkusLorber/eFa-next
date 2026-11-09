# Upgrade

An upgrade (for example 6.0.0.3 to 6.0.0.4) comes from the eFa-next repository: by the automatic update in its maintenance
window, on the page System, Maintenance & update, or on the console with `sudo dnf --enablerepo=efa-next upgrade eFa-next eFa-next-base`
(the repository file first, see below).

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

A fresh host is still set up with `build.bash` ([Install](install.md)): it also adds the other repositories eFa-next needs (EPEL, rspamd).

**Hosts on 6.0.0.4** must take 6.0.0.5 once by hand, with
`sudo dnf --enablerepo=efa-next upgrade eFa-next eFa-next-base`: their own update looks only for packages named `eFa` and
`eFa-base` and does not install the renamed ones. The command replaces them with `eFa-next` and `eFa-next-base` as an
upgrade: the settings stay. After that the update display and the automatic update work again. (6.0.0.4.1 is a tag on
not published as packages.)

## What stays

- Every login stays as it was: the web admin password, the other users with their groups, API tokens, the console user and
  the SSH settings. An upgrade changes no setting; it only adds what is new.
- New features of the release are off until you switch them on (for example the attachment checks of 6.0.0.4 that look at
  file names and at programs by their content).

## The first login after the upgrade

Log in as before (see [Logging in](install.md#logging-in)). Then:

1. **Terms of use and legal texts**: when they changed with the release, the web interface first shows them and asks you to
   confirm them once. Nothing else opens before that.
2. **Dashboard, "Needs attention"**: notes of the upgrade, each with a link to its page. With 6.0.0.4 for example:
   - "TLS was raised to the profile BSI TR-02102-2 by the update": old TLS versions and weak ciphers are off. Nothing to do,
     unless an old server must still send to you (Security, TLS profile).
   - "Terms of use not yet confirmed for these active blocklists": confirm the terms on the page Blocklists, or switch the
     list off.
3. The new options of the release are on their pages; [CHANGELOG.md](../CHANGELOG.md) lists them.

Five wrong logins from one address lock that address out for five minutes. Forgotten password:
[Forgotten password or locked out](install.md#forgotten-password-or-locked-out).

## After a migration from eFa 5

- **Web admin**: `efa-migrate` makes a new web admin password. It shows it once at the end and writes it to the file
  `web-admin-password` in its backup folder (root only). Store it, then delete that file. Log in at `https://<host name>/login`
  with an empty user name and this password.
- **MailWatch users are not carried over**: eFa-next has one web admin plus its own users. Make the users again on the page
  Users & access, Users, or with `sudo efactl user-set --username <name> --action set --role <role>`.
- **System accounts and SSH** stay as they were on the eFa 5 host: the migration does not run the setup wizard, so it makes no
  console user and does not change the root login.

More: [Migrate from eFa 5](migration.md).
