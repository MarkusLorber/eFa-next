<p align="center">
  <img src="assets/logo.svg" alt="eFa-next" title="eFa-next" width="400">
</p>

# eFa-next

eFa-next is a non-commercial email filter appliance for EL9 systems such as AlmaLinux 9. It continues the [eFa project](https://efa-project.org) with a modern stack and is not affiliated with it.

It sits in front of your mail server, filters incoming mail and hands the clean mail on.

## What is different from eFa 5

| Task | eFa 5 | eFa-next |
| --- | --- | --- |
| Spam, SPF, DKIM, DMARC, greylisting | MailScanner, SpamAssassin, opendkim, opendmarc, sqlgrey | rspamd with Redis |
| Virus scan | ClamAV | ClamAV |
| Web server | Apache and PHP | nginx and waitress |
| Web interface | MailWatch | Python web interface |
| Mail log | MailWatch database | MariaDB, kept by age or size |
| DNS | Forwarding possible | Own resolver with unbound, no forwarding |

## Features

- Follows the DMARC policy each sender publishes and marks SPF, DKIM and DMARC failures in the header, optionally in the subject on hard failures
- DKIM keys with at least 2048 bits RSA and always ED25519
- The same functions in the `efactl` command line and in the web interface
- Sender lists and rules for addresses, domains, IP addresses and patterns
- Quarantine with release and delete
- Mail keeps flowing if a milter fails, and is marked with `X-Milter-Failed`; a local health service watches the services
- SELinux stays enforcing

## Install

On a fresh EL9 system as root. The script loads eFa-next from the latest release of this repository and everything else from the public distribution, EPEL and rspamd repositories:

```bash
curl -fsSLO https://raw.githubusercontent.com/MarkusLorber/eFa-next/master/build/build.bash
```

```bash
bash build.bash
```

## Migrate from eFa 5.0

See [migration/README.md](migration/README.md). Take a VM snapshot first, there is no automatic way back.

## Status

Early release, test it before you rely on it.

- The packages are not signed. `SHA256SUMS` only catches damaged downloads.
- The current `build.bash` and `efa-migrate` have not run end to end. A previous version of the migration ran on a clone of a production system.
- Not tested: real mail flow from outside and to an internal mail server, Let's Encrypt, DKIM verified by external receivers, sending DMARC reports.

## License

GNU General Public License v3, see [LICENSE](LICENSE). Based on the work of the eFa project and its contributors, whose copyright notices stay in the source files.
