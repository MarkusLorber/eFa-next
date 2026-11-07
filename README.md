<p align="center">
  <img src="assets/logo.svg" alt="eFa-next" title="eFa-next" width="400">
</p>

# eFa-next

eFa-next is a non-commercial email filter appliance for EL9 systems such as AlmaLinux 9. It continues the [eFa project](https://efa-project.org) with a modern stack and is not affiliated with it.

It sits in front of your mail server, filters incoming mail and hands the clean mail on.


**Intended use:** eFa-next is a mail filter server for qualified administrators in businesses and organisations and needs
technical knowledge of Linux, DNS, SMTP and TLS. It is not intended for consumers or private persons and is not released for
that use ([DISCLAIMER.md](DISCLAIMER.md)); the rights under the AGPL are not affected by this.

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

## Encryption

eFa-next uses only modern, secure encryption, following RFC 9325 (BCP 195) and BSI TR-02102-2:

- TLS 1.2 and 1.3 only: no SSL, no TLS 1.0 or 1.1.
- Forward secrecy (ECDHE) with AEAD ciphers only (AES-GCM, ChaCha20-Poly1305): no CBC, RC4, 3DES, RSA key exchange or SHA-1.
- For all services: SMTP in and out, submission, the web interface and the user portal, IMAP, the cluster and the APIs, also after
  an upgrade. The security self check tests each service live.

Status in 6.0.0.4: the web interface and the user portal keep to this today; Postfix, the cluster and the APIs get the
same limit with the TLS profiles of 6.0.0.4 ([TLS profiles](docs/tls-profiles.md)), which raise weaker settings on the upgrade too.

Data at rest: backups are encrypted with OpenPGP (AES-256) when a backup password is set; the journal of the cluster with Fernet
(AES-128-CBC with HMAC-SHA256; AES-256-GCM is planned); passwords of the web interface are stored as PBKDF2-HMAC-SHA256 with
600 000 rounds, logins of mail systems as SHA512-CRYPT. DKIM keys are RSA with at least 2048 bits, or Ed25519.

## Install

On a fresh EL9 system as root. The script loads eFa-next from the latest release of this repository and everything else from the public distribution, EPEL and rspamd repositories:

```bash
curl -fsSLO https://raw.githubusercontent.com/MarkusLorber/eFa-next/master/build/build.bash
```

```bash
bash build.bash
```

Then the setup wizard in a browser at `https://<host name or IP>/` with the setup code from `sudo cat /run/efa-init/setup-code`.
How to log in after the install (web, portal, console; root SSH is off), after an upgrade or a migration, and with a forgotten
password: [docs/install.md](docs/install.md#logging-in) and [docs/upgrade.md](docs/upgrade.md).

## Build

On an EL9 system with `rpm-build` and `checkpolicy`:

```bash
python3 build/build-rpms.py --next-dir next --out dist
```

The self-tests need no root and change nothing on the host:

```bash
python3 -B -m unittest discover -s tests
```

`src/` holds the base packaging and the setup programs, `next/` the eFa-next programs, laid out like the target file system.

## Migrate from eFa 5.0

See [migration/README.md](migration/README.md). Take a VM snapshot first, there is no automatic way back.

## Status

Early release, test it before you rely on it.

- Releases are signed with the eFa-next repository key `1823 D6D3 BB7D 5AEA 286E 836D CFE7 E079 16CC 8046` and come from `https://repo.efa-next.eu`, the GitHub releases are a mirror. Installer, `efa-migrate` and the update check take only releases with a valid signature ([docs/install.md](docs/install.md)).
- A fresh install, the upgrade from 6.0.0.2 and a full migration from eFa 5 ran on a clone of a production system, with SMTP to the outside blocked.
- Not tested: real mail flow from outside and to an internal mail server, Let's Encrypt, DKIM verified by external receivers, sending DMARC reports.

## Security and support

Report vulnerabilities as described in [SECURITY.md](SECURITY.md), never in a public issue. Help: [SUPPORT.md](SUPPORT.md).

## License

eFa-next is written by Markus Lorber and Lukasz Galusinski; IT-World ITW GmbH sponsors the project and holds no rights to the code ([AUTHORS.md](AUTHORS.md)).

eFa-next comes without any warranty. To the maximum extent permitted by applicable law, Markus Lorber, all authors and contributors of eFa-next and its sponsors, including IT-World ITW GmbH, are not liable for any damage from its use; you use it at your own risk. See [DISCLAIMER.md](DISCLAIMER.md).

Everything that comes from eFa-next is under the GNU Affero General Public License, version 3 or later
(AGPL-3.0-or-later, [LICENSE](LICENSE)). The programs eFa-next uses and does not change, such as Postfix, rspamd, ClamAV, MariaDB,
Redis, nginx, Unbound, the Python libraries and the packages of the operating system, keep their own licenses; the SBOM of each
release names every component with its version and license. [LICENSES.md](LICENSES.md) has the details.
