<p align="center">
  <img src="assets/logo.svg" alt="eFa-next" title="eFa-next" width="400">
</p>

# eFa-next

eFa-next is an open-source email filter appliance for RHEL-compatible systems such as AlmaLinux, Rocky Linux, CentOS Stream and
RHEL, built with data privacy and sovereignty first. It continues the idea of the [eFa project](https://efa-project.org) as a free open source project on a modern stack and
is not affiliated with it (but inspired).

It is built as an autonomous security fortress, designed with sovereignty, compliance and especially EU regulations in mind.

It sits in front of your mail server, filters incoming and/or outgoing mail and hands the clean, sealed, signed mail on.

**Intended use:** eFa-next is a mail filter server for qualified administrators in businesses and organisations and needs
technical knowledge of Linux, DNS, SMTP and TLS. It is not intended for consumers or private persons and is not released for
that use ([DISCLAIMER.md](DISCLAIMER.md)); the rights under the AGPL are not affected by this.

## Requirements

- Version 9 or 10 (EL9/EL10) of AlmaLinux, Rocky Linux, CentOS Stream or RHEL, freshly installed (minimal is enough). Tested on
  AlmaLinux 9 and 10. There will be an upgrade switch from EL9 to EL10 with public release of version 6.0.0.6.
- A fixed IP address and a host name in DNS with a matching PTR record; access to the package repositories over HTTPS.
- From 2 CPUs and 4 GB RAM for up to 50,000 mails a day; sizes for more in [docs/install.md](docs/install.md).

## Install

As root on the fresh host: load the installer, compare its SHA256 with the
[release notes](https://github.com/MarkusLorber/eFa-next/releases), then run it. It installs its own tools, sets the clock,
adds EPEL, CRB and rspamd with checked keys and installs the packages `eFa-next` and `eFa-next-base` from the signed repository
https://repo.efa-next.eu:

```bash
curl -fsSLO https://repo.efa-next.eu/build.bash && sha256sum build.bash
```

```bash
bash build.bash
```

Then open the setup wizard in a browser at `https://<host name or IP>/` with the setup code from
`sudo cat /run/efa-init/setup-code`. Details, the wizard and updates: [docs/install.md](docs/install.md).

Releases, the repository index and `SHA256SUMS` are signed with the eFa-next repository key
`1823 D6D3 BB7D 5AEA 286E 836D CFE7 E079 16CC 8046`. https://repo.efa-next.eu is the source; the
[GitHub releases](https://github.com/MarkusLorber/eFa-next/releases) are a mirror. The installer, `efa-migrate` and the update
check take only releases with a valid signature.

## Migrate from eFa 5.0

See [docs/migration.md](docs/migration.md). Take a VM snapshot first: there is no automatic way back and there is no guarantee of no data loss.

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

The complete list, grouped, each with a link to its page: [docs/FEATURES.md](docs/FEATURES.md) (Deutsch:
[docs/FEATURES.de.md](docs/FEATURES.de.md)).

| Area | In short |
| --- | --- |
| Mail filter and detection | rspamd with Redis, ClamAV with Sanesecurity, blocklists, Bayes, fuzzy, threat feeds, outbreak filter |
| Phishing and impersonation | BEC and lookalike checks, link check on click, QR codes, phishing reports, warning banner |
| Attachments and sandbox | type filter, content disarm, macros, encrypted archives, CAPEv2 sandbox, own hash and YARA blocks |
| Quarantine and portal | quarantine, user portal with digest, mail log search, queue, spooling, emergency access, recall |
| Encryption | TLS 1.2/1.3 only, TLS profiles, DANE, MTA-STS, S/MIME and PGP, DKIM RSA and Ed25519 |
| Login and roles | 2FA per user, passkeys, OIDC, LDAP/AD, roles, tenants, four eyes, REST API |
| Privacy and EU | EU relation, GDPR requests, pseudonyms, header privacy, tracking protection, NIS2 reports |
| Operation | cluster, signed and encrypted backups, offline updates, monitoring, SIEM and EVE export, Wazuh |
| Install and setup | one command, setup wizard (guided or manual), English and German |
| Security of the system | SELinux enforcing, security minimum guard, CVE watch, hardening report, signed audit anchor |

## Encryption

eFa-next uses only modern encryption, following RFC 9325 (BCP 195) and BSI TR-02102-2:

- TLS 1.2 and 1.3 only: no SSL, no TLS 1.0 or 1.1.
- Forward secrecy (ECDHE) with AEAD ciphers only (AES-GCM, ChaCha20-Poly1305): no CBC, RC4, 3DES, RSA key exchange or SHA-1.
- For all services: SMTP in and out, submission, the web interface and the user portal, IMAP, the cluster and the APIs. The
  [TLS profiles](docs/tls-profiles.md) raise weaker settings on an upgrade too, and the security self check tests each service live.

Data at rest: backups are encrypted with OpenPGP (AES-256) when a backup password is set; the journal of the cluster with Fernet
(AES-128-CBC with HMAC-SHA256; AES-256-GCM is planned); passwords of the web interface are stored as PBKDF2-HMAC-SHA256 with
600 000 rounds, logins of mail systems as SHA512-CRYPT. DKIM keys are RSA with at least 2048 bits, or Ed25519.

## Status

Early release: test it before you rely on it. Known limits: [docs/STATUS-6.0.0.5.md](docs/STATUS-6.0.0.5.md). Changes per
release: [CHANGELOG.md](CHANGELOG.md).

## Build from source

On an EL9 system with `rpm-build` and `checkpolicy`:

```bash
python3 build/build-rpms.py --next-dir next --out dist
```

The self-tests need no root and change nothing on the host:

```bash
python3 -B -m unittest discover -s tests
```

`src/` holds the base packaging and the setup programs, `next/` the eFa-next programs, laid out like the target file system.

## Security and support

Report vulnerabilities as described in [SECURITY.md](SECURITY.md), never in a public issue. Help: [SUPPORT.md](SUPPORT.md).

## License

eFa-next is written by Markus Lorber and Lukasz Galusinski; IT-World ITW GmbH sponsors the project and holds no rights to the code ([AUTHORS.md](AUTHORS.md)).

eFa-next comes without any warranty. To the maximum extent permitted by applicable law, Markus Lorber, all authors and contributors of eFa-next and its sponsors, including IT-World ITW GmbH, are not liable for any damage from its use; you use it at your own risk. See [DISCLAIMER.md](DISCLAIMER.md).

Everything that comes from eFa-next is under the GNU Affero General Public License, version 3 or later
(AGPL-3.0-or-later, [LICENSE](LICENSE)). The programs eFa-next uses and does not change, such as Postfix, rspamd, ClamAV, MariaDB,
Redis, nginx, Unbound, the Python libraries and the packages of the operating system, keep their own licenses; the SBOM of each
release names every component with its version and license. [LICENSES.md](LICENSES.md) has the details.
