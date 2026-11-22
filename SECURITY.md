# Security policy

## Report a vulnerability

Please do not open a public issue for a security problem.

- Contact: **security-cra-report.efa-next.eu@it-status.org**. This is also the contact for vulnerabilities after Art. 13 of
  the Cyber Resilience Act (EU 2024/2847). The same address is in `/.well-known/security.txt` of efa-next.eu
  (`docs/security.txt`, RFC 9116). Reports are taken as plain mail, protected by TLS in transit; there is no OpenPGP key.
  Leave secrets such as passwords out of the report; we agree on a way for anything sensitive with you.
- Tell us: the version (`efactl status`), what you did, what happened, and what an attacker gains.
  A proof of concept helps; please do not use real mail of other people.
- Do not test against systems that are not yours.

## What happens then

These are guideline values of a private open source project, not binding commitments.

| Step | Usually within |
|------|----------------------|
| We confirm that we got your report | 3 working days |
| First assessment and severity (CVSS 3.1) | 10 working days |
| Fix for critical and high issues | 30 days |
| Fix for medium and low issues | with the next release |

We keep you informed and agree on a date for publication with you.

## Coordinated disclosure

- We publish an advisory together with the fixed release. Default: at most 90 days after your report, earlier once the fix is out.
- If an issue is exploited in the wild, we publish as soon as a fix or a workaround exists.
- We name you in the advisory unless you prefer not to be named.

## CVE

We request a CVE for every vulnerability that affects a released version, through the security advisories of the code hosting
platform or through MITRE. The advisory names the CVE, the affected and the fixed versions, and a workaround if there is one.

## Security updates

- Fixes come as a normal release of the `eFa-next` and `eFa-next-base` packages. `efactl update-check` and the dashboard show it, marked as a
  security update (Q13). The security self check reports a missing security update after 7 days.
- Updates of the operating system and of third-party packages (Postfix, rspamd, ClamAV, MariaDB, nginx) come from their own
  repositories through the system updates of eFa-next.
- An update never changes your settings; new functions are off after an upgrade.

## Signed releases, SBOM and compliance file

These help operators check what they install and support the duties of the Cyber Resilience Act; they are no certification.

- Every release is signed with the eFa-next key `1823 D6D3 BB7D 5AEA 286E 836D CFE7 E079 16CC 8046`: the packages, the
  repository index of https://repo.efa-next.eu, the release checksums (`SHA256SUMS`, signed as `SHA256SUMS.asc`) and the release
  tag. The installer, `efa-migrate` and the update check take only releases with a valid signature.
- Every release ships a software bill of materials (SBOM, CycloneDX JSON) for EL9 and EL10, listed in the signed `SHA256SUMS`.
- From 6.0.0.6.7 on, every release ships its compliance file (`eFa-next-<version>.compliance.json`, `.md`, `.de.md` and the
  OSCAL export `.compliance.oscal.json`), listed in the signed `SHA256SUMS`. It says which controls of a standard a release
  covers, covers in part or does not cover, each with its evidence. It is no legally binding statement and no certification.
- Published advisories are also available as a signed feed: `https://repo.efa-next.eu/advisories/advisories.json`.

## Supported versions

| Version | Security fixes |
|---------|----------------|
| 6.0.0.x, latest release | yes |
| 6.0.0.x, older releases | no: update to the latest release |
| eFa 5 and older (the original eFa project) | no: not part of eFa-next, see `docs/migration.md` |

By operating system:

| Platform | Support |
|----------|---------|
| EL10: AlmaLinux 10 | full support |
| EL9: AlmaLinux 9, Rocky Linux 9, RHEL 9 | support and security updates until 2027-05-31 |

From 2027-06-01 an EL9 host gets no more updates of eFa-next. Only the move to version 10 stays: the release upgrade
(`docs/release-upgrade.md`) or a migration. The dates of the operating system itself are its own (AlmaLinux 9: security updates
until 2032-05-31); they are not a promise of eFa-next. The dashboard of an EL9 host warns from 2026-12-01 (yellow) and is red
from 2027-06-01.

## Scope

In scope: the code in this repository and the packages built from it, their default configuration, and the way they configure
third-party software.

Out of scope: vulnerabilities in third-party software itself (report them to that project, we update as soon as they ship a
fix), systems changed by hand outside `efactl`, and findings that need root on the appliance already.

## No warranty

This policy describes how the project handles reports; it is not a contract and no guarantee of a response or a fix. eFa-next
comes without any warranty ([DISCLAIMER.md](DISCLAIMER.md), sections 15 and 16 of the [license](LICENSE)). The operator remains
responsible for the operation and the updates of their installation.

## Kurzfassung (Deutsch)

Schwachstellen bitte nie in einem öffentlichen Issue melden, sondern per Mail an
**security-cra-report.efa-next.eu@it-status.org** (auch Kontakt nach Art. 13 des Cyber Resilience Act, siehe
`/.well-known/security.txt` von efa-next.eu). Jedes Release ist mit dem eFa-next-Schlüssel signiert und enthält eine SBOM, ab
6.0.0.6.7 auch die Compliance-Datei. Die Zeiten oben sind Richtwerte eines privaten Open-Source-Projekts, keine verbindlichen
Zusagen; eFa-next wird ohne Gewährleistung bereitgestellt ([DISCLAIMER.md](DISCLAIMER.md)).
