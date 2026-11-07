# Security policy

**DRAFT. The contact address and the times below are placeholders until 6.0.0.6.**

## Report a vulnerability

Please do not open a public issue for a security problem.

- Contact: **to be announced with 6.0.0.6** (a dedicated address with an OpenPGP key).
  Until then, send a private message to the maintainers of the repository you got eFa-next from.
- Tell us: the version (`efactl status`), what you did, what happened, and what an attacker gains.
  A proof of concept helps; please do not use real mail of other people.
- Do not test against systems that are not yours.

## What happens then

| Step | Within (placeholder) |
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

- Fixes come as a normal release of the `eFa` and `eFa-base` packages. `efactl update-check` and the dashboard show it, marked as a
  security update (Q13). The security self check reports a missing security update after 7 days.
- Updates of the operating system and of third-party packages (Postfix, rspamd, ClamAV, MariaDB, nginx) come from their own
  repositories through the system updates of eFa-next.
- An update never changes your settings; new functions are off after an upgrade.

## Supported versions

| Version | Security fixes |
|---------|----------------|
| 6.0.0.x, latest release | yes |
| 6.0.0.x, older releases | no: update to the latest release |
| eFa 5 and older (the original eFa project) | no: not part of eFa-next, see `docs/migration.md` |

## Scope

In scope: the code in this repository and the packages built from it, their default configuration, and the way they configure
third-party software.

Out of scope: vulnerabilities in third-party software itself (report them to that project, we update as soon as they ship a
fix), systems changed by hand outside `efactl`, and findings that need root on the appliance already.
