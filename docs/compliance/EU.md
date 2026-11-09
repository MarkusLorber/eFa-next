# EU conformity: GDPR, CRA, NIS2 (technical mapping)

A technical mapping of requirements to the functions of eFa-next 6.0.0.5 (S2). It is no legal advice and no certification:
the operator stays responsible for the use. Status: **met** (built and on by default for new installs), **partly** (built,
needs a setting or a step of the operator, or covers part of the requirement), **open** (planned).

## GDPR (EU 2016/679)

| Requirement | Implementation (file / function) | Status | Next step |
| --- | --- | --- | --- |
| Art. 5 (1) c data minimisation | No mail content in logs; subjects only for permitted roles (`mail.view_subject`); pseudonyms in the mail log after 14 days on new installs (D2, `pseudonymise-set`); headers stored only when switched on | met | |
| Art. 5 (1) e storage limitation | Days per kind of data and per tenant, nightly purge with audit entry (9h, `retention-set`, `maillog-purge`, `audit-purge`) | met | |
| Art. 15 right of access | `gdpr-export` per address (D1) | met | |
| Art. 17 right to erasure | `gdpr-delete` per address, audited with pseudonym and reason (D1) | partly | backups keep data up to 5 days, accounts and sender lists by hand |
| Art. 25 privacy by design and default | New features off after an update, private defaults on new installs (pseudonyms, quarantine encrypted, EU relation yes, no ruf) | met | |
| Art. 30 records of processing | Templates `docs/datenschutz/VVT.md`; a draft from the real settings: `privacy-evidence` (M3) | met | |
| Art. 32 security of processing | TLS profiles BSI TR-02102-2 (5t), held mail encrypted at rest per tenant (D3), signed backups (C2), encrypted backups, 2FA/passkeys (5r/5s, block 3), login lockout (B6), audit chain with signed anchors (B2) | partly | 5r/5s |
| Art. 33/34 breach notification | Audit log, strict audit chain, SIEM export (5d, E1); NIS2 report helper (O3) for the timeline | partly | the GDPR notice itself stays a text of the operator |
| Art. 44 ff. transfers to third countries | EU relation (EU): no ruf, report services outside the EU only after a typed confirmation; backups only to providers in European hands (5z) | met | |
| Art. 28 processors (MSP) | Template `docs/datenschutz/AVV.md`; tenants fully separated in rights (5q) | partly | review by a lawyer |

## Cyber Resilience Act (EU 2024/2847), Annex I

| Requirement | Implementation | Status | Next step |
| --- | --- | --- | --- |
| Secure by default | S1 audit, fail closed defaults (C7 scan failures, TLS limits, no plain SIEM) | met | |
| Protection against unauthorised access | Roles and scopes (5q), lockout (B6), allowlists (5p), 2FA (block 3) | partly | 5r/5s |
| Confidentiality and integrity of data | TLS everywhere, D3, C2, B2 | met | |
| Signed updates | Own GPG-signed repository (9k), fingerprint pin | met | |
| Vulnerability handling and contact (Art. 13) | `SECURITY.md`, `security-cra-report.efa-next.eu@it-status.org`, `docs/security.txt` | met | OpenPGP key |
| SBOM | CycloneDX 1.5 per release, SPDX expressions, checked against the official schema (SBOM-1) | met | |
| Security updates for the support period | `SECURITY.md` supported versions; update check (Q13); CVE watch (9o, block 4) | partly | 9o |

## NIS2 (EU 2022/2555), Art. 21

| Measure | Implementation | Status | Next step |
| --- | --- | --- | --- |
| Incident handling | Events to SIEM/OTLP/Wazuh, EVE export (E1); report helper for 24 h / 72 h / a month (O3) | met | |
| Logging and monitoring | Audit log, strict audit with HMAC chain and signed anchors (B2), Prometheus | met | |
| Access control, MFA | Roles, scopes, OIDC/LDAP; TOTP and passkeys (5r/5s) | partly | block 3 |
| Cryptography | TLS profiles (5t), DANE, MTA-STS checks, PQC hybrid with EL10 (6.0.0.6) | partly | EL10 |
| Backup and recovery | Encrypted, signed (C2), EU only (5z), restore checked | met | |
| Supply chain | SBOM, signed repository, dependencies from distribution repositories only | met | |

## ePrivacy and Austrian TKG 2021

Mail content is opened only where needed: content views need the right `mail.view_content` and, if set, a reason (5f), every
view is audited. Works councils: introducing mail filtering and logging can need an agreement under § 96 ArbVG (Austria) or
§ 87 BetrVG (Germany); the audit log and the role model are the technical basis for it.

## European Accessibility Act

Only a hint: the user portal, the login, the link warning pages and the Outlook task pane are checked against WCAG 2.1 AA by
own self-tests (P5: labels, names, language, headings, tab order, focus, contrast in light and dark). No external audit.

This document is part of the release checklist (`docs/RELEASE-CHECKLIST.md`): check the status column at every release.
