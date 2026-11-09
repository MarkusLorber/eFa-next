# Frameworks of the guided setup

The guided setup and Re-Setup (Security, Setup variant) ask which frameworks apply to the organisation. The choice only drives
suggestions: each framework raises a few settings of eFa-next, never lowers one. It is no legal advice and no certification:
choosing a framework does not mean the system complies with it (Text A of the setup). Every row below is shown as a
**non-binding suggestion**. The table is the one of `efa_setup.FRAMEWORKS`; Hans checks it, changes go there and here.

## What a framework raises

| Setting | What eFa-next sets | Where |
| --- | --- | --- |
| 2FA for all admins | `totp-policy-set` to required for super, tenant, domain, manager, helpdesk, readonly and auditor | Users, 2FA |
| Audit log 1 year / 5 years | `retention-set --data audit` to at least 365 / 1825 days (default 400) | Mail log, Storage & privacy |
| TLS profile | BSI TR-02102-2 when the profile is not one of those the framework accepts (a custom list counts as not accepted) | Security, TLS profile |
| Security self check every day | `security-check-set --mode on` (more often than the weekly hardening report asked for) | Security, Security self check |

Guided itself, with or without frameworks: 2FA for the main admin and the console admin (SSH) is a must.

## The frameworks

| Framework | Raises | Note (non-binding) |
| --- | --- | --- |
| GDPR | nothing more: the EU link sets the EU rules (always selected with an EU link) | |
| NIS2 (Directive (EU) 2022/2555), NISG 2026 (AT), NIS2UmsuCG/BSIG (DE), KRITIS (DE) | 2FA for all admins, audit log 1 year, TLS BSI or Mozilla modern | NIS2 incidents: Users, NIS2 incidents (O3) |
| DORA (Regulation (EU) 2022/2554) | as NIS2, audit log 5 years | admin access only from allowed addresses (Security, Admin access) |
| BSI IT-Grundschutz, BSI TR-02102 | TLS BSI TR-02102-2 | SSH after TR-02102-4: hardening report, `ssh-profile-set --mode bsi` |
| ISO/IEC 27001, ISO/IEC 27701, TISAX | 2FA for all admins, security self check every day | record of processing and TOM: Users, Privacy evidence (M3) |
| BAO/UGB (AT), HGB/AO/GoBD (DE) | nothing | eFa-next is not an archive that meets the legal retention rules; retention periods not below the legal ones |
| PCI DSS, HIPAA (US), SOC 2, NIST CSF | 2FA for all admins, audit log 1 year, TLS BSI, RFC 9325 or Mozilla modern | |
| TKG 2021 (AT), TDDDG (DE), ENISA eHealth, revDSG (CH), UK GDPR | nothing | no own setting in eFa-next; the EU question and the security minimum apply |
| Other (free text) | nothing | kept as a note |

A framework with no setting of its own shows only its note: eFa-next does not pretend a protection it does not have.

## Raise only

Re-Setup compares the system with what the chosen frameworks ask for and lists only what is lower, for example
`audit_days 90 -> 365` or `tls_profile custom -> bsi`. A stricter value stays (an audit log of 3000 days, TLS 1.3 only).
Taking a framework away later changes nothing back. Every raise is in the audit log with its old and new value.
