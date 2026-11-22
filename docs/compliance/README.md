# The compliance file of a release

Every release of eFa-next from 6.0.0.6.7 on comes with a compliance file: `eFa-next-<version>.compliance.json`, with the same
content as tables in `eFa-next-<version>.compliance.md` (English) and `eFa-next-<version>.compliance.de.md` (German). It lists,
for each standard, which technical requirements eFa-next covers, how far, and the evidence to check each claim.

**Not a legally binding statement.** The file is no certification, no confirmation of conformity by a third party and no legal
advice. Warranty and liability: [DISCLAIMER.md](../../DISCLAIMER.md) applies, to the maximum extent permitted by law. The
operator stays responsible for the conformity of their organisation. Anyone can have the information verified independently at
any time by auditors of their own choice, with the means below.

## Standards

GDPR, Cyber Resilience Act (Annex I), NIS2 (Art. 21), DORA, PCI DSS 4.0.1, HIPAA Security Rule, NIST SP 800-53 Rev. 5,
NIST CSF 2.0, SOC 2 Trust Services Criteria, ISO/IEC 27001:2022 Annex A, BSI TR-02102-1/-2/-4, TR-03108, TR-03116-4 and
IT-Grundschutz, the parts of the CIS AlmaLinux OS 9/10 benchmark that eFa-next checks, GPG13, RFC 9325, and the own criteria
of eFa-next for EU digital sovereignty (open source, self-hosted, no telemetry, EU-only backup targets, signed updates, SBOM).

## Status of a control

| Status | Meaning |
| --- | --- |
| covered | eFa-next does what the requirement asks for its part, with evidence. |
| partial | eFa-next does part of it, or only with a setting or a step of the operator; the limits say what is missing. |
| not covered | eFa-next does not do it (for example FIPS 140 mode, a login banner, a BAA template). |
| out of scope | A requirement of the organisation (policies, staff, physical security), not of a mail gateway. |

Each control also names who carries it (`efa-next`, `os` for AlmaLinux and its packages, `operator`, or `shared`), its scope,
its limits and its evidence.

## Evidence

Every claim of *covered* or *partial* names evidence beyond a document:

| Type | What it is | Checked |
| --- | --- | --- |
| `test` | a unit test, `module.Class.test` in `tests/` | passed in the full CI run of the release |
| `selftest` | the self-test of a program (`scripts/ci.sh`) | passed in the full CI run of the release |
| `hardening` | a check of the hardening report | on a host: `efactl compliance-verify` |
| `standard` | a security standard of `standards.json` | on a host: `efactl compliance-verify` |
| `command` | a read-only efactl command, optionally with a field and its expected value | on a host: `efactl compliance-verify` |
| `file` | a file of the source tree; below `next/` also installed | exists; on a host: installed |
| `wazuh-rule` | a rule of `efa-next_rules.xml` | exists; on a host: in the installed rule file |

## OSCAL export

`eFa-next-<version>.compliance.oscal.json` is the same content as an OSCAL 1.1.2 component-definition (NIST OSCAL): one
component eFa-next, one control-implementation per standard, one implemented-requirement per control with the props
`coverage`, `owner`, `label` and `evidence` (namespace `https://efa-next.eu/ns/oscal`), the OSCAL `implementation-status`
(covered: implemented, partial: partial, out of scope: not-applicable; not covered: none), the scope as description and the
limits as remarks. Control ids: the official ids of the NIST SP 800-53 Rev. 5 catalog (for example `ac-11`); every other
standard has ids of the eFa-next namespace (`efa-<standard>-<control>`), with the id of the standard in the prop `label`, and
as source the namespace, not an official catalog. The notice is in `metadata.remarks`. The export is checked against the
official schema `oscal_component_schema.json` of OSCAL v1.1.2, pinned in `third-party/oscal-1.1.2/SHA256SUMS`.

## How the file is made and checked

- The source is `next/usr/share/eFa/compliance/controls.json`. It ships in the package, so `efactl compliance-verify` checks
  the claims of exactly the installed release.
- `scripts/compliance_build.py --version <version>` writes the three files. It fails when a covered or partial control has no
  evidence besides a document, when a reference does not resolve, when a test it names did not pass in the CI log given with
  `--ci-log`, or when the JSON does not match `compliance/compliance.schema.json` (JSON Schema draft-07, python3-jsonschema).
  A hardening check that no control names is a warning.
- The CI step `compliance` (`scripts/ci.sh`) runs it after the unit tests and self-tests of the same run and keeps the files with
  the packages of a green run. `tests/test_compliance_file.py` checks the rules themselves; `scripts/legal_check.py` (L16)
  checks the notice in both languages at the top of both Markdown files.
- `scripts/compliance_diff.py <old>.compliance.json <new>.compliance.json` lists new, changed and removed controls for the
  changelog and the release notes.

## Verify it yourself

1. Download the files of the release with `SHA256SUMS` and `SHA256SUMS.asc`.
2. `gpg --verify SHA256SUMS.asc SHA256SUMS` with the release key (`RPM-GPG-KEY-efa-next`, fingerprint in the install guide).
3. `sha256sum -c --ignore-missing SHA256SUMS`.
4. On an installed host, as a super admin or auditor: `sudo efactl compliance-verify` (all standards) or
   `sudo efactl compliance-verify --standard pci-dss`. Read only. Per control: the claimed status and the result on this host:

| Result | Meaning |
| --- | --- |
| pass | every evidence that can be checked on this host holds |
| fail | at least one does not hold here: often a setting that is off (for example the idle timeout above 15 minutes) |
| not-applicable | only tests and self-tests, checked by the CI of the release |
| operator | out of scope, or the operator's task without a check here |

The web interface shows the same under *Privacy & Compliance*, *Compliance file*.

### The signed result of a host

*Privacy & Compliance*, *Compliance file*, **Download verification result** (super admins and auditors of the whole system;
a login limited to tenants or domains gets none) runs the check on the click and gives a zip, the same as
`sudo efactl compliance-verify --signed`. Every download is in the audit log. The zip holds `result.json` (host, eFa-next
version, time in UTC, `source_sha256` of the controls, per control the claimed status and the result here), `result.json.sig`
(Ed25519 over `result.json`, with the backup signing key of the host, or the hardware module when `backup-hsm-set` is on),
`signer.pub.pem` and a README. No secrets, no mail content. Check it:

    openssl pkeyutl -verify -pubin -inkey signer.pub.pem -rawin -in result.json -sigfile result.json.sig

Then compare the fingerprint in `result.json` (`signer.fingerprint`) with `sudo efactl backup-key-show` on that host, or on any
eFa-next host in one step: `sudo efactl compliance-verify-check --file result.zip --fingerprint "<fingerprint>"`.
`source_sha256` equals `source_sha256` of the compliance file of the release, so the result belongs to that release.

5. Read the source code (AGPL-3.0) and run the tests yourself: `python3 -m unittest discover -s tests -v`.
