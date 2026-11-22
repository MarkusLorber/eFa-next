# Business Associate Agreement (HIPAA): template

**Template, not checked by a lawyer. Adapt it with your own legal counsel before use.** Not a legally binding statement of the
eFa-next project; see [DISCLAIMER.md](../../DISCLAIMER.md). The eFa-next project processes no data of yours: this template is for an
organisation (for example an MSP) that runs eFa-next for a HIPAA covered entity and so handles ePHI in the mail flow.

Placeholders are in square brackets: `[Covered Entity]`.

## Parties

This Business Associate Agreement ("Agreement") is made between `[Covered Entity]` ("Covered Entity") and `[Business Associate]`
("Business Associate"), effective `[date]`.

## 1. Definitions

Terms used in this Agreement have the meaning given in 45 CFR Parts 160 and 164 (the HIPAA Rules).

## 2. Permitted uses and disclosures

Business Associate may use or disclose Protected Health Information (PHI) only to operate the mail security gateway eFa-next
for Covered Entity (receiving, filtering, quarantining and delivering e-mail, and the logs and backups this needs), as described
in `[service description]`, or as required by law.

## 3. Safeguards (45 CFR 164.308, 164.310, 164.312, 164.316)

Business Associate uses appropriate safeguards. The technical safeguards of the gateway are listed in the output of
`efactl privacy-evidence` (Privacy & Compliance, Privacy evidence) and checked with `efactl compliance-verify --standard hipaa`
on the host; attach both, dated, as Annex 1. Administrative and physical safeguards: `[describe]`.

## 4. Reporting

Business Associate reports to Covered Entity any use or disclosure not provided for by this Agreement, and any Security Incident
and Breach of Unsecured PHI, without unreasonable delay and in no case later than `[number]` days after discovery
(45 CFR 164.410). eFa-next's audit log, events and the incident report helper support the timeline.

## 5. Subcontractors

Business Associate ensures that subcontractors that create, receive, maintain or transmit PHI on its behalf agree to the same
restrictions (45 CFR 164.502(e)(1)(ii)). Backup targets and other services used: `[list]`.

## 6. Access, amendment, accounting

Business Associate makes PHI available for access, amendment and an accounting of disclosures as required by 45 CFR 164.524,
164.526 and 164.528, within `[number]` days of a request (`efactl gdpr-export` finds the data of one address).

## 7. Term and termination

On termination Business Associate returns or destroys all PHI (retention settings, `efactl gdpr-delete`, backups expiring after
`[days]`), or, if not feasible, extends the protections of this Agreement to it.

## 8. Signatures

`[Covered Entity]`, name, title, date: `[...]`

`[Business Associate]`, name, title, date: `[...]`
