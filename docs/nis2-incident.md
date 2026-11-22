# Incident reports: NIS2, GDPR, DORA

Under Users, NIS2 incidents (O3). For a significant incident NIS2 Art. 23 asks for an early warning within 24 hours, a
notification within 72 hours and a final report within a month, to the CSIRT or the authority (in Austria GovCERT or CERT.at,
depending on the sector). eFa-next prepares the text; it sends nothing itself.

1. `efactl incident-open --title "Mailbox taken over" --detected "2026-11-08 10:15" --malicious yes --cross_border unknown
   --impact "..." --summary "..."` opens a record (`/etc/eFa/incidents`, root only) and shows the three deadlines.
2. `efactl incident-report --id 20261108-101500 --stage early|notification|final [--format pdf]` builds the report: the
   answers, the fields the stage asks for, facts of this server (version, open findings of the security self check) and the
   timeline from 24 hours before the detection until now: audit entries and events of warning and above.
3. Check and complete it, then send it the way your CSIRT asks for.

The same record also gives:

- `--stage gdpr`: the notification of a personal data breach to the supervisory authority (GDPR Art. 33, within 72 hours of
  becoming aware), with the fields Art. 33(3) asks for: personal data concerned (`--personal_data` at opening), categories and
  approximate number of people and records (`--subjects`), the data protection officer, likely consequences, measures.
- `--stage dora-initial | dora-intermediate | dora-final`: the reports of a major ICT incident to the competent authority (DORA
  Art. 19: initial within 4 hours of the classification as major and at the latest 24 hours after becoming aware, intermediate
  within 72 hours, final within a month), with the classification criteria of Art. 18 to assess.

eFa-next never sends a report to an authority by itself. The template of the process around it: docs/compliance/incident-response.md.

Opening a record and every report are in the audit log (opening also in the strict audit log).
