# Job applications per domain (8j)

For domains with EU relation (docs/eu-relation.md): job applications contain special personal data (CVs, certificates) and
should reach only the addresses meant for them. Domain settings, Job applications.

- Per domain or subdomain (a subdomain without own setting follows its domain): **allowed to all addresses** (the default; the
  dashboard asks until you confirm it with `application-set --mode open`) or **only to the allowed addresses**
  (`efactl application-set --domain example.com --mode list --allowed "jobs@example.com hr@example.com"`).
- A mail counts as application with two signals: words of German or English applications in the subject, in the text, or in
  the name of an attachment (Lebenslauf, Bewerbung, Zeugnis, CV, resume, ...). Sent to an address not on the list, the whole
  mail is refused at the end of DATA with `550` and this text (or an own one per domain, without any address):
  "Ihre Nachricht wurde aus Datenschutzgründen nicht angenommen. Bitte erfragen Sie beim Empfänger den korrekten Weg bzw. die
  korrekte Adresse für Bewerbungen." and the English one. Nothing is stored, no redirect, no quarantine; the sending server
  tells its user.
- Senders such as recruiters are exceptions (`application-exception-set --action add --sender agency.example`).
- The log has only time, sender domain, rule and action (the symbol `EFA_APPLICATION`); every change is in the audit log.
