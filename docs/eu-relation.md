# EU relation and external services

Do the domains belong to persons or companies in the EU, or does the server run in the EU? Domain settings, EU relation:
one answer for all domains, and per domain where it differs. A new install starts with **yes**; after an update the dashboard
asks until it is answered, and until then eFa-next treats the domains as EU. Every answer is in the (strict) audit log.

With EU relation:

- no DMARC failure reports (`ruf`): they carry whole mails to a third party; the DMARC generator refuses them and the
  dashboard names saved records that still ask for them;
- backups only to providers in European hands (always the case since 6.0.0.5, docs/backup-eu.md);
- DMARC aggregate reports (`rua`) to a service that is not shown to be in the EU only after typing
  "I accept the transfer outside the EU"; the confirmation goes into the audit log, the strict audit log and out as the
  warning event `eu_transfer_confirmed`. Without EU relation the same confirmation is asked.

With the EU link of the setup wizard or Re-Setup (6.0.0.5, docs/install.md) the EU rules apply hard: the typed confirmation is
no longer accepted, the fields are greyed out with the reason, and "no" for all or a domain only comes through Re-Setup with the
typed confirmation of Text D. Without EU link from the setup, a new EU link (an answer yes, an own domain under an EU ending)
locks the EU settings again.

One check, `external_service()` in efactl, sorts the host of an external service into EU, outside the EU or unknown: known
report services and storage providers outside the EU (dmarcian, Valimail, Agari, EasyDMARC, MXToolbox, Red Sift, Proofpoint,
Mimecast, the big clouds ...) and known ones in the EU (URIports, DMARC Advisor, the EU storage providers). Unknown counts as
"not shown to be in the EU". The lists have the stand of 2026-11-08; they are hints, no legal advice.
