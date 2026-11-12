# 12. Retention and privacy

## How long data is kept

*Mail & quarantine › Mail log › Storage & privacy* shows for each kind of data how long it is kept and where that is set.

| Data | Set with |
|---|---|
| Mail log and message search | `maillog-retention-set`, a size limit with `maillog-size-set` |
| Headers of all mail | `headers-store-set`, per tenant and domain under *Domain settings* |
| Quarantine and held mail | *Quarantine › Settings*, *Held mail › Settings*, per tenant and domain under *Domain settings* |
| Audit log, DMARC and TLS reports, originals of disarmed attachments, reported phishing mails | `retention-set` |

**Per tenant:** a tenant can keep its mail log, reports, audit log, the held mail of the admins, the originals of disarmed
attachments, reported phishing mails and the DKIM selectors seen shorter or longer than the global days. Tenant admins may set
shorter days only; longer ones need a super admin. `--days inherit` takes the global days again.

```bash
sudo efactl retention-set --data maillog --days 30 --tenant customer1
sudo efactl retention-set --data audit --days inherit --tenant customer1
```

A mail of several tenants goes when the longest of their days ends. The nightly jobs delete what is older and write how much
into the audit log. An upgrade changes no days.

## Privacy settings

On the same card:

- **Pseudonyms:** addresses in the mail log become pseudonyms after a number of days (`pseudonymise-set`).
- **A reason for content:** opening the content of a mail can require a typed reason, kept in the audit log
  (`content-reason-set`).
- **Subject display:** whether the mail log shows subjects (`subject-display-set`).

Details: [privacy-and-reason.md](../privacy-and-reason.md), [header-privacy.md](../header-privacy.md).

## GDPR requests

*Mail log › Data of one person (GDPR)*:

- **Export (Art. 15):** everything eFa-next holds about one mail address.
- **Erase (Art. 17):** deletes the data of one address for good; needs a reason (such as the date and number of the request)
  and a typed yes. The erasure itself is in the audit log.

```bash
sudo efactl gdpr-export --address person@example.com
sudo efactl gdpr-delete --address person@example.com --reason "request 2026-11-01 no. 12" --confirm yes
```

Templates for the records of processing, the technical measures and a data processing agreement (German):
[datenschutz/](../datenschutz/README.md). More: [gdpr-requests.md](../gdpr-requests.md).

Next: [Backup and restore](13-backup.md) · Back: [Manual](README.md)
