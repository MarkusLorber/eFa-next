# Mail & quarantine

## Mail routing

Which domains eFa takes mail for and where it delivers it; who may send through eFa; size limit and recipient check.

- Add a domain: *Domains and their mail servers*, domain and mail server (`host` or `host:port`).
- Allow your own mail servers to send out: *Add networks*, then *Apply* in the list above.

![Mail routing](images/flow.png)

## Held mail

Mail eFa keeps for its recipients instead of rejecting it. Off by default (Settings, at the end of the page). Users get a daily digest with links, or log in with their address.

- *Release* delivers it, *Ask an admin* when the user may not release alone, *Allow sender* / *Block sender* add the sender to the user's lists.
- *Text* shows the mail as plain text: links are not clickable and nothing is loaded. Attachments are only listed.
- A virus only gets out through a super admin.

![Held mail](images/held.png)

A user sees only their own mail:

![Held mail of a user](images/user-held.png)

On a phone each mail is one block:

<img src="images/phone-held.png" alt="Held mail on a phone" width="300">

## Quarantine

Spam held back in the mail queue: deliver, headers, text, delete.

![Quarantine](images/quar.png)

## Mail log

Search all mail by sender, recipient, subject, result, date and the header fields From, Reply-To, Return-Path, X-Mailer. *Output: CSV file* downloads the result.

![Mail log](images/log.png)

*Live log* shows new mail as it comes, with filters. A click on a row shows its details.

![Live log](images/live-log.png)

### Details of a mail

Overview, the path over the servers with the time per hop, the authentication results, the DNS evidence (the records the checks used, with TTL and DNSSEC), and the raw headers. With the permission *export*: download the headers as `.txt` or the evidence as JSON.

![Details of a mail](images/mail-detail.png)

### Export headers

*Export headers* (under the search) writes a ZIP with one file per mail and `index.csv`, for the same filters. Above 5,000 mails it runs in the background; the link works when it is done, for 24 hours. On the console:

```bash
efactl headers-export --rcpt '*@example.com' --date_from 2026-11-01 --out /var/lib/eFa/exports/november.zip
```

Headers of all mail are stored for 30 days by default (*Storage & privacy* on this page, and per tenant or domain under Domain settings).
