# Privacy defaults & a reason for content

eFa-next is sparing with data from the start, and it can require a reason before anyone opens the content of a mail. Under Mail ›
Storage & privacy, and Security › the strict audit mode.

## Sparing defaults

- Short log retention, no mail content in the log, and an update check that reaches only EU hosts without personal data.
- An upgrade keeps your current values and notes the change on the dashboard.

## A reason to open content

- In the strict audit mode a reason (at least five characters) is required to open the content or the headers of a mail
  (`uq-content`, `quarantine-content`, `mail-show`, `quarantine-show`). The reason goes to the audit log.
- `content-reason-set` can require the reason on its own, without the full strict mode.

(Deletion periods per kind of data — 9h — move to 6.0.0.5.)

## Retention per kind of data and per tenant (9h)

Mail log, Storage & privacy, Retention shows how long each kind of data is kept and where that is set: mail log and message
search, headers, quarantine, audit log, DMARC and TLS reports, originals of disarmed attachments, reported phishing mails.
A tenant can keep its mail log and its reports shorter or longer than the global days
(`efactl retention-set --data maillog --days 30 --tenant <name>`, `--days inherit` for the global days again); its rows are
those with a sender or recipient of its domains. Quarantine and headers have their days per tenant and domain under Domain
settings. The nightly jobs (03:40 mail log, 03:45 audit log and reports) delete what is older and write how much into the audit
log. The defaults are the values before 6.0.0.5; an upgrade changes nothing.

## Pseudonyms in the mail log (D2)

After 7, 14, 30 or 90 days (Storage & privacy, Mail log: pseudonyms) the nightly job replaces the part before the @ of every
address in the mail log (sender, recipients, From, Reply-To, Return-Path) by a pseudonym `p<16 hex digits>@domain`, an HMAC
with a key for root only, and removes the subject. Counts and statistics per domain stay right. A search for one exact address
by a login that may read headers (the admins) still finds the old rows; everybody else sees only the pseudonyms. The key never
leaves the host, so nobody gets the addresses back from the pseudonyms alone. Stored headers have their own days: keep them as
short. A new install pseudonymises after 14 days; after an upgrade it is off until you set it.

## Tracking protection (M1)

`efactl tracking-set --mode on [--domain d | --tenant t]` (Spam & virus, Tracking protection) takes tracking out of incoming
mail. The content milter does it after the DKIM and ARC checks, before the link check, so wrapped links carry no tracking
either:

- **Tracking pixels:** pictures of 1x1 or 0x0 pixels, and pictures from known tracking hosts (a local list, plus own hosts
  with `tracking-list-set --kind host`).
- **Tracking parameters of links:** `utm_*`, `fbclid`, `gclid`, `msclkid`, `mc_eid`, `mc_cid`, `_hsenc`, `mkt_tok` and similar.
  The other parameters of a link stay.

Nothing is asked outside. Signed and encrypted mail stays as it is. Senders that must keep their links as they are go on the
exception list: `tracking-list-set --kind exception --action add --value newsletter@partner.example`.

The mail gets the header `X-eFa-CDR` with what was removed. Like the other changes of the content milter, the DKIM signature of
the sender no longer fits for the mail client afterwards; eFa-next checked it before. Off by default.

