# DMARC reports, DANE & MTA-STS

Transport security and the DMARC aggregate reports for your domains. Under Domains & tenants and System.

## DMARC aggregate reports (RUA)

- A mailbox reads the RUA reports other servers send (zip or gzip, XML). Entities and DOCTYPE are refused; a report never
  needs them.
- Shown per domain and per sending source, with a hint for sources that fail alignment and for senders you may have missed.
- `dmarc-report-show` for the stored reports; retention follows the deletion periods.

## DANE (outbound)

- `dane-set` turns on `smtp_tls_security_level = dane` for outgoing mail, with DNSSEC over the local Unbound.
- A TLSA generator builds the record for your own mail server from its certificate; you publish it, eFa checks it matches.
- `tlsa-show` shows the records and whether they fit the certificate now.

## MTA-STS

- eFa builds the `mta-sts.txt` policy per domain (testing, enforce or none; the mx list from your real MX; a `max_age`) and
  serves it itself through nginx at `https://mta-sts.example.com/.well-known/mta-sts.txt`; you point the `mta-sts` host name
  at this server and publish the `_mta-sts` TXT record with its id.
- `mta-sts-show` shows the policy and the records, `mta-sts-set` turns it on per domain.

(In 6.0.0.5, item 9p, eFa stops serving the policy and only generates it for your own web server and checks it; until then the
policy is served here.)
