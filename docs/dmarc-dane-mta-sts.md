# DMARC reports, DANE & MTA-STS

Transport security and the DMARC aggregate reports for your domains. Under Domains & tenants and System.

## DMARC aggregate reports (RUA)

- A mailbox reads the RUA reports other servers send (zip or gzip, XML). Entities and DOCTYPE are refused; a report never
  needs them.
- Shown per domain and per sending source, with a hint for sources that fail alignment and for senders you may have missed.
- `dmarc-report-show` for the stored reports; retention follows the deletion periods.

## DANE (outbound)

- `dane-set` turns on `smtp_tls_security_level = dane` for outgoing mail, with DNSSEC over the local Unbound.
- A TLSA generator builds the record for your own mail server from its certificate; you publish it, eFa-next checks it matches.
- `tlsa-show` shows the records and whether they fit the certificate now.

## TLS reports and the key of the certificate (P8)

- TLS reports (RFC 8460) received at the report address are evaluated per domain, policy and reporter (TLS reports received).
  When at least 10 sessions and 1 % of all sessions to an own domain failed within 7 days, the dashboard says so.
- The certificate of Let's Encrypt keeps its key at each renewal (`--reuse-key`), so a published TLSA `3 1 1` record of the MX
  stays right. For a new key, `efactl letsencrypt-rollover --step prepare` makes a second certificate with a new key and shows
  its record; publish it next to the old one, wait at least the TTL (a day is safe), then `--step switch` uses the new
  certificate only if DNS shows the new record. Remove the old record a day later. Certificates of 6.0.0.4 and older made a
  new key at each renewal: `--step keep` makes their renewals keep it.

## MTA-STS (9p)

eFa-next writes the MTA-STS policy of each domain and checks it. It does not serve the policy itself: put the file on your own
web server.

- **The policy.** `mta-sts-set` sets it per domain: mode testing, enforce or none; the mx lines from the real MX of the domain
  (or the names you give); `max_age` 604800 (a week) unless set. The id changes only when the policy changes.
- **Copy or download.** Protection, MTA-STS shows the policy text, the address it must have, and the DNS records.
  `mta-sts-text --domain example.com` gives the file `mta-sts.txt` to download.
- **On your web server.** Serve the file at `https://mta-sts.example.com/.well-known/mta-sts.txt`: as `text/plain`, with a valid
  certificate for `mta-sts.example.com`, without a redirect.
- **In DNS.** Publish `_mta-sts.example.com. IN TXT "v=STSv1; id=<id>"`, and the TLS-RPT record when reports are on. No CNAME
  to this server is needed.

**The check.** It runs once a day, and on demand with `mta-sts-check`; never while a page loads. For each domain it fetches
only the public address of the policy: HTTPS with a full certificate check, at most 5 s and 64 KB. It parses the policy and
compares it with the one written here. It reads the MX and the TXT record through the own resolver.

The dashboard warns when:
- the policy is not reachable, or its certificate fails or has expired;
- the policy served differs from the one written here;
- an MX is missing from a policy in enforce;
- this server is an MX but not in the policy;
- the TXT record is missing or has another id.

**Update from 6.0.0.4.** The nginx server of the policies (`/etc/nginx/conf.d/efa-mta-sts.conf`, `/var/www/efa-mta-sts`) is
removed. The policies stay, and for 30 days the dashboard reminds you to put them on your own web server. Do it before the
`max_age` that senders cached runs out; until then they keep the last policy they fetched. If `mta-sts.<domain>` pointed to this
server, point it to your web server.

## DKIM selectors seen (6c)

efa-maillog reads the DKIM-Signature headers of every mail, in and out, with the result rspamd gave per domain, and keeps one
row per domain, selector, algorithm and direction: first and last time, passes and failures, and counters per day (DKIM, ARC &
DMARC, DKIM selectors seen; `efactl dkim-selectors [--domain d] [--format csv|json]`). Only metadata, no addresses or content.
Once a day the length of up to 200 published RSA keys is read through the own resolver. Warnings: a new selector of an own
domain that eFa-next does not sign with (someone else signs for it), keys under 2048 bits or SHA-1, and many failures of a
selector on the day before. The days per day follow the retention of reports (9h). On by default (it changes no mail).
This is an own development, independent of any other DKIM collector.

