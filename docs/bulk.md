# Newsletter-friendly sending

A bulk mode for mass mail, so a large send does not look like a hijacked account and reaches the big providers. Off by
default. Set per sender address or sender domain, and used automatically on `Precedence: bulk` or a `List-Unsubscribe`
header.

## What it does

- Mail of a bulk sender goes out through Postfix transports of its own, and only when all its recipients are outside the own
  domains: one each for Google, Microsoft and Yahoo with their own pace, and `efabulk-other` for the rest (6.0.0.7).
- The pace of the rest, per destination domain: *gentle* (1 connection, 3 s between mails, 20 recipients each), *normal*
  (1, 1 s, 50) or *fast* (5, no pause, 100). Google: 2 connections, 1 s, 50; Microsoft: 1, 2 s, 20; Yahoo: 1, 2 s, 30.
- Before sending, what the big providers ask of bulk senders is checked: a one-click unsubscribe (RFC 8058), a DKIM key here,
  SPF and DMARC in DNS. Missing parts are logged and named in the header `X-eFa-Bulk-Missing`, or the mail is held for an
  admin (`--missing hold`).
- Bulk mail does **not** count against the sending limits of the hijacked-account detection; its pace is its limit.

`bulk-set` turns it on and sets the senders, the pace and what happens when something is missing; `bulk-status` shows the
setting and, per sender domain, what the providers would miss.

## Own address, warm-up, complaints, statistics (6.0.0.7)

- **Own address:** `bulk-set --address 198.51.100.20` sends all bulk mail from that address, with the name of its PTR record as
  HELO. The address has to be on this server, with a PTR record whose name points back to it (checked when set). If the
  address is gone later, the bulk mail waits; it never leaves from the main address. Put the address into the SPF record of
  the sender domains.
- **Warm-up:** `bulk-set --warmup on` lets a new address start slowly: 50 recipients a day per provider on the first day,
  doubled each day, no limit from day 15. Mail over the limit of the day is refused with a temporary error (4xx): the sending
  application tries again later.
- **Complaints:** `bulk-set --arf fbl@example.com` takes the complaints the providers send as ARF reports (RFC 5965) to that
  address of yours. Register it at the feedback loops of the providers (for example Microsoft JMRP/SNDS, Yahoo CFL; Gmail
  shows complaints only in Postmaster Tools). Each report is counted per day and sender domain, and its recipient gets no more
  bulk mail (only a hash is kept). No cloud interface of a provider is used. A report counts only when this server checked
  its DKIM or DMARC as passed for the domain of a known feedback loop (Microsoft, Yahoo, AOL, Comcast, Mail.ru, Yandex,
  Fastmail, GMX/Web.de, Zoho, Rackspace); anything else at that address is dropped, and a report that cannot be read is
  dropped too, never bounced. The statistics keep at most 500 sender domains.
- **Statistics:** `bulk-stats --days 7`: per provider how much was sent, deferred and bounced (from the delivery log), and the
  complaints per day and sender domain.

Not built: templates and statistics per campaign.
