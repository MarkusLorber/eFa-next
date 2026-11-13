# Newsletter-friendly sending

A bulk mode for mass mail, so a large send does not look like a hijacked account and reaches the big providers. Off by
default. Set per sender address or sender domain, and used automatically on `Precedence: bulk` or a `List-Unsubscribe`
header.

## What it does

- Mail of a bulk sender goes out through a separate Postfix transport (`efabulk`), and only when all its recipients are outside
  the own domains.
- One pace for that transport, per destination domain: *gentle* (1 connection, 3 s between mails, 20 recipients each),
  *normal* (1, 1 s, 50) or *fast* (5, no pause, 100).
- Before sending, what the big providers ask of bulk senders is checked: a one-click unsubscribe (RFC 8058), a DKIM key here,
  SPF and DMARC in DNS. Missing parts are logged and named in the header `X-eFa-Bulk-Missing`, or the mail is held for an
  admin (`--missing hold`).
- Bulk mail does **not** count against the sending limits of the hijacked-account detection; its pace is its limit.

`bulk-set` turns it on and sets the senders, the pace and what happens when something is missing; `bulk-status` shows the
setting and, per sender domain, what the providers would miss.

## Not built yet

Planned for a later release: an own sender IP for bulk mail, a pace per provider (Gmail, Microsoft, Yahoo, GMX/Web.de,
T-Online) with templates and a warm-up for a new IP, statistics per campaign and sender, bounce handling (VERP) and feedback
loops.
