# Newsletter-friendly sending

A bulk mode for mass mail, so a large send does not look like a hijacked account and reaches the big providers. Off by
default. Set per sender, domain or submitter, and used automatically on `Precedence: bulk` or a `List-Unsubscribe` header.

## What it does

- A separate Postfix transport for mass mail, optionally with its own sender IP.
- Throttling per destination provider (for example Gmail, Microsoft, Yahoo, GMX/Web.de, T-Online) by how many connections
  run at once, pauses, and recipients per connection, with a warm-up for a new IP.
- Mass mail does **not** trigger the hijacked-account detection, but it has its own limits.
- Per-campaign and per-sender statistics in the reports.

`bulk-set` turns it on and sets the senders and the pace; `bulk-status` shows the setting.
