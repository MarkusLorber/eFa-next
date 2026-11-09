# Taken-over accounts: hold and release

With the sending limits of the outbound check on (Mail routing, Submitters: recipients or target domains per hour of a
sender, all senders of a domain, or of a tenant), `--auto_hold on` (A1) treats a sender over a limit as a possibly taken-over
account:

- this mail and all further mail of the account (its login, or the address of its client) wait in the hold queue of Postfix;
- the admin gets one mail with the account and the limit;
- `efactl hijack-list` shows the held accounts, since when and why; after the password of the account was changed,
  `efactl hijack-release --who <account>` lets it send again. Its held mail stays in the queue (Mail queue, Held) for a
  decision: release or delete.

The list of held accounts survives a restart of the milter (`/var/lib/efa-outbound/held-senders.json`). Bulk mail (8i) does
not count for the limits. Off by default and after an upgrade.
