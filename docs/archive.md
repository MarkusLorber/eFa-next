# Archive forwarding

Send a copy of every mail to an external archive (for example MailStore or piler). Global or per domain. Off by default.

## How it works

- A copy of each mail — incoming, outgoing or both — goes to a journal address or mailbox that the archive collects, by SMTP
  with TLS.
- Templates for **MailStore** and **piler** (open source, recommended). An optional journal format wraps the mail with an
  envelope (all recipients, BCC included, and the time) as an attachment.
- Built on Postfix `recipient_bcc_maps` / `sender_bcc_maps` or an own forward; you can choose the copy before or after the
  quarantine decision.
- A delivery failure stays in the queue, so nothing is lost; an alarm warns on a backlog.

A commercial archive is never required. `archive-set`, `archive-remove`, `archive-status`.
