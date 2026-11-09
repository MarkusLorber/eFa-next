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

## Journal format (6, rest of 8h)

`efactl archive-set ... --format journal` gives the archive a journal report instead of a plain copy (`--format copy`, the
default).

**What the report holds:**
- the envelope: the sender, all recipients including the BCC recipients, the time and the queue ID (in the text and in the
  headers `X-eFa-Journal-*`);
- the mail itself, as an embedded message (`message/rfc822`).

**When it is made:** right after the verdict of rspamd and before a quarantine hold. So the archive also gets mail that waits
in quarantine.

**How it travels:** the reports go through a port of Postfix without filters, BCC or content filter (`127.0.0.1:10031`, local
only). They are never filtered or archived again. Then they take the transport and TLS settings of the archive target.

**If the report cannot be handed over:** the mail gets a temporary error, and the sending server tries again. A mail is never
delivered without its journal report.

The content milter efa-cdr makes the reports, so it runs while a journal target exists. A mail over its size limit (30 MB) goes
into the report with its headers only and a note.

