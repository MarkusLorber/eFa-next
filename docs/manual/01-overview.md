# 1. Overview

eFa-next is a mail filter appliance for businesses and organisations. It receives the mail of your domains from the
internet, checks it, and passes clean mail on to your own mail server (Microsoft 365, Exchange, Google Workspace or any SMTP
server). Outgoing mail can go through eFa-next too: it is then signed with DKIM and checked for data loss and taken-over
accounts. eFa-next is the successor of eFa 5; it keeps the idea and replaces MailScanner, MailWatch, Apache, PHP and Perl
with a single, smaller stack.

**Intended use:** for qualified administrators with knowledge of Linux, DNS, SMTP and TLS; not for consumers. See
[DISCLAIMER.md](../../DISCLAIMER.md).

## How mail flows

```
internet ──► Postfix (postscreen, TLS, blocklists, greylisting, recipient check)
                 │
                 ▼
            rspamd (spam, SPF/DKIM/DMARC/ARC, BEC, Bayes, fuzzy)  ◄──► ClamAV (+ extra signatures)
                 │
                 ▼
            content milter (attachments, content disarm, link check, banner)
                 │
     ┌───────────┼─────────────────────────┐
     ▼           ▼                         ▼
  deliver    held mail / quarantine      reject
  to your    (users release it in the
  mail       portal, admins in the
  server     web interface)
```

Every decision is written to the mail log (MariaDB), which the web interface searches and the reports count.

## The parts

| Part | Job |
|---|---|
| Postfix | receives and delivers mail, TLS, postscreen, queue |
| rspamd | spam scoring, authentication checks (SPF, DKIM, DMARC, ARC), DKIM signing |
| ClamAV | virus scan, with Sanesecurity and optional URLhaus, InterServer and SecuriteInfo signatures |
| Unbound | own validating DNS resolver (DNSSEC), so DNS blocklists answer and no foreign resolver sees your queries |
| MariaDB | mail log, users, groups, settings with scope |
| Redis (Valkey on EL10) | short-lived state: greylisting, rate limits, sender relations |
| nginx + efa-web | the admin web interface and the user portal over HTTPS |
| efactl | the one command behind every action; the web interface reaches it only through `efactl-runner` |

Settings live in `/etc/eFa`, logs in `/var/log/eFa`, data in `/var/lib/eFa`.

## The web interface

The menu on the left has seven groups:

| Group | Pages |
|---|---|
| Overview | Dashboard |
| Mail & quarantine | Mail routing, Held mail, Quarantine, Mail queue, Mail log |
| Protection | Spam & virus, Blocklists, IP blocklists, Sender lists, Rules, Impersonation & BEC |
| Domains & tenants | DKIM, ARC & DMARC, Data loss prevention, Bulk mail, Archive handover, Encrypted PDF mail, Disclaimers, Domain settings, Tenants |
| Users & access | My account, Users, Groups, Security standards, Security |
| Monitoring & reports | Mail report, Monitoring, Wazuh |
| System | DNS resolver for other networks, Network & certificate, Backup & restore, Cluster & offline, Maintenance & update |

Each login sees only the pages and cards its groups allow (chapter 8). Every card has a one-line explanation under its title
and an (i) with the full help, as has every field. The interface is in English and German (switch on the login page, and per
login under *My account › My settings*, with time zone, rows per page and the default view).

All features, grouped, with a link to each reference page: [FEATURES.md](../FEATURES.md) ([Deutsch](../FEATURES.de.md)).

## Principles

- **Secure by default.** Modern TLS only, two-factor login, no open relay, no open resolver, fail closed where a check
  cannot run. A security minimum (TLS 1.2 or newer, ECDHE, AEAD) cannot be lowered.
- **Your data stays with you.** No third-party check service is asked unless you switch it on; sources outside the EU say so.
- **Everything audited.** Every change, from the web or the console, goes into the audit log with who, when and what.
- **Resource-friendly.** No extra daemons for things a timer or the web process can do.

Next: [Requirements and install](02-install.md) · Back: [Manual](README.md)
