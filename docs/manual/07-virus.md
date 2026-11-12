# 7. Viruses, attachments and links

All on *Protection › Spam & virus*, each a card of its own.

## Virus scan (ClamAV)

Every mail is scanned by ClamAV. *Scan limits* bound one scan: the seconds clamd may take (5 to 20), the largest mail it scans
(10 to 64 MB) and the seconds of all checks of rspamd (8 to 60). When the scan fails (clamd down, too slow, a limit hit), the
mail either passes unscanned (*fail open*) or is deferred with `451` so the sender tries again (*fail closed*); a mail too
large to scan is then rejected. A new install fails closed; the mode can differ per tenant
(`efactl scan-fail-set --tenant <name> --fail closed`).

*Extra virus scanners* and *Sandbox* add further engines and a detonation service where they are installed; see
[protection.md](../protection.md).

## Virus signatures

ClamAV gets its own signatures through freshclam. *Virus signatures* adds more, checked every 2 hours:

| Source | Origin | What it adds | Needs |
|---|---|---|---|
| Sanesecurity | Sanesecurity and partners | phishing, scam and malware signatures | on by default (own switch, `sanesecurity-set`) |
| URLhaus | abuse.ch, Switzerland | links of known malware | its terms accepted |
| InterServer | USA | hashes of malware and web shells | the tick (the provider publishes no terms) |
| SecuriteInfo | France | many extra signatures | an own SecuriteInfo account |

Each source has its own switch with the state in effect. Switching one on with terms not yet accepted shows the link of the
provider and a tick box first; the acceptance is kept with name and time. Each file comes over HTTPS, only when it changed,
up to 200 MB, and counts only after `clamscan` has loaded it. A source switched off loses its files at the next run.
Only super admins change the sources; each change is in the audit log.

### SecuriteInfo: account tier and download lines

SecuriteInfo is used with your own account. In its row:

1. Choose the **account tier**. *Basic*: at most one round of downloads every 30 minutes and at most 300 kB/s. eFa-next keeps
   to it itself, also across restarts and manual runs.
2. Paste the `DatabaseCustomURL` lines from the setup page of your SecuriteInfo account, or enter the account ID.

The lines hold your subscription key. eFa-next stores them for root only, never shows, logs or audits them; the page only
says how many lines are stored, with *Replace* and *Delete*. The lines are checked strictly: `https`, a host of
`securiteinfo.com`, a ClamAV database file, at most 40 lines. Console (asks for the lines on standard input):

```bash
sudo efactl clam-securiteinfo-set --tier basic
```

In a cluster each node downloads by itself and counts against the limit of the account.

## Attachments

*Attachments* blocks or holds by the real file type (the content, not the ending) and by what is inside an archive. Executables
are blocked; exceptions by name are possible and a single sender can be allowed. *Encrypted archives* opens encrypted ZIP
archives for the scan with a password found in the subject or text of the mail. *Office macros* reads VBA macros and scores
autostart and suspicious calls.

## Content disarm (CDR)

*Content disarm* strips the active parts out of Office and PDF files: macros go (a `.docm` becomes a `.docx`), PDF files lose
JavaScript, open and launch actions and embedded files. A file that cannot be cleaned is replaced by a short note; a file that
cannot be read makes the mail wait. The original is kept for the admin (`efactl cdr-list`, `cdr-release`; releasing active
content needs the right to release malware). *Active HTML* removes scripts, forms and event handlers from HTML mail. Signed or
encrypted mail is left unchanged. Details: [attachments-and-cdr.md](../attachments-and-cdr.md).

## Link check on click

*Link check* rewrites the links of incoming mail to a signed address on this server, so each link is checked again when it is
clicked. A safe link forwards at once, a dangerous one shows a warning page with the real address and the reason. Exceptions
by domain are possible. *Hints* on the warning page can be set per tenant. Details: [link-check.md](../link-check.md).

## Phishing reports and banner

*Phishing reports and banner* gives users a way to report a mail (also through an Outlook add-in) and puts a warning banner
into mail from outside. Details: [phishing-and-banner.md](../phishing-and-banner.md).

Next: [Domains, tenants, users and the portal](08-domains-users.md) · Back: [Manual](README.md)
