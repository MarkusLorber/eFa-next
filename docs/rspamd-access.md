# rspamd and eFa-next

eFa-next is the place where mail filtering is set and looked at. The rspamd web interface only opens for reading, for the main
admin, and only for a while. Everything that changes the filter goes through eFa-next, so it keeps the rights of the login, an
audit entry and the cluster.

## The rspamd web interface (read only, for a while)

- Off by default. Security: rspamd web interface, "Read only" for 15 minutes, 1 hour or 4 hours, then it closes by itself
  (a timer, and the check of the login refuses it after that time even without the timer).
- Only the main admin (role super) may open it: it shows the mail of every domain, without the limits of tenants and domains.
- nginx lets only GET and HEAD through; the browser never gets the rspamd password, the headers Password, Cookie and
  X-Forwarded-For are removed. Each opening and each change of the switch goes into the audit log.
- Full access is no longer offered. An update turns a full or open access of before into one hour of reading, with a notice
  on the dashboard.

## What eFa-next shows instead

| rspamd web interface | eFa-next |
|---|---|
| Actions and limits | Spam & virus: spam scores; per domain, tenant, group or sender: Rules |
| Score of a symbol | Spam & virus, expert view: Symbol scores (-50 to 50, with a way back to the score of rspamd) |
| History of a mail | Mail log: each mail with its symbols, their scores and what they mean |
| Scan a message | Mail log: Check a mail |
| Learn spam / ham | Report as spam or wanted, with approval; own model; Bayes status |
| Maps and lists | Sender lists, own DNS blocklist, IP blocklists, Rules |
| Neural network | Spam & virus, expert view |
| Several nodes | Cluster: mail log, quarantine, queue and status of all nodes |

Not in eFa-next, as it is not needed to run the filter: fuzzy hashes by hand, testing selectors, worker details and the
error log of rspamd (on the console: journalctl -u rspamd).

## Own scores of symbols

`efactl symbol-score-set --symbol NAME --score N` (or `--reset on`) writes `/etc/rspamd/local.d/groups.conf` from
`/etc/eFa/symbol-scores.json`. rspamd checks the file (`rspamadm configtest`) before it loads it; a file it refuses is taken
back. The file belongs to eFa: updates of rspamd do not touch it, changes go to every cluster node.

## Check a mail

The mail log page takes one .eml of up to 10 MB: the main admin any mail, a domain admin only mail that names one of the own
domains in From, Sender, To, Cc or Delivered-To. The mail goes to rspamd once, in memory, with the flags `no_log` and
`no_stat`, and is not stored by eFa-next.

What is kept:

- eFa-next: one audit line with who checked, the action, the score and the size. No sender, recipient or subject.
- rspamd (measured on rspamd 4.2): no history entry, no summary log line, no learning. rspamd still writes two lines to its
  log: the Message-ID of the mail with its size and checksum, and the result of a check that set the action before the scan
  (such as DMARC). The log of rspamd is kept as long as the system keeps its logs.
