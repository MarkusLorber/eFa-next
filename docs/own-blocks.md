# Own blocks: file hashes and YARA

Under Spam & virus, Own blocks (M5). Empty after an install and an upgrade.

Every entry, a file hash or a YARA rule, has its scope: **only this tenant** (the default for a new entry) or **for all
tenants**. Tenant admins (permission `security.rules`) make entries for their own tenant only. Only a super admin, or a login
with `security.rules.global`, makes an entry for all tenants or changes one. A tenant admin never sees the hashes or YARA rules
of another tenant; of the rules for all tenants they see the name, not the text. Adding an entry again with the other scope
moves it. Every change, also of the scope, is in the audit log and builds the lists anew.

## SHA-256 of files

`efactl own-hash-set --action add --sha256 <64 hex digits> --name invoice.zip --scope tenant --tenant <name>` puts the SHA-256
of a file on the list: a mail with an attachment of exactly this content is rejected (`550`, "Attachment blocked by the
administrator", symbol `EFA_OWN_HASH`), for the recipients of that tenant or, with `--scope all`, for everybody. The check runs
in rspamd over every attachment.

## YARA rules

`efactl own-yara-set --action add --rules 'rule name { ... }' --scope tenant --tenant <name>` (or `--file rule.yar` on the
console) adds one YARA rule; the same name again changes it, `--action remove --name <rule>` removes it. Before a rule is
loaded, clamscan has to take it alone and together with all other rules; `import` and `include` are not allowed, at most 256 KB.

ClamAV takes only YARA rules with at least one string: a rule with only a condition (`condition: true`) and modules such as
`pe` are skipped by ClamAV, so eFa-next refuses them with that reason instead of keeping a rule that never matches. A rule
counts only when ClamAV reports it as loaded; a syntax error is shown with the line ClamAV names.

ClamAV reads all rules from one database (`/var/lib/clamav/efa-own.yar`): a rule for all tenants keeps its name, the rule of a
tenant is named `t<id>_<name>` there. A hit rejects the mail. As soon as a tenant has a rule of its own, rspamd gives the hits of
tenant rules the symbol `EFA_TENANT_YARA`, and eFa-next rejects the mail only when a recipient belongs to that tenant
(`EFA_AV_REJECT`); then eFa-next, not the antivirus module of rspamd, rejects viruses too, with the same result.

Limit: the rules of all tenants run in the one clamd of the host for every mail; a tenant rule that is slow costs all mail.
The scan limits (Scan limits) bound that time. In a cluster set the entries on each node (or on the master in master/client
mode).
