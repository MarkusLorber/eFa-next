# Requests of data subjects (GDPR Art. 15 and 17)

Under Mail log, Data of one person (GDPR) (D1). For the admins of the domain of the address only.

## Access (Art. 15)

`efactl gdpr-export --address anna@example.com` lists everything eFa-next keeps about the address: the rows of the mail log
(as sender, recipient, From, Reply-To or Return-Path, also those already under a pseudonym, D2), the stored headers of these
mails, held mail for or from the address, spam reports, accounts, and the number of mail relations of the BEC check. Not in
it: backups (kept 5 days), the logs of the operating system, and mail already delivered to the mailbox.

## Erasure (Art. 17)

`efactl gdpr-delete --address anna@example.com --reason "request 2026-11-08 #12" --confirm yes` deletes the mail log rows,
stored headers and DNS evidence of these mails, the held mail for the address (the file goes once no other recipient waits
for it), the spam reports and the BEC relations and writing profile in Redis. Accounts stay (Users), as do entries of the
sender lists; held mail of this sender for other recipients is the data of those recipients. Backups keep the data for up to
5 days.

Both steps are in the audit log (and the strict audit log) with the pseudonym of the address and the reason, never the address
itself.
