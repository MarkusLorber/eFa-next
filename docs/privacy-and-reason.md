# Privacy defaults & a reason for content

eFa is sparing with data from the start, and it can require a reason before anyone opens the content of a mail. Under Mail ›
Storage & privacy, and Security › the strict audit mode.

## Sparing defaults

- Short log retention, no mail content in the log, and an update check that reaches only EU hosts without personal data.
- An upgrade keeps your current values and notes the change on the dashboard.

## A reason to open content

- In the strict audit mode a reason (at least five characters) is required to open the content or the headers of a mail
  (`uq-content`, `quarantine-content`, `mail-show`, `quarantine-show`). The reason goes to the audit log.
- `content-reason-set` can require the reason on its own, without the full strict mode.

(Deletion periods per kind of data — 9h — move to 6.0.0.5.)
