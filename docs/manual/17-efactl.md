# 17. efactl reference

Every action of the web interface is a command of `efactl` on the console, with the same checks, rights and audit log.
Run it as the console admin with `sudo`. `sudo efactl --help` lists all commands, `sudo efactl <command> --help` the
arguments of one, `sudo efactl menu` opens the text menu with the same pages as the web interface.

This list is generated from the menu of the web interface and the command titles of `efactl` in this release.
Commands marked *writes* change the system; the others only read.

## Overview

### Dashboard

| Command | Title |
|---|---|
| `status` | Status |
| `settings` | Settings: show |

## Mail & quarantine

### Mail routing

| Command | Title |
|---|---|
| `transport-set` | Domains and their mail servers *(writes)* |
| `relay-networks-list` | Relay networks |
| `relay-networks-add` | Add networks *(writes)* |
| `relay-networks-remove` | Remove a network *(writes)* |
| `relay-networks-apply` | Apply relay network changes *(writes)* |
| `relay-networks-discard` | Discard relay network changes *(writes)* |
| `relay-networks-set` | Relay networks *(writes)* |
| `smarthost-set` | Outbound smarthost *(writes)* |
| `submitter-list` | Submitters |
| `submitter-set` | Submitter: add or change *(writes)* |
| `submitter-remove` | Submitter: remove *(writes)* |
| `outbound-limits-set` | Sending limits per sender and hour *(writes)* |
| `hijack-list` | Held accounts (possibly taken over) |
| `hijack-release` | Held accounts: release one *(writes)* |
| `header-privacy-status` | Header privacy of outgoing mail |
| `header-privacy-set` | Header privacy: for whom *(writes)* |
| `message-size-set` | Maximum message size *(writes)* |
| `recipient-verification-set` | Recipient verification *(writes)* |
| `tls-partner-list` | TLS with partner domains |
| `tls-partner-set` | TLS with partner domains: require or remove *(writes)* |

### Held mail

| Command | Title |
|---|---|
| `uq-list` | Held mail |
| `uq-show` | Held mail: headers |
| `uq-release` | Held mail: release *(writes)* |
| `uq-request` | Held mail: ask an admin to release *(writes)* |
| `uq-sender` | Held mail: allow or block the sender *(writes)* |
| `uq-delete` | Held mail: delete *(writes)* |
| `train-request` | Report as spam or as wanted *(writes)* |
| `train-list` | Spam reports |
| `train-decide` | Spam reports: decide *(writes)* |
| `uq-status` | Quarantine for users |
| `uq-set` | Quarantine for users: settings *(writes)* |
| `uq-encrypt-set` | Quarantine for users: stored encrypted *(writes)* |
| `my-settings` | My settings |
| `my-settings-set` | My settings: change *(writes)* |
| `account-show` | My account |
| `account-set` | My account: name and phone *(writes)* |
| `account-email-set` | My account: email address *(writes)* |
| `password-change` | My account: password *(writes)* |
| `totp-status` | 2FA of my login |
| `totp-setup` | 2FA: set up the app (or a new one) *(writes)* |
| `totp-confirm` | 2FA: switch on with the first code *(writes)* |
| `totp-recovery-new` | 2FA: new recovery codes *(writes)* |
| `totp-disable` | 2FA: switch off *(writes)* |
| `passkey-status` | Passkeys |
| `passkey-register` | Passkeys: add *(writes)* |
| `passkey-remove` | Passkeys: remove one of mine *(writes)* |
| `graymail-status` | Newsletters (graymail) |
| `graymail-mine-set` | Newsletters to my mailbox *(writes)* |
| `user-spam-status` | Own spam limit |
| `user-spam-mine-set` | My spam limit *(writes)* |
| `recall-list` | My mails in the recall window |
| `recall-withdraw` | Withdraw a mail of mine *(writes)* |
| `emergency-list` | Emergency access: received mail |
| `emergency-show` | Emergency access: read a mail |
| `emergency-file` | Emergency access: save an attachment or the mail |

### Quarantine

| Command | Title |
|---|---|
| `quarantine-list` | Quarantine: list |
| `quarantine-show` | Quarantine: show headers |
| `quarantine-release` | Quarantine: deliver *(writes)* |
| `quarantine-delete` | Quarantine: delete *(writes)* |
| `quarantine-set` | Quarantine for spam *(writes)* |
| `quarantine-days-set` | Quarantine: days to keep *(writes)* |
| `quarantine-purge` | Quarantine: delete old mail now *(writes)* |
| `emergency-status` | Emergency access: copies of delivered mail |
| `emergency-set` | Emergency access: keep a sealed copy of delivered mail *(writes)* |

### Mail queue

| Command | Title |
|---|---|
| `queue-list` | Mail queue |
| `queue-show` | Mail queue: headers |
| `queue-action` | Mail queue: hold, release, requeue or delete *(writes)* |
| `queue-flush` | Mail queue: try all now *(writes)* |
| `spool-status` | Spooling and receiving servers |
| `spool-set` | Spooling: how long mail waits *(writes)* |
| `queue-alarm-set` | Mail queue: alarm *(writes)* |

### Mail log

| Command | Title |
|---|---|
| `message-search` | Message search |
| `maillog-search` | Mail log: search |
| `maillog-live` | Mail log: live |
| `sender-action-check` | Sender of a mail: what allow or block would do |
| `sender-action` | Sender of a mail: allow or block *(writes)* |
| `gdpr-export` | GDPR: everything about one mail address (Art. 15) |
| `gdpr-delete` | GDPR: erase the data of one mail address (Art. 17) *(writes)* |
| `headers-export` | Export headers *(writes)* |
| `retention-status` | Retention of the data |
| `retention-set` | Retention: days to keep *(writes)* |
| `pseudonymise-status` | Mail log: pseudonyms |
| `pseudonymise-set` | Mail log: pseudonyms after days *(writes)* |
| `content-reason-set` | Reason before mail content is shown *(writes)* |
| `subject-display-set` | Subjects in the mail log *(writes)* |
| `headers-store-set` | Headers of all mail *(writes)* |
| `maillog-retention-set` | Mail log: days to keep *(writes)* |
| `maillog-size-set` | Mail log: size limit *(writes)* |
| `maillog-purge` | Mail log: delete old entries now *(writes)* |

## Protection

### Spam & virus

| Command | Title |
|---|---|
| `spam-scores-set` | Spam scores *(writes)* |
| `greylisting-set` | Greylisting *(writes)* |
| `subject-get` | Subject marking: show |
| `subject-set` | Subject marking: set *(writes)* |
| `bayes-status` | Bayes classifier |
| `sanesecurity-status` | Sanesecurity signatures |
| `sanesecurity-set` | Sanesecurity signatures: switch *(writes)* |
| `sanesecurity-update` | Update signatures now *(writes)* |
| `clam-source-status` | More ClamAV signatures |
| `clam-source-set` | More ClamAV signatures: a source on or off *(writes)* |
| `clam-securiteinfo-set` | More ClamAV signatures: account tier and URLs of SecuriteInfo *(writes)* |
| `attachment-status` | Attachments |
| `attachment-set` | Attachments: settings *(writes)* |
| `qr-status` | QR codes in mail |
| `qr-set` | QR codes in mail: switch *(writes)* |
| `unlock-status` | Encrypted archives |
| `unlock-set` | Encrypted archives: open with the password of the mail and scan *(writes)* |
| `ole-status` | Office macros (oletools) |
| `ole-set` | Office macros: read by olevba and scored *(writes)* |
| `tracking-status` | Tracking protection |
| `tracking-set` | Tracking protection: pixels and link parameters out of incoming mail *(writes)* |
| `tracking-list-set` | Tracking protection: exceptions and own tracking hosts *(writes)* |
| `lookalike-status` | Lookalike domains in new certificates |
| `lookalike-set` | Lookalike watch: new certificates of domains like the own ones *(writes)* |
| `lookalike-run` | Lookalike watch: check now *(writes)* |
| `lookalike-allow` | Lookalike watch: a domain that is harmless *(writes)* |
| `retro-status` | Check after delivery |
| `retro-set` | Check after delivery: delivered mail against new feed data *(writes)* |
| `retro-run` | Check after delivery: check now *(writes)* |
| `retro-imap-set` | Take dangerous mail back out of the mailboxes (IMAP) *(writes)* |
| `outbreak-status` | Outbreak filter |
| `outbreak-set` | Outbreak filter: defer new waves *(writes)* |
| `fuzzy-status` | Own fuzzy store |
| `fuzzy-set` | Own fuzzy store of approved spam *(writes)* |
| `community-status` | Community fuzzy store |
| `community-set` | Community fuzzy store of the operators *(writes)* |
| `scanner-status` | Extra virus scanners |
| `scanner-set` | Extra virus scanner: add, change or remove *(writes)* |
| `sandbox-status` | Sandbox (CAPEv2) |
| `sandbox-set` | Sandbox: suspicious attachments to the own CAPEv2 *(writes)* |
| `own-block-status` | Own blocks: file hashes and YARA rules |
| `own-hash-set` | Own blocks: SHA-256 of a file *(writes)* |
| `own-yara-set` | Own blocks: a YARA rule *(writes)* |
| `graymail-set` | Newsletters (graymail): settings *(writes)* |
| `user-spam-set` | Own spam limits of the users *(writes)* |
| `scan-status` | Virus scan: limits per mail |
| `scan-limits-set` | Virus scan: limits per mail and scan failures *(writes)* |
| `scan-fail-set` | Virus scan: scan failures of a tenant *(writes)* |
| `cdr-status` | Content disarm |
| `cdr-set` | Content disarm: switch *(writes)* |
| `cdr-list` | Content disarm: originals |
| `cdr-release` | Content disarm: deliver the original *(writes)* |
| `html-disarm-set` | Content disarm: active HTML *(writes)* |
| `bimi-set` | BIMI: the logo of a checked sender *(writes)* |
| `links-status` | Link check |
| `links-set` | Link check: settings *(writes)* |
| `links-hint-set` | Link check: own hint on the warning page *(writes)* |
| `phish-set` | Phishing reports: the address of a domain *(writes)* |
| `banner-set` | Warning banner for mail from outside *(writes)* |
| `outlook-addin` | Outlook add-in for reports: the manifest |
| `neural-status` | Neural network |
| `neural-set` | Neural network: settings *(writes)* |
| `symbol-scores` | Symbol scores of rspamd |
| `symbol-score-set` | Symbol scores: own score of a symbol *(writes)* |
| `ml-status` | Own model |
| `ml-set` | Own model: settings *(writes)* |
| `ml-train` | Own model: learn now *(writes)* |

### Blocklists

| Command | Title |
|---|---|
| `rbl-show` | Blocklists |
| `rbl-set` | Change a blocklist *(writes)* |
| `rbl-custom-set` | Your own blocklist *(writes)* |
| `postscreen-status` | postscreen on port 25 |
| `postscreen-set` | postscreen on port 25: switch *(writes)* |
| `feed-status` | Threat feeds |
| `feed-set` | Threat feeds: add, switch off or remove *(writes)* |
| `feeds-run` | Threat feeds: fetch now *(writes)* |

### IP blocklists

| Command | Title |
|---|---|
| `blocklist-show` | IP blocklists |
| `blocklist-set` | IP blocklists: add or change a list *(writes)* |
| `blocklist-entry` | IP blocklists: own entries *(writes)* |
| `blocklist-remove` | IP blocklists: remove a list *(writes)* |

### Sender lists

| Command | Title |
|---|---|
| `sender-list` | Sender lists |
| `sender-add` | Add senders *(writes)* |
| `sender-remove` | Remove senders *(writes)* |
| `sender-move` | Move a sender to the other list *(writes)* |
| `sender-list-set` | Sender allow and block lists *(writes)* |
| `sender-rule-set` | Sender rules: IP, pattern, per recipient *(writes)* |

### Rules

| Command | Title |
|---|---|
| `rule-list` | Rules |
| `rule-set` | Rules: add, change or remove *(writes)* |

### Impersonation & BEC

| Command | Title |
|---|---|
| `bec-status` | Impersonation and BEC |
| `bec-set` | Impersonation and BEC: switch and scores *(writes)* |
| `bec-vip-set` | Impersonation and BEC: VIPs *(writes)* |
| `bec-partner-set` | Impersonation and BEC: partner domains *(writes)* |

## Domains & tenants

### DKIM, ARC & DMARC

| Command | Title |
|---|---|
| `dkim-check` | DKIM keys |
| `dkim-create` | DKIM keys: generate *(writes)* |
| `dkim-import` | DKIM: import a key *(writes)* |
| `dkim-remove` | DKIM: remove a key *(writes)* |
| `dkim-export` | DKIM: export DNS records |
| `rotation-status` | Rotation: status |
| `rotation-all-set` | Auto-rotate all domains *(writes)* |
| `rotation-set` | Own rotation settings for one domain *(writes)* |
| `rotation-pregenerate` | Rotation: create future keys now *(writes)* |
| `rotation-run` | Rotation: check now *(writes)* |
| `resolver-set` | DNS servers for the rotation check *(writes)* |
| `dkim-provision-status` | DKIM: managed externally |
| `dkim-provision-set` | DKIM: provisioning API on port 8463 *(writes)* |
| `dkim-source-set` | DKIM: a source that delivers keys *(writes)* |
| `dkim-source-remove` | DKIM: remove a source *(writes)* |
| `dkim-provision-takeover` | DKIM: take a domain back from its source *(writes)* |
| `arc-show` | ARC sealing |
| `arc-all-set` | ARC for all domains *(writes)* |
| `arc-set` | ARC for one domain *(writes)* |
| `arc-trusted-set` | ARC: trusted sealers *(writes)* |
| `dmarc-record-show` | Saved DMARC records |
| `dmarc-record-set` | DMARC record generator *(writes)* |
| `dmarc-record-history` | DMARC record: history |
| `dmarc-record-check` | Check an existing DMARC record |
| `dmarc-reports-set` | DMARC reports *(writes)* |
| `dmarc-report-show` | DMARC reports received |
| `tls-report-show` | TLS reports received |
| `reports-in-set` | Received reports: the address *(writes)* |
| `dkim-selectors` | DKIM selectors seen |

### Data loss prevention

| Command | Title |
|---|---|
| `dlp-status` | Data loss prevention |
| `dlp-set` | Data loss prevention: card numbers and IBANs *(writes)* |
| `dlp-rule-set` | Data loss prevention: own rule *(writes)* |

### Bulk mail

| Command | Title |
|---|---|
| `bulk-status` | Bulk mail |
| `bulk-set` | Bulk mail: settings *(writes)* |

### Archive handover

| Command | Title |
|---|---|
| `archive-status` | Archive handover |
| `archive-set` | Archive handover: add or change a target *(writes)* |
| `archive-test` | Archive handover: test the connection |
| `archive-remove` | Archive handover: remove a target *(writes)* |

### Encrypted PDF mail

| Command | Title |
|---|---|
| `pdf-status` | Encrypted PDF mail |
| `pdf-set` | Encrypted PDF mail: keyword in the subject *(writes)* |
| `pdf-password-set` | Encrypted PDF mail: agreed password of a recipient *(writes)* |

### Disclaimers

| Command | Title |
|---|---|
| `disclaimer-status` | Disclaimers |
| `disclaimer-which` | Disclaimer: which one a sender gets |
| `disclaimer-template-set` | Disclaimer for all domains, a tenant, a domain or groups *(writes)* |
| `disclaimer-import` | Disclaimer: import a ZIP *(writes)* |
| `disclaimer-template-remove` | Remove a disclaimer *(writes)* |
| `disclaimer-restore` | Disclaimer: back to the version before *(writes)* |
| `disclaimer-set` | Disclaimer of a domain *(writes)* |
| `signature-status` | AD signatures |
| `signature-set` | AD signatures: fields of the directory in the disclaimer templates *(writes)* |
| `signature-sync` | AD signatures: read the directory now *(writes)* |
| `crypto-status` | S/MIME and PGP: keys and policy |
| `crypto-key-make` | S/MIME and PGP: make an own key *(writes)* |
| `crypto-import` | S/MIME and PGP: import a certificate or public key *(writes)* |
| `crypto-remove` | S/MIME and PGP: remove a key *(writes)* |
| `crypto-policy-set` | S/MIME and PGP: sign, encrypt, decrypt *(writes)* |
| `crypto-hsm-set` | S/MIME and PGP: an own S/MIME key in a hardware module (PKCS#11) *(writes)* |

### Domain settings

| Command | Title |
|---|---|
| `domain-settings-show` | Domain settings: show with their source |
| `domain-spam-set` | Domain settings: spam limits *(writes)* |
| `domain-quarantine-set` | Domain settings: quarantine and digest *(writes)* |
| `domain-routing-set` | Domain settings: TLS to the domain *(writes)* |
| `domain-general-set` | Domain settings: language and stored headers *(writes)* |
| `eu-relation-status` | EU relation |
| `eu-relation-set` | EU relation of the domains *(writes)* |
| `application-status` | Job applications per domain |
| `application-set` | Job applications: allowed to all, or only to listed addresses *(writes)* |
| `application-exception-set` | Job applications: senders that always pass *(writes)* |
| `domain-check-status` | Domain check: light of each domain |
| `domain-check-show` | Domain check: details and DNS records of a domain |
| `domain-check-run` | Domain check: check now *(writes)* |
| `domain-check-set` | Domain check: switch and weekly reminder *(writes)* |
| `role-status` | Role addresses of each domain |
| `role-set` | Role addresses: on or off, and where a role goes *(writes)* |
| `security-txt` | security.txt of a domain (RFC 9116) |
| `trap-status` | Spam trap addresses |
| `trap-set` | Spam trap address: add or remove *(writes)* |

### Tenants

| Command | Title |
|---|---|
| `tenant-list` | Tenants |
| `tenant-set` | Tenants: add or remove *(writes)* |
| `tenant-domain-set` | Tenants: domains *(writes)* |
| `domain-pending-list` | Tenants: domains waiting for DNS |
| `domain-onboard` | Tenants: add a domain *(writes)* |
| `domain-verify` | Tenants: check the TXT record of a domain *(writes)* |
| `tenant-usage` | Tenant usage |
| `tenant-limits-set` | Tenant limits *(writes)* |
| `tenant-brand-show` | Tenant look |
| `tenant-brand-set` | Tenant look: name, colour, logo *(writes)* |
| `tenant-idp-status` | Tenant login directory |
| `tenant-ldap-set` | Tenant login directory: LDAP *(writes)* |
| `tenant-oidc-set` | Tenant login directory: OIDC *(writes)* |
| `tenant-group-map-set` | Tenant login directory: give a group an eFa-next group *(writes)* |
| `tenant-lock` | Tenant: lock or unlock *(writes)* |
| `tenant-delete` | Tenant: delete with all its data *(writes)* |

## Users & access

### My account

| Command | Title |
|---|---|
| `whoami` | My login |
| `session-list` | Active sessions |
| `session-end` | Active sessions: end one *(writes)* |

### Users

| Command | Title |
|---|---|
| `user-2fa-reset` | 2FA of a user: reset (lost phone) *(writes)* |
| `totp-policy-set` | 2FA: required per role *(writes)* |
| `passkey-reset` | Passkeys of a user: remove all (lost key) *(writes)* |
| `passkey-set` | Passkeys: host name and mode per role *(writes)* |
| `user-list` | Users |
| `user-show` | Users: effective permissions |
| `user-set` | Users: add, change or remove *(writes)* |
| `user-state` | Users: lock (off) or unlock (on) *(writes)* |
| `token-list` | API tokens |
| `token-create` | API tokens: make one *(writes)* |
| `token-revoke` | API tokens: delete one *(writes)* |
| `api-status` | REST API |
| `api-set` | REST API: switch *(writes)* |
| `oidc-status` | Single sign-on (OIDC) |
| `oidc-set` | Single sign-on: switch *(writes)* |
| `ldap-status` | LDAP or Active Directory login |
| `ldap-set` | LDAP login: switch *(writes)* |
| `audit-search` | Audit log |
| `incident-list` | NIS2 incidents |
| `incident-open` | NIS2 incident: open a record *(writes)* |
| `incident-report` | NIS2 incident: report for 24 h, 72 h or the final report |
| `privacy-evidence` | Privacy evidence: record of processing and TOM |
| `audit-strict-status` | Strict audit mode |
| `audit-mode` | Strict audit mode: switch *(writes)* |
| `audit-verify` | Strict audit log: check the chain |
| `audit-anchor-verify` | Strict audit log: check the signed daily anchors |
| `audit-rules-set` | auditd rules for the eFa-next files *(writes)* |

### Groups

| Command | Title |
|---|---|
| `group-list` | Groups |
| `group-set` | Groups: add, change or copy *(writes)* |
| `group-state` | Groups: disable or enable *(writes)* |
| `group-remove` | Groups: remove *(writes)* |
| `permission-list` | Permissions |
| `group-map-list` | Directory groups |
| `group-map-set` | Directory groups: give an eFa-next group *(writes)* |

### Security standards

| Command | Title |
|---|---|
| `standards-show` | Security standards: the last check |
| `standards-check` | Security standards: check now (all standards, the settings in effect) |
| `standards-status` | Security standards |
| `standards-set` | Security standards: choose, preview and apply *(writes)* |
| `standards-rollback` | Security standards: back to the settings before *(writes)* |
| `os-harden-status` | Hardening of the operating system and of eFa-next: state |
| `os-harden-set` | Hardening of the operating system: one item *(writes)* |

### Security

| Command | Title |
|---|---|
| `threat-status` | Attack alert |
| `threat-set` | Attack alert: sensitivity *(writes)* |
| `harvest-status` | Address harvesting |
| `harvest-set` | Address harvesting: ban senders that try many unknown recipients *(writes)* |
| `login-lockout-status` | Failed logins: lockout |
| `login-lockout-set` | Failed logins: lockout of web, portal, API and port 587 *(writes)* |
| `ssh-root-status` | Root login through SSH |
| `ssh-root-set` | Root login through SSH: switch *(writes)* |
| `web-allowlist-show` | Admin web access |
| `web-allowlist-set` | Admin web access: allowed addresses *(writes)* |
| `fail2ban-set` | Fail2Ban *(writes)* |
| `admin-email-set` | Admin email *(writes)* |
| `rspamd-sso-set` | rspamd web interface through eFa-next: read only, for a while *(writes)* |
| `audit-rspamd` | Note an opening of rspamd *(writes)* |
| `web-harden` | Apply web server hardening *(writes)* |
| `firewall-show` | Firewall |
| `firewall-set` | Firewall: admin allowlist *(writes)* |
| `firewall-confirm` | Firewall: keep the change *(writes)* |
| `firewall-revert` | Firewall: take back the change *(writes)* |
| `firewall-guard-status` | Firewall guard: status |
| `firewall-guard-set` | Firewall guard *(writes)* |
| `firewall-guard-run` | Firewall guard: check now *(writes)* |
| `firewall-test` | Run firewall tests |
| `firewall-probe-set` | Outside probe *(writes)* |
| `security-status` | Security self check |
| `security-check` | Security self check: run now |
| `security-check-set` | Security self check: every day *(writes)* |
| `security-oval-set` | Security self check: CVEs from OVAL data *(writes)* |
| `pwned-check-set` | New passwords: check against known data breaches *(writes)* |
| `cve-watch-status` | CVE watch: last result |
| `cve-watch-set` | CVE watch and self-lockdown of the web services *(writes)* |
| `cve-watch-run` | CVE watch: check now *(writes)* |
| `cve-mute` | CVE watch: mute one warning *(writes)* |
| `web-lockdown` | Self-lockdown of the web services: state or release *(writes)* |
| `cluster-cve` | CVE warnings of all nodes |
| `history-list` | Configuration history |
| `history-show` | Configuration history: the diff of a change |
| `history-undo` | Configuration history: take a change back *(writes)* |
| `four-eyes-list` | Four eyes: changes that wait |
| `four-eyes-decide` | Four eyes: confirm or reject a change *(writes)* |
| `four-eyes-set` | Four eyes for critical changes *(writes)* |
| `milter-health-status` | Milter health: accept or tempfail per milter |
| `milter-health-set` | Milter health: what happens when a milter is down *(writes)* |
| `tls-profile-status` | TLS profile |
| `tls-profile-set` | TLS profile for the web interface and mail *(writes)* |
| `tls-port25-set` | Require TLS on port 25 *(writes)* |
| `setup-variant-status` | Setup variant |
| `setup-offer-dismiss` | Re-Setup: hide the offer on the dashboard *(writes)* |
| `console-2fa-set` | 2FA of the console admin (SSH) *(writes)* |
| `floor-status` | Security minimum |
| `floor-check` | Security minimum: check and set back *(writes)* |
| `ssh-profile-status` | SSH profile |
| `ssh-profile-set` | SSH profile: BSI TR-02102-4 or the system setting *(writes)* |
| `ssh-profile-confirm` | SSH profile: keep it (after a new login worked) *(writes)* |
| `hardening-report` | Hardening report (CIS AlmaLinux 9, BSI TR-03108) |
| `switches-status` | Switches: what is set now |
| `tls-min-set` | SMTP: TLS 1.2 or newer only *(writes)* |
| `kernel-hardening-set` | Kernel settings of the hardening report *(writes)* |
| `service-harden-status` | Sandbox of the services |
| `service-harden` | Sandbox of the services: tested units only, untested sandbox files removed *(writes)* |

## Monitoring & reports

### Mail report

| Command | Title |
|---|---|
| `report-show` | Report: show or print |
| `report-status` | Reports by mail |
| `report-set` | Reports by mail: switch *(writes)* |
| `mailreport-today` | Today |
| `mailreport-yesterday` | Yesterday |
| `mailreport-week` | Last 7 days |
| `mailreport-set` | Daily mail *(writes)* |

### Monitoring

| Command | Title |
|---|---|
| `siem-status` | SIEM export |
| `siem-set` | SIEM export: settings *(writes)* |
| `otlp-status` | OpenTelemetry export |
| `otlp-set` | OpenTelemetry export: settings *(writes)* |
| `otlp-test` | OpenTelemetry export: connection test *(writes)* |

### Wazuh

| Command | Title |
|---|---|
| `wazuh-status` | Wazuh agent |
| `wazuh-config` | Wazuh agent: settings *(writes)* |
| `wazuh-service` | Wazuh agent: start, stop or restart *(writes)* |
| `wazuh-check` | Wazuh agent: check the package *(writes)* |
| `wazuh-install` | Wazuh agent: install *(writes)* |
| `wazuh-update` | Wazuh agent: update *(writes)* |
| `wazuh-remove` | Wazuh agent: remove *(writes)* |

## System

### DNS resolver for other networks

| Command | Title |
|---|---|
| `dns-share-list` | DNS for other networks |
| `dns-share-add` | DNS for other networks: allow *(writes)* |
| `dns-share-del` | DNS for other networks: remove *(writes)* |
| `dns-share-secondary-set` | Second DNS resolver of this host (the other MX) *(writes)* |

### Network & certificate

| Command | Title |
|---|---|
| `network-show` | Network: show |
| `network-set` | Network: set (after reboot) *(writes)* |
| `hostname-set` | Host name: change it everywhere *(writes)* |
| `interfaces-list` | Network interfaces |
| `interface-set` | Network interfaces: role and address *(writes)* |
| `interface-confirm` | Network interfaces: keep the change *(writes)* |
| `interface-revert` | Network interfaces: take back *(writes)* |
| `uplink-route-set` | Outgoing mail of a domain over an uplink *(writes)* |
| `dns-zone-list` | Internal DNS: servers and domains |
| `dns-servers-set` | Internal DNS servers *(writes)* |
| `dns-zone-set` | Internal DNS domains *(writes)* |
| `dns-zone-test` | Internal DNS: ask the SOA of a domain through this host |
| `dns-forward-status` | Internal DNS: does unbound send all names to forwarders? |
| `dns-forward-fix` | Internal DNS: resolve on this host (the forwarder for all names goes) *(writes)* |
| `letsencrypt-set` | Let's Encrypt certificate *(writes)* |
| `letsencrypt-takeover` | Let's Encrypt: take over the certificate on this host *(writes)* |
| `dane-status` | DANE for outgoing mail |
| `dane-set` | DANE for outgoing mail: switch *(writes)* |
| `tlsa-show` | TLSA records of this server |
| `letsencrypt-rollover` | Let's Encrypt: a new key without breaking DANE *(writes)* |
| `mta-sts-show` | MTA-STS |
| `mta-sts-set` | MTA-STS: policy of a domain *(writes)* |
| `mta-sts-check` | MTA-STS: check the published policies now *(writes)* |
| `mta-sts-text` | MTA-STS: download the policy file |

### Backup & restore

| Command | Title |
|---|---|
| `backup-list` | Backup: list |
| `backup-now` | Back up now *(writes)* |
| `backup-set` | Automatic backup *(writes)* |
| `backup-password-set` | Password for automatic backups *(writes)* |
| `backup-key-show` | Backups: fingerprint of the signing key |
| `restore` | Restore a backup *(writes)* |
| `backup-download` | Backup: where it is |
| `backup-read` | Backup: raw download |
| `backup-import` | Backup: store an uploaded file *(writes)* |
| `backup-target-list` | External backup targets |
| `backup-target-set` | External backup targets: add or remove *(writes)* |
| `backup-target-test` | External backup targets: upload the newest backup now *(writes)* |
| `backup-hsm-set` | Backups: the signing key in a hardware module (PKCS#11) *(writes)* |

### Cluster & offline

| Command | Title |
|---|---|
| `cluster-status` | Cluster |
| `cluster-init` | Cluster: make this node the master *(writes)* |
| `cluster-mode-set` | Cluster: master/client or HA *(writes)* |
| `cluster-token` | Cluster: one-time token for a new node *(writes)* |
| `cluster-join` | Cluster: join a master *(writes)* |
| `cluster-resync` | Cluster: take all settings of the master anew *(writes)* |
| `cluster-mx-check` | Cluster: MX records and failover |
| `cluster-node-remove` | Cluster: remove a node *(writes)* |
| `cluster-promote` | Cluster: this client becomes the master (the old one is gone) *(writes)* |
| `cluster-leave` | Cluster: leave it *(writes)* |
| `cluster-update-status` | Staged updates of the cluster |
| `cluster-update-set` | Staged updates: one node first, a health window, then the rest *(writes)* |
| `offline-status` | Offline operation |
| `update-mirror-set` | Offline operation: updates from a local mirror *(writes)* |
| `offline-trust-set` | Offline operation: trust the key of the bundles *(writes)* |
| `offline-bundle-apply` | Offline operation: apply a bundle *(writes)* |
| `offline-bundle-make` | Offline operation: make a signed bundle (on a host with internet) *(writes)* |
| `cluster-maillog` | Cluster: mail log of all nodes |
| `cluster-quarantine` | Cluster: held mail of all nodes |
| `cluster-queue` | Cluster: mail queues of all nodes |
| `cluster-mail-action` | Cluster: act on a mail of a node *(writes)* |
| `cluster-unban` | Cluster: lift a ban on all nodes *(writes)* |

### Maintenance & update

| Command | Title |
|---|---|
| `update-pending` | Pending updates |
| `update-status` | Last system update |
| `update-system` | Update system *(writes)* |
| `autoupdate-status` | eFa-next updates |
| `autoupdate-set` | Automatic eFa-next updates *(writes)* |
| `update-check` | Check for an eFa-next update now *(writes)* |
| `update-install` | Install the eFa-next update now *(writes)* |
| `update-rollback` | Update: back to the version before *(writes)* |
| `update-now` | Update now *(writes)* |
| `update-system-run` | Update system: background job *(writes)* |
| `update-post-boot` | Update system: check after reboot *(writes)* |
| `update-run` | Automatic update job *(writes)* |
| `os-check-status` | Check after package updates |
| `os-check-run` | Check after package updates: run now *(writes)* |
| `maintenance-set` | Maintenance mode *(writes)* |
| `load-set` | Load warning limits *(writes)* |
| `load-notify` | Mail a load warning |
| `release-upgrade-status` | Release upgrade to EL10: status and log |
| `release-upgrade` | Release upgrade to EL10 *(writes)* |
| `reboot` | Reboot *(writes)* |
| `halt` | Halt *(writes)* |
| `milter-chain-set` | Milter order *(writes)* |
| `extra-service-set` | Watch an extra service *(writes)* |
| `mariadb-repair` | Repair databases *(writes)* |

## Console only and internal

Commands that no page shows: some are for the console only (for example `admin-password`, `clone-reset`, `menu`), others are used by the services of eFa-next themselves.

| Command | Title |
|---|---|
| `admin-2fa-verify` | Check the 2FA code of the main admin |
| `admin-password` | Web admin password (console only) |
| `audit-note` | Strict audit log: an action of the web interface |
| `audit-purge` | Audit log: remove old entries |
| `backup-targets-eu-lock` | Backup targets outside the EU: lock |
| `blocklist-import` | IP blocklists: import a file (efa-migrate) |
| `blocklist-run` | IP blocklists: background job |
| `clone-reset` | Cloned host: new per-host secrets (console only) |
| `cluster-content-apply` | Cluster: apply the link key of the master |
| `cluster-dkim-apply` | Cluster: apply the DKIM keys of the master |
| `cluster-snapshot` | Cluster: the shared settings of the master |
| `console-2fa-enroll` | Own 2FA of a console admin (SSH): set up |
| `console-2fa-verify` | Check the 2FA code of the console admin |
| `dash-stats` | Dashboard values |
| `disclaimer-export` | Disclaimer: export as ZIP |
| `disclaimer-provision-apply` | Disclaimer: one call of a source (efa-dkim-api) |
| `disclaimer-sync` | Disclaimer: take over the folder of the master (cluster) |
| `dkim-generate` | RSA key: generate |
| `dkim-generate-ed25519` | Ed25519 key: generate |
| `dkim-provision-apply` | DKIM: one call of a source (efa-dkim-api) |
| `events-run` | Events: background job |
| `flow-set` | Mail flow picture: moving letters |
| `flow-status` | Mail flow picture |
| `form-check` | Forms: current values (check) |
| `legal-accept` | Legal texts: confirm |
| `legal-status` | Legal texts |
| `log-show` | Show a log |
| `mail-check` | Check a mail: the verdict of rspamd, nothing is kept or learned |
| `mail-show` | Mail: details and headers |
| `mailreport-run` | Mail report: background job |
| `menu` | Text menu with the pages of the web interface (console only) |
| `metrics` | Values for Prometheus |
| `ml-settings` | Own model: settings |
| `mta-sts-unserve` | MTA-STS: remove the policy server of 6.0.0.4 from nginx |
| `network-harden` | Network: no automatic profiles for new interfaces |
| `neural-settings` | Neural network: settings |
| `oidc-finish` | Single sign-on: finish a login |
| `oidc-start` | Single sign-on: start a login |
| `outbound-hold-run` | Recall and confirmation: the job of every minute |
| `outbound-hold-set` | Recall window, or confirmation of attachments to new recipients |
| `outbound-hold-status` | Recall window and confirmation of attachments |
| `passkey-login` | Passkeys: log in without a password |
| `passkey-login-options` | Passkeys: start a login |
| `passkey-register-options` | Passkeys: start a new one |
| `quarantine-content` | Quarantine: text |
| `rbl-apply` | Blocklists: write the rspamd settings |
| `redis-tune` | Limit the memory of Redis |
| `refusal-note` | Audit log: a change the web interface refused to this login |
| `resetup` | Re-Setup: EU link, frameworks and 2FA |
| `sanesecurity-run` | Sanesecurity: background job |
| `sasl-apply` | Logins of port 587: apply |
| `service-restart` | Restart a service |
| `session-check` | Web login: still on |
| `session-open` | Web login: record |
| `setup-failed-note` | Package setup: the audit line of a failed step |
| `setup-variant-apply` | Setup variant of the setup wizard |
| `ssh-profile-revert` | SSH profile: back unless confirmed (job) |
| `standards-preview` | Security standards: preview of a choice (reads only) |
| `submission-pam-set` | Port 587: logins of system accounts (PAM) |
| `threat-run` | Attack alert: background check |
| `tls-profile-upgrade` | TLS profile: keep the limit after an update |
| `token-check` | Check an API token |
| `totp-import` | 2FA of the main admin (or a console admin) from the setup wizard |
| `update-staged-set` | Staged updates: the master decides when this node installs |
| `uq-content` | Held mail: text |
| `uq-link-use` | Link in a digest: do it |
| `uq-link-view` | Link in a digest: what it does |
| `user-verify` | Check a login |

Back: [Manual](README.md)
