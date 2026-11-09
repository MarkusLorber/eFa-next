# eFa-next features (6.0.0.5)

Everything eFa-next 6.0.0.5 contains. "Off by default" means the function is there and switched on by the admin. Every
function is a command of `efactl` and, where it has settings, a page of the web interface, with the same checks and the same
audit log. Deutsch: [FEATURES.de.md](FEATURES.de.md).

## Mail filter and detection

- **rspamd with Redis** checks every mail: spam score, SPF, DKIM, DMARC (the policy of each sender), ARC, greylisting. [Protection](protection.md)
- **ClamAV** scans for viruses, with the Sanesecurity signatures (low-risk files, checked by their GPG signature). [Protection](protection.md)
- **More ClamAV signatures**: URLhaus, InterServer, SecuriteInfo, each after its terms are confirmed. Off by default.
- **Extra virus scanners** over ICAP and the external services of rspamd (the operator's scanner and licence). Off by default.
- **DNS blocklists** through the own resolver (Spamhaus with DQS key, SpamCop, PSBL and more), terms linked and confirmed. [Blocklists](rbl.md)
- **IP blocklists** of feeds and own lists, applied in the firewall. [Protection](protection.md)
- **Postscreen** on port 25 with pregreet check and weighted blocklists.
- **Sender lists and rules** for addresses, domains, IP addresses and patterns. [Protection](protection.md)
- **Rule engine**: policies and routing by sender, domain, recipient, tenant or directory group. [Protection](protection.md)
- **Bayes and the neural network** of rspamd, trained by the spam reports admins approve.
- **Own fuzzy store**: variants of approved spam recognised again; nothing leaves the host. Off by default.
- **Community fuzzy store**: an encrypted fuzzy store run by operators, opt-in. Off by default.
- **Threat feeds**: abuse.ch URLhaus and ThreatFox, STIX/TAXII, MISP and plain lists into local lists. Off by default. [Threat feeds](threat-feeds.md)
- **Outbreak filter**: a new wave of the same attachment or text is held back for 15 to 60 minutes, then checked again. Off by default.
- **Check after delivery**: hashes of delivered mail compared with each feed update; hits reported. Off by default.
- **Spam traps**: trap addresses teach Bayes and the fuzzy store and score the sending servers. Off by default.
- **Newsletters (graymail)**: detected by their list headers, per user delivered, marked or held. Off by default.
- **Own spam limits** per user within the limits of the admin. Off by default.
- **Young domains** score higher; the days as a choice.
- **Address harvesting**: a source probing many unknown recipients is noted and banned. [Address harvesting](address-harvesting.md)
- **Greylisting and sending limits** per sender, sender domain and tenant.

## Phishing and impersonation

- **Impersonation and BEC**: forged display names against a VIP list, lookalike and cousin domains, sender and recipient relations. [BEC](bec.md)
- **BEC patterns**: a known sender writing at a new hour, much more than usual or to new recipients scores higher.
- **Lookalike watch**: new certificates of domains that imitate your own or your partners' (Certificate Transparency). Off by default.
- **Link check on click**: links rewritten to a signed redirect and checked again when clicked, with hints on dangerous links. [Link check](link-check.md)
- **QR codes** in pictures and PDF files are read and their links checked. Off by default.
- **Phishing reports and warning banner**: a report address per domain, a banner in suspicious mail. [Phishing & banner](phishing-and-banner.md)
- **Outlook add-in** to report a mail with one click. [Protection](protection.md)
- **BIMI**: the logo of a sender with a strict DMARC policy, checked as SVG Tiny PS. Off by default.
- **Taken-over accounts**: a sender over its sending limit is held until an admin releases it. Off by default. [Taken-over accounts](hijacked-accounts.md)

## Attachments and sandbox

- **Attachment filter** with real type detection, also inside archives, and dangerous file names. [Attachments & CDR](attachments-and-cdr.md)
- **Content disarm (CDR)** of Office and PDF files, or conversion to PDF. [Attachments & CDR](attachments-and-cdr.md)
- **Office macros** read by olevba; auto-start macros and suspicious calls score. Off by default.
- **Encrypted ZIP archives** opened with a password found in the mail and scanned. Off by default.
- **Sandbox**: suspicious attachments to the own CAPEv2 sandbox; the mail waits for the verdict. Off by default.
- **Own blocks**: SHA-256 of attachments and YARA rules, per tenant or for all. [Own blocks](own-blocks.md)
- **Virus scan limits**: time and size per mail, fail open or closed, per tenant.

## Quarantine, portal and mail handling

- **Quarantine** with release and delete; **held mail** for users with a daily digest. [Mail & quarantine](mail-and-quarantine.md)
- **User portal** (own process) for the own quarantine, sender lists, spam limit, 2FA and passkeys.
- **Mail log** in MariaDB, kept by age or size, with an indexed **message search** and CSV/JSON export.
- **Mail queue** page: view, hold, release, delete, re-send.
- **Spooling** while the mail server behind is down, with reachability per destination. [Spooling](spooling.md)
- **Emergency access**: received mail readable while the mail servers behind are down. Off by default.
- **Recall window**: outgoing mail of users waits 1 to 5 minutes and can be withdrawn. Off by default.
- **Misdirected-mail protection**: an attachment to a new recipient waits for a confirmation. Off by default.
- **Role addresses** (postmaster@, abuse@, security@ ...) sent on per domain, and a security.txt generator. [Role addresses](role-addresses.md)
- **Job applications** per domain accepted from all or from listed addresses only. [Job applications](job-applications.md)
- **Disclaimers and signatures** per domain, tenant or group, with fields from LDAP/AD. [Disclaimer API](api-disclaimer.md)
- **Outbound DLP**: IBAN, credit card, tax and social numbers and own patterns. Off by default.
- **Password PDF**: mail and attachments as an AES-256 PDF on request. Off by default.
- **Archive forwarding** and **journal reports** to an external archive. [Archive](archive.md)
- **Newsletter-friendly sending** for bulk senders. [Bulk](bulk.md)
- **Taking mail back** out of mailboxes over IMAP after a late hit. Off by default.
- **Mail reports** hourly, daily and weekly, as a page or by mail.

## Encryption

- **TLS 1.2 and 1.3 only**, forward secrecy with AEAD ciphers, after RFC 9325 and BSI TR-02102-2, for all services. [TLS profiles](tls-profiles.md)
- **TLS profiles** (BSI, RFC 9325, Mozilla modern) and a post-quantum hybrid key exchange where OpenSSL has it.
- **TLS with partners**: TLS, verification or DANE required per partner domain. [TLS partners](tls-partners.md)
- **S/MIME and PGP** at the gateway: sign, encrypt, decrypt per address or domain. Off by default. [S/MIME & PGP](smime-pgp.md)
- **DKIM** with RSA (2048 bits and more) and Ed25519, rotation, a provisioning API. [DKIM API](api-dkim-provisioning.md)
- **DMARC reports, DANE and MTA-STS**: reports read and shown, MTA-STS policy written and checked. [DMARC, DANE, MTA-STS](dmarc-dane-mta-sts.md)
- **Domain check**: MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC, DANE, BIMI and PTR as a light per domain. [Domain check](domain-check.md)
- **Let's Encrypt** with a key that stays at renewal and a DANE-safe rollover.
- **Keys in a hardware module** (PKCS#11) for the backup signature and S/MIME. Off by default. [HSM](hsm.md)
- **Held mail encrypted at rest** (AES-256-GCM per mail, keys per tenant).

## Login, roles and tenants

- **Two-factor login** (TOTP) for every user, each with an own secret and recovery codes; none asked where none is set up. [Two-factor](two-factor.md)
- **Passkeys and security keys** (WebAuthn) as second factor or alone, per role. [Two-factor](two-factor.md)
- **Single sign-on** with OIDC and **directory login** with LDAP/AD, groups mapped to roles. [Users & access](users-and-access.md)
- **Roles and permissions**: super, tenant, domain, helpdesk, user, and own groups with a permission per command. [Users & access](users-and-access.md)
- **Tenants** for service providers: customers with their domains, users and settings in three levels. [Domains & tenants](domains-and-tenants.md)
- **Sessions** listed and ended; a rights change ends the sessions of that account.
- **Failed logins**: one lockout for web, portal, API and port 587. [Login lockout](login-lockout.md)
- **Admin access by network** and the password asked again for critical changes. [Security model](security-model.md)
- **Four eyes** for critical changes. Off by default. [Config history](config-history.md)
- **REST API** with tokens per user and **Prometheus** metrics.

## Privacy and EU

- **EU relation**: report services outside the EU only after a typed confirmation, strictly audited. [EU relation](eu-relation.md)
- **Backup targets in the EU only**, with a backup password. [Backup in the EU](backup-eu.md)
- **GDPR requests**: access to and erasure of all data of one address. [GDPR requests](gdpr-requests.md)
- **Pseudonyms in the mail log** after the set days. On for new installs.
- **Retention** per tenant, every purge audited.
- **Header privacy**: outgoing mail without internal Received lines and client headers. [Header privacy](header-privacy.md)
- **Tracking protection**: tracking pixels and tracking parameters out of incoming mail. Off by default. [Privacy](privacy-and-reason.md)
- **Privacy evidence**: drafts of the record of processing and the TOM from the real settings. [Templates](datenschutz/README.md)
- **NIS2 incident reports** with deadlines and the report text. [NIS2](nis2-incident.md)
- **EU conformity** map of GDPR, CRA, NIS2 and ePrivacy to the functions. [EU conformity](compliance/EU.md)
- **Privacy by default**: short retention, no content in the log on new installs.

## Operation

- **Cluster**: a master with clients or an HA cluster over mutual TLS, staged updates. [Cluster](cluster.md)
- **Backups** encrypted (OpenPGP AES-256) and signed (Ed25519), to S3 or SFTP targets. [Backup targets](backup-targets.md), [Signed backups](backup-signature.md)
- **Configuration history**: each change kept with a diff, one change taken back. [Config history](config-history.md)
- **Operation without internet**: local mirror and signed offline bundles. [Offline](offline.md)
- **Updates** only from releases with a valid signature, automatic if wanted.
- **Monitoring**: dashboard, milter health, events, load display. [Monitoring](monitoring-and-reports.md)
- **SIEM export** over TLS (syslog), **EVE-JSON** export, OpenTelemetry. [EVE export](eve-export.md)
- **Wazuh agent** setup. [Wazuh](WAZUH.md)
- **Internal DNS servers** and the domains they answer, with DNSSEC per domain. [DNS forwarding](dns-forwarding.md)
- **More network interfaces** and extra uplinks per sender domain. [Interfaces](interfaces.md)
- **Migration from eFa 5** with all Postfix settings and the sender lists. [Migration](migration.md)

## Install and setup

- **One command** installs on a minimal AlmaLinux, Rocky Linux or RHEL 9: repositories with checked keys, tools, clock. [Install](install.md)
- **Setup wizard** in English and German: legal notice, guided or manual setup, EU link, frameworks, network, 2FA, check. [First steps](first-steps.md)
- **Guided setup**: frameworks (NIS2, DORA, BSI, ISO 27001 ...) raise the settings, 2FA for main and console admin required.
- **Re-Setup** on a running system, only raising.
- **Standard and Expert view**, English and German interface, search over pages and settings, dark mode.

## Security of the system

- **SELinux enforcing**, own policy module; systemd sandbox for the services that parse mail.
- **Security minimum guard**: TLS settings under the limit go back or the service stays stopped. [Security model](security-model.md)
- **CVE watch** of the installed packages with a red banner for reachable holes, optional self-lockdown of the web services. [CVE watch](cve-watch.md)
- **Hardening report** (also as PDF) after BSI TR-02102. [Hardening report](hardening-report-pdf.md)
- **Audit log** with a strict mode and a daily signed anchor. [Audit anchor](audit-anchor.md)
- **Root SSH** warning and switch; the console admin with own 2FA over SSH.
- **No Apache, PHP or Perl** of its own; reproducible builds and an SBOM per release.

## Known limits

- The own fuzzy store works per host; a store shared by the nodes of a cluster is not built.
- BIMI checks the logo, not the VMC/CMC certificates.
- Perl comes at runtime only with MariaDB and rspamd, which need it themselves.
