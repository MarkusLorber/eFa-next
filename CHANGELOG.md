# Changelog

## 6.0.0.5 (release date: pending)

**Hosts on 6.0.0.4 take this release once by hand.** The packages are now `eFa-next` and `eFa-next-base` (first published
release with the new names). The update of 6.0.0.4 looks only for `eFa` and `eFa-base` and does not offer it:

    sudo curl -fsSL -o /etc/yum.repos.d/efa-next.repo https://repo.efa-next.eu/el9/efa-next.repo
    sudo dnf --enablerepo=efa-next upgrade eFa-next eFa-next-base

The command replaces `eFa` and `eFa-base` as an upgrade; the settings stay. After that the update display and the automatic
update work again.

### Setup variant (guided or manual)
- Setup wizard: a note on presets and recommendations to confirm (Text A), then the setup variant. **Guided** asks for the EU
  link and the frameworks (chips, several at once) and raises the settings to match; **manual** asks the EU question only.
  English by default, German as the alternative. Each confirmation is kept with its time and the SHA-256 digest of the text as
  shown, handed to efa-apply (SETUPVARIANT, EULINK, EULINKCONFIRM, FRAMEWORKS, NOTICEACCEPTED) and in the audit log.
- EU link: with it the EU rules apply hard (no typed exception for services outside the EU, the fields greyed out with the
  reason); without it only after a tick and the typed phrase `at my own risk` / `auf eigenes Risiko`, a yellow note on the
  dashboard, and a new EU link (an answer yes, an own domain under an EU ending) locks the EU settings again.
- Guided: 2FA (TOTP of 5r) for the main admin set up in the wizard (QR code, first code, ten recovery codes), and for the
  console admin by SSH with the same code through the login shell `efa-console-2fa` (fail closed; local console without).
- Frameworks (docs/compliance/frameworks.md): NIS2, DORA, BSI, ISO 27001 and others raise 2FA for all admins, the days of the
  audit log, the TLS profile or the daily security check, never lower; a framework without a setting in eFa-next shows a note.
- Re-Setup (Security, Setup variant, `/resetup`, `efactl resetup`): the same questions for a running system, old and new first,
  a backup, then raise only; guided to manual with password and 2FA code, 2FA stays on. After an update or migration nothing
  changes; the dashboard offers Re-Setup once.
- Security minimum guard (docs/security-model.md): a path unit on the TLS settings of postfix, nginx and dovecot, a check before
  each start of them, in efa-apply and once a day. A value under the limit goes back to the TLS profile; if that fails the
  service stays stopped (fail closed) and the dashboard shows red. Audit log and event with file, values, digest, owner,
  `rpm -V` and the logins of the journal; a copy of the file in `/var/lib/eFa/tamper/`; a mail to the admin.

### Setup wizard
- In the look of the web interface: logo bar with the English/Deutsch switch, "Step n of m", a progress bar and the groups
  (Start, Server, Network, DNS, Admins, System, Mail server, 2FA, Check), Back on the left and Next on the right on every page
  after the first. Each step has a title, one sentence, an example and its error below the field; values are prefilled with
  those in effect on the host; long legal texts scroll in a box. Checks while typing (/wizard.js), every page works without it.
  Every text translated (the i18n check covers the wizard).
- The language can be switched on every page and stays; it keeps the step, the values and the confirmations given, and becomes
  the language of the main admin and of the login page. Fixed: a switch dropped the confirmations, and the admin had to go
  through the whole wizard twice to reach 2FA.
- Netmask as a list (/24 (255.255.255.0)); 255.255.255.0, /24 and 24 are taken, only a mask that is not contiguous is refused.
- The answers survive a restart of the wizard (/run/efa-init/answers.json, 0600, removed after the setup); after the setup code
  the walk goes on where it was. Each step is logged in the journal, without values.
- Each user its own 2FA (owner's rule): the guided wizard sets up the main admin (web) and then the console admin (SSH), each
  with its own QR code, code, recovery codes and PDF; the app entries name user and host. SSH asks the console admin for the
  code of its own 2FA only, never the one of the main admin; no 2FA set up means no code asked, the login noted, and in the
  guided setup a red dashboard line until it is set up. The console admin's 2FA is a root file (/etc/eFa/console-2fa,
  0600), not in the database, so SSH works while MariaDB is down (`sudo efactl console-2fa-enroll`, or a reset by a super admin with
  re-authentication). Five wrong codes lock that user, not the others.
- 2FA: the ten recovery codes in a grid with Copy and Download as PDF (made in memory, not stored, gone once confirmed); Next
  only after "I have saved the codes". A wrong code shows the time of the server and, more than 30 s off against the browser,
  the minutes and a button to set the clock now.
- New step Time servers after the time zone: the NTP servers of chrony.conf, editable; Next sets the clock (efa-apply
  --time-sync: sources, burst, makestep, waitsync) and shows the offset, or why not (UDP 123, DNS, network).
- Check page grouped with Edit per group. After the start the page shows the new address in large letters, checks it and opens
  it once it answers (CSP only that origin); hints after 5 minutes. The self-signed certificate carries the static IP addresses.
- Fixed: after the setup code the page seemed to hang. An older Werkzeug made the redirect absolute with http (what waitress
  sees behind nginx), and form-action 'self' blocked it; redirects are relative now, in the wizard and the web interface.
- Fixed: after a wrong 2FA code the wizard showed the server time in UTC only, which read as an hour off. It now shows the
  local time with its zone, then UTC.

### Web interface
- Login: an expired or missing form token leads back to the login with a note and the user name (never password or code),
  audited as csrf_expired, not counted as a failed login. Error pages (400, 403, 404, 405, 500) in the look of the interface,
  translated, without details. Before the login the language of the setup, else the browser; English/Deutsch switch.
- Own cookie names for the wizard, the admin interface and the portal (__Host-efa-init, __Host-efa-admin, __Host-efa-portal):
  the cookie of the wizard no longer meets the login on the same address. Logged-in sessions end once with the update.
- Page times: postconf answers are kept in /run/efa-postconf.json until main.cf or postconf changes (settings read 140 ms →
  a few ms, the users page was 171 ms); efactl settings asks postconf once instead of six times; the status reads of the held
  mail page are kept 30 s like the others.
- Security page: the reads of postconf, sshd -T and fail2ban-client are kept like the other slow reads (30 to 60 s), and the
  TLS profile asks postconf once instead of once per value, so the page stays within its 100 ms budget after a restart.
- Dashboard: the notes on the disk use of the emergency copies and on own S/MIME certificates that end soon come from the
  daily job; the status call reads only its result (no database query, no openssl per certificate).
- Accessibility (P5): own WCAG 2.1 AA checks in the self-tests (labels, names, language, heading, tab order, focus, contrast
  light and dark) over the portal, the login, the link pages and the Outlook task pane; borders, the warning colour and the focus
  ring of fields darker for 3:1, a heading on the login and link pages (docs/faq.md).
- Search in the admin interface (9f): a field at the top of the menu (key `/`) over pages, cards, fields, help texts and
  pulldown values, English and translated; umlauts, ß, parts of words and a few synonyms; only what the rights show; posted, so
  the terms stay out of the logs; suggestions while typing (docs/faq.md).
- Web interface (UI-2): the content follows the dark mode of the system as well (cards, forms, tables, notes, the live log, the
  footer); the light colours stay as before. This lifts the known limit of 6.0.0.4.
- Web interface (UI-1): the notices and warnings efactl builds with values (new interface found, update available, terms of a
  blocklist not confirmed, DKIM keys, SSH root, cluster master, SIEM, harvesting) are in the language catalog as templates and
  show translated with their values (`_text` in efactl, `efa_i18n.runtime`).

### Protection
- More ClamAV signatures (5v a): URLhaus, InterServer and SecuriteInfo as sources in the job of the Sanesecurity signatures,
  each off by default and on only with its terms confirmed, each file loaded by clamscan before it counts.
- Office macros (5v b): olevba of oletools (EPEL) reads the VBA macros of Office files in the sandboxed service efa-unlock;
  macros that start on opening and suspicious calls count as rspamd symbols; off by default.
- Spamhaus error codes (5v i): the blocklist page names what 127.255.255.254 and 127.255.255.255 mean and what helps.
- Check after delivery (5v j): hashes of the links, hosts and attachments of delivered mail kept for 72 hours (never the links)
  and compared after each feed update; hits to the admins, as event and audit, optionally warned to the recipients; off by
  default.
- Taking mail back (N6): a hit can also be moved or deleted in the mailboxes over IMAP with TLS and a master login of the own
  mail server; no cloud API; off by default (docs/protection.md).
- Lookalike watch (M4): new certificates (Certificate Transparency, crt.sh, once a day) of domains that imitate own or partner
  domains (homoglyph, IDN, typo, other ending, own name in front); hits on the dashboard, by mail, as event, and into a map
  scored EFA_LOOKALIKE_CT; off by default, with EU relation only after the typed confirmation (docs/protection.md).
- Tracking protection (M1): tracking pixels (1x1 and known tracking hosts) and tracking parameters of links (utm_*, fbclid,
  gclid, mc_eid ...) out of incoming mail in the content milter, per domain, tenant or all; sender exceptions and own hosts;
  local lists only; off by default (docs/privacy-and-reason.md).
- Sandbox (14): suspicious attachments to the own CAPEv2 sandbox (HTTPS, token as systemd credential); verdicts kept by hash
  for 7 days in the sandboxed service efa-sandbox; a new file defers its mail until the verdict is there (30 minutes at most,
  then marked); malicious rejects; off by default.
- Extra virus scanners (7): ICAP and the engines of rspamd external_services (operator's scanner and licence), each rejecting or
  marking; a scanner outside the own networks with EU relation only after the typed confirmation; none by default.
- Spam traps (M6): trap addresses per domain; their mail teaches Bayes and the own fuzzy store and is dropped; the sending
  servers of the last 7 days score EFA_TRAP_IP; only the address of the server is kept, for 30 days.
- Community fuzzy store (P7): a fuzzy store run by the operators (for example in the EU) asked encrypted with its key; with
  sharing on, the hashes of approved spam go there too, never content or addresses; opt-in after the EU rule.
- Own fuzzy store (N4): the fuzzy worker of rspamd on 127.0.0.1 with Redis, fed with the spam admins approve from the reports;
  variants count as EFA_FUZZY_LOCAL; nothing goes out; off by default. A store shared by the nodes of a cluster is not built yet.
- Outbreak filter (11): a new wave (the same attachment or text to many recipients within minutes) is deferred with a
  temporary error until it is 15, 30 or 60 minutes old, then checked again with fresh signatures; known senders (BEC pairs)
  and exceptions pass; counters in Redis for a day; off by default.
- Encrypted archives (10): encrypted ZIP archives (ZipCrypto) opened with a password found in the subject or text (up to 10
  candidates, 5 s) in the sandboxed service efa-unlock and each file scanned by clamd in memory; a virus rejects, an opened clean
  archive takes back the mark, one that stays shut is marked as before; off by default (docs/protection.md).
- QR codes (5x, 9): links in QR codes of pictures and PDF files, read by zbar in a sandboxed local service, count as rspamd
  symbols, more in mail almost without text and when a threat feed names them; off by default.
- BIMI (5w): the logo of a sender with DMARC pass and quarantine or reject, checked as SVG Tiny PS, as BIMI headers and a bimi result;
  headers of the sender removed; certificates not checked; off by default.
- Threat feeds (12, N1, 5v c): abuse.ch URLhaus and ThreatFox, STIX 2.1/TAXII 2.1, MISP and plain lists into four local lists for
  rspamd (URLs, domains, SHA-256, IPs), fetched hourly and only when changed; terms per feed; off by default (docs/threat-feeds.md).
- More protection (5v): postscreen on port 25 with pregreet and weighted blocklists (new installs); active HTML out of mail per
  domain; young-domain days as dropdown; systemd sandbox for rspamd, clamd, freshclam, redis, unbound and nginx with a check and
  a way back per service; docs/design-decisions.md names what is not built.
- Link check (item 4): the warning page gives short hints how to spot dangerous links, and an own text per tenant; the tenant is
  signed into the link token.
- Newsletters and own spam limits (items 2, 3): graymail detected by its list headers, per user delivered, marked or kept in the own
  quarantine; users set their own spam limit within the limits of the admin. Both off by default.
- BEC patterns: the habits of a known sender (hours, mails a day, recipients here) are kept in Redis; a known sender that writes at a
  new hour, much more than usual or to new recipients gets EFA_BEC_PATTERN. Score 2 on new installs, 0 (off) after an upgrade.
- Taken-over accounts (A1): a sender over a sending limit is held with all its further mail until an admin releases it; the admin
  gets a mail (docs/hijacked-accounts.md). Off by default.
- Greylisting and sending limits (9j): delay and expiry of greylisting as dropdowns; the sending limits of the outbound check
  also per sender domain and per tenant over all their senders, with the same notice and action (Mail routing, Submitters).
- Own blocks (M5): SHA-256 of attachments and YARA rules, each for only one tenant (default) or for all tenants (super admin
  or security.rules.global); a tenant rule counts only for mail to that tenant; YARA through ClamAV after a test load with
  clamscan; every change and scope switch in the audit log (docs/own-blocks.md).
- Virus scan limits (C7): seconds and size per mail for clamd, seconds for all checks of rspamd, and fail open or closed when
  the scan fails, globally and per tenant. Fail closed defers the mail (451), one too large to scan is rejected. On for new
  installs with fail closed; an upgrade keeps the old behaviour.

### Mail handling
- S/MIME and PGP at the gateway (15): sign, encrypt (always or if possible) and decrypt with keys of addresses or whole domains
  (domain certificates between gateways); own keys made on the host (S/MIME with CSR, PGP Ed25519), partner certificates and
  keys imported or collected from signed mail; a recipient without a key under "always" is refused, never sent in clear;
  keys for efa-outbound only, as systemd credentials; off by default (docs/smime-pgp.md).
- Journal format of the archive handover (6/8h): a journal report per mail with the envelope (sender, all recipients with BCC,
  time, queue ID) and the mail as message/rfc822, made after the verdict of rspamd and before a quarantine hold, sent through a
  local port of Postfix without filters; fail closed (docs/archive.md).
- Outlook add-in for reports (13): manifest per report address; a static task pane under /outlook/ (nginx, no own service)
  opens a new message to the report address with the open mail attached (docs/protection.md).
- AD signatures: placeholders {{name}}, {{title}}, {{phone}} ... in the disclaimer templates, filled per sender from LDAP or
  Active Directory (read hourly, paged, handed to efa-outbound as a systemd credential); escaped in HTML; lines of empty
  fields left out; off by default (docs/api-disclaimer.md).
- Emergency access (5n): received mail readable while the mail servers behind are down, from the queue and (per domain or
  tenant, 1 to 30 days, off by default) from a copy sealed with the key of the tenant; users see their own mail in the portal,
  admins with the right mail.emergency.read and a reason; text only, attachments as files, dangerous ones after a typed yes;
  every access audited (docs/mail-and-quarantine.md).
- Recall window (P6): outgoing mail of logged-in users waits 1 to 5 minutes and can be withdrawn in the portal; per domain or
  tenant, off by default.
- Misdirected-mail protection (P1): a mail with attachment to a recipient the sender never wrote to waits for a confirmation by
  link; not confirmed within 1, 4 or 24 hours it goes back to the sender; fail closed; per domain or tenant, off by default
  (docs/mail-and-quarantine.md).
- Role addresses (6b): postmaster@, abuse@, security@, hostmaster@, webmaster@, noc@, the report addresses and the CRA and NIS2
  contacts per domain sent on to set targets with own SRS (bounces back through the hash check); on/off and targets per domain,
  tenant and all, off by default; postmaster@ and abuse@ never refused as spam; targets outside the EU only with the typed
  confirmation; security.txt generator (docs/role-addresses.md).
- Domain check (6a): MX, SPF (syntax, 10 lookups, end), DKIM against the own keys, DMARC, MTA-STS, TLS-RPT, DNSSEC, DANE,
  BIMI, PTR/HELO and what public resolvers (DNS4EU, Quad9) see differently, as a light per domain with the ready DNS records;
  every 6 hours and on demand; dashboard note and weekly mail while SPF, DMARC, MTA-STS or TLS-RPT are missing; on for new
  installs, off after an upgrade (docs/domain-check.md).
- MTA-STS (9p): eFa-next only writes the policy of each domain (mx from the real MX, to copy or download as mta-sts.txt) and
  checks the one served on the own web server once a day (strict HTTPS, no redirect, 64 KB): differences, expired certificate,
  enforce with a missing MX, missing or old TXT id warn on the dashboard. The update removes the nginx server of the policies
  of 6.0.0.4; the policies stay (docs/dmarc-dane-mta-sts.md).
- Job applications (8j): per domain with EU relation allowed to all (confirmed) or only to listed addresses; others refused at DATA
  with the approved text, nothing stored; exceptions for recruiters (docs/job-applications.md).
- DKIM selectors seen (6c): every selector in and out with first/last time, results and key length, warnings for new selectors of own
  domains, weak keys and failures; CSV/JSON export.
- TLS with partner domains (A2): per partner, TLS required for mail to it (encrypt, verify or DANE) and/or for mail from it
  (450 without TLS), under Mail routing (docs/tls-partners.md).

### Privacy and EU
- Privacy evidence (M3): a draft of the record of processing and the TOM from the real settings, for all or one tenant, as
  Markdown or PDF (docs/datenschutz/README.md).
- NIS2 incident reports (O3): incident records with the deadlines of 24 h, 72 h and a month, and the report text (Markdown or
  PDF) with the timeline of audit entries and warnings of the server (docs/nis2-incident.md).
- EU conformity (S2): docs/compliance/EU.md maps GDPR, CRA, NIS2, ePrivacy/TKG to the functions with their status; part of
  the release checklist.
- EU relation (EU): per server and domain; with it no DMARC failure reports, report services outside the EU or of unknown seat
  only after a typed confirmation, strictly audited; a new install answers yes, an update asks on the dashboard (docs/eu-relation.md).
- Backup targets only in the EU (5z): Hetzner, Scaleway, IONOS, STACKIT or an own server confirmed in the EU; providers outside
  the EU refused by name and CNAME; existing ones locked by the update with a notice; a backup password is needed (docs/backup-eu.md).
- Held mail encrypted at rest (D3): AES-256-GCM per mail, the key wrapped per tenant with X25519; the storing service has only the
  public keys, root the private ones. On for new installs, off after an upgrade.
- GDPR requests (D1): access to and erasure of all data of one mail address (mail log, headers, quarantine, spam reports, BEC
  relations), audited with its pseudonym and the reason (docs/gdpr-requests.md).
- Pseudonyms in the mail log (D2): after the set days the addresses keep only their domain and an HMAC pseudonym, the subject goes;
  exact searches of admins still find them. On for new installs after 14 days, off after an upgrade.
- Retention (9h): a tenant keeps its mail log and its reports for own days; every purge and every change of days is in the audit
  log; the retention list names the GDPR templates.
- Header privacy (M2): outgoing mail of all senders, of chosen sender domains or submitters leaves without Received lines, client
  addresses and mail program headers; headers covered by a DKIM signature of the sender stay (docs/header-privacy.md).

### Security
- Quarantine for users: mail with an attachment the attachment checks block (program, dangerous ending, encrypted archive,
  macro) or with a failed virus scan is admin-only like a virus. With such an attachment the virus scan did not run, so a virus
  in it could be released by its recipient alone. An upgrade writes the rule anew where the quarantine for users is on.
- Audit: an action in the user portal (release, delete, request) names the portal user (`user portal (<user>)`) in the audit
  log and in the quarantine, not only the portal.
- No systemd sandbox on the services of the distribution (5v h): with NoNewPrivileges, unbound, redis and freshclam could not
  enter their SELinux domains (unbound did not start, and the host had no DNS). An install or upgrade removes such sandbox files
  of test builds; a unit put on the list later must stay active after its restart, else it runs without and the dashboard says so.
- Keys in a hardware module (P3): the signing key of the backups and own S/MIME keys optionally in an HSM through PKCS#11 (pkcs11
  provider of OpenSSL 3); software keys by default. DKIM and ARC stay software keys: rspamd has no PKCS#11 (docs/hsm.md).
- Four eyes (P2): critical changes of admin logins (rules, releases, switching protection, rights) wait for a second admin;
  emergency path for a super admin with a reason; per tenant or all, off by default (docs/config-history.md).
- CVE watch (9o): every 15 minutes and after each package change, the OVAL data (with CVSS vector and CWE), the signed advisory
  feed of eFa-next and the exploited list of ENISA (EUVD) against the installed packages; holes reachable over the network in
  listening or mail packages warn at once (red dashboard banner, mail to the super admins, event, audit), the rest weekly;
  mute with a reason; cluster view on the master; only GETs; on by default.
  Self-lockdown of the web services (9o-b) at an unpatched web-stack hole without login named by the distribution or the
  signed feed: off by default, super admin only; Let's Encrypt renews standalone during the lock (docs/cve-watch.md).
- Passkeys and security keys (5s): WebAuthn as second factor or passwordless per role, several keys per login, own script and
  checks (CBOR with limits, ES256/EdDSA/RS256, one-time challenges, origin, counter), only with a trusted certificate for the
  host name (docs/two-factor.md).
- Two-factor login (5r): TOTP after RFC 6238 for admins, users of the portal and the main admin, set up with a QR code of an own
  encoder; ten recovery codes; required per role if set; reset by a higher admin; re-auth of critical changes asks for the
  code too; secrets encrypted per user (docs/two-factor.md).
- TLS reports and certificate keys (P8): failed TLS sessions of the TLS reports on the dashboard; Let's Encrypt keeps the key at
  renewal, and `letsencrypt-rollover` changes it DANE-safe (prepare, publish the new TLSA record, switch only when DNS shows it).
- Signed backups (C2): a manifest with the SHA-256 of each file, signed with an Ed25519 key of the host, inside every backup;
  the restore checks signature, signer and every file before it changes anything. A backup of another host needs its
  fingerprint, an unsigned one (6.0.0.4 or older, efa5-export) a typed yes, logged (docs/backup-signature.md).
- Strict audit log (B2): a daily anchor signed with an own Ed25519 key (last MAC, entries, SHA-256 of the closed files, link
  to the anchor before), sent out as the event `audit_anchor`; `efactl audit-anchor-verify` and a check in the hardening report
  (docs/audit-anchor.md).
- Failed logins (B6): one lockout for the web interface, the user portal, the API and port 587 by Fail2Ban per address, with
  tries, minutes and ban time as dropdowns and a week for repeat offenders; relay networks, allowlist and cluster nodes are never
  banned. On for new installs; an upgrade keeps the old jails (docs/login-lockout.md).
- SECURITY.md: the address for vulnerability reports, security-cra-report.efa-next.eu@it-status.org, also the contact after
  Art. 13 of the Cyber Resilience Act; `docs/security.txt` (RFC 9116) for the project website.

### Operation
- Internal DNS servers and domains (docs/dns-forwarding.md): the internal DNS servers are set once, then the domains they answer
  for, mail domains or not (git, update, proxy or directory servers eFa-next reaches); a domain may name its own servers. Ports,
  DNS over TLS with a checked certificate, at most 64 domains and 8 servers, never "." for all names, a note per domain, a test
  (SOA through the own Unbound) and an audit entry. DNSSEC stays on for a new domain unless it is turned off for it; existing
  domains and the one of the wizard keep it off. Unbound has to stay up after a change, else the settings of before come back.
- Operation without internet (M7 = P4): updates from a local mirror of the repository (the same signature check); signed bundles
  of packages, ClamAV signatures and threat maps for isolated networks, applied only when the Ed25519 signature of a trusted key
  and every checksum fit, packages checked by rpm too; dashboard note when the virus signatures get old (docs/offline.md).
- Staged cluster updates (O2): the master has one node install first, waits a health window of 1, 2 or 4 hours, then the
  rest one by one and itself last; an unhealthy node stops the rollout and alerts; off by default (docs/cluster.md).
- Configuration history (O1): each change through efactl keeps the configuration files it changed (old and new, never
  secrets) with a diff; one change can be taken back after the checks of Postfix, rspamd and nginx, else nothing changes.
- SIEM export in EVE-JSON style (E1): one object per line for every mail (queue id, direction, verdict, symbols, tenant) and
  every eFa-next event, over TLS; pseudonyms when D2 is on; off by default (docs/eve-export.md).
- More interfaces (5l-b): when the last interface leaves the internal firewall zone, the zone gets back the services it had
  before eFa-next first set them.

### Build and CI
- Fixed: on a fresh minimal AlmaLinux 9 nginx came as 1.20 of AppStream, which does not know "http2 on;": nginx refused its
  files and the setup failed. The installer enables the module stream nginx:1.26 by name (the newest stream where 1.26 is
  missing), moves an older nginx there and stops before the install when nginx is older than 1.25.1; nginx-config.sh writes
  the HTTP/2 line in the form of the installed nginx. A reinstall after a failed first setup runs the first setup again (no
  version file yet). Before the wizard the audit log does not report the missing database as an error.
- Install in one command: `build.bash source` sets up a test installation from a clone (build tools, `dnf builddep`, the packages built
  and installed, a second run installs the newest commit again); build-rpms.py names missing build tools and the builddep
  command instead of a traceback. The released installer is to be published as https://repo.efa-next.eu/build.bash.
- The installer installs its own tools first on a minimal EL9 (curl, gnupg2, dnf-plugins-core, the SELinux tools, tar,
  chrony, git-core for source) and names what was missing; it checks DNS, starts chronyd and sets the clock (burst, makestep,
  up to 30 s waitsync, the offset before and after), with a clear warning when it stays unsynchronized. The first install of
  the package does the same (efa-configure step time-sync); an upgrade leaves chrony alone. install.md: a test installation from
  source in one line, again to update.
- The installer runs as the systemd unit efa-install when started by hand: a lost SSH connection does not stop it, the shell
  only follows its progress (Ctrl-C ends the display), a second call attaches. The system update comes right before the install.
- Fixed: on a host without IPv6 (ipv6.disable=1) Postfix kept inet_protocols=all and tried IPv6 sockets, and SELinux denied
  sendmail_t loading the module (newaliases). IPv6 is now read from the kernel switches (/proc/cmdline, /proc/sys/net/ipv6,
  disable_ipv6) without opening a socket; install and upgrade set inet_protocols=ipv4 on such a host, a host with IPv6 keeps
  its value. The setup keeps 127.0.0.1 localhost in /etc/hosts, so localhost never goes to DNS. ci.sh checks the fresh host
  before it restores the saved one, and checks inet_protocols.
- Fixed: a line of /etc/hosts with a foreign address that also named localhost let localhost resolve there. The setup takes the
  localhost names off lines whose address is not loopback (the other names stay, the file before in /etc/hosts.efa-bak, a log
  line). The dashboard warns when the own host name has an address in /etc/hosts that no interface has; it changes nothing.
- Fixed: reports, headers, the backup manifest, the cluster and the login labels took socket.getfqdn(), which is the first name
  of 127.0.0.1 in /etc/hosts or an answer of DNS: an old name there showed in the hardening report. They take one value now,
  myhostname of Postfix, else the name of the kernel (efa_host). The dashboard warns of another full name on the loopback lines.
- Fixed: after an upgrade a changed module could run as its old bytecode. The build clamps all file times, so a module of
  the same size kept the bytecode of the version before. Both packages now compile /usr/lib/eFa/python by the hash of the
  source before their setup runs, and remove __pycache__ when they are erased; ci.sh plants such bytecode before the install
  and checks that the new code runs.
- SBOM (SBOM-1): the older Fedora license names of the EL9 packages become SPDX expressions (unclear ones such as BSD or
  Public Domain as LicenseRef-), only texts without a clear SPDX form stay names (9 of 248 in the 6.0.0.4 SBOM); rspamd gets
  the purl namespace rspamd; build/sbom.py checks the CycloneDX 1.5 fields, purls, refs and expressions and, with
  python3-jsonschema, against the official CycloneDX 1.5 schema (pinned files in third-party/cyclonedx-1.5), and fails on a problem.
- CI: a step checks that every script with `#!` is executable (a checkout from Windows loses the bit); ci.sh installs
  python3-jsonschema for the schema check of the SBOM when it is missing. The SBOM check knows the main package as a component
  that others depend on.

## 6.0.0.4.1

**Not published as packages**: 6.0.0.4.1 has no published packages. They are not signed and are not in the signed
repository or on GitHub; the repository stays at 6.0.0.4. The next published release is 6.0.0.5, with everything below.
Hosts on 6.0.0.4 take 6.0.0.5 once by hand (their update looks only for the old package names):

    sudo curl -fsSL -o /etc/yum.repos.d/efa-next.repo https://repo.efa-next.eu/el9/efa-next.repo
    sudo dnf --enablerepo=efa-next upgrade eFa-next eFa-next-base

The repository file is off by default and checks the signatures (gpgcheck, repo_gpgcheck).

**Packages renamed**: `eFa` is now `eFa-next` and `eFa-base` is now `eFa-next-base`, so the product is not mixed up with the
eFa project. On a 6.0.0.4 host that command replaces the two old packages with the new ones in one step; it runs as an
upgrade: every setting, login and service stays, and no first-install step runs. Paths (`/etc/eFa`, `/var/lib/eFa`), units,
users, the database and `efactl` keep their names. `rpm -q eFa-next eFa-next-base` shows the installed version from now on.

- Impersonation & BEC: a fresh install turns the checks on (after the setup, when the domain is known); an upgrade keeps the
  setting. The lookalike check also catches the same name under another ending (`example.net` for `example.com`) and an own
  domain in front of a foreign one (`example.com.evil.net`); own subdomains never count. Domains added later (transport,
  tenants) reach the protected list at once. A self-test runs the check in the Lua of rspamd.
- Update check: the last result says that the release source answered, instead of an older "not reachable".
- Update check: versions with five parts (6.0.0.4.1) are compared in full; before, 6.0.0.4.1 counted as 6.0.0.4 and was never
  offered as an update.
- Spam and viruses page: the content disarm status (about 70 ms) is kept for 30 s like the other slow reads, so the page stays
  within its 100 ms budget.
- CI: a Forgejo Actions runner runs `scripts/ci.sh --install` (upgrade and fresh-install test) on each push
  to master; `EFA_CI_LOCK_WAIT` lets a run wait for the one before it.
- Texts: the product is called eFa-next everywhere (web interface, mails, help texts, docs); a CI check stops a bare "eFa"
  from coming back. Mentions of eFa 5 and of the eFa project stay.
- CHANGELOG: "Fixed during the release check" and the known limit of 6.0.0.4 under 6.0.0.4, no longer under "Moved to 6.0.0.5".

## 6.0.0.4

### Web interface
- Fast pages: efactl runs through efactl-runner (loaded once, one fork per call) instead of a new Python behind sudo per call; the
  reads of a page run at the same time; slow or seldom changing reads are kept briefly per login and emptied by every change;
  the templates are compiled once. The median page went from 2.7 s to 33 ms, the slowest from 23 s to under 0.2 s. CI
  measures every page (`scripts/page_times.py`, median per page at most 100 ms).
- Opening a page no longer runs jobs or slow checks (Sanesecurity download, mail report, cluster apply, form check, security
  self check): they run from their button only.
- DKIM: one form for new keys, the domain once, RSA, Ed25519 or both (`efactl dkim-create`); the old commands stay for the command
  line and the API.
- The animated mail flow picture of the start page is off until a better drawing exists.
- Standard and Expert view: a switch at the top right, always visible, kept per login in My settings (new logins: Standard).
  Standard shows what can be set and the warnings that ask for an action; values without a setting, advanced sections and fine
  tuning are in Expert. CI checks that every card of the standard view has a control or is a warning or a list of every day.
- The On/Off badge in the head of a card is a switch: one click turns it on or off (the form of the card with only the switch
  changed). Cards that ask for a password, a confirmation or show a risk first keep their form. No second line for the same
  value; long lists such as file endings as chips, from 12 on folded.
- Slow reads (Bayes statistics of rspamd, pending updates) never hold up a page: from the cache, else loaded by their button.
- efactl-runner: time limit and umask of sudo per call; CI checks who may use it after every install.
- The view only hides: both views read the same values, so the tiles of the start page show the mail system in Standard
  too. CI renders every page in both views and compares the values of every card and tile. The user portal reads in
  parallel and keeps what a session may do: 60 ms a page instead of 0.8 s. Templates are compiled at the start.
- IP blocklists (new page): feeds such as Cisco Talos (off until its terms are accepted) and own lists with entries for
  hours or for good, ports per list, in the nftables table efa_block of eFa-next; a reload of firewalld keeps it. Feeds are
  fetched over https with ETag and honour 429/503 with Retry-After. Relay networks, allowed admins, cluster nodes and the
  own addresses are never blocked. Package updates of eFa take the same lock, so no list is loaded while dnf runs.
- efa-migrate takes over other blockers: firewalld rich rules with a source address and reject or drop become eFa-next IP
  blocklists (one per port set, runtime-only rules for 2 hours), and it names the cron jobs that keep them up. Only with
  --disable-foreign-blockers are those cron jobs commented out and the imported rules removed, never with a reload, and
  restore-blockers.sh in the backup puts them back. Rules such as "source NOT address" for a service stay.
- rspamd web interface: only reading, only for the main admin and only for 15 minutes to 4 hours, then it closes by itself;
  full access is gone (an update turns it into one hour of reading, with a notice). In eFa-next instead: own scores of rspamd
  symbols (expert view, checked by rspamd before loading, audit, cluster) and "Check a mail" (one .eml through rspamd with
  no_log and no_stat, nothing stored or learned). See docs/rspamd-access.md.
- efa-migrate: the usual MailScanner rule files become eFa-next settings: sender lists, and for single senders "spam filter
  off, the virus scan stays" or "encrypted archives allowed" as rules that stay on and are listed on the dashboard until
  checked; signatures, size limits and other kinds go into the report with a hint. Wildcards and IP keys of sender_access are
  taken over too. A migration that stops before the removal turns mail intake back on, and a stopped intake is never carried
  over; dovecot is only enabled when it is installed. CI checks every program for names that are used but never defined.
- Hardening report as PDF: a button "Download PDF" on its card, `efactl hardening-report --pdf FILE` (or `--pdf -`). Date, host,
  version, mode, a summary and every check of the table with its result, the failed ones first; A4, page X / Y on every page,
  colored marks, Producer and Creator eFa-next; no secrets, only results. The PDF code is plain Python (efa_pdf.report) for
  the other reports to come.
- efa-migrate also reads the MailScanner rule sets in /etc/MailScanner itself (filename, filetype, archives, numeric
  phishing); a sender with the attachment filter off ("allowall") is named in the report, as eFa-next checks attachments of
  every sender.
- efa-migrate never leaves eFa less strict than eFa 5 for attachments: when the attachment filter of eFa 5 was active, the
  eFa-next filter goes on with reject (also inside archives), with the endings eFa 5 blocked added to its own, the name rules
  of eFa 5 (over 150 characters, CLSID names, 10 or more spaces) and programs by their content (Windows, self-extracting, ELF).
  Endings eFa 5 allowed but eFa-next blocks (such as url, reg) stay blocked and are named in the report with the command to
  allow them. New options of the attachment filter for both: hiding file names, programs by content (off unless set).
- New network interfaces stay unused until they have a role: no automatic DHCP profile of NetworkManager (it could take an
  address or a default route from an unknown network); the dashboard names them, the hardening report names automatic
  profiles that exist already (docs/network.md).
- More network interfaces (5l): mail of a sender domain can leave over an extra uplink (`efactl uplink-route-set`), through an
  own Postfix transport bound to the address of that uplink; its answers come back through the routing table of the uplink.
- No insecure ways (S1): the rules in docs/SECURITY-DESIGN.md; a unit test keeps passwords and tokens off command lines and the
  install check of CI fails on a file readable by everyone that holds a secret. Audit of part 2 (file permissions, secrets in
  logs and arguments): nothing found.
- Legal texts (5y): LICENSE, DISCLAIMER.md and THIRD-PARTY-NOTICES.md come with the package in /usr/share/eFa/legal, each also
  as PDF and all together, made at build time with the own PDF code, with version and digest in them; open without a login
  under /legal. A new version of the texts (a new digest) is confirmed once: by any admin before the first admin page (a box:
  qualified administrator, no consumer, texts read), in the setup wizard, or in efa-migrate by typing ja or yes (unattended
  --accept-legal=<digest>); without it efa-migrate changes nothing. The user portal and the mail flow never wait for it. Each
  confirmation goes into the audit log with time, admin, address and version (efactl legal-status, legal-accept).
- Disclaimers (8k): templates for all domains, a tenant, a domain or groups of senders in a domain (eFa-next groups or
  directory groups, read when saved, so mail never waits), as text or as HTML with pictures (cid:) and attachments (png, jpg,
  gif, pdf, vcf). Each mail gets one, the most specific that fits; "which one does a sender get" on the page. Import and export
  as ZIP (manifest.json, body.html, body.txt, media/, attachments/), checked whole before anything changes: no paths out of
  the folder, no links, size, file count and packing limits, file types by content, HTML without scripts, event handlers or
  outside resources. The last three versions stay for the way back. Other systems deliver ZIPs over the provisioning API on
  port 8463 (mTLS and token as for DKIM) with their own right "disclaimer"; a source sets only disclaimers of its own
  domains. Cluster nodes get the disclaimer folder. The older text per domain keeps working. See docs/api-disclaimer.md.
- ci.sh: packages of a failed or older run are removed; a green run leaves its packages in /var/tmp/efa-ci-green with the
  hash of the source tree, and only those are used for test installs.
- ci.sh `--fresh` (also part of `--install`): the fresh-install path on the CI host, with the wizard and the first boot,
  checked and then put back as it was (`--fresh-restore` after an interrupted run).
- efa-migrate: the entries of /etc/postfix/sender_access go to the eFa-next sender lists (marked "migrated from sender_access";
  OK entries, which let mail past every filter, marked for checking and listed in the report); wildcards, IP keys and broken
  lines are reported, not guessed. Every map of the old main.cf the new setup does not read any more is named in the report.
- Security self check: an interface with the default route in a zone that lets everything in (such as trusted) is a
  problem, rules in a zone without interface or source are a warning; nothing is changed automatically.
- Tenants, domains and users: a data model with tenants (a customer, its domains, its users), from the start for MSPs
  (`tenant-*`, `user-*`). The main admin in `admin.pw` keeps all rights. Empty after an upgrade.
- Roles and permissions: super, tenant, domain, helpdesk and user as predefined groups, a permission per command; `efactl
  --as <user>` holds the rights of the login and limits every result to its domains, so the web forms and the API cannot
  differ. A second check in efactl, a scope and IDOR check per call; a rights change ends the sessions.
- REST API: `/api/v1/<command>` and `/api/v1/schema`, bearer tokens kept as hashes, per user and time-limited; the web uses the
  same dispatcher, not HTTP. Accounts of the role user get no token. Off by default.
- Single sign-on (OIDC): code flow with PKCE, RS256 only, checks of issuer, audience, expiry and nonce; the login state has its
  own Lax cookie while the session stays SameSite=Strict. Off by default.
- Directory login (LDAP/AD): `ldaps://` or `ldap://` with STARTTLS, an empty password never binds; groups map to roles, a login
  without a mapped group is refused. Off by default.
- Prometheus endpoint `/metrics` with a token of a global role, cached a few seconds.
- Message search: a lasting, indexed search over the whole mail log (MariaDB), with filters and CSV/JSON export up to 50,000
  rows; spreadsheet formulas in CSV cells are defused.
- Daily and weekly reports (`report-set`, `report-show`): mail flow and threats as a page the browser prints to PDF and by mail
  to the admins and tenant admins. Off by default.
- Rule engine (`rule-set`): policies and routing by sender, sender domain, recipient, domain, tenant or directory group, carried
  out in rspamd and Postfix.
- User quarantine (`uq-set`): rspamd moves mail from a set score, and viruses, instead of rejecting; a daily digest with signed
  one-time links; self-service release, allow or block a sender, a login link. Off by default.
- Impersonation and BEC (`bec-set`): forged display names against a VIP list, lookalike and cousin domains (Levenshtein,
  homoglyphs, IDN), the sender-recipient relation in Redis with an expiry. A score, nothing rejected on it alone. Off by default.
- Attachments and content disarm (`attachment-set`, `cdr-set`): a type and archive filter with real type detection, encrypted
  archives marked, Office macros and PDF active content removed; a file it cannot clean is replaced, the original kept for the
  admin; a mail it cannot read waits (4xx), never delivered unchecked. Off by default.
- Link check on click (`links-set`): links rewritten to a signed redirect behind nginx, checked again against rspamd on the
  click, a warning page on a hit; exceptions per domain. Off by default.
- DMARC aggregate reports, DANE and MTA-STS: a RUA mailbox read (zip/gz, XML, no DOCTYPE or entities), shown per domain and
  source; DANE outbound (`dane-set`, DNSSEC over Unbound) with a TLSA generator; MTA-STS generated and checked daily.
- Phishing reports and warning banner (`phish-set`, `banner-set`): a report address per domain feeding Bayes and Fuzzy after a
  release; a banner on incoming mail, by default only without a valid DKIM signature. Off by default.
- Mail queue (`queue-list`, `queue-action`): a page for the Postfix queue (view, hold, release, delete, re-send), each with a
  confirmation and the audit log, an alarm on size or age.
- Spooling (`spool-set`): queue and bounce lifetime in the web (5 days by default), per destination "reachable since /
  unreachable since", an alarm on an outage and return, staggered delivery after return.
- External backup targets (`backup-target-*`): the encrypted backups uploaded over S3 or SFTP after each backup, with a
  bandwidth limit; credentials for root only, never in a log; retention and a checksum per target. Off by default.
- Outbound DLP (`dlp-set`, `dlp-rule-set`): IBAN (check digits), credit card (Luhn), AT/DE tax and social numbers and own
  keywords; per rule log, quarantine, reject or encrypt. Off by default.
- Password PDF (`pdf-set`): mail and attachments as an AES-256 PDF (qpdf), the password kept apart; triggered by a subject
  keyword or a rule. Off by default.
- Archive forwarding (`archive-set`): a copy of each mail to an external archive (MailStore, piler) over SMTP with TLS, global
  or per domain; a failure stays in the queue, an alarm on a backlog. Off by default.
- Bulk/newsletter sending (`bulk-set`): a bulk mode per sender, domain or submitter and on `Precedence: bulk` or
  `List-Unsubscribe`, throttled per destination provider. Off by default.
- Cluster (`cluster-*`): a master with clients or an HA cluster, connected only by mutual TLS from the master's CA; settings,
  blocks, quarantine and queue state shared. Operating mode (`cluster-mode-set`): single host (default), HA or master/client.
  Manual master takeover (`cluster-promote`) when the old master cannot be reached, with a confirmation and the audit log.
- Config migration across hosts (`efa-migrate export`/`import`, `efa5-export`): the settings of an eFa 5.0 host exported as an
  encrypted, signed file and imported on a fresh eFa-next host with a preview (taken over / adjusted / not possible).
- DKIM provisioning API (`dkim-provision-*`, port 8463): PUT/POST/GET/DELETE over HTTPS (TLS 1.2+), a client certificate and a
  bearer token per source, an address allowlist and a rate limit; a source sets only its own domains. Off by default.
- Address harvesting (`harvest-set`): one source probing many unknown recipients gets a dashboard note and an automatic Fail2Ban
  ban with an allowlist, on every host in a cluster. On by default on a new install, off after an upgrade.
- Milter health (A5): efa-milter-health marks mail with `X-Milter-Failed`, feeds the dashboard, the metrics and the
  service_down events, and shows a hardening finding when a milter or service is down. Per milter `milter-health-set` chooses
  accept (let mail pass when it is down, the default and what `milter_default_action=accept` gives) or tempfail (turn the mail
  away with a retryable 451). Default and upgrade keep accept.

### Security
- Encryption: only modern, secure encryption (TLS 1.2/1.3, ECDHE with AEAD ciphers, following RFC 9325 and BSI TR-02102-2), see
  [docs/tls-profiles.md](docs/tls-profiles.md).
- TLS profiles for the web interface and mail (Security, TLS profile): BSI TR-02102-2 (default), RFC 9325, Mozilla modern
  (TLS 1.3 for web and logins) or a custom list checked against the limit; ciphers, curves and protocols for nginx and
  Postfix, each checked before loading. An update sets BSI where no profile is set yet and raises weaker settings, with a
  notice. TLS 1.0 and 1.1 can no longer be switched back on.
- Post-quantum: the web interface offers the hybrid key exchange X25519MLKEM768 first where OpenSSL has it (OpenSSL 3.5 on EL9),
  X25519, P-256 and P-384 behind it. Postfix 3.5 and the Python services keep the classic groups for now (docs/tls-profiles.md).
- BSI TR-02102-1/-4 in the hardening report: key lengths of the certificate, the SSH host key and the DKIM keys (RSA from
  3000 bits), the SSH key exchange, ciphers, MACs and host key algorithms, and whether the hybrid key exchange is available.
  New `efactl ssh-profile-set --mode bsi`: SSH after TR-02102-4, back by itself after 10 minutes unless confirmed.
  Let's Encrypt certificates are requested as ECDSA P-256. DKIM keys below 3000 bits get a BSI note.
- Postfix: the TLS minimum is written in the form Postfix 3.5 (EL9) understands; `>=TLSv1.2` before Postfix 3.6 is a finding of the
  security self check.
- The user portal runs as a process of its own without sudo, behind a helper with a fixed set of commands
  ([docs/security-model.md](docs/security-model.md)).
- Admin access to the web interface can be limited to allowed networks; the user portal stays open.
- Changes to users, groups, the firewall, root SSH, the admin allowlist and other critical settings ask for the password again.
- A change of the rights of an account ends its sessions; accounts of the role user get no API token.
- The root SSH switch checks with `sshd -T` that its value takes effect, and names the file that overrules it.
- Forms show the values that are set now, never the first choice of a pulldown.
- Logins of mail systems on port 587 are checked by the new efa-sasl, a small hardened service of eFa-next, in place of Dovecot,
  which is no longer a dependency. Hosts that still let system accounts log in on 587 keep Dovecot until they switch to
  submitter logins.
- Blocklists: their terms of use are linked, and switching one on needs the confirmation of its terms.
- No readable exports (S1): the SIEM export runs only over TLS (syslog over TLS, port 6514), the OpenTelemetry export only to an https:// receiver with its certificate always checked. Setups of before over plain TCP/UDP or http:// stop sending with the upgrade, with a dashboard notice how to switch.
- Releases: installer, `efa-migrate` and the update check take a release only when its `SHA256SUMS` carry a valid signature of the eFa-next repository key `1823 D6D3 BB7D 5AEA 286E 836D CFE7 E079 16CC 8046`, from the own repository `repo.efa-next.eu` or the GitHub mirror.
- Hardening (A1): every external call in efactl has a time limit (60 s by default, longer for dnf, rpm, ssh, systemd-run), so a
  hung program cannot block a timer or the CLI.
- Hardening (A2): the services that parse untrusted mail (efa-cdr, efa-maillog, efa-milter-health, efa-outbound, efa-sasl,
  efa-portal) run under a systemd lockdown drop-in (CapabilityBoundingSet=, a @system-service syscall filter,
  RestrictAddressFamilies, kernel and proc protections, NoNewPrivileges) and as users that efactl-runner does not answer, so a
  parser bug cannot reach root efactl.
- Hardening (A3): the backup upload has a hard size cap (`MAX_CONTENT_LENGTH`) and streams to efactl instead of reading the
  whole file into memory; backup download and upload name the acting admin in the audit log.
- Hardening (A4): one safe ZIP reader (`efa_zip.safe_unzip`) for the report and disclaimer imports, with limits on members,
  unpacked size, compression ratio (ZIP bombs), path traversal, absolute paths, links and encryption.
- Hardening: the in-memory rate-limit and notify tables of efa-dkim-api, efa-maillog and efa-sasl are bounded, so a flood of
  changing addresses cannot grow them without end. A DOCTYPE in a UTF-16 DMARC report is caught (the check reads the decoded
  text). efa-apply uses the same password minimum as the wizard (12).
- Fuzzing the parsers (Q2): CDR (OOXML, OLE, PDF, links), MIME, DMARC XML, DLP and disclaimers, standard library only, a fixed
  seed and limits on size, depth and time; runs in CI (`scripts/fuzz.py`).
- SECURITY.md (Q3): a report address (placeholder until 6.0.0.6), response times, coordinated disclosure, CVE assignment and the
  supported versions.
- Reproducible builds and SBOM (Q4): the same source gives the same RPMs; an SBOM per release (JSON) with every component and
  its license.
- Secure by default: a new install checks attachments (dangerous endings, also in archives, file names that hide what the
  file is, programs by their content) and disarms Office macros and active PDF content. An upgrade keeps what was set; a
  migration from eFa 5 turns the checks on only where eFa 5 had attachment rules.
- The files efactl writes for other services (SMTP-AUTH logins, the mail log password, the event log, the Wazuh enrollment
  password) keep their group read right under a strict umask (077): before, every login on port 587 failed there.
- Privacy by default (Q7): sparing defaults on a new install (short log retention, no content in the log, an EU-only update
  check without personal data) and a reason required to open the content of a mail in the strict audit mode
  (`content-reason-set`).
- GDPR papers (Q6): templates for the record of processing, the technical and organisational measures and the data processing
  agreement, as drafts for a lawyer (docs/datenschutz/). SUPPORT.md (Q8): the community way and optional paid support
  (placeholders until 6.0.0.6).
- Guides (Q9): Microsoft 365, Google Workspace and Exchange, inbound and outbound through eFa-next, SPF/DKIM/DMARC and a DKIM
  import/export so mail is not signed twice. Detection rate (Q10, `scripts/detection_benchmark.py`) and a load and performance
  test (Q11, `scripts/load_test.py`) with a size recommendation in the docs and a small run in CI.

### Fixed during the release check
- The secure defaults of a fresh install switched content disarm on before any milter ran, and the first-install step failed.
  Content disarm now goes on at the first boot; ci.sh also tests the fresh-install path.

### Known limit

Known limit of 6.0.0.4: the web interface has no dark theme for its content yet; only the logo and the mail flow picture
follow the dark mode of the system. It comes with 6.0.0.5.

## Moved to 6.0.0.6

These are not built in 6.0.0.5: AlmaLinux 10 and FreeBSD as platforms. The animated mail flow picture (9l) stays deferred
behind `FLOW_PICTURE = False`.

## Moved to 6.0.0.5 (done)

These were planned for 6.0.0.4 and moved out by the scope freeze; 6.0.0.5 builds them: emergency read access (5n),
2FA/TOTP (5r), passkeys/WebAuthn (5s), extra protection sources (5v), BIMI (5w), QR codes (5x), EU-only backup targets (5z),
EU relation / external services (EU), domain check (6a), role addresses (6b), DKIM selector inventory (6c), application mails
per domain (8j), search in the web interface (9f), retention periods per data kind (9h), the greylisting and rate-limit UI
(9j), CVE watch (9o), web self-lockdown (9o-b), MTA-STS generate-and-check-only (9p) and the EU conformity document (S2).
