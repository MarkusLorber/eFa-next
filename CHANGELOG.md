# Changelog

## 6.0.0.4 (in progress)

### Web interface
- Fast pages: efactl runs through efactl-runner (loaded once, one fork per call) instead of a new Python behind sudo per call; the
  reads of a page run at the same time; slow or seldom changing reads are kept briefly per login and emptied by every change;
  the templates are compiled once. On MX03 the median page went from 2.7 s to 33 ms, the slowest from 23 s to under 0.2 s. CI
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
  hours or for good, ports per list, in the nftables table efa_block of eFa; a reload of firewalld keeps it. Feeds are
  fetched over https with ETag and honour 429/503 with Retry-After. Relay networks, allowed admins, cluster nodes and the
  own addresses are never blocked. Package updates of eFa take the same lock, so no list is loaded while dnf runs.
- efa-migrate takes over other blockers: firewalld rich rules with a source address and reject or drop become eFa IP
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
- efa-migrate: the entries of /etc/postfix/sender_access go to the eFa sender lists (marked "migrated from sender_access";
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
- Guides (Q9): Microsoft 365, Google Workspace and Exchange, inbound and outbound through eFa, SPF/DKIM/DMARC and a DKIM
  import/export so mail is not signed twice. Detection rate (Q10, `scripts/detection_benchmark.py`) and a load and performance
  test (Q11, `scripts/load_test.py`) with a size recommendation in the docs and a small run in CI.

## Moved to 6.0.0.5

These were planned for 6.0.0.4 but moved out by the scope freeze; they are not built in 6.0.0.4: emergency read access (5n),
2FA/TOTP (5r), passkeys/WebAuthn (5s), extra protection sources (5v), BIMI (5w), QR codes (5x), EU-only backup targets (5z),
EU relation / external services (EU), domain check (6a), role addresses (6b), DKIM selector inventory (6c), application mails
per domain (8j), search in the web interface (9f), retention periods per data kind (9h), the greylisting and rate-limit UI
(9j), CVE watch (9o), web self-lockdown (9o-b), MTA-STS generate-and-check-only (9p) and the EU conformity document (S2). The
animated mail flow picture (9l) stays deferred behind `FLOW_PICTURE = False`.

### Fixed during the release check
- A change for secure defaults on fresh installs (78565c4) broke the first-install step on Forgejo master from 20:26 to 20:37
  on 2026-11-07: content disarm was switched on before any milter ran. Fixed in 96dc2c7 (it goes on at the first boot) and
  proven by a third fresh install; ci.sh now also tests the fresh-install path.

Known limit of 6.0.0.4: the web interface has no dark theme for its content yet; only the logo and the mail flow picture
follow the dark mode of the system. It comes with 6.0.0.5.

The full list of 6.0.0.4 comes with the release.
