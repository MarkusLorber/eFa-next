# State of 6.0.0.4

Work in progress on master. The packages carry the version 6.0.0.4. The plan is internal and not in the repository.

## Release gate (2026-11-07)

- Code review of the whole repo (checklist section 1): the 4 high findings fixed (efa-sasl auth reply, efa-cdr fail closed,
  mail services off root efactl, TLS handshake timeout in the DKIM API and the cluster), the mediums fixed, and the hardening
  items A1-A5 (subprocess timeouts, systemd lockdown of the mail-parsing services, backup upload cap and streaming, one safe
  ZIP reader, milter outage visible with a per-milter tempfail). The low findings in the mail services are fixed too (bounded
  rate-limit and notify tables, a UTF-16 DOCTYPE caught, the password minimum aligned to 12). One medium stays open on
  purpose: full efa-web.service confinement needs the sudo path moved to efactl-runner first.
- `scripts/ci.sh --install` green on MX03 for each push.
- Changelog and docs brought up to date: the foundation and the A1-A5 items in CHANGELOG.md with a "Moved to 6.0.0.5"
  section; new doc pages for the features that had none (BEC, attachments/CDR, link check, phishing and banner, DMARC
  reports/DANE/MTA-STS, spooling, backup targets, archive, bulk, fuzzing, hardening PDF, privacy, interfaces, harvesting).

## Done

### 5 Admin basics

All of it is off or empty after an upgrade: the API is off, no users or tenants exist, SIEM, OIDC and LDAP are off. The tables and the new indexes on the mail log come with `efactl maillog-setup`.

- **Tenants, domains, users.** `tenant-*`, `user-*`, tables in the database `efa`. The main admin in `admin.pw` stays and has all rights.
- **Roles.** super, tenant, domain, helpdesk, user. `efactl --as <user>` holds the rights and limits the results to the domains of the caller, so forms and API cannot differ. A helpdesk without tenant reads everything except backups and works on the quarantine.
- **Audit log.** Table `audit`: who, from where, command, arguments, old and new values from a settings snapshot, result. Secrets are masked, timer jobs stay in the file log only. Kept 400 days.
- **REST API.** `/api/v1/<command>`, `/api/v1/schema`, bearer tokens stored as hashes, per user and valid for a set time. Failed tokens count like failed logins for Fail2Ban. A revoked token works for up to a minute more, because the check is remembered that long.
- **Web forms and API.** They share one dispatcher in `efa-web.py`, the same schema and the same rights in `efactl`. The forms do not call the API over HTTP.
- **Message search.** `message-search` with filters, a full-text index on the subject, CSV up to 50000 rows. Spreadsheet formulas in CSV cells are defused.
- **SIEM.** `siem-set` writes `/etc/rsyslog.d/90-efa-siem.conf`: mail, audit, firewall and Fail2Ban lines as RFC 5424 or JSON, only over TLS (RFC 5425, port 6514, the certificate of the SIEM checked by its name; `rsyslog-gnutls` comes from AppStream when it is switched on), with a bounded queue. A setup of before over plain TCP or UDP stops with the upgrade; the dashboard says how to switch it to TLS.
- **Prometheus.** `/metrics` with a token of a global role, cached for 15 s.
- **OIDC.** Code flow with PKCE, RS256 only, checks of issuer, audience, expiry and nonce. The login state has its own Lax cookie, the session stays SameSite=Strict, and the last step is a page that moves on by itself: a redirect would lose the Strict cookie.
- **LDAP.** `ldaps://`, or `ldap://` with STARTTLS. An empty password never binds. Groups map to roles with `group-map-set`, for OIDC and LDAP. A login without a mapped group is refused, and the role is set again on each login.
- **Passwords.** Asked twice wherever one is set, see `password_twice`.

### 5b Reports

`report-show` for yesterday or the last 7 days, as values or a page the browser can print to PDF. `report-set` mails them to the admin and to tenant admins with an address, as text and HTML: every day, and on Mondays. Off by default. The new daily report replaces the short one if both are on.

### 5c Rule engine

`rule-set`, stored in `/etc/eFa/rules.json`. A rule fits a sender, sender domain, recipient, domain, tenant or directory group, and sets other spam limits, quarantine instead of rejecting, or another route. The highest priority that fits wins. rspamd gets `local.d/settings.conf`, Postfix `efa-rule-transport` and `efa-rule-sender-relay` in front of its maps, and both go back to what they were when the last rule is gone. Tenants and groups are read again every hour.

- One verdict per mail: with several recipients, a rule counts if one of them fits.
- Only the super-admin can change rules so far.
- A group needs LDAP, and it cannot have a route.

### 1 Quarantine for users

`uq-set`, off by default. When on, a postfilter in `/etc/rspamd/efa-quarantine.lua` sends mail from the limit on, and viruses, to `efa-maillog` on 127.0.0.1:8906. It stores the file in `/var/spool/efa-quarantine` (0700 efa-web) and a row per recipient in MariaDB. Only after the answer 200 does rspamd discard the mail; on any failure it takes its normal way. Below 10 % free disk nothing is stored. Own mail and hard blocks (sender lists, DMARC reject) stay as before.

- Digest once a day per recipient, text and HTML, with links that are valid 7 days and work once. Opening a link only asks, the button does it: mail scanners open links too.
- Self-service: release (if allowed), ask an admin, allow or block the sender for this recipient only, and a login link to the page of the user. A virus only gets out through a super-admin.
- Roles see only their mailbox or their domains. A released mail does not pass the filters again.
- Kept for the set number of days, links and rows go with the hourly job.
- rspamd needs the action `discard` declared: it is added to `local.d/actions.conf`, without a score.

### 5d Events and OTLP export

- **Events.** `/var/log/eFa/events.json`, one JSON line per event with the stable fields `timestamp` (ISO 8601, UTC), `event`, `severity`, `user`, `src_ip`, `tenant`, `host`, `efa_version`. Written only while OTLP, the SIEM export or Wazuh reads it. Mode 0640, group `wazuh` if it exists. Rotated with the other logs.
- **Sources.** Each change through efactl, quarantine actions, firewall guard repairs; and every minute from the journal (web logins ok and failed, Fail2Ban bans), the health service (service down and up) and the rspamd counters (viruses and blocklist hits as a summary). DKIM and ARC errors are not in it yet: rspamd has no counter for failed signing.
- **OTLP/HTTP with JSON**, own code: `/v1/logs` for events and mail log rows, `/v1/metrics` for the values of `/metrics`. Resource attributes `service.name`, `service.version`, `host.name`, the tenant per record. gzip, batches of up to 500 records or 1 MB.
- **Auth and TLS.** Bearer, API key with its own header name, or extra headers. Certificate check on, own CA, client certificate for mTLS. `/etc/eFa/otlp.json` is 0600 root, the status says only "set" or "not set".
- **Outage.** A disk buffer per signal with a size limit; when full the oldest data goes and is counted. On 429, 5xx or no answer the next try waits 30 s, then doubles up to an hour, or follows Retry-After.
- **Cost.** A timer every minute. While nothing is on, systemd does not start the job; a run takes about 0.2 s.
- The SIEM export takes `events.json` too, so nothing is collected twice.

### 5e Wazuh agent

- Web page **Wazuh** and `efactl wazuh-status`, `wazuh-check`, `wazuh-install`, `wazuh-config`, `wazuh-service`, `wazuh-update`, `wazuh-remove`, super-admin only. Details in `docs/WAZUH.md`.
- Install from `packages.wazuh.com` with the key fingerprint checked; repository `enabled=0`, so only the update button updates the agent. Package signature and package scripts are checked before anything is installed: a script that calls `firewall-cmd`, `firewalld`, `iptables` or `nft` stops it.
- `wazuh-config`: manager, ports 1514/1515, agent name, groups, enrollment password twice into `authd.pass` (0640 root:wazuh). One marked eFa block in `ossec.conf` (events.json as JSON, maillog, FIM of `/etc/eFa`, `/etc/postfix`, `/etc/rspamd/local.d`, `/etc/nginx` without file content, SCA policy, active response off unless turned on). Everything else in `ossec.conf` stays.
- `/usr/share/eFa/wazuh/`: decoders and rules for the manager (IDs 108000-108099), SCA policy (108100-108199).
- The agent runs as root, as its package sets it up; the status says so.
- An agent that eFa did not install is only read ("Agent present, not managed by eFa"); config, service, update and remove refuse. Take-over only with `--adopt yes` and the confirmation.

### 5g Users, groups and permissions

- **Permissions** as a fixed catalogue (`efactl permission-list`): `status.view`, `settings.view`, `settings.edit`, `quarantine.self`, `quarantine.view`, `quarantine.release`, `quarantine.release_malware`, `search`, `mail.view_content`, `export`, `reports.view`, `rules.edit`, `users.view`, `users.manage`, `groups.manage`, `tenants.view`, `tenants.manage`, `audit.view`, `api_tokens.manage`, `monitoring.edit`, `wazuh.manage`, `backup.manage`. Some count only in a global group (settings, rules, groups, tenants, tokens of others, monitoring, Wazuh, backups).
- **Each command needs one permission**; commands without their own need `settings.view` to read and `settings.edit` to change. The same check for web, API and efactl, in efactl.
- **Predefined groups**: super admin, tenant admin, domain admin, helpdesk, user, read-only, auditor. They cannot be changed or removed, only copied. Their scope is the tenant or domain of each member; the helpdesk without tenant or domain reads the whole system, as in 6.0.0.3.
- **Own groups**: name, description, permissions, scope global, tenants or domains. Disable, enable, remove with confirmation.
- **Users**: local (password twice), LDAP or OIDC, in several groups; permissions add up, each with the scope of its group. Disable and enable; a disabled user cannot log in, its tokens stop. `user-show` lists the effective permissions with their scope.
- **Directory groups** of LDAP/AD and OIDC map to eFa groups; a login gets one eFa group per mapped directory group, again on each login.
- **Protection**: nobody hands out a permission or scope they do not have, or changes a user who has more; nobody changes, disables or removes their own login's groups; the last active super admin (the main admin counts) cannot be removed, disabled or demoted; removing needs yes.
- **Audit**: each change of users, groups and mappings is in the audit log with old and new of that entry.
- **Upgrade**: the role of each user becomes a membership of the matching predefined group with the same tenant or domain, once; directory mappings get the matching group. The old columns stay. `--role` still works.
- Web: page **Groups**, page Users & API with user-show and user-state.

### 5i-e Sessions and locking

- Each web login is recorded in `web_sessions` with the hash of its session ID only, user, address, browser, start and last use.
- `efactl session-list` and the page Users & API: your own sessions, on other devices too; those of users you may change; those of the main admin only for a super admin. `session-end` ends one; the browser is out within 15 seconds. Logout ends the session too.
- Lock with `user-state --mode off`: the user is out within 15 seconds, cannot log in, API tokens stop. Unlock with on. Removing a user ends its sessions.
- The web interface asks efactl every 15 seconds per active session; the role is taken again then, so a change of groups counts without a new login. If efactl fails, nobody is logged out.
- Ending and locking are in the audit log.

### 5j Tenants and domains (part 1 and 2: delegation, settings in three levels)

- **Domain permissions**, scoped like all others: `domain.settings.view`, `domain.settings.edit`, `domain.spam`, `domain.quarantine`, `domain.lists`, `domain.routing`, `domain.dkim`, `domain.disclaimer`, `domain.users` (brings users.view and users.manage in the same scope).
- **New predefined group "domain manager"**: all domain permissions and its own quarantine, in its domains. Tenant admin and domain admin get the domain permissions too, so they keep what they had; the domain admin can now also manage the users of its domain.
- **Commands that name a domain** (DKIM, rotation, ARC, DMARC record, DNS export, mail server, sender rules per recipient) refuse a domain outside the scope, and an empty domain that would mean all. Results that name domains (status, settings, DKIM, rotation, ARC, DMARC) keep only the own ones; the global sender lists stay hidden from a domain scope.
- **Settings in three levels**, global, tenant, domain; the lower one wins. `domain-settings-show` lists each value with its source; `domain-spam-set`, `domain-quarantine-set`, `domain-routing-set`, `domain-general-set` set them for a domain or tenant, `inherit` takes the value away again. Page **Domain settings**.
  - Spam limits (mark, reject) become rspamd settings rules per domain, below the rules of the admins.
  - Quarantine retention per recipient domain; a mail goes when no recipient is left. Digest hour and a text at the top of the digest.
  - TLS level to the domain as a Postfix `smtp_tls_policy_maps` map; without entries the map is not in the configuration.
  - Language is stored for the multilingual interface (5i-h).
- Global settings (system, firewall, updates, Wazuh, monitoring, backup) stay global-only.

### 5j Tenants (part 3)

- **Login directory per tenant**: `tenant-ldap-set`, `tenant-oidc-set`, `tenant-group-map-set`, `tenant-idp-status` (permission `tenants.idp`, the tenant admin has it). A login with an address of a domain of the tenant uses its directory; the login page asks for the mail domain for single sign-on. The directory of a tenant only gives groups inside the tenant, also if a mapping row says otherwise, and only for addresses of its domains. Each tenant has its own mapping table.
- **Tokens bound to a tenant**: `token-create --tenant`. Such a token reaches only that tenant, even of a super admin, and nothing of the whole system.
- **Look per tenant**: name, colour and a PNG logo (up to 200 KB and 1024 pixels; SVG is refused, it can carry script). Shown in the web interface after login for users of that tenant, at the top of the digest and the reports, the logo inline in the mail.
- **Domain onboarding**: `domain-onboard` by a tenant admin gives a TXT record `_efa-verify.<domain>`; `domain-verify` turns the domain on once DNS has it. A super admin adds it at once.
- **Limits** per tenant: domains, users, mails per day, quarantine in MB. From 80 % and at 100 % one mail a day to the admin and an event. At 100 % no new domain or user; a full quarantine stores no new mail for the tenant, the mail takes its normal way. Mails per day only warn.
- **Usage**: `tenant-usage` with domains, users, quarantine, mails of the month and of today, as JSON or CSV.
- **Lock**: `tenant-lock` logs its users out and refuses their logins and tokens; mail flows on, or waits in the queue with `--mail defer` (Postfix `retry`).
- **Delete**: `tenant-delete` with the name typed again and yes: users only in it, its groups, mappings, settings, DKIM keys, mail server routes, sender rules, rules, quarantine and mail log rows, logo and directory files. The audit log stays.
- Page **Tenants**. Without tenants nothing changes.

### Bayes status

- `efactl bayes-status`, read only: learned spam and ham, min_learns, active or not, autolearn, per user or global. On the dashboard and the page Spam scores, in `/metrics` (`efa_bayes_learned`, `efa_bayes_active`) and as the events `bayes_active` and `bayes_inactive`.

### Fix: GET on actions, and the system update

- A GET on any `/run/<action>` (reload, link, back button, the redirect after login) never runs it and never shows 405: it goes with 303 to the page with that form. The same for logout, backup download and upload, logo upload.
- After a POST the browser is sent on (Post/Redirect/Get); the result shows once, a reload does not run the action again.
- System update from the web and `update-now`: backup first as before, then a check of the package scripts and triggers of all pending updates (downloaded, not installed). Packages that reload or restart firewalld are left out and named; install them by hand between minute 20 and 50, then `efactl firewall-guard-run`. The update starts only between minute 20 and 50, otherwise it is planned for the next xx:20. The firewall guard runs right after it, as before.

### Web interface: test and revision

- **Navigation by task**, seven groups: Overview, Mail & quarantine, Protection, Domains & tenants, Users & access, Monitoring & reports, System. 21 pages instead of 27: Mail routing holds domains, relay networks and limits; Spam & virus holds the virus signatures; DKIM, ARC & DMARC holds key rotation and the DMARC record; Security holds the firewall test. The old addresses (`/p/relay`, `/p/limits`, `/p/virus`, `/p/rot`, `/p/dmarcrec`, `/p/fwtest`) answer 301 to the page they are part of now. Each role sees only the groups and pages it can use.
- **Sections** on the busy pages; settings that are seldom needed are closed under their heading. Explanations longer than a line are behind "Help".
- **One card per topic**: a status and its switch are one card with an On/Off badge (SIEM, OTLP, API, OIDC, LDAP, quarantine for users, reports, virus signatures, firewall guard, automatic update, SSH root login, Wazuh). The Monitoring page has its own Prometheus card.
- **Dropdowns for fixed choices**, from one table in efactl (`ARG_CHOICES`): actions, lists, protocol, format, authentication, language, TLS level, scope, rule kind, period, key type, modes. efactl refuses any other value before it runs anything. Confirmations are a checkbox instead of typing yes. Tenants, domains and groups are dropdowns with what the login may choose. Labels are nouns.
- No 404 for the browser icon on each page any more. Internal commands of the web interface are no longer shown as forms.

### Subjects, headers, content, DNS evidence

- **Subjects**: encoded words (RFC 2047) decoded, control characters removed, always escaped where shown. Live log: own column with the full text as tooltip; at phone width a second line under the sender. New permission `mail.view_subject` (predefined admin groups and helpdesk); `subject-display-set` switches them off for the log and the search. Users still see their own held mail.
- **Headers of all mail**: the rspamd metadata exporter now uses an own formatter (`efa_json`, written by `maillog-setup`) with the same fields plus the raw header block, up to 64 KB (longer ones cut and marked). efa-maillog stores them zlib-compressed in `mail_headers`, linked to the mail log row; From, Reply-To, Return-Path and X-Mailer are indexed in the mail log and searchable. On by default, also after the upgrade: the mail flow does not change. `headers-store-set` (global on/off, days, default 30) and per tenant or domain on the page Domain settings; the first recipient's domain decides. Hourly deletion; below 10 % free disk nothing is stored and the admin gets a mail.
- **Detail view** `/mail/<id>` from the search result and the live log: overview, path over the servers with the seconds per hop, authentication/ARC/DKIM headers, spam headers, raw headers with a copy button; download as `.txt` with the original line ends only with the permission `export`. New permission `mail.view_headers`.
- **Content** of stored mail (held mail and the quarantine of the queue): "Text" shows the plain part, or the HTML part as plain text (scripts and styles removed, links as text with the address, nothing loaded), cut at 100 KB with "Show more". Attachments as a list only. Permission `mail.view_content`. Delivered mail: "Content not stored".
- **DNS evidence** per mail, beside the mail path: right after the scan efa-maillog asks the local Unbound again for what the checks used (SPF with its include and redirect chain, MX/A/AAAA of the sender domain, DMARC, each DKIM and ARC key with type and size, PTR and forward check of the client), with TTL, DNSSEC validation (AD), time and resolver; blocklist hits from the symbols of rspamd. Each record set is stored once and referred to. A full queue drops the evidence, the mail never waits. Shown in the detail view, as JSON with `export`. Kept and deleted with the headers.
- Reading headers, evidence or content is in the audit log.
- **Header export**: single file from the detail view (`<date>_<queue ID>.headers.txt`, original line ends, evidence as `.evidence.json`). In bulk with the filters of the search: `headers-export` on the page Mail log, by the API and on the console, a ZIP with one file per mail and `index.csv` (formula-safe; subject only with its permission), optionally with the evidence. Written mail by mail, at most 50,000 per export; above 5,000 it runs in the background and the link works when it is done. Web exports are for the login that made them only and go after 24 hours; console exports go to `/var/lib/eFa/exports/` with mode 0600. Needs `mail.view_headers` and `export`, only within the own scope; each export is in the audit log.

### Documentation

- `docs/`: README (index), install, migration, first steps, one page per menu group (dashboard, mail & quarantine, protection, domains & tenants, users & access, monitoring & reports, system), FAQ. Short and by task, with 27 screenshots in `docs/images/` (desktop 1280 px, three at phone width).
- The screenshots come from a demo copy of the web interface on 127.0.0.1 of the test host: the same pages with demo data (example.com, example.org, example.net, 192.0.2.x, made-up people) instead of efactl; outputs of the real host only after every address, host and domain was replaced, mail data made up. Each image was checked by hand.
- Found while checking them, and fixed: the groups table broke the permissions letter by letter (now a count that opens the list); held mail on a phone was 11,786 px high with six buttons in one column (now one block per mail); the mail report and the DKIM page were very long (yesterday, 7 days, rotation, ARC and DMARC now closed); the Wazuh field "groups" offered the eFa groups; the stored-header settings were missing in the domain settings form; a tenant admin saw "Last backup: None" with a warning; a successful system update was listed under "Needs attention" with a link to DKIM; users saw "Release" for a virus they cannot release.

### Q1 CI

- `scripts/ci.sh` on an EL9 build and test host: Python compiles, POSIX sh syntax, the OS-call check (`scripts/os_lint.py` against `scripts/os-calls-baseline.json`), unit tests, the self-tests of seven programs, the RPM build; with `--install` it also installs the built packages on the host (the upgrade path) and checks status, `rpm -V` and the self-test of the installed efactl. The last line says OK or FAILED.
- `.forgejo/workflows/ci.yml` runs the same once a Forgejo Actions runner with the label `el9` exists (planned for 6.0.0.5). Until then `scripts/ci.sh --install` runs on the test host before each push to Forgejo.
- Fresh install: `scripts/ci.sh --fresh` (part of `--install`) sets the test host up anew from the packages of the run, with the wizard and the first boot, checks it and puts it back as it was. No container (the package scripts need systemd) and no fresh VM per run (that needs a hypervisor the CI can drive).
- `docs/FREEBSD-PORT.md` and `docs/EL10-PORT.md`: what calls the OS directly today, and what the ports need.

### Also added

- `X-eFa-next-ARC-Sealer: eFa-next/<version>; host=<FQDN>; i=<instance>; d=<domain>; s=<selector>`, only on mail rspamd really sealed. Headers of that name from outside are removed. rspamd reads the version when it loads its config, and the package reloads rspamd after an update.
- `X-eFa-next-DKIM-Signer: eFa-next DKIM Signer Version <version>`, only on mail rspamd really signed, the same way.
- Website links for the blocklists, warning and switch for root login through SSH.

### 5f: strict audit mode

- `efactl audit-mode --mode on --reason ...`, also on the page Users under Strict audit mode. Only a super admin switches it, always with a reason; the switch itself is logged, switching off also goes out as a warning event. Off by default, also after an upgrade.
- While on, every efactl call (command, arguments with secrets masked, result ok, error or denied) and every request of the web interface (page view, search with its filters, download, API call, refusal, login, failed login, logout, session timeout) is one line in `/var/log/eFa/audit-strict.log`: ts in UTC, user, role, tenant, source IP, hashed session, action, object, result, old and new, reason.
- Each line carries an HMAC-SHA256 over itself and the MAC before it; the key is root only. `efactl audit-verify` checks the chain and names the first broken line. The file is append only (chattr +a). A new day closes the file with a last entry and a signature, the next file goes on with the chain. Closed files are kept 365 days by default (30 to 3650).
- Fail closed: if the log cannot be written, the action is refused. Mail flow never depends on it.
- Optional: a reason before the content or headers of a mail is shown; auditd rules for /etc/eFa, /etc/postfix, /etc/rspamd and the eFa programs, loaded with augenrules.
- Each entry also goes to events.json, so to Syslog, OTLP and Wazuh, when one of them is on.

### 5m: eFa 5.0 settings to a fresh host

- `migration/efa5-export` reads an eFa 5.0 host, changes nothing, and writes an encrypted eFa-next backup (gpg AES256 like the other backups, password twice, at least 12 characters). `--preview` only shows the report.
- The restore of that file makes its safety backup, then applies the settings once through the same efactl commands as `efa-migrate`, and renames the plan. The report says taken over, adjusted, not taken over, plus every failed step; it stays in `/etc/eFa/efa5-import/report.txt`, the folder for root only.
- The conversion is in `efa5_convert.py`, shared by `efa-migrate` and `efa5-export`. A fresh host keeps its own host name, address, certificate and the Postfix settings it sets itself; files a setting names must exist there.

## Tested on the test system

- Roles through the API with one token per role, tenant limits in the search and in a real held mail, audit entries with old and new values, no password in the audit table or file.
- Search and CSV, the query plan uses the indexes. SIEM as JSON and RFC 5424 to a local UDP listener. `/metrics`.
- OIDC in a real headless Chromium against a small local test provider, across two sites, with the session cookie Strict.
- OTLP against a local TLS receiver: refused without the CA, accepted with it, 401 with a clear message for a wrong token, differing token entries refused, token never in status or audit log, logs and metrics received with their resource attributes, receiver down with buffer and backoff, catch-up when it is back, a full buffer drops the oldest and counts them.
- Web interface on the test system in a real browser (Edge/Chromium through playwright-core), five roles (super admin, tenant admin, domain manager, helpdesk, user) of a demo tenant with example.com and example.org: every page, every action by GET (303, never 405), every form with required fields sent empty (a clear message each time), phone width 390 px (no page wider than the screen), dark mode. Before: 27 pages in 5 groups, 2 internal commands shown as forms (404), an icon 404 on each page, about 60 fixed choices as free text. After: 21 pages in 7 groups, none of these errors, the remaining text fields hold free values only. Screenshots before and after for each role on the admin PC (not in the repository: real host).
- Header export on the test system: console ZIP valid with CRLF kept and index.csv, a path outside the export folder and a job given from outside refused; a domain manager refused, the helpdesk of the demo tenant gets its mails, its `--out` ignored; a background run with the limit lowered for the test; in the web interface the form has no internal fields, the helpdesk downloads its ZIP, a tenant admin gets 404 for it; three exports in the audit log.
- Subjects, headers, evidence on the test system with three and two test mails to example.com, routed to 192.0.2.1 and deleted from the queue afterwards: an encoded subject decoded, an XSS subject stored as text and shown escaped, From/Reply-To/X-Mailer indexed and found by the search, headers about 313 bytes per mail stored (409 raw), 0.024 ms to compress; the detail view for helpdesk with download, refused for a user and a domain manager; the subject switch. Evidence: 7 record sets for the first mail, none new for the second; 753 bytes per mail with the records stored once, 1747 without; 1.3 ms and 0.8 ms CPU per mail from the cache; DNSSEC validated answers marked. RRSIG answers and the null MX of example.org were shown wrong at first, fixed.
- Fix on the test system: GET on update-system, reboot, greylisting-set, logout, backup download, logo upload: 303 to the page with the form; after a POST the result shows once, a reload shows the page. The script check matches the `firewall-cmd --reload` of cockpit-ws and, after a fix, the `systemd-update-helper mark-restart-system-units firewalld.service` of the firewalld package (the EL9 way of restarting after an update). No updates were pending: the left-out path only by the self-test. Planned at minute 16 for 21:20, the timer removed again; no system update was run.
- 5j part 3 on the test system with two tenants: the tenant admin of one reaches nothing of the other (usage, look, onboarding, directory, mapping, users, tokens, settings, DNS export, lock, limits, delete, a domain of the other); onboarding with a wrong and a right TXT record (lookup replaced in the test, the real lookup checked separately), the other tenant cannot verify or see it; limits for users and domains refuse, the quarantine limit writes the list efa-maillog reads as efa-web, and it stores nothing for that tenant; usage as JSON and CSV; a super admin token bound to a tenant cannot reboot or see the other tenant; logo upload as PNG works, SVG and a logo for the other tenant are refused, logo and colour shown after login; directory mapping to super admin or to a domain of the other tenant refused, a forged mapping row gives no login; lock with defer: logins refused, transport map has retry, unlock takes it out; delete removes users, DKIM key, route and mail log rows of that tenant only.
- 5j on the test system, one tenant with two domains, a domain manager of domain 1 only: through efactl, the API and the web interface nothing of domain 2 is shown or changed (DKIM, export, all-domains export, mail server, sender rule, spam, tenant, settings, rotation, DMARC history, users of domain 2, a stronger group in domain 1, rules, firewall, updates, Wazuh, backup, quarantine). Settings, status, rotation, ARC, DMARC output: no mention of domain 2. Users of domain 1 made by the manager. Inheritance tenant, domain, inherit back to tenant; the rspamd rule and rspamd configtest; TLS map in and out of the Postfix configuration. Retention: domain 1 keeps 10 days, global 30: a 15 days old mail of domain 1 gone, the domain 2 recipient of a shared mail kept.
- 5i-e on the test system with real logins over HTTPS: two devices of a tenant admin, a domain admin, a user of another domain. Each sees only what it may; ending a session of another domain or of a stronger user refused; the own phone ended, out after 5 s, laptop still in. Locked user out after 1 s, login refused; unlocked, login works. Logout ends the session. Audit has each action; only hashes stored.
- 5g on the test system: six users of the five roles made with the efactl of 6.0.0.3, twelve commands each, then the schema back to 6.0.0.3, upgrade, migration twice: every role runs exactly the same commands as before. Own group with domain scope, user in two groups with the scopes added up, copy of the helpdesk with tenant scope, predefined group refused. Tenant admin: super admin, global read-only, another tenant, a user of another tenant, own groups, self-disable, own group all refused; domain admin in the own tenant allowed, removal only with yes. Disabled user: login and --as refused. Last super admin (main admin file moved away for the test): remove, disable, demote refused. LDAP mapping with a dummy directory: two groups, then one, unmapped refused. Audit log with old and new per user and group, no password in it.
- Wazuh on the test system, where an agent of another Wazuh manager is installed and connected: status read only (4.14.7, connected, last keep-alive). `wazuh-check` downloaded 4.14.10 and 4.14.7 for x86_64, signature ok, scripts without firewall calls. `wazuh-config` on a copy of `ossec.conf`: differing passwords refused, manager and enrollment changed, one eFa block also after three runs, `wazuh-agentd -t` accepts the copy, the real file unchanged. events.json written with group wazuh. Rules and decoders: XML well-formed, IDs unique, references known; SCA YAML loads.
- Quarantine for users with SMTP from a non-local address: spam and EICAR held with `milter-discard`, the digest with its links, a link that only asks on GET, release once and no second time, allow the sender, login as the recipient who sees only their mail and cannot release the virus, release of the virus by the super-admin, the file gone after the last recipient, local mail not held, off again.
- Reports: values for all domains and per tenant, the mail in the queue with both parts, no second mail from a second run.
- Rules: limits by recipient, sender domain and tenant with `rspamc`, priorities, a route seen in the mail log, Postfix settings back to before after the last rule. Quarantine instead of rejecting: the limit and the spam mark with `rspamc`. From this host Postfix sees local mail, which gets no spam mark, so the hold itself was not seen.
- ARC: real seals with a test key, published through the local Unbound. `ARC_ALLOW` and `R_DKIM_ALLOW` on the sealed mail, the forged header gone, the header not signed, i=2 on a second seal.

- 5f on the test system: on with a reason; a read-only user and an auditor (test users, removed afterwards): reads logged as ok, the write of the read-only user and the switch by the auditor logged as denied, with their source addresses; a failed login through the web path; content of a mail refused without a reason and shown with one, both logged; key and log 0600, log append only; a changed line found at its line number, after restoring the file the chain is ok; a real rotation into a signed closed file, the chain ok over both files; an entry in events.json (switch for events patched for that one call, no export is set up here); off with a reason, nothing logged after that.
- 5m on the test system (fresh 6.0.0.3, then the current packages): a file built from the plan and config backup of the in-place migration of the test system in the morning, restored with `efactl restore --file`. 18 items taken over, 0 failed: 7 relay networks, 32 allowed, 198 blocked, 62 sender rules, 13 Postfix tables, Fail2Ban on; `postfix check` ok, status ok, audit entry, outbound block still in place. Third-party milters, postfix-ldap, Let's Encrypt and the own MailScanner rules named under not taken over.
- TUI in a pseudo-terminal of 80x24: a form with a plain field failed on a missing choice list, fixed; the TUI self-test now runs in the CI.
- Security self check and release check on the test system: open ports of two site services found (left as they are), root password login and SSH passwords found; release source 404 (private repository) reported as not reachable, nothing changed.
- Web admin password: two differing entries and a single line refused, the password file unchanged; a password as an argument no longer accepted.

## Not tested

- Content view and the evidence of a real external mail with DKIM and ARC: only with local test mails and the self-tests.
- 5j: LDAP and OIDC of a tenant against a real directory: only the mapping and the login logic with dummy groups. The TXT check with a real published record.
- 5j: the digest at its own hour and with its text only by the self-test (no mail sent out here).
- 5g: LDAP and OIDC against a real directory: only with the dummy groups. The web pages only by the self-test of efa-web.
- Wazuh: install, update, remove and a real enrollment were not run, because the agent on the test system belongs to another manager. No manager here, so no `wazuh-logtest`: the rules are checked for form and references only.
- OTLP against a real collector, mTLS. Login events end to end: only the parsing of the log lines.
- The digest in a real mail program, and the quarantine under load or with very large mail.
- Rules for a directory group against a real directory.
- OIDC with real Entra ID or Keycloak. LDAP against a real directory: the command lines ran against stand-in tools, the real tools only with no server.
- SIEM over TCP to a real SIEM. SELinux for a target port other than 514.
- The header after a real version change: only that it reads the current version.
- The upgrade test from 6.0.0.3 and the idle resource test, planned at the end.
- 5m: `efa5-export` itself on a running eFa 5.0 (no eFa 5.0 host left; the reading part is the unchanged code of `efa-migrate`). The web upload of the file.
- The root login switch key-only/off/on live: not run, needs the admin.

## Later

- One migration run in a single pass with final packages, when the snapshot gets reset.
