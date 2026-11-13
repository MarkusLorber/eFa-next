# Changelog

## 6.0.0.6 (release date: pending)

### Release upgrade: new mail held for every sender
- While the release upgrade holds new mail (421), the maintenance entry stays first in every list of client restrictions, also
  after the heal of the sender allow list ran during a package update: an allowed sender gets the 421 too. On the way back only
  the own entry goes; the list of before, with its order, stays (S36).
### Cluster: shared bans no longer count as repeat offences
- A ban another node of the cluster found is set in its own jail, efa-cluster (every port, as long as the master keeps it), not
  in the jail of the node that found it. recidive does not count these bans, so one event on one node no longer becomes a week
  on every node, and no node reports a shared ban again as its own (CL-RECIDIVE).

### Security standards and the hardening wizard: the strict lists, said plainly
- The SSH profile `bsi` takes the tables of BSI TR-02102-4 from standards.json, the same lists the check uses: ECDH over the
  NIST curves and DH group exchange, AES-GCM and AES-CTR, HMAC-SHA2 with encrypt-then-MAC first, ECDSA host keys only. The
  quantum-safe hybrid mlkem768x25519-sha256 stays in front. Not in it any more: curve25519, sntrup761, ChaCha20-Poly1305,
  Ed25519 and RSA host keys. Every client then sees the ECDSA host key on its next login (the preview says so); without an
  ECDSA host key the profile is refused. PermitRootLogin is never touched.
- The kernel settings add the sysctl values of CIS (rp_filter, log_martians, no source routing, no secure redirects); the
  status counts them as on only while the values are in effect.
- An SSH profile or kernel settings written by an older version show as outdated in the status, the check and the wizard;
  an update never rewrites them, the admin applies them again on purpose.
- A value outside the list of a standard counts as fulfilled only when the table `equivalents` in standards.json names it,
  with its source: the check then says "fulfilled through a stronger or equal standard" (X25519MLKEM768: NIST FIPS 203,
  RFC 10024; X25519: RFC 7748, RFC 8446, NIST SP 800-186; mlkem768x25519-sha256: NIST FIPS 203, RFC 10042; brainpool: RFC 5639,
  7027, 8734, BSI TR-03116-4). `"deliberate": {"on": false}` makes the check and the SSH profile strictly BSI.
- Mail offers brainpoolP256r1 (and brainpoolP256r1tls13 from Postfix 3.6), the web brainpoolP256r1tls13 where OpenSSL has it.
  Mail keeps X25519MLKEM768 out: Postfix 3.5 and 3.8 do not take its name.
- Mozilla modern: `efactl web-cert-set --mode ecdsa` (or the wizard item) gives the web interface its own Let's Encrypt
  certificate with an ECDSA P-384 key; the certificate of mail and its TLSA record stay.
- The preview names each chosen standard that stays not fulfilled, and why (an item not chosen); the dialog after Apply
  lists what stays open. An item that is on already is not named.
- DANE: with TLS required for all outgoing mail (encrypt), the wizard keeps it and explains why instead of stopping: Postfix
  has no "DANE where TLSA records exist, else TLS required". Switching to DANE anyway is a box of dane-set (audited).
- Crypto policy FUTURE: the warning says not on a mail server in production without a test (RSA 2048 partners, DKIM).
- The sandbox of the services: on EL10 the default also takes Valkey and nginx (they ran without a SELinux denial).

### Job applications for all domains
- One rule for all domains (`application-set --domain=*`, super admins only): its addresses are the parts before the @
  (jobs, karriere), each at the domain of the recipient. A domain with its own setting keeps it.

### Mail queue: why a mail is held
- Held mail shows its reason, from the hold line of the mail log (for the quarantine: "eFa quarantine: header X-Spam-Status:
  Yes, score=…"); postqueue gives none.

### Release upgrade to EL10: repository keys, settings files, services
- The finish takes the signing keys of the rspamd and eFa-next repositories only with their fingerprint, keeps them as local
  files and fetches the metadata without a question; a repository that does not answer fails a check (a production host
  stopped rspamd updates with "Signing key not found"). Every address form of the repository files is moved to EL10.
- The check after the upgrade names every service that ran before and not after it, the units of the host too (a warning).

### Settings files no longer readable by everyone
- The files below /etc/eFa are 0640 with the group of the service that reads them (the new group efa-conf for the web
  interface and the portal; efa-mailconf for the mail services, outbound.json and milter-health.json; efa-dkim-api) or root
  only; a stricter 0600 stays. The update heals existing hosts (`conf-modes-heal`). The security self-check no longer suggests
  `chmod o-r` for them (S32).
- The secrets of the web interface (admin password, session key, key of nginx) in /etc/efa-web are readable only for the web
  interface and the first-run wizard (group efa-websecret), no longer for the mail services; the update heals them (S37).

### Updates and pre-releases
- A host with a pre-release (6.0.0.6-alpha2) is offered the release of the same numbers only from an answer that says it is
  no pre-release, never a pre-release of the same numbers again; the display marks a pre-release. The way back of an update
  is the installed version itself, for a pre-release its own packages (testing channel or GitHub), no longer the release.
  The updater of 6.0.0.6-alpha2 itself still builds its way back from the release packages: take a VM snapshot before the
  update from the alpha to the release.

### 2FA and names in the interface
- The banner of the guided setup names which account has no 2FA: the main admin of the web interface (login admin) or the
  console admin over SSH, each with the way to set it up; the dashboard links to My account, 2FA. A code typed in for a login
  without active 2FA is said to be unchecked.
- The update display reads eFa-next installed, latest, update available.

### Fixes
- The dashboard of a domain admin failed when a notice named a domain outside its scope (only the text was filtered away);
  such a notice now goes as a whole.
- `efactl --self-test` refuses on a set-up host; only in CI (EFA_CI=yes) or with `--allow-service-changes`. As root it runs
  in a mount namespace of its own: settings, state, logs and the quarantine are overlays that are thrown away, and the
  commands that change services or the firewall do nothing there. It no longer restarts efa-cdr, switches freshclam or
  writes ARC keys, allow maps or state files on the host (S33).

### A dialog after the steps that change the system
- After Apply of a wizard (the hardening wizard of the security standards among them) and after the long steps (release
  upgrade, update, rollback, OS update, standards, OS hardening, the sandbox of the services, restore) a dialog says what
  happened: per setting before and now, or the names of what changed; when a step stopped, its reason, what it had changed
  already and what it took back, as efactl names them. A native dialog of the browser: the button has the focus, Esc
  closes it, the page behind stays as it was. No library, the script comes from the server itself (content security policy).

### Release upgrade to EL10: start with only a VM snapshot
- The start of the release upgrade may leave out the encrypted external backup (owner, 2026-11-12): only a super admin with
  password and 2FA, besides the snapshot box and the host name, with the sentence `without backup, snapshot only` (or
  `ohne Backup, nur Snapshot`) typed in (`efactl release-upgrade --action=start --snapshot=yes --hostname=... --no_backup=...`).
  The audit log names who started so and on which host, the page warns that the VM snapshot is then the only way back. Each
  start asks again; the default stays the backup, and the check "Backup works" after the first EL10 boot stays.

### Release upgrade and migration: findings of the acceptance
- The check "Settings unchanged" after the upgrade to EL10 took package files whose mode, owner or time differed (a host
  migrated from eFa 5) for changed settings, and the EL10 package's own sample files then failed it (postfix canonical,
  generic, relocated, virtual; unbound example.com.conf, remote-control.conf). Only the content counts now (rpm -V size,
  digest, link); a changed content still fails the check.
- A check that is no condition (leftover packages kept on purpose) is logged as a warning, not as FAILED.
- MIG-587: SMTP AUTH on port 587 of an eFa 5 host (Dovecot) is not taken over when its submission block is replaced; the
  audit log and the dashboard say so, the migration guide tells how to switch it on (submitters with a login, or the system
  accounts). New CI step efa5-587-auth.

### Version file /etc/eFa-next-Version
- The version of eFa-next is now in `/etc/eFa-next-Version`. `/etc/eFa-Version` stays as a symlink to it: the updater and
  the scripts of 6.0.0.5.x and older read that name. Every reader of eFa-next takes the new name first, the old one after.

### Legal texts: checked in CI, one new confirmation
- CI checks the legal texts (`scripts/legal_check.py`, called by `scripts/license_check.py`): DISCLAIMER.md in English
  and German with intended use, warranty and liability and the severability clause, every exclusion qualified by the law,
  LICENSE the unchanged AGPL-3.0, every package the RPMs require in THIRD-PARTY-NOTICES.md, and the references to the
  disclaimer in the setup, the web interface, efa-migrate and the blocklist confirmation.
- The confirmation of a blocklist excludes liability to the maximum extent permitted by law and refers to DISCLAIMER.md
  with its severability clause; the footer of the web interface says the same. THIRD-PARTY-NOTICES.md names the operating
  system packages eFa-next requires, with their licenses from the CentOS Stream 9 spec files.
- THIRD-PARTY-NOTICES.md is one of the legal texts, so their digest changes: after the update the first admin login, the
  setup and efa-migrate ask once to confirm the legal texts again.
- The confirmation text of the blocklists changed too (state of the terms 2026-11-13): the dashboard asks the admins once to
  confirm each active blocklist again; active lists stay active until then.
- Mailspike links its terms of use (mailspike.io/ip_verify/usage); its note says what they allow: free via public DNS for
  low-volume sites, up to 100,000 messages and 100,000 DNS queries per day, larger sites contact Mailspike.
### Tests of the functions with real mail, rspamd modules watched
- Every CI run with an install (scripts/ci.sh --install) now sends real mail through Postfix, rspamd and the milters and
### Sending limits for the whole cluster, tests for the open functions
- The sending limits (recipients and target domains per sender, per sender domain and per tenant) now hold for the cluster
  as a whole, not per node (8g): the nodes report their counts of the hour to the master every half minute over the cluster
  connection (mutual TLS) and take the counts of the others into their Redis. A target domain reached through two nodes
  counts once. Without a cluster nothing changes; while the master is not reached each node counts its own mail. See
  docs/cluster.md. The Redis protocol of efa-outbound is now the library efa_redis, which also reads bulk answers and lists.
- New tests for functions that had none (TST-1, SSO-1, M1-1, 5s, N6): the 53 writing efactl commands without a test of their
  own; single sign-on (oidc-set, oidc-start, oidc-finish, tenant-oidc-set) end to end against a test provider with a real
  RSA key, PKCE and signed ID tokens, including forged, unsigned, expired and foreign tokens; the ARC set of efa-cdr checked by
  an independent verifier (dkimpy) after a change of the mail (CI step arc-independent, needs python3-dkim from EPEL); passkeys
  in Chromium with its virtual authenticator, registration and login without a password, replay and foreign keys (CI step
  passkey-browser, the Python of the live-test venv); taking mail back over IMAP against a Dovecot of the test with a master
  login, move and delete (CI step retro-imap, the Dovecot of the host is not touched).

### Tests of the functions with real mail, rspamd modules watched
- Every CI run with installation (scripts/ci.sh --install) now sends real mail through Postfix, rspamd and the milters and
  checks the result, one check per function: BEC VIP names, programs as attachments, graymail, own SHA-256 blocks, job
  applications, warning banner, link check, tracking protection, DLP of outgoing mail, header privacy and DKIM signing
  (scripts/live_features.py, step live-features), and the mail paths clean, spam, virus, quarantine and release (step
  live-mail, before only in the manual live test). Incoming mail comes through XCLIENT as a client outside the own networks.
  Nothing leaves the host: every transport waits for the time of the test, every mail of the run is deleted afterwards, and
  each function switched on for its check is switched off again.
- rspamd only logs an own module that fails to load and goes on without it. eFa-next now checks after every package change,
  in the daily mail check and in CI that each switched-on module (BEC, attachments, graymail, own blocks, applications, QR
  codes and the others) is loaded: one that is not is red on the dashboard, in `efactl status` and mailed to the admin. The
  self-test compiles the Lua of every module, the user quarantine logs its load error like the others.

### SecuriteInfo: account tier and URLs
- The row of SecuriteInfo (Spam & virus, Virus signatures) has a choice of the account tier and a field for the
  DatabaseCustomURL lines of the SecuriteInfo setup page. Tier Basic: at most one round of downloads every 30 minutes and at
  most 300 kB/s, kept by the job itself (the time is written before the first request and holds across restarts and manual
  runs; the download is read at the rate). The row shows the tier in effect and when SecuriteInfo was last asked.
- The lines are checked strictly (https, securiteinfo.com only, a ClamAV database file, at most 40) and hold the
  subscription key: stored for root only (0600), sent on stdin, never shown, logged or in the audit log. The page only says
  how many URLs are stored; replace or delete them. Super admins only; `efactl clam-securiteinfo-set`.
- Cluster: the key of SecuriteInfo stays on the master. Tier and URLs are set there only; the account ID no longer goes into
  the cluster journal or the snapshot for a new node. A node never asks SecuriteInfo; its row says "waiting for the master"
  until it has the checked signature files from the master, then "Signatures from the master, last received <time>". The
  upgrade takes the account ID and URL lines out of older journal entries (audited, without the key) and off the nodes.
  Older backups of a cluster master or node can still hold the key in the journal or the node settings: if a cluster was
  used with SecuriteInfo, renew the key at SecuriteInfo.
- Cluster: only the master downloads the ClamAV signatures of Sanesecurity, URLhaus, InterServer and SecuriteInfo. It lists
  them with size and SHA-256 in a manifest and tells the nodes through the cluster journal; each node fetches what it lacks
  over the cluster port with mutual TLS, checks size, SHA-256 and that clamscan loads it, swaps it in atomically and keeps
  the old file when a check fails. The master serves only the names of its manifest (no links, nothing outside the folder).
  Docs: docs/cluster.md.
- Cluster, also from the master: the RDAP list, the lookalike domains of crt.sh, the exploited list of EUVD and the threat
  feeds; the nodes ask none of them themselves. The API keys of threat feeds stay on the master (also removed from older
  journal entries and from the nodes on upgrade).
- Cluster: the IP blocklists too. Only the master fetches the feeds; a node checks the lists it gets (public networks only)
  and loads them into its own table efa_block in one nft transaction; the firewall stays host-local, the loaded lists stay
  when nft refuses.
- Cluster: the official ClamAV databases too. A node stops freshclam while its master answers and gets main, daily and
  bytecode from it, checked by clamscan; freshclam runs again in fallback and after leaving the cluster (only if eFa-next
  turned it off). Large transfers run on their own and are tried again every ten minutes when they fail.
- Cluster: lookalike alerts are mailed once. Only the master sends; a node in fallback notes its findings, the first node
  of the list sends after a day without the master, and the master takes the findings of its nodes on their return and
  alerts once per domain.
- Cluster, master out of reach: after a grace time per source (at least two hours) a node downloads the public sources
  itself with the same checks, never SecuriteInfo or keyed feeds; it says so on the dashboard and in the audit log, and goes
  back to the files of the master as soon as the master answers.

### Attack alert: banner on every page, lamps and gauges on the dashboard
- Once a minute eFa-next checks the host for attacks and problems: SMTP connection floods (possible DDoS), SYN floods,
  password guessing on SMTP AUTH and web logins, many rejects or Fail2Ban bans, spam and virus waves, a filling mail queue,
  stopped services, a full disk, little free memory and very high load. A flood counts only above a fixed floor and well
  above the normal value of the last hour, so a busy server stays green at its usual load.
- Whatever is found shows as a banner right under the top bar of every admin page (red for an attack or a fault, amber for
  something unusual), with since when, a link to the page that helps and, for super admins, the addresses that caused most of
  it. An alert stays for five minutes after the value fell back (marked as easing), so it does not flicker.
- The dashboard starts with *Status at a glance*: a lamp per service (mail server, spam filter, virus scanner, database,
  cache, DNS, web server, Fail2Ban, firewall, milters) and for attacks, spam and viruses, the queue and the resources, and
  gauges for CPU, RAM, disk, mails and spam share of the last 10 minutes, SMTP connections per minute and failed logins.
  Banner and board renew themselves every 30 seconds while the page is visible.
- Resource-light: no new service or timer. efa-web runs `efactl threat-run` once a minute in its load thread; it reads only
  the new journal lines of Postfix, Fail2Ban and efa-web, the TCP counters of the kernel, two counts of the mail log (the
  normal value of the day before is renewed every 15 minutes) and the queue folders. A page reads only the kept answer.
- *Security > Attack alert*: the last result and the sensitivity (low: twice the limits, normal, high: half the limits).
  Tenant admins see the alert without addresses. Docs: docs/dashboard.md.

### Forms without console rules, password once per five minutes (UI-M4, UI-M5)
- Field labels no longer carry the rules of the console: "empty keeps it" and the like are the grey text in the empty
  field, "- for none" is a tick box Clear next to the field (it sends the - of the console), "type yes" is a tick box.
  The labels of efactl stay as they are for the console.
- Cards that need your password show the password and 2FA fields only when the last confirmation is over; for the
  five minutes after it, the card says how long it still holds. The check on the server is unchanged.

### Package upgrade: the submission service is left alone
- Each package upgrade rewrote master.cf with the same content and left a master.cf.efa-submission-<time>.bak, because the
  submission service was compared with its -o options inline. A rewrite now only happens when a field or an option really
  differs. After the EL10 release upgrade this had made the check "Settings unchanged" fail and kept the maintenance mode on.

### Security standards
- New page *Security standards* (superadmin, step-up 2FA): choose BSI TR-02102-1/-2/-4, TR-03116-4, TR-03108, RFC 9325,
  Mozilla modern or intermediate, NIST SP 800-52 Rev. 2 or CIS (sshd, sysctl, crypto policy). A preview shows each setting
  now and after; applying it needs `--apply yes` (and `--confirm yes` with warnings), writes a rollback point and an audit
  entry. The strictest value of the chosen standards is applied, never below the limit of eFa-next, never weaker than now.
- Mozilla modern sets TLS 1.3 only for the web interface; port 587 stays at TLS 1.2. Port 25 stays opportunistic unless TLS
  there is required on purpose.
- `efactl standards-check` checks every standard against the settings in effect: fulfilled, over-fulfilled, not fulfilled
  or needs DNS records, with the reason of each finding. On the dashboard, in the PDF of the hardening report, and a notice
  for a chosen standard that is not fulfilled.
- HSTS now with max-age 63072000 (two years), as Mozilla asks.
### More ClamAV signatures: the card
- Each source (URLhaus, InterServer, SecuriteInfo) has its own switch with the state in effect. Switching one on with terms not
  yet accepted opens the terms first: the link of the provider ("no published terms" for InterServer) and a tick box. The terms
  are accepted once; switching a source off and on again does not ask again. The account ID of SecuriteInfo has its field in
  its row; it goes to efactl on stdin and is never shown. Super admins only; each change is in the audit log.
- Fixed column widths: headers and badges no longer break letter by letter; on a phone the rows stack.
- The live UI test flags any table header, pill, badge or switch narrower than its longest word, at 1280 and 390 px.

### Dashboard notices open their setting
- Each notice links to the page and the card that holds its setting, named in the link ("Domain settings → Job
  applications"), in the expert view where only that view shows the card. Before, every notice opened Maintenance, Last
  system update. Job applications open with the first domain that still needs an answer.
### Web interface: 2026 look, search with suggestions
- The search of the menu suggests while typing: pages, actions and settings with a one-line explanation (the help text of
  the card), synonyms in English and German ("whitelist" finds the sender lists), and the mail log with a filter for an
  address, domain, IP or queue ID. One index per login and language, only what the login may open; matched in the
  browser, nothing per keystroke. Keyboard: / focuses, arrow keys, Enter, Esc.
- One look for all pages: cards, tables, buttons, the menu and the sections in the style of the mail views; list tables
  become cards on a phone; dangerous buttons ask in a small dialog of the page.
- The lists without arguments (users, groups, tenants, sessions, tokens, blocklists and the others) show in the Standard
  view too, not only in the Expert view; the rights of each login stay the same.

### Mail log, live log and quarantine
- Allow, block or search all mails from the sender of a mail: a click on the sender, its domain or the IP in the mail log,
  the live log or the quarantine opens a small menu. Allow and Block write through `sender-add` and the own IP blocklist
  (`blocklist-entry`), no new list. A dialog shows the exact entry and list first and warns on a clash with the other list,
  on an own domain and on private, relay, cluster or own addresses (these need the confirmation; never-blocked addresses
  stay refused). Super admins only for global entries and IPs; tenant and domain admins get a rule for an own recipient
  domain. A message with Undo follows; every action is in the audit log with the queue ID of the mail.
  New commands: `sender-action-check`, `sender-action`.
- Mail log search: filters `from:`, `domain:`, `ip:`, `result:` in the search field, and the fields Domain and IP.
- Readable tables: full width, the time as its age with the exact time on hover, badges for the result and SPF, DKIM and
  DMARC, queue ID and IP in a fixed-width font, no wrapping of time, queue ID, IP, result and score, long values shortened
  with the full text in the tooltip, sticky table heads, cards below 900 pixels. Details of a mail open at the side.
- The search stands in the page address after `#` (bookmarks, links to colleagues); that part never reaches the server.
- Quarantine: actions on the row under the mouse and in a "…" menu; tick several mails to deliver, delete or block their
  senders at once.
### Help for every card and field, German throughout (UI-HELP)
- Every card of the admin interface explains in one sentence under its title what it does; an (i) next to the title opens
  the whole explanation, and an (i) next to each field explains that field. The popups use the popover of the browser, no
  script. The texts are in efa_help.py (444 cards, 789 fields), English and German.
- One title per card: the second heading with the command name (": switch", ": settings") is gone.
- German interface without English left over: the choices of every pulldown, the switch labels (Active, On/Off), Help,
  none, Tenant, Domain and Groups are translated (de.po 3433 of 3433 texts).
- The Admin email card no longer points to efactl admin-password for the web password: that is under My account.
- tests/test_ui_texts.py fails for a card or field without help, for help of a command or field that does not exist, and
  for a shown text without German translation; scripts/i18n_extract.py collects the help, card titles, labels and choices.

### Wazuh agent installed by someone else
- The release upgrade to EL10 leaves a Wazuh agent exactly as it is (the same build serves EL9 and EL10; its package scripts
  would stop, restart or unmask it): no update, kept by leapp; if leapp would change it, the upgrade stops before the
  reboot. After the upgrade its package, ossec.conf, client.keys and its enabled and running state must be as before, or
  maintenance stays on. Preflight shows the agent and lists packages from other repositories.
- The hint for an agent eFa-next did not install named a command that does not exist ("wazuh-config", without efactl and
  without the confirmation). It now names `efactl wazuh-config --adopt yes --confirm yes`, and the status shows what
  eFa-next finds in its ossec.conf. A missing confirmation on the console says "Add --confirm yes to confirm.".
- Taking it over changes nothing: the settings are read from ossec.conf into wazuh.json (a copy of ossec.conf beside it),
  no password prompt, ossec.conf and client.keys stay byte for byte, the agent is not started, stopped, restarted or
  enrolled; an agent that is off stays off. Before, the take-over rewrote ossec.conf with the settings of eFa-next and
  turned active response off. `--adopt no` gives it back.
- The upgrade of eFa-next, the migration from eFa 5 and the release upgrade take an existing agent over the same way and
  say so in their report; if its ossec.conf cannot be read, the agent stays untouched and the upgrade goes on.
- A setting changed through eFa-next keeps what the agent had (enrollment name, groups and other values, its own blocks,
  active response unless the admin turns it off) and restarts a taken-over agent only if it runs.
- Ctrl+C at a password prompt ends with "aborted, nothing changed" (exit 130), without a traceback.

### EL10 support
- Tested on a fresh AlmaLinux 10 host and on an upgrade of an AlmaLinux 9 host to 10 (EL10 gate); the release upgrade in the
  web interface stays locked until the signed repository repo.efa-next.eu/el10 exists.
- A platform module for EL10 (AlmaLinux, Rocky, RHEL 10): Valkey instead of Redis (service, CLI, config, account), lmdb
  instead of Berkeley DB for every Postfix table and cache, update sources from repo.efa-next.eu/el10. On EL9 nothing changes:
  the tables stay hash, Redis stays.
- build.bash takes AlmaLinux 10 as well as EL9: the repositories by the major version of the host (EPEL 9 or 10, rspamd
  centos-9 or centos-10, eFa-next from repo.efa-next.eu/el9 or /el10, the GitHub mirror only for EL9) and the nginx module
  stream only on EL9. RHEL 10 stays closed until it is tested, Rocky Linux 10 and others are refused. build-rpms.py finds the
  packages also where mock puts them (RPMS/ without noarch/).
- The release upgrade also switches the options in master.cf to lmdb, moves the Redis data to Valkey, switches efa-next.repo
  and rspamd.repo to EL10, and compares the settings exported before `leapp upgrade` with those after the first EL10 boot: any
  difference keeps the maintenance mode on. `nginx -t` is one of the checks.
- After every change of the installed packages a check runs (efa-os-check): the configuration tests of Postfix, nginx,
  rspamd, Unbound and fail2ban, the mail services running, and .rpmnew/.rpmsave files beside managed files. A failure is red on
  the dashboard and mailed to the admin. The health service watches nginx, MariaDB, Unbound, fail2ban and firewalld too.
- dnf keeps ClamAV, flask, werkzeug, waitress, pymilter and fail2ban on their tested major versions, as rspamd already.
- Backups also hold rspamd override.d, the fail2ban jails, the ClamAV daemon settings and the SSH profile; the held mail and
  the Redis/Valkey data are kept as data, a restore does not write them back.

### Release upgrade to EL10
- Maintenance & update has a section Release-Upgrade for super admins (API: 403 for everyone else): AlmaLinux 9 to 10 with
  ELevate in fixed steps (`efactl release-upgrade --action=preflight|preupgrade|start|abort|status`). Preflight checks EL9,
  eFa-next 6.0.0.6, the EL10 repository of eFa-next (missing for now, so the upgrade cannot start yet), x86-64-v3, free space (/boot: 400 MB, a warning below 600 MB, leapp decides),
  pending updates, keyfiles and time, and warns of network drivers EL10 no longer maintains and of Postfix hash:/btree: maps.
  Preupgrade installs ELevate with leapp vendor files for the eFa-next and rspamd repositories and stops at any inhibitor.
  Start asks for the password, the 2FA code, a confirmed VM snapshot and the typed host name, makes an encrypted backup that
  must reach every external target with the same checksum and pass a test extract, gives new mail 421, then runs leapp
  upgrade. After the first EL10 boot `efa-release-upgrade-finish.service` runs mariadb-upgrade, switches the Postfix maps to
  lmdb:, sets SELinux enforcing, removes ELevate and checks the system; mail is accepted again only when every check passes.
  The test mails of the checks (a clean one, GTUBE, EICAR) never leave the host: the delivering transports wait while they are
  sent, and an accepted one is deleted from the queue by its id.
  The checks after the first EL10 boot keep their mark until they have run to their end, so a crash or power cut in between
  runs them again at the next boot (the mail block stays on meanwhile).
  The 421 during the upgrade also holds for the smtpd services with a client list of their own in master.cf (such as
  submission), which the setting in main.cf did not reach; the lists of before come back with the mail.
- leapp no longer removes eFa-next: the eFa-next repository is enabled while leapp runs (leapp takes its vendor files only
  then), and preupgrade as well as start stop before the reboot when the leapp log shows the vendor not taken, eFa-next not
  in the upgrade, or eFa-next or a package it needs removed. A safety net outside the packages installs eFa-next again at
  the first EL10 boot if it is missing anyway, or keeps the maintenance mode on with a note on the console.
  For the leapp run nginx, sendmail-milter and python3-pytz are kept (the package data of leapp-data-almalinux drops them,
  EL10 has them), eFa-next and its direct needs come from the target repositories, and EPEL is that of the target release
  (10.2), through leapp's own customisation files, which are put back as shipped afterwards.
  Preflight stops on network teaming (team connections or links): EL10 has no teamd, so the host would have no network after
  the upgrade; convert to a bond first.
- After the first EL10 boot the checks wait for leapp's own last phase (leapp_resume.service), take leapp's names off the
  exclude= line of dnf.conf, remove ELevate, leapp and the el9 kernels (verified afterwards), move the .rpmnew/.rpmsave files
  beside the files eFa-next writes itself to /var/lib/eFa/release-upgrade/rpmnew/, allow perl-locale (EL10 split of
  perl-POSIX), and no longer count unchanged files of a package as changed settings; what an admin changed still counts.
  Once every check passed, what leapp leaves on disk goes (/etc/leapp/files, /var/lib/leapp, /root/tmp_leapp_py3; its logs
  stay). Before the upgrade the queue drain waits only for mail on its way; deferred mail stays queued and is counted in the
  log, it goes out on its next try after the upgrade.
- The release upgrade is in the standard view for super admins (other logins never see it), with a red warning above the
  form: no way back except a VM snapshot, 30 to 60 minutes without mail. Its status card shows the state, the waiting step,
  the time of the last change and the last message first; the whole record is folded under Details.
  See docs/release-upgrade.md.

### Security
- DNS resolver for other networks: the Unbound of this host can answer listed networks too (the second MX), IPv4 and IPv6,
  each in Unbound and as two firewall rules for port 53 from that network only (runtime and permanent, no reload); never
  0.0.0.0/0, nothing wider than /8 or /32, outside the private ranges only with a typed yes; rate limits on; password and
  2FA code asked. Optional second resolver of the host (the other MX). Kept in the backup, written again on every update.
- SELinux: no denial of fail2ban at boot on hosts without IPv6 (it asked the kernel for the IPv6 module); the request stays
  denied, only its log entry goes, as for freshclam.
- Migration from eFa 5: the submission service (port 587) of eFa 5 stayed in master.cf after a migration: SASL through
  dovecot, which the migration removes, checks of its own (also a placeholder blocklist), no TLS towards relays. The
  migration now puts the submission service of eFa-next in its place, and the update does the same on hosts migrated
  before (master.cf kept as .bak, audited); what efactl itself sets on 587 (SASL, milters) stays. An smtps service
  (465) of eFa 5 with the placeholder blocklist goes too.
- Network form: IPv6 can be set to disabled, and the form shows the IPv6 that is in effect (the method of the connection,
  or disabled with a note when the kernel has IPv6 off) instead of a default; sent unchanged, IPv6 stays as it is. The
  consistency check finds every form field with a default or a pulldown whose current value may be missing.
- My account (top right, every login): name and phone, a new email address (it counts once a link to it is clicked, the
  old address gets a note), the own password, 2FA with a QR code, a new app (the old one counts until the new one is
  confirmed), new recovery codes and 2FA off. Address, password and 2FA ask the password again, with the current 2FA code
  if one is set up, every time; a wrong one counts as a failed login. Each change is in the audit log. A login without
  2FA sees a warning on the dashboard. `efactl totp-setup --qr` shows the QR code on the console.
- The top right of the web interface and the user portal always shows who is logged in (login name and role); its menu
  holds My account and Log out. Log out is no longer at the end of the sidebar.
- The timer jobs that start again on their own (firewall guard, CVE watch, IP blocklists, events, mail report, outbound hold,
  Sanesecurity, reboot check) no longer stay "failed" when an update restarts the units of eFa-next in the middle of a run;
  the automatic update and the DKIM key rotation still show such an end as a failure.
- Removing a user now removes everything bound to it in one transaction: its 2FA secret and recovery codes, passkeys, API
  tokens, groups and login links of the portal; its sessions end at once, and the audit log names what went. Before, the 2FA
  secret and the passkeys stayed in the database. The update deletes such left-over rows of users removed before, once,
  with their count in the audit log.
- A restore that was killed (power cut, kill -9) left /etc/eFa/restore-running behind, and every update said "A restore is
  running." for good. The marker now names its process; an update removes a marker whose process is gone (or one of an older
  version after 2 hours), with an entry in the audit log.
- Migration from eFa 5: after sender_access moved to the sender lists, Postfix no longer reads that file (its OK lines let a
  faked envelope sender past every check); the report says which restriction lists changed. The allowed senders from it are
  named on the dashboard until they are checked, with the advice to keep only exact addresses.
- SELinux: no denials on hosts without IPv6. Redis listens on 127.0.0.1 only there (its default tried ::1), and the
  attempt of freshclam to use IPv6 is no longer logged as a denial.
- Test installation from the source: the command in docs/install.md and `build.bash source` take a tag as well as a branch
  (a tag is fetched and checked out, only a branch is pulled; `git pull` failed on a tag).
- Migration: docs/migration.md says where efa-migrate comes from (the source of the release) and what the legal
  confirmation accepts. `efa-migrate --legal-digest` shows the texts, their digest, how to check it with sha256sum and the
  command line of an unattended run; the prompt names the digest correctly (it is no hash of the PDF). Nothing is accepted
  without the person.
- efa-cluster and efa-dkim-api are not started on a host without their certificate (no cluster, no provisioning API);
  before, a new install started them again and again every few seconds.
- Security advisories of eFa-next (advisories/advisories.json) are published signed with each release at
  https://repo.efa-next.eu/advisories/; the CVE watch of the hosts takes them only with a valid signature of the repository
  key and keeps the last good copy otherwise. The first entries are the fixes of 6.0.0.5.1.
- The advisories are published by the release step itself, signed and checked online, and name the fixed release without
  the platform (one entry for EL9 and EL10).
- The dashboard names an eFa-next service that failed or starts again and again (the health service reports it), instead
  of a quiet restart loop.
- An update of the packages on a set-up host is never taken for a first install, also when /etc/eFa-Version is missing:
  the first-install steps would have replaced its nginx, rspamd and Postfix settings.
- The admin web interface has no sudo rule any more: it reaches efactl only through efactl-runner, also for the backup
  download and the backup and logo upload (as pipes handed over the socket). The rule of 6.0.0.5 and older is removed on the
  update. `efa-web.service` now runs with `NoNewPrivileges`, a read-only file system, no capabilities, a system call filter and
  no access to the private keys of the host.
- Restore: the SQL of a backup runs with the database client in sandbox mode (no client commands). An unsigned backup (6.0.0.4
  and older, efa5-export) may only be restored by the main admin. A backup with two entries of the same name is refused, and a
  restore never writes through a link that is already on the host.
- Single sign-on (OIDC): an account is bound to the issuer and subject of its login, no longer to the name the provider sends;
  an e-mail address counts only when the provider marks it as checked (`email_verified`), also for the login directory of a
  tenant. Accounts of 6.0.0.5 are bound on their next login. ID tokens that are not valid yet (`nbf`, `iat`) are refused.
- Login directories (LDAP, OIDC, also those of tenants) are never reached at this host itself, its loopback, link-local
  addresses (cloud metadata) or other special addresses; their connection errors stay in the log instead of the answer.
- The web interface and the portal take the address of the browser (X-Real-IP) only from nginx, which sends a key of its own
  with it: another local process can no longer forge an address for the audit, the login lockout and the admin allowlist.
- efactl takes from the provisioning API (efa-dkim-api) only its two calls, word for word.
- efactl-runner takes a pipe from the web interface, and with it the long time limit of a download, only for the backup
  download and upload and the logo upload; any other call with a pipe is refused.
- A settings file that is no valid JSON is named in a clear error instead of a traceback; it never counts as the default.
- Two writers of the same settings file at once no longer take each other's temporary file (a service start could fail).
- The outbound milter (DLP, disclaimers, PDF encryption) and the sandbox service always find the files systemd hands them,
  also after a restore from a host without these features; before, they did not start then, and with DLP or PDF encryption on, mail on port 587 waited.
- Files with keys are created with their final rights, never readable by everyone for a moment.
- The header export is streamed instead of read into memory.
- The hourly job runs each of its steps on its own: a step that fails, or a mail log that cannot be read, is logged and
  named in the event `hourly_job_failed`; the other steps still run, the daily check of the security minimum and the EU lock
  too.
- The mail log service takes scan results and mail for the quarantine only from rspamd: a post from any other local
  process is refused, so it can no longer write log entries or put mail into the quarantine.
- Sending limits and taken-over accounts (A1, 9j): the counts per sender, sender domain and tenant are kept in Redis for the
  running hour, so a restart of the outbound service no longer starts them from zero; if Redis does not answer they are
  counted in memory as before. One notice per sender and hour, also after a restart.
- Require TLS on port 25 (5t), as docs/tls-profiles.md describes it: a switch on the card TLS profile, off by default and
  after an update, on only after the warning is confirmed (RFC 3207: a public mail server normally accepts mail without TLS);
  the card shows the sessions on port 25 of the last 7 days and the senders without TLS. Only the SMTP service on port 25
  requires it, never submission or the internal ports; audited.
- Documentation says only what is built: docs/bulk.md (the pace is one per transport; own sender IP, a pace per provider,
  warm-up and campaign statistics are planned), the known limits of 6.0.0.5 completed (docs/STATUS-6.0.0.5.md), the cluster
  journal is AES-256-GCM, no IMAP service, internal DNS servers only for their domains (README, docs/tls-profiles.md,
  docs/security-model.md).
- systemd sandbox (5v h, D-1) for rspamd, clamd, freshclam and unbound, on by default for new installs and migrations from
  eFa 5: a read-only system with only the folders each daemon writes, no /home, an own /tmp, read-only kernel tunables and
  control groups, nothing that needs NoNewPrivileges (it blocks the SELinux domain of these daemons). Each unit is restarted
  with it and must stay up, else it runs without and the dashboard says so. redis and nginx stay without by default (OV-1b:
  on a real host redis met SELinux denials and nginx did not stay up); `efactl service-harden --mode on` adds them, with the
  same fallback. An update keeps what was chosen; a host without the sandbox gets a dashboard notice that links to the card,
  where *default* switches it on. The drop-ins live in /etc/systemd/system, so updates of the packages keep them. The
  provisioning API and the setup wizard get the limits that leave their sudo call working.
- ClamAV unpacks archives to a depth of 17 at most, now set by eFa-next (`MaxRecursion`, the default of ClamAV).
- Cloned hosts (S29): `efactl clone-reset --confirm yes [--hostname NAME]`, as root on the console only and never on a member of a
  cluster, makes new what belongs to one host only (SSH host keys, machine id and its boot entries, host name, the keys of the web
  interface, the portal and nginx, SRS and link check keys; the backup and offline signing keys again on first use, their old
  fingerprints shown) and names what it keeps because it encrypts existing data or belongs to the domains (docs/system.md).
- Root login through SSH has one place, 00-efa-root.conf, written by the switch for every mode (on writes yes); the SSH hardening
  file no longer names it. On the update the value sshd takes now goes into that file first, so no host changes its root login.
  Other files that set PermitRootLogin (such as the one of the installer) stay and are named as overridden in the status and the
  hardening report.
- A fresh install no longer turns root login through SSH off on its own: the wizard asks for it (off, with an SSH key only,
  on), prefilled with the value in effect, with the recommendation and the warning; the choice goes through the switch of
  efactl (audited). Without a choice, as in an unattended install, it stays as it was (`ROOTSSH` in the answers sets it).
- Single sign-on (OIDC) in the user portal: with its own redirect address at the provider (`/portal/login/oidc/callback`), for
  the global provider and those of tenants; a checked mail address of an own domain logs in as a user of the role user, bound
  to issuer and subject; an address an admin account has as its name or e-mail (any case) is refused there, also for a login
  link, and portal users at the admin interface. The portal reaches the
  provider only through efa-portal-helper, which always asks for the portal login. Off until the redirect address is set
  (docs/users-and-access.md).
- ARC after a change of the content milter (M1): rspamd seals a mail before efa-cdr changes it (tracking protection, links,
  banner), so its seal no longer fit. efa-cdr now adds the next ARC set (ARC-Authentication-Results with the results of rspamd,
  ARC-Message-Signature over the changed mail, ARC-Seal) with the domain and key rspamd sealed with, rsa-sha256 after RFC 8617;
  the order of the milters stays. Mail it does not change, or that rspamd did not seal, stays as it is. The keys reach efa-cdr
  as systemd credentials (/etc/eFa/arc-seal, root only, kept in step with the ARC settings).
- Reports as PDF (5h): the daily and weekly report also as a PDF attachment of its mail (`efactl report-set --pdf on`, off
  until switched on) and as a PDF to download from the report page (`report-show --format pdf`), each reader with the domains
  it may see; made with the own PDF code of the hardening report (A4, page X / Y), no extra library.
- Retention per tenant (9h) for every kind of data: besides the mail log and the reports also the audit log, the held mail of
  the admins, the originals of disarmed attachments, reported phishing mails and the DKIM selectors seen
  (`efactl retention-set --data ... --tenant ...`). Headers, held mail for users and emergency copies have their days per tenant in
  their own settings; the statistics hold counts only. A mail or original of several tenants goes when the longest of their
  days ends. Tenant admins may set shorter days only, longer ones a super admin. Every purge and change in the audit log;
  nothing changes until days are set.
- CI: the Forgejo job runs ci.sh in a unit of its own, so a cancelled job no longer stops it in the middle of the fresh test.
- The rspamd repository is used only over https (its file names http for packages and key; dnf could take a new key
  unasked); existing hosts are changed on the update.
- A plain dnf update keeps rspamd on its major version 4; a new major version comes only with an eFa-next release
  tested with it.
- DKIM provisioning: the client certificate of a source must be a file with certificates only, never one with a key.
- The web interface takes multipart bodies only for its four uploads and only after a login, before it parses them, and
  other forms up to 4 MB: Werkzeug 2.0 of EL9 parses multipart without a limit on its parts (CVE-2023-25577, CVE-2023-46136,
  CVE-2024-49767).

### Fixes
- PDF reports, the hardening report, legal texts and encrypted mail as PDF show every letter (Polish, Czech, Greek, Cyrillic
  and others) instead of '?' (PDF-1): such text is set in DejaVu Sans (new dependency dejavu-sans-fonts), embedded only into
  a PDF that needs it; a PDF in Western European letters stays as small as before. Names and titles of the document as UTF-16.
- Submitter logins for Dovecot (SHA512-CRYPT, while PAM is on) no longer need the crypt module of Python, which is gone from
  Python 3.13 on (PY-1): efa_shacrypt makes and checks them in plain Python, tested against the vectors of the scheme.
- The hourly count of the sessions on port 25 (Require TLS on port 25) counts each line for the day of its time stamp, so
  the lines before midnight stay on their day; after a rotation of the mail log the hourly job first reads the rest of the
  rotated file, so no lines are lost between the last run and the rotation (JOB-2).
- Migration from eFa 5: the forward-zone "." it left in unbound (all names to 8.8.8.8 or a router) goes when the root servers
  answer over UDP and TCP; its forwarders for internal zones stay under Internal DNS. Before, the free blocklists did not
  filter and every mail domain went to that resolver. Hosts migrated before get a dashboard notice and the one-click fix
  dns-forward-fix (same test; if no name resolves without the forwarder, it is put back).
- Blocklists page: one switch per list that shows the state in effect (On/Off), not the action; switching on a list with
  unconfirmed terms opens its terms with the tick box; the Spamhaus DQS key sits in the Spamhaus rows; ID, type, score, hits
  and errors no longer wrap, and on a phone the rows stack.
- DNS: the local unbound resolving through the root servers is the default. The setup offers own DNS servers only as an
  exception (servers of the own network, and only when the root servers do not answer), never a public resolver; the
  system asks its own unbound (NetworkManager dns=none, resolv.conf 127.0.0.1), and a host that asks others gets the hint
  and the one-click fix. An update changes nothing by itself.
- Greylisting and BEC: a new install greylists (5 minutes, 7 days), a migration from eFa 5 switches on greylisting and the
  BEC checks (named in the report); an update keeps what was set. The dashboard names a gap (greylisting off with its score
  below the spam marking: mail in between got no action) and recommends both when they are off, each with its card.
- Web interface: efactl-runner takes up to 128 waiting connections (the default was 5), and the web interface tries again
  when the backlog is full for a moment; a page with many reads at once showed "Unknown" tiles before.
- Hardening report: the key check reads the certificates nginx and Postfix use now (nginx -T, smtpd_tls_chain_files or
  smtpd_tls_cert_file) and shows both when they differ; the check of the certificate end shows the date and the days left
  instead of a number of seconds.
- Sender lists: an allowed address or domain always gets through (owner: "immer, überall"): Postfix lets it past the RBL,
  HELO and DNS checks (OK right after permit_mynetworks/permit_sasl_authenticated in the client, helo, sender and data
  checks; in the recipient and relay checks only after reject_unauth_destination, never an open relay). Each pass is
  logged and in the audit log; the page warns that sender addresses can be forged. A virus in its mail is cut out by
  efa-cdr and the mail goes on (a note in its place, X-eFa-next-Removed, the original kept and audited); in the text itself
  the mail is held and the recipients are told. The update takes a table efa-sender-skip-domaincheck (by hand or of the
  first 6.0.0.6 version) over into the allow list and removes it; efa-migrate takes the OK entries of sender_access over.
- Migration from eFa 5: a valid Let's Encrypt certificate of the host is taken over for nginx and Postfix as it is (same
  lineage, key and key type, no new request), so a TLSA record stays right; renewals keep the key and run through the
  webroot of nginx (the apache settings of eFa 5 go). eFa-next writes the paths itself, without the installer of certbot. Before, nginx kept the
  self-signed certificate. New command `efactl letsencrypt-takeover`, and a dashboard notice on hosts migrated before.
- After an update with a reboot, the post-boot check (maintenance off, health check, mail to the admin) now also runs on
  hosts set up fresh; before, only hosts migrated from eFa 5 had it.

## 6.0.0.5.2 (release date: pending)

Fix of the migration from eFa 5 on top of 6.0.0.5.1; an update keeps all settings.

- Migration from eFa 5: after sender_access moved to the sender lists, Postfix no longer reads that file (its OK lines let a
  faked envelope sender past every check); the report says which restriction lists changed. The allowed senders from it are
  named on the dashboard until they are checked, with the advice to keep only exact addresses.
- SELinux: no denials on hosts without IPv6. Redis listens on 127.0.0.1 only there (its default tried ::1), and the
  attempt of freshclam to use IPv6 is no longer logged as a denial.
- Migration: docs/migration.md says where efa-migrate comes from (the source of the release) and what the legal
  confirmation accepts. `efa-migrate --legal-digest` shows the texts, their digest, how to check it with sha256sum and the
  command line of an unattended run; the prompt names the digest correctly (it is no hash of the PDF). Nothing is accepted
  without the person.
- Migration: files that a MailScanner worker left behind when it was gone (a crash) no longer hold the migration up while
  it waits for MailScanner; they are kept in the backup and named in the report. Before, the migration stopped after
  10 minutes with "MailScanner still holds ... files".
- Migration: a host of eFa 5 without IPv6 (`IPV6ADDRESS:--` in eFa-Config) is migrated with IPv6 off; before, the step
  "configuring" stopped with "invalid value for IPV6ADDRESS" after the old system was removed (`--resume` continues).
- Migration: efa-migrate checks first, also when it only lists, that the root password of the database in
  /etc/eFa/MySQL-Config still works, and stops with a clear message if not; before, it failed with an SQL error while
  reading the old system. docs/migration.md has the check to run before a migration.
- Migration: `efa-migrate --execute-i-have-a-snapshot --reset-db-root-password` sets MariaDB to the root password of
  /etc/eFa/MySQL-Config when it refuses it (over the socket of root, else a short start without grant tables and network),
  and /root/.my.cnf with it; the password goes only through stdin and the environment.

## 6.0.0.5.1 (release date: pending)

Security update of 6.0.0.5; an update keeps all settings.

- An update of the packages on a set-up host is never taken for a first install, also when /etc/eFa-Version is missing:
  the first-install steps would have replaced its nginx, rspamd and Postfix settings.
- The web interface takes multipart bodies only for its four uploads and only after a login, before it parses them, and
  other forms up to 4 MB. Werkzeug 2.0 of EL9 parses multipart without a limit on its parts (CVE-2023-25577, CVE-2023-46136,
  CVE-2024-49767), which was reachable without a login.
- The rspamd repository is used only over https: its file names http for packages and key, and dnf could take a new key
  unasked. Existing hosts are changed on the update.
- A plain dnf update keeps rspamd on its major version 4; a new major version comes only with an eFa-next release
  tested with it.
- Two writers of the same settings file at once no longer take each other's temporary file (a service start could fail).
- The outbound milter (DLP, disclaimers, PDF encryption) and the sandbox service always find the files systemd hands them,
  also after a restore from a host without these features; before, they did not start then, and with DLP or PDF encryption on, mail on port 587 waited.

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
  agreement, as drafts for a lawyer (docs/datenschutz/). SUPPORT.md (Q8): the community way.
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
