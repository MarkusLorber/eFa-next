# State of 6.0.0.3

Last update: 2026-11-05. The clean-room code is integrated. Both packages build as 6.0.0.3. On the test system the upgrade from 6.0.0.2, the full migration from eFa 5 and a fresh install all passed.

## Clean-room integration

- Every file of the old upstream list is deleted. `build/`, `rpm/`, `src/` and `tests/` are the clean-room code, `next/` holds the eFa-next programs. Changes to the clean-room files and the closed open points: `docs/CLEANROOM-NOTES.md`.
- A first install on a host with `/etc/MailScanner/MailScanner.conf` is blocked too. Tested with a real `rpm -U`: refused, nothing changed.
- Dovecot stays, SASL only, also on a fresh install.
- Redis: `efactl redis-tune` sets `maxmemory` to 25 % of the RAM and the policy `volatile-lru`, in `/etc/redis/efa.conf`. It runs at install and upgrade, without a restart. A later RAM change needs another run.
- The monitor is `efa-monitor`. It watches postfix, rspamd, nginx, mariadb, redis, clamd and unbound. It costs 0.17 s per run, every minute.

### Root login through SSH

Decision of the owner: warn only, with a switch. `/etc/ssh/sshd_config.d/01-permitrootlogin.conf` of Anaconda comes first and wins over `39-efa-root.conf` and `40-efa.conf`, and eFa leaves it alone. Nothing changes by itself, also not at an upgrade.

- The dashboard and the security page warn when root can log in through SSH. `efactl ssh-root-status` shows the value and who could take over.
- `efactl ssh-root-set --mode off --confirm yes`, also in the web interface, writes `00-efa-root.conf`, which comes before the Anaconda file. It refuses unless another user has full sudo rights and an SSH key or a password login, counting AllowUsers, DenyUsers and their group forms. Unclear cases count against the user. `sshd -t` checks the result, a rejected file is taken back, then sshd reloads without a restart.
- Tested by self-test only for the switch itself. The status and pages ran on the test system, where root login stays on as decided.

### Migration test on the test system, eFa 5 to 6.0.0.3

From the snapshot, with a first run at 10:34 that stopped while configuring, then `--resume` at 11:20 and the reboot at 11:24.

- Of 113 old Postfix parameters only `mynetworks` and `smtpd_milters` differ, as intended. Milter chain: two site milters, rspamd 11332, 8999. 32 allow and 198 block entries, 62 sender rules and 96559 mail log rows match the plan.
- `efactl status` is ok, no failed unit, all 19 web pages answer after a real login. Dovecot has no IMAP or POP3 port. EICAR is found. SELinux is enforcing without denials since the boot. The firewall guard repairs nothing, `public.xml` holds 1574 rules, the outbound block stays.

### Fresh install test on the test system

The eFa packages and their data were removed first, and Postfix went back to stock. Then `build.bash production /root/efa-rpms`, the web wizard through nginx, the reboot, first boot and a second reboot, at 18:38 to 18:43.

- Passed: no manual step beyond the wizard. `efactl status` is ok, no failed unit, all 19 web pages after a real login with the password set in the wizard.
- SELinux enforcing: no denial from the install to the second reboot, so `efa.te` stays without rules. This host still has the `mailscanner` module loaded, and dontaudit rules were not turned off.
- Dovecot serves only SASL: `AUTH` on port 587 works with the console user, and no IMAP or POP3 port is open. No eFa daemon runs as root, no PHP, Apache or Perl is required.
- A test mail passed both milters and reached the mail log. rspamd rejects EICAR. Backup, Sanesecurity, mail report, blocklists, DKIM key, quarantine list and maintenance mode work. The monitor is on after first boot, the wizard and its sudo rule are gone.
- The self-tests of `efa-web.py` and `efa-init.py` also pass with the OS packages (Flask 2.0.3, waitress 1.4.4). The running services on this host use the newer pip packages in `/usr/local`, so the OS packages did not serve real traffic.

The wizard now checks the name of the mail server through the resolver Postfix will use. If it does not resolve, the wizard asks for the internal DNS server that knows it, or the IP address of the mail server, because Postfix would bounce the mail.

Bugs the fresh install found, all fixed: Unbound had remote control on without its keys, nginx was not started for the wizard. The migration found: `postconf -n` stopped on a stock `main.cf` if `localhost` resolves to a foreign address, and Unbound lacked `chroot: ""`.

### Outage of the test system at 12:20

Not caused by eFa code. The OS update in `build.bash` upgraded `cockpit-ws`, whose package script runs `firewall-cmd --reload`. firewalld 1.3.4 crashed during that reload with `RuntimeError: dictionary changed size during iteration` in `fw_policy.cleanup`, which iterates the timeouts of the IP blocker's `--timeout` rules. Afterwards every zone call answered `INVALID_ZONE: public` and the host stayed cut off until firewalld was stopped on the console. Any package with such a script can trigger this on a host where rules with a timeout exist, also through dnf-automatic.

### Upgrade test on the test system, 6.0.0.2 to 6.0.0.3

Run at 10:22 with `dnf upgrade` of both RPMs, built on that host, then a reboot at 10:25. Result:

- All steps passed, `/etc/eFa-Version` is `eFa-6.0.0.3`. The file was missing before.
- Settings, keys and lists are unchanged by file hash in `/etc/eFa`, `/etc/efa-web`, `/etc/postfix`, `/etc/rspamd`, `/etc/dovecot`, `/etc/unbound`, `/etc/nginx`, `/etc/clamd.d`, `/etc/my.cnf.d`, `/etc/letsencrypt` and SSH. The only differences: `redis.conf` and `efa.conf`, as intended; `sanesecurity.json`, by its timer; `jail.d/efa.local` gets the `[efa-web]` jail from `web-harden`, as every upgrade before; modes of `MySQL-Config` (0600), `/var/log/eFa` and `/var/lib/eFa` (0750).
- Newly enabled: only `efa-reboot-check.timer` and `efa-setup-reboot.path`. The wizard, first boot and kickstart units stay disabled.
- No eFa daemon runs as root. Apache and PHP-FPM stay inactive. The packages need no PHP, Apache or Perl.
- All 19 web pages answer 200 after a real login. A login with a `pbkdf2_sha256` hash from `efa-apply` works, a wrong password does not.
- `firewall-guard-run` repairs nothing. `public.xml` is byte for byte the same with 1574 rules. Before the reboot the runtime held 1694, which were not in `public.xml`: the next run of the IP blocker has to be checked. `efa_test_block` is active.
- After the reboot: `efactl status` is ok, no failed unit, Redis keeps its limit, no SELinux denial.
- A test mail through port 25 passed both milters, reached the mail log and stayed in the queue because of the block. It was deleted.
- The monitor restarted a stopped Redis. Maintenance mode on and off works. A backup works. `logrotate -d` accepts the new file. The wizard unit starts as `efa-init` and answers through nginx.
- Self-tests: 35 clean-room tests on Python 3.9, and the self-tests of `efactl`, `efa-web.py`, `efa-maillog.py`, `efa-milter-health.py`, `efa-init.py`, `efa-migrate`.

## Done

### Migration from eFa 5 (`migration/efa-migrate`)

- Full run from the snapshot on the test system passed its local checks: run 3 at 07:42, in about 6 minutes, without `--resume`.
- Carries over all Postfix settings and files. Only the milter chain, what belongs to the removed filters, and HOLD rules for MailScanner are replaced or dropped, and the report names each one. `encrypt` stays `encrypt`.
- Recipient check through LDAP stays. IMAP and POP3 are closed, PHP-FPM is masked, old stack files are removed, old daily backups move to the migration folder.
- The monitor pauses from before the removal until 3 minutes after the reboot.
- The web admin password never goes to a log. It is printed only to a terminal and written to a 0600 file that the admin deletes.
- Changed after run 3, self-test only: `message_size_limit` stays exact, clamav-unofficial-sigs is removed, `rbl-apply --keep yes` runs.

### Sanesecurity signatures

- `efactl sanesecurity-run`, timer `efa-sanesecurity.timer`: every 2 hours with up to 15 minutes of random delay.
- Python standard library plus gpg and clamscan. EPEL 9 has no `fangfrisch` package.
- Only the required files and those Sanesecurity rates as low false-positive risk. Files are fetched by the host at run time and never shipped. The package holds only the public signing key.
- A changed file is downloaded with If-None-Match and If-Modified-Since, checked against the GPG signature with a pinned fingerprint, and test-loaded with clamscan. clamd reloads only if something changed. clamd's default concurrent reload stays.
- A run without changes only sends the conditional requests over one connection.
- Replaces clamav-unofficial-sigs: removed from the spec, with `Obsoletes`. The first run deletes its leftover database files.
- Web page "Virus signatures": switch (default on), status, update now, note on the terms.
- Tested on the test system: first run 48 s with 13 files, 113432 signature lines, clamd reloaded, EICAR found. Without changes 5.5 s, 0.2 s CPU, no reload. Before the shared connection this took 16 s.

### Blocklists

- rspamd `rbl` module through the local Unbound, no extra daemon. `efactl rbl-show`, `rbl-set`, `rbl-custom-set`, `rbl-apply`. Web page "Blocklists".
- 15 presets. Rules that rspamd ships keep their own return codes. Spamhaus takes an optional DQS key.
- Custom lists: name, zone, type, score, optional return codes, validated, confirmation required.
- Warnings when Unbound forwards the root zone, when a list answers with error codes, and when Spamhaus runs without a DQS key. Hits and errors come from `rspamc counters`, not from DNS queries.
- Tested on the test system with a temporary Unbound zone: a real listing scores, 127.0.0.1 and 127.255.255.254 do not, a return code list is respected, a disabled list does nothing, the web toggle works. Published test addresses answered for SpamCop, PSBL, UCEPROTECT, Spamhaus ZEN and DBL, Barracuda, Mailspike, DNSWL, blocklist.de and SURBL.

### Mail report

- `efactl mailreport-run`, timer `efa-mailreport.timer`: hourly. Own Python code written from the Postfix log format, no Pflogsumm code and no Perl.
- Reads only new lines from a saved offset. Stores one small aggregate per day in `/var/lib/eFa/mailreport`, for 8 days. Pages only read that.
- Web page "Mail report": today, yesterday, last 7 days. Optional daily mail to the admin, default off.
- Tested on the test system: 0.2 s per run on a small log, numbers match the log.

### Resource use

Idle test on the test system, 2026-11-05 09:00 to 09:10, no mail, all blocklists on. CPU in percent of one core:

| Process | CPU | Memory |
|---|---|---|
| `efa-milter-health` | 0.92 % before the fix, about 0.2 % after | 19 MB |
| `crond` with `eFa-Monitor` and other jobs | 0.61 % | 9 MB |
| `efa-web` with the load sampler | 0.01 % | 58 MB |
| `efa-maillog` | 0.01 % | 28 MB |
| `efa-firewall-guard` | 1.1 s per run, every 5 minutes | |
| clamd | not captured | 1034 MB, 56 MB of it Sanesecurity |
| rspamd | 0.07 % | 650 MB RSS sum, 420 MB by cgroup |
| mariadb | 0.02 % | 249 MB |

Fixed: `efa-milter-health` called `postconf` and six times `systemctl` every 10 seconds. It now asks `postconf` only after `main.cf` changed, and `systemctl` once. In 120 s it used 237 ms CPU, which is about 1.2 s per 10 minutes instead of 5.5 s. A stopped service is still reported as down.

Unbounded logs and caches: `/var/log/eFa/*.log` is now rotated, before only two of those logs were. `login_failures` in `efa-web` forgets addresses silent for a day. Bounded already: load samples, sessions, mail report, mail log table.

## Decisions

- Own updater for Sanesecurity, because EPEL 9 has no `fangfrisch`. It replaces clamav-unofficial-sigs. Only low-risk databases. No feeds that need a registration.
- An upgrade or migration must not weaken filtering: every list rspamd uses at that moment stays on, with its terms note and the Spamhaus DQS warning. Only a fresh install starts with Spamhaus, Mailspike, SURBL, URIBL, DNSWL and the unchecked lists off. SpamCop and PSBL are new lists and on in both cases.
- A migration keeps all Postfix parameters and files, and must not make a host less secure.
- The mail report stays: own Python code, no Perl, no Pflogsumm code.
- No Apache, PHP or Perl in eFa. They stay on the host where other things may use them.
- Commits and pushes to Forgejo need no approval: normal pushes only, no force, no rewrite, no deletion. GitHub, now private, needs the owner's explicit yes.
- firewalld is never reloaded. Changes that touch it run from minute 20 to 50, away from the runs of the IP blocker of the site.
- The firewall guard stays as it is, its code is sensitive. clamd keeps the concurrent reload.
- The Gmail dots in the mail log are only noted for now.

## Not tested yet

- Spamhaus DQS key against the real service, hit counters with real mail, HELO and domain type lists.
- The daily report mail, and a report on a large log.
- Real mail flow from outside and to the internal mail server, Let's Encrypt, `--resume`, DKIM keys in a migration: the clone has none.
- The run of the IP blocker on the migrated system. The rule count stayed plausible, the run itself was not checked.

## Open

- **Reload crash of firewalld**, see the outage above. eFa does not reload, but package scripts do. Worth a look on hosts with the IP blocker.
- **Terms of use.** The official pages I could reach did not state the terms of SpamCop, PSBL, UCEPROTECT, Mailspike, DNSWL, SURBL or URIBL. The notes in `RBL_PRESETS` come from general knowledge and third-party sources. SpamCop and PSBL default to on because they are generally known as free. Someone has to read the current terms before the release. The same holds for the terms of Sanesecurity.
- rspamd removes dots from Gmail senders in the mail log (`efa.migtest` becomes `efamigtest`).
- A running 6.0.0.2 updater writes the old monitor line again after its own upgrade, in its `finally` step. After an automatic update from 6.0.0.2, run `efactl maintenance-set --mode off` once. The repo is private and such updates fail for now.
- `NOTICE`, `AUTHORS.md` and the license text of the README still describe a project with parts from eFa, and need the lawyer. `LICENSES.md` is updated.
- The mailscanner SELinux module cannot be removed by the migration and stays. README says it does nothing without MailScanner, this was not verified.
- `/var/www/html/mailscanner_backup` and the `*.bak` files stay after a migration: they are not from eFa.
- The installer and `efa-migrate` without `--rpm-dir` load from GitHub releases, which fail while the repo is private. Automatic updates may be affected too, not checked.
- Each Sanesecurity change makes clamd briefly hold old and new database: 1465 MB once right after a reload.
