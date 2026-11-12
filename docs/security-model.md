# Security model

How eFa-next keeps users, admins and the system apart, so that a taken-over account or a hole in one web program reaches as
little as possible.

## Two web programs

| | Admin interface | User portal |
|---|---|---|
| Address | `https://<host>/` | `https://<host>/portal/`, digest links `/q/…`, checked mail links `/l/…` |
| Service | `efa-web.service`, user `efa-web` | `efa-portal.service`, user `efa-portal` |
| Who logs in | the admin roles (super, tenant, domain, helpdesk, readonly, auditor) | role `user` only: the own mailbox |
| Rights | `sudo /usr/sbin/efactl`; efactl checks the role of the login for every command | none: no sudo, no database, no settings |
| Cookie | `session` | `efa_portal`, its own key |

Both are the same program (`efa-web.py`); the portal starts it with `EFA_WEB_MODE=portal` and then keeps only its own routes:
the code of the admin pages is not reachable there at all, not only hidden.

nginx sends `/portal/`, `/q/` and `/l/` to the portal and everything else to the admin interface.

### efactl-runner: the only way of the admin interface to efactl

The admin interface runs efactl only through **efactl-runner** (`efactl-runner.service`, root): the code is loaded once and
every call runs in its own fork. From 6.0.0.6 on `efa-web` has **no sudo rule** (the rule
`efa-web ALL=(root) NOPASSWD: /usr/sbin/efactl` of 6.0.0.5 and older is removed on the update), so `efa-web.service` runs
with `NoNewPrivileges`, a read-only file system and no access to the private keys of the host
(`efa-web.service.d/hardening.conf`).

| | efactl-runner |
|---|---|
| Who | the user `efa-web` only: the uid of the caller from the kernel (`SO_PEERCRED`); the socket `/run/efactl-runner/runner.sock` is `0660 root:efa-web`, so other users cannot open it, and `efa-init` (group `efa-web`) is refused by its uid |
| What | `/usr/sbin/efactl` (its loaded code) with arguments as a list of strings, no shell, no newline or NUL in them; the CLI-only commands and `menu` are refused for `efa-web` |
| Rights checks | efactl checks the role of the login for every command |
| Environment | emptied, then `PATH=/sbin:/bin:/usr/sbin:/usr/bin`, `HOME=/root`, `SUDO_USER`/`SUDO_UID`/`SUDO_GID`/`SUDO_COMMAND` as sudo would set them; umask `022` |
| Input | secrets over the socket, given to efactl as its stdin; a backup or logo upload and the backup download as a pipe of efa-web handed over the socket (`SCM_RIGHTS`), only pipes, only the ones the request names |
| Time limit | 120 s, 1800 s for a call with a pipe (`SIGALRM` ends the fork, efa-web reports the call as failed) |
| Audit | efactl writes its audit and strict audit entries (it sees `SUDO_USER=efa-web`); the runner logs caller and command name to the journal, not the arguments, as they can hold mail addresses (GDPR) |
| Fallback | none: without the runner the web interface reports that efactl-runner does not answer; a call that broke off is never sent a second time |

What stays: whoever takes over the web process can call efactl through the runner like the logged-in admins, within the
rights checks of efactl. The sandbox of efa-web keeps the rest of the host out of reach.

Not set on purpose for `efactl-runner.service`: `NoNewPrivileges`, `ProtectSystem`, `PrivateTmp` and `RestrictAddressFamilies`. They would apply to efactl
itself and break what it is for: it installs packages (`dnf`/`rpm` need their SELinux domain transitions, which
`NoNewPrivileges` blocks), writes `/etc` and `/usr`, shares files in `/tmp` with other services, and talks to rspamd, the
cluster nodes, DNS and the update server over the network. Under sudo none of these limits applied either; the runner keeps the
same rights, not more. `KillMode=process`: a restart of the runner, as by a package update, does not end a call still running.

The CI checks the boundary after every install: socket mode and owner, `ok` for `efa-web`, `denied` for `efa-portal` and
`nobody`, `refused` for `efa-init` (`efactl-runner.py --probe`), and the self-test covers the environment, umask, stdin, the
time limit and a refused uid.

### What the portal can do

The portal reaches eFa-next only through **efa-portal-helper** (`efa-portal-helper.service`, root), over the socket
`/run/efa-portal-helper/helper.sock` (root and the group `efa-portal`). The helper

Like efactl-runner, the helper loads efactl once and runs each call in its own fork, with the same environment, umask and
time limit (`SUDO_USER=efa-portal`); the checks above stay in front of every call.

- takes only a fixed list of commands: the held mail of the login (`uq-list`, `uq-show`, `uq-release`, `uq-request`, `uq-sender`,
  `uq-delete`), spam reports (`train-request`), the own settings (`my-settings`, `my-settings-set`), the login itself and the links
  of the digests;
- refuses the login of every admin role: admins log in at the admin interface only;
- gives the session id itself at the login and runs every command with `--as <login>` of that session, so a portal taken over
  cannot act for another user and efactl checks the role `user` a second time;
- never takes `--as`, `--session`, `--client` or `--limit-tenant` from the portal;
- keeps the key of the mail links: the portal asks it for the target of a link.

A portal taken over can so do what its logged-in users may do, and nothing else.

### systemd hardening of the portal

`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, no capabilities, only Unix and IP sockets,
`SystemCallFilter=@system-service`, `MemoryMax=256M`, and no access at all to `/etc/eFa`, `/etc/efa-web`, `/etc/postfix`,
`/etc/rspamd`, `/etc/dovecot`, `/etc/ssh`, private keys, sudoers, the database files, the mail queue, `/var/lib/eFa` and the logs.

## Logins of mail systems on port 587 (efa-sasl)

Postfix asks `efa-sasl` (`efa-sasl.socket`, `efa-sasl.service`) whether a login on port 587 is right; it replaces Dovecot.

- Only the Unix socket `/run/efa-sasl/auth` (group postfix, mode 0660, the socket of port 587), no network port; the service runs as
  `efa-sasl` with no capabilities, no network (`PrivateNetwork`), a read-only system, 64 MB of memory at most, and only while
  logins come in: systemd starts it at the first one, it ends itself after ten idle minutes.
- Only PLAIN and LOGIN, and only on a TLS connection (Postfix offers AUTH on 587 only after STARTTLS).
- Only the logins of the submitters (`efactl submitter-set --kind auth`), stored as scrypt; older SHA512-CRYPT entries still work.
  System accounts do not log in on 587.
- Five failures per login name or per client address within ten minutes, and every further try fails at once for that time;
  each failure waits two seconds and is logged for Fail2Ban.
- Without any login on 587 neither efa-sasl nor Dovecot runs, and 587 offers no AUTH.

Hosts that still let system accounts log in on 587 (PAM, from older versions) keep Dovecot for that, and the security self
check says so; with submitter logins and `efactl submission-pam-set --mode off` Dovecot stops.

## Admins among each other

- Every command checks the right of the login in efactl (`COMMAND_PERMISSIONS`), with the scope of tenant and domain; the web
  interface only shows what efactl allows.
- Nobody can give rights they do not have (`grants_cover` when accounts and groups are made or changed), nobody can lock
  themselves out, and the last super admin stays.
- API tokens carry the rights of their owner.

## Admin access only from allowed addresses (5p)

*Security → Admin access*: a list of admin networks, each with a comment, and the switch **All addresses / Only allowed admin
IPs** (default: all addresses). The list can be kept while it does not act.

- On, nginx refuses every path of the admin interface from other addresses (403); the user portal stays open to all.
- The admin interface checks the address itself too; refusals are logged and count for Fail2Ban.
- Switching on is refused while the list is empty or does not hold the own address of the admin.
- The way back on the console: `efactl web-allowlist-set --mode off`.

This is besides the firewall allowlist (*Security → Firewall: admin allowlist*), which closes SSH and port 443 completely, the
user portal too.

## Cluster: own key per host

- Every connection between nodes is TLS 1.3 with mutual certificates (port 8460); TLS 1.2 is refused.
- Each node makes its own key pair; the private key never leaves the node, only its certificate request goes to the master. The CA
  key stays on the master alone.
- A node trusts the CA and in addition the exact certificate of the member it calls: the master for a node, each node for the
  master. Another or a removed node cannot stand in for the master, even with a certificate of the same CA.
- There is no shared cluster secret and no shared symmetric key. A join token works once and for one hour.
- The journal of the master is encrypted at rest with AES-256-GCM under a key of the master alone (root only); the nodes get the
  entries only over mutual TLS, and once every node confirmed an entry its secrets and file contents are removed from it.
- Snapshots are not stored: a node fetches it over mutual TLS and applies it at once. A node gets the settings it runs with,
  among them the DKIM keys and the hashes of the submitter logins; never the CA key, the journal key, the API tokens of the web
  interface or the certificates of other nodes.
- Removing a node takes its certificate out of the list of members at once: every request with it is refused from then on.

## Setup variant and EU link (6.0.0.5)

The setup wizard and Re-Setup keep their answers in `/etc/eFa/setup-variant.json` (readable for efa-web, which greys out what
the EU link forbids). With an EU link from the setup `eu_transfer_check` refuses every service outside the EU, the typed
exception of before included, and `eu-relation-set` refuses "no"; only Re-Setup with the typed confirmation of Text D changes
it. Without an EU link the daily job and every answer of `eu-relation-set` look for a new one (an answer "yes", an own domain
under an EU ending such as .at, .de or .eu): then the EU settings are locked again, with a mail, an event and an audit entry.

## Console admin with 2FA (6.0.0.5)

In the guided setup the console admin of the setup logs in by SSH with the code of its own 2FA (never the one of the main
admin; docs/two-factor.md). Its login shell is `/usr/sbin/efa-console-2fa`: it asks `efactl console-2fa-verify` (one sudo rule,
file `/etc/sudoers.d/efa-console-2fa`; the user is the one sudo names) whether this user has an own 2FA. With one it asks for the
code and starts bash only when efactl accepts it: without a terminal, without a code, with a wrong code or when efactl does not
answer there is no shell (fail closed); five wrong codes lock this user for 15 minutes. Without one (none set up) no code is
asked, the login is noted in the audit log and the dashboard shows it red. An sshd drop-in (`50-efa-console-2fa.conf`) switches
off tunnels and forwarding for this user, so `ssh -N` cannot pass the question. On the local console (`/dev/ttyN`) no code is
asked. Own code instead of google-authenticator (EPEL): the factor of 5r is reused, no PAM change. With an own 2FA, `scp` and
`sftp` of this user do not work (no terminal for the question).

## Security minimum guard (6.0.0.5)

The limit of 5t (TLS 1.2 or newer, only ECDHE with AES-GCM or ChaCha20-Poly1305, no CBC, RSA key exchange, SHA-1, 3DES or RC4;
RSA keys of 3000 bits and more) is checked against changes by hand too:

- **When:** after each change of the files (systemd `efa-floor-guard.path` on main.cf, master.cf, the nginx and dovecot
  configuration), before each start of postfix, nginx and dovecot (`ExecStartPre` drop-ins), in efa-apply and once a day.
  Event-driven, no daemon; the check after a change waits 5 seconds (a burst of changes is one check) and runs with the lowest
  CPU and disk priority. The drop-ins on these units of the distribution hold only the `ExecStartPre`, no sandbox setting
  (NoNewPrivileges blocks their SELinux domains); efactl runs there as in the own units of eFa-next.
- **Fail closed:** a service that cannot be set back stays stopped or does not start. That always raises the alarm: a mail, an
  event, the red banner and one line per service with the reason in `efactl status` (`security_minimum`).
- **Only for real tampering:** when the check itself fails, or calls the value eFa-next writes itself low, that is a fault of
  eFa-next, not a change of the files: the service keeps running, the alarm (mail, critical event `security_floor_guard_error`,
  red banner) names it, and the setup or update step fails so that it is seen. TLS 1.3 suites, which `openssl ciphers` lists with
  any cipher list (on EL9 also `TLS_AES_128_CCM_SHA256`), are not judged: a cipher list does not choose them.
- **What:** Postfix `smtpd_/smtp_tls_*protocols`, the cipher grades, `tls_high_cipherlist`, `smtpd_tls_auth_only`, the `-o` of
  master.cf; nginx `ssl_protocols` and `ssl_ciphers` of `nginx -T`; dovecot `ssl_min_protocol` and `ssl_cipher_list`; the key
  length of the certificates (reported only); the cluster (8460) and the DKIM API (8463), which have the limit in their code, get a
  handshake with TLS 1.1 that must fail.
- **Reaction:** only the low values go back to the TLS profile, the rest of the file stays; postfix, nginx and dovecot check the
  result before they reload. If that fails the service stays stopped and the dashboard shows red; at port 25 the sending servers
  keep the mail and try again, so nothing is lost while it is fixed within days.
- **Evidence:** audit log and an event (SIEM, OTLP, Wazuh) with file, parameter, old and new value, SHA-256, time, owner and mode
  of the file, `rpm -V`, the logins and sudo calls of the journal around the change; a copy of the file in `/var/lib/eFa/tamper/`
  (root only); a mail to the admin.
- **Honest limit:** whoever is root can switch the guard off. It protects against mistakes, bad instructions and attackers
  without root, not against a malicious root.

## Built since the first version of this page

A rights table per route of the admin interface checked in the self-test
(`ROUTE_RIGHTS` in efa-web), the password or 2FA asked again for critical actions, the end of all sessions of an account when its
rights change, a test of every predefined role against every command, two-factor login (TOTP, 5r), passkeys (5s, see
[two-factor.md](two-factor.md)) and single sign-on (OIDC) in the user portal ([users-and-access.md](users-and-access.md)).
