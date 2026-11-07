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

### efactl-runner: efactl without a new process behind sudo

The admin interface runs efactl through **efactl-runner** (`efactl-runner.service`, root) instead of starting a new
`sudo /usr/sbin/efactl` per call: the code is loaded once and every call runs in its own fork. The boundary is the one of the
sudo rule `efa-web ALL=(root) NOPASSWD: /usr/sbin/efactl`, nothing wider:

| | sudo way | efactl-runner |
|---|---|---|
| Who | the user `efa-web` (sudoers) | the user `efa-web` only: the uid of the caller from the kernel (`SO_PEERCRED`); the socket `/run/efactl-runner/runner.sock` is `0660 root:efa-web`, so other users cannot open it, and `efa-init` (group `efa-web`) is refused by its uid |
| What | `/usr/sbin/efactl` with any arguments | the same program (its loaded code) with any arguments: a list of strings, no shell, no newline or NUL in them |
| Rights checks | efactl checks the role of the login for every command | the same code, unchanged |
| Environment | `env_reset`, `secure_path` | emptied, then `PATH=/sbin:/bin:/usr/sbin:/usr/bin`, `HOME=/root`, `SUDO_USER`/`SUDO_UID`/`SUDO_GID`/`SUDO_COMMAND` as sudo sets them; umask `022` |
| Input | secrets over stdin | secrets over the socket, given to efactl as its stdin |
| Time limit | 120 s (efa-web ends the process) | 120 s (`SIGALRM` ends the fork, efa-web reports the call as failed) |
| Audit | efactl writes its audit and strict audit entries; sudo logs the whole command line | efactl writes the same entries (it sees the same `SUDO_USER`); the runner logs caller and command name to the journal, not the arguments, as they can hold mail addresses (GDPR) |
| Fallback | | when the socket is not there efa-web uses sudo; a call that broke off is never sent a second time |

Not set on purpose: `NoNewPrivileges`, `ProtectSystem`, `PrivateTmp` and `RestrictAddressFamilies`. They would apply to efactl
itself and break what it is for: it installs packages (`dnf`/`rpm` need their SELinux domain transitions, which
`NoNewPrivileges` blocks), writes `/etc` and `/usr`, shares files in `/tmp` with other services, and talks to rspamd, the
cluster nodes, DNS and the update server over the network. Under sudo none of these limits applied either; the runner keeps the
same rights, not more. `KillMode=process`: a restart of the runner, as by a package update, does not end a call still running.

The CI checks the boundary after every install: socket mode and owner, `ok` for `efa-web`, `denied` for `efa-portal` and
`nobody`, `refused` for `efa-init` (`efactl-runner.py --probe`), and the self-test covers the environment, umask, stdin, the
time limit and a refused uid.

### What the portal can do

The portal reaches eFa only through **efa-portal-helper** (`efa-portal-helper.service`, root), over the socket
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

## Not yet

- Single sign-on (OIDC) for users in the portal: the portal needs its own redirect address at the provider. Users log in with
  their password meanwhile.
- A rights table per route of the admin interface with a check in CI, a second password or 2FA check for critical actions, the end
  of all sessions of an account when its rights change, and a test of every role against every action: next steps of 5q.
- Two-factor login (TOTP, 5r) and passkeys (5s).
