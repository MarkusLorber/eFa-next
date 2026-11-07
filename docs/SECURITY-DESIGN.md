# Security design: no insecure ways

The rule (S1): eFa-next is a modern mail security system and allows no insecure way. A setting, a fallback or a default that
would weaken the system is not offered; where an old setup has one, the update raises it and says so on the dashboard. When
security and convenience conflict, security wins; an exception needs the decision of the project owner and stands here.

How the processes are separated, who may do what, and the portal: [security-model.md](security-model.md). Encryption:
[tls-profiles.md](tls-profiles.md).

## What is never offered

| Topic | In eFa-next |
|---|---|
| TLS versions | TLS 1.2 and 1.3 only, everywhere; TLS 1.0/1.1 cannot be switched on again |
| Ciphers | ECDHE with AEAD only; no CBC, RC4, 3DES, NULL, EXPORT, static RSA, SHA-1 or MD5 for security |
| Web interface over HTTP | port 80 only redirects to HTTPS and answers ACME; HSTS |
| SMTP-AUTH | only inside TLS (`smtpd_tls_auth_only`) |
| Exports of logs and metrics | SIEM only over TLS (6514), OpenTelemetry only to https with certificate check |
| Cluster, provisioning API | TLS with certificates on both sides (8460), client certificate and token (8463), never token alone |
| Updates | signed packages from the own repository, checked against a pinned key |
| Open relay | refused by configuration; outgoing only for logged in users, relay networks and allowed submitters |
| Secrets | never in logs, URLs, command arguments or the audit log (below) |
| Debug in production | no debug switches in the shipped services |

The one exception: incoming port 25 does not force STARTTLS by default (RFC 3207: a public MX that refuses mail without TLS loses
mail). It can be switched on, with a warning; MTA-STS, DANE and TLS-RPT are the way to protect the transport.

## Secrets

- Passwords and tokens reach efactl on stdin (`secret` arguments), never as command-line arguments; the web interface and the
  API hand them over that way. A unit test (`tests/test_secrets.py`) fails when an argument named like a password, token or
  secret is not marked secret, or when code passes a password to a program on its command line.
- Programs that need a secret get it from a file or a file descriptor: MariaDB (`MYSQL_PWD` in the environment of the call),
  LDAP (`-y` with a file readable by root only), gpg (`--passphrase-fd`), qpdf (an argument file 0600), systemd services
  (`LoadCredential`).
- Files with secrets are 0600 or 0640 with the group of the service that reads them; none is readable by everyone. The install
  check of CI looks for files readable by everyone below /etc/eFa, /etc/efa-web, /etc/efa-portal, /etc/postfix, /etc/rspamd,
  /etc/dovecot, /etc/nginx and /var/lib/eFa that hold a password, token, secret or private key, and fails on one.
- Logs and the audit log name who did what, never a password, token or key; tokens are kept as SHA-256 only and shown once.
- A new admin password of a migration is printed once on the console that ran it, and nowhere else.

## Audit S1, part 2 (2026-11-07)

| Checked | Result |
|---|---|
| Files readable by everyone with secrets, on MX03 after install | none |
| Arguments named password, token or secret without `secret` in efactl | none (`new_token` is a yes/no switch) |
| Passwords on command lines (mysql -p, ldap -w, openssl pass:, sshpass, curl -u) | none |
| Passwords or tokens in syslog, audit log or output | none; the migration prints the new admin password once, on purpose |
