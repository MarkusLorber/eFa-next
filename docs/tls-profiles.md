# Encryption and TLS profiles

## The rule

eFa-next uses only modern, secure encryption, following RFC 9325 (BCP 195) and BSI TR-02102-2 / TR-03108. This lower limit
holds for every service and every profile, a custom one too, and is kept on an upgrade (a weaker setting is raised, with a
notice in the dashboard):

| | Allowed | Never |
|---|---|---|
| Protocols | TLS 1.2, TLS 1.3 | SSLv2, SSLv3, TLS 1.0, TLS 1.1 |
| Key exchange | ECDHE (X25519, P-256, P-384), DHE with at least 3072 bits (ffdhe3072) | static RSA, anonymous (aNULL) |
| Ciphers | AEAD: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 | CBC, RC4, 3DES, NULL, EXPORT |
| MAC / hash | SHA-256, SHA-384 (in AEAD) | MD5, SHA-1 |

eFa-next sets this per service and leaves the system-wide crypto policy of the operating system as it is.

## Per service

| Service | Port | Set by |
|---|---|---|
| Web interface and user portal (nginx) | 443 | the TLS profile: protocols, ciphers, curves |
| SMTP in (Postfix) | 25 | the TLS profile: ciphers and curves; TLS 1.2 and 1.3 in every profile |
| Submission (Postfix) | 587, 465 | the TLS profile: protocols, ciphers, curves |
| SMTP out (Postfix) | – | the TLS profile: ciphers and curves; TLS 1.2 and 1.3 in every profile |
| Logins of mail systems on 587 (efa-sasl) | – | no network port of its own: a Unix socket for Postfix, logins only inside the TLS of 587 |
| Cluster | 8460 | fixed in the code: TLS 1.2 or newer, ECDHE with AES-GCM or ChaCha20, certificates on both sides |
| Provisioning API (DKIM, disclaimers) | 8463 | fixed in the code: as the cluster |

## The profiles

*Security → TLS profile* (`efactl tls-profile-set --profile NAME`, `efactl tls-profile-status`):

| Profile | Protocols | Ciphers |
|---|---|---|
| **bsi** – BSI TR-02102-2 (default) | TLS 1.2, 1.3 | ECDHE with AES-256-GCM and AES-128-GCM |
| **rfc9325** – RFC 9325 (BCP 195) | TLS 1.2, 1.3 | ECDHE with AES-GCM and ChaCha20-Poly1305 |
| **mozilla-modern** | TLS 1.3 for web and logins (587/465); 25 and outgoing keep TLS 1.2 | as rfc9325 for TLS 1.2 |
| **custom** | TLS 1.2, 1.3 | an OpenSSL list (`--ciphers`), refused if one cipher is outside the limit (checked with `openssl ciphers -v`) |

Curves in every profile: X25519, P-256, P-384. Postfix gets the grade `high` in its cipher settings and the list in
`tls_high_cipherlist`, `tls_preempt_cipherlist = yes`; `postfix check` runs before the reload and a refused setting is taken
back, nginx likewise with `nginx -t`. DHE is not offered: Postfix on EL9 has no 3072-bit group of its own.

TLS 1.0 and 1.1 are never offered again: `efactl tls-min-set --mode off` is refused. An update sets the profile **bsi** on a
host that has none yet and raises what lies below the limit, with a notice on the dashboard for a week.

With *Require TLS on port 25* (`smtpd_tls_security_level = encrypt`, kept by the migration from eFa 5), Postfix uses the
protocols for logins on port 25 too: with **mozilla-modern** that is TLS 1.3 only, and senders without TLS 1.3 are refused.

## Post-quantum: hybrid key exchange

Against "store now, decrypt later", eFa-next offers the hybrid key exchange X25519MLKEM768 (X25519 together with ML-KEM-768)
first where the platform has it, with X25519, P-256 and P-384 always behind it. It is found at run time (`openssl list
-tls-groups`); the hardening report shows where it is missing as a note, not as a failure.

| Service | EL9 with OpenSSL 3.5 (MX03: 3.5.8) |
|---|---|
| Web interface and user portal (nginx, 443) | X25519MLKEM768 first |
| SSH | mlkem768x25519-sha256 and sntrup761x25519 in the SSH profile `bsi`, where OpenSSH knows them (9.9: yes) |
| Mail (Postfix 3.5, 25/587/465/outgoing) | not yet: Postfix 3.5 does not take the group; classic groups |
| Cluster (8460), provisioning API (8463) | not yet: Python 3.9 cannot set TLS groups and the system crypto policy leaves ML-KEM out |

Data at rest is encrypted with AES-256, which needs no change. Post-quantum signatures (ML-DSA) for the package repository and
updates follow when GnuPG and rpm support them. EL10 and FreeBSD come with 6.0.0.5 and are checked there.

## Key lengths (BSI TR-02102-1)

RSA from 3000 bits, ECC with P-256, P-384 or Ed25519. eFa-next makes: web certificate self-signed RSA 3072, Let's Encrypt ECDSA
P-256, cluster and provisioning API ECDSA P-256. DKIM stays at RSA 2048 plus Ed25519 by default, as 2048 is the common limit of
DNS records; RSA 3072 can be chosen (a longer TXT record). The hardening report names every key below the limit (certificate,
SSH host key, DKIM) with a hint to renew it; existing keys are not changed by an update.

## SSH (BSI TR-02102-4)

The hardening report checks what sshd offers: key exchange, ciphers, MACs and host key algorithms; no SHA-1, no CBC, MACs only
encrypt-then-MAC, no ssh-rsa or DSA host keys. `efactl ssh-profile-set --mode bsi` writes /etc/ssh/sshd_config.d/40-efa-bsi.conf
(read before the crypto policy of the system), checks it with `sshd -t` and reloads sshd; running sessions stay. Unless
`efactl ssh-profile-confirm` follows within 10 minutes, from a new login, it goes back by itself. `--mode system` removes it.
eFa-next never changes sshd on its own.

## Requirements and how eFa-next meets them

A technical mapping, no legal advice; whether a setup meets a rule depends on the whole operation.

| Requirement | How eFa-next meets it | Status |
|---|---|---|
| BSI TR-02102-1: algorithms and key lengths | AEAD ciphers only, SHA-256/384, RSA 3000+ or ECC for own keys, report of shorter keys | met; DKIM RSA 2048 by default (DNS), reported |
| BSI TR-02102-1: post-quantum preparation | X25519MLKEM768 where the platform has it, see above | partly: web and SSH; mail, 8460, 8463 later |
| BSI TR-02102-2 / TR-03116: TLS | TLS 1.2/1.3 only, ECDHE with AEAD, no CBC, no static RSA, profiles above | met |
| BSI TR-02102-4: SSH | report, SSH profile bsi with automatic way back | met when the profile is set |
| BSI TR-03108: secure mail transport | TLS profiles, DANE, MTA-STS checks, hardening report | met for the transport part |
| RFC 9325 (BCP 195) | profile rfc9325 | met |
| NIS2 Art. 21 (cryptography, access, logging) | profiles, key report, 2FA (later), audit log, hardening report as PDF | partly |
| DORA (EU) 2022/2554: tests of cryptography and networks | hardening report with date and host as PDF, audit log, security self check | evidence available |
| ENISA eHealth guidelines: transport of patient data | TLS 1.2/1.3 with forward secrecy everywhere; VPN/IPsec is not part of eFa-next | met for TLS |

## SMTP on port 25

Mail between servers uses TLS when both sides can (opportunistic). A sending server that offers none of the allowed ciphers
delivers without encryption instead of being refused; eFa-next shows how many did in the last 7 days. *Require TLS on port 25*
refuses them instead (off on a new install; a migration from eFa 5 keeps the setting it finds).

## Postfix

Postfix wants a grade in `smtpd_tls_ciphers` (`high`), and the list of ciphers in `tls_high_cipherlist`. A list in the grade
setting, as eFa 5 had it, makes Postfix log "invalid TLS cipher grade" and breaks STARTTLS; eFa-next corrects it on the upgrade
and on the migration. EL9 ships Postfix 3.5, which does not know the form `>=TLSv1.2`: eFa-next writes
`!SSLv2, !SSLv3, !TLSv1, !TLSv1.1`.

## Checked live

The security self check (*Security → Security self check*) connects to each service from the outside and fails when a protocol
or cipher outside the limit is accepted.

## Data at rest

| What | How |
|---|---|
| Backups | OpenPGP, AES-256, when a backup password is set |
| Cluster journal | Fernet: AES-128-CBC with HMAC-SHA256 (AES-256-GCM is planned) |
| Passwords of the web interface | PBKDF2-HMAC-SHA256, 600 000 rounds, random salt |
| Logins of mail systems (submission) | SHA512-CRYPT |
| DKIM keys | RSA 2048, 3072 or 4096 bits, or Ed25519 |
