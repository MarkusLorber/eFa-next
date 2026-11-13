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

Curves in every profile: X25519, P-256, P-384; the web adds brainpoolP256r1tls13 where OpenSSL offers it. Mail adds
brainpoolP256r1 (BSI TR-03116-4), from Postfix 3.6 (EL10) also brainpoolP256r1tls13. Postfix gets the grade `high` in its cipher settings and the list in
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

| Service | EL9 with OpenSSL 3.5 (3.5.8) |
|---|---|
| Web interface and user portal (nginx, 443) | X25519MLKEM768 first |
| SSH | mlkem768x25519-sha256 first in the SSH profile `bsi`, where OpenSSH knows it (9.9: yes) |
| Mail (Postfix) | not yet: Postfix 3.5 (EL9) and 3.8 (EL10) do not take the name X25519MLKEM768 (it logs "ignoring unknown key exchange group"); X25519, P-256, P-384 and brainpool |
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

The hardening report checks what sshd offers against the tables of TR-02102-4 (key exchange, ciphers, MACs, host key
algorithms), kept in `/usr/share/eFa/standards.json`. The profile `bsi` writes exactly these lists, limited to what this sshd
knows (`ssh -Q`): key exchange ECDH over NIST curves and DH group exchange, AES-GCM and AES-CTR, HMAC-SHA2, ECDSA host keys
only. Kept on purpose: the quantum-safe hybrid mlkem768x25519-sha256 first (see *Deliberate deviations*). Not in it any more:
curve25519, sntrup761, ChaCha20-Poly1305, Ed25519 and RSA host keys.

ECDSA host keys only means: **every client sees a new host key** on its next login (the ECDSA key of the host), unless it
knows it already. Compare the fingerprint before you accept it: `ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub`. Without an
ECDSA host key the profile is refused. The preview of the wizard says so too.

`efactl ssh-profile-set --mode bsi` writes /etc/ssh/sshd_config.d/40-efa-bsi.conf
(read before the crypto policy of the system), checks it with `sshd -t` and reloads sshd; running sessions stay. Unless
`efactl ssh-profile-confirm` follows within 10 minutes, from a new login, it goes back by itself. `--mode system` removes it.
eFa-next never changes sshd on its own. Root login (PermitRootLogin) is not touched.

A profile written by 6.0.0.6-alpha2 or older (with curve25519, Ed25519 and RSA) is **outdated**: an update leaves it as it
is and only reports it (`ssh-profile-status`, the check, the wizard preview). Apply it again on purpose to get the BSI
lists. The same holds for the kernel settings: 6.0.0.6 adds the sysctl values of CIS (among them rp_filter = 1, log_martians,
no source routing, no secure redirects); a file of before shows as outdated until `kernel-hardening-set --mode on` or the
wizard writes it anew. rp_filter = 1 drops packets that come in on another interface than the reply goes out: check own
routes for an uplink first.

## Security standards: choose, apply, check

*Security standards* (`efactl standards-status`, `standards-set`, `standards-check`, `standards-show`, `standards-rollback`;
superadmin with a fresh second factor) lists the standards below with their version. Choose one or more:

- **Preview first.** `efactl standards-set --select "bsi-02102-2 moz-modern"` shows each setting with its value now and after,
  and the warnings. Nothing changes.
- **Apply.** `--apply yes` makes the change; with warnings it also needs `--confirm yes`. A rollback point is written first
  (`standards-rollback` goes back to it), and the audit log gets an entry.
- **The strictest value wins.** Of the chosen standards, the strictest value of each setting is applied. It is never below
  the limit of eFa-next and never weaker than now.
- **Port 25** stays opportunistic unless *Require TLS on port 25* is chosen on purpose (`--port25-tls on`): the warning
  shows how many sessions came without TLS in the last 7 days.
- **The check** runs daily and on demand. It tests every standard, chosen or not, against the settings in effect (`postconf`,
  `nginx -T`, `sshd -T`, sysctl, crypto policy, certificates, DKIM keys, the resolver). Each result is *fulfilled*,
  *over-fulfilled*, *fulfilled through a stronger or equal standard*, *not fulfilled* or *needs DNS records or a mailbox*, with the reason of each finding. The result is on
  the dashboard and in the PDF of the hardening report. A chosen standard that is not fulfilled shows a notice.

| Standard (id) | Version | What applying it sets | Kept on purpose, reported as a deviation |
|---|---|---|---|
| BSI TR-02102-2, TLS (`bsi-02102-2`) | 2026-01 | TLS profile `bsi` | X25519 and X25519MLKEM768 (quantum-safe), not yet in the TR |
| BSI TR-02102-1, key lengths (`bsi-02102-1`) | 2026-01 | nothing: existing keys are reported, not replaced | DKIM RSA 2048 (DNS limit) |
| BSI TR-02102-4, SSH (`bsi-02102-4`) | 2026-01 | SSH profile `bsi` (ECDSA host keys only), with the automatic way back after 10 minutes | mlkem768x25519-sha256 (quantum-safe): fulfilled through a stronger standard |
| BSI TR-03116-4, TLS in federal agencies (`bsi-03116-4`) | 2025 | TLS profile `bsi` | as TR-02102-2 |
| BSI TR-03108, secure mail transport (`bsi-03108`) | 2.0 | TLS profile `bsi`, DANE outgoing (only with a validating resolver) | DANE incoming, MTA-STS, TLS-RPT need DNS records or a mailbox |
| RFC 9325, BCP 195 (`rfc9325`) | November 2022 | TLS profile `rfc9325` (or `bsi` if set now) | – |
| Mozilla modern (`moz-modern`) | 6.0 | web interface TLS 1.3 only; port 587 stays at TLS 1.2 (intermediate) | – |
| Mozilla intermediate (`moz-inter`) | 6.0 | TLS profile `rfc9325` | – |
| NIST SP 800-52 Rev. 2 (`nist-80052`) | August 2019 | TLS profile `rfc9325` | – |
| CIS AlmaLinux OS 9/10, sshd, sysctl and crypto policy only (`cis-el`) | Benchmark 2.0 | SSH profile `bsi`, kernel hardening | not checked against the current text; root login by key is the admin's choice |

The values come from the texts named, kept in `/usr/share/eFa/standards.json` with the version and the link. A standard
marked *not verified* is shown as such in the check.

### Web certificate for Mozilla modern

Mozilla modern asks for an ECDSA certificate on the web. `efactl web-cert-set --mode ecdsa` (or the item *Web interface: own
ECDSA certificate* of the hardening wizard) gives nginx its own Let's Encrypt certificate with an ECDSA P-384 key, for the names
the web certificate has now; Postfix keeps its certificate, so a TLSA record of the MX (DANE) stays right. Let's Encrypt must
reach the server on port 80 and an account must exist (Let's Encrypt certificate). `--mode mail` gives nginx the certificate of
mail again. Deutsch: `web-cert-set --mode ecdsa` gibt nginx ein eigenes Let's-Encrypt-Zertifikat mit ECDSA-P-384-Schlüssel;
Postfix behält sein Zertifikat, ein TLSA-Eintrag (DANE) bleibt richtig. Port 80 muss erreichbar sein.

### Fulfilled through a stronger or equal standard

A value outside the list of a standard counts as fulfilling it only when the table `equivalents` in standards.json names it,
with the value it is measured against and the source. The check then says *fulfilled through a stronger or equal standard*
and names the source, instead of *not fulfilled*. Values without an entry stay *not fulfilled*; nothing is guessed.

| Value | Measured against | Sources |
|---|---|---|
| X25519MLKEM768 (TLS) | stronger than P-256 | NIST FIPS 203 (ML-KEM), RFC 10024 (PQ/T hybrid key agreement for TLS 1.3) |
| X25519 (TLS) | as strong as P-256 (about 128 bits) | RFC 7748, RFC 8446, NIST SP 800-186 |
| mlkem768x25519-sha256 (SSH) | stronger than ecdh-sha2-nistp256 | NIST FIPS 203 (ML-KEM), RFC 10042 (PQ/T hybrid key exchange with ML-KEM in SSH) |
| brainpoolP256r1, brainpoolP256r1tls13 (TLS) | as strong as P-256 | RFC 5639, RFC 7027, RFC 8734, BSI TR-03116-4 |

eFa-next keeps the quantum-safe hybrid on purpose (owner decision): it protects against recording now and decrypting later,
and BSI does not list it yet. `"deliberate": {"on": false}` in standards.json makes the check and the SSH profile strictly BSI.

### Deutsch

*Sicherheitsstandards* (nur Superadmin, mit frischem zweitem Faktor) zeigt die Standards der Tabelle mit Version.
Ein oder mehrere wählen:

- **Zuerst die Vorschau.** Sie zeigt jede Einstellung mit dem Wert jetzt und danach, dazu die Warnungen. Es ändert sich nichts.
- **Anwenden** mit `--apply yes`, bei Warnungen zusätzlich `--confirm yes`. Vorher wird ein Rücksprungpunkt geschrieben
  (`standards-rollback`), dazu ein Eintrag im Audit-Log.
- **Der strengste Wert gilt**, nie unter der Grenze von eFa-next und nie schwächer als jetzt.
- **Port 25** bleibt opportunistisch, außer *TLS auf Port 25 verlangen* wird bewusst gewählt.
- **Die Prüfung** läuft täglich und auf Abruf. Sie prüft jeden Standard, gewählt oder nicht, gegen die wirksamen Einstellungen.
  Das Ergebnis ist *erfüllt*, *übererfüllt*, *erfüllt über einen stärkeren oder gleichwertigen Standard*, *nicht erfüllt* oder *braucht DNS-Einträge oder ein
  Postfach*, mit dem Grund jedes Befunds. Es steht im Dashboard und im PDF des Härtungsberichts.

**Erfüllt über einen stärkeren oder gleichwertigen Standard:** Ein Wert außerhalb der Liste eines Standards gilt nur dann als
erfüllt, wenn die Tabelle `equivalents` in standards.json ihn mit Vergleichswert und Quelle nennt. X25519MLKEM768 (stärker als
P-256; NIST FIPS 203, RFC 10024), X25519 (gleich stark wie P-256; RFC 7748, RFC 8446, NIST SP 800-186) und
mlkem768x25519-sha256 für SSH (stärker als ecdh-sha2-nistp256; NIST FIPS 203, RFC 10042), brainpoolP256r1 und
brainpoolP256r1tls13 (gleich stark wie P-256; RFC 5639, RFC 7027, RFC 8734, BSI TR-03116-4). Werte ohne Eintrag bleiben
*nicht erfüllt*. eFa-next behält den quantensicheren Hybrid bewusst; `"deliberate": {"on": false}` macht Prüfung und
SSH-Profil streng BSI.

**SSH-Profil `bsi`:** genau die Listen der TR-02102-4: ECDH über NIST-Kurven und DH-Group-Exchange, AES-GCM und AES-CTR,
HMAC-SHA2, nur ECDSA-Host-Keys; dazu bewusst mlkem768x25519-sha256 vorne. Nicht mehr darin: curve25519, sntrup761,
ChaCha20-Poly1305, Ed25519- und RSA-Host-Keys. **Jeder Client sieht beim nächsten Login einen neuen Host-Key** (den ECDSA-Key),
Fingerprint vorher prüfen: `ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub`. PermitRootLogin bleibt unangetastet.

**Veraltet:** Ein SSH-Profil von 6.0.0.6-alpha2 oder älter und die Kernel-Einstellungen von vorher ändert ein Update nicht;
Status, Prüfung und Assistent melden sie als veraltet. Erst bewusstes Anwenden schreibt sie neu. Die Kernel-Einstellungen
bekommen dann die sysctl-Werte von CIS, darunter rp_filter = 1: Antworten über ein anderes Interface (eigene Routen für einen
Uplink) werden verworfen, Routen vorher prüfen.

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
The switch is on the card TLS profile (`efactl tls-port25-set --mode on --confirm yes`); it is on only after the warning is
confirmed, and the card shows the sessions of the last 7 days and the senders that came without TLS (counted hourly from the
mail log, local connections left out). It sets `smtpd_tls_security_level = encrypt` for the SMTP service on port 25 only
(behind postscreen when that is on), never for submission or the internal ports.

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
| Cluster journal | AES-256-GCM (a journal of an older release in Fernet is read once and written anew) |
| Passwords of the web interface | PBKDF2-HMAC-SHA256, 600 000 rounds, random salt |
| Logins of mail systems (submission) | SHA512-CRYPT |
| DKIM keys | RSA 2048, 3072 or 4096 bits, or Ed25519 |
