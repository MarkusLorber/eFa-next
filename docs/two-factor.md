# Two-factor login (2FA) with TOTP

Under Users, Two-factor login (admins) and in the user portal under Held mail (users) (5r). Off until a user sets it up, or a
super admin asks for it per role.

## Set up

1. `totp-setup` shows a QR code and the key as text, for any TOTP app (FreeOTP, Aegis, Microsoft or Google Authenticator,
   Duo Mobile). The QR code is drawn by eFa-next itself, no picture comes from outside.
2. `totp-confirm --code 123456` with the first code of the app switches it on and shows ten recovery codes once. Keep them
   safe; each works once instead of a code of the app.

From then on the login asks for the code (RFC 6238: 30 seconds, 6 digits, one step of slack each way), and the confirmation of
critical changes asks for password and code. A code counts once. Wrong codes count as failed logins (lockout, B6).

## Rules and resets

- `totp-policy-set --role tenant --mode required`: logins of this role must set up 2FA at their next login; until then they
  reach only the 2FA setup. Only a super admin sets the rules. Default: optional for every role.
- Lost phone: an admin with the right to manage the user runs `user-2fa-reset --username <name>`; the main admin of the
  console is reset only on the console (`efactl user-2fa-reset --username @admin`). Nobody resets their own.
- `totp-disable --code ...` switches it off, not when the role asks for it.
- Logins with single sign-on (OIDC) use the second factor of their provider.

The secrets are stored encrypted (AES-256-GCM, key `/etc/eFa/totp.key`, root only) and bound to the user; recovery codes only
as hashes.

## Guided setup (6.0.0.5)

Every user has an own 2FA; a code of one user never counts for another. In the guided setup the setup wizard sets up two,
one after the other, before anything is set: the main admin (web interface, app entry `eFa-next: admin@<host>`) and the
console admin of the setup (SSH, app entry `eFa-next: <name>@<host>`), each with its own QR code, first code, ten recovery
codes and PDF. efa-apply hands them to `efactl totp-import` (the console admin with `--console_user`). The main admin can then
not switch it off. Re-Setup to guided on a running system asks the main admin to set it up at the next login.

No 2FA set up: no code asked (the same for the web interface, the user portal and SSH). The login is noted in the audit log, and
in the guided setup the dashboard shows red which admin has none, until it is set up.

The console admin over SSH: its login shell (`efa-console-2fa`, set by `console-2fa-set`) asks `efactl console-2fa-verify` for
the user sudo names whether that user has an own 2FA; with one, it asks for that code (or a recovery code), five wrong ones lock
that user for 15 minutes; without one, the shell starts. The 2FA of a console admin is a file of root,
`/etc/eFa/console-2fa/<user>.json` (0600, the secret sealed with `/etc/eFa/totp.key`), not a row of the database: SSH works while
MariaDB is down, the thing an admin may have to repair. If that file cannot be read or efactl does not answer, no shell (fail
closed). The local console (tty) asks no code.

- Set up or renew the own 2FA of a console admin: `sudo efactl console-2fa-enroll` (prints the otpauth link and the secret for
  the app), then `sudo efactl console-2fa-enroll --code NNNNNN` (ten recovery codes, shown once). As root it is the console
  admin of the setup.
- Lost phone of the main admin: recovery codes, or on the local console `efactl user-2fa-reset --username @admin`.
- Lost phone of a console admin: recovery codes, or a super admin with re-authentication
  `user-2fa-reset --username @console:<name>` (Users, 2FA); then SSH asks no code until it is set up again.

## Passkeys and security keys (5s)

WebAuthn Level 2 with an own small script (`/passkey.js`, no third-party code; without script the login with password and
TOTP works as before).

- A super admin chooses the host name of the passkeys (`passkey-set --rp_id mx.example.org`): one of the names of the server
  and its certificate. The certificate must not be self-signed (Let's Encrypt, or an own CA the browsers of the admins trust)
  and must name the host; otherwise passkeys stay off.
- Per role (`passkey-set --role tenant --mode ...`): off (default), as second factor, or as second factor or alone without a
  password (passwordless; then the key must verify the user, by PIN or fingerprint).
- Each login can add several keys with a name (Users, Passkeys, or in the portal); the browser makes them on "Make the passkey
  now". At the login, "Use a passkey" with user name and password is the second factor; with an empty password it logs in
  alone, where the role allows it.
- Checked: a challenge used once within two minutes, the origin `https://<host>`, the hash of the host in the authenticator
  data, user presence (and verification when passwordless), the signature (ES256, EdDSA or RS256 with at least 2048 bits) and a
  sign counter that may not go back (a copied key). Attestation is not asked; the AAGUID is shown only.
- A lost key: remove it yourself, or an admin removes all keys of the user (`passkey-reset`); then log in with password and
  TOTP or a recovery code. The main admin of the console uses password and TOTP.

