# Two-factor login (2FA) with TOTP

Under Users, Two-factor login (admins) and in the user portal under Held mail (users) (5r).

## Required for every admin (6.0.0.6.7)

Every admin login (super, tenant, domain, manager, helpdesk, read-only, auditor, the main admin `admin`, LDAP logins) must have
a second factor: TOTP or a passkey. An admin without one sets it up right after the password at the next login and reaches
nothing else before; nobody is locked out. The console admin (SSH) sets up its own at its first SSH login: the login shell
shows the app entry and asks for the first code, then shows the ten recovery codes once; the local console (tty) asks for
nothing, as before.

- New install: from the first login. Upgrade: at the next login after the update, as on a new install: the password, then
  straight into the 2FA setup, which works with the password, so nobody is locked out. `efactl admin-2fa-heal` (run by the
  package) writes the day in `/etc/eFa/admin-2fa.json` and puts the console admin behind the login shell.
- Not affected: the user portal (role user: optional, or per `totp-policy-set --role user`), logins with single sign-on (OIDC:
  the factor of their provider), the break-glass admin (its one-time codes), API tokens.
- A 2FA of an admin cannot be switched off any more (`totp-disable`, `console-2fa-set --mode off` refuse); a lost phone is reset
  as below, and the login sets up a new one at its next login.
- Fail closed: a missing 2FA table refuses the login (S38), a missing or broken `/etc/eFa/admin-2fa.json` counts as "required now".
- In a cluster in master/client mode the web 2FA of a login is set up on the master (a node names the master on the setup page);
  it reaches every node. The console admin is of its host and sets up its 2FA there.
- Only a development host (the dev flag of efa-init, `/etc/eFa/dev-no-setup-code`, root:root) has no such rule; the hardening
  report shows "2FA required for every admin role" as failed there. There is no setting that lifts it.

## Every confirmation asks for the code (6.0.0.6.7)

What an admin confirms with the password again (the critical changes of the dashboard, the last step of a wizard, the own login
under My account) also takes the code of the 2FA app, every time, checked by efactl on the server: there is no "if set up" any
more. An admin without a 2FA app gets "Set up your 2FA app first" and sets it up under My account; a passkey alone gives no code,
so such an admin adds an app. The first app is set up with the password only. A confirmation counts five minutes, as before.
Not affected: the user portal (role user), OIDC logins (the factor of their provider), the console, API tokens (they never do
these changes) and a development host with the dev flag.

## Set up

1. `totp-setup` shows a QR code and the key as text, for any TOTP app (FreeOTP, Aegis, Microsoft or Google Authenticator,
   Duo Mobile). The QR code is drawn by eFa-next itself, no picture comes from outside.
2. `totp-confirm --code 123456` with the first code of the app switches it on and shows ten recovery codes once. Keep them
   safe; each works once instead of a code of the app.

From then on the login asks for the code (RFC 6238: 30 seconds, 6 digits, one step of slack each way), and the confirmation of
critical changes asks for password and code. A code counts once. Wrong codes count as failed logins (lockout, B6).

## Rules and resets

- `totp-policy-set --role user --mode required`: logins of the user portal must set up 2FA at their next login; until then they
  reach only the 2FA setup. Only a super admin sets the rules. Admins need 2FA in any case (see above).
- New phone, old one still there: My account, set up 2FA again (password and current code). The old app counts until the new
  one is confirmed.
- Lost phone: log in with a recovery code, then set up a new app under My account. Every recovery code used is in the audit
  log, and the login gets a mail to its confirmed address (6.0.0.6.5).
- Lost phone and no recovery codes: an admin resets it with `user-2fa-reset --username <name>` (Users, 2FA). Nobody resets their
  own. Since 6.0.0.6.5:
  - over the web interface or the API only an admin who has an own 2FA (app or passkey), with password and code again;
  - the 2FA of an admin login only by a super admin; logins of the portal (role user) by the admins of their scope;
  - the main admin only on the console (`efactl user-2fa-reset --username @admin`);
  - the reset ends all open sessions of the login, sends it a mail, and the login must set up a new 2FA at its next login
    before it reaches anything else (before 6.0.0.6.5 it came in with the password alone, unless its role asked for 2FA);
  - with four eyes on, the reset waits for a second admin; every reset is in the audit log (and the strict audit).
- `totp-disable --code ...` switches it off, not for an admin and not when the role asks for it.
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

