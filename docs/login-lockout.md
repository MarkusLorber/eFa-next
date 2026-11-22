# Failed logins: lockout

One lockout for the failed logins of the web interface, the user portal, the API and the logins of port 587 (B6). Under
Security, Failed logins. On by default on a new install; after an upgrade the earlier jails stay as they were until you switch
it on.

## How it works

- The web interface, the portal and the API log every failed login with the address of the client; Postfix logs every failed
  login of port 587. Fail2Ban counts them per address.
- After the set number of failed logins (3, 5, 10 or 20) within the set minutes (5, 10, 30 or 60) the address is banned for
  1 hour, 6 hours, a day or a week, on the ports of the service it attacked.
- Repeat offenders: an address banned three times within a day is banned for a week on every port (the `recidive` jail of
  Fail2Ban). It can be switched off.
- Never banned: localhost, the relay networks, the allowlist of the firewall, the cluster nodes and the own list of the
  address-harvesting ban. Save the lockout again after you change these.
- There is no lockout per account on purpose: anybody could then keep the admin out by guessing wrong with the admin name.
  The web interface also blocks an address after 5 failed logins for 5 minutes and answers every failed login after a fixed
  second; efa-sasl (port 587) also stops a login name after 5 failures in 10 minutes, from any address. Every admin has 2FA
  (6.0.0.6.7). The compensating control for PCI DSS 8.3.4 and NIST AC-7: docs/compliance/compensating-controls.md.

`efactl login-lockout-set --mode on --tries 5 --minutes 10 --hours 1 --repeat on` sets it; `efactl login-lockout-status` shows
the values and the addresses banned now. The values are written to `/etc/fail2ban/jail.d/efa.lockout.local`, which Fail2Ban
reads after `efa.local`.

## Idle timeout of admin sessions

Under Security, Logins: an admin session of the web interface ends after 5, 10, 15, 30 or 60 idle minutes (PCI DSS 8.2.8 and
NIST SP 800-53 AC-11 ask for 15 at most). A new install starts with 15; an upgraded host keeps its value (60 before); the user
portal always keeps 60.

- `efactl admin-idle-status` shows the value in effect; `efactl admin-idle-set --minutes 15` sets it. Only a super admin.
- Shorter needs nothing more. Longer weakens the protection: the web interface and the API ask the password (and the 2FA code)
  again, and while four eyes is on the change waits for a second admin. The audit log keeps the old and the new value.
- One value for the whole cluster: the master hands it on. It is stored in `/etc/eFa/admin-idle.json` (0640 root:efa-conf);
  efa-web reads it again when it changes, without a restart, and a shorter timeout also ends sessions already open.
- The hardening report shows *Admin sessions end after at most 15 minutes idle* for information. The setup frameworks PCI DSS,
  HIPAA and NIST SP 800-53 suggest 15 minutes and only ever shorten it (Re-Setup shows `idle_minutes 60 -> 15`).

## Login banner

Under Security, Admin access: a text of the operator before the admin login of the web interface, for example a notice on
authorised use and logging (NIST SP 800-53 AC-8). Off by default. `efactl login-banner-set --text "..." [--ssh on]`; empty text
removes it. With SSH on the same text goes to `/etc/issue.net` (the original is kept and comes back with off) and a drop-in of
sshd shows it before the SSH login. Plain text, up to 1000 characters; the web shows it escaped. Only a super admin; one text
for the cluster. The hardening report shows "A login banner is shown before the admin login" for information.
