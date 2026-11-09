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
  The web interface and efa-sasl also slow down failed logins per address and per name by themselves.

`efactl login-lockout-set --mode on --tries 5 --minutes 10 --hours 1 --repeat on` sets it; `efactl login-lockout-status` shows
the values and the addresses banned now. The values are written to `/etc/fail2ban/jail.d/efa.lockout.local`, which Fail2Ban
reads after `efa.local`.
