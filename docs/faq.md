# FAQ and troubleshooting

**Mail does not arrive.** Mail & quarantine › Mail log: is it there, and with which result? Open its details for the checks. Not there at all: the sender's server did not reach eFa; check the MX record and the firewall test (Users & access › Security).

**Mail waits in the queue.** `mailq` on the console. *Connection refused* or a timeout towards your mail server: check the route under Mail routing.

**A mail was rejected as spam, but it is fine.** Release it from Held mail or Quarantine if it is there. For the future: allow the sender under Protection › Sender lists, or a rule for that recipient.

**The web page says "Not allowed".** Your groups do not hold the permission of that action. Users & access › Users › *effective permissions* shows what you have and where.

**I locked myself out of the web interface.** On the console: `efactl firewall-revert` takes back an unconfirmed firewall change; `efactl admin-password` sets a new web password.

**A setting does not seem to apply to a domain.** Domains & tenants › Domain settings › *show with their source*: a value of the domain or its tenant may override the global one.

**Where are the logs?** `/var/log/eFa/` (audit, events, install), `/var/log/maillog` (Postfix), `journalctl -u rspamd -u efa-web`.

**Is my data sent anywhere?** No, unless you turn it on: SIEM, OTLP, Wazuh and the blocklists are your choice. eFa uses no third-party check services.
