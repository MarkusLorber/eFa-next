# FAQ and troubleshooting

**Mail does not arrive.** Mail & quarantine › Mail log: is it there, and with which result? Open its details for the checks. Not there at all: the sender's server did not reach eFa-next; check the MX record and the firewall test (Users & access › Security).

**Mail waits in the queue.** `mailq` on the console. *Connection refused* or a timeout towards your mail server: check the route under Mail routing.

**A mail was rejected as spam, but it is fine.** Release it from Held mail or Quarantine if it is there. For the future: allow the sender under Protection › Sender lists, or a rule for that recipient.

**The web page says "Not allowed".** Your groups do not hold the permission of that action. Users & access › Users › *effective permissions* shows what you have and where.

**I locked myself out of the web interface.** On the console: `efactl firewall-revert` takes back an unconfirmed firewall change; `efactl admin-password` sets a new web password.

**A setting does not seem to apply to a domain.** Domains & tenants › Domain settings › *show with their source*: a value of the domain or its tenant may override the global one.

**Where are the logs?** `/var/log/eFa/` (audit, events, install), `/var/log/maillog` (Postfix), `journalctl -u rspamd -u efa-web`.

**Is my data sent anywhere?** No, unless you turn it on: SIEM, OTLP, Wazuh and the blocklists are your choice. eFa-next uses no third-party check services.

## How do I find a setting? (9f)

Use the search field at the top of the menu of the admin interface, or press `/`.

- **What it searches:** page titles, card titles, field labels, help texts and the values of the pulldowns, in English and in
  the language of the interface.
- **How it matches:** upper and lower case do not matter. Umlauts and ß match their spelled-out forms (Größe finds groesse).
  Parts of words count. A few synonyms count too (junk finds spam, Passwort finds password).
- **What it shows:** only what your rights let you see. A hit opens the page at the card, in the expert view when the card is
  there.
- **Privacy:** the search terms are posted, so they do not appear in a log.

## Is the portal accessible? (P5)

The user portal, the login, the pages of the links in the digests and the warning page of the link check aim at WCAG 2.1 AA.
The self-tests in CI check them with own rules (no external service):
- every field has a label, and every button and link a name;
- the page has its language and a heading;
- no positive tab order;
- a visible focus;
- contrast of text on its background at least 4.5:1, and of borders, status marks and the focus at least 3:1, in the light and
  in the dark scheme.

A program cannot check everything: reading order, clear texts and the use with a screen reader are tested by hand before a
release.

