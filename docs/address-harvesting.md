# Address harvesting & flooding

Stops one source that probes many unknown recipients to find valid addresses, or floods the server. On by default on a new
install; off after an upgrade. Under Security.

## How it works

- eFa watches the Postfix recipient check. A source that tries many unknown recipients in a short time gets a note on the
  dashboard and an automatic Fail2Ban ban.
- An allowlist keeps your own networks, relay senders and cluster nodes from ever being banned.
- In a cluster the ban is applied on every host.

`harvest-set` turns it on or off; `harvest-status` shows the state and the current bans.
