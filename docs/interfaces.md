# More network interfaces

For a host with more than one network card: a second uplink, or a leg into an internal mail network. Under System › Network
& certificate › More interfaces. Off after an upgrade. (The interface of the default route is changed above, not here.)

## Per interface

- The **role**: uplink, internal or management (a pulldown). The internal zone opens only the services it needs, and
  `mynetworks` is built from it.
- Static or DHCP, gateway, DNS and VLAN. Set through the platform layer (nmcli).
- Several uplinks get policy routing (a table per uplink), failover, and `smtp_bind_address` per transport or domain. A hint
  reminds you to match PTR, SPF and HELO.

## Safety

- Every change is confirmed and reverts by itself after a few minutes unless you keep it, like the firewall guard.
- A firewall zone changes only between minute 20 and 50 of an hour, and never with a reload.

Also on the console (`efactl interface-set`, `interface-confirm`, `interface-revert`).
