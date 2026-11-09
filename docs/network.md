# More network interfaces

The interface of the default route is set during the installation and on the page *Network & certificate*; eFa-next never
changes it from here. Every other ethernet interface gets a role (*Network → More interfaces*, `efactl interface-set`):

| Role | Firewall zone | What it is for |
|---|---|---|
| uplink | public | a second way to the internet; its own routing table, so answers leave where the request came in |
| internal | internal | a network of own mail servers: SMTP, submission, SSH and HTTPS reachable from it |
| management | internal | admins only: SSH and HTTPS |
| unused | drop | nothing |

An interface takes a fixed address or DHCP, an optional gateway (uplinks only), DNS servers and a VLAN ID. An internal network
never becomes the default route.

## New interfaces stay unused

A new interface (a second network card of a VM, for instance) gets no automatic DHCP profile: eFa-next sets `no-auto-default=*`
for NetworkManager (/etc/NetworkManager/conf.d/50-efa-no-auto-default.conf), so a mail gateway never takes an address or a
default route from an unknown network by itself. The dashboard names such an interface until it has a role. An update sets
this for interfaces that come later and leaves existing profiles as they are; the hardening report names profiles that
NetworkManager made by itself ("Wired connection N").

## The way back

Each change takes itself back after 5 minutes unless `efactl interface-confirm` follows, as the firewall guard does. A change of
the firewall zone happens only between minute 20 and 50 of an hour, and eFa-next never reloads the whole firewall.

## Outgoing mail over an uplink

`efactl uplink-route-set --domain example.org --device ens35` sends the mail of the sender domain example.org over the uplink
ens35: Postfix gets a transport of its own (`efa-out-ens35`) bound to the address of that uplink. `--device main` sends it
over the main interface again. The address of the uplink needs a PTR record with the HELO name and its place in the SPF
record of the domain; the command says so.
