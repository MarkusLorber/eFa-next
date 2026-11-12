# Internal DNS servers and domains

eFa-next resolves names with its own Unbound on 127.0.0.1, directly from the root servers and with DNSSEC. Names that only the
DNS servers of your network know need a forwarding: you name your **internal DNS servers** once, and then the **domains** they
answer for. Queries for these domains go to the internal servers, everything else is resolved as before.

The domains do not have to be mail domains: add every internal domain eFa-next has to reach, such as the mail server behind
it, a git, update or proxy server, the directory (LDAP) or the time server. A domain can also name its own servers instead of
the internal ones, for example a partner network.

Under **System, DNS and certificate** (super admin only) you set the servers, see the domains, add or remove one and test it.

    efactl dns-servers-set --servers 192.0.2.53,192.0.2.54
    efactl dns-zone-set --zone example.internal --action add --note "mail server and git server"
    efactl dns-zone-set --zone partner.example --action add --servers 198.51.100.53
    efactl dns-zone-list
    efactl dns-zone-test --zone example.internal
    efactl dns-zone-set --zone example.internal --action remove

- **Servers**: 1 to 8 IP addresses, each optionally with `@port`. Names are refused: a DNS server has to be reachable without
  DNS. With DNS over TLS (`--tls on`) each server is `IP@853#name`, the name being the one in its certificate; the certificate
  is checked against the CA bundle of the system. A change of the internal servers applies to every domain without servers of
  its own. They cannot be emptied while a domain uses them.
- **Domains**: such as `example.internal` or `corp.example.com`, at most 64. `.` (all names) is refused: eFa-next never sends
  all queries to another resolver, the free blocklists refuse such resolvers (see the RBL page).
- **DNSSEC** stays on for a domain. An internal domain below a signed public domain is usually unsigned, and Unbound then
  refuses its answers: turn the check off for that domain only (`--dnssec off`). Then forged answers for it are trusted, so only
  do it for domains of your own network. Domains from 6.0.0.4 and older, and the domain the setup wizard adds for the mail
  server, keep the check off as before.

Each change is checked by `unbound-checkconf`, then Unbound restarts and has to stay up; if not, the settings and the file of
before come back and nothing changed. Each change is in the audit log. The settings are in `/etc/eFa/dns-internal.json`, the file
of Unbound in `/etc/unbound/conf.d/efa-zones.conf`; both are in every backup. Domains of 6.0.0.4 and older stay as they were,
each with its own servers. `efactl dns-zone-test` asks the SOA of the domain through the Unbound of this host.

## The resolver for other networks

Other servers of your network, such as the second MX of a cluster, can ask the Unbound of this host (6.0.0.6). Under **System,
DNS resolver for other networks** (super admin, with your password and 2FA code) you allow addresses or networks, IPv4 and
IPv6: `efactl dns-share-add --nets "192.0.2.11 10.1.0.0/16"`, `efactl dns-share-del`, `efactl dns-share-list`.

- Only the networks listed may ask; everything else stays refused. 0.0.0.0/0 and ::/0 are refused, and nothing wider than /8
  (IPv4) or /32 (IPv6): this server is never an open resolver. A network outside the private ranges needs a typed yes and is
  named in the audit log.
- Each network gets an `access-control ... allow` in Unbound and two firewall rules for port 53 (UDP and TCP) from that
  network only, at runtime and permanent, without a reload of the firewall. Removing it takes both away.
- Unbound limits queries (ratelimit 1000, ip-ratelimit 100). The other MX of a cluster is one entry, its address.
- **Second resolver of this host:** `efactl dns-share-secondary-set --address 192.0.2.11`: this host asks its own Unbound
  first, then the other MX (resolv.conf). Only an address of your own network.
- The list is in the backup (/etc/eFa/dns-share.json); every update writes Unbound and the firewall rules again from it, so a
  restore or the release upgrade to EL10 keeps it.

## Der Resolver für weitere Netze (Deutsch)

Andere Server Ihres Netzes, etwa der zweite MX eines Clusters, können das Unbound dieses Hosts fragen (6.0.0.6). Unter
**System, DNS-Resolver für weitere Netze** (Super-Admin, mit Passwort und 2FA-Code) erlauben Sie Adressen oder Netze, IPv4
und IPv6: `efactl dns-share-add --nets "192.0.2.11 10.1.0.0/16"`, `efactl dns-share-del`, `efactl dns-share-list`.

- Nur die genannten Netze dürfen fragen, alles andere bleibt abgewiesen. 0.0.0.0/0 und ::/0 werden abgelehnt, ebenso alles
  weiter als /8 (IPv4) oder /32 (IPv6): Dieser Server ist nie ein offener Resolver. Ein Netz außerhalb der privaten Bereiche
  braucht ein getipptes yes und steht im Audit-Log.
- Jedes Netz bekommt ein `access-control ... allow` in Unbound und zwei Firewall-Regeln für Port 53 (UDP und TCP) nur von
  diesem Netz, sofort und dauerhaft, ohne Reload der Firewall. Entfernen nimmt beides weg.
- Unbound begrenzt die Anfragen (ratelimit 1000, ip-ratelimit 100). Der andere MX eines Clusters ist ein Eintrag, seine Adresse.
- **Zweiter Resolver dieses Hosts:** `efactl dns-share-secondary-set --address 192.0.2.11`: Dieser Host fragt zuerst sein
  eigenes Unbound, dann den anderen MX (resolv.conf). Nur eine Adresse Ihres eigenen Netzes.
- Die Liste ist im Backup (/etc/eFa/dns-share.json); jedes Update schreibt Unbound und die Firewall-Regeln daraus neu, ein
  Restore oder das Release-Upgrade auf EL10 behält sie.
