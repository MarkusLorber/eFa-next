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
