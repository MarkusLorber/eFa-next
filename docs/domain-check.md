# Domain check (6a)

The domain check shows how well each own domain is set up for mail security. It reads DNS only and changes nothing.

## What it checks

For each own domain:

| Check | Green | Yellow | Red |
|---|---|---|---|
| MX | this server is an MX | another server is the MX (fine behind another gateway) | no MX |
| SPF | one record, valid terms, at most 10 lookups, ends with `~all` or `-all` | | none, several, invalid, more than 10 lookups, `+all`/`?all` or no end |
| DKIM | the key in DNS is the one eFa-next signs with | eFa-next signs no mail of this domain | key missing or another key in DNS |
| DMARC | `p=quarantine` or `p=reject` with `rua` | `p=none`, or no `rua` | none, several, `p=` wrong |
| MTA-STS | the policy checks out (9p) | written here, not checked yet | no `_mta-sts` record, policy not reachable or wrong |
| TLS-RPT | `_smtp._tls` with a valid `rua` | | none or no valid `rua` |
| DNSSEC | signed and valid (own validating resolver) | not signed | |
| DANE | TLSA `3 1 1` fits the key of this server | no TLSA record (with DNSSEC) | no TLSA record fits: DANE senders cannot deliver |
| BIMI | record with `l=https://` | record without a logo | (none: grey, optional) |
| PTR/HELO | each address of the host name has the host name as PTR | | a PTR is missing or another name |
| Inside / outside | the public resolvers see the same as the own one | they see other MX, SPF, DMARC, MTA-STS or TLS-RPT records | |

DANE and PTR/HELO are checked only when this server is an MX of the domain.

The light of a domain is red if one check is red, yellow if one is yellow, and green otherwise. Grey checks are optional and
do not count.

`efactl domain-check-show --domain example.com` shows each check: what is there, what should be, and the ready DNS record to
copy for the checks that are not green.

## Resolvers and privacy

The domain check queries through the own resolver (Unbound) and through the public resolvers of the DKIM rotation. If none are
set, it uses DNS4EU (EU) and Quad9 (Switzerland), over IPv4 and IPv6.

The public resolvers see only the names of the own domains, which are public anyway. The policy of MTA-STS is fetched only from
the public address of the own domain.

## When it runs

- **Fresh install:** on, every 6 hours (in the hourly job), and on demand with `efactl domain-check-run [--domain d]`.
- **Upgrade:** off until switched on: `efactl domain-check-set --mode on`.
- The page reads the last result. Domain admins see and check only their own domains.

## Reminder

While SPF, DMARC, MTA-STS or TLS-RPT of a domain are red, two reminders go out:
- the dashboard shows a note;
- the alert address and the super admins get a mail, at most once a week per domain.

Switch both off with `efactl domain-check-set --mode on --prompt off`.
