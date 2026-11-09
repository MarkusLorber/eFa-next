# Role addresses (6b)

eFa-next can take the role addresses of a domain and send them on to targets you set. If it does not, they go to the mail
server of the domain as before.

| Role | Address | Basis |
|---|---|---|
| postmaster | `postmaster@` | RFC 5321 |
| abuse, security, hostmaster, webmaster, noc | `abuse@` and so on | RFC 2142 |
| dmarc, tls-reports | `dmarc@`, `tls-reports@` | report addresses of RFC 7489 and RFC 8460 |
| cra | `security-cra@` | contact for vulnerabilities after the Cyber Resilience Act (EU 2024/2847, Art. 13) |
| nis2 | `nis2@` | optional contact for NIS2 |

The address that receives DMARC and TLS reports for eFa-next (Reports in), and the phishing report addresses, keep their own
handling. A role address that is also one of these is left out.

## On, off and inheritance

The switch and the targets are set at three levels. The nearest level wins:

1. the domain, or its parent domain for a subdomain;
2. the tenant;
3. all: this is also the default for new domains.

Every level starts off, also after an upgrade. Each change is written to the audit log.

    efactl role-set --level all --role abuse --addresses "abuse-desk@corp.example"
    efactl role-set --level tenant --target customer1 --mode on
    efactl role-set --level domain --target example.com --role security --addresses "sec@example.com sec-backup@corp.example"
    efactl role-set --level domain --target example.com --role postmaster --addresses inherit
    efactl role-status

`{domain}` in a target stands for the domain, such as `abuse-team+{domain}@corp.example`. A target that is the role address
itself is left out, so mail cannot loop.

When a domain has an EU relation, a target outside the own domains must be shown to be in the EU. Otherwise you must type the
confirmation `I accept the transfer outside the EU`, which goes into the audit log (the EU rule for external services).

## How the mail flows

1. The mail is filtered like any other. postmaster@ and abuse@ are never refused as spam: for them only the virus scan and the
   size limit count, so reports about spam always arrive.
2. The Postfix pipe `efa-roles` sends the mail on to the targets.
3. The envelope sender becomes an SRS address of the domain (Sender Rewriting Scheme, HMAC key in `/etc/eFa/srs.key`), so SPF
   of the targets passes.
4. A bounce to such an address comes back to the pipe. It checks the hash and an age of at most 21 days, and sends the bounce
   to the original sender. A bounce with a wrong or old SRS address is refused.

The domain check (6a) warns when eFa-next takes the role addresses of a domain but this server is not its MX.

## security.txt

`efactl security-txt --domain example.com` gives a `security.txt` after RFC 9116. It names the security@ address as Contact,
expires after one year, and lists the languages de and en. Put it at `https://example.com/.well-known/security.txt`. The
address of the eFa-next project is never used as a default here.
