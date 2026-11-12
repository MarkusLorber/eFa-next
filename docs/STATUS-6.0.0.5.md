# State of 6.0.0.5

The packages carry the version 6.0.0.5. What each item does is in CHANGELOG.md, section 6.0.0.5.

## Done

All items of the 6.0.0.5 plan are built: the main table (newsletters and own spam limits, link check hints, archive journal,
extra virus scanners, QR codes, encrypted archives, outbreak filter, threat feeds, Outlook add-in, sandbox, S/MIME and PGP),
N1, N2 (the sandbox connector), N4, N6, the items moved from 6.0.0.4 (5n, 5r, 5s, 5v, 5w, 5x, 5z, EU relation, 6a-6c, 8j, 9f,
9h, 9j, 9o, 9o-b, 9p, S2, 5l-b, SBOM-1, SBOM-2, UI-1, UI-2), SECURITY.md, AD signatures, BEC patterns, D1-D3, A1, A2, O1-O3,
B2, B6, C2, C7, M1-M7, P1-P8, E1, internal DNS servers, the setup variant and the install in one command.

## Known limits

- N4 own fuzzy store: per host; a store shared by the nodes of a cluster is not built.
- BIMI (5w): the logo is checked as SVG Tiny PS, the VMC/CMC certificates are not.
- Perl at runtime only through mariadb-server (its client package; efactl uses mysqldump, mysql and mysqlcheck) and rspamd
  (rspamd_stats); `build/sbom.py --perl-check` fails on any other chain.
- The browser follows the server to a new address on its own only once it trusts the certificate there; with the self-signed
  certificate the admin opens the link once.
- The 2FA of a console admin is set up on the console (`sudo efactl console-2fa-enroll`); the web interface only resets it.
- N5 (FastText language detection) is moved to a later release.
- Search (9f): in the web interface only; the text interface (efa-tui) has no search.
- Emergency access (5n): mail is shown and its attachments saved one by one; no ZIP or MBOX export per mailbox.
- Changes of the content milter (tracking protection, link rewriting, warning banner) come after the ARC seal of rspamd, so the
  seal of such a mail no longer verifies downstream; the header X-eFa-CDR names the change. Fixed in 6.0.0.6: efa-cdr seals
  the changed mail again (M1-1).
- Keys in a hardware module (P3): DKIM and ARC keys stay software keys (rspamd has no PKCS#11).
- Not yet tested against the real counterpart: the Outlook add-in in Outlook, the sandbox with a running CAPEv2, taking mail back
  over IMAP, staged updates in a running cluster, signatures from a real Active Directory.
