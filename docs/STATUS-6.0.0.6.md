# State of 6.0.0.6

The packages carry the version 6.0.0.6. What each item does is in CHANGELOG.md, section 6.0.0.6; how to use it is in the
[manual](manual/README.md). Deutsch: below.

## 6.0.0.6 limits

These stay documented limits in 6.0.0.6. Each is planned for 6.0.0.7.

- **Own fuzzy store (N4):** per node; a store shared by the nodes of a cluster is not built. *Planned for 6.0.0.7.*
- **BIMI (5w):** the logo is checked as SVG Tiny PS, the VMC/CMC certificates are not. *Planned for 6.0.0.7.*
- **Search (9f):** in the web interface only; the text interface (efa-tui) has no search. *Planned for 6.0.0.7.*
- **Emergency access (5n):** mail is shown and its attachments saved one by one; no ZIP or MBOX export per mailbox.
  *Planned for 6.0.0.7.*
- **Keys in a hardware module (P3):** for the backup signature and S/MIME; DKIM and ARC keys stay software keys (rspamd has no
  PKCS#11). *Planned for 6.0.0.7.*

## Other known limits

- The release upgrade from AlmaLinux 9 to 10 is built but starts only once the signed EL10 repository of eFa-next exists;
  AlmaLinux 10 itself is not tested yet ([release-upgrade.md](release-upgrade.md)).
- Sending limits of taken-over accounts count per node, not across a cluster.
- Single sign-on (OIDC) is not yet tested against a live provider; the ARC seal after content disarm not yet against an
  outside ARC checker.
- Extra uplinks per sender domain without failover.
- PDF files (reports, hardening report) show only Western European letters; others become `?`.
- Not yet tested against the real counterpart: the Outlook add-in in Outlook, the sandbox with a running CAPEv2, taking mail back
  over IMAP, staged updates in a running cluster, signatures from a real Active Directory, passkeys in a browser.

## Deutsch: Grenzen von 6.0.0.6

Diese Grenzen bleiben in 6.0.0.6 dokumentiert. Jede ist für 6.0.0.7 geplant.

- **Eigener Fuzzy-Speicher (N4):** je Knoten; ein gemeinsamer Speicher der Knoten eines Clusters ist nicht gebaut.
  *Geplant für 6.0.0.7.*
- **BIMI (5w):** Das Logo wird als SVG Tiny PS geprüft, die VMC/CMC-Zertifikate nicht. *Geplant für 6.0.0.7.*
- **Suche (9f):** nur in der Weboberfläche; das Textmenü (efa-tui) hat keine Suche. *Geplant für 6.0.0.7.*
- **Notfallzugriff (5n):** Mails werden gezeigt und ihre Anhänge einzeln gespeichert; kein ZIP- oder MBOX-Export je Postfach.
  *Geplant für 6.0.0.7.*
- **Schlüssel im Hardware-Modul (P3):** für Backup-Signatur und S/MIME; DKIM- und ARC-Schlüssel bleiben Software-Schlüssel
  (rspamd kann kein PKCS#11). *Geplant für 6.0.0.7.*
