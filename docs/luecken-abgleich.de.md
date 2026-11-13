# Lückenliste kommerzieller Gateways: Abgleich mit eFa-next

Stand 2026-11-12, 08:00 UTC. Geprüft wurde die Lückenliste vom 05.11.2026 (`research/luecken-kommerziell.md`, 12 Produkte, 59 Funktionen) gegen den Code, nur lesend:

- `release-6.0.0.6` = `dev-6.0.0.6` = **9ee41e1** (Forgejo, Stand 03:36 UTC)
- `integration-6.0.0.6` = **18e446a** (9ee41e1 plus Insider-Härtung INS-3 bis INS-9, Lizenz- und Rechtstext-Prüfung, Feature-Link im Benutzermenü)
- `test/live-features-6.0.0.6` = **43bed18** (T-1 bis T-3 und D-1 aus der Funktionsprüfung, auf 76d4914, noch nicht in integration)
- `feature/update-rollback` = 317ae6f (nicht gemergt)

Kein Host angefasst, kein Test gestartet. Belege sind `efactl`-Befehle (Datei `next/usr/sbin/efactl`), Module unter `next/usr/local/sbin/` und `next/usr/lib/eFa/python/` und die Doku unter `docs/`.

**Testnachweis** (Spalte „Test“):
- **CI-Mail**: eine echte Mail im `ci.sh --install`, ab 43bed18 (`scripts/live_features.py`, Schritt `live-features`).
- **CI**: im CI mit echtem Dienst, aber ohne Mail durch die Funktion.
- **Selbsttest**: nur `efactl --self-test` bzw. Unit-Test, nie eine echte Mail im CI.
- **einmal live**: dokumentierter Einzeltest außerhalb des CI.

## Kurzfazit

1. **Von 59 Funktionen der Liste sind 42 umgesetzt, 8 teilweise und 9 bewusst nicht gebaut.** Bei den 9 hat Hans entschieden oder der Plan sagt „eher nicht“ (Large File Transfer, Server-Modus, M365/Google-API, eDiscovery, QES/De-Mail/AS2, M365-Backup, Teams-Schutz, Browser-Isolation, Bildanalyse). Bei weiteren Zeilen ist nur ein Teil bewusst draußen, etwa die eigene Sandbox oder das Webportal. Keine der 8 Haupt-Lücken der Zusammenfassung ist mehr offen.
2. **Die echten Lücken sind jetzt Testnachweise, nicht Funktionen.** Auch mit 43bed18 bekommen nur 11 Funktionen eine echte Mail im CI. CDR und Makros, QR-Codes, verschlüsselte ZIP, Passwort-PDF, S/MIME und PGP im Mailfluss, Disclaimer, Greylisting, Ausbruchsfilter, Konto-Halt, Rückholfenster, Fehlversand-Schutz und Spamfallen haben weiter nur Selbsttests.
3. **Eine Abweichung vom Plan ist nicht dokumentiert:** Im Cluster bleiben Quarantäne und Queue auf ihrem Knoten. Admins sehen sie über den Master (`cluster-quarantine`, `cluster-queue`), aber Benutzer sehen im Portal nur die zurückgehaltenen Mails des Knotens, an dem sie angemeldet sind. Plan 6.0.0.4 Punkt 9 sagte „Quarantäne auf jedem Knoten sehen und freigeben“. `docs/cluster.md` und die „Known limits“ in FEATURES.md nennen das nicht.

## Abgleich je Funktion

Status: ✅ umgesetzt · 🟡 teilweise · ⛔ bewusst nicht (Entscheidung) · ❌ offen

### Bedrohungsschutz

| Funktion | Status | Beleg | Test |
|---|---|---|---|
| Sandboxing | ✅ als Anbindung | `sandbox-set` (CAPEv2), `efa-sandbox.py`; eigene Sandbox ⛔ (Plan 6.0.0.5 „Bewusst nicht“) | Selbsttest; nie gegen echtes CAPE |
| URL-Rewriting / Time-of-Click | ✅ | `links-set`, `links-hint-set`, `efa_links.py`, docs/link-check.md | CI-Mail (43bed18) |
| Post-Delivery-Remediation | 🟡 | `retro-set`, `retro-run`, `retro-imap-set`: Prüfung nach Zustellung und Zurückholen über IMAP. Microsoft Graph und Google API bewusst nicht (docs/protection.md:313) | Selbsttest; IMAP nie live |
| CDR / Anhang entschärfen | ✅ | `cdr-set`, `html-disarm-set`, `efa-cdr.py`, `ole-set` (olevba), docs/attachments-and-cdr.md | Selbsttest |
| Anhangfilter nach Typ, Name, Archiv | ✅ | `attachment-set`, `efa_mime.py`, `efa_zip.py` | CI-Mail (43bed18, „program by content“) |
| Passwortgeschützte Archive | ✅ | `efa-unlock.py`, `unlock-set` | Selbsttest |
| Impersonation / BEC | ✅ | `bec-set`, `bec-vip-set`, `bec-partner-set`, `lookalike-set`, docs/bec.md; NLP/KI ⛔ | CI-Mail (43bed18, VIP) |
| Absender-Empfänger-Beziehung | ✅ | `bec-partner-set`, BEC-Muster (neue Stunde, neue Empfänger) in FEATURES.md | Selbsttest |
| QR-Codes | ✅ | `qr-set`, `efa-qr.py`, `efa_qr.py` | Selbsttest |
| STIX/TAXII-Feeds | ✅ | `feed-set`, `feeds-run`, `efa_feeds.py` (auch MISP), docs/threat-feeds.md | Selbsttest; nie gegen echtes MISP/TAXII |
| Graymail, Safe Unsubscribe | 🟡 | Graymail ✅ (`graymail-set`, `graymail-mine-set`). Ein sicherer Abmelde-Knopf für Benutzer fehlt | CI-Mail (43bed18) |
| Outbreak / Zero-Hour | ✅ | `outbreak-set` (15 bis 60 min Halt, Neubewertung) | Selbsttest |
| Ausgehende Volumenlimits | ✅ | `outbound-limits-set`, `outbound-hold-set`, `hijack-list`, `efa-outbound.py` (Zähler in Redis seit A1-1) | Selbsttest |
| Greylisting | ✅ | `greylisting-set`; seit MIG-GREY bei Neuinstallation und Migration an | Selbsttest; Verhalten nie im CI |
| Warn-Banner | ✅ | `banner-set`, `efa-phish.py`, docs/phishing-and-banner.md | CI-Mail (43bed18) |
| DANE | ✅ | `dane-set`, `tlsa-show`, `letsencrypt-rollover`, `tls-partner-set` | CI (`le-takeover-live`) |

### Datenschutz und Verschlüsselung

| Funktion | Status | Beleg | Test |
|---|---|---|---|
| DLP ausgehend | ✅ für Regex | `dlp-set`, `dlp-rule-set` (IBAN, Karte, Steuer- und SV-Nummer, eigene Muster); Fingerprinting/OCR ⛔ | CI-Mail (43bed18, IBAN) |
| S/MIME und PGP am Gateway | ✅ | `crypto-key-make`, `crypto-import`, `crypto-policy-set`, `efa_crypto.py`, docs/smime-pgp.md | Krypto-Selbsttest mit echtem openssl/gpg (live_test.sh); nie im Mailfluss |
| Portal-/Push-Verschlüsselung | 🟡 | Passwort-PDF ✅ (`pdf-set`, `pdf-password-set`, `efa_pdf.py`); Webportal ⛔ (Hans 2026-11-05) | Selbsttest |
| Domain-Verschlüsselung Gateway zu Gateway | ✅ | TLS-Pflicht je Partner (`tls-partner-set`), S/MIME-Domainzertifikate (`efa_crypto.py:84`) | Selbsttest |
| Policy-basierte Verschlüsselung | ✅ | `crypto-policy-set`, PDF-Auslöser über Regeln | Selbsttest |
| Large File Transfer | ⛔ | Plan 6.0.0.5 „Bewusst nicht“ | – |
| Zentrale Signaturen / Disclaimer | ✅ | `disclaimer-set`, `disclaimer-template-set`, `disclaimer-sync` (AD/LDAP-Felder), `efa_disclaimer.py` | Selbsttest |
| Fehlversand-Schutz | ✅ | `outbound-hold-set --kind confirm` (1, 4 oder 24 h), `efa-outbound.py`: Anhang an neuen Empfänger wartet auf Bestätigung. Damals „eher nicht“, trotzdem gebaut (P1) | Selbsttest |

### Endbenutzer

| Funktion | Status | Beleg | Test |
|---|---|---|---|
| Quarantäne (Admin) | ✅ | `quarantine-list/-show/-release/-delete`, `uq-encrypt-set` (AES-256-GCM) | live_test.sh; ab 43bed18 im CI (Schritt `live-mail`) |
| End-User-Quarantäne mit Digest | ✅ | `uq-list`, `uq-release`, `uq-request`, `uq-sender`, `uq-link-use` (signierte Links), Portal `efa-portal-helper.py`, OIDC im Portal | einmal live (OIDC mit Keycloak) |
| Persönliche Listen, Spam-Schwelle | ✅ | `uq-sender`, `user-spam-mine-set`, `my-settings-set` | Selbsttest |
| Report-Phishing / Outlook-Add-in | ✅ | `phish-set`, `train-request/-decide`, Add-in unter `next/usr/share/eFa/outlook/`, `outlook-addin` | Selbsttest; Add-in nie in echtem Outlook |
| Inline-Schulung beim Klick | ✅ | `links-hint-set` | Selbsttest |

### Continuity und Verfügbarkeit

| Funktion | Status | Beleg | Test |
|---|---|---|---|
| Spooling bei Ausfall | ✅ | `spool-set`, `spool-status`, `queue-list/-action`, `queue-alarm-set`, docs/spooling.md | Selbsttest |
| Notfall-Postfach | 🟡 | Notfall-Lesezugriff ✅ (`emergency-set/-list/-show/-file`, `efa-emergency.py`), ohne Antwortversand (Hans 2026-11-06). ZIP/MBOX-Export fehlt (5n, als Grenze in STATUS) | Selbsttest |
| Hochverfügbarkeit / Clustering | 🟡 | Master/Client und HA ✅ (`cluster-*`, `efa-cluster.py`, mTLS, gestaffelte Updates). Quarantäne und Queue werden **nicht** abgeglichen: Admins sehen sie über den Master, Benutzer im Portal nur je Knoten (`uq-list` fragt keine anderen Knoten, `CLUSTER_HA_FORWARD` efactl:20627 ohne `uq-*`). Der Digest kommt vermutlich je Knoten (nicht live geprüft). Fuzzy-Speicher je Knoten (N4, als Grenze dokumentiert) | einmal live (6.0.0.4); gestaffelte Updates nie live |
| Server-Modus | ⛔ | „anderes Produkt“ | – |

### Administration

| Funktion | Status | Beleg | Test |
|---|---|---|---|
| Mandanten, delegierte Admins | ✅ | `tenant-*`, `domain-*`, docs/domains-and-tenants.md; Aufbewahrung je Mandant (9h) | Live-UI aller Rollen |
| White-Label für MSPs | 🟡 | `tenant-brand-set` (Name, Farbe, Logo je Mandant) ist gebaut, obwohl der Plan „nicht entschieden“ sagt | Live-UI |
| RBAC / Rollen | ✅ | `permission-list`, `group-set`, Helpdesk-Rolle, Vier-Augen (`four-eyes-*`, INS-9) | Live-UI, Unit-Tests `test_insider_hardening.py` |
| Audit-Log | ✅ | `audit-search`, `audit-mode` (streng), `audit-anchor-verify` (signierter Anker) | Selbsttest |
| Syslog/SIEM-Export | ✅ | `siem-set` (TLS), EVE-JSON, `otlp-set`, Wazuh (`wazuh-*`) | nie gegen echtes SIEM/OTLP |
| SNMP / Monitoring | 🟡 | Prometheus (`metrics`) statt SNMP; SNMP selbst fehlt (grep: kein Treffer) | Selbsttest |
| REST-API | ✅ | `token-create`, `api-set`; INS-7 sperrt passwortpflichtige Befehle (403) | Unit-Test |
| Message Tracking / Suche | ✅ | `message-search`, `maillog-search` (MariaDB, Index, CSV/JSON) | Live-UI |
| Reporting | ✅ | `mailreport-*`, `report-set`, PDF-Berichte (5h), `hardening-report` | Selbsttest |
| DMARC-Report-Auswertung | ✅ | `reports-in-set`, `dmarc-report-show`, `tls-report-show` | Selbsttest |
| SSO für Admin-UI | ✅ | `oidc-set`, `tenant-oidc-set`, OIDC auch im Portal (SSO-1) | einmal live (Keycloak) |
| LDAP/AD-Gruppen | ✅ | `ldap-set`, `group-map-set`, `tenant-group-map-set` | nie gegen echtes AD |
| Regel-Engine | ✅ | `rule-set`, `rule-list`, `domain-routing-set` | Selbsttest |
| M365/Google-API | ⛔ | Plan 6.0.0.5 „Bewusst nicht“; N6 nur IMAP | – |
| Config-Backup extern | ✅ | `backup-target-set` (S3/SFTP), `backup-targets-eu-lock`, signiert | einmal live (SFTP, 6.0.0.4); S3 nie |

### Compliance

| Funktion | Status | Beleg | Test |
|---|---|---|---|
| E-Mail-Archivierung | 🟡 | Weitergabe und Journal an ein externes Archiv ✅ (`archive-set`, docs/archive.md). Eigenes Archiv-Modul: Hans hat es auf ein späteres großes Release verschoben | Selbsttest |
| Aufbewahrung / Löschfristen | ✅ | `retention-set` je Mandant für 7 Datenarten, `maillog-retention-set`, `pseudonymise-set`, `gdpr-delete` | Selbsttest |
| eDiscovery | ⛔ | erst mit eigenem Archiv-Modul | – |
| QES, De-Mail, AS2 | ⛔ | Nische | – |
| M365-Backup | ⛔ | anderes Produktfeld | – |

### Awareness und Sonstiges

| Funktion | Status | Beleg | Test |
|---|---|---|---|
| Phishing-Simulation | 🟡 | eigene Plattform ⛔; für GoPhish & Co. gibt es nur die allgemeinen Absenderlisten (`sender-add`), keine Vorlage „Simulation zulassen“ (grep gophish: kein Treffer) | – |
| Teams-Schutz | ⛔ | außerhalb des Gateways | – |
| Mehrere AV-Engines, ICAP | ✅ | `scanner-set` (ICAP, rspamd external_services), `clam-source-set` (URLhaus, InterServer, SecuriteInfo) | Selbsttest |
| Browser-Isolation | ⛔ | Plan 6.0.0.5 „Bewusst nicht“ | – |
| Harvest- und DoS-Schutz | ✅ | `harvest-set`, `postscreen-set`, `login-lockout-set`, Fail2Ban, docs/address-harvesting.md | Selbsttest |
| Bildinhaltsanalyse | ⛔ | Plan 6.0.0.5 „Bewusst nicht“ | – |

Zählung für die 59 Funktionen der Liste: ✅ 42 · 🟡 8 · ⛔ 9 · ❌ 0. „Mehrere AV-Engines“ und „ICAP“ stehen hier in einer Zeile und zählen zweimal. „White-Label“ steht nicht in der Liste und zählt nicht mit. Zeilen mit „✅ als Anbindung“ oder „✅ für Regex“ zählen als ✅; der ausgeschlossene Rest steht in der Spalte Beleg.

## Was eFa-next über die Liste hinaus hat

Nicht in der Liste, aber bei kommerziellen Produkten selten: Tracking-Schutz eingehend, Header-Datenschutz ausgehend, Datenschutz-Nachweis (VVT/TOM) auf Knopfdruck, NIS2-Meldungen, EU-Bezug mit Sperre, Spamfallen, eigene Hash- und YARA-Sperren, Lookalike-Frühwarnung über Certificate Transparency, Betrieb ohne Internet mit signierten Bundles, CVE-Wache, Sicherheitsstandards mit Prüfung, Release-Upgrade EL9 auf EL10 aus der Oberfläche.

## Vorschlag

### Für 6.0.0.6 nötig

| # | Punkt | Warum | Aufwand |
|---|---|---|---|
| G-1 | **43bed18 mergen** (T-1 bis T-3, D-1) | Kriterium 1: Ohne den Zweig haben nur sehr wenige Mail-Funktionen eine echte Mail im CI, und ein Ladefehler eines eigenen rspamd-Moduls bleibt unbemerkt. Liegt beim Release-Thread | S, CI-Lauf |
| G-2 | **Cluster-Grenze dokumentieren**: Quarantäne und Queue bleiben auf dem Knoten, das Portal zeigt nur den eigenen Knoten, der Digest kommt je Knoten | Plan 6.0.0.4 Punkt 9 sagt etwas anderes; FEATURES.md „Known limits“ und docs/cluster.md schweigen. Nur Text, kein Code | S |
| G-3 | **Restliche Mail-Funktionen in `live_features.py`**, zuerst die mit Sicherheits- oder Datenverlust-Folgen: CDR und Makros, Anhang im Archiv, S/MIME „immer verschlüsseln“ ohne Schlüssel (Abweisung), Passwort-PDF, Konto-Halt, Disclaimer (DKIM bleibt gültig) | Diese Funktionen werben wir, und sie verändern oder blockieren Mails. Ein stiller Fehler fällt nur beim Kunden auf | M |

G-3 ist eine Empfehlung. Wenn Hans Kriterium 1 als „gebaut“ liest und nicht als „im CI mit Mail belegt“, kann G-3 nach 6.0.0.7.

### 6.0.0.7

| # | Punkt | Aufwand |
|---|---|---|
| G-4 | Restliche E2E-Mails: QR, verschlüsselte ZIP, Greylisting im Verhalten, Ausbruchsfilter, Rückholfenster, Fehlversand, Spamfallen, ARC nach CDR mit fremdem Prüfer (dkimpy) | M |
| G-5 | Cluster: Benutzer-Quarantäne über alle Knoten (Portal fragt den Master wie `cluster-quarantine`), ein Digest je Benutzer statt je Knoten, dazu N4 (geteilter Fuzzy-Speicher) | M |
| G-6 | Sicherer Abmelde-Knopf bei Graymail (RFC 8058 One-Click, vom Gateway ausgeführt, mit Audit) | S–M |
| G-7 | Vorlage „Phishing-Simulation zulassen“: Absender-IP plus Header-Muster, zeitlich begrenzt, überspringt Banner, Link-Umschreibung und Quarantäne, mit Audit | S |
| G-8 | Live-Tests gegen echte Gegenstellen, je einer vor dem Bewerben: Outlook-Add-in, CAPEv2, IMAP-Pull-Back, AD-Gruppen, MISP/TAXII, S3, SIEM/OTLP | M |
| G-9 | Notfallzugriff: Export als ZIP/MBOX (5n) | S |

Schon für 6.0.0.7 vorgesehen und hier nur der Vollständigkeit halber: Rücknahme-Knopf (`feature/update-rollback` 317ae6f, falls nicht doch 6.0.0.6), 5w VMC/CMC-Prüfung, TUI-Suche (9f), DKIM/ARC im HSM.

### Später

- SNMP-Agent (nur wenn ein Kunde es braucht; Prometheus und OTLP decken Monitoring ab).
- Microsoft-Graph-Konnektor für das Zurückholen, nur wenn Hans die Cloud-API ausdrücklich will (Plan 6.0.0.5).
- Eigenes Archiv-Modul mit eDiscovery (Hans: späteres großes Release).
- White-Label entscheiden: `tenant-brand-set` ist gebaut, der Plan sagt „nicht entschieden“. Entweder als Funktion in FEATURES.md aufnehmen oder ausbauen.

### Bleibt draußen (bestätigt)

Eigene Sandbox, KI-Schreibstilanalyse, Webportal für verschlüsselte Mails, Large File Transfer, M365/Google-API für Scans, Awareness-Plattform, Browser-Isolation, Bildinhaltsanalyse, Server-Modus, QES/De-Mail/AS2, M365-Backup, Teams-Schutz.

## Grenzen dieser Prüfung

- Status „umgesetzt“ heißt: Befehl, Modul und Doku sind im Code. Bei den meisten Funktionen wurde nicht jede Codezeile gelesen; die Tiefe liegt auf den Zeilen mit 🟡.
- Der Cluster-Befund (Portal nur je Knoten) stammt aus dem Code (`uq_list`, `CLUSTER_HA_FORWARD`), nicht aus einem Test mit zwei Knoten.
- Die Funktionsprüfung von heute Nacht (`releases/audit-6.0.0.6/funktionspruefung-2026-11-12.md`) deckt die Testlage genauer ab; dieser Bericht ordnet sie nur der Lückenliste zu.
