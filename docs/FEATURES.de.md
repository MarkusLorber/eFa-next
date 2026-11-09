# Funktionen von eFa-next (6.0.0.5)

Alles, was eFa-next 6.0.0.5 enthält. „Standardmäßig aus" heißt: die Funktion ist da und wird vom Admin eingeschaltet. Jede
Funktion ist ein Befehl von `efactl` und, wo sie Einstellungen hat, eine Seite der Weboberfläche, mit denselben Prüfungen und
demselben Audit-Log. English: [FEATURES.md](FEATURES.md).

## Mail-Filter und Erkennung

- **rspamd mit Redis** prüft jede Mail: Spam-Wert, SPF, DKIM, DMARC (die Richtlinie jedes Absenders), ARC, Greylisting. [Schutz](protection.md)
- **ClamAV** sucht Viren, mit den Sanesecurity-Signaturen (Dateien mit geringem Fehlalarm-Risiko, per GPG-Signatur geprüft). [Schutz](protection.md)
- **Weitere ClamAV-Signaturen**: URLhaus, InterServer, SecuriteInfo, jeweils nach bestätigten Nutzungsbedingungen. Standardmäßig aus.
- **Zusätzliche Virenscanner** über ICAP und die External Services von rspamd (Scanner und Lizenz des Betreibers). Standardmäßig aus.
- **DNS-Sperrlisten** über den eigenen Resolver (Spamhaus mit DQS-Schlüssel, SpamCop, PSBL und mehr), Bedingungen verlinkt und bestätigt. [Sperrlisten](rbl.md)
- **IP-Sperrlisten** aus Feeds und eigenen Listen, in der Firewall angewendet. [Schutz](protection.md)
- **Postscreen** auf Port 25 mit Pregreet-Prüfung und gewichteten Sperrlisten.
- **Absenderlisten und Regeln** für Adressen, Domains, IP-Adressen und Muster. [Schutz](protection.md)
- **Regel-Engine**: Richtlinien und Routing nach Absender, Domain, Empfänger, Mandant oder Verzeichnisgruppe. [Schutz](protection.md)
- **Bayes und das neuronale Netz** von rspamd, trainiert mit den Spam-Meldungen, die Admins freigeben.
- **Eigener Fuzzy-Speicher**: Varianten bestätigten Spams werden wiedererkannt; nichts verlässt den Server. Standardmäßig aus.
- **Gemeinschafts-Fuzzy-Speicher** von Betreibern, verschlüsselt abgefragt, nur nach Zustimmung. Standardmäßig aus.
- **Bedrohungs-Feeds**: abuse.ch URLhaus und ThreatFox, STIX/TAXII, MISP und einfache Listen in lokale Listen. Standardmäßig aus. [Feeds](threat-feeds.md)
- **Ausbruchsfilter**: eine neue Welle mit demselben Anhang oder Text wird 15 bis 60 Minuten zurückgehalten und dann neu geprüft. Standardmäßig aus.
- **Prüfung nach der Zustellung**: Hashes zugestellter Mails gegen jede Feed-Aktualisierung, Treffer werden gemeldet. Standardmäßig aus.
- **Spamfallen**: Fallenadressen trainieren Bayes und den Fuzzy-Speicher und werten die sendenden Server ab. Standardmäßig aus.
- **Newsletter (Graymail)**: an ihren Listen-Headern erkannt, pro Benutzer zugestellt, markiert oder zurückgehalten. Standardmäßig aus.
- **Eigene Spam-Grenzen** pro Benutzer innerhalb der Grenzen des Admins. Standardmäßig aus.
- **Junge Domains** werden höher bewertet; die Tage als Auswahl.
- **Adress-Sammler**: eine Quelle, die viele unbekannte Empfänger probiert, wird gemeldet und gesperrt. [Adress-Sammler](address-harvesting.md)
- **Greylisting und Sendegrenzen** pro Absender, Absenderdomain und Mandant.

## Phishing und Identitätsbetrug

- **Identitätsbetrug und BEC**: gefälschte Anzeigenamen gegen eine VIP-Liste, ähnliche Domains, Beziehungen von Absender und Empfänger. [BEC](bec.md)
- **BEC-Muster**: ein bekannter Absender, der zu neuer Stunde, viel mehr als üblich oder an neue Empfänger schreibt, wird höher bewertet.
- **Doppelgänger-Domains**: neue Zertifikate von Domains, die eigene oder Partner-Domains nachahmen (Certificate Transparency). Standardmäßig aus.
- **Link-Prüfung beim Klick**: Links über eine signierte Weiterleitung, beim Klick erneut geprüft, mit Hinweisen zu gefährlichen Links. [Link-Prüfung](link-check.md)
- **QR-Codes** in Bildern und PDF-Dateien werden gelesen und ihre Links geprüft. Standardmäßig aus.
- **Phishing-Meldungen und Warnbanner**: eine Meldeadresse pro Domain, ein Banner in verdächtigen Mails. [Phishing & Banner](phishing-and-banner.md)
- **Outlook-Add-in**, um eine Mail mit einem Klick zu melden. [Schutz](protection.md)
- **BIMI**: das Logo eines Absenders mit strenger DMARC-Richtlinie, geprüft als SVG Tiny PS. Standardmäßig aus.
- **Übernommene Konten**: ein Absender über seiner Sendegrenze wird angehalten, bis ein Admin ihn freigibt. Standardmäßig aus. [Übernommene Konten](hijacked-accounts.md)

## Anhänge und Sandbox

- **Anhangfilter** mit echter Typerkennung, auch in Archiven, und gefährlichen Dateinamen. [Anhänge & CDR](attachments-and-cdr.md)
- **Entschärfen (CDR)** von Office- und PDF-Dateien oder Umwandlung in PDF. [Anhänge & CDR](attachments-and-cdr.md)
- **Office-Makros** werden mit olevba gelesen; Autostart-Makros und verdächtige Aufrufe werden bewertet. Standardmäßig aus.
- **Verschlüsselte ZIP-Archive** werden mit einem Passwort aus der Mail geöffnet und geprüft. Standardmäßig aus.
- **Sandbox**: verdächtige Anhänge an die eigene CAPEv2-Sandbox; die Mail wartet auf das Urteil. Standardmäßig aus.
- **Eigene Sperren**: SHA-256 von Anhängen und YARA-Regeln, pro Mandant oder für alle. [Eigene Sperren](own-blocks.md)
- **Grenzen des Virenscans**: Zeit und Größe pro Mail, bei Fehler annehmen oder ablehnen, pro Mandant.

## Quarantäne, Portal und Mail-Behandlung

- **Quarantäne** mit Freigabe und Löschen; **zurückgehaltene Mails** für Benutzer mit täglicher Übersicht. [Mail & Quarantäne](mail-and-quarantine.md)
- **Benutzerportal** (eigener Prozess) für die eigene Quarantäne, Absenderlisten, Spam-Grenze, 2FA und Passkeys.
- **Mail-Log** in MariaDB, nach Alter oder Größe gehalten, mit indizierter **Nachrichtensuche** und CSV/JSON-Export.
- **Mail-Warteschlange**: ansehen, anhalten, freigeben, löschen, erneut senden.
- **Zwischenspeichern**, solange der Mailserver dahinter nicht erreichbar ist, mit Erreichbarkeit pro Ziel. [Spooling](spooling.md)
- **Notfallzugriff**: empfangene Mails lesbar, solange die Mailserver dahinter ausgefallen sind. Standardmäßig aus.
- **Rückholfenster**: ausgehende Mails von Benutzern warten 1 bis 5 Minuten und können zurückgezogen werden. Standardmäßig aus.
- **Schutz vor Fehlversand**: ein Anhang an einen neuen Empfänger wartet auf eine Bestätigung. Standardmäßig aus.
- **Rollenadressen** (postmaster@, abuse@, security@ …) pro Domain weitergeleitet, mit security.txt-Generator. [Rollenadressen](role-addresses.md)
- **Bewerbungen** pro Domain von allen oder nur von gelisteten Adressen angenommen. [Bewerbungen](job-applications.md)
- **Disclaimer und Signaturen** pro Domain, Mandant oder Gruppe, mit Feldern aus LDAP/AD. [Disclaimer-API](api-disclaimer.md)
- **Ausgehende DLP**: IBAN, Kreditkarte, Steuer- und Sozialversicherungsnummern und eigene Muster. Standardmäßig aus.
- **Passwort-PDF**: Mail und Anhänge als AES-256-PDF auf Wunsch. Standardmäßig aus.
- **Archiv-Weiterleitung** und **Journal-Berichte** an ein externes Archiv. [Archiv](archive.md)
- **Newsletter-freundliches Senden** für Massenversender. [Bulk](bulk.md)
- **Mails zurückholen** aus Postfächern über IMAP nach einem späten Treffer. Standardmäßig aus.
- **Mail-Berichte** stündlich, täglich und wöchentlich, als Seite oder per Mail.

## Verschlüsselung

- **Nur TLS 1.2 und 1.3**, Forward Secrecy mit AEAD-Verfahren, nach RFC 9325 und BSI TR-02102-2, für alle Dienste. [TLS-Profile](tls-profiles.md)
- **TLS-Profile** (BSI, RFC 9325, Mozilla modern) und ein hybrider Post-Quanten-Schlüsseltausch, wo OpenSSL ihn bietet.
- **TLS mit Partnern**: TLS, Prüfung oder DANE pro Partnerdomain verlangt. [TLS-Partner](tls-partners.md)
- **S/MIME und PGP** am Gateway: signieren, verschlüsseln, entschlüsseln pro Adresse oder Domain. Standardmäßig aus. [S/MIME & PGP](smime-pgp.md)
- **DKIM** mit RSA (ab 2048 Bit) und Ed25519, Rotation, eine Bereitstellungs-API. [DKIM-API](api-dkim-provisioning.md)
- **DMARC-Berichte, DANE und MTA-STS**: Berichte gelesen und angezeigt, MTA-STS-Richtlinie geschrieben und geprüft. [DMARC, DANE, MTA-STS](dmarc-dane-mta-sts.md)
- **Domain-Prüfung**: MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC, DANE, BIMI und PTR als Ampel pro Domain. [Domain-Prüfung](domain-check.md)
- **Let's Encrypt** mit gleichbleibendem Schlüssel bei der Erneuerung und DANE-sicherem Wechsel.
- **Schlüssel in einem Hardware-Modul** (PKCS#11) für die Backup-Signatur und S/MIME. Standardmäßig aus. [HSM](hsm.md)
- **Zurückgehaltene Mails verschlüsselt gespeichert** (AES-256-GCM pro Mail, Schlüssel pro Mandant).

## Anmeldung, Rollen und Mandanten

- **Zwei-Faktor-Anmeldung** (TOTP) für jeden Benutzer, jeder mit eigenem Geheimnis und Wiederherstellungscodes; ohne eingerichtete 2FA wird keine verlangt. [Zwei-Faktor](two-factor.md)
- **Passkeys und Sicherheitsschlüssel** (WebAuthn) als zweiter Faktor oder allein, pro Rolle. [Zwei-Faktor](two-factor.md)
- **Single Sign-on** mit OIDC und **Verzeichnis-Anmeldung** mit LDAP/AD, Gruppen auf Rollen abgebildet. [Benutzer & Zugriff](users-and-access.md)
- **Rollen und Rechte**: super, tenant, domain, helpdesk, user und eigene Gruppen mit einem Recht pro Befehl. [Benutzer & Zugriff](users-and-access.md)
- **Mandanten** für Dienstleister: Kunden mit ihren Domains, Benutzern und Einstellungen in drei Ebenen. [Domains & Mandanten](domains-and-tenants.md)
- **Sitzungen** aufgelistet und beendet; eine Rechteänderung beendet die Sitzungen dieses Kontos.
- **Fehlanmeldungen**: eine Sperre für Weboberfläche, Portal, API und Port 587. [Anmeldesperre](login-lockout.md)
- **Admin-Zugriff nur aus erlaubten Netzen** und erneute Passwortabfrage bei kritischen Änderungen. [Sicherheitsmodell](security-model.md)
- **Vier-Augen-Prinzip** für kritische Änderungen. Standardmäßig aus. [Konfigurationsverlauf](config-history.md)
- **REST-API** mit Tokens pro Benutzer und **Prometheus**-Metriken.

## Datenschutz und EU

- **EU-Bezug**: Berichtsdienste außerhalb der EU nur nach getippter Bestätigung, streng protokolliert. [EU-Bezug](eu-relation.md)
- **Backup-Ziele nur in der EU**, mit Backup-Passwort. [Backup in der EU](backup-eu.md)
- **DSGVO-Anfragen**: Auskunft und Löschung aller Daten einer Adresse. [DSGVO-Anfragen](gdpr-requests.md)
- **Pseudonyme im Mail-Log** nach den eingestellten Tagen. Bei Neuinstallationen an.
- **Aufbewahrung** pro Mandant, jede Löschung im Audit-Log.
- **Header-Datenschutz**: ausgehende Mails ohne interne Received-Zeilen und Client-Header. [Header-Datenschutz](header-privacy.md)
- **Tracking-Schutz**: Tracking-Pixel und Tracking-Parameter aus eingehenden Mails. Standardmäßig aus. [Datenschutz](privacy-and-reason.md)
- **Datenschutz-Nachweise**: Entwürfe von Verzeichnis der Verarbeitungstätigkeiten und TOM aus den echten Einstellungen. [Vorlagen](datenschutz/README.md)
- **NIS2-Meldungen** mit Fristen und Meldetext. [NIS2](nis2-incident.md)
- **EU-Konformität**: Zuordnung von DSGVO, CRA, NIS2 und ePrivacy zu den Funktionen. [EU-Konformität](compliance/EU.md)
- **Datenschutz durch Voreinstellung**: kurze Aufbewahrung, keine Inhalte im Log bei Neuinstallationen.

## Betrieb

- **Cluster**: ein Master mit Clients oder ein HA-Cluster über gegenseitiges TLS, gestaffelte Updates. [Cluster](cluster.md)
- **Backups** verschlüsselt (OpenPGP AES-256) und signiert (Ed25519), zu S3- oder SFTP-Zielen. [Backup-Ziele](backup-targets.md), [Signierte Backups](backup-signature.md)
- **Konfigurationsverlauf**: jede Änderung mit Diff gespeichert, eine Änderung rücknehmbar. [Konfigurationsverlauf](config-history.md)
- **Betrieb ohne Internet**: lokaler Spiegel und signierte Offline-Pakete. [Offline](offline.md)
- **Updates** nur aus Releases mit gültiger Signatur, auf Wunsch automatisch.
- **Überwachung**: Dashboard, Milter-Zustand, Ereignisse, Lastanzeige. [Überwachung](monitoring-and-reports.md)
- **SIEM-Export** über TLS (Syslog), **EVE-JSON**-Export, OpenTelemetry. [EVE-Export](eve-export.md)
- **Wazuh-Agent** einrichten. [Wazuh](WAZUH.md)
- **Interne DNS-Server** und die Domains, für die sie antworten, mit DNSSEC pro Domain. [DNS-Weiterleitung](dns-forwarding.md)
- **Weitere Netzwerkschnittstellen** und zusätzliche Uplinks pro Absenderdomain. [Schnittstellen](interfaces.md)
- **Migration von eFa 5** mit allen Postfix-Einstellungen und den Absenderlisten. [Migration](migration.md)

## Installation und Einrichtung

- **Ein Befehl** installiert auf einem minimalen AlmaLinux, Rocky Linux oder RHEL 9: Repositorys mit geprüften Schlüsseln, Werkzeuge, Uhr. [Installation](install.md)
- **Einrichtungsassistent** auf Deutsch und Englisch: Hinweis, geführte oder manuelle Einrichtung, EU-Bezug, Regelwerke, Netz, 2FA, Prüfung. [Erste Schritte](first-steps.md)
- **Geführte Einrichtung**: Regelwerke (NIS2, DORA, BSI, ISO 27001 …) heben die Einstellungen an, 2FA für Haupt- und Konsolen-Admin Pflicht.
- **Neu-Einrichtung** eines laufenden Systems, nur anhebend.
- **Standard- und Expertenansicht**, Oberfläche auf Deutsch und Englisch, Suche über Seiten und Einstellungen, dunkles Design.

## Sicherheit des Systems

- **SELinux erzwingend**, eigenes Richtlinienmodul; systemd-Sandbox für die Dienste, die Mails lesen.
- **Sicherheitsminimum-Wache**: TLS-Einstellungen unter der Grenze werden zurückgesetzt oder der Dienst bleibt gestoppt. [Sicherheitsmodell](security-model.md)
- **CVE-Wache** der installierten Pakete mit rotem Hinweis bei erreichbaren Lücken, optionale Selbstsperre der Webdienste. [CVE-Wache](cve-watch.md)
- **Härtungsbericht** (auch als PDF) nach BSI TR-02102. [Härtungsbericht](hardening-report-pdf.md)
- **Audit-Log** mit strengem Modus und täglich signiertem Anker. [Audit-Anker](audit-anchor.md)
- **Root-SSH**-Warnung und Schalter; der Konsolen-Admin mit eigener 2FA über SSH.
- **Kein eigenes Apache, PHP oder Perl**; reproduzierbare Builds und eine SBOM pro Release.

## Bekannte Grenzen

- Der eigene Fuzzy-Speicher arbeitet pro Server; ein gemeinsamer Speicher der Knoten eines Clusters ist nicht gebaut.
- BIMI prüft das Logo, nicht die VMC/CMC-Zertifikate.
- Perl kommt zur Laufzeit nur mit MariaDB und rspamd, die es selbst brauchen.
