# Funktionen von eFa-next (6.0.0.6)

Alles, was eFa-next 6.0.0.6 enthält. „Standardmäßig aus" heißt: die Funktion ist da und wird vom Admin eingeschaltet. Jede
Funktion ist ein Befehl von `efactl` und, wo sie Einstellungen hat, eine Seite der Weboberfläche, mit denselben Prüfungen und
demselben Audit-Log. English: [FEATURES.md](FEATURES.md). Wie man sie nutzt, Kapitel für Kapitel: das [Handbuch](manual/README.de.md).

## Mail-Filter und Erkennung

- **rspamd mit Redis** prüft jede Mail: Spam-Wert, SPF, DKIM, DMARC (die Richtlinie jedes Absenders), ARC, Greylisting. [Schutz](protection.md)
- **ClamAV** sucht Viren, mit den Sanesecurity-Signaturen (Dateien mit geringem Fehlalarm-Risiko, per GPG-Signatur geprüft). [Schutz](protection.md)
- **Weitere ClamAV-Signaturen**: URLhaus, InterServer, SecuriteInfo (mit Kontostufe und eigenen Download-Zeilen, der Schlüssel wird nie gezeigt), jeweils nach bestätigten Nutzungsbedingungen. Standardmäßig aus.
- **Zusätzliche Virenscanner** über ICAP und die External Services von rspamd (Scanner und Lizenz des Betreibers). Standardmäßig aus.
- **DNS-Sperrlisten** über den eigenen Resolver (Spamhaus mit DQS-Schlüssel, SpamCop, PSBL und mehr), Bedingungen verlinkt und bestätigt. [Sperrlisten](rbl.md)
- **IP-Sperrlisten** aus Feeds und eigenen Listen, in der Firewall angewendet. [Schutz](protection.md)
- **Postscreen** auf Port 25 mit Pregreet-Prüfung und gewichteten Sperrlisten.
- **Absenderlisten und Regeln** für Adressen, Domains, IP-Adressen und Muster; ein erlaubter Absender kommt immer durch, nie als offenes Relay. [Schutz](protection.md)
- **Absender erlauben oder sperren** direkt aus Mail-Log, Live-Log oder Quarantäne, mit Prüfung vorher und Rückgängig. [Mail & Quarantäne](mail-and-quarantine.md)
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
- **Der DNS-Resolver für weitere Netze** (der zweite MX), nur für die genannten Netze, nie offen.

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
- **Entschärfen (CDR)** von Office- und PDF-Dateien; das Original bleibt für den Admin. [Anhänge & CDR](attachments-and-cdr.md)
- **Office-Makros** werden mit olevba gelesen; Autostart-Makros und verdächtige Aufrufe werden bewertet. Standardmäßig aus.
- **Verschlüsselte ZIP-Archive** werden mit einem Passwort aus der Mail geöffnet und geprüft. Standardmäßig aus.
- **Sandbox**: verdächtige Anhänge an die eigene CAPEv2-Sandbox; die Mail wartet auf das Urteil. Standardmäßig aus.
- **Eigene Sperren**: SHA-256 von Anhängen und YARA-Regeln, pro Mandant oder für alle. [Eigene Sperren](own-blocks.md)
- **Grenzen des Virenscans**: Zeit und Größe pro Mail, bei Fehler annehmen oder ablehnen, pro Mandant.

## Quarantäne, Portal und Mail-Behandlung

- **Quarantäne** mit Freigabe und Löschen; **zurückgehaltene Mails** für Benutzer mit täglicher Übersicht. [Mail & Quarantäne](mail-and-quarantine.md)
- **Benutzerportal** (eigener Prozess) für die eigene Quarantäne, Absenderlisten, Spam-Grenze, 2FA und Passkeys.
- **Mail-Log** in MariaDB, nach Alter oder Größe gehalten, mit indizierter **Nachrichtensuche**, Filtern (`from:`, `domain:`, `ip:`, `result:`), Live-Log, den Details einer Mail seitlich und CSV/JSON-Export.
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
- **Mail-Berichte** für Tag, Woche oder Monat, als Seite oder PDF; per Mail täglich und wöchentlich, auch als PDF-Anhang.

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
- **Single Sign-on** mit OIDC (Admin-Oberfläche, Mandanten und Benutzerportal) und **Verzeichnis-Anmeldung** mit LDAP/AD, Gruppen auf Rollen abgebildet. [Benutzer & Zugriff](users-and-access.md)
- **Mein Konto** oben rechts auf jeder Seite: eigener Kontakt, Adresse, Passwort, 2FA und Sitzungen.
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
- **Aufbewahrung** je Datenart und je Mandant (Mail-Log, Berichte, Audit-Log, zurückgehaltene Mail, Originale, Phishing-Meldungen), jede Löschung im Audit-Log. [Datenschutz](privacy-and-reason.md)
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
- **Updates** nur aus Releases mit gültiger Signatur, auf Wunsch automatisch; **zurück zur Version davor** in einem Schritt; eine Prüfung der Konfiguration nach jeder Änderung der installierten Pakete. [Upgrade](upgrade.md)
- **Überwachung**: Dashboard, Milter-Zustand, Ereignisse, Lastanzeige. [Überwachung](monitoring-and-reports.md)
- **SIEM-Export** über TLS (Syslog), **EVE-JSON**-Export, OpenTelemetry. [EVE-Export](eve-export.md)
- **Wazuh-Agent** einrichten, oder einen vorhandenen unverändert übernehmen. [Wazuh](WAZUH.md)
- **Angriffswarnung**: ein Banner auf jeder Admin-Seite und Lampen und Anzeigen im Dashboard für Fluten, Passwortraten, Spam- und Virenwellen, gestoppte Dienste und volle Platten. [Dashboard](dashboard.md)
- **Interne DNS-Server** und die Domains, für die sie antworten, mit DNSSEC pro Domain. [DNS-Weiterleitung](dns-forwarding.md)
- **Weitere Netzwerkschnittstellen** und zusätzliche Uplinks pro Absenderdomain. [Schnittstellen](interfaces.md)
- **Migration von eFa 5** mit allen Postfix-Einstellungen und den Absenderlisten. [Migration](migration.md)

## Installation und Einrichtung

- **Ein Befehl** installiert auf einem minimalen AlmaLinux, Rocky Linux oder RHEL 9: Repositorys mit geprüften Schlüsseln, Werkzeuge, Uhr. [Installation](install.md)
- **Einrichtungsassistent** auf Deutsch und Englisch: Hinweis, geführte oder manuelle Einrichtung, EU-Bezug, Regelwerke, Netz, 2FA, Prüfung. [Erste Schritte](first-steps.md)
- **Geführte Einrichtung**: Regelwerke (NIS2, DORA, BSI, ISO 27001 …) heben die Einstellungen an, 2FA für Haupt- und Konsolen-Admin Pflicht.
- **Neu-Einrichtung** eines laufenden Systems, nur anhebend.
- **Sicherheitsstandards in der Einrichtung**: Der Assistent fragt, welche Standards der Server erfüllen soll, und setzt den strengsten Wert aller gewählten.
- **Standard- und Expertenansicht**, Oberfläche durchgehend auf Deutsch und Englisch, Suche mit Vorschlägen über Seiten, Einstellungen und das Mail-Log, Hilfe zu jeder Karte und jedem Feld, dunkles Design.
- **Assistenten** für die häufigsten Einrichtungen (Domain und Mailserver, DKIM-Schlüssel, Disclaimer, Mailarchiv, Härtung), neben den vollen Karten. [Handbuch](manual/04-dashboard.de.md)
- **Funktion wünschen oder verbessern**: ein Link in der Weboberfläche zum Formular für Funktionswünsche des Projekts.

## Sicherheit des Systems

- **SELinux erzwingend**, eigenes Richtlinienmodul; **systemd-Sandbox** für die Dienste, die Mails lesen (rspamd, ClamAV, unbound), bei Neuinstallation und Migration ab Werk an; redis und nginx auf Wunsch; die Weboberfläche erreicht efactl ohne sudo.
- **Sicherheitsminimum-Wache**: TLS-Einstellungen unter der Grenze werden zurückgesetzt oder der Dienst bleibt gestoppt. [Sicherheitsmodell](security-model.md)
- **CVE-Wache** der installierten Pakete mit rotem Hinweis bei erreichbaren Lücken, optionale Selbstsperre der Webdienste. [CVE-Wache](cve-watch.md)
- **Härtungsbericht** (auch als PDF) nach BSI TR-02102. [Härtungsbericht](hardening-report-pdf.md)
- **Sicherheitsstandards**: BSI, RFC 9325, Mozilla, NIST oder CIS wählen, die Änderung vorher sehen, mit Rücksprungpunkt anwenden, dazu eine tägliche Prüfung aller Standards gegen die wirksamen Einstellungen. [Sicherheitsstandards](tls-profiles.md#security-standards-choose-apply-check)
- **Audit-Log** mit strengem Modus und täglich signiertem Anker. [Audit-Anker](audit-anchor.md)
- **Härtungs-Assistent**: die Standards, die Punkte des Betriebssystems und von eFa-next, eine Vorschau und ein Rücksprungpunkt; fremde Dienste und Ports nur gemeldet. [Handbuch](manual/09-security.de.md)
- **TLS auf Port 25 verlangen**, bewusst, mit der Zahl der Sitzungen ohne TLS der letzten 7 Tage.
- **Root-SSH**-Warnung und Schalter; der Konsolen-Admin mit eigener 2FA über SSH.
- **Kein eigenes Apache, PHP oder Perl**; reproduzierbare Builds und eine SBOM pro Release.

## Eigener Server

eFa-next braucht einen eigenen Server oder eine eigene VM. Darauf laufen nur eFa-next und das Betriebssystem: keine weiteren
Serverdienste, keine weiteren offenen Ports. Monitoring- oder Backup-Agenten des Admins (etwa Wazuh) sind möglich, auf eigenes
Risiko. eFa-next härtet und prüft den Server als Ganzes; der Härtungs-Assistent meldet Dienste und offene Ports, die nicht zu
eFa-next oder zum Betriebssystem gehören. Er stoppt oder entfernt sie nie.

## Bekannte Grenzen

- Der eigene Fuzzy-Speicher arbeitet je Knoten; ein gemeinsamer Speicher der Knoten eines Clusters ist nicht gebaut (geplant für 6.0.0.7).
- Im Cluster bleiben zurückgehaltene Mails und die Warteschlange auf dem Knoten, der die Mail angenommen hat. Admins sehen und bearbeiten alle Knoten über den Master; Benutzer sehen im Portal nur die zurückgehaltenen Mails des Knotens, auf dem das Portal läuft, und bekommen einen Digest je Knoten. Eine gemeinsame Quarantäne aller Knoten folgt in 6.0.0.7.
- BIMI prüft das Logo, nicht die VMC/CMC-Zertifikate (geplant für 6.0.0.7).
- Suche nur in der Weboberfläche, nicht im Textmenü efa-tui (geplant für 6.0.0.7).
- Notfallzugriff ohne ZIP/MBOX-Export je Postfach (geplant für 6.0.0.7).
- DKIM- und ARC-Schlüssel bleiben Software-Schlüssel; das Hardware-Modul hält nur Backup-Signatur und S/MIME-Schlüssel (geplant für 6.0.0.7).
- Das Release-Upgrade von AlmaLinux 9 auf 10 ist gebaut, startet aber erst, wenn die signierte EL10-Paketquelle von eFa-next existiert; AlmaLinux 10 selbst ist noch nicht getestet. [Release-Upgrade](release-upgrade.md)
- Die Sendegrenzen übernommener Konten zählen je Knoten, nicht über den Cluster.
- Single Sign-on (OIDC) ist noch nicht gegen einen echten Anbieter getestet; das ARC-Siegel nach dem Entschärfen noch nicht gegen einen fremden ARC-Prüfer.
- Zusätzliche Uplinks je Absenderdomain ohne Ausfallumschaltung.
- PDF-Dateien (Berichte, Härtungsbericht) zeigen nur westeuropäische Buchstaben; andere werden zu `?`.
- Perl kommt zur Laufzeit nur mit MariaDB und rspamd, die es selbst brauchen.

Alle Grenzen dieses Releases: [STATUS-6.0.0.6.md](STATUS-6.0.0.6.md).
