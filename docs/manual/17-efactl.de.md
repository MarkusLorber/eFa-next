# 17. efactl-Referenz

Jede Aktion der Weboberfläche ist ein Befehl von `efactl` auf der Konsole, mit denselben Prüfungen, Rechten und demselben Audit-Log.
Als Konsolen-Admin mit `sudo` aufrufen. `sudo efactl --help` listet alle Befehle, `sudo efactl <Befehl> --help` die
Argumente eines Befehls, `sudo efactl menu` öffnet das Textmenü mit denselben Seiten wie die Weboberfläche.

Die Liste ist aus dem Menü der Weboberfläche und den Befehlstiteln von `efactl` dieses Releases erzeugt.
Befehle mit *ändert* ändern das System, die anderen lesen nur. Titel ohne deutsche Übersetzung stehen auf Englisch.

## Übersicht

### Dashboard

| Befehl | Titel |
|---|---|
| `status` | Status |
| `settings` | Einstellungen: zeigen |

## Mail & Quarantäne

### Mail-Routing

| Befehl | Titel |
|---|---|
| `transport-set` | Domains und ihre Mailserver *(ändert)* |
| `relay-networks-list` | Relay-Netze |
| `relay-networks-add` | Netze hinzufügen *(ändert)* |
| `relay-networks-remove` | Ein Netz entfernen *(ändert)* |
| `relay-networks-apply` | Änderungen der Relay-Netze übernehmen *(ändert)* |
| `relay-networks-discard` | Änderungen der Relay-Netze verwerfen *(ändert)* |
| `relay-networks-set` | Relay-Netze *(ändert)* |
| `smarthost-set` | Smarthost für ausgehende Mail *(ändert)* |
| `submitter-list` | Einlieferer |
| `submitter-set` | Einlieferer: hinzufügen oder ändern *(ändert)* |
| `submitter-remove` | Einlieferer: entfernen *(ändert)* |
| `outbound-limits-set` | Versandgrenzen je Absender und Stunde *(ändert)* |
| `hijack-list` | Angehaltene Konten (möglicherweise übernommen) |
| `hijack-release` | Angehaltene Konten: eines freigeben *(ändert)* |
| `header-privacy-status` | Header-Datenschutz ausgehender Mail |
| `header-privacy-set` | Header-Datenschutz: für wen *(ändert)* |
| `message-size-set` | Größte Mailgröße *(ändert)* |
| `recipient-verification-set` | Empfängerprüfung *(ändert)* |
| `tls-partner-list` | TLS mit Partner-Domains |
| `tls-partner-set` | TLS mit Partner-Domains: verlangen oder entfernen *(ändert)* |

### Zurückgehaltene Mail

| Befehl | Titel |
|---|---|
| `uq-list` | Zurückgehaltene Mail |
| `uq-show` | Zurückgehaltene Mail: Header |
| `uq-release` | Zurückgehaltene Mail: freigeben *(ändert)* |
| `uq-request` | Zurückgehaltene Mail: einen Admin um Freigabe bitten *(ändert)* |
| `uq-sender` | Zurückgehaltene Mail: den Absender erlauben oder sperren *(ändert)* |
| `uq-delete` | Zurückgehaltene Mail: löschen *(ändert)* |
| `train-request` | Als Spam oder als erwünscht melden *(ändert)* |
| `train-list` | Spam-Meldungen |
| `train-decide` | Spam-Meldungen: entscheiden *(ändert)* |
| `uq-status` | Quarantäne für Benutzer |
| `uq-set` | Quarantäne für Benutzer: Einstellungen *(ändert)* |
| `uq-encrypt-set` | Quarantäne für Benutzer: verschlüsselt gespeichert *(ändert)* |
| `my-settings` | Meine Einstellungen |
| `my-settings-set` | Meine Einstellungen: ändern *(ändert)* |
| `account-show` | Mein Konto |
| `account-set` | Mein Konto: Name und Telefon *(ändert)* |
| `account-email-set` | Mein Konto: E-Mail-Adresse *(ändert)* |
| `password-change` | Mein Konto: Passwort *(ändert)* |
| `totp-status` | 2FA meiner Anmeldung |
| `totp-setup` | 2FA: die App einrichten (oder eine neue) *(ändert)* |
| `totp-confirm` | 2FA: mit dem ersten Code einschalten *(ändert)* |
| `totp-recovery-new` | 2FA: neue Wiederherstellungscodes *(ändert)* |
| `totp-disable` | 2FA: ausschalten *(ändert)* |
| `passkey-status` | Passkeys |
| `passkey-register` | Passkeys: hinzufügen *(ändert)* |
| `passkey-remove` | Passkeys: einen meiner entfernen *(ändert)* |
| `graymail-status` | Newsletter (Graymail) |
| `graymail-mine-set` | Newsletter an mein Postfach *(ändert)* |
| `user-spam-status` | Eigene Spam-Grenze |
| `user-spam-mine-set` | Meine Spam-Grenze *(ändert)* |
| `recall-list` | Meine Mails im Rückholfenster |
| `recall-withdraw` | Eine meiner Mails zurückziehen *(ändert)* |
| `emergency-list` | Notfallzugriff: empfangene Mail |
| `emergency-show` | Notfallzugriff: eine Mail lesen |
| `emergency-file` | Notfallzugriff: einen Anhang oder die Mail speichern |

### Quarantäne

| Befehl | Titel |
|---|---|
| `quarantine-list` | Quarantäne: Liste |
| `quarantine-show` | Quarantäne: Header zeigen |
| `quarantine-release` | Quarantäne: zustellen *(ändert)* |
| `quarantine-delete` | Quarantäne: löschen *(ändert)* |
| `quarantine-set` | Quarantäne für Spam *(ändert)* |
| `quarantine-days-set` | Quarantäne: Aufbewahrung in Tagen *(ändert)* |
| `quarantine-purge` | Quarantäne: alte Mail jetzt löschen *(ändert)* |
| `emergency-status` | Notfallzugriff: Kopien zugestellter Mail |
| `emergency-set` | Notfallzugriff: eine versiegelte Kopie zugestellter Mail behalten *(ändert)* |

### Mail-Warteschlange

| Befehl | Titel |
|---|---|
| `queue-list` | Mail-Warteschlange |
| `queue-show` | Mail-Warteschlange: Header |
| `queue-action` | Mail-Warteschlange: zurückhalten, freigeben, neu einreihen oder löschen *(ändert)* |
| `queue-flush` | Mail-Warteschlange: alle jetzt versuchen *(ändert)* |
| `spool-status` | Zwischenspeicher und empfangende Server |
| `spool-set` | Zwischenspeicher: wie lange Mail wartet *(ändert)* |
| `queue-alarm-set` | Mail-Warteschlange: Alarm *(ändert)* |

### Mail-Log

| Befehl | Titel |
|---|---|
| `message-search` | Mailsuche |
| `maillog-search` | Mail-Log: suchen |
| `maillog-live` | Mail-Log: live |
| `sender-action-check` | Absender einer Mail: was Erlauben oder Sperren tun würde |
| `sender-action` | Absender einer Mail: erlauben oder sperren *(ändert)* |
| `gdpr-export` | DSGVO: alles zu einer Mailadresse (Art. 15) |
| `gdpr-delete` | DSGVO: Daten einer Mailadresse löschen (Art. 17) *(ändert)* |
| `headers-export` | Header exportieren *(ändert)* |
| `retention-status` | Aufbewahrung der Daten |
| `retention-set` | Aufbewahrung: Tage *(ändert)* |
| `pseudonymise-status` | Mail-Log: Pseudonyme |
| `pseudonymise-set` | Mail-Log: Pseudonyme nach Tagen *(ändert)* |
| `content-reason-set` | Begründung vor dem Anzeigen von Mail-Inhalt *(ändert)* |
| `subject-display-set` | Betreffs im Mail-Log *(ändert)* |
| `headers-store-set` | Header aller Mails *(ändert)* |
| `maillog-retention-set` | Mail-Log: Aufbewahrung in Tagen *(ändert)* |
| `maillog-size-set` | Mail-Log: Größengrenze *(ändert)* |
| `maillog-purge` | Mail-Log: alte Einträge jetzt löschen *(ändert)* |

## Schutz

### Spam & Viren

| Befehl | Titel |
|---|---|
| `spam-scores-set` | Spam-Scores *(ändert)* |
| `greylisting-set` | Greylisting *(ändert)* |
| `subject-get` | Betreffmarkierung: zeigen |
| `subject-set` | Betreffmarkierung: setzen *(ändert)* |
| `bayes-status` | Bayes-Klassifikator |
| `sanesecurity-status` | Sanesecurity-Signaturen |
| `sanesecurity-set` | Sanesecurity-Signaturen: schalten *(ändert)* |
| `sanesecurity-update` | Signaturen jetzt aktualisieren *(ändert)* |
| `clam-source-status` | Weitere ClamAV-Signaturen |
| `clam-source-set` | Weitere ClamAV-Signaturen: eine Quelle an oder aus *(ändert)* |
| `clam-securiteinfo-set` | Weitere ClamAV-Signaturen: Konto-Stufe und URLs von SecuriteInfo *(ändert)* |
| `attachment-status` | Anhänge |
| `attachment-set` | Anhänge: Einstellungen *(ändert)* |
| `qr-status` | QR-Codes in Mails |
| `qr-set` | QR-Codes in Mails: schalten *(ändert)* |
| `unlock-status` | Verschlüsselte Archive |
| `unlock-set` | Verschlüsselte Archive: mit dem Passwort aus der Mail öffnen und prüfen *(ändert)* |
| `ole-status` | Office-Makros (oletools) |
| `ole-set` | Office-Makros: von olevba gelesen und bewertet *(ändert)* |
| `tracking-status` | Tracking-Schutz |
| `tracking-set` | Tracking-Schutz: Zählpixel und Link-Parameter aus eingehender Mail entfernen *(ändert)* |
| `tracking-list-set` | Tracking-Schutz: Ausnahmen und eigene Tracking-Hosts *(ändert)* |
| `lookalike-status` | Doppelgänger-Domains in neuen Zertifikaten |
| `lookalike-set` | Doppelgänger-Wache: neue Zertifikate für Domains, die den eigenen ähneln *(ändert)* |
| `lookalike-run` | Doppelgänger-Wache: jetzt prüfen *(ändert)* |
| `lookalike-allow` | Doppelgänger-Wache: eine harmlose Domain *(ändert)* |
| `retro-status` | Prüfung nach der Zustellung |
| `retro-set` | Prüfung nach der Zustellung: zugestellte Mail gegen neue Feed-Daten *(ändert)* |
| `retro-run` | Prüfung nach der Zustellung: jetzt prüfen *(ändert)* |
| `retro-imap-set` | Gefährliche Mail aus den Postfächern zurückholen (IMAP) *(ändert)* |
| `outbreak-status` | Ausbruchsfilter |
| `outbreak-set` | Ausbruchsfilter: neue Wellen zurückstellen *(ändert)* |
| `fuzzy-status` | Eigener Fuzzy-Speicher |
| `fuzzy-set` | Eigener Fuzzy-Speicher für freigegebenen Spam *(ändert)* |
| `community-status` | Gemeinsamer Fuzzy-Speicher |
| `community-set` | Gemeinsamer Fuzzy-Speicher der Betreiber *(ändert)* |
| `scanner-status` | Weitere Virenscanner |
| `scanner-set` | Weiterer Virenscanner: hinzufügen, ändern oder entfernen *(ändert)* |
| `sandbox-status` | Sandbox (CAPEv2) |
| `sandbox-set` | Sandbox: verdächtige Anhänge an die eigene CAPEv2 *(ändert)* |
| `own-block-status` | Eigene Sperren: Datei-Hashes und YARA-Regeln |
| `own-hash-set` | Eigene Sperren: SHA-256 einer Datei *(ändert)* |
| `own-yara-set` | Eigene Sperren: eine YARA-Regel *(ändert)* |
| `graymail-set` | Newsletter (Graymail): Einstellungen *(ändert)* |
| `user-spam-set` | Eigene Spam-Grenzen der Benutzer *(ändert)* |
| `scan-status` | Virenprüfung: Grenzen je Mail |
| `scan-limits-set` | Virenprüfung: Grenzen je Mail und Prüffehler *(ändert)* |
| `scan-fail-set` | Virenprüfung: Prüffehler eines Mandanten *(ändert)* |
| `cdr-status` | Entschärfung von Inhalten |
| `cdr-set` | Entschärfung von Inhalten: schalten *(ändert)* |
| `cdr-list` | Entschärfung von Inhalten: Originale |
| `cdr-release` | Entschärfung von Inhalten: das Original zustellen *(ändert)* |
| `html-disarm-set` | Inhaltsbereinigung: aktives HTML *(ändert)* |
| `bimi-set` | BIMI: das Logo eines geprüften Absenders *(ändert)* |
| `links-status` | Linkprüfung |
| `links-set` | Linkprüfung: Einstellungen *(ändert)* |
| `links-hint-set` | Link-Prüfung: eigener Hinweis auf der Warnseite *(ändert)* |
| `phish-set` | Phishing-Meldungen: die Adresse einer Domain *(ändert)* |
| `banner-set` | Warnbanner für Mail von außen *(ändert)* |
| `outlook-addin` | Outlook-Add-in für Meldungen: das Manifest |
| `neural-status` | Neuronales Netz |
| `neural-set` | Neuronales Netz: Einstellungen *(ändert)* |
| `symbol-scores` | Symbol-Scores von rspamd |
| `symbol-score-set` | Symbol-Scores: eigener Score eines Symbols *(ändert)* |
| `ml-status` | Eigenes Modell |
| `ml-set` | Eigenes Modell: Einstellungen *(ändert)* |
| `ml-train` | Eigenes Modell: jetzt lernen *(ändert)* |

### Blocklisten

| Befehl | Titel |
|---|---|
| `rbl-show` | Blocklisten |
| `rbl-set` | Eine Blockliste ändern *(ändert)* |
| `rbl-custom-set` | Eigene Blockliste *(ändert)* |
| `postscreen-status` | postscreen auf Port 25 |
| `postscreen-set` | postscreen auf Port 25: schalten *(ändert)* |
| `feed-status` | Bedrohungs-Feeds |
| `feed-set` | Bedrohungs-Feeds: hinzufügen, ausschalten oder entfernen *(ändert)* |
| `feeds-run` | Bedrohungs-Feeds: jetzt abrufen *(ändert)* |

### IP-Sperrlisten

| Befehl | Titel |
|---|---|
| `blocklist-show` | IP-Sperrlisten |
| `blocklist-set` | IP-Sperrlisten: Liste anlegen oder ändern *(ändert)* |
| `blocklist-entry` | IP-Sperrlisten: eigene Einträge *(ändert)* |
| `blocklist-remove` | IP-Sperrlisten: Liste entfernen *(ändert)* |

### Absenderlisten

| Befehl | Titel |
|---|---|
| `sender-list` | Absenderlisten |
| `sender-add` | Absender hinzufügen *(ändert)* |
| `sender-remove` | Absender entfernen *(ändert)* |
| `sender-move` | Einen Absender in die andere Liste verschieben *(ändert)* |
| `sender-list-set` | Erlaubte und gesperrte Absender *(ändert)* |
| `sender-rule-set` | Absenderregeln: IP, Muster, je Empfänger *(ändert)* |

### Regeln

| Befehl | Titel |
|---|---|
| `rule-list` | Regeln |
| `rule-set` | Regeln: hinzufügen, ändern oder entfernen *(ändert)* |

### Identitätsbetrug & BEC

| Befehl | Titel |
|---|---|
| `bec-status` | Identitätsbetrug und BEC |
| `bec-set` | Identitätsbetrug und BEC: schalten und Scores *(ändert)* |
| `bec-vip-set` | Identitätsbetrug und BEC: VIPs *(ändert)* |
| `bec-partner-set` | Identitätsbetrug und BEC: Partner-Domains *(ändert)* |

## Domains & Mandanten

### DKIM, ARC & DMARC

| Befehl | Titel |
|---|---|
| `dkim-check` | DKIM-Schlüssel |
| `dkim-create` | DKIM-Schlüssel: erzeugen *(ändert)* |
| `dkim-import` | DKIM: Schlüssel importieren *(ändert)* |
| `dkim-remove` | DKIM: einen Schlüssel entfernen *(ändert)* |
| `dkim-export` | DKIM: DNS-Einträge exportieren |
| `rotation-status` | Rotation: Status |
| `rotation-all-set` | Alle Domains automatisch rotieren *(ändert)* |
| `rotation-set` | Eigene Rotationseinstellungen für eine Domain *(ändert)* |
| `rotation-pregenerate` | Rotation: künftige Schlüssel jetzt erzeugen *(ändert)* |
| `rotation-run` | Rotation: jetzt prüfen *(ändert)* |
| `resolver-set` | DNS-Server für die Rotationsprüfung *(ändert)* |
| `dkim-provision-status` | DKIM: extern verwaltet |
| `dkim-provision-set` | DKIM: Provisioning-API auf Port 8463 *(ändert)* |
| `dkim-source-set` | DKIM: eine Quelle, die Schlüssel liefert *(ändert)* |
| `dkim-source-remove` | DKIM: eine Quelle entfernen *(ändert)* |
| `dkim-provision-takeover` | DKIM: eine Domain von ihrer Quelle zurückholen *(ändert)* |
| `arc-show` | ARC-Versiegelung |
| `arc-all-set` | ARC für alle Domains *(ändert)* |
| `arc-set` | ARC für eine Domain *(ändert)* |
| `arc-trusted-set` | ARC: vertrauenswürdige Sealer *(ändert)* |
| `dmarc-record-show` | Gespeicherte DMARC-Einträge |
| `dmarc-record-set` | DMARC-Eintrag erzeugen *(ändert)* |
| `dmarc-record-history` | DMARC-Eintrag: Verlauf |
| `dmarc-record-check` | Einen bestehenden DMARC-Eintrag prüfen |
| `dmarc-reports-set` | DMARC-Berichte *(ändert)* |
| `dmarc-report-show` | Empfangene DMARC-Berichte |
| `tls-report-show` | Empfangene TLS-Berichte |
| `reports-in-set` | Empfangene Berichte: die Adresse *(ändert)* |
| `dkim-selectors` | Gesehene DKIM-Selektoren |

### Schutz vor Datenabfluss

| Befehl | Titel |
|---|---|
| `dlp-status` | Schutz vor Datenabfluss |
| `dlp-set` | Schutz vor Datenabfluss: Kartennummern und IBANs *(ändert)* |
| `dlp-rule-set` | Schutz vor Datenabfluss: eigene Regel *(ändert)* |

### Massenversand

| Befehl | Titel |
|---|---|
| `bulk-status` | Massenversand |
| `bulk-set` | Massenversand: Einstellungen *(ändert)* |

### Archiv-Weitergabe

| Befehl | Titel |
|---|---|
| `archive-status` | Archiv-Weitergabe |
| `archive-set` | Archiv-Weitergabe: Ziel hinzufügen oder ändern *(ändert)* |
| `archive-test` | Archivübergabe: Verbindung testen |
| `archive-remove` | Archiv-Weitergabe: Ziel entfernen *(ändert)* |

### Verschlüsselte PDF-Mail

| Befehl | Titel |
|---|---|
| `pdf-status` | Verschlüsselte PDF-Mail |
| `pdf-set` | Verschlüsselte PDF-Mail: Stichwort im Betreff *(ändert)* |
| `pdf-password-set` | Verschlüsselte PDF-Mail: vereinbartes Passwort eines Empfängers *(ändert)* |

### Disclaimer

| Befehl | Titel |
|---|---|
| `disclaimer-status` | Disclaimer |
| `disclaimer-which` | Disclaimer: welcher für einen Absender gilt |
| `disclaimer-template-set` | Disclaimer für alle Domains, einen Mandanten, eine Domain oder Gruppen *(ändert)* |
| `disclaimer-import` | Disclaimer: ZIP einspielen *(ändert)* |
| `disclaimer-template-remove` | Disclaimer entfernen *(ändert)* |
| `disclaimer-restore` | Disclaimer: zurück zur vorherigen Version *(ändert)* |
| `disclaimer-set` | Disclaimer einer Domain *(ändert)* |
| `signature-status` | AD-Signaturen |
| `signature-set` | AD-Signaturen: Felder des Verzeichnisses in den Disclaimer-Vorlagen *(ändert)* |
| `signature-sync` | AD-Signaturen: das Verzeichnis jetzt lesen *(ändert)* |
| `crypto-status` | S/MIME und PGP: Schlüssel und Regeln |
| `crypto-key-make` | S/MIME und PGP: einen eigenen Schlüssel erzeugen *(ändert)* |
| `crypto-import` | S/MIME und PGP: ein Zertifikat oder einen öffentlichen Schlüssel einspielen *(ändert)* |
| `crypto-remove` | S/MIME und PGP: einen Schlüssel entfernen *(ändert)* |
| `crypto-policy-set` | S/MIME und PGP: signieren, verschlüsseln, entschlüsseln *(ändert)* |
| `crypto-hsm-set` | S/MIME und PGP: ein eigener S/MIME-Schlüssel in einem Hardwaremodul (PKCS#11) *(ändert)* |

### Domain-Einstellungen

| Befehl | Titel |
|---|---|
| `domain-settings-show` | Domain-Einstellungen: mit Quelle zeigen |
| `domain-spam-set` | Domain-Einstellungen: Spam-Grenzen *(ändert)* |
| `domain-quarantine-set` | Domain-Einstellungen: Quarantäne und Übersicht *(ändert)* |
| `domain-routing-set` | Domain-Einstellungen: TLS zur Domain *(ändert)* |
| `domain-general-set` | Domain-Einstellungen: Sprache und gespeicherte Header *(ändert)* |
| `eu-relation-status` | EU-Bezug |
| `eu-relation-set` | EU-Bezug der Domains *(ändert)* |
| `application-status` | Bewerbungen je Domain |
| `application-set` | Bewerbungen: an alle erlaubt oder nur an gelistete Adressen *(ändert)* |
| `application-exception-set` | Bewerbungen: Absender, die immer durchkommen *(ändert)* |
| `domain-check-status` | Domain-Check: Ampel je Domain |
| `domain-check-show` | Domain-Check: Einzelheiten und DNS-Einträge einer Domain |
| `domain-check-run` | Domain-Check: jetzt prüfen *(ändert)* |
| `domain-check-set` | Domain-Check: Schalter und wöchentliche Erinnerung *(ändert)* |
| `role-status` | Rollenadressen je Domain |
| `role-set` | Rollenadressen: an oder aus, und wohin eine Rolle geht *(ändert)* |
| `security-txt` | security.txt einer Domain (RFC 9116) |
| `trap-status` | Spamfallen-Adressen |
| `trap-set` | Spamfallen-Adresse: hinzufügen oder entfernen *(ändert)* |

### Mandanten

| Befehl | Titel |
|---|---|
| `tenant-list` | Mandanten |
| `tenant-set` | Mandanten: hinzufügen oder entfernen *(ändert)* |
| `tenant-domain-set` | Mandanten: Domains *(ändert)* |
| `domain-pending-list` | Mandanten: Domains, die auf DNS warten |
| `domain-onboard` | Mandanten: eine Domain hinzufügen *(ändert)* |
| `domain-verify` | Mandanten: den TXT-Eintrag einer Domain prüfen *(ändert)* |
| `tenant-usage` | Nutzung des Mandanten |
| `tenant-limits-set` | Limits des Mandanten *(ändert)* |
| `tenant-brand-show` | Aussehen des Mandanten |
| `tenant-brand-set` | Aussehen des Mandanten: Name, Farbe, Logo *(ändert)* |
| `tenant-idp-status` | Anmeldeverzeichnis des Mandanten |
| `tenant-ldap-set` | Anmeldeverzeichnis des Mandanten: LDAP *(ändert)* |
| `tenant-oidc-set` | Anmeldeverzeichnis des Mandanten: OIDC *(ändert)* |
| `tenant-group-map-set` | Anmeldeverzeichnis des Mandanten: einer Gruppe eine eFa-Gruppe zuordnen *(ändert)* |
| `tenant-lock` | Mandant: sperren oder entsperren *(ändert)* |
| `tenant-delete` | Mandant: mit allen Daten löschen *(ändert)* |

## Benutzer & Zugriff

### Mein Konto

| Befehl | Titel |
|---|---|
| `whoami` | Meine Anmeldung |
| `session-list` | Aktive Sitzungen |
| `session-end` | Aktive Sitzungen: eine beenden *(ändert)* |

### Benutzer

| Befehl | Titel |
|---|---|
| `user-2fa-reset` | 2FA eines Benutzers: zurücksetzen (Telefon verloren) *(ändert)* |
| `totp-policy-set` | 2FA: Pflicht je Rolle *(ändert)* |
| `passkey-reset` | Passkeys eines Benutzers: alle entfernen (Schlüssel verloren) *(ändert)* |
| `passkey-set` | Passkeys: Hostname und Modus je Rolle *(ändert)* |
| `user-list` | Benutzer |
| `user-show` | Benutzer: wirksame Rechte |
| `user-set` | Benutzer: hinzufügen, ändern oder entfernen *(ändert)* |
| `user-state` | Benutzer: sperren (off) oder entsperren (on) *(ändert)* |
| `token-list` | API-Tokens |
| `token-create` | API-Tokens: einen erzeugen *(ändert)* |
| `token-revoke` | API-Tokens: einen löschen *(ändert)* |
| `api-status` | REST-API |
| `api-set` | REST-API: schalten *(ändert)* |
| `oidc-status` | Single Sign-on (OIDC) |
| `oidc-set` | Single Sign-on: schalten *(ändert)* |
| `ldap-status` | Anmeldung über LDAP oder Active Directory |
| `ldap-set` | LDAP-Anmeldung: schalten *(ändert)* |
| `audit-search` | Audit-Log |
| `incident-list` | NIS2-Vorfälle |
| `incident-open` | NIS2-Vorfall: Eintrag anlegen *(ändert)* |
| `incident-report` | NIS2-Vorfall: Meldung für 24 h, 72 h oder Abschlussbericht |
| `privacy-evidence` | Datenschutz-Nachweis: Verarbeitungsverzeichnis und TOM |
| `audit-strict-status` | Strenger Audit-Modus |
| `audit-mode` | Strenger Audit-Modus: schalten *(ändert)* |
| `audit-verify` | Strenges Audit-Log: die Kette prüfen |
| `audit-anchor-verify` | Strenges Audit-Log: signierte Tagesanker prüfen |
| `audit-rules-set` | auditd-Regeln für die eFa-Dateien *(ändert)* |

### Gruppen

| Befehl | Titel |
|---|---|
| `group-list` | Gruppen |
| `group-set` | Gruppen: hinzufügen, ändern oder kopieren *(ändert)* |
| `group-state` | Gruppen: deaktivieren oder aktivieren *(ändert)* |
| `group-remove` | Gruppen: entfernen *(ändert)* |
| `permission-list` | Rechte |
| `group-map-list` | Verzeichnisgruppen |
| `group-map-set` | Verzeichnisgruppen: eine eFa-Gruppe zuordnen *(ändert)* |

### Sicherheitsstandards

| Befehl | Titel |
|---|---|
| `standards-show` | Sicherheitsstandards: die letzte Prüfung |
| `standards-check` | Sicherheitsstandards: jetzt prüfen (alle Standards, die wirksamen Einstellungen) |
| `standards-status` | Sicherheitsstandards |
| `standards-set` | Sicherheitsstandards: wählen, Vorschau und anwenden *(ändert)* |
| `standards-rollback` | Sicherheitsstandards: zurück zu den Einstellungen davor *(ändert)* |
| `os-harden-status` | Härtung von Betriebssystem und eFa-next: Stand |
| `os-harden-set` | Härtung des Betriebssystems: ein Punkt *(ändert)* |

### Sicherheit

| Befehl | Titel |
|---|---|
| `threat-status` | Angriffswarnung |
| `threat-set` | Angriffswarnung: Empfindlichkeit *(ändert)* |
| `harvest-status` | Adress-Ausspähung |
| `harvest-set` | Adress-Ausspähung: Absender sperren, die viele unbekannte Empfänger probieren *(ändert)* |
| `login-lockout-status` | Fehlanmeldungen: Sperre |
| `login-lockout-set` | Fehlanmeldungen: Sperre für Web, Portal, API und Port 587 *(ändert)* |
| `ssh-root-status` | Root-Login über SSH |
| `ssh-root-set` | Root-Login über SSH: schalten *(ändert)* |
| `web-allowlist-show` | Admin-Zugang zum Webinterface |
| `web-allowlist-set` | Admin-Zugang: erlaubte Adressen *(ändert)* |
| `fail2ban-set` | Fail2Ban *(ändert)* |
| `admin-email-set` | Admin-E-Mail *(ändert)* |
| `rspamd-sso-set` | rspamd-Weboberfläche über eFa-next: nur lesen, auf Zeit *(ändert)* |
| `audit-rspamd` | Ein Öffnen von rspamd vermerken *(ändert)* |
| `web-harden` | Härtung des Webservers anwenden *(ändert)* |
| `firewall-show` | Firewall |
| `firewall-set` | Firewall: Admin-Positivliste *(ändert)* |
| `firewall-confirm` | Firewall: Änderung behalten *(ändert)* |
| `firewall-revert` | Firewall: Änderung zurücknehmen *(ändert)* |
| `firewall-guard-status` | Firewall-Wächter: Status |
| `firewall-guard-set` | Firewall-Wächter *(ändert)* |
| `firewall-guard-run` | Firewall-Wächter: jetzt prüfen *(ändert)* |
| `firewall-test` | Firewall-Tests ausführen |
| `firewall-probe-set` | Prüfstelle außen *(ändert)* |
| `security-status` | Sicherheits-Selbstprüfung |
| `security-check` | Sicherheits-Selbstprüfung: jetzt starten |
| `security-check-set` | Sicherheits-Selbstprüfung: täglich *(ändert)* |
| `security-oval-set` | Sicherheits-Check: CVEs aus OVAL-Daten *(ändert)* |
| `pwned-check-set` | Neue Passwörter: gegen bekannte Datenlecks prüfen *(ändert)* |
| `cve-watch-status` | CVE-Wache: letztes Ergebnis |
| `cve-watch-set` | CVE-Wache und Selbstsperre der Webdienste *(ändert)* |
| `cve-watch-run` | CVE-Wache: jetzt prüfen *(ändert)* |
| `cve-mute` | CVE-Wache: eine Warnung stummschalten *(ändert)* |
| `web-lockdown` | Selbstsperre der Webdienste: Zustand oder Freigabe *(ändert)* |
| `cluster-cve` | CVE-Warnungen aller Knoten |
| `history-list` | Konfigurationsverlauf |
| `history-show` | Konfigurationsverlauf: die Unterschiede einer Änderung |
| `history-undo` | Konfigurationsverlauf: eine Änderung zurücknehmen *(ändert)* |
| `four-eyes-list` | Vier-Augen-Prinzip: wartende Änderungen |
| `four-eyes-decide` | Vier-Augen-Prinzip: eine Änderung bestätigen oder ablehnen *(ändert)* |
| `four-eyes-set` | Vier-Augen-Prinzip für kritische Änderungen *(ändert)* |
| `milter-health-status` | Milter-Gesundheit: je Milter annehmen oder tempfail |
| `milter-health-set` | Milter-Gesundheit: was geschieht, wenn ein Milter ausfällt *(ändert)* |
| `tls-profile-status` | TLS-Profil |
| `tls-profile-set` | TLS-Profil für Weboberfläche und Mail *(ändert)* |
| `tls-port25-set` | TLS auf Port 25 verlangen *(ändert)* |
| `setup-variant-status` | Einrichtungsvariante |
| `setup-offer-dismiss` | Re-Setup: Angebot im Dashboard ausblenden *(ändert)* |
| `console-2fa-set` | 2FA des Konsolen-Admins (SSH) *(ändert)* |
| `floor-status` | Mindestsicherheit |
| `floor-check` | Mindestsicherheit: prüfen und zurücksetzen *(ändert)* |
| `ssh-profile-status` | SSH-Profil |
| `ssh-profile-set` | SSH-Profil: BSI TR-02102-4 oder die Systemeinstellung *(ändert)* |
| `ssh-profile-confirm` | SSH-Profil: behalten (nachdem eine neue Anmeldung geklappt hat) *(ändert)* |
| `hardening-report` | Härtungsbericht (CIS AlmaLinux 9, BSI TR-03108) |
| `switches-status` | Schalter: was gerade eingestellt ist |
| `tls-min-set` | SMTP: nur TLS 1.2 oder neuer *(ändert)* |
| `kernel-hardening-set` | Kernel-Einstellungen des Härtungsberichts *(ändert)* |
| `service-harden-status` | Sandbox der Dienste |
| `service-harden` | Sandbox der Dienste: nur getestete Units, ungetestete Sandbox-Dateien entfernt *(ändert)* |

## Überwachung & Berichte

### Mail-Bericht

| Befehl | Titel |
|---|---|
| `report-show` | Bericht: zeigen oder drucken |
| `report-status` | Berichte per Mail |
| `report-set` | Berichte per Mail: schalten *(ändert)* |
| `mailreport-today` | Heute |
| `mailreport-yesterday` | Gestern |
| `mailreport-week` | Letzte 7 Tage |
| `mailreport-set` | Tägliche Mail *(ändert)* |

### Überwachung

| Befehl | Titel |
|---|---|
| `siem-status` | SIEM-Export |
| `siem-set` | SIEM-Export: Einstellungen *(ändert)* |
| `otlp-status` | OpenTelemetry-Export |
| `otlp-set` | OpenTelemetry-Export: Einstellungen *(ändert)* |
| `otlp-test` | OpenTelemetry-Export: Verbindungstest *(ändert)* |

### Wazuh

| Befehl | Titel |
|---|---|
| `wazuh-status` | Wazuh-Agent |
| `wazuh-config` | Wazuh-Agent: Einstellungen *(ändert)* |
| `wazuh-service` | Wazuh-Agent: starten, stoppen oder neu starten *(ändert)* |
| `wazuh-check` | Wazuh-Agent: das Paket prüfen *(ändert)* |
| `wazuh-install` | Wazuh-Agent: installieren *(ändert)* |
| `wazuh-update` | Wazuh-Agent: aktualisieren *(ändert)* |
| `wazuh-remove` | Wazuh-Agent: entfernen *(ändert)* |

## System

### DNS-Resolver für weitere Netze

| Befehl | Titel |
|---|---|
| `dns-share-list` | DNS für weitere Netze |
| `dns-share-add` | DNS für weitere Netze: erlauben *(ändert)* |
| `dns-share-del` | DNS für weitere Netze: entfernen *(ändert)* |
| `dns-share-secondary-set` | Zweiter DNS-Resolver dieses Hosts (der andere MX) *(ändert)* |

### Netzwerk & Zertifikat

| Befehl | Titel |
|---|---|
| `network-show` | Netzwerk: zeigen |
| `network-set` | Netzwerk: setzen (nach Neustart) *(ändert)* |
| `hostname-set` | Hostname: überall ändern *(ändert)* |
| `interfaces-list` | Netzwerkschnittstellen |
| `interface-set` | Netzwerkschnittstellen: Rolle und Adresse *(ändert)* |
| `interface-confirm` | Netzwerkschnittstellen: Änderung behalten *(ändert)* |
| `interface-revert` | Netzwerkschnittstellen: zurücknehmen *(ändert)* |
| `uplink-route-set` | Ausgehende Mail einer Domain über einen Uplink *(ändert)* |
| `dns-zone-list` | Interne DNS: Server und Domains |
| `dns-servers-set` | Interne DNS-Server *(ändert)* |
| `dns-zone-set` | Interne DNS-Domains *(ändert)* |
| `dns-zone-test` | Interne DNS: SOA einer Domain über diesen Host abfragen |
| `dns-forward-status` | Internes DNS: schickt unbound alle Namen an Forwarder? |
| `dns-forward-fix` | Internes DNS: auf diesem Host auflösen (der Forwarder für alle Namen entfällt) *(ändert)* |
| `letsencrypt-set` | Let's-Encrypt-Zertifikat *(ändert)* |
| `letsencrypt-takeover` | Let's Encrypt: das Zertifikat auf diesem Host übernehmen *(ändert)* |
| `dane-status` | DANE für ausgehende Mail |
| `dane-set` | DANE für ausgehende Mail: schalten *(ändert)* |
| `tlsa-show` | TLSA-Einträge dieses Servers |
| `letsencrypt-rollover` | Let's Encrypt: neuer Schlüssel, ohne DANE zu brechen *(ändert)* |
| `mta-sts-show` | MTA-STS |
| `mta-sts-set` | MTA-STS: Richtlinie einer Domain *(ändert)* |
| `mta-sts-check` | MTA-STS: veröffentlichte Richtlinien jetzt prüfen *(ändert)* |
| `mta-sts-text` | MTA-STS: Richtliniendatei herunterladen |

### Sicherung & Wiederherstellung

| Befehl | Titel |
|---|---|
| `backup-list` | Sicherung: Liste |
| `backup-now` | Jetzt sichern *(ändert)* |
| `backup-set` | Automatische Sicherung *(ändert)* |
| `backup-password-set` | Passwort für automatische Sicherungen *(ändert)* |
| `backup-key-show` | Sicherungen: Fingerabdruck des Signierschlüssels |
| `restore` | Eine Sicherung wiederherstellen *(ändert)* |
| `backup-download` | Sicherung: wo sie liegt |
| `backup-read` | Sicherung: Rohdownload |
| `backup-import` | Sicherung: eine hochgeladene Datei ablegen *(ändert)* |
| `backup-target-list` | Externe Sicherungsziele |
| `backup-target-set` | Externe Sicherungsziele: hinzufügen oder entfernen *(ändert)* |
| `backup-target-test` | Externe Sicherungsziele: die neueste Sicherung jetzt hochladen *(ändert)* |
| `backup-hsm-set` | Sicherungen: der Signaturschlüssel in einem Hardwaremodul (PKCS#11) *(ändert)* |

### Cluster & offline

| Befehl | Titel |
|---|---|
| `cluster-status` | Cluster |
| `cluster-init` | Cluster: diesen Knoten zum Master machen *(ändert)* |
| `cluster-mode-set` | Cluster: Master/Client oder HA *(ändert)* |
| `cluster-token` | Cluster: Einmal-Token für einen neuen Knoten *(ändert)* |
| `cluster-join` | Cluster: einem Master beitreten *(ändert)* |
| `cluster-resync` | Cluster: alle Einstellungen des Masters neu übernehmen *(ändert)* |
| `cluster-mx-check` | Cluster: MX-Einträge und Ausfallsicherheit |
| `cluster-node-remove` | Cluster: Knoten entfernen *(ändert)* |
| `cluster-promote` | Cluster: dieser Client wird Master (der alte ist weg) *(ändert)* |
| `cluster-leave` | Cluster: verlassen *(ändert)* |
| `cluster-update-status` | Gestaffelte Updates des Clusters |
| `cluster-update-set` | Gestaffelte Updates: ein Knoten zuerst, ein Prüffenster, dann der Rest *(ändert)* |
| `offline-status` | Betrieb ohne Internet |
| `update-mirror-set` | Betrieb ohne Internet: Updates von einem lokalen Spiegel *(ändert)* |
| `offline-trust-set` | Betrieb ohne Internet: dem Schlüssel der Pakete vertrauen *(ändert)* |
| `offline-bundle-apply` | Betrieb ohne Internet: ein Paket einspielen *(ändert)* |
| `offline-bundle-make` | Betrieb ohne Internet: ein signiertes Paket erstellen (auf einem Host mit Internet) *(ändert)* |
| `cluster-maillog` | Cluster: Mail-Log aller Knoten |
| `cluster-quarantine` | Cluster: zurückgehaltene Mails aller Knoten |
| `cluster-queue` | Cluster: Warteschlangen aller Knoten |
| `cluster-mail-action` | Cluster: Aktion für eine Mail eines Knotens *(ändert)* |
| `cluster-unban` | Cluster: Sperre auf allen Knoten aufheben *(ändert)* |

### Wartung & Update

| Befehl | Titel |
|---|---|
| `update-pending` | Ausstehende Updates |
| `update-status` | Letztes Systemupdate |
| `update-system` | System aktualisieren *(ändert)* |
| `autoupdate-status` | eFa-Updates |
| `autoupdate-set` | Automatische eFa-Updates *(ändert)* |
| `update-check` | Jetzt nach einem eFa-Update suchen *(ändert)* |
| `update-install` | Das eFa-Update jetzt installieren *(ändert)* |
| `update-rollback` | Update: zurück auf die Version davor *(ändert)* |
| `update-now` | Jetzt aktualisieren *(ändert)* |
| `update-system-run` | System aktualisieren: Hintergrundjob *(ändert)* |
| `update-post-boot` | System aktualisieren: Prüfung nach dem Neustart *(ändert)* |
| `update-run` | Job für automatische Updates *(ändert)* |
| `os-check-status` | Prüfung nach Paket-Updates |
| `os-check-run` | Prüfung nach Paket-Updates: jetzt ausführen *(ändert)* |
| `maintenance-set` | Wartungsmodus *(ändert)* |
| `load-set` | Grenzen der Lastwarnung *(ändert)* |
| `load-notify` | Eine Lastwarnung mailen |
| `release-upgrade-status` | Release-Upgrade auf EL10: Status und Protokoll |
| `release-upgrade` | Release-Upgrade auf EL10 *(ändert)* |
| `reboot` | Neu starten *(ändert)* |
| `halt` | Herunterfahren *(ändert)* |
| `milter-chain-set` | Reihenfolge der Milter *(ändert)* |
| `extra-service-set` | Einen zusätzlichen Dienst überwachen *(ändert)* |
| `mariadb-repair` | Datenbanken reparieren *(ändert)* |

## Nur Konsole und intern

Befehle, die keine Seite zeigt: Einige gibt es nur auf der Konsole (etwa `admin-password`, `clone-reset`, `menu`), andere nutzen die Dienste von eFa-next selbst.

| Befehl | Titel |
|---|---|
| `admin-2fa-verify` | 2FA-Code des Haupt-Admins prüfen |
| `admin-password` | Web admin password (console only) |
| `audit-note` | Strenges Audit-Log: eine Aktion der Web-Oberfläche |
| `audit-purge` | Audit-Log: alte Einträge entfernen |
| `backup-targets-eu-lock` | Sicherungsziele außerhalb der EU: sperren |
| `blocklist-import` | IP-Sperrlisten: Datei importieren (efa-migrate) |
| `blocklist-run` | IP-Sperrlisten: Hintergrundjob |
| `clone-reset` | Geklonter Host: neue Geheimnisse dieses Hosts (nur Konsole) |
| `cluster-content-apply` | Cluster: Link-Schlüssel des Masters übernehmen |
| `cluster-dkim-apply` | Cluster: DKIM-Schlüssel des Masters übernehmen |
| `cluster-snapshot` | Cluster: die gemeinsamen Einstellungen des Masters |
| `console-2fa-enroll` | Eigene 2FA eines Konsolen-Admins (SSH): einrichten |
| `console-2fa-verify` | 2FA-Code des Konsolen-Admins prüfen |
| `dash-stats` | Werte des Dashboards |
| `disclaimer-export` | Disclaimer: als ZIP exportieren |
| `disclaimer-provision-apply` | Disclaimer: ein Aufruf einer Quelle (efa-dkim-api) |
| `disclaimer-sync` | Disclaimer: Ordner des Masters übernehmen (Cluster) |
| `dkim-generate` | RSA-Schlüssel: erzeugen |
| `dkim-generate-ed25519` | Ed25519-Schlüssel: erzeugen |
| `dkim-provision-apply` | DKIM: ein Aufruf einer Quelle (efa-dkim-api) |
| `events-run` | Ereignisse: Hintergrundjob |
| `flow-set` | Bild des Mailflusses: wandernde Briefe |
| `flow-status` | Bild des Mailflusses |
| `form-check` | Formulare: aktuelle Werte (Prüfung) |
| `legal-accept` | Rechtstexte: bestätigen |
| `legal-status` | Rechtstexte |
| `log-show` | Ein Log zeigen |
| `mail-check` | Mail prüfen: das Urteil von rspamd, nichts wird gespeichert oder gelernt |
| `mail-show` | Mail: Details und Header |
| `mailreport-run` | Mail-Bericht: Hintergrundjob |
| `menu` | Text menu with the pages of the web interface (console only) |
| `metrics` | Werte für Prometheus |
| `ml-settings` | Eigenes Modell: Einstellungen |
| `mta-sts-unserve` | MTA-STS: den Richtlinien-Server von 6.0.0.4 aus nginx entfernen |
| `network-harden` | Netzwerk: keine automatischen Profile für neue Schnittstellen |
| `neural-settings` | Neuronales Netz: Einstellungen |
| `oidc-finish` | Single Sign-on: Anmeldung abschließen |
| `oidc-start` | Single Sign-on: Anmeldung beginnen |
| `outbound-hold-run` | Rückholen und Bestätigung: die Aufgabe jeder Minute |
| `outbound-hold-set` | Rückholfenster, oder Bestätigung von Anhängen an neue Empfänger |
| `outbound-hold-status` | Rückholfenster und Bestätigung von Anhängen |
| `passkey-login` | Passkeys: ohne Passwort anmelden |
| `passkey-login-options` | Passkeys: Anmeldung beginnen |
| `passkey-register-options` | Passkeys: einen neuen beginnen |
| `quarantine-content` | Quarantäne: Text |
| `rbl-apply` | Blocklisten: die rspamd-Einstellungen schreiben |
| `redis-tune` | Den Speicher von Redis begrenzen |
| `refusal-note` | Audit-Log: eine Änderung, die die Weboberfläche diesem Login verweigert hat |
| `resetup` | Re-Setup: EU-Bezug, Regelwerke und 2FA |
| `sanesecurity-run` | Sanesecurity: Hintergrundjob |
| `sasl-apply` | Anmeldungen auf Port 587: anwenden |
| `service-restart` | Einen Dienst neu starten |
| `session-check` | Web-Anmeldung: noch aktiv |
| `session-open` | Web-Anmeldung: aufzeichnen |
| `setup-failed-note` | Paket-Setup: der Audit-Eintrag eines fehlgeschlagenen Schritts |
| `setup-variant-apply` | Einrichtungsvariante des Einrichtungsassistenten |
| `ssh-profile-revert` | SSH-Profil: zurück, wenn nicht bestätigt (Job) |
| `standards-preview` | Sicherheitsstandards: Vorschau einer Auswahl (nur lesend) |
| `submission-pam-set` | Port 587: Anmeldung mit Systemkonten (PAM) |
| `threat-run` | Angriffswarnung: Prüfung im Hintergrund |
| `tls-profile-upgrade` | TLS-Profil: Untergrenze nach einem Update halten |
| `token-check` | Einen API-Token prüfen |
| `totp-import` | 2FA des Haupt-Admins (oder eines Konsolen-Admins) aus dem Einrichtungsassistenten |
| `update-staged-set` | Gestaffelte Updates: der Master entscheidet, wann dieser Knoten installiert |
| `uq-content` | Zurückgehaltene Mail: Text |
| `uq-link-use` | Link in einer Übersicht: ausführen |
| `uq-link-view` | Link in einer Übersicht: was er tut |
| `user-verify` | Eine Anmeldung prüfen |

Zurück: [Handbuch](README.de.md)
