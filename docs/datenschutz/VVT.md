# Verzeichnis von Verarbeitungstätigkeiten: E-Mail-Filter eFa-next

**Vorlage: an die eigene Organisation anpassen.** Platzhalter in eckigen Klammern ausfüllen.

## 1. Angaben zum Verantwortlichen

- Verantwortlicher: [Name, Anschrift]
- Vertretung: [Name]
- Datenschutzbeauftragte/r: [Name, Kontakt, falls bestellt]
- Auftragsverarbeiter (falls ein MSP das System betreibt): [Name, Anschrift], Vertrag: siehe AVV

## 2. Bezeichnung und Zweck

**E-Mail-Sicherheitsgateway (eFa-next)**: Prüfen ein- und ausgehender E-Mails auf Spam, Schadsoftware, Phishing und
Datenabfluss, Zustellung an die internen Mailserver bzw. ins Internet, Nachweis der Zustellung, Abwehr von Angriffen.

Zwecke im Einzelnen:
- Schutz der IT-Systeme und der Beschäftigten vor Schadsoftware, Spam und Betrug
- Zustellung und Nachvollziehbarkeit von E-Mails (Mail-Log, Header)
- Quarantäne verdächtiger Mails mit Freigabe durch Berechtigte
- optional: Schutz vor Datenabfluss (DLP), Verschlüsselung, Disclaimer, Archiv-Weitergabe, Versandgrenzen

Rechtsgrundlage: [vom Verantwortlichen festzulegen, z. B. Art. 6 Abs. 1 lit. f DSGVO (berechtigtes Interesse an IT-Sicherheit),
Art. 6 Abs. 1 lit. c DSGVO (Aufbewahrungspflichten); bei Beschäftigten zusätzlich nationales Recht]

## 3. Kategorien betroffener Personen

- Beschäftigte und andere Nutzer der eigenen Mail-Domains
- externe Absender und Empfänger (Kunden, Lieferanten, sonstige)
- Administratoren und Nutzer der Weboberfläche

## 4. Kategorien personenbezogener Daten

| Daten | Wo | Standard-Löschfrist | Einstellung |
|-------|----|---------------------|-------------|
| Verbindungsdaten: Zeit, IP-Adresse des einliefernden Servers, Queue-ID | Mail-Log (MariaDB `maillog`), Postfix-Log | 30 Tage | Mail-Log: Aufbewahrung (`maillog-retention-set`) |
| Umschlag und Kopfzeilen: Absender, Empfänger, Betreff, Message-ID, From, Reply-To, Return-Path, X-Mailer | Mail-Log | 30 Tage | wie oben; Betreff-Anzeige abschaltbar |
| Prüfergebnisse: Spam-Wert, Symbole, SPF/DKIM/DMARC/ARC, Viren-/Bedrohungsname, Größe | Mail-Log | 30 Tage | wie oben |
| alle Kopfzeilen einer Mail (komprimiert) | `mail_headers` | 30 Tage, je Mandant/Domain änderbar | Domain-Einstellungen: Header speichern / Tage |
| Mail-Inhalt in Quarantäne (zurückgehaltene Mails) | Postfix-Hold-Queue bzw. Quarantäne-Speicher | 30 Tage | Quarantäne-Tage |
| Originale entschärfter Anhänge (CDR) | `/var/lib/efa-cdr` | 30 Tage | CDR an/aus |
| gemeldete Phishing-Mails (Inhalt) | MariaDB `train_requests` | Inhalt nach 30 Tagen gelöscht | Phishing-Meldungen an/aus |
| DMARC- und TLS-Berichte anderer Provider (IP-Adressen, Zählungen) | MariaDB | 400 Tage | Berichte einlesen an/aus |
| Aktionen der Admins und Anmeldungen (Benutzer, IP, Zeit, Aktion, Begründung) | Audit-Log (MariaDB `audit`) | 400 Tage | strenger Audit-Modus: eigene Frist |
| offene Web-Sitzungen (Benutzer, IP, Zeit) | MariaDB `web_sessions` | 1 Tag nach der letzten Nutzung | — |
| Konten der Weboberfläche (Name, Mailadresse, Gruppen, Passwort-Hash) | MariaDB `users` | bis zur Löschung des Kontos | Benutzer & Zugriff |
| Ereignisse für SIEM/OTLP/Wazuh (Anmeldungen, Treffer, Sperren) | `/var/log/eFa/events.json`, ggf. externes SIEM | monatlich rotiert, 4 Monate; extern nach dessen Regeln | Ereignisse / OTLP an/aus |
| gesperrte IP-Adressen (Fail2Ban, Firewall-Wächter) | Fail2Ban-Datenbank | 1 Stunde Sperre; Historie nach den Fail2Ban-Vorgaben (dbpurgeage, Paketstandard 1 Tag) | — |
| Sicherungen aller obigen Daten (verschlüsselt, AES-256) | `/var/eFa/backup`, optional S3/SFTP | 5 Tage lokal, extern je Ziel (Standard 30 Tage) | Sicherung, externe Ziele |
| optional: Kopie jeder Mail an ein externes Archiv | externes Archiv (z. B. MailStore, piler) | nach den Regeln des Archivs | Archiv-Weitergabe (Standard aus) |
| optional: Treffer der DLP-Regeln (Absender, Regelname) | Mail-Log, Ereignisse | wie Mail-Log | DLP (Standard aus) |
| optional: vereinbarte PDF-Passwörter je Empfänger | `/etc/eFa/pdf-passwords.json` (nur root) | bis zur Löschung | Verschlüsselte PDF-Mail |

Besondere Kategorien (Art. 9 DSGVO) werden nicht gezielt verarbeitet, können aber in Mail-Inhalten vorkommen.

## 5. Empfänger

- interne Mailserver des Verantwortlichen (Zustellung)
- Mailserver der externen Empfänger (ausgehende Mail)
- Berechtigte Administratoren, Mandanten-Admins und Nutzer (eigene Quarantäne), nach Rollen und Rechten
- optional: SIEM/OTLP-Ziel, Wazuh, externes Archiv, externe Sicherungsziele (S3/SFTP): [Namen eintragen]
- DNS- und Blocklisten-Abfragen (IP-Adressen und Domains der Absender gehen an die abgefragten Listen): [aktive Listen eintragen]

## 6. Übermittlung in Drittländer

[Vom Verantwortlichen zu prüfen: z. B. Blocklisten-Dienste, Cloud-Speicher für Sicherungen, Archiv außerhalb der EU.]

## 7. Löschfristen

Siehe Spalte "Standard-Löschfrist". eFa-next löscht automatisch nach Ablauf (stündliche bzw. tägliche Läufe). Übersicht und Einstellung: `efactl retention-status`, `retention-set`.

## 8. Technische und organisatorische Maßnahmen

Siehe [TOM.md](TOM.md).
