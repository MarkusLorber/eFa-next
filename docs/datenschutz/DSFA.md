# Datenschutz-Folgenabschätzung (Art. 35 DSGVO): Mailfilterung mit eFa-next

**Vorlage, nicht anwaltlich geprüft. Vor der Verwendung mit der eigenen Rechtsberatung und dem Datenschutzbeauftragten
anpassen.** Keine rechtlich verbindliche Aussage des eFa-next-Projekts; siehe [DISCLAIMER.md](../../DISCLAIMER.md).

Platzhalter stehen in eckigen Klammern: `[Verantwortlicher]`. Der technische Teil (Abschnitt 3 und 5) kommt aus dem eigenen
System: `efactl privacy-evidence` (Datenschutz & Compliance, Nachweise) erzeugt Datenflüsse, Speicherfristen und Maßnahmen aus
den tatsächlichen Einstellungen; `efactl compliance-verify --standard gdpr` prüft die Angaben auf dem Host. Beides datiert anhängen.

## 1. Beschreibung der Verarbeitung

- Verantwortlicher: `[Name, Anschrift]`, Datenschutzbeauftragter: `[Kontakt]`
- Zweck: Schutz der E-Mail-Kommunikation vor Spam, Schadsoftware und Phishing; Zustellung; Nachvollziehbarkeit
- Betroffene: Beschäftigte, Absender und Empfänger von E-Mails, Ansprechpartner von Kunden und Lieferanten
- Daten: Absender- und Empfängeradressen, Kopfzeilen, Betreff (nur für berechtigte Rollen sichtbar), bei Quarantäne der Inhalt
  der Nachricht, IP-Adressen, Ergebnis der Prüfung; Protokolle der Administratoren
- Rechtsgrundlage: `[z. B. Art. 6 Abs. 1 lit. c/f DSGVO, § 26 BDSG bzw. Betriebsvereinbarung]`

## 2. Notwendigkeit und Verhältnismäßigkeit

- Ohne Filterung: `[Risiko durch Schadsoftware, Phishing, Datenabfluss]`
- Datenminimierung: keine Inhalte im Mail-Log, Pseudonyme nach `[Tage]`, Betreff nur für berechtigte Rollen, Header-Datenschutz
- Speicherbegrenzung: Mail-Log `[Tage]`, Quarantäne `[Tage]`, Audit-Log `[Tage]` (Abschnitt 3)
- Mitbestimmung: Einführung und Protokollierung können eine Vereinbarung nach § 96 ArbVG (Österreich) oder § 87 Abs. 1 Nr. 6
  BetrVG (Deutschland) erfordern: `[Stand, Datum]`

## 3. Datenflüsse und Speicherfristen (aus privacy-evidence)

`[Ausgabe von efactl privacy-evidence einfügen: Domains, EU-Bezug, Fristen je Datenart und Mandant, Backup-Ziele, SIEM,
OpenTelemetry, Wazuh, DMARC-Berichtsdienste mit Sitz, DNS-Sperrlisten]`

## 4. Risiken für die Rechte und Freiheiten

| Risiko | Eintrittswahrscheinlichkeit | Schwere | Bewertung |
|---|---|---|---|
| Unbefugte Einsicht in Mailinhalte durch Administratoren | `[...]` | `[...]` | `[...]` |
| Leistungs- oder Verhaltenskontrolle der Beschäftigten über das Mail-Log | `[...]` | `[...]` | `[...]` |
| Offenlegung bei einem Einbruch in den Server | `[...]` | `[...]` | `[...]` |
| Übermittlung in Drittländer (Backup, Berichtsdienste) | `[...]` | `[...]` | `[...]` |
| Fehlfilterung: zurückgehaltene oder verlorene Mail | `[...]` | `[...]` | `[...]` |

## 5. Abhilfemaßnahmen (aus privacy-evidence und compliance-verify)

- Rollen und Rechte, Mandantentrennung, Recht „Mail-Inhalt ansehen“, optional Begründungspflicht und strenges Audit-Log
- 2FA für jeden Admin, Sperre nach Fehlanmeldungen pro Adresse, Anmeldehinweis, Sitzungsende nach Leerlauf
- Verschlüsselung: TLS, gehaltene Mails pro Mandant verschlüsselt, Sicherungen verschlüsselt und signiert; Verschlüsselung der
  Datenträger durch den Betreiber `[LUKS / Virtualisierung: ja/nein]`
- EU-Bezug: Backups nur zu Anbietern in europäischer Hand, Dienste außerhalb der EU nur nach Bestätigung
- `[weitere organisatorische Maßnahmen]`

## 6. Ergebnis

`[Restrisiko, Entscheidung, ggf. Konsultation der Aufsichtsbehörde nach Art. 36 DSGVO, Datum, Unterschrift]`
