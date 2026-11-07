# Gerüst: Vertrag zur Auftragsverarbeitung (Betrieb von eFa-next für Kunden)

**Vorlage: an die eigene Organisation anpassen.** Kein fertiger Vertrag. Das Gerüst nennt die Punkte, die Art. 28 Abs. 3
DSGVO für einen solchen Vertrag aufzählt, und füllt sie mit den technischen Tatsachen von eFa-next. Die Vertragstexte formuliert
die Rechtsberatung.

Parteien: Verantwortlicher [Kunde] und Auftragsverarbeiter [MSP, der eFa-next betreibt].

## 1. Gegenstand und Dauer

- Gegenstand: Betrieb eines E-Mail-Sicherheitsgateways (eFa-next) für die Domains [Liste] des Verantwortlichen
- Dauer: [Laufzeit des Hauptvertrags]

## 2. Art und Zweck der Verarbeitung

Annehmen, Prüfen, Zurückhalten und Zustellen von E-Mails; Protokollierung; optional DLP, Verschlüsselung, Archiv-Weitergabe.
Einzelheiten: VVT.md, Abschnitt 2.

## 3. Art der Daten und Kategorien betroffener Personen

Siehe VVT.md, Abschnitte 3 und 4.

## 4. Pflichten und Rechte des Verantwortlichen

- Weisungen: [Form, Weisungsberechtigte]. Technisch umgesetzte Weisungen sind die Einstellungen in eFa-next; Änderungen stehen im Audit-Log.
- Mandantentrennung: Der Verantwortliche bekommt einen eigenen Mandanten; seine Admins sehen nur dessen Domains.

## 5. Pflichten des Auftragsverarbeiters (Art. 28 Abs. 3 lit. a–h)

| Punkt | Technischer Bezug in eFa-next | Vertrag |
|-------|-------------------------------|---------|
| a) Verarbeitung nur auf Weisung | Einstellungen, Audit-Log | […] |
| b) Vertraulichkeit der Beschäftigten | Rollen und Rechte, strenger Audit-Modus | […] |
| c) Sicherheit (Art. 32) | TOM.md, Härtungsbericht | […] |
| d) Unterauftragsverarbeiter | externe Ziele nur nach Einrichtung (Sicherung S3/SFTP, SIEM, Archiv) | [Liste, Zustimmungsverfahren] |
| e) Unterstützung bei Betroffenenrechten | Suche im Mail-Log, Export (JSON), Löschung nach Frist | […] |
| f) Unterstützung bei Art. 32–36 | Ereignisse, Sicherheits-Check, Härtungsbericht | […] |
| g) Löschung oder Rückgabe nach Ende | Mandant löschen (`tenant-delete`), Sicherungen laufen nach ihrer Frist ab | [Fristen] |
| h) Nachweise und Kontrollen | Audit-Log, Härtungsbericht je Release | […] |

## 6. Meldung von Verletzungen

Technisch: Ereignisse (SIEM/OTLP/Wazuh), Alarme per Mail. Vertrag: [Frist, Kontakt].

## 7. Ort der Verarbeitung

[Standort der Server, Sicherungsziele, Archive; Drittländer ja/nein]

## Anlagen

- VVT.md (Datenarten, Fristen)
- TOM.md (Maßnahmen)
- [Liste der Unterauftragsverarbeiter]
