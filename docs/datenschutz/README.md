# Datenschutz-Unterlagen (Vorlagen)

**Vorlage: an die eigene Organisation anpassen.**

Diese Vorlagen helfen Betreibern von eFa-next, ihre Pflichten nach der DSGVO zu erfüllen. Sie beschreiben, was eFa-next
technisch verarbeitet und welche Einstellungen es dafür gibt. Was rechtlich nötig ist, entscheidet der Betreiber mit seiner
Rechtsberatung.

| Datei | Inhalt |
|-------|--------|
| [VVT.md](VVT.md) | Eintrag für das Verzeichnis von Verarbeitungstätigkeiten (Art. 30 DSGVO) |
| [TOM.md](TOM.md) | Technische und organisatorische Maßnahmen (Art. 32 DSGVO), soweit eFa-next sie umsetzt |
| [AVV.md](AVV.md) | Gerüst für einen Auftragsverarbeitungsvertrag (Art. 28 DSGVO), für MSPs, die eFa-next für Kunden betreiben |

Platzhalter stehen in eckigen Klammern: `[Name des Verantwortlichen]`.

Die genannten Standardwerte (Löschfristen, Schalter) gelten für eFa-next 6.0.0.4. Prüfen Sie die Werte Ihres Systems mit
`efactl settings` und auf den genannten Seiten der Weboberfläche.

## Built from the settings (M3)

`efactl privacy-evidence [--tenant <name>] [--format pdf]` (Users, Privacy evidence) builds a draft of the record of processing
(Art. 30) and of the technical and organisational measures (Art. 32) from the real settings of the server: domains, EU
relation, retention per kind of data and the own days of the tenant, the data flows (backup targets, SIEM, OpenTelemetry,
Wazuh, DMARC report services with their seat, DNS blocklists) and the measures (TLS profile, encryption of held mail,
pseudonyms, backups, access control, lockout, audit). Purposes, legal basis and contacts stay to be filled in from the
templates in this folder.

