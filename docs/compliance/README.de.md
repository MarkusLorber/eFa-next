# Die Compliance-Datei eines Release

Jedes Release von eFa-next ab 6.0.0.6.7 bringt eine Compliance-Datei mit: `eFa-next-<version>.compliance.json`, mit demselben
Inhalt als Tabellen in `eFa-next-<version>.compliance.md` (englisch) und `eFa-next-<version>.compliance.de.md` (deutsch). Sie
listet je Standard, welche technischen Anforderungen eFa-next abdeckt, in welchem Umfang und mit welchem Nachweis jede Angabe
geprüft werden kann.

**Keine rechtlich verbindliche Aussage.** Die Datei ist keine Zertifizierung, keine Konformitätsbestätigung durch Dritte und
keine Rechtsberatung. Gewährleistung und Haftung: Es gilt [DISCLAIMER.md](../../DISCLAIMER.md), soweit gesetzlich zulässig. Der
Betreiber bleibt für die Konformität seiner Organisation verantwortlich. Eine unabhängige Überprüfung durch eigene Prüfer oder
Auditoren ist jederzeit möglich, mit den Mitteln unten.

## Status einer Anforderung

| Status | Bedeutung |
| --- | --- |
| abgedeckt (covered) | eFa-next erfüllt seinen Teil der Anforderung, mit Nachweis. |
| teilweise (partial) | eFa-next deckt einen Teil ab oder nur mit einer Einstellung oder einem Schritt des Betreibers; die Grenzen sagen, was fehlt. |
| nicht abgedeckt (not covered) | eFa-next leistet es nicht (zum Beispiel FIPS-140-Modus, Login-Banner, BAA-Vorlage). |
| außerhalb des Umfangs (out of scope) | Eine Anforderung an die Organisation (Richtlinien, Personal, physische Sicherheit), nicht an ein Mail-Gateway. |

## Nachweise und Prüfung

Jede Angabe *abgedeckt* oder *teilweise* nennt einen Nachweis, der mehr ist als ein Dokument: einen Unit-Test oder Selbsttest
(im vollen CI-Lauf des Release bestanden), eine Prüfung des Härtungsberichts, einen Sicherheitsstandard, einen lesenden
efactl-Befehl mit erwartetem Wert, eine Datei oder eine Wazuh-Regel. Die Quelle ist `next/usr/share/eFa/compliance/controls.json`;
sie liegt im Paket. Erzeugt und geprüft wird die Datei mit `scripts/compliance_build.py` im CI-Schritt `compliance`, gegen das
Schema `compliance/compliance.schema.json`. Änderungen zum vorigen Release liefert `scripts/compliance_diff.py`.

## Selbst prüfen

1. Die Dateien des Release mit `SHA256SUMS` und `SHA256SUMS.asc` herunterladen.
2. `gpg --verify SHA256SUMS.asc SHA256SUMS` mit dem Release-Schlüssel (`RPM-GPG-KEY-efa-next`).
3. `sha256sum -c --ignore-missing SHA256SUMS`.
4. Auf einem installierten Host als Super-Admin oder Auditor: `sudo efactl compliance-verify` oder
   `sudo efactl compliance-verify --standard pci-dss`. Nur lesend. Je Anforderung der angegebene Status und das Ergebnis auf
   diesem Host: pass, fail (oft eine Einstellung, die aus ist), not-applicable (nur Tests, geprüft im CI des Release) oder
   operator (Aufgabe des Betreibers). In der Weboberfläche unter *Datenschutz & Compliance*, *Compliance-Datei*.
5. Das signierte Prüfergebnis des Hosts: *Datenschutz & Compliance*, *Compliance-Datei*, **Prüfergebnis herunterladen**
   (Super-Admins und Auditoren des ganzen Systems; im Audit-Log) oder `sudo efactl compliance-verify --signed`. Das Zip enthält
   `result.json`, die Ed25519-Signatur `result.json.sig` mit dem Backup-Signaturschlüssel des Hosts und `signer.pub.pem`. Prüfen:
   `openssl pkeyutl -verify -pubin -inkey signer.pub.pem -rawin -in result.json -sigfile result.json.sig`, dann den
   Fingerabdruck mit `sudo efactl backup-key-show` des Hosts vergleichen, oder in einem Schritt
   `sudo efactl compliance-verify-check --file ergebnis.zip --fingerprint "<Fingerabdruck>"`.
6. Der OSCAL-Export `eFa-next-<version>.compliance.oscal.json` (OSCAL 1.1.2 component-definition, geprüft gegen das
   offizielle Schema) für Werkzeuge, die OSCAL lesen. NIST SP 800-53 mit den offiziellen Control-IDs, alle anderen Standards
   mit IDs im Namensraum von eFa-next.
7. Den Quellcode (AGPL-3.0) lesen und die Tests selbst laufen lassen: `python3 -m unittest discover -s tests -v`.
