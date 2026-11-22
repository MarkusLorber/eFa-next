# eFa-next

eFa-next ist ein selbst betriebenes Open-Source-Mail-Security-Gateway für RHEL-kompatible Systeme (AlmaLinux, Rocky Linux,
RHEL; EL9 und EL10). Es steht vor Ihrem Mailserver, filtert ein- und ausgehende Mail mit rspamd und ClamAV und gibt die
geprüfte, versiegelte und signierte Mail weiter. Es führt die Idee des [eFa-Projekts](https://efa-project.org) auf einer
modernen Basis fort und ist mit ihm nicht verbunden (aber davon inspiriert).

English: [README.md](README.md)

**Bestimmungsgemäße Verwendung:** eFa-next ist ein Mailfilter-Server für qualifizierte Administratoren in Unternehmen und
Organisationen und setzt Kenntnisse in Linux, DNS, SMTP und TLS voraus. Es ist nicht für Verbraucher oder Privatpersonen
bestimmt und für diese Verwendung nicht freigegeben ([DISCLAIMER.md](DISCLAIMER.md)); die Rechte aus der AGPL bleiben davon
unberührt.

**Handbuch:** das vollständige Handbuch mit Screenshots, von der Installation bis zum täglichen Betrieb:
[Handbuch](docs/manual/README.de.md) (English: [manual](docs/manual/README.md)).

## Sicherheit, Datenschutz, Souveränität und EU-Compliance zuerst

Diese vier gehen jeder anderen Funktion vor: im Entwurf, in den Voreinstellungen und in jedem Release. Das Folgende beschreibt,
wofür eFa-next ausgelegt ist. Es ist keine Rechtsberatung und kein Versprechen eines Ergebnisses; siehe
[Rechtliche Hinweise](#rechtliche-hinweise-und-lizenz).

### Sicherheit

- Sichere Voreinstellungen: nur TLS 1.2 und 1.3 mit Forward Secrecy, SELinux im Enforcing-Modus, ein gehärtetes System,
  Zwei-Faktor-Anmeldung für die Administratoren, Passkeys und nur moderne Verschlüsselung
  ([TLS-Profile](docs/tls-profiles.md)).
- Ein Sicherheitsminimum-Wächter, eine CVE-Überwachung der installierten Pakete, ein Härtungsbericht und ein signierter Anker
  des Audit-Logs helfen dem Betreiber, den Zustand des Servers jederzeit zu sehen.
- Koordinierte Offenlegung von Schwachstellen mit fester Kontaktadresse, Advisories und CVEs: [SECURITY.md](SECURITY.md).
- Jedes Release ist signiert: die Pakete, der Repository-Index, die Prüfsummen (`SHA256SUMS`) und die Release-Tags, mit dem
  eFa-next-Schlüssel `1823 D6D3 BB7D 5AEA 286E 836D CFE7 E079 16CC 8046`. Installer, Migration und Update-Prüfung nehmen nur
  Releases mit gültiger Signatur.

### Datenschutz (DSGVO)

- Mails, Quarantäne, Mail-Log und Einstellungen bleiben auf Ihrem Server. eFa-next hat keine Telemetrie: Es meldet weder
  Nutzung noch Mails an das Projekt. Es verbindet sich nur nach außen, wo seine Funktionen es brauchen (DNS, signierte Updates
  und Feeds oder Dienste, die Sie einschalten).
- Datensparsame Voreinstellungen, Pseudonyme in Berichten, Header-Datenschutz und Tracking-Schutz; vor dem Öffnen des Inhalts
  einer Mail kann ein Grund verlangt werden ([Datenschutz-Voreinstellungen](docs/privacy-and-reason.md)).
- Funktionen, die dem Betreiber bei DSGVO-Anfragen (Auskunft, Löschung) und bei Verzeichnissen und Vorlagen helfen
  ([DSGVO-Anfragen](docs/gdpr-requests.md), [Datenschutz-Vorlagen](docs/datenschutz/README.md)).

### Digitale Souveränität

- Selbst betrieben auf Ihrem eigenen Server oder Ihrer VM: kein Cloud-Konto, kein Abonnement, kein externer Dienst für die
  Grundfilterung nötig.
- Betrieb ohne Internetzugang ist möglich ([Betrieb ohne Internet](docs/offline.md)).
- Mit der Einstellung *EU-Bezug* brauchen Übermittlungen an Dienste außerhalb der EU eine ausdrückliche, protokollierte
  Bestätigung, und Sicherungen lassen sich auf Ziele in der EU beschränken ([EU-Bezug](docs/eu-relation.md),
  [Sicherungsziele in der EU](docs/backup-eu.md)).
- Open Source unter der AGPL-3.0-or-later: Jeder kann den Code prüfen, bauen und betreiben.

### Unterstützung bei der EU-Compliance

eFa-next ist dafür ausgelegt, Betreibern bei ihren Pflichten nach EU-Recht zu helfen. Es macht eine Organisation nicht
rechtskonform und ist nicht zertifiziert.

- **Cyber Resilience Act (CRA):** eine Kontaktadresse für Schwachstellenmeldungen ([SECURITY.md](SECURITY.md)),
  Sicherheitsupdates als signierte Releases, veröffentlichte Advisories und eine Software-Stückliste (SBOM, CycloneDX) zu jedem
  Release.
- **Compliance-Datei je Release** (ab 6.0.0.6.7): für jeden betrachteten Standard, welche Controls das Release abdeckt, teilweise
  abdeckt oder nicht abdeckt, jeweils mit Nachweis; als JSON, Markdown (Englisch und Deutsch) und OSCAL, in den signierten
  Prüfsummen des Release. Sie ist keine rechtlich verbindliche Aussage.
- **DSGVO und NIS2:** Funktionen für DSGVO-Anfragen, NIS2-Vorfallmeldungen ([NIS2-Vorfälle](docs/nis2-incident.md)) und eine
  Zuordnung von EU-Anforderungen zu den Funktionen von eFa-next ([EU-Konformität](docs/compliance/EU.md)).

Der Betreiber bleibt für den Betrieb von eFa-next und für die Erfüllung der rechtlichen Pflichten seiner Organisation
verantwortlich.

## Aktueller Stand

Die aktuelle Release-Linie ist **6.0.0.6** für EL9 und EL10 (AlmaLinux 9 und 10; Rocky Linux und RHEL); das neueste Release
und seine Hinweise stehen auf der [Release-Seite](https://github.com/MarkusLorber/eFa-next/releases). Änderungen je Release:
[CHANGELOG.md](CHANGELOG.md). eFa-next ist ein junges Projekt: Testen Sie es, bevor Sie sich darauf verlassen.

## Installation

Voraussetzungen, eigener Server, Installation, Migration von eFa 5 und Bauen aus dem Quellcode stehen in der englischen
[README.md](README.md) und im [Handbuch](docs/manual/README.de.md). Kurz, als root auf einem frisch installierten Host:

```bash
curl -fsSLO https://repo.efa-next.eu/build.bash && sha256sum build.bash
```

```bash
bash build.bash
```

Vergleichen Sie die SHA256-Summe vorher mit den [Release-Hinweisen](https://github.com/MarkusLorber/eFa-next/releases).
https://repo.efa-next.eu ist die Quelle der Releases; die GitHub-Releases sind ein Spiegel.

## Sicherheit und Support

Schwachstellen melden Sie wie in [SECURITY.md](SECURITY.md) beschrieben, nie in einem öffentlichen Issue. Hilfe:
[SUPPORT.md](SUPPORT.md).

## Rechtliche Hinweise und Lizenz

eFa-next wird von Markus Lorber und Lukasz Galusinski geschrieben; die IT-World ITW GmbH unterstützt das Projekt als Sponsor und
hält keine Rechte am Code ([AUTHORS.md](AUTHORS.md)).

eFa-next wird ohne jede Gewährleistung bereitgestellt. Soweit gesetzlich zulässig, haften Markus Lorber, alle Autoren und
Mitwirkenden von eFa-next und seine Sponsoren, einschließlich der IT-World ITW GmbH, nicht für Schäden aus seiner Verwendung;
die Verwendung erfolgt auf eigenes Risiko. Siehe [DISCLAIMER.md](DISCLAIMER.md) und die Abschnitte 15 und 16 der
[Lizenz](LICENSE).

Die Beschreibungen zu Sicherheit, Datenschutz, Souveränität und EU-Recht auf dieser Seite und in der Dokumentation sagen, wofür
eFa-next ausgelegt ist und was es unterstützt. Sie sind keine Rechtsberatung, keine Zertifizierung und keine Zusicherung, dass
eine Organisation ihre rechtlichen Pflichten erfüllt. Der Betreiber entscheidet, wie eFa-next eingerichtet und verwendet wird,
und bleibt dafür verantwortlich.

Alles, was von eFa-next stammt, steht unter der GNU Affero General Public License, Version 3 oder später
(AGPL-3.0-or-later, [LICENSE](LICENSE)). Die Programme, die eFa-next verwendet und nicht verändert, etwa Postfix, rspamd,
ClamAV, MariaDB, Redis, nginx, Unbound, die Python-Bibliotheken und die Pakete des Betriebssystems, behalten ihre eigenen
Lizenzen; die SBOM jedes Release nennt jede Komponente mit Version und Lizenz. Einzelheiten: [LICENSES.md](LICENSES.md).
