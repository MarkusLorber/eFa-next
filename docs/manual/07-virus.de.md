# 7. Viren, Anhänge und Links

Alles unter *Schutz › Spam & Viren*, jeweils als eigene Karte.

## Virenprüfung (ClamAV)

Jede Mail prüft ClamAV. *Prüfgrenzen* begrenzen eine Prüfung: die Sekunden, die clamd brauchen darf (5 bis 20), die größte Mail,
die es prüft (10 bis 64 MB), und die Sekunden aller Prüfungen von rspamd (8 bis 60). Scheitert die Prüfung (clamd aus, zu langsam,
eine Grenze erreicht), geht die Mail entweder ungeprüft durch (*offen*) oder wird mit `451` aufgeschoben, sodass der Absender es
erneut versucht (*geschlossen*); eine zu große Mail wird dann abgewiesen. Eine Neuinstallation ist geschlossen; der Modus kann je
Mandant abweichen (`efactl scan-fail-set --tenant <Name> --fail closed`).

*Weitere Virenscanner* und *Sandbox* fügen weitere Engines und einen Analysedienst hinzu, wo sie installiert sind; siehe
[protection.md](../protection.md).

## Virensignaturen

ClamAV holt seine eigenen Signaturen über freshclam. *Virensignaturen* fügt weitere hinzu, alle 2 Stunden geprüft:

| Quelle | Herkunft | Was sie hinzufügt | Braucht |
|---|---|---|---|
| Sanesecurity | Sanesecurity und Partner | Signaturen für Phishing, Betrug und Schadsoftware | an ab Werk (eigener Schalter, `sanesecurity-set`) |
| URLhaus | abuse.ch, Schweiz | Links bekannter Schadsoftware | angenommene Bedingungen |
| InterServer | USA | Hashes von Schadsoftware und Web-Shells | das Häkchen (der Anbieter veröffentlicht keine Bedingungen) |
| SecuriteInfo | Frankreich | viele zusätzliche Signaturen | ein eigenes SecuriteInfo-Konto |

Jede Quelle hat ihren eigenen Schalter mit dem wirksamen Zustand. Wird eine Quelle mit noch nicht angenommenen Bedingungen
eingeschaltet, zeigt die Karte zuerst den Link des Anbieters und ein Häkchen; die Annahme wird mit Name und Zeit aufbewahrt. Jede
Datei kommt über HTTPS, nur wenn sie sich geändert hat, bis 200 MB, und zählt erst, wenn `clamscan` sie geladen hat. Eine
abgeschaltete Quelle verliert ihre Dateien beim nächsten Lauf. Nur Super-Admins ändern die Quellen; jede Änderung steht im
Audit-Log.

### SecuriteInfo: Kontostufe und Download-Zeilen

SecuriteInfo wird mit Ihrem eigenen Konto genutzt. In seiner Zeile:

1. Die **Kontostufe** wählen. *Basic*: höchstens eine Runde Downloads alle 30 Minuten und höchstens 300 kB/s. eFa-next hält das
   selbst ein, auch über Neustarts und Läufe von Hand hinweg.
2. Die `DatabaseCustomURL`-Zeilen von der Einrichtungsseite Ihres SecuriteInfo-Kontos einfügen, oder die Konto-ID eingeben.

Die Zeilen enthalten Ihren Abo-Schlüssel. eFa-next speichert sie nur für root, zeigt, protokolliert und auditiert sie nie; die
Seite sagt nur, wie viele Zeilen gespeichert sind, mit *Ersetzen* und *Löschen*. Die Zeilen werden streng geprüft: `https`, ein
Host von `securiteinfo.com`, eine ClamAV-Datenbankdatei, höchstens 40 Zeilen. Konsole (fragt die Zeilen auf der Standardeingabe ab):

```bash
sudo efactl clam-securiteinfo-set --tier basic
```

Im Cluster lädt jeder Knoten selbst und zählt gegen die Grenze des Kontos.

## Anhänge

*Anhänge* sperrt oder hält nach dem echten Dateityp (Inhalt, nicht Endung) und nach dem Inhalt von Archiven. Programme werden
gesperrt; Ausnahmen nach Namen sind möglich, ein einzelner Absender kann erlaubt werden. *Verschlüsselte Archive* öffnet
verschlüsselte ZIP-Archive für die Prüfung mit einem Passwort aus Betreff oder Text der Mail. *Office-Makros* liest VBA-Makros und
bewertet Autostart und verdächtige Aufrufe.

## Entschärfung von Inhalten (CDR)

*Entschärfung von Inhalten* entfernt die aktiven Teile aus Office- und PDF-Dateien: Makros gehen (aus `.docm` wird `.docx`),
PDF-Dateien verlieren JavaScript, Öffnen- und Start-Aktionen und eingebettete Dateien. Eine Datei, die sich nicht reinigen lässt,
wird durch einen kurzen Hinweis ersetzt; eine unlesbare Datei lässt die Mail warten. Das Original bleibt für den Admin
(`efactl cdr-list`, `cdr-release`; aktive Inhalte freizugeben braucht das Recht, Schadsoftware freizugeben). *Aktives HTML*
entfernt Skripte, Formulare und Ereignis-Handler aus HTML-Mail. Signierte oder verschlüsselte Mail bleibt unverändert. Details:
[attachments-and-cdr.md](../attachments-and-cdr.md).

## Linkprüfung beim Klick

*Linkprüfung* schreibt die Links eingehender Mail auf eine signierte Adresse dieses Servers um, sodass jeder Link beim Klick erneut
geprüft wird. Ein sicherer Link leitet sofort weiter, ein gefährlicher zeigt eine Warnseite mit der echten Adresse und dem Grund.
Ausnahmen je Domain sind möglich. *Hinweise* auf der Warnseite lassen sich je Mandant setzen. Details: [link-check.md](../link-check.md).

## Phishing-Meldungen und Warnbanner

*Phishing-Meldungen und Warnbanner* gibt Benutzern einen Weg, eine Mail zu melden (auch über ein Outlook-Add-in), und setzt ein
Warnbanner in Mail von außen. Details: [phishing-and-banner.md](../phishing-and-banner.md).

Weiter: [Domains, Mandanten, Benutzer und Portal](08-domains-users.de.md) · Zurück: [Handbuch](README.de.md)
