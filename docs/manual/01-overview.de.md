# 1. Überblick

eFa-next ist ein Mailfilter für Unternehmen und Organisationen. Es nimmt die Mail Ihrer Domains aus dem Internet an, prüft sie
und gibt saubere Mail an Ihren eigenen Mailserver weiter (Microsoft 365, Exchange, Google Workspace oder jeden SMTP-Server).
Auch ausgehende Mail kann durch eFa-next gehen: Sie wird dann mit DKIM signiert und auf Datenabfluss und übernommene Konten
geprüft. eFa-next ist der Nachfolger von eFa 5; es behält die Idee und ersetzt MailScanner, MailWatch, Apache, PHP und Perl durch
einen einzigen, kleineren Aufbau.

**Bestimmungsgemäße Verwendung:** für qualifizierte Administratoren mit Kenntnissen in Linux, DNS, SMTP und TLS; nicht für
Verbraucher. Siehe [DISCLAIMER.md](../../DISCLAIMER.md).

## Wie Mail fließt

```
Internet ──► Postfix (postscreen, TLS, Blocklisten, Greylisting, Empfängerprüfung)
                 │
                 ▼
            rspamd (Spam, SPF/DKIM/DMARC/ARC, BEC, Bayes, Fuzzy)  ◄──► ClamAV (+ weitere Signaturen)
                 │
                 ▼
            Inhalts-Milter (Anhänge, Entschärfung, Linkprüfung, Banner)
                 │
     ┌───────────┼──────────────────────────┐
     ▼           ▼                          ▼
  Zustellung   zurückgehaltene Mail /     Abweisung
  an Ihren     Quarantäne (Benutzer geben
  Mailserver   im Portal frei, Admins in
               der Weboberfläche)
```

Jede Entscheidung steht im Mail-Log (MariaDB), das die Weboberfläche durchsucht und die Berichte zählen.

## Die Bestandteile

| Teil | Aufgabe |
|---|---|
| Postfix | nimmt Mail an und stellt sie zu, TLS, postscreen, Warteschlange |
| rspamd | Spam-Bewertung, Prüfung von SPF, DKIM, DMARC, ARC, DKIM-Signatur |
| ClamAV | Virenprüfung, mit Sanesecurity und wahlweise URLhaus, InterServer und SecuriteInfo |
| Unbound | eigener validierender DNS-Resolver (DNSSEC): DNS-Blocklisten antworten, kein fremder Resolver sieht Ihre Anfragen |
| MariaDB | Mail-Log, Benutzer, Gruppen, Einstellungen mit Geltungsbereich |
| Redis (Valkey auf EL10) | kurzlebige Daten: Greylisting, Ratenlimits, Absenderbeziehungen |
| nginx + efa-web | Admin-Weboberfläche und Benutzerportal über HTTPS |
| efactl | der eine Befehl hinter jeder Aktion; die Weboberfläche erreicht ihn nur über `efactl-runner` |

Einstellungen liegen in `/etc/eFa`, Logs in `/var/log/eFa`, Daten in `/var/lib/eFa`.

## Die Weboberfläche

Das Menü links hat sieben Gruppen:

| Gruppe | Seiten |
|---|---|
| Übersicht | Dashboard |
| Mail & Quarantäne | Mail-Routing, Zurückgehaltene Mail, Quarantäne, Mail-Warteschlange, Mail-Log |
| Schutz | Spam & Viren, Blocklisten, IP-Sperrlisten, Absenderlisten, Regeln, Identitätsbetrug & BEC |
| Domains & Mandanten | DKIM, ARC & DMARC, Schutz vor Datenabfluss, Massenversand, Archiv-Weitergabe, Verschlüsselte PDF-Mail, Disclaimer, Domain-Einstellungen, Mandanten |
| Benutzer & Zugriff | Mein Konto, Benutzer, Gruppen, Sicherheitsstandards, Sicherheit |
| Überwachung & Berichte | Mail-Bericht, Überwachung, Wazuh |
| System | DNS-Resolver für weitere Netze, Netzwerk & Zertifikat, Sicherung & Wiederherstellung, Cluster & offline, Wartung & Update |

Jede Anmeldung sieht nur die Seiten und Karten, die ihre Gruppen erlauben (Kapitel 8). Jede Karte erklärt unter ihrem Titel in
einem Satz, was sie tut; ein (i) öffnet die ganze Hilfe, ebenso bei jedem Feld. Die Oberfläche gibt es auf Englisch und Deutsch
(Umschalter auf der Anmeldeseite, und je Anmeldung unter *Mein Konto › Meine Einstellungen*, mit Zeitzone, Zeilen je Seite und
Standardansicht).

Alle Funktionen, gruppiert, mit Link zu jeder Referenzseite: [FEATURES.de.md](../FEATURES.de.md).

## Grundsätze

- **Sicher ab Werk.** Nur moderne TLS-Versionen, Zwei-Faktor-Anmeldung, kein offenes Relay, kein offener Resolver, im Zweifel
  geschlossen. Ein Sicherheitsminimum (TLS 1.2 oder neuer, ECDHE, AEAD) lässt sich nicht senken.
- **Ihre Daten bleiben bei Ihnen.** Kein fremder Prüfdienst wird gefragt, außer Sie schalten ihn ein; Quellen außerhalb der EU
  sagen das.
- **Alles im Audit-Log.** Jede Änderung, aus dem Web oder auf der Konsole, steht mit wer, wann und was im Audit-Log.
- **Ressourcenschonend.** Keine zusätzlichen Dienste für Aufgaben, die ein Timer oder der Webprozess erledigen kann.

Weiter: [Voraussetzungen und Installation](02-install.de.md) · Zurück: [Handbuch](README.de.md)
