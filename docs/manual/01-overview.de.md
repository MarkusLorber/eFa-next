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

Das Menü links hat acht Gruppen, oben die Seiten für jeden Tag. *Mein Konto* steht im Benutzermenü oben rechts.

| Gruppe | Seiten |
|---|---|
| Täglich | Dashboard, Mail-Log, Quarantäne, Zurückgehaltene Mail, Mail-Warteschlange |
| Schutz | Spamfilter, Viren, Anhänge & Links, Identitätsbetrug & BEC, Absenderlisten, Blocklisten, Regeln |
| Domains & Routing | Mail-Routing, DKIM, ARC & DMARC, Domain-Einstellungen, Mandanten |
| Ausgehende Mail & Archiv | Schutz vor Datenabfluss, Verschlüsselte PDF-Mail, Disclaimer & Signaturen, Massenversand, Archiv-Weitergabe |
| Benutzer & Zugriff | Benutzer, Gruppen |
| Sicherheit & Datenschutz | Sicherheit, Firewall, Sicherheitsstandards, Datenschutz & Compliance |
| Überwachung & Berichte | Mail-Bericht, Überwachung |
| System | Wartung & Update, Sicherung & Wiederherstellung, Netzwerk, DNS & Zertifikat, Cluster & offline |

Jede Anmeldung sieht nur die Seiten und Karten, die ihre Gruppen erlauben (Kapitel 8). Das (i) neben dem Titel einer Karte und neben
jedem Feld öffnet die Hilfe; die Karten selbst tragen keinen festen Text. Die Oberfläche gibt es auf Englisch und Deutsch
(Umschalter auf der Anmeldeseite, und je Anmeldung unter *Mein Konto › Meine Einstellungen*, mit Zeitzone, Zeilen je Seite und
Standardansicht).

Eine lange Seite liest sich wie ein Menü: Nur ihr erster, wichtigster Abschnitt ist offen, jeder andere nennt unter seinem Titel
die Karten, die er enthält. Ein Klick öffnet ihn; *Alle aufklappen* oben öffnet alle Abschnitte. Ein Abschnitt mit einer Warnung
und der mit der gerade benutzten Karte öffnen sich von selbst, ebenso bei einem Link auf eine Karte. Auf einem breiten Bildschirm
stehen kleine Karten nebeneinander. Die Aktionen einer Karte (etwa Ändern, Sperren oder Entfernen bei
*Benutzer*) sind Knöpfe in dieser Karte; jeder öffnet sein Formular darunter. Wo mehrere Karten dieselbe Einstellung lesen (etwa
*Schutz vor Datenabfluss*), steht sie einmal, die anderen sind Knöpfe darunter. *Live-Log* und *Erweiterte Suche* sitzen in der Suchkarte des *Mail-Logs*.

Alle Funktionen, gruppiert, mit Link zu jeder Referenzseite: [FEATURES.de.md](../FEATURES.de.md).

## Grundsätze

- **Sicher ab Werk.** Nur moderne TLS-Versionen, Zwei-Faktor-Anmeldung, kein offenes Relay, kein offener Resolver, im Zweifel
  geschlossen. Ein Sicherheitsminimum (TLS 1.2 oder neuer, ECDHE, AEAD) lässt sich nicht senken.
- **Ihre Daten bleiben bei Ihnen.** Kein fremder Prüfdienst wird gefragt, außer Sie schalten ihn ein; Quellen außerhalb der EU
  sagen das.
- **Alles im Audit-Log.** Jede Änderung, aus dem Web oder auf der Konsole, steht mit wer, wann und was im Audit-Log.
- **Ressourcenschonend.** Keine zusätzlichen Dienste für Aufgaben, die ein Timer oder der Webprozess erledigen kann.

Weiter: [Voraussetzungen und Installation](02-install.de.md) · Zurück: [Handbuch](README.de.md)
