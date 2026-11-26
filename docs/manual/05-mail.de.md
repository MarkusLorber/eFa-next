# 5. Mail, Quarantäne und Logs

Die Menügruppe *Mail & Quarantäne*.

## Mail-Routing

*Domains & Routing › Mail-Routing* legt fest, für welche Domains eFa-next Mail annimmt und wohin es sie zustellt.

![Mail-Routing](../images/manual/flow.png)

| Karte | Was eingestellt wird | Konsole |
|---|---|---|
| Domains & Ziele | eine Zeile je Domain mit dem Mailserver, der sie annimmt (`host` oder `host:port`) | `efactl transport-set --domain example.com --action add --destination mail.example.com` |
| Relay-Netze & Smarthost | die Netze Ihrer eigenen Mailserver, die über eFa-next hinaus senden dürfen (*Netze hinzufügen*, dann *Anwenden*), ein Smarthost | `relay-networks-add`, `relay-networks-apply`, `smarthost-set` |
| Einlieferer | Anmeldungen, die über Port 587 senden, Sendelimits, übernommene Konten | `submitter-set`, `outbound-limits-set`, `hijack-list` |
| Header-Datenschutz | für welche Absenderdomains oder Einlieferer interne Header aus ausgehender Mail entfernt werden | `header-privacy-set` |
| Limits & Empfängerprüfung | größte Mail; jeden Empfänger vor der Annahme bei Ihrem Mailserver prüfen | `message-size-set`, `recipient-verification-set` |
| TLS mit Partnern | TLS (wahlweise mit geprüftem Zertifikat) zu genannten Partnerdomains verlangen | `tls-partner-set` |

Anleitungen je Mailplattform: [Microsoft 365](../guide-microsoft-365.md), [Google Workspace](../guide-google-workspace.md),
[Exchange Server](../guide-exchange.md).

## Zurückgehaltene Mail

*Täglich › Zurückgehaltene Mail* ist Mail, die eFa-next für ihre Empfänger aufbewahrt, statt sie abzuweisen. Sie ist
aus, bis sie unter *Einstellungen* am Ende der Seite eingeschaltet wird (`efactl uq-set`): ab welcher Punktzahl Mail behalten
wird, wie viele Tage, ob jeder Empfänger täglich eine Übersicht mit Links bekommt und ob Benutzer allein freigeben dürfen.

![Zurückgehaltene Mail](../images/manual/held.png)

- *Freigeben* stellt eine Mail zu, *Admin fragen*, wenn der Benutzer nicht allein freigeben darf, *Absender erlauben* /
  *Absender sperren* machen eine Regel für diesen einen Empfänger.
- *Text* zeigt die Mail als reinen Text: Links sind nicht klickbar, nichts wird nachgeladen; Anhänge werden nur aufgelistet.
- Ein Virus kommt nur durch einen Super-Admin hinaus.
- *Spam-Meldungen*: Mails, die Benutzer als Spam oder erwünscht gemeldet haben, warten hier auf die Entscheidung eines Admins,
  bevor rspamd daraus lernt.

Benutzer sehen ihre eigene zurückgehaltene Mail im **Benutzerportal** (`/portal/login`), mit denselben Knöpfen, eigenen Erlaubt-
und Sperrlisten, Newslettern und eigener Spamgrenze, wo der Admin es erlaubt, *Meine Mail zurückholen* und *Notfallzugriff auf
meine Mail*. Zurückgehaltene Mail kann je Mandant verschlüsselt gespeichert werden (`efactl uq-encrypt-set --mode on`). Details:
[mail-and-quarantine.md](../mail-and-quarantine.md).

## Quarantäne

*Täglich › Quarantäne* enthält Spam und Viren, die in der Mail-Warteschlange zurückgehalten werden. *Zustellen* und
*Header* erscheinen in der Zeile unter der Maus; alle Aktionen stehen im Menü „…" der Zeile. Mehrere Zeilen ankreuzen, um sie auf
einmal zuzustellen, zu löschen oder ihre Absender zu sperren; jede Sammelaktion fragt vorher.

![Quarantäne](../images/manual/quar.png)

<img src="../images/manual/phone-quar-dark.png" alt="Quarantäne auf dem Telefon, dunkles Farbschema" width="300">

*Einstellungen* legt fest, was in die Quarantäne geht und wie viele Tage es bleibt (`quarantine-set`, `quarantine-days-set`);
*Notfallzugriff* lässt Benutzer und Admins eingehende Mail lesen, während Ihr Mailserver nicht läuft: jede Mail wird
gezeigt, ihre Anhänge werden einzeln gespeichert; ein ganzes Postfach geht als ZIP oder mbox hinaus (*Postfach exportieren*, einmal
innerhalb von 15 Minuten abzuholen). Die Kopien und ihre Betreffzeilen sind versiegelt; Absender, Empfänger, Größe und Zeit
stehen im Klartext in der Datenbank.

## Mail-Warteschlange

*Täglich › Mail-Warteschlange* listet die Mail, die Postfix noch nicht zugestellt hat: eine oder alle anhalten,
freigeben, neu einreihen oder löschen (`efactl queue-action`), oder *alle jetzt versuchen* (`queue-flush`). Der Zwischenspeicher
legt fest, wie lange Mail auf einen ausgefallenen Server wartet (etwa `5d`), *Alarm*, ab wie vielen wartenden Mails oder Stunden
der Admin benachrichtigt wird (`queue-alarm-set`).

![Mail-Warteschlange](../images/manual/queue.png)

## Mail-Log

*Täglich › Mail-Log* zeigt *Mail-Log: suchen* mit *Mail prüfen* daneben, darunter die Schaltfläche *Erweiterte Suche*.
Die schnelle Suche nimmt einen Suchbegriff; ihr Feld nimmt auch Filter:

| Filter | Findet |
|---|---|
| `from:a@example.com` | Mail von diesem Absender |
| `domain:example.com` | Mail mit dieser Domain als Absender oder Empfänger |
| `ip:192.0.2.1` | Mail von diesem sendenden Server |
| `result:reject` | Mail mit diesem Ergebnis (`no_action` für keine Aktion) |

![Mail-Log](../images/manual/log.de.png)

Die Tabelle zeigt die Zeit als Alter (genaue Zeit beim Darüberfahren), das Ergebnis sowie SPF, DKIM und DMARC als Abzeichen und
die Queue-ID. Ein Klick auf eine Zeile öffnet die Details seitlich: Überblick, der Weg über die Server mit der Zeit je Station,
die Ergebnisse der Prüfungen, die DNS-Belege und die rohen Header. Mit dem Recht *export*: Header als `.txt` oder Belege als JSON.

Die Suche steht in der Adresse der Seite nach `#` (Lesezeichen, Links für Kollegen); dieser Teil erreicht nie den Server.

*Mail prüfen* nimmt eine gespeicherte Mail (`.eml`, bis 10 MB) und zeigt das Urteil von rspamd; nichts wird aufbewahrt oder
gelernt.

### Erweiterte Suche

*Erweiterte Suche* öffnet die Mailsuche in einem eigenen Fenster (ohne Skript in einem neuen Tab). Sie hat alle Filter: Absender,
Empfänger, Wörter im Betreff, IP-Adresse, Queue-ID, Ergebnis, Datum von und bis, Message-ID und die Headerfelder From, Reply-To,
Return-Path und X-Mailer sowie die Anzahl der Ergebnisse. Die gefundenen Mails stehen direkt unter den Filtern, die neueste zuerst.
*CSV-Datei* und *JSON-Datei* laden das Ergebnis herunter (Recht *export*). Die Filter werden gesendet, nie Teil der Adresse, so
landet keine Adresse und kein Betreff im Log des Webservers.

*Mails, auf die zutrifft* (6.0.0.6.4) verknüpft die Filter: *alle Filter (UND)* wie bisher oder *mindestens ein Filter (ODER)*,
etwa ein Absender oder eine IP-Adresse. Der Zeitraum und die Domains eines Mandanten-Admins gelten immer zusätzlich, egal was
gewählt ist. *Gespeicherte Suchen* behalten die Filter (nie Ergebnisse) unter einem Namen, nur für die eigene Anmeldung, höchstens 20:
*Diese Filter speichern als* speichert das Formular, *Suche laden* füllt es wieder und sucht, *Löschen* entfernt eine. Auf der Konsole:
`efactl search-save --name <Name> --sender '*@example.net' --match any`, `efactl search-saved`, `efactl search-delete --name <Name>`.

Der Schalter *Live-Filter* fügt neue Mail, die zu den Filtern passt, alle 5 Sekunden oben an. Er fragt nur, solange er an und das
Fenster sichtbar ist, und nur nach den Mails nach der neuesten gezeigten. Ein Mandanten-Admin sieht wie bei jeder Suche nur die
Mail der eigenen Domains.

![Erweiterte Suche mit Live-Filter](../images/manual/advanced-search.de.png)

*Header exportieren*, *Daten einer Person (DSGVO)* und *Speicherung & Datenschutz* sind auf der Seite *Datenschutz & Compliance*
(Kapitel 12).

### Live-Log

*Live-Log* auf der Seite des Mail-Logs zeigt neue Mail, sobald sie kommt, mit Filtern, alle 5 Sekunden erneuert, solange es offen
ist.

![Live-Log](../images/manual/live-log.png)

### Absendermenü: erlauben, sperren, suchen

Im Mail-Log, im Live-Log und in der Quarantäne öffnet ein Klick auf Absender, Domain oder IP ein kleines Menü:

- **Erlauben** setzt den Eintrag auf die Erlaubt-Liste, **Sperren** auf die Sperrliste (eine IP kommt in die eigene
  IP-Sperrliste). Es entsteht keine neue Liste; die Einträge stehen wie bisher unter *Absenderlisten* und *IP-Sperrlisten*.
- Ein Dialog zeigt zuerst den genauen Eintrag und die Liste und warnt bei einem Widerspruch zur anderen Liste, bei einer eigenen
  Domain und bei privaten, Relay-, Cluster- oder eigenen Adressen. Adressen, die nie gesperrt werden dürfen, werden abgelehnt.
- Super-Admins schreiben globale Einträge und IPs; Mandanten- und Domain-Admins bekommen eine Regel für ihre eigene
  Empfängerdomain.
- Danach folgt eine Meldung mit **Rückgängig**; jede Aktion steht mit der Queue-ID der Mail im Audit-Log.
- **Alle Mails suchen** öffnet das Mail-Log mit ausgefülltem Filter.

![Absendermenü im Live-Log](../images/manual/sender-menu.png)

Konsole: `efactl sender-action-check` zeigt, was geschähe, `efactl sender-action` tut es.

Weiter: [Spamschutz](06-spam.de.md) · Zurück: [Handbuch](README.de.md)
