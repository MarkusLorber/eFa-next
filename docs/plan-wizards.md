# Plan: geführte Assistenten in der Weboberfläche

Stand: Entwurf auf dem Zweig `feature/wizards`. Welche Version die Assistenten bekommt, ist noch offen.

## Ziel

Seiten mit vielen Karten bekommen einen kurzen Assistenten, der die häufigste Einrichtung Schritt für Schritt führt.
Die vollen manuellen Karten bleiben, sie sind nur einen Klick entfernt. So spart die Seite Platz, und niemand verliert
eine Einstellung.

## Rahmen

- Eine Seite mit Assistent zeigt unter dem Seitentitel zuerst den Assistenten. Ein gut sichtbarer Schalter
  "Assistent | Manuell" wechselt zu den vollen Karten und zurück.
- Die Wahl gilt je Login und Seite. Sie liegt auf dem Server in "Meine Einstellungen" des Logins (`my-settings-set
  --manual=<seite>:on|off`), nicht im Browser.
- Der Assistent ruft nur die bestehenden efactl-Befehle mit ihren strengen Prüfungen auf. Er hat keine eigenen Rechte:
  fehlt einem Login der Befehl im Schema, zeigt die Seite keinen Assistenten, nur die manuellen Karten (sofern erlaubt).
- Jeder Schritt hat "Zurück", ist mit den echten Werten der Konfiguration vorbelegt (nie mit einem Standardwert, wenn
  schon etwas eingestellt ist), und jedes Feld hat sein (i) aus `efa_help`. Feste Werte sind Pillen oder Listen.
- Der Entwurf eines Assistenten liegt bis zum Anwenden im Speicher von efa-web, an die Sitzung gebunden, begrenzt in
  Zahl und Zeit (eine Stunde). Passwörter kommen nie in den Entwurf.
- Der letzte Schritt zeigt die Änderungen (vorher, nachher), dann "Anwenden", dann das Ergebnis mit einem Link zur
  manuellen Ansicht.
- Serverseitig gerendert, kein JavaScript-Framework. Nur der Verbindungstest des Archivs fragt sein Ergebnis mit ein
  paar Zeilen JavaScript ab; ohne JavaScript gibt es einen Link "Ergebnis laden".
- Weniger Arbeit pro Seite: im Assistenten liest die Seite nur, was der Assistent braucht. Ziel bleibt unter 100 ms
  Serverzeit.
- Der Haken für den Assistenten sitzt nur im Inhalt unter dem Seitentitel. Kopfzeile, Seitenrahmen und die Makros
  `card()` und `field()` bleiben unverändert. Das Dashboard bekommt keinen Assistenten.

## Assistenten, die gebaut werden

### A) Disclaimer (Seite "Disclaimers")

1. Bestehenden Disclaimer ändern oder einen neuen anlegen.
2. Für wen: alle Domains, ein Mandant oder eine Domain (Auswahl aus den eigenen Domains und Mandanten).
3. Text: Name, Format (HTML oder Text), Textfassung und HTML-Fassung. Vorbelegt aus dem bestehenden Disclaimer
   (gelesen über `disclaimer-export`), sonst ein neutraler Beispieltext.
4. Vorschau (Text und HTML in einem abgeschotteten Rahmen ohne Skripte), Aktiv ja/nein.
5. Zusammenfassung, Anwenden mit `disclaimer-template-set`.

Richtung: ein Disclaimer gilt nur für ausgehende Mail, das zeigt der Assistent als festen Hinweis. Position: der
Disclaimer steht immer am Ende der Mail, so wie der Milter ihn heute einfügt. Eine andere Position wäre eine Änderung
am Milter und gehört nicht in diesen Zweig.

Das öffentliche Paket enthält keinen firmeneigenen Text und keine Firmennamen. Der eigene Text wird auf dem eigenen Host
eingegeben.

### B) Mailarchiv (Seite "Archive handover")

1. Archiv wählen: MailStore, piler oder ein anderes Archiv per SMTP; oder ein bestehendes Ziel ändern.
2. Ziel: Name, Journal-Adresse, Host, Port, was das Archiv bekommt (Kopie oder Journal-Bericht).
3. Welche Mail: eingehend, ausgehend oder beides; alle Domains oder ausgewählte.
4. TLS: standardmäßig "Pflicht, mit geprüftem Zertifikat" (neue Stufe `verify` in `archive-set`). Dazu ein
   Verbindungstest (neuer lesender Befehl `archive-test`: SMTP, STARTTLS, Zertifikat und Hostname geprüft, Zeitlimit
   etwa 1 s je Schritt). Der Test läuft im Hintergrund, nicht in der Anfrage der Seite.
5. Zusammenfassung, Anwenden mit `archive-set`, danach der Stand aus `archive-status`.

### C) Weitere Seiten

Gebaut, weil klein und sicher:

- DKIM-Schlüssel (Seite "DKIM, ARC & DMARC"): Domain, Schlüsseltyp, RSA-Länge; Anwenden mit `dkim-create`; das Ergebnis
  zeigt die DNS-Einträge zum Kopieren.
- Domain mit Zielserver (Seite "Mail routing"): Domain und interner Mailserver; Anwenden mit `transport-set --action=add`.

Nur geplant, nicht in diesem Zweig:

- Let's Encrypt-Zertifikat (Seite "Network & certificate"): braucht DNS- und Port-80-Prüfung vorher, mehrere Befehle.
- Backup-Ziel (Seite "Backup & restore"): Schlüssel zweimal, EU-Bestätigung, Testupload; der Rahmen bekommt dafür das
  Passwortfeld (zweimal, nie im Entwurf).
- Admin-Benutzer mit 2FA (Seite "Users"): Passwort-Bestätigung (reauth), Gruppen und 2FA-Einrichtung durch den Benutzer
  selbst; das sind mehrere Logins, kein einzelner Ablauf.

## Was manuell bleibt

Alles andere auf den Seiten: Gruppen-Disclaimer, ZIP-Import mit Bildern und Anhängen, Wiederherstellen, Entfernen,
Signaturen und Zertifikate der Disclaimer-Seite; Entfernen eines Archivziels; Import, Rotation und Entfernen von
DKIM-Schlüsseln, ARC und DMARC; Entfernen von Domains und alle anderen Karten von "Mail routing".

## Tests

- Einheitstests für den Rahmen (Wechsel Assistent/Manuell bleibt gespeichert, Entwurf an die Sitzung gebunden,
  Rollen) und für jeden Assistenten (richtige efactl-Argumente, Vorbelegung aus der echten Konfiguration).
- `tests/test_ui_texts.py`: jedes Feld der Assistenten hat Hilfe und eine deutsche Übersetzung.
- CI mit `scripts/ci.sh --install`.
