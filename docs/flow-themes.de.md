# Bild des Mailflusses: Themes

Das Dashboard zeigt, wie eFa-next eine Mail behandelt (6.0.0.7): eingehende Mail auf Port 25 durch Postscreen, die
SMTP-Regeln, die Spam- und Virenprüfung (rspamd mit ClamAV), die Entschärfung und die Zustellung, mit den Abzweigen
*abgelehnt*, *Benutzer-Quarantäne* und *Admin-Halt*; ausgehende Mail von Anmeldungen und Relay-Netzen durch die
Ausgangsprüfung und rspamd mit der DKIM-Signatur. Eine ausgeschaltete Stufe hat einen gestrichelten Rand. Die Zahlen sind die
von heute (Mail-Log) und der Queues; ein Klick öffnet das Mail-Log mit dem passenden Filter, der Admin-Halt öffnet die Queue.
Auf dem Telefon steht das Bild hochkant.

Die Stufen sind Daten in `/usr/lib/eFa/python/efa_flow.py` (`STAGES`, `BRANCHES`); das Layout wird daraus berechnet.

## Ein Theme hinzufügen

Ein Theme ist ein Ordner mit Symbolen, sonst nichts: kein Code ändert sich.

1. Ordner `/usr/share/eFa/flow/<name>` anlegen (`<name>`: Kleinbuchstaben, Ziffern, `-` und `_`, bis 32 Zeichen).
2. Je Symbol eine SVG-Datei hinein, benannt nach dem Symbol: `cdr.svg`, `deliver.svg`, `hold.svg`, `internet.svg`,
   `outbound.svg`, `postscreen.svg`, `rejected.svg`, `rspamd.svg`, `sign.svg`, `smtp.svg`, `uq.svg`, `users.svg`. Als Start
   `/usr/share/eFa/flow/default` kopieren. Ein Ordner, dem eines fehlt, wird nicht angeboten.
3. Auswählen: *Dashboard › Bild des Mailflusses* (Expertenansicht) oder `efactl flow-set --theme <name>`.

Die Symbole werden als Bilder dieses Servers mit einer Richtlinie gezeigt, die kein Skript erlaubt; bitte einfaches SVG
(Pfade und Formen, kein Skript, keine externen Verweise), höchstens 64 KB je Datei. Ein Update von eFa-next lässt eigene Ordner
stehen; der Ordner `default` gehört zum Paket.
