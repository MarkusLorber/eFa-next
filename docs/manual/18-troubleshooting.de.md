# 18. Fehlersuche

## Wo nachsehen

| Was | Wo |
|---|---|
| Zustand der Dienste und was Aufmerksamkeit braucht | das Dashboard (Kapitel 4), `sudo efactl status` |
| Eine Mail | *Mail-Log*, ihre Details seitlich (Kapitel 5) |
| Wartende Mail | *Mail-Warteschlange*, oder `mailq` auf der Konsole |
| Wer was geändert hat | *Benutzer › Audit-Log*, `/var/log/eFa/` |
| Postfix | `/var/log/maillog` |
| Dienste | `journalctl -u postfix -u rspamd -u clamd@scan -u efa-web -u unbound` |
| Installation | `/var/log/eFa/eFa-install.log`, `journalctl -u efa-install` |
| Release-Upgrade | `/var/log/eFa/release-upgrade.log`, `efactl release-upgrade-status` |

## Häufige Probleme

**Mail kommt nicht an.** Im Mail-Log suchen. Steht sie dort, mit welchem Ergebnis? Ihre Details zeigen die Prüfungen. Gar nicht da:
Der sendende Server hat eFa-next nicht erreicht; MX-Eintrag der Domain prüfen und den Firewall-Test laufen lassen
(*Sicherheit › Firewall-Test*).

**Mail wartet in der Warteschlange.** *Connection refused* oder eine Zeitüberschreitung zu Ihrem Mailserver: Ziel unter
*Mail-Routing* und das DNS seines Namens prüfen (interne Zonen, Kapitel 10).

**Eine gute Mail wurde abgewiesen oder zurückgehalten.** Aus *Zurückgehaltene Mail* oder *Quarantäne* freigeben. Für die Zukunft
den Absender erlauben (Absendermenü oder *Absenderlisten*) oder eine *Regel* für diesen Empfänger setzen.

**Viele Mails bekommen keine Aktion.** Ist Greylisting aus und seine Schwelle unter der Spam-Markierung, bekommt Mail dazwischen
keine Aktion; das Dashboard nennt diese Lücke (Kapitel 6).

**Die Blocklisten antworten nicht oder lehnen ab.** Die Seite Blocklisten nennt den Grund von Spamhaus (offener Resolver, zu viele
Anfragen). Das eigene Unbound ohne Weiterleitung behalten oder einen Spamhaus-DQS-Schlüssel setzen.

**Die Seite sagt „Nicht erlaubt".** Ihre Gruppen haben dieses Recht nicht. *Benutzer › Benutzer: wirksame Rechte* zeigt, was eine
Anmeldung hat und wo.

**Eine Einstellung wirkt bei einer Domain nicht.** *Domain-Einstellungen › mit Herkunft zeigen*: Ein Wert der Domain oder ihres
Mandanten kann vor dem globalen gelten.

**Ein rotes Banner oben.** Die Angriffswarnung nennt, was sie gefunden hat, und verlinkt die Seite, die hilft (Kapitel 4).

## Ausgesperrt

| Lage | Weg zurück |
|---|---|
| Eine unbestätigte Änderung an Firewall oder Schnittstelle | 5 Minuten warten, oder `sudo efactl firewall-revert` / `interface-revert` |
| Web-Admin-Passwort vergessen | `sudo efactl admin-password` auf der Konsole |
| 2FA-Gerät verloren | ein Wiederherstellungscode, oder die Rücksetzungen in Kapitel 3 |
| Adresse nach Fehlanmeldungen gesperrt | das Ende der Sperre abwarten; im Cluster `efactl cluster-unban --address <IP>` |
| Einrichtungscode verloren | `sudo systemctl restart efa-init`, dann `sudo cat /run/efa-init/setup-code` |

## Hilfe holen

- Fragen und Probleme: [SUPPORT.md](../../SUPPORT.md).
- Ein Sicherheitsproblem: nie als öffentliches Issue, siehe [SECURITY.md](../../SECURITY.md).
- Mehr Antworten: [FAQ](../faq.md).

Zurück: [Handbuch](README.de.md)
