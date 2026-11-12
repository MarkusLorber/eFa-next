# 12. Aufbewahrung und Datenschutz

## Wie lange Daten bleiben

*Mail & Quarantäne › Mail-Log › Speicherung & Datenschutz* zeigt für jede Datenart, wie lange sie bleibt und wo das eingestellt
wird.

| Daten | Eingestellt mit |
|---|---|
| Mail-Log und Nachrichtensuche | `maillog-retention-set`, eine Größengrenze mit `maillog-size-set` |
| Header aller Mails | `headers-store-set`, je Mandant und Domain unter *Domain-Einstellungen* |
| Quarantäne und zurückgehaltene Mail | *Quarantäne › Einstellungen*, *Zurückgehaltene Mail › Einstellungen*, je Mandant und Domain unter *Domain-Einstellungen* |
| Audit-Log, DMARC- und TLS-Berichte, Originale entschärfter Anhänge, gemeldete Phishing-Mails | `retention-set` |

**Je Mandant:** Ein Mandant kann Mail-Log, Berichte, Audit-Log, die zurückgehaltene Mail der Admins, die Originale entschärfter
Anhänge, gemeldete Phishing-Mails und die gesehenen DKIM-Selektoren kürzer oder länger als die globalen Tage aufbewahren.
Mandanten-Admins dürfen nur kürzere Tage setzen; längere braucht einen Super-Admin. `--days inherit` nimmt wieder die globalen
Tage.

```bash
sudo efactl retention-set --data maillog --days 30 --tenant kunde1
sudo efactl retention-set --data audit --days inherit --tenant kunde1
```

Eine Mail mehrerer Mandanten geht, wenn die längste ihrer Fristen endet. Die nächtlichen Jobs löschen, was älter ist, und
schreiben die Menge ins Audit-Log. Ein Upgrade ändert keine Tage.

## Datenschutz-Einstellungen

Auf derselben Karte:

- **Pseudonyme:** Adressen im Mail-Log werden nach einigen Tagen zu Pseudonymen (`pseudonymise-set`).
- **Ein Grund für Inhalte:** Vor dem Öffnen des Inhalts einer Mail kann ein getippter Grund verlangt werden, der im Audit-Log steht
  (`content-reason-set`).
- **Betreffanzeige:** ob das Mail-Log Betreffzeilen zeigt (`subject-display-set`).

Details: [privacy-and-reason.md](../privacy-and-reason.md), [header-privacy.md](../header-privacy.md).

## DSGVO-Anfragen

*Mail-Log › Daten einer Person (DSGVO)*:

- **Auskunft (Art. 15):** alles, was eFa-next zu einer Mailadresse hält.
- **Löschung (Art. 17):** löscht die Daten einer Adresse endgültig; braucht einen Grund (etwa Datum und Nummer der Anfrage) und ein
  getipptes yes. Die Löschung selbst steht im Audit-Log.

```bash
sudo efactl gdpr-export --address person@example.com
sudo efactl gdpr-delete --address person@example.com --reason "Anfrage 2026-11-01 Nr. 12" --confirm yes
```

Vorlagen für Verarbeitungsverzeichnis, TOMs und Auftragsverarbeitungsvertrag: [datenschutz/](../datenschutz/README.md).
Mehr: [gdpr-requests.md](../gdpr-requests.md).

Weiter: [Sicherung und Wiederherstellung](13-backup.de.md) · Zurück: [Handbuch](README.de.md)
