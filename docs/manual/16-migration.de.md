# 16. Migration von eFa 5

`efa-migrate` macht aus einem eFa-5.0-Host an Ort und Stelle eFa-next: MailScanner, MailWatch, SpamAssassin, opendkim,
opendmarc, sqlgrey und amavis werden durch rspamd, nginx und die Weboberfläche von eFa-next ersetzt. Der erste Lauf ohne Optionen
listet nur, was übernommen würde.

**Es gibt keinen automatischen Weg zurück. Zuerst einen VM-Snapshot machen.**

Der Leitfaden, Schritt für Schritt mit den Prüfungen davor und danach:

- [Migrationsleitfaden (Deutsch)](../migration-guide.de.md)
- [Migration guide (English)](../migration-guide.md)
- Referenz von `efa-migrate`: [migration.md](../migration.md)

Nach der Migration:

- Der Haupt-Admin meldet sich unter `https://<Hostname>/login` mit leerem Benutzernamen und dem neuen Passwort an, das
  `efa-migrate` am Ende einmal zeigt (auch in der Datei `web-admin-password` seines Sicherungsordners, nur für root: aufbewahren,
  dann die Datei löschen).
- MailWatch-Benutzer werden nicht übernommen: unter *Benutzer & Zugriff › Benutzer* neu anlegen (Kapitel 8).
- Systemkonten und SSH bleiben, wie sie auf dem eFa-5-Host waren.
- Greylisting und BEC werden eingeschaltet; Erlaubt- und Sperrlisten der Absender aus eFa 5 wandern in die Absenderlisten.
- *Re-Setup* (Kapitel 2) wird im Dashboard einmal angeboten: Es fragt EU-Bezug, Rahmenwerke und 2FA für das laufende System ab.

Details: [upgrade.md](../upgrade.md#after-a-migration-from-efa-5).

Weiter: [efactl-Referenz](17-efactl.de.md) · Zurück: [Handbuch](README.de.md)
