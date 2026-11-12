# Migrationsleitfaden: von eFa 5 zu eFa-next

Dieser Leitfaden führt Schritt für Schritt durch die Umstellung eines eFa-5.0-Hosts auf eFa-next 6.0.0.5.2 an Ort und
Stelle, mit `efa-migrate`. Die Kurzfassung steht in [migration.md](migration.md), die technische Beschreibung in
[migration/README.md](../migration/README.md). English: [migration-guide.md](migration-guide.md).

**Es gibt keinen automatischen Weg zurück.** Der einzige Rückweg ist ein VM-Snapshot (oder ein vollständiges Image), den
Sie unmittelbar vor der Migration anlegen.

## 1. Voraussetzungen

- **eFa 5.0.x** auf **AlmaLinux 9, Rocky Linux 9 oder RHEL 9** (x86-64). Ältere Versionen (eFa 4 und davor) werden nicht unterstützt.
- **CPU mit x86-64-v3** (AVX2) für das spätere Upgrade auf EL10 (eFa-next auf EL9 läuft auch ohne). Prüfen:

  ```bash
  /lib64/ld-linux-x86-64.so.2 --help | grep x86-64-v3
  ```

  Die Zeile muss `(supported, searched)` enthalten.
- **Freier Platz:** unter `/var` mindestens das Doppelte der Datenbankgröße (für das Backup der alten Datenbanken;
  `efa-migrate` prüft das selbst und bricht sonst ab, bevor es etwas ändert), dazu Platz für die neuen Pakete.

  ```bash
  df -h / /var /boot
  du -sh /var/lib/mysql
  ```

- **Snapshot oder Image** der VM, unmittelbar vor dem Start (Schritt 2).
- **Wartungsfenster** von etwa einer Stunde: während des Laufs nimmt der Host keine Mail an, am Ende startet er neu. Mail, die
  in dieser Zeit kommt, stellen die Absender später erneut zu, oder sie geht an einen anderen MX.
- **Zugang als root** an der Konsole oder per SSH.
- **Greylisting und BEC:** beide sind nach der Migration an, wie bei einer Neuinstallation von eFa-next (Greylisting
  5 Minuten, 7 Tage); der Bericht nennt das und wie man sie ausschaltet.
- **DNS und Zertifikate:** Hostname und MX-Einträge bleiben, wie sie sind. Hat eFa 5 alle Namen an einen Forwarder
  geschickt (eine forward-zone "." in unbound), löst eFa-next danach selbst auf, wenn die Root-Server über UDP und TCP
  Port 53 antworten; Forwarder für interne Zonen bleiben (Internes DNS). Sonst bleibt der Forwarder, und der Bericht nennt es. Vorhandene Let's-Encrypt-Zertifikate in
  `/etc/letsencrypt` werden übernommen. Ein gültiges Zertifikat des Hostnamens bekommen nginx und Postfix so, wie es ist:
  gleicher Schlüssel und Schlüsseltyp, keine neue Anfrage, ein veröffentlichter TLSA-Eintrag (DANE) bleibt also richtig,
  und Verlängerungen behalten den Schlüssel. eFa-next trägt die Pfade in die
  eigenen Einstellungen von nginx und Postfix ein; certbot verlängert über den Webserver von eFa-next (webroot), die
  apache-Einstellungen von eFa 5 in der Renewal-Datei entfallen (eine Kopie bleibt als `.efa-takeover.bak`). Ist es abgelaufen oder für einen anderen Host, steht das im Bericht und nichts
  ändert sich: ein neues mit `efactl letsencrypt-set`. Ein früher migrierter Host zeigt einen Hinweis im Dashboard;
  `efactl letsencrypt-takeover` übernimmt das Zertifikat dann. Einen neuen Schlüssel (ECDSA) gibt es nur mit
  `efactl letsencrypt-rollover`, das zuerst den neuen TLSA-Eintrag zum Veröffentlichen zeigt.
- **Testlauf auf einem Klon:** Zuerst ausgehende Mail sperren (Ports 25, 465 und 587), sonst stellt der Klon Mail aus
  seiner Queue an echte Empfänger zu.
- **Mehrere MX-Hosts oder ein Cluster:** einen Host nach dem anderen umstellen. Erst den nächsten, wenn der vorige wieder
  Mail annimmt und zustellt.

## 1a. Eigener Server

eFa-next braucht einen eigenen Server oder eine eigene VM. Laufen auf dem Host neben eFa 5 noch andere Dienste, ziehen Sie diese zuerst um. Darauf laufen nur eFa-next und das Betriebssystem: keine weiteren
Serverdienste, keine weiteren offenen Ports. Monitoring- oder Backup-Agenten des Admins (etwa Wazuh) sind möglich, auf eigenes
Risiko. eFa-next härtet und prüft den Server als Ganzes; der Härtungs-Assistent meldet Dienste und offene Ports, die nicht zu
eFa-next oder zum Betriebssystem gehören. Er stoppt oder entfernt sie nie.

## 2. VM-Snapshot

Im Hypervisor einen Snapshot des Hosts anlegen, zum Beispiel mit dem Namen `vor-efa-next`. Erst weitermachen, wenn er fertig
ist.

## 3. Datenbank prüfen

`efa-migrate` liest die alte Datenbank mit dem root-Passwort aus `/etc/eFa/MySQL-Config`. Der Befehl muss `1` zeigen:

```bash
MYSQL_PWD="$(sed -n 's/^MYSQLROOTPWD://p' /etc/eFa/MySQL-Config)" mysql --user=root -Ne 'select 1'
```

Zeigt er `ERROR 1045 (28000): Access denied`, wurde das Passwort der Datenbank später geändert, ohne die Datei
nachzuziehen. Zwei Wege:

- Das gültige Passwort in die Zeile `MYSQLROOTPWD:` von `/etc/eFa/MySQL-Config` eintragen, oder
- in Schritt 7 zusätzlich `--reset-db-root-password` angeben. `efa-migrate` setzt MariaDB dann auf das Passwort aus
  `MySQL-Config`: über den Socket von root, wenn MariaDB das erlaubt, sonst mit einem kurzen Start ohne Rechtetabellen und
  ohne Netzwerk. Die Startoptionen werden in jedem Fall wieder entfernt, `/root/.my.cnf` wird nachgezogen (die alte Datei
  bleibt daneben). Das Passwort erscheint in keiner Befehlszeile und keinem Log.

Solange die Prüfung scheitert, bricht `efa-migrate` sofort mit einer klaren Meldung ab, auch im Listenlauf.

## 4. Quellstand von eFa-next holen

`efa-migrate` läuft aus dem Quellstand des Releases. Die Pakete lädt es selbst von `https://repo.efa-next.eu/el9/latest`,
nur mit gültiger Signatur des eFa-next-Schlüssels (`1823 D6D3 BB7D 5AEA 286E 836D CFE7 E079 16CC 8046`).

```bash
cd /root
curl -fsSL https://github.com/MarkusLorber/eFa-next/archive/refs/tags/v6.0.0.5.2.tar.gz | tar xz
cd /root/eFa-next-6.0.0.5.2/migration
```

## 5. Probelauf: was übernommen wird

Der Lauf ohne Optionen ändert nichts. Er zeigt als JSON, was übernommen würde:

```bash
./efa-migrate | tee /root/efa-migrate-liste.txt | tail -3
```

Er endet mit `Nothing was changed. Take a VM snapshot, then run again with --execute-i-have-a-snapshot.`
In `/root/efa-migrate-liste.txt` besonders ansehen:

- `"milter_chain"`: die Milter-Kette danach. Die Milter von eFa 5 (MailScanner, opendkim, opendmarc) werden ersetzt, rspamd
  (11332) und die Milter von eFa-next kommen dazu. **Fremde Milter**, die nicht zu eFa 5 gehören, bleiben an ihrer Stelle.
- `"extra_services"`: fremde Dienste, die eFa-next weiter laufen lässt und in seiner Statusanzeige mitprüft.
- `"foreign_blockers"`: Cron-Einträge und firewalld-Regeln anderer Blocker. Ihre Adressen werden in die IP-Blocklisten von
  eFa-next übernommen; die Blocker selbst laufen weiter. Abschalten nur ausdrücklich mit `--disable-foreign-blockers`
  (beim Migrieren oder später mit dem Backup-Ordner der Migration).
- `"senders"`, `"sender_rules"`: Absenderlisten aus MailWatch. Einträge aus `/etc/postfix/sender_access` werden beim
  Ausführen in die Absenderlisten von eFa-next verschoben.
- `"not_migrated"`: was nicht übernommen wird, etwa die Spam-Schwellen von SpamAssassin (rspamd hat eigene), die
  MailWatch-Benutzer (es gibt danach einen Web-Admin), Bayes-Daten und die alte Quarantäne (bleibt im Backup).

## 6. Rechtstexte

```bash
./efa-migrate --legal-digest
```

Zeigt die Rechtstexte von eFa-next (`LICENSE`, `DISCLAIMER.md`, `THIRD-PARTY-NOTICES.md`), ihren Digest und die Befehlszeile
für einen Lauf ohne Rückfrage. Lesen Sie die Texte. Bestätigt wird in Schritt 7, nichts wird für Sie angenommen.

## 7. Migration

Im Wartungsfenster, am besten in `screen` oder `tmux`:

```bash
./efa-migrate --execute-i-have-a-snapshot
```

`efa-migrate` fragt nach den Rechtstexten; `ja` (oder `yes`) eintippen. Wenn Schritt 3 `Access denied` gezeigt hat:

```bash
./efa-migrate --execute-i-have-a-snapshot --reset-db-root-password
```

Für einen Lauf ohne Rückfrage nennen Sie den Digest aus Schritt 6 mit `--accept-legal=` (die vollständige Zeile zeigt
`--legal-digest`).

Ablauf in der Ausgabe: `Backup to /root/efa-migration-<Datum>-<Zeit>`, `Stopping mail intake, waiting for MailScanner`,
`Removing the old stack`, `Installing the new eFa-next`, `Configuring`, `Restoring settings`, die Hinweise und zuletzt
`The system reboots within a minute.`

- **Web-Admin-Passwort:** Es wird einmal angezeigt und steht zusätzlich in `/root/efa-migration-<Datum>-<Zeit>/web-admin-password`
  (nur für root lesbar). Sicher ablegen, dann die Datei löschen:

  ```bash
  rm /root/efa-migration-*/web-admin-password
  ```

- **Abbruch vor "Removing the old stack":** Das alte System bleibt unverändert und nimmt wieder Mail an. Ursache beheben,
  Schritt 7 wiederholen.
- **Abbruch danach:** Die Meldung notieren und fortsetzen mit dem Backup-Ordner, den der Lauf am Anfang genannt hat:

  ```bash
  ls -d /root/efa-migration-*
  ./efa-migrate --resume /root/efa-migration-<Datum>-<Zeit>
  ```

## 8. Prüfen nach dem Neustart

```bash
efactl status | head -20
systemctl --failed --no-legend
ausearch -m avc -ts boot -if /var/log/audit/audit.log | grep -c denied
cat /etc/eFa-Version; rpm -q eFa-next eFa-next-base
postconf -n | grep -c /etc/postfix/sender_access
postconf -h smtpd_milters
postqueue -p | tail -1
less /root/efa-migration-*/report.txt
```

Erwartet:

- `efactl status`: `"status": "ok"`; unter `checks` rspamd (`milter:11332`), Postfix, Redis, ClamAV und, falls vorhanden,
  die übernommenen fremden Milter und Dienste.
- Keine fehlgeschlagenen Units, keine SELinux-Denials (`0`).
- `eFa-6.0.0.5.2`, beide Pakete in Version 6.0.0.5.2.
- `postconf -n | grep -c /etc/postfix/sender_access` zeigt `0`: Postfix liest `sender_access` nicht mehr, die Einträge
  stehen in den Absenderlisten.
- Die Queue wie vor der Migration oder leer.
- `report.txt`: Was übernommen, ersetzt oder nicht übernommen wurde, Zeilen aus `sender_access`, die von Hand nachzutragen
  sind, und eigene MailScanner-Regeln, die nicht übernommen werden.

## 9. Weboberfläche und Mail

- Anmelden wie in [9a](#9a-erste-anmeldung-nach-der-migration) beschrieben und sofort 2FA einrichten.
- Das Dashboard nennt erlaubte Absender aus der Migration, die in eFa 5 an jedem Filter vorbeikamen: prüfen und nur genaue
  Adressen behalten.
- Eine Testmail von außen an eine eigene Adresse und eine von innen nach außen schicken; im Mail-Log von eFa-next nachsehen.
- Weitere Admins, Helpdesk und Mandanten-Admins neu anlegen (die MailWatch-Benutzer werden nicht übernommen), siehe
  [users-and-access.md](users-and-access.md).

## 9a. Erste Anmeldung nach der Migration

1. `https://<Hostname>/login` öffnen, den **Benutzernamen leer lassen** und das Web-Admin-Passwort eingeben (am Ende des Laufs
   einmal angezeigt, außerdem in `web-admin-password` im Backup-Ordner). Das ist der Haupt-Admin von eFa-next.
2. **2FA sofort einrichten:** *Mein Konto* (oben rechts), Abschnitt *Zwei-Faktor-Anmeldung (2FA)*: *2FA: App einrichten*
   (QR-Code mit einer Authenticator-App scannen), danach *2FA: mit dem ersten Code einschalten*. Bis dahin meldet sich der
   Haupt-Admin nur mit dem Passwort an, und das Dashboard warnt. Oder auf der Konsole, als root:

   ```bash
   efactl totp-setup --qr
   efactl totp-confirm --code=123456
   efactl totp-status
   ```

   `totp-setup --qr` zeigt den QR-Code im Terminal; `--code` ist der Code, den die App dann zeigt (hier steht `123456`
   dafür). Das Geheimnis, der QR-Code und die zehn Wiederherstellungscodes, die `totp-confirm` zeigt, sind geheim: nie
   einen Screenshot machen, nie posten oder mailen; die Wiederherstellungscodes offline aufbewahren. Ein neues
   Web-Admin-Passwort auf der Konsole: `efactl admin-password` (zweimal abgefragt); im Webinterface: *Mein Konto*,
   *Mein Konto: Passwort*.
3. **Jeder weitere Admin bekommt einen eigenen Benutzer** mit eigenem Benutzernamen, Passwort und eigener 2FA (*Benutzer*),
   nie die Anmeldung des Haupt-Admins. Die Benutzer von MailWatch werden nicht übernommen.

## 10. Wenn etwas nicht stimmt

- Zurück nur über den Snapshot aus Schritt 2: VM zurücksetzen, der Host ist wieder eFa 5 wie vorher.
- Die alte Konfiguration, die Datenbanken und die alte Quarantäne liegen in `/root/efa-migration-<Datum>-<Zeit>`.

## 11. Mehrere Hosts

Schritte 2 bis 9 für jeden Host einzeln, einen nach dem anderen. Erst wenn ein Host wieder Mail annimmt und zustellt, den
nächsten beginnen.
