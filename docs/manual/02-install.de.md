# 2. Voraussetzungen und Installation

## Voraussetzungen

- **Betriebssystem:** ein frisches, minimales AlmaLinux 9, Rocky Linux 9, CentOS Stream 9 oder RHEL 9 (getestet auf AlmaLinux 9).
  Version 10 von AlmaLinux, Rocky Linux und RHEL wird ebenfalls angenommen; Rocky Linux 10 und RHEL 10 sind noch nicht auf einem
  echten Host getestet (RHEL braucht ein registriertes System). CentOS Stream 10 wird abgelehnt. Das Release-Upgrade 9 → 10 gibt es
  bisher nur für AlmaLinux.
- **VirtualBox und der EL10-Kernel 6.12.0-211.74.x:** unter VirtualBox 7.2 friert dieser Kernel früh beim Start ein, die letzte
  Zeile auf der Konsole ist `evm: HMAC attrs: 0x1`, und der Host bekommt nie ein Netz. Kernel 6.12.0-211.7.3 startet. Im
  GRUB-Menü den älteren Kernel wählen und ihn als Standard behalten, bis ein behobener Kernel kommt:
  `grubby --set-default /boot/vmlinuz-6.12.0-211.7.3.el10_2.x86_64`. Andere Hypervisoren und echte Server sind nach
  bisherigem Stand nicht betroffen.
- **Netz:** eine feste IP-Adresse, ein Hostname im DNS mit passendem PTR-Eintrag, HTTPS-Zugang zu den Paketquellen.
- **Größe** (Lasttest auf 4 CPUs und 7,5 GB RAM: etwa 2.700 Mails je Minute durch alle Filter):

  | Mails je Tag | CPUs | RAM | Platte |
  |---|---|---|---|
  | bis 50.000 | 2 | 4 GB | 40 GB |
  | bis 500.000 | 4 | 8 GB | 80 GB |
  | mehr | 8 oder mehrere Knoten | 16 GB | 160 GB und mehr |

  Spitzen zählen mehr als die Tagessumme. Die Platte hält Mail-Log, Header und Quarantäne (Standard 30 Tage).
- **Ein eigener Server:** ein Server oder eine VM nur für eFa-next. Darauf laufen nur eFa-next und das Betriebssystem: keine
  weiteren Serverdienste, keine weiteren offenen Ports. Monitoring- oder Backup-Agenten (etwa Wazuh) sind auf eigenes Risiko
  möglich. Der Härtungs-Assistent meldet fremde Dienste und offene Ports; er stoppt oder entfernt sie nie.
- Über einen bestehenden eFa-5-Host wird nicht installiert: siehe [Migration von eFa 5](16-migration.de.md).

## Installation mit einem Befehl

Als root auf dem frischen Host den Installer laden und seine SHA256 mit der in den Release Notes vergleichen:

```bash
curl -fsSLO https://repo.efa-next.eu/build.bash && sha256sum build.bash
```

Dann:

```bash
bash build.bash
```

Der Installer stellt die Uhr, prüft DNS, richtet die Paketquellen EPEL, CRB und rspamd mit ihren Schlüsseln ein, aktualisiert das
System und installiert `eFa-next` und `eFa-next-base` aus der signierten Paketquelle von eFa-next. Er läuft als systemd-Unit
`efa-install`: Eine abgerissene SSH-Verbindung stoppt ihn nicht (`journalctl -fu efa-install` verfolgt ihn wieder); jeder Schritt
schreibt nach `/var/log/eFa/eFa-install.log`. Ein zweiter Lauf schadet nicht.

Ein Release wird nur genommen, wenn seine `SHA256SUMS` eine gültige Signatur des Schlüssels der Paketquelle tragen:

```
1823 D6D3 BB7D 5AEA 286E  836D CFE7 E079 16CC 8046
```

Selbst prüfen: `curl -fsSL https://repo.efa-next.eu/RPM-GPG-KEY-efa-next | gpg --show-keys`.

Unbeaufsichtigte Installation, Testinstallationen aus einem Git-Zweig und die Paketquellen-Datei für Updates von Hand:
[install.md](../install.md).

## Der Einrichtungsassistent

`https://<Hostname oder IP>/` im Browser öffnen. Der Host hat zuerst ein selbstsigniertes Platzhalter-Zertifikat, der Browser
warnt einmal. Der Assistent fragt nach dem **Einrichtungscode**, den nur root lesen kann:

```bash
sudo cat /run/efa-init/setup-code
```

Mit jedem Start des Assistenten kommt ein neuer Code (`sudo systemctl restart efa-init`); nach zehn falschen Codes lehnt er alle
ab, bis zu diesem Neustart.

Der Assistent beginnt auf Englisch (der Link oben schaltet auf Deutsch) und geht durch diese Schritte, jeder mit *Zurück*:

1. **Voreinstellungen und Empfehlungen:** ein Hinweis, mit Häkchen zu bestätigen.
2. **Einrichtungsvariante:**
   - *Geführt (empfohlen):* EU-Bezug und die zutreffenden Rahmenwerke (mehrere zugleich) wählen sichere Voreinstellungen
     ([Rahmenwerke](../compliance/frameworks.md)). Zwei-Faktor-Anmeldung ist Pflicht für den Haupt-Admin und den
     Konsolen-Admin, jeder mit eigenem App-Eintrag: Der Assistent zeigt einen QR-Code, prüft den ersten Code und zeigt zehn
     Wiederherstellungscodes einmal (kopieren oder als PDF). *Weiter* erst nach „Ich habe die Codes gesichert".
   - *Manuell:* Sie stellen alles selbst ein; die EU-Frage kommt auch hier.

   In beiden Varianten fragt dieselbe Seite nach den **Sicherheitsstandards**, die dieser Server erfüllen soll (die Liste in
   Kapitel 9). Die Einrichtung setzt den strengsten Wert aller gewählten, nie unter dem Sicherheitsminimum. Port 25 bleibt
   opportunistisch, und das SSH-Profil nach BSI TR-02102-4 setzt die Einrichtung nicht (es braucht eine neue SSH-Anmeldung
   innerhalb von 10 Minuten): später im Härtungs-Assistenten setzen. Ohne Auswahl bleiben die Standardwerte von eFa-next.
3. **Root-Anmeldung über SSH:** aus, nur mit SSH-Schlüssel oder an. Aus oder nur Schlüssel ist empfohlen.
4. **EU-Bezug:** Mit EU-Bezug gelten die EU-Regeln hart. Ohne fragt der Assistent nach einem Häkchen und dem getippten Satz
   `auf eigenes Risiko`. Jede Bestätigung wird mit Zeit und einem Hash des gezeigten Textes aufbewahrt.
5. **Host und Netz:** Hostname und Domain, Adresse für Benachrichtigungen, Schnittstelle, statisches IPv4 oder DHCP, IPv6, DNS
   (eigene Rekursion über die Root-Server, Standard, oder zwei DNS-Server).
6. **Konten:** das **Passwort des Web-Admins** (zweimal, mindestens 12 Zeichen), der **Konsolen-Benutzer** (nicht root) und sein
   Passwort.
7. **Zeit:** Hypervisor-Werkzeuge, Zeitzone, Zeitserver (die Uhr wird sofort gestellt; 2FA-Codes brauchen sie).
8. **Ihr Mailserver:** IP oder Name des Servers, der die Mail Ihrer Domain annimmt.
9. **Zusammenfassung:** alle Antworten nach Gruppen, jede mit *Bearbeiten*, und die Nutzungsbedingungen zum Bestätigen.

Dann richtet sich der Host ein und startet neu. Bekommt er eine neue Adresse, zeigt die Seite sie und öffnet sie, sobald sie
antwortet.

**Re-Setup** stellt dieselben Fragen später für das laufende System: *Sicherheit & Datenschutz › Sicherheit › Einrichtungsvariante*, die
Adresse `/resetup` oder `sudo efactl resetup`. Es zeigt alte und neue Werte, macht eine Sicherung und hebt Einstellungen nur an.
Von manuell zu geführt ist frei; von geführt zu manuell braucht Passwort und 2FA-Code, und 2FA bleibt an.

Weiter: [Erste Anmeldung, 2FA und Mein Konto](03-first-login.de.md) · Zurück: [Handbuch](README.de.md)
