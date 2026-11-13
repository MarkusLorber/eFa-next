# Plan: Härtungs-Assistent und Sicherheitsstandards im Einrichtungsassistenten

Stand: Entwurf auf dem Zweig `feature/hardening-wizard`, aufgebaut auf `feature/wizards` (Rahmen der Assistenten). Welche
Version ihn bekommt, ist noch offen: dieselbe wie `feature/wizards`.

## Ziel

Der Admin legt fest, nach welchen Standards eFa-next den Server härtet: das Betriebssystem und eFa-next selbst. Der
Assistent führt in sechs Schritten durch Auswahl, Vorschau und Anwenden. Der Einrichtungsassistent einer Neuinstallation
fragt dieselben Standards und richtet danach von selbst den jeweils höchsten Schutz aller gewählten Standards ein.

Es gibt kein zweites System: der Assistent nutzt SEC-STD (`standards-status`, `standards-show`, `standards-set`,
`standards-rollback`, `/usr/share/eFa/standards.json`) und den Härtungsbericht (`hardening-report`) als Quelle des Zustands.
Was ein Standard verlangt, steht an genau einer Stelle: `efa_harden.plan_for(selected)`. Der Härtungs-Assistent wählt damit
vor, die Einrichtung wendet es an, Re-Setup hebt damit nur an.

## Grundregeln

- Nur strenger, nie schwächer: was schon stärker eingestellt ist, bleibt. Keine Auswahl entfernt keine Härtung.
- Nie unter der Untergrenze von eFa-next (docs/tls-profiles.md, Sicherheitsminimum).
- Port 25 bleibt opportunistisch (RFC 3207), außer der Admin verlangt TLS dort ausdrücklich. Die Einrichtung schaltet es nie.
- `PermitRootLogin` wird nie angefasst (eigener Schalter auf der Seite Sicherheit). Ein Test beweist es.
- Nur Hinweise, nie automatisch: SELinux erzwingend (Relabel und Neustart), automatische Updates des Betriebssystems
  (Neustarts, Neuladen der Firewall), neue SSH-Hostschlüssel, Schlüssel des Zertifikats und der DKIM-Schlüssel.
- Fremde Dienste und offene Ports werden nur gemeldet, nie gestoppt oder entfernt. Agenten, die eFa-next selbst verwaltet
  (Wazuh nach der Übernahme), zählen als bekannt.
- Keine eigenen Regeln oder Werte, keine neuen Standards, kein systemd-Sandbox für Units der Distribution (nur die eigenen,
  getesteten Units von `service-harden`).
- Alles geht ins Audit-Log, mit einem gemeinsamen Rücksprungpunkt vor dem Anwenden.

## Der Härtungs-Assistent (Seite "Security standards")

Assistent `hardening` in `efa_wizard.WIZARDS` auf der Seite `standards`, nur für Super-Admins wie die Seite heute. Der Schalter
"Assistent | Manuell" bleibt; die manuellen Karten sind einen Klick entfernt. Die Seite "Sicherheit" bekommt einen Link
"Härtungs-Assistent". Das Dashboard bleibt unberührt (gehört `feature/dashboard-banner`); eine Kachel dort ist ein späterer
Schritt.

1. **Standards wählen**: Häkchen über die Ids aus standards.json, gruppiert: TLS und Schlüssel (bsi-02102-1, bsi-02102-2,
   bsi-03116-4, rfc9325, moz-modern nur Web, moz-inter, nist-80052), Mailtransport (bsi-03108), SSH und Betriebssystem
   (bsi-02102-4, cis-el). Je ein Satz und die Version, dazu der Stand der letzten Prüfung aus `standards-show` (keine neue
   Prüfung in der Anfrage). Vorbelegt aus `standards-status`, nie mit einem Standardwert. Hinweis: keine Auswahl entfernt
   keine Härtung.
2. **Port 25**: Pille "opportunistisch lassen (empfohlen, RFC 3207)" oder "TLS verlangen", vorbelegt mit dem wirksamen Wert,
   dazu die Zahl der Sitzungen ohne TLS der letzten 7 Tage.
3. **Betriebssystem**: je Punkt der Stand des Härtungsberichts und eine Pille "härten" oder "so lassen", vorbelegt mit dem
   wirksamen Wert, vorgewählt, wenn ein gewählter Standard es verlangt (`plan_for`). Punkte: SSH-Profil BSI (bestehend,
   10 Minuten Bestätigung), Kernel-Einstellungen (bestehend), keine automatischen Netzprofile (bestehend), Firewall-Wache
   (bestehend), und neu über `os-harden-set`: auditd an, chronyd an, sshd-Optionen nach CIS in einem eigenen Drop-in,
   ENCRYPT_METHOD in login.defs, Rechte von /etc/shadow, Crypto-Policy nicht LEGACY (FUTURE nur ausdrücklich, mit Warnung).
   Darunter die Hinweise (SELinux, OS-Updates, Hostschlüssel) und der lesende Punkt "Fremde Dienste".
4. **eFa-next**: die bestehenden Schalter mit ihrem wirksamen Stand: service-harden, login-lockout-set, audit-mode,
   pwned-check-set, security-oval-set, submission-pam-set aus, tls-min-set, dane-set, autoupdate-set. Die 2FA des
   Konsolen-Admins wird nur auf der Konsole gesetzt: im Assistenten ein Hinweis. web-allowlist-set und firewall-set nur als Link
   mit Warnung (eine falsche Adresse sperrt aus).
5. **Vorschau** aus `standards-preview` (neu, nur lesend): eine Tabelle für alle Änderungen (Einstellung, jetzt, dann, weil),
   die Warnungen, und ein Block "Das ändert der Assistent nicht" aus der letzten Prüfung der gewählten Standards
   (Zertifikatsschlüssel: Seite Netzwerk und Zertifikat; DKIM RSA unter 3000 Bit: DKIM-Assistent mit 3072 oder 4096; DANE
   eingehend, TLS-RPT, MTA-STS: docs/dmarc-dane-mta-sts.md; HSTS; PermitRootLogin: Seite Sicherheit). Häkchen "Warnungen
   gelesen" ist nur Pflicht, wenn es Warnungen gibt.
6. **Anwenden**: Zusammenfassung, Passwort und 2FA-Code einmal (wie die manuelle Karte, dieselbe Prüfung, dasselbe Fenster von
   300 s, bei Fehler REAUTH_FAILED), dann `standards-set --select=... --port25-tls=... --os=... --efa=... --apply=yes
   --confirm=yes`. Es legt einen gemeinsamen Rücksprungpunkt an und schaltet nacheinander; der erste Fehler hält die Kette an,
   die Meldung nennt, was schon geändert ist, und den Weg zurück (`standards-rollback`). Am Ende die neue Prüfung je gewähltem
   Standard und der Link zum Härtungsbericht. Wurde das SSH-Profil geändert: klarer Hinweis, innerhalb von 10 Minuten neu per
   SSH anmelden und bestätigen (`ssh-profile-confirm`), sonst geht es von selbst zurück.

## Erweiterungen des Rahmens (feature/wizards)

- `reauth`: ein Assistent mit `'reauth': True` wird nicht mehr versteckt, obwohl sein Befehl in REAUTH_COMMANDS steht. Der letzte
  Schritt fragt Passwort und 2FA-Code wie die manuelle Karte. Passwort und Code kommen nie in den Entwurf. Allgemein gehalten
  für einen späteren Admin-mit-2FA-Assistenten.
- `checks`: eine Liste mit Häkchen und Gruppen-Überschriften (statt einer Mehrfachauswahl mit Strg).
- `prefill`: ein Assistent kann Werte vorbelegen, die von anderen Feldern abhängen (hier: vorgewählt, was die Standards
  verlangen). Ändert sich die Auswahl der Standards, werden die abhängigen Felder neu vorbelegt.
- `preview`: vor einem Schritt ruft efa-web einmal einen lesenden Befehl auf und hält das Ergebnis im Entwurf; die Seite selbst
  liest dann nur `standards-status` und `standards-show` (Ziel unter 100 ms).

## Neue efactl-Befehle

- `standards-preview --select --port25-tls --os --efa`: nur lesend (writes False, dieselben Rechte wie `standards-status`). Gibt
  die Vorschau von `standards_plan` und der OS- und eFa-next-Punkte zurück, genau wie `standards-set` ohne `--apply`. Ein Test
  zeigt: keine Datei wird geschrieben (auch nicht /etc/eFa/standards.json, Rücksprungpunkt, Prüfergebnis), nginx, sshd und
  Postfix werden weder neu geladen noch neu gestartet.
- `os-harden-status`: nur lesend, Stand jedes OS-Punkts, die Hinweise und die fremden Dienste.
- `os-harden-set --item=<feste Liste> --mode=on|off`: strenge Liste, Vorschau, Rücksprung (off stellt den gemerkten Stand
  wieder her), Audit, nur Super-Admin und mit Passwort. sshd-Optionen in `/etc/ssh/sshd_config.d/30-efa-cis.conf`, vor dem
  Neuladen `sshd -t`, bei Fehler zurück.
- `standards-set` bekommt `--os` und `--efa` (Listen der Punkte); ohne sie verhält es sich wie bisher.
  `standards-rollback` stellt auch diese Punkte zurück.
- `setup-variant-apply` und `resetup` bekommen `--standards`.

## Einrichtungsassistent (efa-init.py)

Der bestehende Schritt "Regelwerke" wird erweitert, kein zweiter, paralleler Schritt: unter den Regelwerken die
Sicherheitsstandards aus standards.json, mit denselben Texten wie der Härtungs-Assistent. Die Seite gibt es jetzt in beiden
Varianten; manuell zeigt sie nur die Standards (keine Regelwerke, keine Vorschläge), denn die Standards sind eine ausdrückliche
Wahl des Admins, kein Vorschlag. Regelwerke ohne konkrete
Einstellungen bleiben Information. Wo die Zuordnung dokumentiert ist (BSI IT-Grundschutz und BSI TR-02102 auf die
TR-02102-Teile), nennt der Schritt die Standards, zu denen ein Regelwerk führt, und wählt sie vor; sonst keine.

Nach der Einrichtung wendet efactl `standards-set` mit `plan_for(selected)` an: TLS, DANE, Kernel, die OS-Punkte und die
eFa-next-Schalter, die ein gewählter Standard verlangt, der strengste Wert aller gewählten. Ausnahmen: Port 25 bleibt
opportunistisch; das SSH-Profil BSI wird in der Einrichtung nicht gesetzt (gewählt ist der sicherere Weg): die Bestätigung
innerhalb von 10 Minuten braucht eine neue SSH-Anmeldung, die im Web-Installer niemand macht, das Profil ginge sonst
unbemerkt zurück. Die Abschlussseite sagt das und verweist auf den Härtungs-Assistenten. Vor dem Abschluss zeigt die
Prüfseite je Standard, was gesetzt wird. Keine Auswahl: die Standardwerte von eFa-next bleiben. Re-Setup nutzt denselben Weg
und hebt nur an. Der Härtungs-Assistent zeigt später dieselbe Auswahl vorbelegt.

## Tests

- efa_harden: `plan_for` für Überschneidungen (moz-modern und BSI: BSI-Profil und Web nur TLS 1.3), nur bekannte Ids.
- efa_wizard: Vorbelegung, nur bekannte Ids, Pille Port 25, genaue efactl-Argumente für `standards-set` und
  `standards-preview`, Häkchen nur bei Warnungen, kein Passwort im Entwurf.
- efactl: `standards-preview` gleich der Vorschau von `standards-set`, writes False, Nur-Lesen-Beweis; `os-harden-set` je Punkt
  an, aus, Rücksprung; PermitRootLogin unverändert.
- efa-web: nur Super-Admin sieht ihn, ohne Passwort und 2FA wird nichts angewendet, falsches Passwort gibt REAUTH_FAILED und
  ändert nichts, der manuelle Schalter bleibt.
- efa-init: Auswahl bsi-02102-2, rfc9325 und cis-el geht als STANDARDS an efa-apply.
- tests/test_ui_texts.py und die Übersetzung; CI mit `scripts/ci.sh --install`, die Stufe der Neuinstallation wählt Standards
  (ohne SSH-Profil) und prüft mit openssl s_client und der Standardprüfung.

## Später

- Kachel "Härtungs-Assistent" auf dem Dashboard (nach `feature/dashboard-banner`).
- Admin-Benutzer mit 2FA als Assistent auf dem Rahmen `reauth`.
