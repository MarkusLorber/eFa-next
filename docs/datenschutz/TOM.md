# Technische und organisatorische Maßnahmen: E-Mail-Filter eFa-next

**Vorlage: an die eigene Organisation anpassen.** Beschrieben ist, was eFa-next technisch mitbringt. Organisatorische
Maßnahmen (Schulung, Zutritt zum Rechenzentrum, Vertretungen) ergänzt der Betreiber: `[…]`.

Den aktuellen Stand eines Systems zeigen `efactl hardening-report` (CIS AlmaLinux 9, BSI TR-03108) und der Sicherheits-Check.

## 1. Vertraulichkeit

**Zutrittskontrolle**: [Rechenzentrum/Serverraum, Zugang, Protokollierung]

**Zugangskontrolle**
- Weboberfläche nur über HTTPS (TLS 1.2 oder neuer), Anmeldung mit Passwort (Mindestlänge, Prüfung gegen eine Liste schwacher
  Passwörter), optional über LDAP/Active Directory oder OpenID Connect, Sitzungen laufen ab
- Fail2Ban sperrt IP-Adressen nach wiederholten Fehlversuchen bei SSH und SMTP-AUTH; die Weboberfläche sperrt nach mehreren
  Fehlanmeldungen für 5 Minuten
- Firewall mit Freigabeliste für SSH und Weboberfläche, Firewall-Wächter stellt fehlende Regeln wieder her
- SSH: Root-Anmeldung abschaltbar (Schalter in der Weboberfläche), Schlüssel empfohlen
- SMTP-AUTH nur über TLS; Neuinstallation: nur Logins der Einlieferer, keine Systemkonten

**Zugriffskontrolle**
- Rollen und Gruppen mit einzelnen Rechten (z. B. Mail-Inhalt ansehen, Quarantäne freigeben), Mandanten- und Domain-Grenzen
- Nutzer sehen nur ihre eigene Quarantäne
- Optional strenger Audit-Modus: Begründungspflicht beim Ansehen von Mail-Inhalt, manipulationsgeschütztes Audit-Log
- Dienste laufen mit eigenen Benutzern und systemd-Härtung (ProtectSystem, NoNewPrivileges), SELinux erzwingt die Regeln
- Geheimnisse (Passwörter von Zielen, Schlüssel) nur für root lesbar, nie im Log

**Trennungskontrolle**
- Mandanten mit eigenen Domains, Einstellungen, Admins und Identitätsanbietern
- Einlieferer dürfen nur für ihre eigenen Domains senden, kein Querversand zwischen Mandanten (in Postfix erzwungen)

**Verschlüsselung / Pseudonymisierung**
- Transport: STARTTLS ein- und ausgehend, DANE und MTA-STS möglich, TLS-Berichte (TLS-RPT)
- Sicherungen verschlüsselt (AES-256, GnuPG), nur verschlüsselte Sicherungen verlassen das System
- optional: Mail und Anhänge als AES-256-verschlüsseltes PDF (Stichwort im Betreff oder DLP-Regel)
- Passwörter der Weboberfläche nur als Hash (PBKDF2-SHA256), Logins der Einlieferer als SHA512-CRYPT

## 2. Integrität

**Weitergabekontrolle**
- DKIM-Signatur und ARC für ausgehende Mail, Prüfung von SPF/DKIM/DMARC eingehend
- Schutz vor Datenabfluss (DLP) für ausgehende Mail: Kartennummern, IBANs, Steuer-/SV-Nummern, eigene Regeln
- Weitergabe an externe Ziele (SIEM, Archiv, Sicherungen) nur nach ausdrücklicher Einrichtung, Standard aus

**Eingabekontrolle**
- Audit-Log jeder Änderung über efactl und Weboberfläche: wer, wann, von welcher IP, was (400 Tage)
- Mail-Log mit Prüfergebnis jeder Mail (Standard 30 Tage)

## 3. Verfügbarkeit und Belastbarkeit

- tägliche verschlüsselte Sicherung, optional extern (S3/SFTP) mit Prüfsumme und Alarm bei Fehlern
- Mails werden bei Ausfall eines Filters nicht verloren: Postfix hält sie in der Warteschlange, Zwischenspeicherung (Spooling) bis 5 Tage
- Überwachung der Dienste (Health-Dienst), Alarme per Mail und Ereignis (SIEM/OTLP/Wazuh)
- Sicherheits-Updates des Betriebssystems automatisch, eFa-Updates mit Prüfung und Rückweg
- Ausfall des DLP-Filters: ausgehende Mail wartet, statt ungeprüft hinauszugehen

## 4. Verfahren zur regelmäßigen Überprüfung

- täglicher Sicherheits-Check mit Befunden und Abhilfe, Härtungsbericht je Release
- Fuzzing der Parser und Tests in jeder Release-Prüfung
- [Prüfung durch den Betreiber: Intervall, Verantwortliche]

## 5. Datenschutzfreundliche Voreinstellungen (Art. 25 DSGVO)

- neue Funktionen sind nach einem Upgrade aus
- Löschfristen ab Werk: Mail-Log 30 Tage, Kopfzeilen 30 Tage, Quarantäne 30 Tage, CDR-Originale 30 Tage, Phishing-Inhalte 30 Tage,
  Audit-Log 400 Tage (siehe VVT)
- Betreff-Anzeige im Mail-Log abschaltbar, Mail-Inhalt nur mit eigenem Recht sichtbar
- keine Telemetrie
