# Kompensierende Maßnahmen

Keine rechtlich verbindliche Aussage; siehe [DISCLAIMER.md](../../DISCLAIMER.md). Diese Seite beschreibt, wo eFa-next das Ziel
einer Anforderung auf anderem Weg als ihrem Wortlaut erreicht, und warum. Die Compliance-Datei führt das als *teilweise* mit
der Grenze „compensating control documented“ und den Nachweisen unten; ob eine kompensierende Maßnahme anerkannt wird,
entscheidet der Prüfer des Betreibers.

## Sperre nach Fehlanmeldungen (PCI DSS 8.3.4, NIST SP 800-53 AC-7)

**Wortlaut:** das Benutzerkonto nach höchstens 10 Fehlversuchen sperren (PCI DSS: mindestens 30 Minuten oder bis ein Admin es
entsperrt).

**Warum eFa-next keine Konten sperrt:** eine Sperre pro Konto erlaubt jedem, der einen Anmeldenamen kennt, diese Person
auszusperren, auch den Haupt-Admin, durch absichtlich falsche Versuche. Auf einem aus dem Internet erreichbaren Mail-Gateway
wird der Schutz so zum Angriff auf die Administratoren (Designentscheidung des Projekts, docs/login-lockout.md).

**Was stattdessen zusammen schützt:** Sperre pro Adresse (Fail2Ban `efa-web`, `postfix-sasl`, bei Neuinstallationen an: 5 Versuche
in 10 Minuten, 1 Stunde), Wiederholungstäter eine Woche (`recidive`), in der Weboberfläche 5 Fehlversuche in 5 Minuten pro
Adresse und jede Fehlanmeldung erst nach einer festen Sekunde, auf Port 587 (efa-sasl) Stopp pro Anmeldename nach 5 Fehlversuchen
in 10 Minuten von jeder Adresse, 2FA für jeden Admin (seit 6.0.0.6.7), 15 Minuten Sperre nach 5 falschen 2FA-Codes des
Konsolen-Admins über SSH, Audit-Log und Events an SIEM und Wazuh. Nachweise wie in der englischen Fassung
(compensating-controls.md).

**Grenzen:** die Weboberfläche zählt pro Adresse im Speicher (ein Neustart von efa-web beginnt neu; Fail2Ban zählt selbst); ein
Angreifer mit vielen Adressen wird von Fail2Ban gebremst und von 2FA gestoppt, nicht von einem Zähler pro Konto.
