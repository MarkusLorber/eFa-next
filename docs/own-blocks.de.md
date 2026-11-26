# Eigene Sperren: Datei-Hashes und YARA

Unter Viren, Anhänge & Links, Eigene Sperren (M5). Nach einer Installation und einem Upgrade leer.

Jeder Eintrag, ein Datei-Hash oder eine YARA-Regel, hat seinen Geltungsbereich: **nur dieser Mandant** (Standard für einen
neuen Eintrag) oder **für alle Mandanten**. Mandanten-Admins (Berechtigung `security.rules`) legen Einträge nur für ihren
eigenen Mandanten an. Nur ein Super-Admin oder eine Anmeldung mit `security.rules.global` legt einen Eintrag für alle
Mandanten an oder ändert ihn. Ein Mandanten-Admin sieht nie die Hashes oder YARA-Regeln eines anderen Mandanten; von den
Regeln für alle Mandanten sieht er den Namen, nicht den Text. Wird ein Eintrag mit dem anderen Geltungsbereich noch einmal
angelegt, wandert er dorthin. Jede Änderung, auch des Geltungsbereichs, steht im Audit-Log und baut die Listen neu.

## SHA-256 von Dateien

`efactl own-hash-set --action add --sha256 <64 Hex-Ziffern> --name rechnung.zip --scope tenant --tenant <Name>` setzt den
SHA-256 einer Datei auf die Liste: Eine Mail mit einem Anhang genau dieses Inhalts wird abgelehnt (`550`, "Attachment blocked
by the administrator", Symbol `EFA_OWN_HASH`), für die Empfänger dieses Mandanten oder, mit `--scope all`, für alle. Die
Prüfung läuft in rspamd über jeden Anhang.

## YARA-Regeln

`efactl own-yara-set --action add --rules 'rule name { ... }' --scope tenant --tenant <Name>` (oder `--file regel.yar` auf der
Konsole) fügt eine YARA-Regel hinzu; derselbe Name noch einmal ändert sie, `--action remove --name <Regel>` entfernt sie. Bevor
eine Regel geladen wird, muss clamscan sie allein und zusammen mit allen anderen Regeln annehmen; `import` und `include` sind
nicht erlaubt, höchstens 256 KB.

ClamAV nimmt nur YARA-Regeln mit mindestens einem String: Eine Regel nur mit Bedingung (`condition: true`) und Module wie `pe`
überspringt ClamAV, deshalb lehnt eFa-next sie mit diesem Grund ab, statt eine Regel zu behalten, die nie trifft. Eine Regel
zählt erst, wenn ClamAV sie als geladen meldet; ein Syntaxfehler wird mit der Zeile gezeigt, die ClamAV nennt.

ClamAV liest alle Regeln aus einer Datenbank (`/var/lib/clamav/efa-own.yar`): Eine Regel für alle Mandanten behält ihren
Namen, die Regel eines Mandanten heißt dort `t<ID>_<Name>`. Ein Treffer lehnt die Mail ab. Sobald ein Mandant eine eigene
Regel hat, gibt rspamd den Treffern von Mandantenregeln das Symbol `EFA_TENANT_YARA`, und eFa-next lehnt die Mail nur ab, wenn
ein Empfänger zu diesem Mandanten gehört (`EFA_AV_REJECT`); dann lehnt eFa-next, nicht das Antivirus-Modul von rspamd, auch
Viren ab, mit demselben Ergebnis.

Grenze: Die Regeln aller Mandanten laufen im einen clamd des Hosts für jede Mail; eine langsame Mandantenregel kostet alle
Mail. Die Prüfgrenzen (Scan limits) begrenzen diese Zeit. Im Cluster die Einträge auf jedem Knoten setzen (oder im Modus
Master/Client auf dem Master).

## YARA-Regeln der Community (6.0.0.7)

`efactl yara-community-set --mode on --accept yes` fügt die YARA-Regeln der Community hinzu, die das Projekt eFa-next bündelt.
Einmal am Tag kommt das Bündel von `https://repo.efa-next.eu/yara/community.yar` mit seiner Signatur (`community.yar.sig`),
geprüft mit dem fest hinterlegten Schlüssel von eFa-next, wie die Advisories und Updates. Ein Bündel, dessen Signatur nicht
passt, wird nicht verwendet.

Bevor es geladen wird, nimmt clamscan das Bündel in einem Test an, und seine Ladezeit wird gemessen. Regeln, die ClamAV nicht
annimmt, bleiben einzeln draußen, mit höchstens 48 Testläufen insgesamt. Der endgültige Satz wird noch einmal geladen und
gemessen, und er darf in eingebauten sauberen Mails (reiner Text, ein Newsletter in HTML, eine Rechnung mit PDF, eine Antwort,
ein Kalendereintrag) nichts finden. Ein Bündel muss im signierten Text seine Version und ein Ablaufdatum nennen, neuer sein als
das verwendete und darf nicht abgelaufen sein: Ein altes Bündel, das noch einmal geschickt wird, wird abgelehnt. Ein Bündel,
das gar nicht lädt, zu langsam lädt, eine saubere Mail trifft oder abgelehnt wird, lässt die Regeln von vorher stehen. Ein
Treffer zählt wie ein Virus (Quarantäne, wo sie an ist). `efactl yara-community-status` zeigt, wie viele Regeln geladen sind,
die Version des Bündels, die Ladezeit und die letzte Prüfung; `efactl yara-community-run` prüft sofort. `--mode off` entfernt
die Regeln. Die Regeln stehen unter den Lizenzen ihrer Autoren (`--accept yes`). Standardmäßig aus, auch nach einem Upgrade; im
Settings-Export als Teil `yara`.
