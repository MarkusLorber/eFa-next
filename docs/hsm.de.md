# Schlüssel in einem Hardware-Modul (P3)

eFa-next kann zwei Arten von Schlüsseln in einem Hardware-Sicherheitsmodul (HSM) oder einem Token halten, über PKCS#11 und den
pkcs11-Provider von OpenSSL 3 (`dnf install pkcs11-provider`, AppStream). Der private Schlüssel verlässt das Modul nie. Ohne Modul
werden wie bisher Software-Schlüssel verwendet.

| Schlüssel | Wie | Befehl |
|---|---|---|
| Signatur der Sicherungen (C2) | ein Ed25519-Schlüssel im Modul; `openssl pkeyutl -rawin` signiert | `efactl backup-hsm-set --mode on --module ...` |
| Eigene S/MIME-Schlüssel (15) | ein RSA- oder EC-Schlüssel im Modul mit seinem Zertifikat; `openssl cms` signiert und entschlüsselt | `efactl crypto-hsm-set --id @example.com --module ... --cert ...` |

**Die URI:** Beide Befehle fragen die PKCS#11-URI des Schlüssels als Geheimnis ab, etwa
`pkcs11:token=efa;object=backup;type=private;pin-value=...`. Die PIN verlässt die URI sofort: Sie kommt in eine eigene Datei
(Modus 0400; `/etc/eFa/backup-hsm.pin`, für S/MIME `pin-smime-own-<ID>` in `/etc/eFa/crypto`), und OpenSSL erhält nur
`pin-source=file:` mit diesem Pfad, nie die PIN; sie steht daher nicht in der Prozessliste. Eine URI, die schon eine
`pin-source` nennt, bleibt wie sie ist. URI und PIN-Datei gehören nur root; efa-outbound bekommt sie als systemd-Credential. Ein
Sicherungsschlüssel, der vor 6.0.0.7 mit der PIN in der URI eingerichtet wurde, wird beim ersten Signieren in die PIN-Datei
übernommen.

**Die Prüfungen:** Beim Einrichten signiert der Sicherungsschlüssel einen Test, und die Signatur wird mit seinem öffentlichen
Schlüssel geprüft. Ein Modul, das nicht antwortet, bricht eine Sicherung mit einem Fehler ab; es wird nie auf einen
Software-Schlüssel ausgewichen.

## Nicht in einem Modul

- **DKIM und ARC:** Sie signiert rspamd, das kein PKCS#11 kennt. Ihre Schlüssel bleiben Software-Schlüssel in `/etc/rspamd/dkim`
  (nur root und rspamd). Sie in ein Modul zu legen, bräuchte einen eigenen Signierer vor rspamd.
- **PGP:** GnuPG nutzt Schlüssel auf einer Smartcard (OpenPGP-Karte) über seinen eigenen scdaemon, den die Sandbox von
  efa-outbound nicht erreicht. Die eigenen PGP-Schlüssel bleiben Software-Schlüssel.

Ein Netzwerk-HSM ist für efa-outbound die bessere Wahl: Der Dienst läuft in einer Sandbox ohne Zugriff auf USB-Geräte.
