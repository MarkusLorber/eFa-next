# DKIM-Schlüssel in einem Hardware-Modul (HSM) auf eigener Hardware

eFa-next kann den DKIM-Schlüssel einer Domain in einem Hardware-Modul halten (6.0.0.7): ein USB-Token wie Nitrokey HSM, eine
SmartCard-HSM, ein YubiHSM 2 oder jedes Modul mit einer PKCS#11-Bibliothek. Der private Schlüssel verlässt das Modul nie; die
Mail wird zuletzt von efa-cdr signiert, über OpenSSL 3 und seinen pkcs11-Provider.

**Nur mit SoftHSM getestet; ein echtes Gerät wurde noch nicht getestet.** Der Code ist für jedes Modul derselbe.

## Das Modul einrichten

1. Was OpenSSL braucht und die Bibliothek des Moduls aus den Repositories installieren:
   `dnf install pkcs11-provider opensc pcsc-lite` (OpenSC und pcscd für USB-Token und Smartcards) oder die Bibliothek des
   Herstellers (etwa `yubihsm-shell` für ein YubiHSM 2). pcscd starten: `systemctl enable --now pcscd`.
2. Token einstecken und mit den Werkzeugen des Moduls einen Schlüssel erzeugen (RSA ab 2048 Bit oder Ed25519), etwa
   `pkcs11-tool --module /usr/lib64/pkcs11/opensc-pkcs11.so --login --keypairgen --key-type rsa:2048 --id 01 --label dkim-example`.
3. SELinux: efa-cdr läuft eingeschränkt wie die anderen Mail-Dienste; ein Modul, das mit pcscd spricht, braucht pcscd. Schlägt
   die Testsignatur fehl, `ausearch -m avc -ts recent` prüfen.
4. *DKIM › Hardware-Modul*: Domain, einen neuen Selektor, das Modul aus der Liste (OpenSC, YubiHSM 2, SoftHSM, p11-kit; *other*
   für einen eigenen Pfad), das Label des Tokens, das Label des Schlüssels und die PIN. Zuerst läuft die Testsignatur: Das Modul
   signiert eine Test-Kopfzeile, die Signatur wird mit seinem öffentlichen Schlüssel geprüft. Erst dann signiert rspamd die
   Domain nicht mehr, und efa-cdr signiert sie über das Modul.
5. Den angezeigten DKIM-Eintrag (`<Selektor>._domainkey.<Domain>`) veröffentlichen, bevor Mail der Domain hinausgeht.

SoftHSM (nur für Tests): Die Token-Dateien müssen der Gruppe `ods` gehören und für sie les- und schreibbar sein
(`chgrp -R ods /var/lib/softhsm/tokens; chmod -R g+rwX /var/lib/softhsm/tokens`); efactl gibt efa-cdr diese Gruppe.

## Wenn das Modul nicht antwortet

Ausgehende Mail der Domain wartet in der Queue (4xx) und geht nie unsigniert hinaus; das Dashboard zeigt es. Das Modul in
Ordnung bringen oder vorübergehend auf den Software-Schlüssel umschalten: *DKIM: Notbetrieb mit Software-Schlüssel* (`efactl
dkim-hsm-fallback --domain <Domain> --mode on`), verlangt Passwort und 2FA-Code und einen Software-Schlüssel der Domain.
Zurück mit `--mode off`.

```bash
sudo efactl dkim-hsm-status
sudo efactl dkim-hsm-test --domain example.com
```

Die PIN bleibt nur auf diesem Host, in einer eigenen Datei (`/etc/eFa/dkim-hsm-pins/<Domain>.pin`, Modus 0400, root), und geht
nie an die anderen Knoten eines Clusters: Jeden Knoten mit seinem eigenen Modul einrichten. efa-cdr bekommt sie als
systemd-Credential. OpenSSL erhält nur den Pfad dieser Datei (`pin-source=file:`), nie die PIN selbst; sie steht daher nicht in
der Prozessliste.

Eine ausgehende Mail einer solchen Domain über 30 MB wird abgelehnt (552): efa-cdr signiert nur, was es im Speicher hält, und
rspamd signiert diese Domain nicht mehr; sie ginge sonst ohne Signatur hinaus.
