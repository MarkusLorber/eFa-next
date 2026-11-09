# Keys in a hardware module (P3)

eFa-next can keep two kinds of keys in a hardware security module (HSM) or a token, through PKCS#11 and the pkcs11 provider of
OpenSSL 3 (`dnf install pkcs11-provider`, AppStream). The private key never leaves the module. Without a module, software keys
are used as before.

| Key | How | Command |
|---|---|---|
| Signature of the backups (C2) | an Ed25519 key in the module; `openssl pkeyutl -rawin` signs | `efactl backup-hsm-set --mode on --module ...` |
| Own S/MIME keys (15) | an RSA or EC key in the module with its certificate; `openssl cms` signs and decrypts | `efactl crypto-hsm-set --id @example.com --module ... --cert ...` |

**The URI:** both commands ask for the PKCS#11 URI of the key as a secret, such as
`pkcs11:token=efa;object=backup;type=private;pin-value=...`. It is stored for root only; efa-outbound gets it as a systemd
credential.

**The checks:** on setup, the backup key signs a test and the signature is checked with its public key. A module that does not
answer stops a backup with an error; it never falls back to a software key.

## Not in a module

- **DKIM and ARC:** they are signed by rspamd, which has no PKCS#11. Their keys stay software keys in `/etc/rspamd/dkim`
  (root and rspamd only). Moving them into a module would need a signer of their own in front of rspamd.
- **PGP:** GnuPG uses keys on a smartcard (OpenPGP card) through its own scdaemon, which the sandbox of efa-outbound cannot
  reach. The own PGP keys stay software keys.

A network HSM is the better choice for efa-outbound: the service runs in a sandbox without access to USB devices.
