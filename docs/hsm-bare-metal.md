# DKIM keys in a hardware module (HSM) on own hardware

eFa-next can keep the DKIM key of a domain in a hardware module (6.0.0.7): a USB token such as a Nitrokey HSM, a SmartCard-HSM, a
YubiHSM 2, or any module with a PKCS#11 library. The private key never leaves the module; the mail is signed last, by efa-cdr,
through OpenSSL 3 and its pkcs11 provider.

**Tested with SoftHSM only; no real device was tested yet.** The code path is the same for every module.

## Set up the module

1. Install what OpenSSL needs and the library of your module, from the repositories:
   `dnf install pkcs11-provider opensc pcsc-lite` (OpenSC and pcscd for USB tokens and smart cards), or the library of the
   vendor (for example `yubihsm-shell` for a YubiHSM 2). Start pcscd: `systemctl enable --now pcscd`.
2. Put the token in and make a key with the tools of the module (an RSA key of 2048 bits or more, or Ed25519), for example
   `pkcs11-tool --module /usr/lib64/pkcs11/opensc-pkcs11.so --login --keypairgen --key-type rsa:2048 --id 01 --label dkim-example`.
3. SELinux: efa-cdr runs confined like the other mail services; a module that talks to pcscd needs pcscd running. Check
   `ausearch -m avc -ts recent` after the test signing if it fails.
4. *DKIM › Hardware module*: choose the domain, a new selector, the module from the list (OpenSC, YubiHSM 2, SoftHSM, p11-kit;
   *other* for a path of your own), the label of the token, the label of the key and the PIN. The test signing runs first:
   the module signs a test header and the signature is checked with its public key. Only then rspamd stops signing the
   domain and efa-cdr signs it through the module.
5. Publish the DKIM record shown (`<selector>._domainkey.<domain>`) before the mail of the domain goes out.

SoftHSM (for tests only): its token files must belong to the group `ods` and be readable and writable for it
(`chgrp -R ods /var/lib/softhsm/tokens; chmod -R g+rwX /var/lib/softhsm/tokens`); efactl gives efa-cdr that group.

## When the module does not answer

Outgoing mail of the domain waits in the queue (4xx) and is never sent unsigned; the dashboard says so. Fix the module, or
switch to the software key for a while: *DKIM: emergency mode with the software key* (`efactl dkim-hsm-fallback --domain
<domain> --mode on`), which asks for your password and 2FA code and needs a software key of the domain. Switch back with
`--mode off`.

```bash
sudo efactl dkim-hsm-status
sudo efactl dkim-hsm-test --domain example.com
```

The PIN is kept on this host only, in a file of its own (`/etc/eFa/dkim-hsm-pins/<domain>.pin`, mode 0400, root) and never goes
to the other nodes of a cluster: set up each node with its own module. efa-cdr gets it as a systemd credential. OpenSSL is
told only the path of that file (`pin-source=file:`), never the PIN itself, so it does not show in the process list.

An outgoing mail of such a domain larger than 30 MB is refused (552): efa-cdr signs only what it holds in memory, and rspamd
no longer signs that domain, so it would otherwise leave without a signature.
