# S/MIME and PGP at the gateway (15)

eFa-next can sign, encrypt and decrypt mail centrally, so users and their mail programs need no keys. OpenSSL (`cms`) and GnuPG
do the cryptography; the outbound milter efa-outbound applies them before rspamd. Off by default.

## Keys

Keys belong either to an address or to a whole domain (`@example.com`). The key of a domain is used for every address of it:
these are domain certificates between gateways.

- **Own S/MIME key:** `efactl crypto-key-make --kind smime --id @example.com` makes an RSA 3072 key. It gives a request (CSR)
  for a CA, and a self-signed certificate valid for 2 years, which is enough between gateways that trust each other. The
  certificate the CA signs goes in with `crypto-import --kind smime-own-cert`. It must fit the own key.
- **Own PGP key:** `crypto-key-make --kind pgp` makes an Ed25519 key with an encryption subkey (cv25519). Its public key is
  shown, to hand on to partners.
- **Partners:** `crypto-import --kind smime-peer` (a certificate) or `--kind pgp-peer` (a public key), each for an address or
  `@domain`.
- **Collected certificates:** with `crypto-policy-set --scope harvest --mode on`, the certificate of each sender who signs a
  mail with S/MIME is kept and used to encrypt to that sender.

Own private keys never come in through a form. They live in `/etc/eFa/crypto` (root only). efa-outbound gets them as systemd
credentials and starts again when they change. The dashboard warns 30 days before an own certificate ends.

## Policy

    efactl crypto-policy-set --scope sign --target example.com --mode smime
    efactl crypto-policy-set --scope encrypt --target partner.example --mode always --kind auto
    efactl crypto-policy-set --scope encrypt --target client@other.example --mode if-possible --kind pgp
    efactl crypto-policy-set --scope decrypt --target example.com --mode on

- **Sign:** the mail of an own domain or address is signed with its own key (S/MIME or PGP), if that key exists.
- **Encrypt:** the mail to a domain or address is encrypted when every recipient has a key of one kind. `auto` takes S/MIME,
  then PGP. With `always` and a recipient without a key, the mail is refused (550) with the name of that recipient, never sent
  in clear. With `if-possible` it goes out signed only.
  - S/MIME uses AES-256-CBC with RSA-OAEP.
  - PGP uses PGP/MIME (RFC 3156); signed and encrypted mail is signed inside the encryption.
- **Decrypt:** incoming encrypted mail to an own domain is decrypted with the key of the recipient or of its domain, before
  rspamd, so the filter sees the content. The mail gets the header `X-eFa-Crypto`.

A mail the sender signed or encrypted already stays as it is. If signing or encryption fails, the mail gets a temporary error and
the sending program tries again: it never goes out without what the policy asks for.
