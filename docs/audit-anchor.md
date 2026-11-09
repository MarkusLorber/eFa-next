# Strict audit log: signed daily anchors

The strict audit mode writes every action into a chain of entries; each entry carries an HMAC over the one before, so a
changed or removed line breaks the chain (`efactl audit-verify`). The HMAC key lives on the same host: someone with root
could write the whole chain anew. The daily anchor (B2) closes that gap.

## How it works

- Once a day, after the log of the day before is closed, eFa-next writes an anchor to `/var/log/eFa/anchors/<day>.json`: the MAC
  of the last entry, the number of entries, the SHA-256 of every closed file, the hash of the anchor before and whether the
  chain was intact. It is signed with an Ed25519 key of its own (`/etc/eFa/audit-anchor.key`, root only; the public key is
  `/etc/eFa/audit-anchor.pub`).
- The anchor also goes out as the event `audit_anchor` with its digest to the SIEM, OTLP and Wazuh targets that are set up.
  Kept there, a chain written anew on the host no longer matches what left it.
- `efactl audit-anchor-verify` (Users, Strict audit mode) checks every anchor: the signature, the link to the anchor before,
  that its last entry is still in the chain and that the closed files are unchanged. Anchors older than the files kept by the
  retention only count with signature and link.
- The hardening report has a check for it: with the strict audit mode on, it passes when the anchors are valid and the last
  one is at most a day old; with the mode off it is not applicable.

To check an anchor outside the host, keep the public key and the anchors (or their digests from the SIEM) and compare.
