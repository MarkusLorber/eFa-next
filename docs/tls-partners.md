# TLS with partner domains

For partners you exchange confidential mail with (bank, tax adviser, law firm), TLS can be required per domain (A2). Under
Mail routing, TLS with partners. Off until you add a partner; an upgrade changes nothing.

- **Mail to the partner**: `encrypt` (TLS required), `verify` (TLS required and the certificate of the partner's mail server
  checked against the public CAs) or `dane-only` (checked by DANE; needs DANE switched on, so that the resolver checks DNSSEC).
  Without TLS the mail waits in the queue and is never sent unencrypted; the queue alarm reports it.
- **Mail from the partner**: a mail with a sender address of the partner domain or one of its subdomains is taken only over
  TLS. Without TLS Postfix refuses it for now (`450`, `reject_plaintext_session`), so a partner server that lost TLS by mistake
  tries again instead of losing the mail. Own networks and logged-in senders are not asked.
- Own domains are not partners: their TLS to the internal mail server is set under Domain settings.

`efactl tls-partner-set --action add --domain bank.example --out verify --inbound on`, `efactl tls-partner-list`.
The maps are `/etc/postfix/efa-tls-partner-out` (in `smtp_tls_policy_maps`) and `/etc/postfix/efa-tls-partner-in` (in
`smtpd_sender_restrictions`, class `efa_tls_partner`). TLS on port 25 for all senders stays opportunistic (RFC 3207); use
MTA-STS and DANE for that.
