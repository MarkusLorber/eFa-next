# Impersonation & BEC

Catches business email compromise: a stranger who pretends to be a known person or a known domain. On after a fresh install (from
6.0.0.4.1); after an upgrade it stays as it was, so on an upgraded host turn it on under Protection, Impersonation & BEC (or
`sudo efactl bec-set --mode on`), then set the scores and lists. Nothing is rejected on these checks alone — they add a score that the spam
limit weighs.

## What it checks

- **Forged display name**: a `From` display name that matches one of your VIPs (for example *Alex Example, CEO*) but comes
  from an outside address.
- **Lookalike and cousin domains**: a domain close to one of your own or your partners' by one edit (Levenshtein), by
  look-alike letters (homoglyphs) or by an international spelling (IDN) — for example `exampIe.com` or `example-support.com`
  against `example.com`. Also the same name under another ending (`example.net`, `example.co`) and your domain put in front
  of a foreign one (`example.com.evil.net`); your own subdomains (`mail.example.com`) never count.
- **First contact**: a sender and recipient that have not written to each other before. The relation is kept in Redis with an
  expiry; after the set days it counts as first contact again.
- **Young domain**: the sender domain was registered only days ago (over RDAP, cached).

## Turn it on and fill it

1. On: `sudo efactl bec-set --mode on` (or the switch of the card).
2. VIPs: `sudo efactl bec-vip-set --action add --name "Alex Example" --address alex@example.com`, one per person.
3. Partner domains: `sudo efactl bec-partner-set --action add --domain partner.example`. Your own domains (transport, DKIM,
   tenants) are taken in by themselves, also the ones you add later.
4. Send your outgoing mail through eFa-next: the first-contact check learns who writes to whom from it.
5. Your own domains need SPF, DKIM and DMARC (`p=quarantine` or `p=reject`): a mail with exactly your own address from
   outside is stopped by the DMARC check, not here.

## Settings

- **VIP list**: the names and addresses to protect, such as `ceo@example.com`.
- **Partner domains**: domains to guard against look-alikes besides your own.
- **Scores**: a score per check; raise it to act sooner, set it to 0 to switch that check off.
- **Relation days** and **young-domain days**: the windows for first contact and a young domain.

Every change goes to the audit log. In a cluster the lists and scores are shared.
