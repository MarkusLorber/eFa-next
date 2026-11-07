# Impersonation & BEC

Catches business email compromise: a stranger who pretends to be a known person or a known domain. Off by default; turn it on
under Protection, then set the scores and lists. Nothing is rejected on these checks alone — they add a score that the spam
limit weighs.

## What it checks

- **Forged display name**: a `From` display name that matches one of your VIPs (for example *Alex Example, CEO*) but comes
  from an outside address.
- **Lookalike and cousin domains**: a domain close to one of your own or your partners' by one edit (Levenshtein), by
  look-alike letters (homoglyphs) or by an international spelling (IDN) — for example `exampIe.com` or `example-support.com`
  against `example.com`.
- **First contact**: a sender and recipient that have not written to each other before. The relation is kept in Redis with an
  expiry; after the set days it counts as first contact again.
- **Young domain**: the sender domain was registered only days ago (over RDAP, cached).

## Settings

- **VIP list**: the names and addresses to protect, such as `ceo@example.com`.
- **Partner domains**: domains to guard against look-alikes besides your own.
- **Scores**: a score per check; raise it to act sooner, set it to 0 to switch that check off.
- **Relation days** and **young-domain days**: the windows for first contact and a young domain.

Every change goes to the audit log. In a cluster the lists and scores are shared.
