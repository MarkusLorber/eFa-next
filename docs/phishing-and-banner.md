# Phishing reports & warning banner

Two features for incoming mail, both off by default, under Protection.

## Report a phish

- A report address per domain, for example `phishing@example.com`. A user forwards a suspicious mail there.
- After an admin releases it, the mail flows into Bayes and Fuzzy so the filter learns from it.
- `phish-set` adds or removes the address per domain; `phish-status` lists them.

## Warning banner

- A short banner at the top of the text and HTML parts of incoming mail from outside.
- By default only on mail **without** a valid DKIM signature, so adding the banner never breaks a signature. You can switch
  it to all outside mail.
- Exceptions by sender domain, for example `partner.example`.
- The banner text can be changed (up to 300 characters, no `<` or `>`).
- Signed or encrypted mail (S/MIME, PGP) is left unchanged.

`banner-set` turns it on and sets the text and exceptions; `banner-status` shows the current setting.
