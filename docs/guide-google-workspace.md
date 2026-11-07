# Google Workspace behind eFa-next

Incoming and outgoing mail of Google Workspace through eFa-next, and SPF, DKIM and DMARC that fit. The names of the Google Admin
console menus are those of 2026 and may change.

## Incoming mail

1. **eFa-next**: route the domain to Google: `efactl transport-set --domain example.org --action add --destination aspmx.l.google.com`
   (or `smtp.google.com`, as Google lists it for your account).
2. **DNS**: point the MX record to eFa-next.
3. **Admin console → Apps → Google Workspace → Gmail → Spam, phishing and malware → Inbound gateway**: enter the addresses of
   eFa-next. Turn on *Reject all mail not from gateway IPs* (the lock down) and, if eFa-next marks spam with a header, the spam
   header option. With the gateway entry Google looks behind eFa-next for SPF and its own checks.

## Outgoing mail (smart host, 8g)

1. **Admin console → Apps → Google Workspace → Gmail → Routing → Outbound gateway**: the name of eFa-next. (A routing rule with an
   own host instead works for single groups.)
2. **eFa-next, Mail routing → Submitters**: Google sends from shared ranges. Add Google as submitter by its certificate where you can,
   bound to your domains:

   ```
   efactl submitter-set --name google_example --kind cert --value <SHA-256 fingerprint> --domains example.org
   ```

   For applications that use Google's *SMTP relay* service the same submitter applies.

## SPF, DKIM and DMARC

- **SPF**: `v=spf1 ip4:<eFa-next address> include:_spf.google.com -all` while Google still sends some mail directly.
- **DKIM, sign once**: Google signs before eFa-next; a disclaimer or encryption on eFa-next breaks that signature. Either let
  eFa-next sign alone (`efactl dkim-generate`, record from `efactl dkim-export`, Google signing off for the domain), or keep
  eFa-next from changing the mail (no disclaimer, no PDF encryption for these domains). Google's private keys cannot be exported.
- **DMARC**: `efactl dmarc-record-set --domain example.org --p quarantine`; reports to eFa-next with `efactl reports-in-set`.

## Check

As for Microsoft 365: the Received lines show eFa-next, DKIM and SPF pass at an outside receiver, direct delivery to Google from
other addresses is rejected.
