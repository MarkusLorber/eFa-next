# Microsoft 365 behind eFa-next

How to put eFa-next in front of Exchange Online: incoming mail through eFa-next, outgoing mail through eFa-next, and SPF, DKIM
and DMARC that fit. The names of the Microsoft menus are those of 2026 and may change.

## Incoming mail

1. **eFa-next**: route the domain to Exchange Online, to the MX host Microsoft shows for it (`contoso-com.mail.protection.outlook.com`):

   ```
   efactl transport-set --domain contoso.com --action add --destination contoso-com.mail.protection.outlook.com
   ```

2. **DNS**: point the MX record of the domain to eFa-next. Keep a low TTL during the change.
3. **Microsoft 365, Exchange admin center → Mail flow → Connectors**: add a connector *from a partner organization to Office 365*,
   identified by the sender IP addresses of eFa-next, and require TLS.
4. **Lock down**: reject mail that does not come through eFa-next, otherwise spammers deliver past it straight to
   `*.mail.protection.outlook.com`. In the same connector restrict the domain to the IP addresses of eFa-next, or add a mail flow
   rule that rejects mail for the domain from other addresses.
5. **Enhanced Filtering for Connectors** (Defender): list the eFa-next addresses, so Microsoft sees the real sending server and not
   eFa-next. Otherwise SPF of every external sender looks like eFa-next.

## Outgoing mail (smart host, 8g)

1. **Microsoft 365, connectors**: add a connector *from Office 365 to a partner organization*, for all domains, delivered through
   the smart host `efa.contoso.com` (the name of eFa-next), TLS required with certificate check.
2. **eFa-next, Mail routing → Submitters**: add Exchange Online as submitter, bound to its own domains only.
   Microsoft sends from shared address ranges that other tenants use too, so do not trust the addresses alone:

   ```
   efactl submitter-set --name m365_contoso --kind cert --value <SHA-256 fingerprint> --domains contoso.com --tenant contoso
   ```

   The fingerprint changes when Microsoft renews its certificate; until submitters can be named by the certificate name, check it
   after each renewal (`openssl s_client -connect` from a test, or the Postfix log line `TLS connection established from`).
   With `--kind ip` and the Microsoft ranges, the binding to the own domains still stops other tenants from sending for other
   domains, but not for yours: prefer the certificate.
3. Optional on eFa-next: DLP, encrypted PDF mail, disclaimers, sending limits (Protection and Mail pages). They act on this mail
   before it is signed.

## SPF, DKIM and DMARC

- **SPF**: the mail now leaves through eFa-next: `v=spf1 ip4:<eFa-next address> include:spf.protection.outlook.com -all`.
  Keep the Microsoft include as long as Microsoft still sends some mail directly (for example notices of its own).
- **DKIM, sign once**: eFa-next changes outgoing mail (disclaimer, encryption), which breaks a signature made before. Let eFa-next
  sign: `efactl dkim-generate --domain contoso.com`, publish the record from `efactl dkim-export --domain contoso.com`, then turn
  DKIM signing for the domain off in Microsoft 365 (Defender → Email authentication). Microsoft does not hand out its private keys,
  so they cannot be imported. A key that another system of yours signs with now can be imported: `efactl dkim-import`.
- **DMARC**: `efactl dmarc-record-set --domain contoso.com --p quarantine`, later `reject`. Aggregate reports can come to
  eFa-next itself (`efactl reports-in-set`).

## Check

- Send a mail from outside: the header `X-eFa-…` and the Received lines show eFa-next before Microsoft.
- Send a mail out: DKIM `d=contoso.com` with the selector of eFa-next passes at the receiver, SPF passes with the eFa-next address.
- Try to deliver directly to `contoso-com.mail.protection.outlook.com` from another address: it must be rejected.
