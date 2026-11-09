# Exchange Server (on premises) behind eFa-next

eFa-next as the mail gateway of an Exchange organisation: it takes mail from the internet, filters it and hands it to Exchange,
and Exchange sends out through eFa-next.

## Incoming mail

1. **eFa-next**: route each domain to the Exchange server (or its load balancer):

   ```
   efactl transport-set --domain example.org --action add --destination exchange.example.local
   ```

   Turn on the recipient check (*Mail routing → Limits & recipient check*), so mail for unknown addresses is rejected at once and
   eFa-next sends no bounces to forged senders (backscatter).
2. **DNS**: point the MX record to eFa-next. Only eFa-next may reach port 25 of Exchange from outside (firewall).
3. **Exchange, receive connector** for port 25: limit *remote network settings* to the addresses of eFa-next and the internal
   networks; TLS on. With *Externally secured* or with eFa-next listed as internal SMTP server (`Set-TransportConfig -InternalSMTPServers`),
   Exchange takes the original sender address for its own checks.

## Outgoing mail (smart host, 8g)

1. **Exchange, send connector** for `*`: route mail through the smart host eFa-next, TLS required.
2. **eFa-next, Mail routing → Submitters**: the Exchange servers by their addresses, bound to the own domains:

   ```
   efactl submitter-set --name exchange --kind ip --value 192.0.2.10/32 --domains example.org,example.com
   ```

   Several servers: one submitter each, or a network that holds only them. Do not add the whole internal network: then every
   client could send.
3. Applications and printers that send mail: their own submitter with a login (`--kind auth`, port 587), bound to their domain.

## SPF, DKIM and DMARC

- **SPF**: only eFa-next sends to the internet: `v=spf1 ip4:<eFa-next address> -all`.
- **DKIM, sign once**: Exchange itself does not sign; if an add-on signs today, turn it off and let eFa-next sign
  (`efactl dkim-generate`), or take its key over with `efactl dkim-import --domain example.org --selector <selector>` so the DNS
  record stays as it is.
- **DMARC**: `efactl dmarc-record-set --domain example.org --p quarantine`, later `reject`.

## Check

- Mail from outside reaches the mailbox, the Received lines show eFa-next; mail to an unknown address is rejected at eFa-next.
- Mail out: DKIM and SPF pass at the receiver; eFa-next shows it under *Mail log* as outgoing.
- From a client in the internal network that is no submitter, sending through eFa-next to the internet must fail.
