# Header privacy of outgoing mail

Outgoing mail of internal systems carries headers that tell the outside about the internal network: `Received` lines with
host names and addresses of the mail server and the PC, `X-Originating-IP`, `X-Forwarded-For`, `X-Client-IP`, and the mail
program in `X-Mailer` or `User-Agent`. With header privacy (M2) eFa-next removes them in its outbound milter before the mail is
signed and leaves the host. Under Mail routing, Header privacy. Off until you add a scope; an upgrade changes nothing.

- Scope: all senders, one own sender domain, or one submitter (Mail routing, Submitters; by its network or its login).
- A header that a DKIM signature of the internal system covers stays: removing it would break that signature.
- The mail still gets the `Received` line of the receiving server, as every mail does.

`efactl header-privacy-set --action add --scope domain --name example.com`, `efactl header-privacy-status`.
