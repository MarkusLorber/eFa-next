# EVE-JSON style export

A third format of the SIEM export (Monitoring, SIEM export), next to RFC 5424 and JSON (E1): `efactl siem-set --mode on
--target siem.example --format eve`. Off by default; no IDS is installed, no new package is needed.

- One JSON object per line, in the style of Suricata EVE-JSON: `timestamp`, `event_type`, `src_ip`, `dest_ip`, `proto`,
  `dest_port`, `app_proto`, `host`.
- Mail: `event_type` `smtp`, with `smtp.mail_from` and `smtp.rcpt_to`, and the part `efa` with `queue_id`, `direction`
  (inbound when all recipients are own domains), `verdict` (the action of rspamd), `score`, `symbols`, `tenant` and `size`.
  efa-maillog writes the line when it stores the mail in the mail log.
- eFa-next events (logins, audit entries, quarantine, ...): `event_type` `efa`, the event in the part `efa`.
- With pseudonyms in the mail log on (D2), the addresses in the export are pseudonyms too, with a key of their own (the same
  address always gives the same pseudonym in the SIEM, but it differs from the one in the mail log).
- rsyslog sends the lines unchanged over TLS with the certificate of the SIEM checked; the file is
  `/var/log/efa-eve/eve.json`, moved to `.1` at 200 MB.

Snort or Suricata themselves are not part of eFa-next.
