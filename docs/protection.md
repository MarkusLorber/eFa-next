# Protection

## Spam & virus

When mail is greylisted, marked or rejected; subject marking for failed SPF, DKIM or DMARC; the Bayes classifier (read only); the extra Sanesecurity virus signatures.

![Spam & virus](images/spam.png)

### Greylisting

Greylisting (Spam & virus) holds mail of an unknown sender back once. 9j: how long a new sender waits (1 to 15 minutes, default
5 as rspamd) and how long a sender that came back stays known (1, 3 or 7 days, default 1), as dropdowns showing the values in
use. A new install and a migration from eFa 5 switch it on with 5 minutes and 7 days (from 6.0.0.6); an update keeps what was set.
With greylisting off and its score below the spam marking, mail in between gets no action at all: the dashboard names that gap.

### Scan limits

`efactl scan-limits-set` (Spam & virus, Scan limits) bounds the virus scan of one mail: the seconds clamd may take (5 to 20),
the largest mail it scans (10 to 64 MB; clamd reads at most four times that from archives) and the seconds of all checks of rspamd
(8 to 60). When the scan fails (clamd not running, too slow, a limit hit) the mail either passes unscanned (fail open, as before)
or fails closed: it is deferred with `451` and the sender tries again; a mail too large to scan is rejected. The mode is set for
all and can differ per tenant (`efactl scan-fail-set --tenant <name> --fail open|closed|inherit`). A new install fails closed;
an upgrade keeps the old behaviour until the limits are switched on. Changing them restarts clamd, which takes up to a minute;
domains that fail closed defer their mail during that time.

## Blocklists

DNS blocklists, asked through the own resolver of eFa-next. Each with its terms: lists that are free only for low volume or non-commercial use stay off until you turn them on. *Your own blocklist* adds one more.

![Blocklists](images/rbl.png)

## Sender lists

Always allow or block senders, by address, domain, IP or pattern. *Manage* opens the list with search, import and export. A rule for one recipient or domain goes in *Sender rules*.

**An allowed address or domain always gets through (6.0.0.6).** Postfix lets it past its own checks that could reject it: the
blocklists of the client (RBL), the HELO and the DNS of the sender (an internal domain such as `ai.local` that does not resolve).
The lookup of the allow list stands right after `permit_mynetworks`/`permit_sasl_authenticated` in the client, HELO, sender and
data checks, and in the recipient and relay checks only after `reject_unauth_destination`: an allowed sender never makes this
server an open relay. Postscreen and the TLS policy stay for everyone. **Sender addresses can be forged:** whoever gives an allowed
address gets the same; each pass is logged by Postfix (`efa-allow`) and written to the audit log. Keep only senders you need, as
exact addresses rather than whole domains.

A virus in the mail of an allowed sender is cut out and the mail goes on: the attachment becomes a short note, the header
`X-eFa-next-Removed` names it, and the original is kept for the admin (*Content disarm*, `efactl cdr-list`, `cdr-release`), with an
entry in the audit log. A virus in the text itself cannot be cut out: the mail is held (queue *hold*) and its recipients get a
note. This needs content disarm (efa-cdr) in the milter chain; without it a virus is rejected for every sender as before.

**Ein erlaubter Absender kommt immer durch (6.0.0.6).** Eine erlaubte Adresse oder Domain kommt an den Prüfungen von Postfix
vorbei, die sie abweisen könnten (Blocklisten des Clients, HELO, DNS des Absenders); vor der Relay-Prüfung steht sie nie, ein
offenes Relay entsteht nicht. **Absender sind fälschbar:** Jeder, der eine erlaubte Adresse angibt, bekommt dasselbe; jedes
Durchlassen steht im Audit-Log. Ein Virus in der Mail eines erlaubten Absenders wird herausgeschnitten, die Mail geht weiter
(Hinweis im Text, Header `X-eFa-next-Removed`, Original für den Admin); steckt er im Text selbst, wird die Mail angehalten und die
Empfänger bekommen einen Hinweis.

![Sender lists](images/senders.png)

## Rules

Other spam limits, quarantine instead of rejecting, or another route, for a sender, a sender domain, a recipient, a domain, a tenant or a directory group. The highest priority that fits wins; with several recipients a rule counts if one of them fits.

Example: mail to `partner@example.com` is never rejected but quarantined.

| Field | Value |
|---|---|
| Name | partner-mail |
| Applies to | recipient |
| Address | partner@example.com |
| Quarantine instead of rejecting | Yes |

![Rules](images/rules.png)

On the console: `efactl rule-set --name partner-mail --action set --kind recipient --value partner@example.com --quarantine on`.

## Habits of known senders (BEC patterns)

With Impersonation & BEC on and a score for it, eFa-next keeps for each external sender the hours it writes at, how many mails a
day and to whom here (Redis, for the days a relation counts). From 20 mails on, a mail at an hour the sender never wrote at,
far more mails in a day than usual (more than 10 and five times the average), or only to recipients it never wrote to gets
`EFA_BEC_PATTERN` with what was new. This catches the mailbox of a partner in the hands of a fraudster. Score 2 on new installs,
0 after an upgrade: `efactl bec-set --mode on --score_pattern 2`. The data of one address goes with `gdpr-delete` (D1).

## Lookalike watch (M4)

`efactl lookalike-set --mode on` (Spam & virus, Lookalike watch) looks for new certificates of domains that imitate an own or
partner domain. It uses Certificate Transparency.

1. Once a day the CT search of crt.sh is asked for each name of the own and partner domains (the first label, from 4 letters
   on).
2. A certificate of the last 7 days for a domain that imitates one of them counts as a hit. The kinds are the same as in the
   BEC check: homoglyphs and IDN, one typo, another ending, the own name in front of a foreign domain. Own subdomains do not
   count.
3. For each hit:
   - the dashboard shows it, and the admins get a mail (`--mail off` switches the mail off);
   - the event `lookalike_certificate` is sent;
   - the domain goes into a map: mail from it scores `EFA_LOOKALIKE_CT` (8).

`lookalike-allow --domain d` takes a harmless domain out and never reports it again.

The query tells crt.sh (Sectigo, United Kingdom) the names of the own domains. So the watch is off by default, and with EU
relation it needs the typed confirmation `I accept the transfer outside the EU` when it is switched on.

## More ClamAV signatures (5v a)

`efactl clam-source-set --source urlhaus --mode on --accept_terms yes` (Spam & virus, Virus signatures) adds a source of ClamAV
signatures to the job of the Sanesecurity signatures (every 2 hours). The sources:
- URLhaus (abuse.ch, Switzerland): links of known malware;
- InterServer (USA): hashes of malware and web shells;
- SecuriteInfo (France): needs an own account ID, entered as a secret.

Each source is off by default and is switched on only with its terms confirmed; the confirmation is kept with name and time.
- **Download:** each file comes over HTTPS, only when it changed, up to 200 MB.
- **Check:** clamscan must load it before it counts.
- **Storage:** it is kept as `efa-<source>-<file>` next to the other signatures.
- **Switching off:** a source that is switched off loses its files at the next run.

SecuriteInfo account tier and URLs (6.0.0.6): in the row of SecuriteInfo, choose the account tier and paste the
`DatabaseCustomURL` lines from the setup page of your SecuriteInfo account (console:
`efactl clam-securiteinfo-set --tier basic`, then the lines one by one, an empty line ends).
- **Tier Basic:** at most one round of downloads every 30 minutes and at most 300 kB/s. The job keeps to it itself: the time
  of the last round is written to `/var/lib/eFa/securiteinfo-last` before the first request, so a second run, a restart or a
  manual update within the 30 minutes does not ask SecuriteInfo; the download is read no faster than the rate. The row shows
  the tier in effect and when SecuriteInfo was last asked. More tiers are one line in `SI_TIERS` of efactl.
- **Checked lines:** only `DatabaseCustomURL https://...` with a host securiteinfo.com or one below it, no user, port or
  query, a ClamAV database file at the end, at most 40 lines; blank lines and `#` comments are skipped, anything else is
  refused with the line number.
- **The key:** the lines hold the subscription key. They are kept in `/etc/eFa/securiteinfo-urls.json` (root, 0600), go to
  efactl on stdin, never in an argument, and are never shown, logged or put into the audit log; the page only says how many
  URLs are stored, with Replace and Delete. With stored URLs the account ID is not needed; deleting them makes the ID count again.
- **Cluster:** only the master knows the key and asks SecuriteInfo; the nodes get the checked files from it (docs/cluster.md). Tier and URLs are set on the master; the account ID
  goes neither into the cluster journal nor into the snapshot for a new node. A node shows "waiting for the master" until it
  has the checked signature files from the master. The upgrade to 6.0.0.6 (`efactl cluster-secret-scrub`) takes the ID and
  URL lines out of older journal entries and off the nodes. Older backups may still hold them: if SecuriteInfo was used in a
  cluster before 6.0.0.6, renew the key at SecuriteInfo.

Example of the lines (with a placeholder key):

    DatabaseCustomURL https://www.securiteinfo.com/get/signatures/EXAMPLEKEY/securiteinfo.hdb
    DatabaseCustomURL https://www.securiteinfo.com/get/signatures/EXAMPLEKEY/javascript.ndb

Office macros (5v b): `efactl ole-set --mode on` (Spam & virus, Office macros) has olevba of oletools (EPEL, BSD licence) read
the VBA macros of Office files, in the sandboxed service efa-unlock. Up to three files a mail are read, each up to 10 MB.
- `EFA_OLE_AUTOEXEC` (4): a macro that starts on opening.
- `EFA_OLE_SUSPICIOUS` (3): suspicious calls such as Shell, CreateObject or downloads.
- `EFA_OLE_AUTOEXEC_SUSPICIOUS` (10): both.

This comes next to the own macro check of the content disarm, which only knows whether a file has macros. Off by default.

Spamhaus error codes (5v i): when Spamhaus refuses the queries, the blocklist page says why. `127.255.255.254` means a public or
open resolver; `127.255.255.255` means too many queries. It also says what helps: the own Unbound without forwarders, or a
Spamhaus DQS key.

## Hints on the warning page of the link check (item 4)

When the link check blocks a link, its warning page explains what made it dangerous (the lists that name it) and how to spot
such links: look at the real address, watch for small changes of the name, mistrust urgency and prizes, check with the sender
on a known number. A tenant adds its own text under these hints, such as whom to call
(`efactl links-hint-set --tenant <name> --text "..."`, empty removes it; without tenant for all). The tenant is part of the
signed link token, so the page knows it without any other lookup; links written before 6.0.0.5 show the hint for all.

## More protection (5v)

- **postscreen** (Blocklists page): in front of smtpd on port 25. It drops clients that talk before their turn (pregreet) and
  clients the active IP blocklists of eFa-next with confirmed terms name with enough weight (each list weighs half its score,
  at least 1; threshold 2 to 5, default 3). Own networks, cluster nodes and the never-banned addresses pass, deep protocol tests
  stay off. On for new installs, off after an upgrade (`efactl postscreen-set --mode on`). It restarts Postfix.
- **Active HTML** (Content disarm): `efactl html-disarm-set --mode on [--domain <domain>]` takes scripts, frames, plugins,
  forms, event handlers, `javascript:` links and meta refresh out of HTML mail, after rspamd checked DKIM and ARC of the
  original; the mail gets `X-eFa-HTML-Disarmed`. Signed and encrypted mail stays as it is. Off by default.
- **Young domains**: the days a domain counts as young are a dropdown (7, 14, 30, 90, 365); the age comes from the RDAP server
  of the registry, which learns the domain that is asked for.
- **Sandbox of the services**: eFa-next confines its own services in their unit files. Since 6.0.0.6 rspamd, clamd, freshclam,
  redis, unbound and nginx get a drop-in too (`/etc/systemd/system/<unit>.d/efa-hardening.conf`): the system read-only except
  the folders the daemon writes (its data and log folders and /run for the sockets), no /home, an own /tmp, read-only kernel
  tunables and control groups. Nothing in it needs NoNewPrivileges, which blocks the change into their own SELinux domains (in
  the tests of 6.0.0.5 unbound did not start with it, and the host had no DNS). Postfix and MariaDB stay without. redis runs as its own user and so gets
  the read-only system without the kernel and control group limits, which would bring NoNewPrivileges for it; the check of the
  security minimum before nginx, Postfix and Dovecot start runs outside their sandbox. `efactl
  service-harden --mode on|off` switches it; each unit is restarted and must stay active over a stability window, else it runs
  without the sandbox and the dashboard says so (`efactl service-harden-status`). On for new installs; an update keeps the
  choice and writes the drop-ins of the new release. Updates of the distribution packages do not touch these files.
- What is deliberately not built is in docs/design-decisions.md.

## BIMI (5w)

`efactl bimi-set --mode on` (Spam & virus, Content disarm). For a sender domain that passed DMARC with p=quarantine or
p=reject, eFa-next reads its BIMI record (`default._bimi.<domain>`, or the selector of a BIMI-Selector header) through the own
resolver, fetches the logo over HTTPS (at most 32 KB, 5 seconds) and checks it as SVG Tiny PS with a strict parser without DTD
or entities: no scripts, no animation, no links or images outside. Then the mail gets `BIMI-Location`, `BIMI-Indicator` and
`Authentication-Results: ...; bimi=pass header.d=<domain> header.selector=<selector> policy.authority=none`; otherwise `bimi=`
fail, none, skipped, declined or temperror with the reason. BIMI-Location and BIMI-Indicator of the sender never come through.
Results are kept for an hour per domain. Certificates (VMC/CMC, `a=`) are not checked. Off by default.

## QR codes (5x, 9)

`efactl qr-set --mode on` (Spam & virus, QR codes) reads QR codes in pictures and in the first three pages of PDF files (each
part up to 10 MB, up to five parts a mail, 10 seconds each) with zbar in the own sandboxed service efa-qr, which keeps nothing.
A link of a QR code counts as `EFA_QR_URL` (2), in a mail almost without text as `EFA_QR_URL_TEXTLESS` (5), and when a threat
feed names it as `EFA_QR_FEED` (10). The link check at the click cannot catch these links, a phone opens them directly. zbar
(EPEL) and poppler-utils come from the repositories. Off by default. No text recognition (OCR) of pictures.

## Encrypted archives (10)

`efactl unlock-set --mode on` (Spam & virus, Encrypted archives) opens encrypted ZIP archives for the virus scan. It works in
the own sandboxed service efa-unlock, which writes and keeps nothing.

1. rspamd hands the archive (up to 10 MB, up to three a mail) with the subject and text of the mail to efa-unlock.
2. efa-unlock looks for the password there. First come the words after "Passwort", "password", "Kennwort", "PW", "Code" and
   similar; then short tokens on lines of their own. It tries at most 10 of them, within 5 seconds.
3. Each file goes to clamd over its socket, in memory. Limits: 50 files, 50 MB unpacked, compression ratio 100.

The result:
- **Virus inside:** the mail is rejected (`EFA_ARCHIVE_VIRUS`).
- **Opened and clean:** `EFA_ARCHIVE_UNLOCKED` takes back the mark of encrypted archives (`MIME_ENCRYPTED_ARCHIVE`).
- **Stays shut**, or AES-ZIP, 7z or RAR (not in the Python standard library): marked as before.

Off by default.

## Outbreak filter (11)

`efactl outbreak-set --mode on` (Spam & virus, Outbreak filter) defers a new wave of the same mail with a temporary error.

- **What is a wave:** the same attachment, or the same text when the mail has none, goes to many recipients (default 30) within
  a few minutes (default 10) of its first mail.
- **What happens:** until the wave is 30 minutes old (15, 30 or 60), its mails get a temporary error (`EFA_OUTBREAK_HELD`). The
  sending servers try again later, and by then the virus signatures and the threat feeds may know it. After that the mails are
  checked again as usual.
- **Who always passes:** senders a recipient wrote to before (the pairs of the BEC check), and the exceptions (addresses or
  domains).
- **Data:** the counters live in Redis for a day. They hold only the hash of the part and the first time it was seen.

Off by default.

## Own fuzzy store (N4)

`efactl fuzzy-set --mode on` (Spam & virus, Own fuzzy store) runs the fuzzy worker of rspamd on `127.0.0.1:11335`, with its
hashes in the local Redis for 90 days.

- **What it learns:** a report an admin approves as spam (Spam reports: phishing reports and the reports of users) goes to
  Bayes and into the store (flag 11).
- **What it finds:** new mails that are variants of such spam count as `EFA_FUZZY_LOCAL` (default 8 points, 1 to 20).
- **Data:** only fuzzy hashes are kept, no content and no addresses. Nothing leaves the host.

In a cluster each node has its own store and learns the reports approved on it. A shared store between the nodes needs the
fuzzy port open between them; this is not built yet.

Off by default.

## Community fuzzy store (P7)

`efactl community-set --mode on --server fuzzy.example.eu:11335 --key <public key>` (Spam & virus, Community fuzzy store) also
asks a fuzzy store that the operators run themselves, for example one store for several eFa-next installations in the EU. A hit
counts as `EFA_FUZZY_COMMUNITY` (5).

- **Encryption:** the requests are encrypted with the public key of the store (`rspamadm keypair` on the store).
- **What it gets:** without `--share on` this host only asks. With it, the spam admins approve goes there too, as fuzzy hashes
  only: no content and no addresses.
- **EU rule:** a store outside the private networks and the own domains, with EU relation, needs the typed confirmation.

Off by default.

## Spam traps (M6)

`efactl trap-set --action add --address old-catalog@example.org` (Domain settings, Spam trap addresses) makes an address of an
own domain a spam trap. Use an address that never gets real mail, for example an old one that was only ever harvested.

A mail to a trap is taken and dropped; it is not kept. Before that it teaches the filter:
- Bayes learns it as spam;
- the own fuzzy store (N4) keeps its hashes when the store is on;
- the address of the sending server is stored, without the mail.

The servers of the last 7 days form the map `EFA_TRAP_IP` (6 points) for all other mail. A hit is deleted after 30 days.

A role or report address cannot be a trap.

## Extra virus scanners (7)

`efactl scanner-set` (Spam & virus, Extra virus scanners) adds more scanners through the `external_services` module of rspamd.
You bring the scanner and its licence.

- **Kinds:** ICAP (with the service name, such as `srv_clamav`) and the engines rspamd speaks to: kaspersky_se, avast, fprot,
  sophos, savapi, virustotal.
- **A hit:** each scanner either rejects the mail or marks it with 6 points (`EFA_SCAN_<NAME>`).
- **Limits:** each scan has 15 seconds and parts up to 20 MB.
- **Outside the own networks:** a scanner outside the private networks and the own domains gets parts of the mail. With an EU
  relation it needs the typed confirmation `I accept the transfer outside the EU`, which goes into the audit log.

    efactl scanner-set --name icap_office --action reject --type icap --server 192.0.2.10:1344 --service srv_clamav
    efactl scanner-set --name icap_office --action remove

None is set by default.

## Check after delivery (5v j) and taking mail back (N6)

`efactl retro-set --mode on` (Spam & virus, Check after delivery) checks delivered mail again when the threat feeds learn
something new.

1. While it is on, efa-maillog keeps hashes of the links, of their hosts and of the attachments of each delivered mail, for 72
   hours. It keeps hashes only, never the links: they may hold personal tokens.
2. After each feed update with new entries, these hashes are compared with the feeds.
3. For each mail that a feed now names:
   - the admins get a mail;
   - the event `retro_hit` is sent;
   - the hit goes into the audit log;
   - with `--tell_recipients on`, the recipients get a warning too.

The link check blocks such links from then on anyway, because the feed now knows them.

`efactl retro-imap-set --mode on --host imap.example.org --login '{user}*{master}' --master efa --action move --folder Junk`
also takes such a mail out of the mailboxes.
- **How:** over IMAP with TLS, logged in as a master user of the own mail server (Dovecot master users, for example). It
  searches the Message-ID in the inbox of each recipient, then moves or deletes the mail.
- **No cloud APIs:** no Microsoft Graph, no Google API.
- **Password:** stored for root only.
- **Audit:** each pull-back goes into the audit log.

Both are off by default.

## Sandbox (14)

`efactl sandbox-set --mode on --url https://cape.example.org --token ...` (Spam & virus, Sandbox) sends suspicious attachments
to your own CAPEv2 sandbox. No sandbox runs on the eFa-next host.

Suspicious attachments are up to three per mail, up to 20 MB each, of these kinds: programs and scripts (exe, dll, js, vbs,
ps1, hta, lnk, msi, jar ...), Office files with and without macros, RTF, PDF, archives and disk images (iso, img, vhd).

1. The local service efa-sandbox keeps the verdict of each file by its SHA-256, for 7 days.
2. A file it has not seen goes to the sandbox; its mail gets a temporary error (`EFA_SANDBOX_PENDING`). The sending server
   tries again, and the retry finds the verdict.
3. The verdict:
   - **Malicious** (malscore from the threshold on, default 5): the mail is rejected (`EFA_SANDBOX_MALICIOUS`).
   - **Clean:** nothing changes.
   - **No verdict after 30 minutes:** the mail is delivered with a mark (`EFA_SANDBOX_TIMEOUT`, 3 points).

Mail of logged-in users is not sent.

- **Connection:** HTTPS only, with the API token. For an own CA, add it to the system trust store.
- **Token:** it is stored for root only and handed to the service as a systemd credential. Status pages never show it.
- **Outside the own networks:** a sandbox outside the private networks and the own domains gets the attachments. With an EU
  relation it needs the typed confirmation.

Off by default.

## Outlook add-in for reports (13)

`efactl outlook-addin --address phishing@example.com` (Spam & virus, Phishing reports and banner) gives the manifest of an
Outlook add-in for one of the report addresses. Install it in Exchange or Microsoft 365 for the users (central deployment).

- **What it does:** in a mail that is open, its task pane has the button "Report / Melden". The button opens a new message to
  the report address with the mail as an attachment. The user sends it, and the report then takes the normal way of phishing
  reports.
- **Where it runs:** the task pane is a static page of eFa-next under `/outlook/`, served by nginx; no own service runs for
  it. It is reachable like the portal.
- **Office.js:** it comes from Microsoft, as every Outlook add-in needs.
- **What it needs:** the public address of the portal (https), because the manifest points there.

