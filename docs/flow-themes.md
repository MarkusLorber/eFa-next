# Mail flow picture: themes

The dashboard shows how eFa-next handles a mail (6.0.0.7): incoming mail on port 25 through postscreen, the SMTP rules, the
spam and virus checks (rspamd with ClamAV), content disarm and delivery, with the branches *rejected*, *user quarantine* and
*admin hold*; outgoing mail from logins and relay networks through the outbound checks and rspamd with the DKIM signature.
A stage that is switched off has a dashed outline. The numbers are those of today (mail log) and of the queues; a click opens
the mail log with the matching filter, the admin hold opens the queue. On a phone the picture stands upright.

The stages are data in `/usr/lib/eFa/python/efa_flow.py` (`STAGES`, `BRANCHES`); the layout is computed from them.

## Add a theme

A theme is a folder of icons, nothing else: no code changes.

1. Make a folder `/usr/share/eFa/flow/<name>` (`<name>`: lower case letters, digits, `-` and `_`, up to 32 characters).
2. Put one SVG file per icon into it, each named after the icon: `cdr.svg`, `deliver.svg`, `hold.svg`, `internet.svg`,
   `outbound.svg`, `postscreen.svg`, `rejected.svg`, `rspamd.svg`, `sign.svg`, `smtp.svg`, `uq.svg`, `users.svg`. Copy
   `/usr/share/eFa/flow/default` as a start. A folder without all of them is not offered.
3. Choose it: *Dashboard › Mail flow picture* (Expert view), or `efactl flow-set --theme <name>`.

The icons are shown as images of this server with a policy that allows no script; keep them plain SVG (paths and shapes,
no script, no external references), at most 64 KB each. An update of eFa-next keeps own folders; the folder `default` belongs
to the package.
