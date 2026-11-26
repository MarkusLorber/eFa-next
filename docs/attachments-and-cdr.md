# Attachments & content disarm

Two steps against dangerous attachments: a filter by file type, and content disarm (CDR) that strips the active parts out of
Office and PDF files. Both off by default, under Protection.

## Attachment filter

- Blocks or holds by real file type (the content, not the ending) and by what is inside an archive.
- Marks or blocks encrypted archives (their content cannot be scanned).
- Detects Office macros.
- Executables are blocked.
- Exceptions by name are possible; a single sender can be allowed.

## Content disarm (CDR)

- Office files lose their macros; the file is handed on in the plain format (a `.docm` becomes a `.docx`).
- PDF files lose their active content: JavaScript, open and launch actions, embedded files.
- A file with macros or active content that cannot be cleaned is **replaced** by a short note, never let through.
- A file that cannot be read at all makes the mail wait (a retryable 4xx), it is never delivered unchecked.
- The original is kept for the admin, who can still deliver it: see *Content disarm* in the mail pages (`efactl cdr-list`,
  `cdr-release`). Releasing a file with active content needs the permission to release malware.

Content disarm works on incoming mail. Signed or encrypted mail is left unchanged.

### Outgoing mail (CDR outbound)

Outgoing mail (from logins on port 587 and from the relay networks) is **never changed** by default: rspamd signs it with
DKIM before content disarm runs, and a change afterwards would break the signature. `efactl cdr-outbound-set --mode on`
disarms outgoing mail too (with content disarm on): the disarm runs, then efa-cdr makes each DKIM signature of this host again
over the changed mail, with the same key, selector and signed headers (RSA and ED25519). A mail whose signature cannot be made
again (no key of this host for it, a signature of another server) goes on unchanged. Off by default, also after an update.
