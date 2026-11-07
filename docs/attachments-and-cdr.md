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

Content disarm runs before the DKIM signature. Signed or encrypted mail is left unchanged.
