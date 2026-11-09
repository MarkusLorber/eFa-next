# Hardening report as PDF

The hardening report (how this host stands against the CIS AlmaLinux 9 benchmark and BSI TR-03108) can be downloaded as a
PDF. Under Security › Hardening report.

- The button **Download PDF** on the card, or `efactl hardening-report --pdf report.pdf` (or `--pdf -` to stdout).
- The PDF holds the date, the host name, the version, the mode, a summary and every check of the table with its result, the
  failed ones first; A4, page X / Y on every page, with colored marks.
- It carries no secrets, only the results.
- The PDF is made by eFa-next's own code (no external tool); `Producer` and `Creator` are eFa-next.

Checked in CI with `qpdf --check` and `pdftotext`.
