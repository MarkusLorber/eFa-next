# Incident response: template for operators of eFa-next

Not a legally binding statement; see [DISCLAIMER.md](../../DISCLAIMER.md). A template to adapt; the plan, the team and every
report to an authority are the operator's. eFa-next prepares the texts and the timeline; it never sends anything to an
authority by itself.

## 1. Roles

| Role | Name | Deputy | Reachable |
| --- | --- | --- | --- |
| Incident lead | `[...]` | `[...]` | `[...]` |
| Administrator eFa-next | `[...]` | `[...]` | `[...]` |
| Data protection officer | `[...]` | `[...]` | `[...]` |
| Contact to the CSIRT / authority (NIS2, DORA) | `[...]` | `[...]` | `[...]` |

## 2. Detect

Alerts of eFa-next: the dashboard, mails to the admin address, events to SIEM, OpenTelemetry and Wazuh (docs/WAZUH.md: rules
108000-108099 and 108200-108299 with their levels). `[Who watches them, when.]`

## 3. Record and assess

1. Open a record at once: `efactl incident-open --title ... --detected "YYYY-MM-DD HH:MM" [--personal_data yes|no|unknown]
   [--subjects ...]` (Users, Incidents). It shows the deadlines.
2. Assess: significant incident (NIS2 Art. 23)? personal data breach (GDPR Art. 33/34)? major ICT incident (DORA Art. 18, for
   financial entities)? `[Criteria and thresholds of the organisation.]`
3. Keep evidence: the audit log, the strict audit log with its signed anchors (`efactl audit-anchor-verify`), the mail log,
   a backup (`efactl backup-now`) before changes.

## 4. Report (deadlines from the moment of becoming aware)

| Law | Report | Deadline | eFa-next |
| --- | --- | --- | --- |
| NIS2 Art. 23 | early warning / notification / final report | 24 h / 72 h / 1 month | `incident-report --stage early|notification|final` |
| GDPR Art. 33 | notification to the supervisory authority | 72 h | `incident-report --stage gdpr` |
| GDPR Art. 34 | telling the people concerned | without undue delay, when high risk | text of the operator |
| DORA Art. 19 | initial / intermediate / final report | 4 h after classification (max. 24 h) / 72 h / 1 month | `incident-report --stage dora-initial|dora-intermediate|dora-final` |

Check and complete every text before sending it the way the authority asks for.

## 5. Contain, recover, learn

`[Steps: block senders or addresses (sender lists, firewall), reset logins and 2FA (user-2fa-reset), restore (docs/backup-eu.md),
check with the security self check and compliance-verify, lessons learned, update this plan.]`
