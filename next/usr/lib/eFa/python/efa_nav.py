# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The menu of eFa-next: groups, pages, their commands and help texts. The web interface and the text interface (efa-tui) both read it,
so they cannot drift apart; what is not listed here still shows up in both, under Other."""
NAV = [
    ('Overview', [
        {'slug': 'dash', 'title': 'Dashboard', 'sub': 'Current state of this server.',
         'sections': [('Details', ['status', 'settings'], 'advanced')],
         'load': ['quarantine-list', 'backup-list', 'dkim-check', 'rotation-status', 'ssh-root-status', 'bayes-status', 'security-status', 'dash-stats',
                  'rbl-show', 'standards-show']}]),
    ('Mail & quarantine', [
        {'slug': 'flow', 'title': 'Mail routing', 'sub': 'Which domains this server takes mail for, where it goes, and who may send through it.',
         'sections': [('Domains & destinations', ['transport-set']),
                      ('Relay networks & smarthost', ['relay-networks-list', 'relay-networks-add', 'relay-networks-remove', 'relay-networks-apply',
                                                      'relay-networks-discard', 'relay-networks-set', 'smarthost-set']),
                      ('Submitters', ['submitter-list', 'submitter-set', 'submitter-remove', 'outbound-limits-set', 'hijack-list', 'hijack-release']),
                      ('Header privacy', ['header-privacy-status', 'header-privacy-set'], 'advanced'),
                      ('Limits & recipient check', ['message-size-set', 'recipient-verification-set']),
                      ('TLS with partners', ['tls-partner-list', 'tls-partner-set'], 'advanced')],
         'show': ['transports'],
         'notes': {'relay-networks-add': 'Changes wait in the list above until you apply them.',
                   'submitter-set': 'Internal mail systems such as Exchange, Microsoft 365 or an application that send through this server. '
                                    'Each one may send only for its own domains and with the empty sender of bounces, '
                                    'Postfix rejects everything else. Without a submitter everything stays as it was.',
                   'tls-partner-set': 'Mail to the partner then never leaves unencrypted; it waits in the queue instead. Mail from the partner '
                                      'without TLS is refused for now, the sending server tries again. Own domains: Domain settings.',
                   'header-privacy-set': 'Removes Received, X-Originating-IP, X-Mailer, User-Agent, X-Forwarded-For and X-Client-IP before the mail '
                                         'is signed. A header that a DKIM signature of the internal system covers stays.',
                   'outbound-limits-set': 'Against taken over accounts: a sender over the limit within one hour is logged, throttled, held or '
                                          'rejected, and the admin and the sender get a notice once.'}},
        {'slug': 'held', 'title': 'Held mail', 'sub': 'Mail stored for its recipients until someone releases it.',
         'sections': [('Held mail', ['uq-list', 'uq-show', 'uq-release', 'uq-request', 'uq-sender', 'uq-delete']),
                      ('Spam reports', ['train-request', 'train-list', 'train-decide']),
                      ('Settings', ['uq-status', 'uq-set', 'uq-encrypt-set'], 'advanced'), ('My settings', ['my-settings', 'my-settings-set'], 'advanced'),
                      ('My account', ['account-show', 'account-set', 'account-email-set', 'password-change'], 'advanced'),
                      ('Two-factor login (2FA)', ['totp-status', 'totp-setup', 'totp-confirm', 'totp-recovery-new', 'totp-disable', 'passkey-status', 'passkey-register', 'passkey-remove'], 'advanced'),
                      ('Newsletters and my spam limit', ['graymail-status', 'graymail-mine-set', 'user-spam-status', 'user-spam-mine-set']),
                      ('Recall my mail', ['recall-list', 'recall-withdraw']),
                      ('Emergency access to my mail', ['emergency-list', 'emergency-show', 'emergency-file'])],
         'autoload': ['uq-list'],
         'notes': {'uq-set': 'Off by default: mail is then rejected as before. A virus only gets out through a super-admin. '
                             'A released mail does not pass the filters again.'}},
        {'slug': 'quar', 'title': 'Quarantine', 'sub': 'Spam held back in the mail queue instead of delivered.',
         'sections': [('Quarantine', ['quarantine-list', 'quarantine-show', 'quarantine-release', 'quarantine-delete']),
                      ('Settings', ['quarantine-set', 'quarantine-days-set', 'quarantine-purge'], 'advanced'),
                      ('Emergency access', ['emergency-list', 'emergency-show', 'emergency-file', 'emergency-status', 'emergency-set'], 'advanced')]},
        {'slug': 'queue', 'title': 'Mail queue', 'sub': 'Mail Postfix holds: being delivered, waiting, held. Every action asks first and is logged.',
         'sections': [('Queue', ['queue-list', 'queue-show', 'queue-action', 'queue-flush']),
                      ('Spooling and receiving servers', ['spool-status', 'spool-set'], 'advanced'),
                      ('Alarm', ['queue-alarm-set'], 'advanced')],
         'autoload': ['queue-list'],
         'notes': {'spool-set': 'After a server is back, Postfix starts with this many connections and raises them while delivery works.'}},
        {'slug': 'log', 'title': 'Mail log', 'sub': 'Search delivered and rejected mail.', 'load': ['my-settings'],
         'sections': [('Search', ['message-search', 'maillog-search', 'maillog-live', 'sender-action-check', 'sender-action']),
                      ('Data of one person (GDPR)', ['gdpr-export', 'gdpr-delete'], 'advanced'), ('Export headers', ['headers-export'], 'advanced'),
                      ('Storage & privacy', ['retention-status', 'retention-set', 'pseudonymise-status', 'pseudonymise-set', 'content-reason-set', 'subject-display-set', 'headers-store-set',
                                             'maillog-retention-set', 'maillog-size-set', 'maillog-purge'], 'advanced')]}]),
    ('Protection', [
        {'slug': 'spam', 'title': 'Spam & virus', 'sub': 'When mail is greylisted, marked or rejected, and the extra virus signatures.',
         'sections': [('Spam', ['spam-scores-set', 'greylisting-set', 'subject-get', 'subject-set', 'bayes-status']),
                      ('Virus signatures', ['sanesecurity-status', 'sanesecurity-set', 'sanesecurity-update', 'clam-source-status', 'clam-source-set', 'clam-securiteinfo-set']),
                      ('Attachments', ['attachment-status', 'attachment-set']),
                      ('QR codes', ['qr-status', 'qr-set'], 'advanced'),
                      ('Encrypted archives', ['unlock-status', 'unlock-set'], 'advanced'),
                      ('Office macros', ['ole-status', 'ole-set'], 'advanced'),
                      ('Tracking protection', ['tracking-status', 'tracking-set', 'tracking-list-set'], 'advanced'),
                      ('Lookalike watch', ['lookalike-status', 'lookalike-set', 'lookalike-run', 'lookalike-allow'], 'advanced'),
                      ('Check after delivery', ['retro-status', 'retro-set', 'retro-run', 'retro-imap-set'], 'advanced'),
                      ('Outbreak filter', ['outbreak-status', 'outbreak-set'], 'advanced'),
                      ('Own fuzzy store', ['fuzzy-status', 'fuzzy-set'], 'advanced'),
                      ('Community fuzzy store', ['community-status', 'community-set'], 'advanced'),
                      ('Extra virus scanners', ['scanner-status', 'scanner-set'], 'advanced'),
                      ('Sandbox', ['sandbox-status', 'sandbox-set'], 'advanced'),
                      ('Own blocks', ['own-block-status', 'own-hash-set', 'own-yara-set'], 'advanced'),
                      ('Newsletters and own limits', ['graymail-status', 'graymail-set', 'user-spam-status', 'user-spam-set'], 'advanced'),
                      ('Scan limits', ['scan-status', 'scan-limits-set', 'scan-fail-set'], 'advanced'),
                      ('Content disarm', ['cdr-status', 'cdr-set', 'cdr-list', 'cdr-release', 'html-disarm-set', 'bimi-set'], 'advanced'),
                      ('Link check', ['links-status', 'links-set', 'links-hint-set'], 'advanced'),
                      ('Phishing reports and banner', ['phish-status', 'phish-set', 'banner-status', 'banner-set', 'outlook-addin'], 'advanced'),
                      ('Neural network', ['neural-status', 'neural-set'], 'advanced'),
                      ('Symbol scores', ['symbol-scores', 'symbol-score-set'], 'advanced'),
                      ('Own model', ['ml-status', 'ml-set', 'ml-train'], 'advanced')],
         'notes': {'subject-set': 'Put in front of the subject of mail with a hard SPF, DKIM or DMARC failure.',
                   'own-hash-set': 'An attachment with this SHA-256 is rejected, for only this tenant (default) or for all tenants.',
                   'own-yara-set': 'One rule per entry, read by ClamAV; a hit rejects the mail. A rule of a tenant counts only for mail to that '
                                   'tenant. Checked by clamscan before it is loaded; import and include are not allowed.',
                   'scan-limits-set': 'Fail closed: a mail whose virus scan failed waits at the sender and comes again; one too large to scan is '
                                      'rejected. Fail open delivers it unscanned. Changing the limits restarts clamd.',
                   'bayes-status': 'Read only. Bayes counts once it has learned min_learns spam and as many ham mails.',
                   'sanesecurity-update': 'Runs by itself every 2 hours and fetches only what changed.'}},
        {'slug': 'rbl', 'title': 'Blocklists', 'sub': 'DNS blocklists, asked through the own resolver of this server.',
         'commands': ['rbl-show', 'rbl-set', 'rbl-custom-set', 'postscreen-status', 'postscreen-set', 'feed-status', 'feed-set', 'feeds-run'],
         'notes': {'rbl-show': 'Hits and errors count from the last rspamd start. Lists that are only free for low volume or non-commercial use '
                               'stay off until you switch them on. Read the terms first.',
                   'rbl-custom-set': 'An error answer of a list never counts as a listing, whether you name return codes or not.',
                   'postscreen-set': 'Before a smtpd starts: drops clients that talk too early, and those the active IP lists name with enough weight. '
                                     'Own networks, cluster nodes and the never-banned addresses pass. Restarts Postfix.'}},
        {'slug': 'ipblock', 'title': 'IP blocklists', 'sub': 'Block mail servers by their address, in the firewall of this server: feeds such as Talos, and own lists.',
         'commands': ['blocklist-show', 'blocklist-set', 'blocklist-entry', 'blocklist-remove'],
         'notes': {'blocklist-set': 'A feed stays off until you accept its terms. Relay networks, allowed admin addresses, cluster nodes and the '
                                    'own addresses are never blocked. Firewall reloads of package updates keep every list.'}},
        {'slug': 'senders', 'title': 'Sender lists', 'sub': 'Always allow or block senders, by address, domain, IP or pattern.',
         'commands': ['sender-list', 'sender-add', 'sender-remove', 'sender-move', 'sender-list-set', 'sender-rule-set'],
         'notes': {'sender-rule-set': 'A rule for one recipient or domain only. Other rules are managed above.',
                   'sender-add': 'Sender addresses can be forged. An allowed address or domain passes the RBL, HELO and DNS checks of '
                                 'Postfix, also when someone else gives it; each pass is in the audit log. A virus in its mail is cut out, the '
                                 'mail goes on. Exact addresses rather than whole domains, and only senders you need.'}},
        {'slug': 'rules', 'title': 'Rules', 'sub': 'Other spam limits, quarantine or another route, by sender, recipient, domain, tenant or group.',
         'commands': ['rule-list', 'rule-set'],
         'notes': {'rule-set': 'One verdict per mail: with several recipients, a rule counts if one of them fits. Quarantine needs the quarantine switched on. '
                               'A virus is rejected in any case. Tenants and groups are read again every hour.'}},
        {'slug': 'bec', 'title': 'Impersonation & BEC', 'sub': 'Fake names of VIPs, lookalike domains, first contacts and senders that suddenly write differently.',
         'commands': ['bec-status', 'bec-set', 'bec-vip-set', 'bec-partner-set'],
         'notes': {'bec-set': 'On after a new install and after a migration from eFa 5; an update keeps what was set. Each check adds its score, so a lookalike domain at a first contact counts more. Runs in rspamd, '
                              'the relations and sender profiles are kept in Redis for the days set.',
                   'bec-partner-set': 'Own domains are protected anyway: those of the routes, the DKIM keys and the tenants.'}}]),
    ('Domains & tenants', [
        {'slug': 'dkim', 'title': 'DKIM, ARC & DMARC', 'sub': 'Signing keys, their rotation, ARC sealing and the DMARC record of your domains.',
         'sections': [('DKIM keys', ['dkim-check', 'dkim-create', 'dkim-import', 'dkim-remove', 'dkim-export']),
                      ('Key rotation', ['rotation-status', 'rotation-all-set', 'rotation-set', 'rotation-pregenerate', 'rotation-run', 'resolver-set'], 'advanced'),
                      ('Managed externally', ['dkim-provision-status', 'dkim-provision-set', 'dkim-source-set', 'dkim-source-remove', 'dkim-provision-takeover'], 'advanced'),
                      ('ARC', ['arc-show', 'arc-all-set', 'arc-set', 'arc-trusted-set'], 'advanced'),
                      ('DMARC record', ['dmarc-record-show', 'dmarc-record-set', 'dmarc-record-history', 'dmarc-record-check', 'dmarc-reports-set'], 'advanced'),
                      ('Reports received', ['dmarc-report-show', 'tls-report-show', 'reports-in-set']),
                      ('DKIM selectors seen', ['dkim-selectors'], 'advanced')],
         'notes': {'dkim-import': 'Take over the key another system signs with, so each mail is signed once. '
                                  'The private key never leaves this server again: export gives the public DNS records only.',
                   'dkim-export': 'Public DNS records as a zone file. As CSV, on the console: efactl dkim-export --format csv',
                   'arc-trusted-set': 'Empty by default. A valid ARC chain of a sealer named here counts for the checks and softens a DMARC reject of '
                             'mail it forwarded, for example microsoft.com, google.com or yahoo.com.', 'arc-show': 'ARC seals mail this server passes on, so the next server can trust its checks. '
                               'RFC 8617 defines RSA only, Ed25519 is not used for ARC.',
                   'rotation-status': 'Future keys are made in advance; a key rotates from its date on, once enough DNS servers show its record. '
                                      'Publish the records of future keys in advance: the DNS export above contains them. The check runs every 2 hours.',
                   'resolver-set': 'Use external servers. Empty fields are not asked. A key never rotates before its date.',
                   'rotation-all-set': 'Also applies to domains added later. Switching off keeps the future keys.',
                   'rotation-set': 'Shown as override in the status above. Mode default removes it again.',
                   'dmarc-record-set': 'Builds the _dmarc record after RFC 9989; eFa-next only stores it, you publish it. Start with p=none and read the reports. '
                                       'Move to quarantine and then reject once all legitimate mail passes.',
                   'dmarc-record-check': 'Names tags that RFC 9989 removed, such as pct. Saves nothing.'}},
        {'slug': 'dlp', 'title': 'Data loss prevention', 'sub': 'Outgoing mail with card numbers, IBANs, tax or social security numbers or own search patterns: log, encrypt, hold or reject.',
         'commands': ['dlp-status', 'dlp-set', 'dlp-rule-set'],
         'notes': {'dlp-set': 'Only mail of logged in users and of the relay networks. Card numbers count with a right check digit, '
                              'IBANs with a right check sum, tax and social security numbers with their check digit and a word like Steuer or SV before them. '
                              'Held mail waits in the queue (Queue page) until an admin releases or deletes it.',
                   'dlp-rule-set': 'Searched are the subject, the text and HTML parts and text attachments, up to 2 MB per mail. '
                                   'PDF, Office files and archives are not searched.'}},
        {'slug': 'bulk', 'title': 'Bulk mail', 'sub': 'Newsletters and other bulk mail through their own slower transport, checked against what the big providers ask.',
         'commands': ['bulk-status', 'bulk-set'],
         'notes': {'bulk-set': 'Bulk mail goes out more slowly per target domain and does not count for the sending limits. Only mail whose '
                               'recipients are all outside this server takes the bulk transport. Checked: a one-click unsubscribe link '
                               '(List-Unsubscribe with List-Unsubscribe-Post, RFC 8058), a DKIM key here for the sender domain, SPF and DMARC in DNS.'}},
        {'slug': 'archive', 'title': 'Archive handover', 'sub': 'A copy of each mail to an external archive such as MailStore or piler, by SMTP.',
         'commands': ['archive-status', 'archive-set', 'archive-test', 'archive-remove'],
         'notes': {'archive-set': 'MailStore: set up MailStore Gateway (free) as journal target, or a journal mailbox that MailStore fetches, '
                                  'and give its address here. piler takes the copies on its own SMTP port. Copies of mail that is held '
                                  'wait with it; rejected mail is not archived. A copy that cannot be delivered waits in the queue, '
                                  'nothing is lost; the queue alarm (Queue page) reports a backlog. A commercial archive is never needed.'}},
        {'slug': 'pdfmail', 'title': 'Encrypted PDF mail', 'sub': 'Outgoing mail and its attachments in a PDF encrypted with AES-256, without a web portal.',
         'commands': ['pdf-status', 'pdf-set', 'pdf-password-set'],
         'notes': {'pdf-set': 'A mail with the keyword in its subject goes out as encrypted PDF, the keyword is taken out of the subject. '
                              'DLP rules with the action encrypt do the same. The subject itself stays readable.',
                   'pdf-password-set': 'Without an agreed password the sender gets a new password for each mail in a mail of its own, '
                                       'and gives it to the recipients another way, by phone for instance.'}},
        {'slug': 'disclaimer', 'title': 'Disclaimers', 'sub': 'A text or HTML with pictures and attachments at the end of outgoing mail, added before the mail is signed.',
         'commands': ['disclaimer-status', 'disclaimer-which', 'disclaimer-template-set', 'disclaimer-import', 'disclaimer-template-remove', 'disclaimer-restore',
                      'disclaimer-set', 'signature-status', 'signature-set', 'signature-sync', 'crypto-status', 'crypto-key-make', 'crypto-import',
                      'crypto-remove', 'crypto-policy-set', 'crypto-hsm-set'],
         'notes': {'disclaimer-template-set': 'Each mail gets one disclaimer: the most specific that fits its sender (group, then domain, then tenant, '
                                              'then all domains), within a level the lowest priority. Groups: eFa-next group names or ldap:<DN>; their '
                                              'members are read when a disclaimer is saved, the mail never waits for the directory.',
                   'disclaimer-import': 'A ZIP with manifest.json, body.html and/or body.txt, media/ (pictures, named in the HTML as cid:<file>) and '
                                        'attachments/ (png, jpg, gif, pdf, vcf). Checked whole before anything changes (docs/api-disclaimer.md).',
                   'disclaimer-restore': 'The last three versions are kept.',
                   'disclaimer-set': 'The older way, one text per domain; a template of the domain wins over it. Only mail of logged in users and of '
                                     'the relay networks. Signed or encrypted mail stays as it is, and a reply that quotes the disclaimer does not get it twice.'}},
        {'slug': 'domset', 'title': 'Domain settings', 'sub': 'Values of a tenant or a domain over the global ones; the domain wins over its tenant.',
         'commands': ['domain-settings-show', 'domain-spam-set', 'domain-quarantine-set', 'domain-routing-set', 'domain-general-set',
                      'eu-relation-status', 'eu-relation-set', 'application-status', 'application-set', 'application-exception-set',
                      'domain-check-status', 'domain-check-show', 'domain-check-run', 'domain-check-set', 'role-status', 'role-set', 'security-txt',
                      'trap-status', 'trap-set'],
         'notes': {'domain-settings-show': 'Each value with its source: domain, tenant or global.',
                   'domain-spam-set': 'Type inherit to take the value of the tenant or global again. Rules for a sender or recipient still win.',
                   'domain-routing-set': 'The mail server of a domain is on the page Mail routing.',
                   'eu-relation-set': 'With EU relation: no failure reports, backups only in the EU, reports to services outside the EU only '
                                      'after a typed confirmation.'}},
        {'slug': 'tenants', 'title': 'Tenants', 'sub': 'Tenants with their domains, login directory, look, limits and usage.',
         'sections': [('Tenants & domains', ['tenant-list', 'tenant-set', 'tenant-domain-set', 'domain-pending-list', 'domain-onboard', 'domain-verify']),
                      ('Usage & limits', ['tenant-usage', 'tenant-limits-set']),
                      ('Look', ['tenant-brand-show', 'tenant-brand-set']),
                      ('Login directory', ['tenant-idp-status', 'tenant-ldap-set', 'tenant-oidc-set', 'tenant-group-map-set'], 'advanced'),
                      ('Lock & delete', ['tenant-lock', 'tenant-delete'], 'advanced')],
         'notes': {'domain-onboard': 'A tenant admin gets a TXT record to publish; the domain counts after domain-verify finds it. A super admin adds it at once.',
                   'tenant-limits-set': 'From 80 % the admin gets a mail. At 100 % no new domain or user, and no new quarantine for the tenant; mail still flows.',
                   'tenant-lock': 'Locked: its users are logged out and cannot log in. Mail flows on, or waits in the queue.',
                   'tenant-delete': 'Deletes users that are only in this tenant, its groups, settings, DKIM keys, quarantine and mail log. The audit log stays.',
                   'tenant-oidc-set': 'The login page then asks for the mail domain. Only addresses of the domains of the tenant can log in through it.'}}]),
    ('Users & access', [
        {'slug': 'account', 'title': 'My account', 'sub': 'Your own login: address, password, 2FA, settings and sessions.',
         'sections': [('My login', ['whoami', 'account-show', 'account-set', 'account-email-set', 'password-change']),
                      ('Two-factor login (2FA)', ['totp-status', 'totp-setup', 'totp-confirm', 'totp-recovery-new', 'totp-disable']),
                      ('Passkeys', ['passkey-status', 'passkey-register', 'passkey-remove'], 'advanced'),
                      ('My settings', ['my-settings', 'my-settings-set']),
                      ('My sessions', ['session-list', 'session-end'])],
         'notes': {'session-end': 'Your own sessions on other devices too. The browser is logged out within 15 seconds.',
                   'totp-setup': 'With 2FA on already: a new app, after your password and the current code. The old app counts until the new '
                                 'one is confirmed.',
                   'account-email-set': 'The new address gets a link (valid for one day); it counts once the link is clicked. The old '
                                        'address then gets a note.',
                   'password-change': 'Your other sessions end.'}},
        {'slug': 'users', 'title': 'Users', 'sub': 'Users with their groups, API tokens and the audit log.',
         'sections': [('2FA of the users', ['user-2fa-reset', 'totp-policy-set']),
                      ('Passkeys', ['passkey-reset', 'passkey-set'], 'advanced'),
                      ('Users', ['user-list', 'user-show', 'user-set', 'user-state']),
                      ('API tokens', ['token-list', 'token-create', 'token-revoke', 'api-status', 'api-set']),
                      ('Login directory', ['oidc-status', 'oidc-set', 'ldap-status', 'ldap-set'], 'advanced'),
                      ('Audit log', ['audit-search']),
                      ('NIS2 incidents', ['incident-list', 'incident-open', 'incident-report'], 'advanced'),
                      ('Privacy evidence', ['privacy-evidence'], 'advanced'),
                      ('Strict audit mode', ['audit-strict-status', 'audit-mode', 'audit-verify', 'audit-anchor-verify', 'audit-rules-set'], 'advanced')],
         'notes': {'api-set': 'Off by default. The API is at /api/v1/ with the header Authorization: Bearer <token>, /api/v1/schema lists the commands.',
                   'user-set': 'A user can be in several groups; the permissions add up. Tenant and domain are the scope of the predefined groups '
                               '(tenant admin needs a tenant, domain admin a domain). You cannot hand out what you do not have, or change your own groups.',
                   'user-show': 'The effective permissions, each with where it counts.',
                   'user-state': 'Locked users are logged out within 15 seconds and cannot log in; their API tokens stop.'}},
        {'slug': 'groups', 'title': 'Groups', 'sub': 'Groups with their permissions and scope, and which directory group gets which eFa-next group.',
         'sections': [('Groups', ['group-list', 'group-set', 'group-state', 'group-remove', 'permission-list']),
                      ('Directory groups', ['group-map-list', 'group-map-set'], 'advanced')],
         'notes': {'group-set': 'The predefined groups cannot be changed or removed; copy one and change the copy. '
                                'Scope: global, or the tenants or domains named. Permissions marked global_only need a global group.',
                   'group-map-set': 'For LDAP the full DN or the CN, for OIDC the name or ID of the group. A login gets one eFa-next group per mapped directory group.'}},
        {'slug': 'standards', 'title': 'Security standards', 'sub': 'Choose standards (BSI, RFC 9325, Mozilla, NIST, CIS), see the change first, and check which ones this host meets.',
         'sections': [('Check', ['standards-show', 'standards-check']), ('Choose and apply', ['standards-status', 'standards-set', 'standards-rollback']),
                      ('Operating system', ['os-harden-status', 'os-harden-set'], 'advanced')],
         'notes': {'standards-set': 'Without apply=yes only a preview: every setting with its value now and after, and the warnings. The strictest '
                                    'value of the chosen standards, never below the limit of eFa-next. Port 25 stays opportunistic unless you '
                                    'require TLS there. Mozilla modern only for the web interface, logins on 587 stay at TLS 1.2.',
                   'standards-check': 'Every standard, chosen or not, against the settings in effect (postconf, nginx -T, sshd -T, sysctl, '
                                      'crypto policy), with the reason of each finding. DANE incoming, MTA-STS and TLS-RPT need DNS records '
                                      'or a mailbox. Also in the PDF of the hardening report.'}},
        {'slug': 'sec', 'title': 'Security', 'sub': 'Admin access, the firewall and its test.',
         'sections': [('Attack alert', ['threat-status', 'threat-set']),
                      ('Address harvesting', ['harvest-status', 'harvest-set']),
                      ('Failed logins', ['login-lockout-status', 'login-lockout-set']),
                      ('Admin access', ['ssh-root-status', 'ssh-root-set', 'web-allowlist-show', 'web-allowlist-set', 'fail2ban-set', 'admin-email-set', 'rspamd-sso-set', 'audit-rspamd', 'web-harden']),
                      ('Firewall', ['firewall-show', 'firewall-set', 'firewall-confirm', 'firewall-revert', 'firewall-guard-status', 'firewall-guard-set', 'firewall-guard-run']),
                      ('Firewall test', ['firewall-test', 'firewall-probe-set'], 'advanced'),
                      ('Security self check', ['security-status', 'security-check', 'security-check-set', 'security-oval-set', 'pwned-check-set']),
                      ('CVE watch', ['cve-watch-status', 'cve-watch-set', 'cve-watch-run', 'cve-mute', 'web-lockdown', 'cluster-cve']),
                      ('Configuration history', ['history-list', 'history-show', 'history-undo'], 'advanced'),
                      ('Four eyes', ['four-eyes-list', 'four-eyes-decide', 'four-eyes-set']),
                      ('Milter health', ['milter-health-status', 'milter-health-set'], 'advanced'),
                      ('TLS profile', ['tls-profile-status', 'tls-profile-set', 'tls-port25-set']),
                      ('Setup variant', ['setup-variant-status', 'setup-offer-dismiss', 'console-2fa-set']),
                      ('Security minimum', ['floor-status', 'floor-check']),
                      ('SSH profile', ['ssh-profile-status', 'ssh-profile-set', 'ssh-profile-confirm'], 'advanced'),
                      ('Hardening report', ['hardening-report', 'switches-status', 'tls-min-set', 'kernel-hardening-set', 'service-harden-status', 'service-harden'], 'advanced')],
         'notes': {'login-lockout-set': 'Counts the failed logins of the web interface, the user portal, the API and port 587 per address. '
                                        'Relay networks, the firewall allowlist and cluster nodes are never banned.',
                   'ssh-root-set': 'Off also stops the SSH keys of root: only other users can log in then, with sudo. Key-only keeps root keys and stops '
                                   'passwords. Off refuses unless another user has full sudo rights and an SSH key or a password login. '
                                   'Log in as that user first, in a second session.',
                   'admin-email-set': 'To change the web password, on the console: efactl admin-password',
                   'rspamd-sso-set': 'Off: /rspamd/ is not reachable. Read only: the main admin can look for 15 minutes to 4 hours, then it closes '
                                     'by itself. Changes go through eFa-next (rights, audit, cluster). Only with an eFa-next login; the rspamd password is not used.',
                   'firewall-set': 'Reverts after 5 minutes unless you confirm. Keep your own network in the list.',
                   'setup-variant-status': 'Re-Setup asks the questions of the setup again (EU link, frameworks, 2FA), shows old and new, makes '
                                           'a backup and raises the settings, never lowers one: open /resetup. Guided to manual needs your '
                                           'password and 2FA code; 2FA stays on.',
                   'floor-check': 'The guard also runs after each change of the files and before each start of postfix, nginx and dovecot. '
                                  'A value under the limit goes back to the TLS profile; if that fails the service stays stopped.',
                   'firewall-guard-set': 'Restores missing eFa-next rules every 5 minutes and starts firewalld if it is down. '
                                         'Never changes other rules, ports or zones.',
                   'firewall-test': 'Checks whether eFa-next gets out on all ports and answers from outside. No mail is sent.',
                   'security-check': 'Missing security updates (those of listening packages first), open ports, firewall, SSH, TLS, open relay, file modes, '
                                     'certificate. Reads only, changes nothing.',
                   'firewall-probe-set': 'efa-probe runs on a server of yours and connects back only to the address that asks it. '
                                         'eFa-next uses no third-party check services.'}}]),
    ('Monitoring & reports', [
        {'slug': 'report', 'title': 'Mail report', 'sub': 'Summary of the mail log, updated once an hour.',
         'sections': [('Report', ['report-show', 'report-status', 'report-set']), ('Today', ['mailreport-today']),
                      ('Yesterday', ['mailreport-yesterday'], 'advanced'), ('Last 7 days', ['mailreport-week'], 'advanced'), ('Daily mail', ['mailreport-set'])],
         'notes': {'report-show': 'Opens as a page. To get a PDF, use Print in the browser.',
                   'report-set': 'Tenant admins with an email address get the report of their tenant.'}},
        {'slug': 'export', 'title': 'Monitoring', 'sub': 'Send logs and events to a SIEM or an OTLP collector, and values to Prometheus.',
         'sections': [('SIEM export', ['siem-status', 'siem-set']), ('OTLP', ['otlp-status', 'otlp-set', 'otlp-test']), ('Prometheus', ['api-status'])],
         'notes': {'otlp-set': 'OTLP/HTTP with JSON, gzip, a disk buffer that drops the oldest data when full, and retries that wait longer each time. '
                               'The token is never shown again: the status only says set or not set.',
                   'otlp-test': 'Sends one test record now and shows the HTTP status.',
                   'siem-set': 'Sends mail, audit, firewall, event and Fail2Ban lines through rsyslog.'}},
        {'slug': 'wazuh', 'title': 'Wazuh', 'sub': 'The Wazuh agent: install, connect to a manager, update and remove.',
         'sections': [('Agent', ['wazuh-status', 'wazuh-config', 'wazuh-service']), ('Install & update', ['wazuh-check', 'wazuh-install', 'wazuh-update', 'wazuh-remove'], 'advanced')],
         'notes': {'wazuh-status': 'The Wazuh agent is a third-party program and runs as root, as its package sets it up.',
                   'wazuh-install': 'From packages.wazuh.com, with the key fingerprint checked. The package scripts are checked first: '
                                    'if they would touch the firewall, nothing is installed. Updates come only from this page.',
                   'wazuh-config': 'Active response stays off unless you turn it on: the manager could then change firewalld at any time. '
                                   'An agent that eFa-next did not install is only read; eFa-next takes it over only with adopt and the confirmation.'}}]),
    ('System', [
        {'slug': 'dnsshare', 'title': 'DNS resolver for other networks', 'sub': 'Let other servers of your network (a second MX) ask the resolver of this host.',
         'commands': ['dns-share-list', 'dns-share-add', 'dns-share-del', 'dns-share-secondary-set'],
         'notes': {'dns-share-add': 'Only the networks listed may ask, everything else stays refused (never an open resolver): at most /8 for IPv4, '
                                    '/32 for IPv6. Each net also opens port 53 in the firewall, from that net only. A net outside the private '
                                    'ranges needs yes. The other MX of a cluster is one entry, its address.',
                   'dns-share-secondary-set': 'This host asks its own unbound first, then the other MX.'}},
        {'slug': 'net', 'title': 'Network & certificate', 'sub': 'Changes to the network apply after a reboot.',
         'sections': [('Main interface', ['network-show', 'network-set', 'hostname-set']),
                      ('More interfaces', ['interfaces-list', 'interface-set', 'interface-confirm', 'interface-revert', 'uplink-route-set'], 'advanced'),
                      ('DNS and certificate', ['dns-zone-list', 'dns-servers-set', 'dns-zone-set', 'dns-zone-test', 'dns-forward-status', 'dns-forward-fix', 'letsencrypt-set', 'letsencrypt-takeover']),
                      ('DANE', ['dane-status', 'dane-set', 'tlsa-show', 'letsencrypt-rollover'], 'advanced'),
                      ('MTA-STS', ['mta-sts-show', 'mta-sts-set', 'mta-sts-check', 'mta-sts-text'], 'advanced')],
         'show': ['dns_zones'],
         'notes': {'interface-set': 'For internal mail servers or a second uplink. The interface of the default route is changed above, not here. '
                                    'Reverts after 5 minutes unless you keep the change; a firewall zone changes only between minute 20 and 50.'}},
        {'slug': 'bak', 'title': 'Backup & restore', 'sub': 'Backups hold the database and private keys; encrypted ones need their password to restore.',
         'commands': ['backup-list', 'backup-now', 'backup-set', 'backup-password-set', 'backup-key-show', 'restore', 'backup-download', 'backup-read', 'backup-import',
                      'backup-target-list', 'backup-target-set', 'backup-target-test', 'backup-hsm-set'],
         'notes': {'backup-password-set': 'Automatic backups are encrypted with it. It is stored for root only and never shown '
                                          'again. If you lose it, those backups are unusable.',
                   'backup-target-set': 'Only encrypted backups leave this host, right after each backup. For SFTP, compare the host key shown '
                                        'with the one of the server before the first backup goes there.'}},
        # A page of its own (6.0.0.5): on the Security page its reads and cards cost more than the page budget of 100 ms.
        {'slug': 'cluster', 'title': 'Cluster & offline', 'sub': 'Several nodes, staged updates and operation without internet.',
         'sections': [('Cluster', ['cluster-status', 'cluster-init', 'cluster-mode-set', 'cluster-token', 'cluster-join', 'cluster-resync', 'cluster-mx-check', 'cluster-node-remove', 'cluster-promote', 'cluster-leave'], 'advanced'),
                      ('Staged cluster updates', ['cluster-update-status', 'cluster-update-set'], 'advanced'),
                      ('Offline operation', ['offline-status', 'update-mirror-set', 'offline-trust-set', 'offline-bundle-apply', 'offline-bundle-make'], 'advanced'),
                      ('Cluster: all nodes', ['cluster-maillog', 'cluster-quarantine', 'cluster-queue', 'cluster-mail-action', 'cluster-unban'], 'advanced')]},
        {'slug': 'maint', 'title': 'Maintenance & update', 'sub': 'Updates, maintenance mode and power. Actions that interrupt mail ask first.',
         'sections': [('Updates', ['update-pending', 'update-status', 'update-system', 'autoupdate-status', 'autoupdate-set', 'update-check', 'update-install', 'update-rollback',
                                   'update-now', 'update-system-run', 'update-post-boot', 'update-run', 'os-check-status', 'os-check-run']),
                      ('Maintenance', ['maintenance-set', 'load-set', 'load-notify']),
                      ('Release-Upgrade', ['release-upgrade-status', 'release-upgrade'], 'advanced'),
                      ('Power', ['reboot', 'halt']),
                      ('Advanced', ['milter-chain-set', 'extra-service-set', 'mariadb-repair'], 'advanced')],
         'show': ['smtpd_milters', 'extra_services'],
         'notes': {'maintenance-set': 'Stops the service monitor from restarting services.',
                   'release-upgrade': 'Super admins only. Steps in order: preflight, preupgrade, start. Start needs your password and 2FA code, the snapshot box and the host name; it makes an encrypted backup, uploads it to the external target and test-extracts it first. The button stays without effect while the preflight names a reason, such as the missing eFa-next repository for EL10.',
                   'update-system': 'First a backup and an export of the eFa-next configuration, encrypted if a backup password is set. '
                                    'It starts only between minute 20 and 50, and leaves out packages whose scripts reload or restart firewalld. '
                                    'Operating system updates cannot be rolled back automatically.',
                   'autoupdate-set': 'Auto installs in the window with a backup, a health check and a rollback if that fails. The packages are not signed: '
                                     'auto trusts the release account. RPM signing is recommended before using it in production.'}}]),
]
for _group, _pages in NAV:
    for _page in _pages:
        # A page lists its commands once, in section order; sections without a title are the page itself.
        _page.setdefault('sections', [('', _page.get('commands', []))])
        _page['commands'] = [name for section in _page['sections'] for name in section[1]]
PAGES = {page['slug']: page for _, pages in NAV for page in pages}
# Pages of earlier versions, now part of another one: old links and bookmarks keep working.
MOVED = {'relay': 'flow', 'limits': 'flow', 'virus': 'spam', 'rot': 'dkim', 'dmarcrec': 'dkim', 'fwtest': 'sec'}
# A status shown inside the card of its switch: one card per topic.
STATUS_OF = {'disclaimer-set': 'disclaimer-status', 'disclaimer-template-set': 'disclaimer-status', 'disclaimer-template-remove': 'disclaimer-status', 'disclaimer-restore': 'disclaimer-status', 'disclaimer-import': 'disclaimer-status', 'retention-set': 'retention-status', 'bulk-set': 'bulk-status', 'archive-set': 'archive-status', 'archive-remove': 'archive-status', 'pdf-set': 'pdf-status', 'pdf-password-set': 'pdf-status', 'dlp-set': 'dlp-status', 'dlp-rule-set': 'dlp-status', 'spool-set': 'spool-status', 'phish-set': 'phish-status', 'banner-set': 'banner-status', 'milter-health-set': 'milter-health-status', 'mta-sts-set': 'mta-sts-show', 'dane-set': 'dane-status', 'links-set': 'links-status', 'ml-set': 'ml-status', 'ml-train': 'ml-status', 'cdr-set': 'cdr-status', 'attachment-set': 'attachment-status', 'neural-set': 'neural-status', 'bec-set': 'bec-status', 'bec-vip-set': 'bec-status', 'bec-partner-set': 'bec-status', 'my-settings-set': 'my-settings', 'audit-mode': 'audit-strict-status', 'audit-rules-set': 'audit-strict-status', 'security-check-set': 'security-status', 'siem-set': 'siem-status', 'otlp-set': 'otlp-status', 'api-set': 'api-status', 'oidc-set': 'oidc-status', 'ldap-set': 'ldap-status',
             'uq-set': 'uq-status', 'report-set': 'report-status', 'sanesecurity-set': 'sanesecurity-status', 'firewall-guard-set': 'firewall-guard-status',
             'autoupdate-set': 'autoupdate-status', 'ssh-root-set': 'ssh-root-status', 'web-allowlist-set': 'web-allowlist-show', 'wazuh-config': 'wazuh-status'}
# Notes longer than this go into a Help block that opens on a click.
NOTE_SHORT = 110


# Where each form takes the values it shows before a change: the read command and, per field, the key of its output (a.b for a
# nested one, ? before it when the key is there only once the function is set up). None: the field describes an action or a new
# entry and stays empty. Confirmations and secrets always stay empty. The web interface and efa-tui fill the forms from here, and
# the self test of efactl fails for a form that has fields but no entry here or in FORM_NEW / FORM_KEYED.
FORM_SOURCE = {
    'admin-email-set': ('settings', {'email': 'admin_email'}),
    'api-set': ('api-status', {'mode': 'api'}),
    'arc-all-set': ('arc-show', {'mode': 'arc_all', 'key': 'arc_all_key', 'bits': 'arc_all_bits'}),
    'attachment-set': ('attachment-status', {'mode': 'enabled', 'action': 'action', 'encrypted': 'encrypted', 'macros': 'macros', 'names': 'names', 'executables': 'executables', 'add': None, 'remove': None}),
    'audit-mode': ('audit-strict-status', {'mode': 'on', 'require_reason': 'require_reason', 'days': 'days', 'reason': None}),
    'audit-rules-set': ('audit-strict-status', {'mode': 'audit_rules'}),
    'autoupdate-set': ('autoupdate-status', {'mode': 'mode', 'days': 'days', 'time': 'time'}),
    'backup-set': ('settings', {'mode': 'auto_backup'}),
    'banner-set': ('banner-status', {'mode': 'enabled', 'text': 'text', 'unsigned_only': 'unsigned_only', 'add': None, 'remove': None}),
    'milter-health-set': ('milter-health-status', {'milter': None, 'action': None}),
    'bec-set': ('bec-status', {'mode': 'enabled', 'score_vip': 'scores.vip', 'score_lookalike': 'scores.lookalike', 'score_first_contact': 'scores.first_contact',
                               'score_style': 'scores.style', 'relation_days': 'relation_days', 'score_language': 'scores.language',
                               'score_young_domain': 'scores.young_domain', 'young_days': 'young_days', 'score_pattern': 'scores.pattern'}),
    'bulk-set': ('bulk-status', {'mode': 'enabled', 'auto': 'auto', 'senders': 'senders', 'pace': 'pace', 'missing': 'missing'}),
    'cdr-set': ('cdr-status', {'mode': 'enabled'}),
    'content-reason-set': ('audit-strict-status', {'mode': 'content_reason'}),
    'dane-set': ('dane-status', {'mode': 'enabled'}),
    'dlp-set': ('dlp-status', {'cards': 'cards', 'iban': 'iban', 'ids': 'ids', 'ignore': 'ignore'}),
    'dmarc-reports-set': ('settings', {'mode': 'dmarc_reports', 'domain': None, 'email': None, 'org': None}),
    'fail2ban-set': ('settings', {'mode': 'fail2ban'}),
    'firewall-guard-set': ('firewall-guard-status', {'mode': 'guard'}),
    'firewall-probe-set': ('firewall-show', {'url': 'firewall_probe_url'}),
    'firewall-set': ('firewall-show', {'allowlist': 'firewall_allowlist', 'submission': 'firewall_submission'}),
    'greylisting-set': ('settings', {'mode': 'greylisting', 'minutes': 'greylist_minutes', 'days': 'greylist_days'}),
    'headers-store-set': ('settings', {'mode': 'store_headers', 'days': 'headers_days'}),
    'kernel-hardening-set': ('switches-status', {'mode': 'kernel_hardening'}),
    'ldap-set': ('ldap-status', {'mode': 'ldap', 'uri': '?uri', 'bind_dn': '?bind_dn', 'base': '?base', 'user_filter': '?user_filter'}),
    'links-set': ('links-status', {'mode': 'enabled', 'base': 'base', 'allow_continue': 'continue', 'unchecked': 'unchecked', 'add': None, 'remove': None}),
    'load-set': ('settings', {'percent': 'load_percent', 'minutes': 'load_minutes'}),
    'threat-set': ('threat-status', {'sensitivity': 'sensitivity'}),
    'maillog-retention-set': ('settings', {'days': 'maillog_days'}),
    'maillog-size-set': ('settings', {'megabytes': 'maillog_max_mb'}),
    'mailreport-set': ('settings', {'mode': 'mailreport_daily'}),
    'maintenance-set': ('settings', {'mode': 'maintenance_mode'}),
    'message-size-set': ('settings', {'megabytes': 'message_size_limit_mb'}),
    'milter-chain-set': ('switches-status', {'ports': 'milter_ports'}),
    'ml-set': ('ml-settings', {'mode': 'enabled', 'min_each': 'min_each', 'score': 'score'}),
    'account-set': ('account-show', {'name': 'name', 'phone': 'phone'}),
    'dns-share-secondary-set': ('dns-share-list', {'address': 'secondary'}),
    'standards-set': ('standards-status', {'select': 'selected', 'port25_tls': 'port25_tls', 'apply': '?apply', 'os': None, 'efa': None}),
    'my-settings-set': ('my-settings', {'language': 'language', 'timezone': 'timezone', 'page_size': 'page_size', 'notifications': 'notifications',
                                        'view': 'view', 'manual': None}),
    'hostname-set': ('network-show', {'hostname': 'hostname'}),
    'network-set': ('network-show', {'hostname': 'hostname', 'method': 'ipv4.method', 'address': 'ipv4.addresses', 'gateway': 'ipv4.gateway',
                                     'ipv6_method': 'ipv6.method', 'ipv6_address': '?ipv6.addresses', 'ipv6_gateway': '?ipv6.gateway'}),
    'neural-set': ('neural-settings', {'mode': 'enabled', 'max_trains': 'max_trains', 'max_usages': 'max_usages', 'score_spam': 'score_spam', 'score_ham': 'score_ham'}),
    'oidc-set': ('oidc-status', {'mode': 'oidc', 'issuer': '?issuer', 'client_id': '?client_id', 'redirect_uri': '?redirect_uri', 'group_claim': '?group_claim', 'portal_redirect_uri': '?portal_redirect_uri'}),
    'otlp-set': ('otlp-status', {'mode': 'enabled', 'endpoint': 'endpoint', 'auth': 'auth', 'header_name': 'header_name', 'headers': None, 'signals': 'signals',
                                 'verify': 'verify', 'ca_file': 'ca_file', 'client_cert': 'client_cert', 'client_key': 'client_key', 'buffer_mb': 'buffer_mb'}),
    'outbound-limits-set': ('submitter-list', {'recipients_hour': 'limits.recipients_hour', 'domains_hour': 'limits.domains_hour', 'action': 'limits.action',
                                               'domain_recipients_hour': 'limits.domain_recipients_hour', 'tenant_recipients_hour': 'limits.tenant_recipients_hour',
                                               'auto_hold': 'limits.auto_hold'}),
    'pdf-set': ('pdf-status', {'keyword': 'keyword'}),
    'pwned-check-set': ('switches-status', {'mode': 'pwned'}),
    'qr-set': ('qr-status', {'mode': 'enabled'}),
    'unlock-set': ('unlock-status', {'mode': 'enabled'}),
    'ole-set': ('ole-status', {'mode': 'enabled'}),
    'sandbox-set': ('sandbox-status', {'mode': 'enabled', 'url': 'url', 'threshold': 'threshold'}),
    'fuzzy-set': ('fuzzy-status', {'mode': 'enabled', 'score': 'score'}),
    'retro-set': ('retro-status', {'mode': 'enabled', 'tell_recipients': 'tell_recipients'}),
    'signature-set': ('signature-status', {'mode': 'enabled'}),
    'four-eyes-set': ('four-eyes-list', {'mode': 'all', 'tenant': '?tenant', 'level': None}),
    'cluster-update-set': ('cluster-update-status', {'mode': 'enabled', 'window': 'window', 'first': 'first'}),
    'community-set': ('community-status', {'mode': 'enabled', 'server': 'server', 'key': 'key', 'share': 'share'}),
    'outbreak-set': ('outbreak-status', {'mode': 'enabled', 'recipients': 'recipients', 'window': 'window', 'hold': 'hold', 'exceptions': 'exceptions'}),
    'cve-watch-set': ('cve-watch-status', {'mode': 'mode', 'lockdown': 'lockdown'}),
    'domain-check-set': ('domain-check-status', {'mode': 'mode', 'prompt': 'prompt'}),
    'service-harden': ('service-harden-status', {'mode': 'mode'}),
    'dns-servers-set': ('dns-zone-list', {'servers': 'servers', 'tls': 'tls'}),
    'postscreen-set': ('postscreen-status', {'mode': 'mode', 'threshold': 'threshold'}),
    'graymail-set': ('graymail-status', {'mode': 'enabled', 'default': 'default', 'subject': 'subject'}),
    'graymail-mine-set': ('graymail-status', {'mode': 'mine_choice'}),
    'user-spam-set': ('user-spam-status', {'mode': 'allowed', 'low': 'low', 'high': 'high'}),
    'user-spam-mine-set': ('user-spam-status', {'score': 'mine'}),
    'eu-relation-set': ('eu-relation-status', {'mode': 'choice', 'domain': None}),
    'pseudonymise-set': ('pseudonymise-status', {'days': 'days'}),
    'quarantine-days-set': ('settings', {'days': 'quarantine_days'}),
    'quarantine-set': ('settings', {'mode': 'quarantine'}),
    'queue-alarm-set': ('switches-status', {'alarm_size': 'alarm_size', 'alarm_hours': 'alarm_hours'}),
    'recipient-verification-set': ('settings', {'mode': 'recipient_verification'}),
    'relay-networks-set': ('settings', {'networks': 'relay_networks'}),
    'report-set': ('report-status', {'daily': 'daily', 'weekly': 'weekly', 'pdf': 'pdf'}),
    'reports-in-set': ('switches-status', {'mode': 'reports_in', 'address': 'reports_in_address'}),
    'resolver-set': ('rotation-status', {'ipv4_1': 'ipv4_1', 'ipv4_2': 'ipv4_2', 'ipv6_1': 'ipv6_1', 'ipv6_2': 'ipv6_2', 'threshold': 'threshold'}),
    'rotation-all-set': ('rotation-status', {'mode': 'rotation_all', 'interval': 'rotation_interval', 'horizon': 'rotation_horizon', 'bits': 'rotation_bits'}),
    'rspamd-sso-set': ('settings', {'mode': 'rspamd_sso', 'minutes': None}),
    'sanesecurity-set': ('settings', {'mode': 'sanesecurity'}),
    'scan-limits-set': ('scan-status', {'mode': 'enabled', 'av_seconds': 'av_seconds', 'scan_mb': 'scan_mb', 'task_seconds': 'task_seconds', 'fail': 'fail'}),
    'security-check-set': ('security-status', {'mode': 'daily'}),
    'security-oval-set': ('switches-status', {'mode': 'oval'}),
    'siem-set': ('siem-status', {'mode': 'siem', 'target': '?target', 'port': '?port', 'protocol': '?protocol', 'format': '?format', 'ca_file': '?ca_file'}),
    'smarthost-set': ('settings', {'host': 'smarthost'}),
    'spam-scores-set': ('settings', {'greylist': 'spam_scores.greylist', 'mark': 'spam_scores.rewrite_subject', 'reject': 'spam_scores.reject'}),
    'spool-set': ('spool-status', {'maximal_queue_lifetime': 'maximal_queue_lifetime', 'bounce_queue_lifetime': 'bounce_queue_lifetime',
                                   'initial_destination_concurrency': 'initial_destination_concurrency'}),
    'ssh-root-set': ('ssh-root-status', {'mode': 'mode'}),
    'flow-set': ('flow-status', {'animation': 'animation'}),
    'login-lockout-set': ('login-lockout-status', {'mode': 'mode', 'tries': 'tries', 'minutes': 'minutes', 'hours': 'hours', 'repeat': 'repeat'}),
    'harvest-set': ('harvest-status', {'mode': 'mode', 'tries': 'tries', 'minutes': 'minutes', 'hours': 'hours', 'allow': 'allow'}),
    'dkim-provision-set': ('dkim-provision-status', {'mode': 'mode'}),
    'cluster-mode-set': ('cluster-status', {'mode': 'mode'}),
    'subject-display-set': ('settings', {'mode': 'show_subjects'}),
    'subject-set': ('subject-get', {'text': 'subject_tag'}),
    'submission-pam-set': ('switches-status', {'mode': 'submission_pam'}),
    'tls-min-set': ('switches-status', {'mode': 'tls_min'}),
    'tls-profile-set': ('tls-profile-status', {'profile': 'profile', 'ciphers': None}),
    'tls-port25-set': ('tls-profile-status', {'mode': 'port25_mode'}),
    'console-2fa-set': ('setup-variant-status', {'mode': 'console_2fa'}),
    'resetup': ('setup-variant-status', {'variant': 'variant', 'eulink': 'eulink', 'notice': None, 'noeu': None, 'frameworks': 'frameworks',
                                         'note': 'note', 'lang': None, 'standards': None, 'apply': None}),
    'ssh-profile-set': ('ssh-profile-status', {'mode': 'profile'}),
    'web-allowlist-set': ('web-allowlist-show', {'mode': 'mode', 'networks': 'networks'}),
    'uq-encrypt-set': ('uq-status', {'mode': 'encrypt'}),
    'uq-set': ('uq-status', {'mode': 'enabled', 'score': 'score', 'days': 'days', 'digest': 'digest', 'self_release': 'self_release', 'public_url': 'public_url'}),
}
# Forms that add, remove or act on one entry, or start a job: nothing to show beforehand.
FORM_NEW = {
    'account-email-set', 'password-change', 'totp-recovery-new', 'totp-setup', 'floor-check', 'release-upgrade', 'setup-variant-apply', 'totp-import', 'console-2fa-enroll', 'archive-remove', 'archive-set', 'arc-trusted-set', 'audit-rspamd', 'backup-import', 'backup-now', 'backup-password-set', 'backup-target-set', 'backup-target-test',
    'bec-partner-set', 'bec-vip-set', 'scan-fail-set', 'tls-partner-set', 'header-privacy-set', 'own-hash-set', 'own-yara-set', 'letsencrypt-rollover', 'gdpr-export', 'gdpr-delete', 'incident-open', 'incident-report', 'privacy-evidence', 'totp-confirm', 'totp-disable', 'user-2fa-reset', 'totp-policy-set', 'passkey-register', 'passkey-remove', 'passkey-reset', 'passkey-set', 'hijack-release', 'links-hint-set', 'html-disarm-set', 'feed-set', 'bimi-set', 'tracking-set', 'tracking-list-set', 'lookalike-set', 'lookalike-run', 'lookalike-allow', 'recall-withdraw', 'outbound-hold-set', 'outbound-hold-run', 'update-staged-set', 'emergency-show', 'emergency-file', 'emergency-set', 'history-show', 'history-undo', 'four-eyes-decide', 'signature-sync', 'outlook-addin', 'update-mirror-set', 'offline-trust-set', 'offline-bundle-apply', 'offline-bundle-make', 'crypto-key-make', 'crypto-import', 'crypto-remove', 'crypto-policy-set', 'crypto-hsm-set', 'backup-hsm-set', 'clam-securiteinfo-set', 'clam-source-set', 'retro-run', 'retro-imap-set', 'application-exception-set', 'mta-sts-check', 'mta-sts-unserve', 'mta-sts-text', 'domain-check-run', 'domain-check-show', 'role-set', 'security-txt', 'trap-set', 'scanner-set', 'cve-mute', 'web-lockdown', 'cve-watch-run', 'cdr-release', 'cluster-init', 'cluster-join', 'cluster-mail-action', 'cluster-promote', 'cluster-node-remove', 'cluster-unban',
    'blocklist-entry', 'blocklist-remove', 'legal-accept', 'uplink-route-set', 'ssh-profile-confirm', 'ssh-profile-revert', 'disclaimer-template-remove', 'disclaimer-restore', 'disclaimer-import', 'blocklist-set', 'symbol-score-set', 'dkim-create', 'dkim-generate', 'dkim-generate-ed25519', 'dkim-provision-takeover', 'dkim-remove', 'dkim-source-remove', 'dkim-source-set', 'dlp-rule-set', 'dns-zone-set', 'domain-onboard', 'domain-verify', 'extra-service-set',
    'group-map-set', 'group-remove', 'group-set', 'group-state', 'headers-export', 'dns-forward-fix', 'letsencrypt-set', 'letsencrypt-takeover', 'pdf-password-set', 'phish-set', 'quarantine-delete',
    'group-map-set', 'group-remove', 'group-set', 'group-state', 'headers-export', 'dns-share-add', 'dns-share-del', 'letsencrypt-set', 'letsencrypt-takeover', 'pdf-password-set', 'phish-set', 'quarantine-delete',
    'quarantine-release', 'queue-action', 'rbl-apply', 'rbl-custom-set', 'relay-networks-add', 'relay-networks-remove', 'restore', 'rotation-pregenerate',
    'rotation-run', 'rule-set', 'sender-add', 'sender-list-set', 'sender-move', 'sender-remove', 'sender-rule-set', 'service-restart', 'session-end',
    'submitter-remove', 'submitter-set', 'tenant-delete', 'tenant-domain-set', 'tenant-group-map-set', 'tenant-lock', 'tenant-set', 'token-create',
    'token-revoke', 'train-decide', 'train-request', 'transport-set', 'update-rollback', 'update-run', 'update-system', 'update-system-run', 'uq-delete',
    'uq-release', 'uq-request', 'uq-sender', 'sender-action', 'user-set', 'user-state', 'wazuh-check', 'wazuh-config', 'wazuh-install', 'wazuh-remove', 'wazuh-service',
    'wazuh-update'}
# shortcut: forms for one domain, tenant, list or interface show their values only when opened through the Change button of
# their table (the key in the address); filling them from the picked key needs a request per pick, later.
FORM_KEYED = {'os-harden-set', 'application-set', 'arc-set', 'disclaimer-set', 'disclaimer-template-set', 'dmarc-record-set', 'domain-general-set', 'domain-quarantine-set', 'domain-routing-set', 'domain-spam-set',
              'interface-set', 'mta-sts-set', 'rbl-set', 'retention-set', 'rotation-set', 'tenant-brand-set', 'tenant-ldap-set', 'tenant-limits-set',
              'tenant-oidc-set'}


# A switch that is off has no value in effect: its fields show the default that switching it on would use.
DEFAULT_WHILE_OFF = {('siem-set', 'port'), ('siem-set', 'protocol'), ('siem-set', 'format')}


def optional_source_problems(forms, args_of, choices):
    """Fields that show a default or a pulldown but may lack their value: an optional key (?) would leave the default in
    place of the value in effect. forms: FORM_SOURCE, args_of(name): the arguments of a command, choices: ARG_CHOICES."""
    found = []
    for name, (_status, keys) in sorted(forms.items()):
        for arg in args_of(name):
            key = keys.get(arg['name'])
            if (name, arg['name']) in DEFAULT_WHILE_OFF:
                continue
            if key and key.startswith('?') and ('default' in arg or (name, arg['name']) in choices or arg.get('choices')):
                found.append(f'{name} --{arg["name"]}: optional source {key} for a field with a default or a pulldown')
    return found


def form_value(output, key):
    """The value a form field shows from the output of its read command, as text; None when the output lacks it."""
    if not key or not isinstance(output, dict):
        return None
    key = key.lstrip('?')
    value = output
    # nmcli names its settings with a dot (ipv4.method): a key as it stands comes first.
    for part in [key] if key in output else key.split('.'):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    if isinstance(value, bool):
        return 'on' if value else 'off'
    if isinstance(value, list):
        return ', '.join(str(item) for item in value)
    if value is None or isinstance(value, dict):
        return ''
    return str(value)
