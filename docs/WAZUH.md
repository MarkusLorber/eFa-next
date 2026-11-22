# Wazuh and eFa-next

eFa-next can install, connect, update and remove the Wazuh agent, on the web page **Wazuh** or with efactl.
Everything is off by default; an upgrade of eFa-next turns nothing on.

## Commands

| Command | What it does |
|---|---|
| `efactl wazuh-status` | Installed version, running, connection to the manager, last keep-alive, eFa-next block present. |
| `efactl wazuh-check [--version V]` | Downloads the package and checks signature and package scripts, installs nothing. |
| `efactl wazuh-install [--version V] --confirm yes` | Installs the agent. It starts only after `wazuh-config`. |
| `efactl wazuh-config --manager M [--port 1514] [--enrollment_port 1515] [--agent_name N] [--groups a,b] [--events on/off] [--active_response on/off]` | Writes the manager and the eFa-next block, asks the enrollment password twice (empty keeps it), restarts the agent. |
| `efactl wazuh-service --action start/stop/restart` | Starts, stops or restarts the agent. |
| `efactl wazuh-update [--version V] --confirm yes` | Updates the agent, with the same checks as the install. |
| `efactl wazuh-remove [--repo yes] --confirm yes` | Stops and removes the agent and the eFa-next block; the repository only with `--repo yes`. |

All of them are for the super-admin only.

## An agent that eFa-next did not install

If a `wazuh-agent` is installed and eFa-next did not install it (no `"managed": true` in `/etc/eFa/wazuh.json`),
the page shows "Agent present, not managed by eFa-next" and only its status.
`wazuh-config`, `wazuh-service`, `wazuh-update` and `wazuh-remove` refuse to act on it; the status shows what eFa-next
finds in its `ossec.conf` (manager, port, protocol, enrollment name and groups, active response) and the command to take
it over.

Taking it over changes nothing on the agent:

    efactl wazuh-config --adopt yes --confirm yes

(web page: Wazuh agent: settings, take over: "Take over, change nothing", confirm: yes). eFa-next reads the settings from
`ossec.conf` into `/etc/eFa/wazuh.json` and keeps a copy `ossec.conf.efa-<time>` beside it. `ossec.conf` stays byte for
byte, `client.keys` too, and the agent is neither started, stopped, restarted nor enrolled: an agent that is off stays off.
It asks for no enrollment password. The answer names the manager address first.

The same take-over runs by itself, read only and with the same result, when eFa-next is upgraded, when an eFa 5 host is
migrated (efa-migrate) and before a release upgrade to EL10 (the settings comparison of the release upgrade includes
`ossec.conf` and `wazuh.json`). The update or migration report says "Wazuh agent taken over: manager ..., groups ...,
active response on|off; config unchanged". If `ossec.conf` cannot be read (no client section with a manager), eFa-next
does not take the agent over, says why, and the upgrade goes on.

After the take-over, a setting changed through eFa-next writes `ossec.conf` (with a copy first) and keeps what the agent
had: its enrollment name and groups, the other values of its enrollment, its own blocks, and its active response, which
eFa-next turns off only when the admin sets it off. A taken-over agent is restarted only if it runs, never switched on.

Giving it back removes only the block of eFa-next from `ossec.conf` (with a copy first) and the agent counts as not
managed again; the agent keeps running as it is:

    efactl wazuh-config --adopt no --confirm yes

## Install and updates

- Source: the official repository `https://packages.wazuh.com/4.x/yum/`, written to `/etc/yum.repos.d/wazuh.repo` with `enabled=0`.
  So `dnf upgrade`, `dnf-automatic` and the eFa update never touch the agent: it is updated only with `wazuh-update`.
- The signing key is downloaded and imported only if its fingerprint is `0DCF CA55 47B1 9D2A 6099 5060 96B3 EE5F 2911 1145`.
- The package is downloaded first and checked: `rpm -K` must say the signatures are OK,
  and its scripts must not call `firewall-cmd`, `firewalld`, `iptables` or `nft`. Otherwise nothing is installed.
  A `firewall-cmd --reload` from a package script can cut a host off, so this check is strict.
- No `curl | bash`, no installer script.

## The agent runs as root

The Wazuh agent is a third-party program. Its package runs it as root, and eFa-next does not change that.
Everything else of eFa-next runs without root where possible.

## What eFa-next writes into ossec.conf

`wazuh-config` changes the manager address and port and the enrollment section in `<client>`,
and appends one block between the markers `BEGIN eFa-next managed block` and `END eFa-next managed block`.
Everything else in `/var/ossec/etc/ossec.conf` stays as it is. The block contains:

- `localfile` with `log_format json` for `/var/log/eFa/events.json`, only when `--events on`.
- `localfile` with `log_format syslog` for `/var/log/maillog`.
- File integrity monitoring (`syscheck`) of `/etc/eFa`, `/etc/postfix`, `/etc/rspamd/local.d`, `/etc/nginx`,
  hashes and attributes only (`report_changes="no"`), so no file content leaves the host.
- The SCA policy `/usr/share/eFa/wazuh/sca-efa-next.yml`.
- `<active-response><disabled>yes</disabled></active-response>` unless `--active_response on`.

The enrollment password is stored in `/var/ossec/etc/authd.pass`, mode 0640, owner root, group wazuh.
It never appears in a log, the audit log or the status.

### Active response

Active response lets the manager run commands on the agent, for example `firewall-drop`, at any time.
On eFa-next this is off by default, because a firewall change from outside can cut off mail or the admin access.
The firewall commands of Wazuh add single rules and do not reload firewalld (checked with 4.14.7),
but eFa-next has its own blocking with Fail2Ban and the firewall guard. Turn it on only if you need it.

## Events

`/var/log/eFa/events.json` holds one JSON object per line, written only while OTLP, the SIEM export or Wazuh reads it.
Mode 0640, group `wazuh` if that group exists, so the agent can read it.

Fields: `timestamp` (ISO 8601, UTC), `event`, `severity`, `user`, `src_ip`, `tenant`, `host`, `efa_version`,
and per event `service`, `command`, `count` or `repairs`. The JSON decoder of Wazuh files `user` under `dstuser`;
the rules use `$(dstuser)`.

Events with a rule: `login_ok`, `login_failed`, `ip_banned`, `ip_unbanned`, `service_down`, `service_up`,
`firewall_guard_repair`, `config_change`, `config_change_failed`, `virus_found`, `rbl_hits`, `audit_anchor`, `audit_mode_off`,
`audit_entry`, `four_eyes_request`, `console_2fa_failed`, `admin_network_bruteforce`, `web_lockdown`, `web_lockdown_end`,
`breakglass`, `cve_alert`, `security_floor_violation`, `security_floor_guard_error`, `os_check_failed`, `security_findings`,
`rspamd_module_failed`, `service_not_starting`, `service_sandbox_failed`, `setup_variant_set`, `setup_eu_locked`,
`cluster_mode`, `eu_transfer_confirmed`, `update_hook_refused`, `release_upgrade`, `retro_hit`, `dlp_match`, `link_blocked`,
`lookalike_certificate`, `sending_limit`, `feed_failed`, `blocklist_feed_failed`, `backup_upload_failed`, `queue_alarm`,
`destination_down`, `headers_disk_full`, `hourly_job_failed`, `monitor_cron_restored`, `cluster_update_stopped`, `update_fallback`, `tenant_limit`, `update_available`.

Events without a rule of their own (information only, they reach the manager as rule 108000): `otlp_test`,
`link_unchecked`, `bayes_active`, `bayes_inactive`, `dkim_provisioned`, `destination_up`, `tls_port25`,
`quarantine_released` and the other `quarantine_<state>` events (one row per mail).

## Manager side: decoders and rules

Copy these files to the Wazuh manager and restart it:

```
/usr/share/eFa/wazuh/efa-next_decoders.xml  ->  /var/ossec/etc/decoders/
/usr/share/eFa/wazuh/efa-next_rules.xml     ->  /var/ossec/etc/rules/
```

Rule IDs 108000-108099 and 108200-108299 (108100-108199 are the SCA checks). Every rule with a level above 0 carries the compliance groups that the Wazuh dashboards PCI DSS,
GDPR, HIPAA, NIST 800-53, GPG13 and TSC read. They are copied from the rule of the Wazuh ruleset 4.14 that is closest
to the eFa-next event (table below); the unit test `tests/test_wazuh_rules.py` fails if a rule with a level above 0 has
no `pci_dss_`, `nist_800_53_` or `tsc_` group, or matches an event or command that efactl does not have. The groups
name the topic of a control for the dashboards; they are no statement of conformity.

| ID | Level | Description | Tag set |
| --- | --- | --- | --- |
| 108010 | 3 | web login of $(dstuser) from $(src_ip) | AUTH_OK |
| 108011 | 5 | failed web login of $(dstuser) from $(src_ip) | AUTH_FAIL |
| 108012 | 10 | many failed web logins from $(src_ip) | AUTH_FAILS |
| 108013 | 6 | Fail2Ban banned $(src_ip) | BLOCK |
| 108014 | 3 | Fail2Ban released $(src_ip) | BLOCK |
| 108020 | 10 | service $(service) is down | SERVICE |
| 108021 | 3 | service $(service) runs again | SERVICE |
| 108022 | 8 | the firewall guard repaired the firewall | BLOCK |
| 108030 | 3 | $(dstuser) changed settings ($(command)) | CONFIG |
| 108031 | 5 | a change by $(dstuser) failed ($(command)) | CONFIG |
| 108040 | 7 | viruses found in mail | VIRUS |
| 108041 | 3 | mail refused by blocklists | INTRUSION |
| 108050 | 7 | configuration file $(file) changed | FIM |
| 108060 | 3 | signed daily anchor of the strict audit log written ($(day)) | LOG_OK |
| 108061 | 12 | strict audit log chain broken, the anchor of $(day) records the break | LOG_BAD |
| 108062 | 9 | $(dstuser) switched the strict audit mode off | LOG_BAD |
| 108063 | 3 | strict audit entry: $(action) by $(dstuser) | CONFIG |
| 108064 | 5 | strict audit entry not ok: $(action) by $(dstuser) | CONFIG |
| 108065 | 5 | $(dstuser) asked for a four-eyes change ($(command)) | PRIV |
| 108066 | 5 | wrong 2FA code of console admin $(dstuser) | AUTH_FAIL |
| 108067 | 10 | many wrong 2FA codes of console admin $(dstuser) | AUTH_FAILS |
| 108068 | 12 | login lockout: $(src_ip) blocked from the admin network after $(count) failures | AUTH_FAILS |
| 108069 | 12 | web admin lockdown ($(reason)) | BLOCK |
| 108070 | 3 | web admin lockdown ended | BLOCK |
| 108071 | 10 | break-glass admin: $(action) ($(service) from $(source)) | PRIV |
| 108072 | 13 | break-glass admin used: $(action) ($(service) from $(source)) | PRIV |
| 108073 | 12 | $(cve) affects $(package) $(installed), fixed in $(fixed) | VULN |
| 108074 | 12 | security floor violated by $(service) | ANOMALY |
| 108075 | 12 | security floor guard failed for $(service) | ANOMALY |
| 108076 | 8 | OS check found $(count) problems | ANOMALY |
| 108077 | 7 | security self-check found $(problems) new problems | ANOMALY |
| 108078 | 10 | rspamd modules not loaded: $(modules) | ANOMALY |
| 108079 | 8 | service $(service) does not start or its sandbox failed | SERVICE |
| 108080 | 8 | $(dstuser) changed users, roles or tenants ($(command)) | ACCOUNT |
| 108081 | 8 | $(dstuser) changed a credential, 2FA or API token ($(command)) | ACCOUNT |
| 108082 | 8 | $(dstuser) changed a security policy ($(command)) | CONFIG |
| 108083 | 5 | setup or cluster mode changed ($(event)) | CONFIG |
| 108084 | 6 | $(dstuser) confirmed a backup target outside the EU for $(domain) | CONFIG |
| 108085 | 8 | update hook refused: $(reason) | ANOMALY |
| 108086 | 3 | release upgrade finished | CONFIG |
| 108087 | 10 | release upgrade failed | SERVICE |
| 108088 | 7 | mail found malicious after delivery: $(message_id) | VIRUS |
| 108089 | 5 | outbound DLP rule hit ($(action), $(rules)) | INTRUSION |
| 108090 | 5 | a blocked link was clicked | INTRUSION |
| 108091 | 7 | look-alike domain certificate: $(domains) | INTRUSION |
| 108092 | 6 | sending limit hit by $(who) ($(action)) | INTRUSION |
| 108093 | 5 | threat feed update failed | FEED |
| 108094 | 7 | backup upload or restore test failed ($(target)) | SERVICE |
| 108095 | 7 | mail flow problem ($(event)) | SERVICE |
| 108096 | 5 | update or scheduled job problem ($(event)) | SERVICE |
| 108097 | 5 | tenant $(tenant) reached its $(limit) limit | SERVICE |
| 108098 | 3 | update available: $(version) | VULN |
| 108099 | 10 | security update available: $(version) | VULN |
| 108200 | 7 | $(count) configuration files changed outside efactl ($(files)) | FIM |

| Tag set | Copied from the Wazuh rule | Groups |
| --- | --- | --- |
| AUTH_OK | 5715 sshd: authentication success | `gdpr_IV_32.2,gpg13_7.1,gpg13_7.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.5,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3` |
| AUTH_FAIL | 5716 sshd: authentication failed | `gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3` |
| AUTH_FAILS | 5720 sshd: multiple authentication failures | `gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_SI.4,pci_dss_10.2.4,pci_dss_10.2.5,pci_dss_11.4,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3` |
| BLOCK | 651 host blocked by firewall-drop active response | `pci_dss_11.4,gpg13_4.13,gdpr_IV_35.7.d,nist_800_53_SI.4,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,tsc_CC7.4` |
| SERVICE | 506 Wazuh agent stopped (503 started) | `pci_dss_10.6.1,pci_dss_10.2.6,gpg13_10.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.6,nist_800_53_AU.14,nist_800_53_AU.5,tsc_CC7.2,tsc_CC7.3,tsc_CC6.8` |
| CONFIG | 2932 / 2933 yum package installed / updated (config_changed) | `pci_dss_10.6.1,pci_dss_10.2.7,gpg13_4.10,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.6,nist_800_53_AU.14,tsc_CC7.2,tsc_CC7.3,tsc_CC6.8,tsc_CC8.1` |
| ACCOUNT | 5904 information from the user was changed (5902 new user) | `pci_dss_10.2.7,pci_dss_10.2.5,pci_dss_8.1.2,gpg13_4.13,gdpr_IV_35.7.d,gdpr_IV_32.2,hipaa_164.312.b,hipaa_164.312.a.2.I,hipaa_164.312.a.2.II,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_AC.2,nist_800_53_IA.4,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3` |
| PRIV | 5402 successful sudo to root | `pci_dss_10.2.5,pci_dss_10.2.2,gpg13_7.6,gpg13_7.8,gpg13_7.13,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_AC.6,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3` |
| VIRUS | 52502 ClamAV: virus detected | `pci_dss_5.1,pci_dss_5.2,pci_dss_11.4,gpg13_4.2,gdpr_IV_35.7.d,nist_800_53_SI.3,nist_800_53_SI.4,tsc_A1.2,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3` |
| FEED | 52509 ClamAV: could not download the definition update | `pci_dss_5.2,pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SI.3,nist_800_53_SI.4,tsc_A1.2,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3` |
| FIM | 550 integrity checksum changed (553, 554) | `pci_dss_11.5,gpg13_4.11,gdpr_II_5.1.f,hipaa_164.312.c.1,hipaa_164.312.c.2,nist_800_53_SI.7,tsc_PI1.4,tsc_PI1.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3` |
| LOG_OK | 591 log file rotated | `pci_dss_10.5.2,pci_dss_10.5.5,gpg13_10.1,gdpr_II_5.1.f,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.9,tsc_CC6.1,tsc_CC7.2,tsc_CC7.3,tsc_PI1.4,tsc_PI1.5,tsc_CC7.1,tsc_CC8.1` |
| LOG_BAD | 592 log file size reduced | `pci_dss_10.5.2,pci_dss_11.4,gpg13_10.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.9,nist_800_53_SI.4,tsc_CC6.1,tsc_CC7.2,tsc_CC7.3,tsc_CC6.8` |
| ANOMALY | 80711 auditd: process ended abnormally (audit_anom) | `pci_dss_10.6.1,pci_dss_11.4,gdpr_IV_30.1.g,gdpr_IV_35.7.d,gpg13_4.14,hipaa_164.312.b,nist_800_53_AU.6,nist_800_53_SI.4,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3` |
| INTRUSION | 5705 / 5706 sshd: possible scan or break-in attempt | `gdpr_IV_35.7.d,gpg13_4.12,nist_800_53_SI.4,pci_dss_11.4,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3` |
| VULN | own choice: the vulnerability rules 23502-23506 of Wazuh 4.14 carry no compliance groups | `pci_dss_6.2,pci_dss_11.2.1,gdpr_IV_35.7.d,nist_800_53_SI.2,nist_800_53_RA.5,tsc_CC7.1` |

Rules 108080-108082 are children of 108030 (settings changed): they raise the level for the efactl commands that change
users, roles and tenants, credentials, 2FA and API tokens, and security policies (login lockout, four eyes, admin
access, admin idle timeout, strict audit mode, SSH root login, firewall, password check).

SCA check IDs 108100-108199: SSH root login with a password, rspamd and ClamAV not as root,
web interface not as root, nginx TLS 1.2/1.3 only, Postfix without SSLv2/SSLv3, eFa-next settings not world-readable.
Each check has a `compliance` section in the format of the Wazuh SCA policies (`nist_sp_800-53`, `pci_dss_v4.0`, `hipaa`,
`soc_2`, `gdpr`). No `cis` ids: the checks are eFa-next's own and not the same as a CIS recommendation (108100 allows a
root login with a key, CIS AlmaLinux 9 asks for none).

## Without an agent: syslog to the manager

`efactl siem-set` forwards mail log, audit log, firewall log and events over syslog.
On the manager, a `<remote>` section with `<connection>syslog</connection>`, the port and `<allowed-ips>` of the eFa-next host takes it.
Use format `json` or `rfc5424`; the events arrive with the tag `efa-events`, which the decoder `efa-events` reads.
