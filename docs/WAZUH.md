# Wazuh and eFa-next

eFa-next can install, connect, update and remove the Wazuh agent, on the web page **Wazuh** or with efactl.
Everything is off by default; an upgrade of eFa turns nothing on.

## Commands

| Command | What it does |
|---|---|
| `efactl wazuh-status` | Installed version, running, connection to the manager, last keep-alive, eFa block present. |
| `efactl wazuh-check [--version V]` | Downloads the package and checks signature and package scripts, installs nothing. |
| `efactl wazuh-install [--version V] --confirm yes` | Installs the agent. It starts only after `wazuh-config`. |
| `efactl wazuh-config --manager M [--port 1514] [--enrollment_port 1515] [--agent_name N] [--groups a,b] [--events on/off] [--active_response on/off]` | Writes the manager and the eFa block, asks the enrollment password twice (empty keeps it), restarts the agent. |
| `efactl wazuh-service --action start/stop/restart` | Starts, stops or restarts the agent. |
| `efactl wazuh-update [--version V] --confirm yes` | Updates the agent, with the same checks as the install. |
| `efactl wazuh-remove [--repo yes] --confirm yes` | Stops and removes the agent and the eFa block; the repository only with `--repo yes`. |

All of them are for the super-admin only.

## An agent that eFa did not install

If a `wazuh-agent` is installed and eFa did not install it (no `"managed": true` in `/etc/eFa/wazuh.json`),
the page shows "Agent present, not managed by eFa" and only its status.
`wazuh-config`, `wazuh-service`, `wazuh-update` and `wazuh-remove` refuse to act on it.
eFa takes it over only with `efactl wazuh-config --adopt yes --confirm yes` (or the same on the web page),
never by itself and never with an upgrade.

## Install and updates

- Source: the official repository `https://packages.wazuh.com/4.x/yum/`, written to `/etc/yum.repos.d/wazuh.repo` with `enabled=0`.
  So `dnf upgrade`, `dnf-automatic` and the eFa update never touch the agent: it is updated only with `wazuh-update`.
- The signing key is downloaded and imported only if its fingerprint is `0DCF CA55 47B1 9D2A 6099 5060 96B3 EE5F 2911 1145`.
- The package is downloaded first and checked: `rpm -K` must say the signatures are OK,
  and its scripts must not call `firewall-cmd`, `firewalld`, `iptables` or `nft`. Otherwise nothing is installed.
  A `firewall-cmd --reload` from a package script once cut off a test host, so this check is strict.
- No `curl | bash`, no installer script.

## The agent runs as root

The Wazuh agent is a third-party program. Its package runs it as root, and eFa does not change that.
Everything else of eFa runs without root where possible.

## What eFa writes into ossec.conf

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
On eFa this is off by default, because a firewall change from outside can cut off mail or the admin access.
The firewall commands of Wazuh add single rules and do not reload firewalld (checked with 4.14.7),
but eFa has its own blocking with Fail2Ban and the firewall guard. Turn it on only if you need it.

## Events

`/var/log/eFa/events.json` holds one JSON object per line, written only while OTLP, the SIEM export or Wazuh reads it.
Mode 0640, group `wazuh` if that group exists, so the agent can read it.

Fields: `timestamp` (ISO 8601, UTC), `event`, `severity`, `user`, `src_ip`, `tenant`, `host`, `efa_version`,
and per event `service`, `command`, `count` or `repairs`. The JSON decoder of Wazuh files `user` under `dstuser`;
the rules use `$(dstuser)`.

Events: `login_ok`, `login_failed`, `ip_banned`, `ip_unbanned`, `service_down`, `service_up`,
`firewall_guard_repair`, `config_change`, `config_change_failed`, `virus_found`, `rbl_hits`, `otlp_test`.

## Manager side: decoders and rules

Copy these files to the Wazuh manager and restart it:

```
/usr/share/eFa/wazuh/efa-next_decoders.xml  ->  /var/ossec/etc/decoders/
/usr/share/eFa/wazuh/efa-next_rules.xml     ->  /var/ossec/etc/rules/
```

Rule IDs 108000-108099:

| ID | Level | Event |
|---|---|---|
| 108010 | 3 | Web login ok |
| 108011 | 5 | Web login failed |
| 108012 | 10 | 8 failed logins from one address in 2 minutes |
| 108013 / 108014 | 6 / 3 | Fail2Ban ban / release |
| 108020 / 108021 | 10 / 3 | Service down / up again |
| 108022 | 8 | Firewall guard repaired the firewall |
| 108030 / 108031 | 3 / 5 | Settings changed / change failed |
| 108040 / 108041 | 7 / 3 | Viruses found / blocklist hits |
| 108050 | 7 | A watched configuration file changed (FIM) |

SCA check IDs 108100-108199: SSH root login with a password, rspamd and ClamAV not as root,
web interface not as root, nginx TLS 1.2/1.3 only, Postfix without SSLv2/SSLv3, eFa settings not world-readable.

## Without an agent: syslog to the manager

`efactl siem-set` forwards mail log, audit log, firewall log and events over syslog.
On the manager, a `<remote>` section with `<connection>syslog</connection>`, the port and `<allowed-ips>` of the eFa host takes it.
Use format `json` or `rfc5424`; the events arrive with the tag `efa-events`, which the decoder `efa-events` reads.
