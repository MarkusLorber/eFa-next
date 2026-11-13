# 18. Troubleshooting

## Where to look

| What | Where |
|---|---|
| State of the services and what needs attention | the dashboard (chapter 4), `sudo efactl status` |
| One mail | *Mail log*, its details at the side (chapter 5) |
| Mail that waits | *Mail queue*, or `mailq` on the console |
| Who changed what | *Users › Audit log*, `/var/log/eFa/` |
| Postfix | `/var/log/maillog` |
| Services | `journalctl -u postfix -u rspamd -u clamd@scan -u efa-web -u unbound` |
| Install | `/var/log/eFa/eFa-install.log`, `journalctl -u efa-install` |
| Release upgrade | `/var/log/eFa/release-upgrade.log`, `efactl release-upgrade-status` |

## Common problems

**Mail does not arrive.** Search it in the mail log. There, with which result? Open its details for the checks. Not there at
all: the sending server did not reach eFa-next; check the MX record of the domain and run the firewall test
(*Security › Firewall test*).

**Mail waits in the queue.** *Connection refused* or a timeout towards your mail server: check the destination under
*Mail routing* and the DNS of its name (internal zones, chapter 10).

**A good mail was rejected or held.** Release it from *Held mail* or *Quarantine*. For the future allow the sender (sender menu
or *Sender lists*), or set a *Rule* for that recipient.

**Many mails get no action.** With greylisting off and its score below the spam marking, mail in between gets no action; the
dashboard names that gap (chapter 6).

**The blocklists answer nothing or refuse.** The blocklist page names the reason of Spamhaus (open resolver, too many queries).
Keep the own Unbound without forwarders, or set a Spamhaus DQS key.

**The page says "Not allowed".** Your groups do not hold that permission. *Users › Users: effective permissions* shows what a
login has and where.

**A setting does not apply to a domain.** *Domain settings › show with their source*: a value of the domain or its tenant may
win over the global one.

**A red banner at the top.** The attack alert names what it found and links to the page that helps (chapter 4).

## Locked out

| Situation | Way back in |
|---|---|
| An unconfirmed firewall or interface change | wait 5 minutes, or `sudo efactl firewall-revert` / `interface-revert` |
| Web admin password forgotten | `sudo efactl admin-password` on the console |
| 2FA device lost | a recovery code, or the resets in chapter 3 |
| Address locked after failed logins | wait for the ban to end; `efactl cluster-unban --address <ip>` in a cluster |
| Setup code lost | `sudo systemctl restart efa-init`, then `sudo cat /run/efa-init/setup-code` |

## Ask for help

- Questions and problems: [SUPPORT.md](../../SUPPORT.md).
- A security problem: never as a public issue, see [SECURITY.md](../../SECURITY.md).
- More answers: [FAQ](../faq.md).

Back: [Manual](README.md)
