# Users & access

## Users

Local users (password twice, at least 12 characters), or users of LDAP/Active Directory or OIDC. A user can be in several groups; the permissions add up. *Lock* logs a user out within 15 seconds; their API tokens stop. The top right always shows who is logged in, with the role; its menu holds *My account* and *Log out*. *My account* holds your own name, phone, email address (it counts once a link to it is clicked), password and 2FA, and lists your sessions, also on other devices, and ends them. Address, password and 2FA ask your password again, with the current 2FA code if one is set up.

![Users](images/users.png)

### Single sign-on in the user portal

The user portal can use the same OIDC provider (globally or of a tenant), with a redirect address of its own:
`https://<host>/portal/login/oidc/callback`, registered at the provider and set as *User portal: redirect address* next to the
single sign-on settings (`efactl oidc-set ... --portal_redirect_uri=...`, `tenant-oidc-set` for a tenant). Without it the portal
keeps password, login link and passkey. A portal login takes the mail address only when the provider marks it as checked
(`email_verified`), only of a domain of this server (of the tenant, when its provider answered), as a user of the role *user*
bound to the issuer and subject of the provider. An address that an admin account has as its name or its e-mail (any case,
also of a tenant) logs in at the admin interface, never in the portal; the same for a login link.
The second factor is the one of the provider. Off until the redirect address is set.

## Groups and permissions

Each action needs one permission, for example `quarantine.release` or `domain.dkim`. A group holds permissions and a scope: global, some tenants, or some domains.

| Predefined group | For |
|---|---|
| super admin | everything, in all tenants |
| tenant admin | one tenant: quarantine, mail log, reports, users, settings of its domains |
| domain admin | one domain: quarantine, mail log, reports, its settings and users |
| domain manager | the settings and users of its domains |
| helpdesk | reads and works on the quarantine; without tenant or domain for the whole system |
| read-only | reads, changes nothing, no mail content |
| auditor | the audit log, users and reports |
| user | the own mailbox: held mail and digest |

Predefined groups cannot be changed; copy one and change the copy. Nobody can hand out a permission or scope they do not have, change their own groups, or remove the last super admin. *Directory groups* map groups of LDAP or OIDC to eFa-next groups.

![Groups](images/groups.png)

## Security

Root login through SSH (warns, and refuses to turn it off unless another admin can log in), Fail2Ban, the admin address, the rspamd web interface, the firewall allowlist for SSH and web (reverts after 5 minutes unless you confirm), the firewall guard and the firewall test.

![Security](images/sec.png)
