# Disclaimers: templates, ZIP and API

eFa-next adds one disclaimer to each outgoing mail (mail of logged in users and of the relay networks), in its own milter
before the mail is signed. Signed or encrypted mail stays as it is, and a reply that quotes the disclaimer does not get it twice.

## Which one a mail gets

A template is for all domains (`global`), a `tenant`, a `domain`, or a `group` of senders in a domain. The most specific
template that fits the sender wins: group, then domain, then tenant, then all domains; within a level the lowest priority,
then the id. A template can have a start and an end date. `efactl disclaimer-which --sender anna@example.org` shows the one a
sender gets.

Groups are eFa-next group names or `ldap:<DN of a directory group>`. Their members are read when a template is saved and when
the outbound settings are written; the mail flow never waits for the directory. If the directory does not answer, the last
known members stay.

Who may change: all domains only the main admin; a tenant its admins; a domain and its groups the admins of the domain.

## Formats

- `text`: the text at the end of the text part; HTML parts get it as HTML.
- `html`: the HTML at the end of the HTML part, the text version (body.txt, or made from the HTML) at the end of the text part.
  Pictures come with the template and are named in the HTML as `src="cid:<file name>"` (or the name without its ending).

Allowed: pictures png, jpg, gif; attachments png, jpg, gif, pdf, vcf. The content must match the ending. SVG is refused, as
it can carry script. HTML may not hold script, frames, forms, style or meta tags, event handlers, javascript: links or
pictures from the internet; links only https:, mailto: and tel:.

## Signatures from the directory (AD signatures)

The text and the HTML of a template may hold placeholders that are filled for each sender from LDAP or Active Directory:

`{{name}}` (displayName), `{{first}}`, `{{last}}`, `{{title}}`, `{{department}}`, `{{company}}`, `{{phone}}`, `{{mobile}}`,
`{{fax}}`, `{{street}}`, `{{postcode}}`, `{{city}}`, `{{country}}`, `{{mail}}`, `{{web}}`.

    Regards
    {{name}}
    {{title}}, {{department}}
    Mobile: {{mobile}}

- **Filling:** in HTML templates the values are escaped. A field the sender has not stays empty. A line whose fields are all
  empty (such as `Mobile: {{mobile}}` without a mobile number) goes away.
- **Switching on:** `efactl signature-set --mode on` (Disclaimers, AD signatures). It needs a login directory (global or of a
  tenant).
- **Reading the directory:** once an hour, and with `signature-sync`. It reads the users with a mail address of the own domains,
  with paged results for large directories. A mail never waits for the directory.
- **Storage:** the fields are kept for efa-outbound only, as a systemd credential. The milter starts again only when the fields
  changed.

## The ZIP

```
manifest.json
body.html        (format html)
body.txt         (format text; with html: the text version, optional)
media/logo.png   (pictures for the HTML)
attachments/card.vcf
```

manifest.json:

```json
{"id": "sales-de", "name": "Sales Germany", "scope": "group", "target": "example.org", "groups": ["ldap:CN=Sales,OU=Groups,DC=example,DC=org"],
 "format": "html", "priority": 10, "enabled": true, "valid_from": "2026-12-01", "valid_until": ""}
```

`target` is the domain (domain, group) or the tenant name (tenant), empty for global. Limits: 50 files, 5 MB unpacked, 2 MB per
file, no paths outside the folders above, no links, no encrypted entries, no entries packed more than 100 times. A ZIP is
checked whole; if one part is wrong, nothing changes.

```
efactl disclaimer-import --file sales-de.zip --dry_run on     # only check and show
efactl disclaimer-import --file sales-de.zip
efactl disclaimer-export --id sales-de --file sales-de.zip
efactl disclaimer-restore --id sales-de                        # the version before (the last three are kept)
```

In the web interface: page *Disclaimers*, card "Disclaimer: import a ZIP", with "Only check and show" on by default.

## API (port 8463)

The same port, certificate pin and login as the DKIM provisioning (docs/api-dkim-provisioning.md): the client certificate of
the source AND its bearer token, its allowed addresses, its calls per minute (429 with Retry-After), Fail2Ban after failed
logins. A source needs the right `disclaimer`:

```
efactl dkim-source-set --name hr-system --cert hr.crt --domains example.org --rights disclaimer
```

A source sets only templates of its own domains, or of a tenant all of whose domains are its own; never one for all domains,
and never one that the admins or another source made (409).

| Call | Body | Answer |
|---|---|---|
| `GET /api/v1/disclaimer` | | 200, the templates of this source |
| `GET /api/v1/disclaimer/<id>` | | 200, or 404 |
| `PUT /api/v1/disclaimer/<id>` | the ZIP, up to 5 MB; the id in manifest.json must be `<id>` | 200, 400 (ZIP refused, with the reason), 403, 409, 413 |
| `DELETE /api/v1/disclaimer/<id>` | | 200, or 404 |

```
curl --cert hr.crt --key hr.key --cacert efa-8463.crt -H "Authorization: Bearer $TOKEN" \
     -X PUT --data-binary @sales-de.zip -H 'Content-Type: application/zip' \
     https://mx.example.org:8463/api/v1/disclaimer/sales-de
```

Every call goes into the audit log of eFa-next. In a cluster the master takes the calls and hands the disclaimer folder to the
nodes.
