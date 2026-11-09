# DKIM provisioning API

Another system that signs mail for some domains (a DKIM signer behind or beside eFa-next, such as a signing service of an Exchange
organisation) can hand its DKIM keys, its key rotation and its DNS records to eFa-next. For those domains the delivered data wins:
eFa-next signs with the delivered keys, or not at all, and its own DKIM settings for them can only be read.

Off by default. Nothing changes for a domain until a source delivers it.

## How it works

1. The admin of eFa-next registers a **source**: a name, its client certificate (eFa-next shows its fingerprint), a token and the
   domains it may deliver.
2. The source sends the state of a domain over HTTPS with its client certificate and its token. eFa-next checks both, the domain,
   the version and the keys, stores the keys like its own DKIM keys and answers with the public state.
3. From then on the domain is **managed externally**: in the web interface, efa-tui and efactl its DKIM, ARC key and rotation
   settings show `managed externally by <source>, read only`; eFa-next generates and rotates no keys for it.
4. A new key of the source takes over at its `valid_from`, but only once at least as many configured DNS resolvers show its
   DNS record as the rotation of eFa-next needs (default 2, *DKIM: Rotation → DNS servers*). Until then the old key stays and
   eFa-next warns once a day, as its own rotation does.
5. A super-admin can take the domain back (*DKIM: Managed externally → Take over*, with a confirmation and an audit entry), or the
   source deletes it. The keys stay; eFa-next manages them from then on.

In a cluster only the master takes these calls; it hands the keys to the nodes like its own (9b).

## Security

| | |
|---|---|
| Transport | HTTPS only, TLS 1.2 or newer, on its own port **8463**, with a long-lived certificate of eFa-next itself (not the Let's Encrypt one), so a pin on it stays valid. |
| Who | Mutual TLS: the client certificate must be the registered certificate of a source (eFa-next shows its SHA-256 fingerprint). A self-signed certificate is fine. An unknown certificate fails already in the TLS handshake; no certificate gets 401. |
| And | `Authorization: Bearer <token>` of that source. The token is stored as a hash; it is shown once, when it is made. |
| Where from | Optional: allowed addresses per source; the firewall opens 8463 only for them. |
| How often | At most 600 calls per minute and source by default, settable per source (60, 120, 300, 600 or 1200); more get 429 with a `Retry-After` header (seconds). A `POST /` with many domains counts as one call. Before the login a strict limit per address applies: 30 failed logins in a minute, then Fail2Ban bans the address. |
| What | A source may deliver only its own domains (or those of its tenant). |
| Keys | Private keys are never returned: GET answers with the public data and the state. They are stored like the own DKIM keys (mode 0600, group of rspamd) and never written to a log. |
| Trace | Every call goes to the audit log; every change also as the event `dkim_provisioned` (SIEM, OpenTelemetry, Wazuh). |

## Set it up on eFa-next

```
efactl dkim-provision-set --mode on
efactl dkim-source-set --name signer-1 --cert signer-1.crt --domains example.org,example.com --addresses 192.0.2.20 --rate 600
```

`dkim-source-set` prints the token once. A source has the right `dkim` unless `--rights` says otherwise; `--rights disclaimer`
lets it deliver disclaimers instead (docs/api-disclaimer.md), `--rights dkim,disclaimer` both. `efactl dkim-provision-status` shows the SHA-256 fingerprint of the server certificate of
port 8463 for the pin in the source. In the web interface: *DKIM, ARC & DMARC → Managed externally*. Open port 8463 in the
firewall only for the addresses of the sources.

The source makes its certificate itself and gives eFa-next the `.crt` file (never the key), for example:

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 -subj "/CN=signer-1" -keyout signer-1.key -out signer-1.crt
openssl x509 -in signer-1.crt -noout -fingerprint -sha256
```

## Calls

Base address: `https://<efa-next>:8463/api/v1/dkim/provision`

| Call | What |
|---|---|
| `GET /` | All domains of this source with their state. |
| `GET /<domain>` | The state of one domain. |
| `PUT /<domain>` | The full state of one domain. The same version again changes nothing. |
| `POST /` | Several domains at once: `{"domains": [<domain state>, ...]}`, each checked on its own, at most 500 domains. |
| `DELETE /<domain>` | The source gives the domain back; eFa-next manages its keys from then on. |

### The state of a domain (PUT body)

```json
{
  "domain": "example.org",
  "version": 17,
  "mode": "sign_here",
  "selectors": [
    {"selector": "s2026a", "type": "rsa", "private_key": "-----BEGIN PRIVATE KEY-----\n...",
     "valid_from": "2026-06-01T00:00:00Z", "valid_until": "2026-12-31T23:59:59Z"},
    {"selector": "s2026b", "type": "ed25519", "private_key": "-----BEGIN PRIVATE KEY-----\n...",
     "valid_from": "2026-12-01T00:00:00Z"}
  ],
  "dns": {
    "dkim": {"s2026a._domainkey.example.org": "v=DKIM1; k=rsa; p=MIIB..."},
    "spf": "v=spf1 mx include:_spf.example.org -all",
    "dmarc": "v=DMARC1; p=reject; rua=mailto:dmarc@example.org"
  },
  "checksum": "sha256:9f2c..."
}
```

| Field | |
|---|---|
| `domain` | Must match the address and be one of the domains of the source. |
| `version` | Whole number. Higher than the stored one: applied. Equal: nothing changes (200). Lower: refused (409). |
| `mode` | `sign_here`: eFa-next signs with these keys. `signed_downstream`: the source signs, eFa-next does not (no second signature). |
| `selectors` | For `sign_here` at least one. `type` `rsa` (2048, 3072 or 4096 bits) or `ed25519`; `private_key` PEM (PKCS#8 or PKCS#1). `valid_from` / `valid_until` in UTC. With RSA and Ed25519 valid at once, eFa-next signs with both. |
| `dns.dkim` | The DKIM records the source has published: eFa-next compares them with the real DNS and with the keys. |
| `dns.spf`, `dns.dmarc` | Optional, for display and the check against the real DNS only; eFa-next changes no DNS. |
| `checksum` | SHA-256 over the body without this field, keys sorted, no spaces (`json.dumps(body, sort_keys=True, separators=(',', ':'))`). |

### Answer

```json
{"domain": "example.org", "version": 17, "mode": "sign_here", "managed_by": "signer-1",
 "active": [{"selector": "s2026a", "type": "rsa", "bits": 2048, "public_key": "MIIB...", "dns_visible": 2}],
 "waiting": [{"selector": "s2026b", "type": "ed25519", "valid_from": "2026-12-01T00:00:00Z", "dns_visible": 0}],
 "dns_check": {"dkim": "ok", "spf": "differs", "dmarc": "ok"}, "warnings": ["SPF in DNS differs from the delivered record."]}
```

### Errors

| Code | When |
|---|---|
| 400 | The body is no valid JSON, a field is missing or wrong, a key cannot be read, a key is too short, or the checksum does not match. |
| 401 | No client certificate, an unknown certificate, no token or a wrong token. |
| 403 | The domain is not one of this source, the address is not allowed, or the provisioning is off. |
| 404 | `GET` or `DELETE` of a domain this source has not delivered. |
| 409 | The version is lower than the stored one. |
| 413 | The body of a `PUT` is larger than 1 MB, the body of a `POST /` larger than 2 MB, or a `POST /` has more than 500 domains. |
| 429 | More calls in a minute than the limit of the source (default 600). The `Retry-After` header says how many seconds to wait. |

Each error answers `{"error": "<text>"}`; the text never holds a key.

Clients with many domains should use `POST /` and follow `Retry-After`.

## Examples

```
B=https://efa-next.example.org:8463/api/v1/dkim/provision
AUTH="--cert signer-1.crt --key signer-1.key -H Authorization:Bearer\ $TOKEN"

curl -sS $AUTH -X PUT -H 'Content-Type: application/json' --data @example.org.json $B/example.org
curl -sS $AUTH $B/example.org
curl -sS $AUTH $B/
curl -sS $AUTH -X DELETE $B/example.org
```

Add `--cacert efa-next.crt` while eFa-next has a self-signed certificate.

## Rotation through the source

Deliver the next key early, with a `valid_from` in the future, and publish its DNS record at once. eFa-next shows it under
*waiting* with the number of resolvers that see it, takes it over at `valid_from` once enough of them do, and signs with the old key
until then. Remove an old selector from the state only after its `valid_until`; its DNS record can go a few days later, so mail in
transit still verifies.

## Not part of eFa-next

A sender for a particular signing product is not part of this package: any system that can make the calls above can be a
source.
