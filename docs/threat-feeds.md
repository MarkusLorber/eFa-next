# Threat feeds (STIX/TAXII, MISP, abuse.ch)

Under Blocklists, Threat feeds (12, N1, 5v c). Off until a feed is added with its terms confirmed.

- Presets: **urlhaus** (abuse.ch URLhaus, URLs that spread malware, CC0) and **threatfox** (abuse.ch ThreatFox, indicators of
  the last 48 hours, CC0): `efactl feed-set --name urlhaus --action add --accept_terms yes`.
- Own feeds over HTTPS: `--kind stix` (a TAXII 2.1 collection, `.../collections/<id>/objects/`, or a STIX 2.1 bundle; key as
  `user:password` or a token), `--kind misp` (the restSearch of a MISP instance with its API key: URLs, domains, SHA-256 and
  destination IPs marked for IDS of the last 7 days), `--kind list` (one value per line). Keys are stored for root only.
- Every hour the job fetches what changed (ETag, If-Modified-Since), at most 50 MB a feed, and builds four lists of all feeds
  that are on: URLs, domains, SHA-256 of files, IP addresses. rspamd reads them as file maps and loads a list again only when it
  changed; there is no reload. `efactl feeds-run` fetches at once.
- Hits: `EFA_FEED_URL` (8), `EFA_FEED_DOMAIN` (6), `EFA_FEED_SHA256` (15, an attachment of a feed is rejected), `EFA_FEED_IP` (5).
- Nothing goes out to a feed but the request itself: no addresses, no mail data.

The retrospective check of delivered mail against new feed data (5v j) and the pull-back of mail (N6) come with block 5.
