# Cluster

One master, any number of nodes. What is set on the master applies to all nodes, automatically.

## Modes

| Mode | Settings | When the master is down |
|---|---|---|
| Single host | not in a cluster (default) | – |
| `master-client` | only on the master; a client refuses a change and shows "Managed by &lt;master&gt;" | the clients filter on with the last settings |
| `ha` | on every node: a node hands the change to the master, which runs it and hands it to all; the order of the master decides, so the last change wins, each one in the audit log of the master with the node and user | the nodes filter on with the last settings; changes wait until the master is back |

In both modes bans, the overview of mail log, queues and quarantine, and the actions on a mail of a node go through the master; in
`ha` a node shows them too. Set the mode with `efactl cluster-init --mode ha` or later on the master:

```
efactl cluster-mode-set --mode ha --confirm yes
```

Each node sees the new mode within a minute and takes all settings anew (`cluster-resync`).

## Setting up

On the master:

```
efactl cluster-init --name mx-01
efactl cluster-token
```

On each node, with the token and the CA fingerprint of `cluster-token`:

```
efactl cluster-join --master mx-01.example.org:8460 --name mx-02 --address 192.0.2.12 --ca_fingerprint <fingerprint>
```

Joining takes a snapshot of the master once. After that the node follows the journal of the master over mutual TLS (port 8460).

## What is shared

- The eFa settings in `/etc/eFa` (except the files of the host below), rspamd `local.d` and `override.d`, DKIM and ARC keys.
- The Postfix tables: access, helo_access, sender_canonical, transport, relay domains, header checks and the other rule tables.
- The rule parts of `main.cf` and the eFa-next services in `master.cf`.
- The content rules (`/etc/efa-web/content.json`), the users, groups, roles and scoped settings.
- Bans of Fail2Ban, in both directions. Protected networks are never banned.
- The sending limits (A1, 8g): every half minute each node reports to the master how many recipients and which target domains
  each sender, sender domain and tenant had in the running hour, and takes the counts of all other nodes back into its Redis.
  A sender whose mail is spread over the nodes is counted as one: the limit holds for the cluster, at most half a minute late.
  A target domain reached through two nodes counts once (up to 150 target domains per sender and node are sent by name). A
  report older than two minutes no longer counts; while the master is not reached, each node counts only its own mail, as
  without a cluster. Which senders are held stays per node: each node holds a sender over the limit when it next sends there.

## Downloads only on the master (6.0.0.6)

Download-only data is fetched by the master alone; the nodes never download it themselves. In 6.0.0.6 this covers the
ClamAV signatures of Sanesecurity, URLhaus, InterServer and SecuriteInfo (the job of the Sanesecurity signatures).

- **Master:** the job runs as on a single host (with the limits of the SecuriteInfo tier). After each round it lists the files
  with size and SHA-256 in `/var/lib/eFa/cluster-manifest.json` (root, 0600) and, when something changed, writes one entry
  into the cluster journal. The manifest has file names, sizes and hashes only: no address, no account ID, no key.
- **Transfer:** a node takes the entry within half a minute and fetches the files it lacks from the master over the cluster
  port with mutual TLS (`GET /v1/manifest`, `GET /v1/file?kind=clamav&name=...`). The master serves only names of its current
  manifest, plain names in the signature folder, regular files and no links; other requests and members without a
  certificate of the cluster are refused. After its start a node asks once for what it lacks.
- **Node:** a file is swapped in only when its size and SHA-256 match the manifest and clamscan loads it; it is written next
  to the others and replaced atomically, then clamd reloads. A failed file keeps the old one. Files the master no longer
  lists go. The page says "Signatures from the master, last received <time>", or "waiting for the master" until the first
  complete transfer; the dashboard names a node that waits or whose last transfer failed. The download settings of
  SecuriteInfo (tier, URLs, account ID) are set on the master only.
- **Also from the master:** the RDAP list of IANA (BEC, young domains), the lookalike domains of crt.sh (only the master asks
  crt.sh for the own names), the exploited list of EUVD (CVE watch) and the threat feeds (the four rspamd maps). A map is
  checked line by line, a JSON file must load; the files are replaced atomically and rspamd reads them as on the master.
  The cards of a node say "From the master, last received <time>" or "waiting for the master". OVAL and the signed CVE feed
  of eFa-next stay on each host.
- **IP blocklists:** only the master fetches the feeds. A node gets the lists (public addresses and networks only, checked
  line by line) and loads them into its own table `efa_block` in one nft transaction, as the master does; the firewall
  itself stays on each host and is never reloaded. If nft refuses, the loaded lists stay.
- **Official ClamAV databases:** while the master answers, a node stops and disables freshclam (marked in
  `/var/lib/eFa/freshclam-off-in-cluster`) and gets `main`, `daily` and `bytecode` (`.cvd`/`.cld`) from the master, each
  checked by clamscan before it is swapped in; clamd reloads as before. The master tells the nodes within half a minute
  after freshclam changed a file. An official database is removed on a node only when the master has it in its other form.
  In fallback, after leaving the cluster or as master, freshclam runs again, but only if eFa-next had turned it off.
  Transfers run on their own, so the poll of the journal goes on; a failed one is tried again every ten minutes.
- **Master out of reach:** after a grace time per source (`SYNC_SOURCES` in efactl: twice the interval, at least two hours)
  a node downloads the public sources itself, with the same code and the same checks as the master, and the dashboard says
  "Master not reachable since <time>: this node downloads the public sources itself". Never SecuriteInfo or threat feeds of
  kind STIX or MISP (they may need a key): their last files stay. Once the master answers again the node stops, takes the
  files of the master at once and notes it in the audit log, as it noted the start.
- **Lookalike alerts once:** while the master answers, only the master asks crt.sh and mails the admins. A node in fallback
  notes what it finds (with the time) and shows it on its dashboard, but sends nothing. After a day without the master the
  first node of the list the master last handed on (`/v1/manifest`) sends the alerts alone; the nodes cannot reach each
  other (each knows only the certificate of the master), so if that node is down too the findings stay on the dashboards.
  Back with the master, a node hands its findings to it (`POST /v1/lookalike`); the master keeps them and alerts once per
  domain, only for domains it did not know and no node had sent.
  Timeline of a master outage: for the first two days (the grace time of crt.sh) no node asks crt.sh, so there are no new
  findings and no mail; the lookalike map of the master stays in use. From then on the nodes ask crt.sh themselves and show
  new findings on their dashboards; the first warning mail comes from the first node of the list, so about two days after
  the master went away.
- **Keys:** the API keys of threat feeds stay on the master too: `feed-set` goes into the journal without them, and the
  upgrade removes them from older journal entries and from the nodes.

## What stays on each host

Only the identity of the host: host name and HELO name, own addresses and `inet_interfaces`, certificates and keys of TLS, the cluster role, the machine ID, the SSH host keys and session secrets. Firewall, network, update, backup and Wazuh commands always run on their own host only.

A shared Postfix table that names the master (for example `helo_access` with the own host name) names the node on the node: the snapshot replaces the host name of the master with the host name of the node.

## Values for one node only

A value that must differ on one node goes into `/etc/eFa/local.d/`. Nothing in that folder is shared, and a resync does not touch it.

- `/etc/eFa/local.d/content.json`: placed over the shared content settings, key by key. Example, the address of the checked links on this node:

```
{"links": {"base": "https://mx-02.example.org/l"}}
```

The node applies it after each snapshot and after each change of the content settings from the master.

## When the master is gone

The nodes go on filtering with the last settings and count sending limits on their own; each one shows "Cluster master … not reachable since …" on its dashboard. No node
takes over by itself: with two nodes, both would become master. When the master is gone for good:

1. On one node: `efactl cluster-promote --confirm yes`. It checks three times that the old master does not answer, keeps its old
   cluster folder, and becomes the master of a new cluster with a new CA of its own (the CA key stays in one place).
2. On each other node: `efactl cluster-leave --confirm yes`, then `efactl cluster-join` with a token of the new master.
3. The old master, once it is back: `efactl cluster-leave --confirm yes` before it joins the new master. Until then it sees itself as
   master of a cluster without nodes.

## Security

TLS 1.3 with mutual certificates between the nodes, an own key per node, the certificate of each peer pinned, the journal
encrypted with AES-256-GCM on the master, no shared secret. Details in [security-model.md](security-model.md#cluster-own-key-per-host).

## Checking and repairing

- `efactl cluster-status` on the master: each node, whether it answers, how far it is behind, and its failed entries.
- `efactl cluster-resync` on a node: takes all shared settings of the master anew. Failed entries that the snapshot covers are closed.
- `efactl cluster-mx-check`: whether the MX records of the own domains point to the nodes.
- `efactl cluster-unban --address <ip>`: lifts a ban on all nodes.

## Staged updates (O2)

`efactl cluster-update-set --mode on --window 2 [--first node1]` on the master staggers the eFa-next updates of the cluster:

1. The nodes no longer install updates by themselves. The master switches this on each node (`update-staged-set`).
2. In the maintenance window of the master, the first node installs the update.
3. The master waits the health window (1, 2 or 4 hours). The node must answer, show the new version and report no service down.
4. Then the next node installs, one by one. The master installs last.
5. A node that is not healthy within the window (at least 2 hours) stops the rollout. The other nodes keep their version, and
   the admins get a mail and the event `cluster_update_stopped`. After the check, `cluster-update-set --mode on` starts the
   rollout again with the next window.

The master goes one step on with its hourly update job. Off by default.

## Limits

Held mail and the mail queue stay on the node that took the mail; nothing is copied between nodes. For admins the master shows
and acts on them (`cluster-quarantine`, `cluster-queue`, `cluster-mail-action`). The user portal and the daily digest only know
the held mail of their own node: a user with held mail on two nodes gets two digests, and the portal shows only the mail of the
node it runs on. While a node is down, its held mail waits there until the node is back. A quarantine shared by all nodes follows
in 6.0.0.7.
