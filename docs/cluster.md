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
- The rule parts of `main.cf` and the eFa services in `master.cf`.
- The content rules (`/etc/efa-web/content.json`), the users, groups, roles and scoped settings.
- Bans of Fail2Ban, in both directions. Protected networks are never banned.

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

The nodes go on filtering with the last settings; each one shows "Cluster master … not reachable since …" on its dashboard. No node
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
