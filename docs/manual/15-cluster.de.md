# 15. Cluster und Betrieb ohne Internet

*System › Cluster & offline*.

![Cluster & offline](../images/manual/cluster.png)

## Cluster

Ein Master, beliebig viele Knoten. Was auf dem Master eingestellt wird, gilt für alle Knoten.

| Modus | Einstellungen | Wenn der Master ausfällt |
|---|---|---|
| einzelner Host | nicht im Cluster (Standard) | – |
| `master-client` | nur auf dem Master; ein Knoten lehnt eine Änderung ab und zeigt „Verwaltet von …" | die Knoten filtern mit den letzten Einstellungen weiter |
| `ha` | auf jedem Knoten: ein Knoten gibt die Änderung an den Master, der sie ausführt und an alle weitergibt | die Knoten filtern weiter; Änderungen warten, bis der Master zurück ist |

Einrichten:

```bash
# auf dem Master
sudo efactl cluster-init --name mx-01 --mode ha --confirm yes
sudo efactl cluster-token
# auf jedem Knoten, mit Token und CA-Fingerabdruck aus cluster-token
sudo efactl cluster-join-check --master mx-01.example.com:8460   # zuerst die Prüfungen, der Token bleibt gültig
sudo efactl cluster-join --master mx-01.example.com:8460 --name mx-02 --address 192.0.2.12 --ca_fingerprint <Fingerabdruck>
sudo efactl cluster-join-preview        # was die Einstellungen des Masters hier ersetzen (ein wartender Knoten darf nur schauen, beitreten oder gehen)
sudo efactl cluster-activate --understood yes --confirm yes   # Sicherung, dann die Einstellungen des Masters
```

Die Knoten folgen dem Journal des Masters über gegenseitiges TLS (Port 8460), jeder mit eigenem Schlüssel. Gemeinsam: die
Einstellungen von eFa-next, rspamd-Regeln, DKIM- und ARC-Schlüssel, die Postfix-Tabellen, Benutzer, Gruppen und Einstellungen mit
Geltungsbereich und die Fail2Ban-Sperren. Jeder Host behält seine Identität: Hostname, Adressen, TLS-Zertifikate,
SSH-Hostschlüssel; Firewall, Netz, Update, Sicherung und Wazuh wirken immer auf dem eigenen Host. Werte nur für einen Knoten
kommen nach `/etc/eFa/local.d/`.

*Cluster: alle Knoten* zeigt Mail-Log, Quarantäne und Warteschlange aller Knoten und handelt auf einer Mail jedes Knotens.

Benutzer sehen im Portal die zurückgehaltene Mail aller Knoten (6.0.0.7), eine Stunde lang nach einer Anmeldung mit Passwort: Der Master prüft dieses Passwort selbst und signiert ein Ticket; mit Passkey, Single Sign-on oder Digest-Link zeigt das Portal die zurückgehaltene Mail des eigenen Knotens, und Digest-Links wirken auf jedem Knoten (Tickets für Passkey und Single Sign-on: eine spätere Version). Ein anderer Knoten fragt nur für einen genannten Login mit diesem Ticket, nie für einen Super-Admin, und gibt nie einen Virus frei; Super-Admins und die Freigabe eines Virus arbeiten auf der Weboberfläche des Knotens, der die Mail hält.
Der Fuzzy-Speicher ist gemeinsam (6.0.0.7): Die Knoten lesen ihn und schicken, was sie lernen, über das gegenseitige TLS des
Clusters an den Master; nur der Master schreibt hinein. Ein als übernommen gehaltenes Konto (über einem Sendelimit) wird
innerhalb einer halben Minute auf jedem Knoten gehalten, eine spätere Freigabe gilt überall. Solange der Master fehlt, zählt
jeder Knoten nur seine eigene Mail und hält die Sendelimits bei 1/N (N die Knoten des Clusters); das Dashboard sagt es.
`efactl cluster-status` zeigt jeden Knoten und wie weit er zurückliegt, `cluster-resync` übernimmt alle Einstellungen neu,
`cluster-mx-check` prüft die MX-Einträge. Ist der Master endgültig weg, macht `cluster-promote` einen Knoten zum Master eines neuen
Clusters.

Der zweite MX kann diesen Host als DNS-Resolver nutzen (Kapitel 10).

**Gestaffelte Updates:** Im Cluster ist jede Installation gestaffelt (6.0.0.6.7): Der Master aktualisiert einen Knoten nach dem
anderen, der erste Knoten installiert im Wartungsfenster, der Master wartet ein Gesundheitsfenster (`efactl cluster-update-set
--mode on --window 2`), dann folgt der nächste, der Master zuletzt; ein ungesunder Knoten stoppt die Verteilung. Die
Update-Einstellungen sind die des Masters, auch für das Betriebssystem; Kapitel 14, *Updates im Cluster*. Details: [cluster.md](../cluster.md).

## Betrieb ohne Internet

- **Ein lokaler Spiegel:** `efactl update-mirror-set --url https://mirror.example.lan/el9` holt Updates nur aus einer Kopie der
  eFa-next-Paketquelle. Die Signatur wird genau wie bei der Paketquelle selbst geprüft.
- **Signierte Pakete** für ein Netz ganz ohne Verbindung: `offline-bundle-make` auf einem Host mit Internet packt die Pakete des
  neuesten Releases, die ClamAV-Signaturen und die Karten der Bedrohungs-Feeds in eine Datei, signiert mit eigenem Schlüssel; der
  abgeschottete Host vertraut diesem Schlüssel einmal (`offline-trust-set`) und spielt die Datei ein (`offline-bundle-apply`).

Details: [offline.md](../offline.md).

Weiter: [Migration von eFa 5](16-migration.de.md) · Zurück: [Handbuch](README.de.md)
