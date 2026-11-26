# Weitere Netzwerkschnittstellen

Die Schnittstelle der Standardroute wird bei der Installation und auf der Seite *Netzwerk, DNS & Zertifikat* festgelegt;
eFa-next ändert sie von hier aus nie. Jede andere Ethernet-Schnittstelle bekommt eine Rolle (*Netzwerk → Weitere
Schnittstellen*, `efactl interface-set`):

| Rolle | Firewall-Zone | Wofür |
|---|---|---|
| uplink | public | ein zweiter Weg ins Internet; eigene Routing-Tabelle, damit Antworten dort hinausgehen, wo die Anfrage hereinkam |
| internal | internal | ein Netz eigener Mailserver: SMTP, Submission, SSH und HTTPS von dort erreichbar |
| management | internal | nur Admins: SSH und HTTPS |
| unused | drop | nichts |

Eine Schnittstelle bekommt eine feste Adresse oder DHCP, ein optionales Gateway (nur Uplinks), DNS-Server und eine VLAN-ID. Ein
internes Netz wird nie zur Standardroute.

## Neue Schnittstellen bleiben ungenutzt

Eine neue Schnittstelle (etwa eine zweite Netzwerkkarte einer VM) bekommt kein automatisches DHCP-Profil: eFa-next setzt
`no-auto-default=*` für NetworkManager (/etc/NetworkManager/conf.d/50-efa-no-auto-default.conf), damit ein Mail-Gateway nie von
sich aus eine Adresse oder eine Standardroute aus einem unbekannten Netz übernimmt. Das Dashboard nennt eine solche
Schnittstelle, bis sie eine Rolle hat. Ein Update setzt das für später hinzukommende Schnittstellen und lässt bestehende Profile
wie sie sind; der Härtungsbericht nennt Profile, die NetworkManager selbst angelegt hat ("Wired connection N").

## Der Weg zurück

Jede Änderung nimmt sich nach 5 Minuten selbst zurück, wenn nicht `efactl interface-confirm` folgt, so wie beim
Firewall-Wächter. Eine Änderung der Firewall-Zone geschieht nur zwischen Minute 20 und 50 einer Stunde, und eFa-next lädt nie die
ganze Firewall neu.

## Ausgehende Mail über einen Uplink

`efactl uplink-route-set --domain example.org --device ens35` sendet die Mail der Absenderdomain example.org über den Uplink
ens35: Postfix bekommt einen eigenen Transport (`efa-out-ens35`), gebunden an die Adresse dieses Uplinks. `--device main`
sendet sie wieder über die Hauptschnittstelle. Die Adresse des Uplinks braucht einen PTR-Eintrag mit dem HELO-Namen und ihren
Platz im SPF-Eintrag der Domain; der Befehl sagt es.

## Umschalten ausgehender Mail auf einen Ersatz-Uplink (6.0.0.7)

`efactl uplink-failover-set --mode on --backup ens36`: Jede Minute fragt efa-uplink-watch, ob der Haupt-Uplink noch arbeitet.
Standardmäßig pingt er das Gateway des Haupt-Uplinks und fragt keinen Dritten. Mit `--probe a:443,b:443,c:25` verbindet er sich
stattdessen mit drei Hosts Ihrer Wahl, und zwei davon müssen antworten; `--probe -` geht zurück zum Gateway. Nach drei
Fehlschlägen hintereinander geht ausgehende Mail über den Ersatz-Uplink hinaus (eigener Transport und eigene Routing-Tabelle),
aber nur, wenn der Ersatz zum Senden taugt: Seine Adresse hat einen PTR-Eintrag, dieser Name ist der HELO-Name dieses Servers
und zeigt auf die Adresse zurück, und der SPF-Eintrag jeder eigenen Domain lässt die Adresse senden. Sonst schaltet nichts um,
die Mail wartet in der Warteschlange, und das Dashboard nennt, was fehlt. Fünf gute Antworten des Haupt-Uplinks schalten zurück.
Eingehende Mail bleibt unberührt, ebenso die Firewall (kein Reload).
