# Newsletter-freundlicher Versand

Ein Bulk-Modus für Massenmail, damit ein großer Versand nicht wie ein gekapertes Konto aussieht und bei den großen Anbietern
ankommt. Standardmäßig aus. Eingestellt je Absenderadresse oder Absenderdomain, und automatisch verwendet bei
`Precedence: bulk` oder einem Header `List-Unsubscribe`.

## Was er tut

- Mail eines Bulk-Absenders geht über eigene Postfix-Transporte hinaus, und nur, wenn alle ihre Empfänger außerhalb der eigenen
  Domains liegen: je einer für Google, Microsoft und Yahoo mit eigenem Tempo und `efabulk-other` für den Rest (6.0.0.7).
- Das Tempo für den Rest, je Zieldomain: *gentle* (1 Verbindung, 3 s zwischen Mails, je 20 Empfänger), *normal* (1, 1 s, 50)
  oder *fast* (5, keine Pause, 100). Google: 2 Verbindungen, 1 s, 50; Microsoft: 1, 2 s, 20; Yahoo: 1, 2 s, 30.
- Vor dem Versand wird geprüft, was die großen Anbieter von Bulk-Absendern verlangen: Abmelden mit einem Klick (RFC 8058), ein
  DKIM-Schlüssel hier, SPF und DMARC im DNS. Fehlendes wird protokolliert und im Header `X-eFa-Bulk-Missing` genannt, oder die
  Mail wird für einen Admin zurückgehalten (`--missing hold`).
- Bulk-Mail zählt **nicht** zu den Versandgrenzen der Erkennung gekaperter Konten; ihr Tempo ist ihre Grenze.

`bulk-set` schaltet ihn ein und setzt die Absender, das Tempo und was geschieht, wenn etwas fehlt; `bulk-status` zeigt die
Einstellung und je Absenderdomain, was die Anbieter vermissen würden.

## Eigene Adresse, Warm-up, Beschwerden, Statistik (6.0.0.7)

- **Eigene Adresse:** `bulk-set --address 198.51.100.20` sendet alle Bulk-Mail von dieser Adresse, mit dem Namen ihres
  PTR-Eintrags als HELO. Die Adresse muss auf diesem Server liegen, mit einem PTR-Eintrag, dessen Name auf sie zurückzeigt
  (geprüft beim Setzen). Ist die Adresse später weg, wartet die Bulk-Mail; sie geht nie von der Hauptadresse hinaus. Die Adresse
  in den SPF-Eintrag der Absenderdomains aufnehmen.
- **Warm-up:** `bulk-set --warmup on` lässt eine neue Adresse langsam beginnen: am ersten Tag 50 Empfänger je Anbieter, jeden Tag
  doppelt so viele, ab Tag 15 ohne Grenze. Mail über der Grenze des Tages wird mit einem vorübergehenden Fehler (4xx) abgelehnt:
  Die sendende Anwendung versucht es später noch einmal.
- **Beschwerden:** `bulk-set --arf fbl@example.com` nimmt die Beschwerden, die die Anbieter als ARF-Berichte (RFC 5965) an diese
  Adresse von Ihnen schicken. Melden Sie sie bei den Feedback-Loops der Anbieter an (etwa Microsoft JMRP/SNDS, Yahoo CFL; Gmail
  zeigt Beschwerden nur in den Postmaster Tools). Jeder Bericht wird je Tag und Absenderdomain gezählt, und sein Empfänger bekommt
  keine Bulk-Mail mehr (nur ein Hash wird behalten). Keine Cloud-Schnittstelle eines Anbieters wird genutzt. Ein Bericht zählt
  nur, wenn dieser Server DKIM oder DMARC für die Domain eines bekannten Feedback-Loops als bestanden geprüft hat (Microsoft,
  Yahoo, AOL, Comcast, Mail.ru, Yandex, Fastmail, GMX/Web.de, Zoho, Rackspace); alles andere an dieser Adresse wird verworfen,
  und ein Bericht, der sich nicht lesen lässt, auch, nie mit einer Rückmeldung an den Absender. Die Statistik behält höchstens
  500 Absenderdomains.
- **Statistik:** `bulk-stats --days 7`: je Anbieter, wie viel gesendet, verschoben und zurückgewiesen wurde (aus dem
  Zustellprotokoll), und die Beschwerden je Tag und Absenderdomain.

Nicht gebaut: Vorlagen und Statistik je Kampagne.
