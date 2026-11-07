# Blocklists (RBL, DNSBL, URIBL)

eFa-next can ask public blocklists about the sending address, the HELO name, the sender domain and the links of a mail
(*Protection → Blocklists*, `efactl rbl-show`).

## Their terms

Each list is run by its provider, under the provider's own terms of use. The table of the blocklists links them; where a
provider publishes no terms, it says so and links its website.

eFa-next, everyone involved in the project and its sponsors have no influence on these lists or their use. Switching a list on needs a
confirmation, in the web interface, in efa-tui and on the command line:

> I have read and accept the terms of use of this list. eFa-next, everyone involved in the project and its sponsors, including
> IT-World ITW GmbH, have no influence on this list or its use and are not liable for it. For any problem with the list I contact
> its provider directly.

```
efactl rbl-set --id spamcop --mode on --accept_terms yes
```

The confirmation goes to the audit log with the account, the time, the list and the state of the terms (the date of the links
in eFa-next). The table shows "accepted by … on …".

- When an update brings a new state of the terms, the dashboard asks to confirm again. The lists stay active until then: an
  update stops no filtering.
- After the upgrade from an earlier version, the lists that were on stay on; the dashboard shows "terms of use not yet
  confirmed" until someone confirms them. Lists that were off stay off.
- The same holds for your own lists (`efactl rbl-custom-set`): you confirm the terms of their provider.

## Free use and limits

Many free lists allow only a limited number of queries, non-commercial use, or need a registration of the resolver; Spamhaus
needs a DQS key beyond low volume. Most of them refuse queries through public resolvers: eFa-next resolves on its own with
unbound, and warns when the resolver forwards to another one.
