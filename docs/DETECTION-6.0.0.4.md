# Detection rate and false alarms, eFa-next 6.0.0.4 (Q10)

Measured on 2026-11-06 on a test system (rspamd 4.2.3 with the eFa-next rules, ClamAV), with
`scripts/detection_benchmark.py`: each mail went to rspamd `checkv2`, a check only, nothing was learned or delivered.
"Caught" means the action would be reject, add header, rewrite subject or soft reject; greylisting does not count.

## Corpus

SpamAssassin public corpus (spamassassin.apache.org/old/publiccorpus), downloaded over HTTPS:
`20030228_spam` and `20050311_spam_2` (1,896 spam), `20030228_easy_ham` (2,500 ham) and `20030228_hard_ham`
(250 ham that looks like spam on purpose: newsletters, mailings).

**The mails are from 2002 to 2005.** Their senders, domains and IP addresses no longer exist or are on block lists today, their
dates are 20 years old. The result shows the rules and filters, not how eFa-next handles today's spam. A measurement on current
mail follows in a pilot.

## Results

| Run | Spam caught | False alarms, all ham | easy ham | hard ham |
|-----|-------------|-----------------------|----------|----------|
| A: all rules | 72.0 % | 41.5 % | | |
| B: without DATE_IN_PAST | 89.6 % | 16.3 % | | |
| C: without DATE_IN_PAST and Bayes | 54.6 % | 7.8 % | 5.4 % | 30.8 % |

Why three runs:
- **DATE_IN_PAST** hits every mail of an old corpus, ham as well. It is turned off for B and C (rspamd `Settings` header,
  only for these checks).
- **Bayes** on the test system had learned 501 ham and 208 spam by autolearn, among them 500 generated mails of the load test
  (Q11). Trained on that word list, Bayes calls real ham spam: in A it hit 111 of 114 wrongly flagged ham mails. B still holds it,
  so B shows what a Bayes trained on wrong data does. C shows the rules and filters without Bayes.

Run C is the fairest number for this corpus: **54.6 % of the old spam caught, 5.4 % false alarms on normal ham** (30.8 % on
the hard ham). Without Bayes, many old spam mails stay just under the thresholds; most are greylisted (277) or get no action (584).
A Bayes trained on the own mail flow (`efactl train-request`, autolearn on real mail) is the main lever, as the 89.6 % of B suggest,
but only with clean training data.

## Repeat

```
python3 scripts/detection_benchmark.py --spam corpus/spam --ham corpus/ham --parallel 8 \
    --without DATE_IN_PAST,BAYES_SPAM,BAYES_HAM --markdown
```

The corpus stays on the test system in `/home/efa-ci/corpus` for later comparisons.
