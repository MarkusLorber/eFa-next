# Compensating controls

Not a legally binding statement; see [DISCLAIMER.md](../../DISCLAIMER.md). This page documents where eFa-next meets the aim of a
requirement in another way than its letter, and why. The compliance file names it as status *partial* with the limit
"compensating control documented" and the evidence below; whether a compensating control is accepted is the decision of the
assessor of the operator.

## Lockout after failed logins (PCI DSS 8.3.4, NIST SP 800-53 AC-7)

**The letter:** lock the user ID after at most 10 failed attempts (PCI DSS: for at least 30 minutes or until an administrator
unlocks it).

**Why eFa-next does not lock accounts:** a lockout per account lets anybody who knows a login name keep that person out, the
main admin included, by guessing wrong on purpose. On a mail gateway reachable from the internet that turns the protection into
a denial of service against the administrators (owner's design decision, docs/login-lockout.md).

**What protects instead, together:**

| Control | Where | Effect | Evidence |
| --- | --- | --- | --- |
| Lockout per address | Fail2Ban jails `efa-web` and `postfix-sasl` (`efactl login-lockout-set`, on for new installs: 5 tries in 10 minutes, 1 hour ban) | An address that guesses is banned on the ports it attacked | `efactl login-lockout-status` (mode on), Wazuh rules 108012, 108068 |
| Repeat offenders | Fail2Ban `recidive` | Three bans in a day: a week on every port | `login-lockout-status` (repeat) |
| Per address in the web interface | efa-web: 5 failures in 5 minutes block the address; every failed login answers after a fixed second | No fast guessing, the answer tells nothing about the name | efa-web self-test |
| Per login name on port 587 | efa-sasl: 5 failures in 10 minutes stop that name from any address | Guessing one name from many addresses stops | `tests/test_admin_2fa_required.py` SaslPerName.test_per_name |
| 2FA for every admin | Required since 6.0.0.6.7 (TOTP or passkey) | A guessed password alone gives no access | `tests/test_admin_2fa_required.py`, hardening check "2FA required for every admin role" |
| 2FA code of the console admin | efa-console-2fa: 5 wrong codes lock that user for 15 minutes over SSH | No guessing of the code; the local console stays open | efactl self-test |
| Audit and alert | Audit log, events `login_failed`, `admin_network_bruteforce` to SIEM and Wazuh | Attacks are seen | Wazuh rules 108011, 108012, 108068 |

**Limits:** the web interface counts per address in memory (a restart of efa-web starts again; Fail2Ban keeps its own count);
an attacker with many addresses is slowed by Fail2Ban per address and stopped by 2FA, not by a per-account counter.
