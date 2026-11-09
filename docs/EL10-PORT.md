# RHEL 10 / AlmaLinux 10 / Rocky 10 (target: 6.0.0.5)

Planned together with FreeBSD. For 6.0.0.4 only this: nothing may make it harder.

- **Platform layer**: `efa_platform.detect()` reads `/etc/os-release` (ID, ID_LIKE, VERSION_ID) and returns the EL9 platform for major 9. EL10 gets `efa_platform_el10.py`, a subclass of the EL9 one that overrides only what differs; `detect()` picks it for major 10.
- **Redis or Valkey**: EL10 ships Valkey by default. Service name, config path and CLI must come from the platform layer (`service('redis')`, a path name for the config), not from the literal `redis`. Today efactl has `REDIS_CONF = /etc/redis/redis.conf` and sets the owner `redis`: both move into the platform layer. rspamd talks to it on 127.0.0.1 either way.
- **Logins on 587**: efa-sasl (Python, standard library) replaces Dovecot, so its changed syntax in 2.4 does not matter. Python 3.12 drops the `crypt` module: logins stored as SHA512-CRYPT then need a new password once (efa-sasl logs it); new ones are scrypt.
- **Spec files**: `Release: 1%{?dist}` already gives el9 or el10. `Requires: redis` becomes `Requires: (redis or valkey)`; the other requirements and `fail2ban-firewalld`, `dnf-automatic` and the SELinux policy build (checkpolicy, policycoreutils) are to be checked against the EL10 repositories.
- **The check**: the same `scripts/os_lint.py` as for FreeBSD keeps new direct calls out (see [FREEBSD-PORT.md](FREEBSD-PORT.md)).
