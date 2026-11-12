# RHEL 10 / AlmaLinux 10 / Rocky 10 (target: 6.0.0.6)

**Untested on EL10**: no EL10 host exists yet. Everything below is checked on EL9 only (CI on EL9 stays green); the EL10
parts are code and unit tests with EL10 fixtures.

- **Platform layer** (done): `efa_platform.detect()` reads `/etc/os-release` (ID, ID_LIKE, VERSION_ID) and returns the EL9 platform for major 9 and `efa_platform_el10.EL10` for major 10, a subclass of the EL9 one that overrides only what differs: Valkey (service, account, config `/etc/valkey/valkey.conf`, data `/var/lib/valkey`), lmdb tables, the rspamd EL10 repository and ClamAV from EPEL 10, the versions (Python 3.12, MariaDB 10.11, Postfix 3.8) and no SHA-1 signatures in the DEFAULT crypto policy.
- **Postfix tables** (done): EL10 has no Berkeley DB in Postfix. The table type comes from `map_type()` of the platform: what `default_database_type` of this Postfix says, else hash on EL9 and lmdb on EL10. efactl (`_map()`, `_cache_map()`, every `postmap`) and the setup (`efa_services`) use it; EL9 hosts keep hash, nothing changes there. `tests/test_map_literals.py` keeps `hash:`/`btree:` out of the code (except the platform modules and the eFa 5 and release-upgrade converters).
- **Redis or Valkey** (done): EL10 ships Valkey 8 (AppStream), no Redis. The platform layer resolves the unit `redis` to
  `valkey` (`UNIT_ALIASES`), and gives the config (`redis_conf`), the CLI (`redis_cli`: `valkey-cli`) and the account
  (`redis_user`). efactl (`redis-tune`, the key scans), the health service and the rspamd setup use them; the spec requires
  `valkey` on EL10 and `redis` on EL9. The release upgrade copies `/var/lib/redis/dump.rdb` to `/var/lib/valkey` once and
  starts Valkey. rspamd talks to it on 127.0.0.1:6379 either way.
- **Update sources** (done): efactl takes `repo.efa-next.eu/el9` or `/el10` by the release of the host; the GitHub releases
  hold the EL9 packages only, so an EL10 host does not use them as a mirror. The release upgrade switches
  `/etc/yum.repos.d/efa-next.repo` and `rspamd.repo` to EL10. `efa-migrate` (eFa 5, which runs on EL9 only) stays on `/el9`.
- **Logins on 587**: efa-sasl (Python, standard library) replaces Dovecot. AlmaLinux 10 ships Dovecot 2.3.21 (checked
  2026-11-09), not 2.4: the syntax of the Dovecot SASL setup does not change with EL10 for now. Python 3.12 still has the
  `crypt` module (removed in 3.13): logins stored as SHA512-CRYPT keep working on EL10.
- **Fresh install** (build.bash): AlmaLinux 10 is taken; repositories by the major version (EPEL 10, rspamd centos-10,
  repo.efa-next.eu/el10, no GitHub mirror, no nginx module stream). RHEL 10 is closed (`RHEL10_ENABLED=no`) until tested,
  Rocky 10 and others are refused. The packages build for EL10 in mock (alma+epel-10-x86_64) and natively on AlmaLinux 10
  with the same result, byte for byte.
- **Rehearsal before the EL10 repository exists** (test only): `EFA_EL10_TEST_REPO` in a drop-in of
  `efa-release-upgrade.service` points the release upgrade at a repository of unsigned test builds, taken only as
  `http(s)://127.0.0.1...` or `file://...` and only while `/etc/eFa/testing-unsigned-el10-repo` exists (root, 0600); otherwise
  it is ignored, and preflight and the log say why. The web interface never passes it (efactl-runner gives a fixed
  environment). Never on a production host.
- **leapp package data** (leapp-data-almalinux, `pes-events.json` of 2025-12-22): it marks three packages as removed in
  AlmaLinux 10 that eFa-next needs and EL10 still has: nginx of the module stream 1.26 (event #17687; AlmaLinux 10 AppStream
  has nginx 1.26 without a module), sendmail-milter (#14207; EPEL 10, its libmilter is needed by python3-pymilter) and
  python3-pytz (#17202; EPEL 10, needed by certbot 4.2). leapp's EPEL vendor repository is the newest EPEL 10, which can be
  built for a newer minor release than the target (EPEL 10.3 pyOpenSSL needs the cryptography of 10.3). For each leapp run
  the release upgrade therefore adds eFa-next's lines to leapp's `/etc/leapp/transaction/to_keep` and `to_install` and points
  the metalink of `vendors.d/epel.repo` at EPEL of the target release (10.2 from leapp's upgrade paths); afterwards the files
  are as leapp shipped them again.
- **After leapp** (rehearsal on AlmaLinux 9.8 to 10.2): leapp puts its own packages on the `exclude=` line of
  `/etc/dnf/dnf.conf`, so a plain `dnf remove` skips them and ends with 0; `leapp_resume.service` runs leapp's last phase
  after the default target and fails if SELinux is enforcing or leapp is removed before it; the el9 kernel stays installed;
  EL10 splits `perl-locale` off perl-POSIX; the stock Postfix sample tables, unbound's conf.d files and postfix-lmdb's
  dynamicmaps files change with their packages. The finish step handles each: it waits for leapp, removes with
  `--disableexcludes=main`, removes the el9 kernels by name, allows perl-locale, and counts unchanged package files as the
  package's in the settings comparison.
- **Wazuh agent of the operator** (wazuh-agent from packages.wazuh.com/4.x/yum): one build for EL9 and EL10 (no el tag,
  4.14.10-1 needs only coreutils and shadow-utils), signed RSA/SHA256 with the key 0DCFCA55 47B19D2A 60995060 96B3EE5F
  29111145, which EL10 (crypto policy DEFAULT) imports and checks (tried on AlmaLinux 10.2). The release upgrade leaves the
  package exactly as it is: no vendor file, no update. Its package scripts would stop a running agent in the upgrade
  environment and restart it, and they delete /etc/systemd/system/wazuh-agent.service with a daemon-reload, which is the
  mask of an agent that must stay off (a clone). wazuh-agent is on leapp's to_keep list; if leapp's transaction would still
  update, reinstall, downgrade or remove it, preupgrade and start stop. After the first EL10 boot the checks compare its
  version, ossec.conf and client.keys (SHA-256) and its enabled and running state with before: an agent that was off stays off.
  Preflight lists the agent and every package from a repository other than the distribution, EPEL, rspamd and eFa-next.
- **Boot after the upgrade in VirtualBox**: the first boot into EL10 (kernel 6.12.0-211.74.1) can sit for minutes on a dark
  console and look hung. It is slow, not broken: a reset of the VM boots normally. Not seen on other hypervisors so far.
- **Packages on EL10** (checked against AlmaLinux 10 and EPEL 10 on 2026-11-09): available are valkey 8.0, postfix 3.8 with
  postfix-lmdb, nginx 1.26, mariadb-server 10.11, unbound 1.24, dovecot 2.3.21, dnf-automatic, python3-cryptography,
  python3-PyMySQL (AppStream), bind-utils, openldap-clients, rsyslog, checkpolicy, selinux-policy-targeted; from EPEL 10
  python3-pymilter, python3-flask 3.1, python3-werkzeug, python3-waitress, python3-certbot-nginx and certbot 4.2,
  fail2ban-server and fail2ban-firewalld 1.1, clamav, clamd 1.4; rspamd 4.2.3 from rspamd.com/rpm-stable/centos-10.
  Open: `clamav-update` is called `clamav-freshclam` in EPEL 10 (check whether it provides the old name, else the spec
  needs it per release); `dnf-utils` is not a package of its own on EL10 (`yum-utils`/`dnf-plugins-core`; check the
  provide). The SELinux module must be built against the EL10 policy. Nothing of it is built yet.
- **Release upgrade** (6.0.0.6): ELevate with the checks after the first EL10 boot; it switches main.cf and master.cf
  (`postconf -n` and `-P`) from hash/btree to lmdb. See [release-upgrade.md](release-upgrade.md).
- **The check**: the same `scripts/os_lint.py` as for FreeBSD keeps new direct calls out (see [FREEBSD-PORT.md](FREEBSD-PORT.md)).
