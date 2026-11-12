# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Platform layer for EL10 (AlmaLinux, Rocky Linux, RHEL 10): the same tools as EL9, with these differences.

- Valkey instead of Redis: service, account, configuration and data path (the protocol and port 6379 stay).
- Postfix without Berkeley DB: new lookup tables are lmdb.
- Python 3.12, nginx and MariaDB 10.11 from the base repositories (no module streams), Postfix 3.8.
- The DEFAULT crypto policy refuses SHA-1 signatures (old DKIM rsa-sha1 signatures fail to verify).
- ClamAV from EPEL 10, rspamd from its EL10 repository.

Untested on EL10: no EL10 host exists yet (docs/EL10-PORT.md).
"""

from efa_platform_el9 import EL9


class EL10(EL9):
    name = "el10"

    PATHS = {**EL9.PATHS, "redis_conf": "/etc/valkey/valkey.conf", "redis_dir": "/var/lib/valkey", "redis_cli": "/usr/bin/valkey-cli"}
    UNIT_ALIASES = {"redis": "valkey", "redis.service": "valkey.service"}
    SERVICES = {**EL9.SERVICES, "redis": "valkey"}
    ACCOUNTS = {**EL9.ACCOUNTS, "redis_user": "valkey"}
    REPOSITORIES = {"rspamd": "https://rspamd.com/rpm-stable/centos-10/$basearch", "clamav": "epel-release (EPEL 10)",
                    "nginx": "base repository"}
    VERSIONS = {"python": "3.12", "nginx": "1.26", "mariadb": "10.11", "postfix": "3.8"}
    SHA1_SIGNATURES = False
    MAP_TYPE = "lmdb"
