# Which license applies to which file

## The rule

- **Everything that comes from eFa-next is under the AGPL-3.0-or-later** ([LICENSE](LICENSE)): the programs, libraries, setup
  scripts, systemd units, templates, tests, build scripts and documentation of this repository. Each source file starts with
  `SPDX-License-Identifier: AGPL-3.0-or-later`, `Copyright (C) 2026 Markus Lorber and eFa-next contributors` and
  `Author: Markus Lorber, Lukasz Galusinski`; CI checks that every source file has them (`scripts/license_check.py`).
- **Third-party components keep their own licenses.** eFa-next uses them and does not change them: Postfix, rspamd, ClamAV,
  MariaDB, Redis, nginx, Unbound, fail2ban, the Python libraries (such as cryptography, Flask, waitress) and the packages of the
  operating system. The SBOM of each release (`eFa-next-<version>.cdx.json`, CycloneDX) names every component with its version
  and its license as an SPDX expression where the package states one; CI fails when a component has no license, and when eFa
  or eFa-base is not AGPL-3.0-or-later. The license texts are in `third-party/licenses/`, the notices in
  `THIRD-PARTY-NOTICES.md`.
- **Author**: Markus Lorber, who holds the rights together with the contributors. IT-World ITW GmbH sponsors the project and holds no rights.
- **Code from eFa**, the project eFa-next is based on, stays under its license, the GPL-3.0 (`LICENSES/GPL-3.0.txt`), with its
  notices. eFa-next was rebuilt clean-room (`docs/CLEANROOM-NOTES.md`): no file of this repository holds code from eFa any more.
  A file that does again is listed here, with its GPL-3.0 header kept.

## Files with code from eFa

None.
