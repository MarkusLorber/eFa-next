# Release checklist

For every release of eFa-next, once all its features are built. The release report comes only after all of it.

## 1. Code review

- **Security**: input validation at every boundary (web, API, efactl arguments, files, mail), permission check of each command,
  injection, XSS, CSRF, path traversal, secrets (never in logs, arguments or the audit log), subprocess calls only as argument lists without a shell,
  file and directory permissions, SELinux contexts. No insecure way (docs/SECURITY-DESIGN.md): nothing below the rules there is
  offered, an old weaker setting is raised by the update with a dashboard notice.
- **Stability**: error paths, timeouts on every external call, size and count limits, no service that can hang,
  no cache or log without a bound or rotation.
- **Minimalism**: dead code, duplicates, dependencies nobody needs, functions that grew too long.

Fix what is found, with a test where it is logic.

## 2. Tests, end to end

- `scripts/ci.sh` green (unit tests, self-tests, lint, RPM build, install and upgrade test).
- Self-tests of each program and the unit tests.
- Web interface with all roles in a real browser (Playwright): every page, form, action by GET and POST, phone width, dark mode.
- Upgrade from the previous release, without any setting changing.
- Fresh install.
- Idle resource test: CPU, RAM and processes of an idle host.
- The main mail paths on the test host: inbound, outbound, spam, virus, quarantine, release.

## 3. Documentation

- Docs updated, screenshots with demo data only (example.com, made-up users, no real hosts, addresses, tokens or passwords), each image checked by hand.
- Changelog.

## 4. Release report

What is in it, what was tested and how, what was not tested, known limits.
