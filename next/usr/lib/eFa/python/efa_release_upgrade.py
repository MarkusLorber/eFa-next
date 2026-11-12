# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The release upgrade from Enterprise Linux 9 to 10 with ELevate (leapp): the pure parts, without a system call.

efactl collects the facts and runs the steps; this module decides from them: the preflight, the leapp report, the
confirmation of the start, the leapp vendor files of the eFa-next repository and the comparison after the first EL10 boot.
Everything here runs in the CI on any host (python3 efa_release_upgrade.py --self-test)."""
import json
import os
import re

STATE_DIR = '/var/lib/eFa/release-upgrade'
LOG = '/var/log/eFa/release-upgrade.log'
# The repository of eFa-next for EL10; until it exists the preflight says so and the start stays disabled.
# For a rehearsal before it exists: EFA_EL10_TEST_REPO (set in a drop-in of efa-release-upgrade.service) names a repository
# of unsigned test builds instead; its vendor file then checks no signature, and preflight warns. Never in production. It
# counts only with the marker file below (root, 0600) and a repository on this host itself; else it is ignored, with the reason.
EL10_TEST_MARKER = '/etc/eFa/testing-unsigned-el10-repo'
EL10_TEST_URL = re.compile(r'^(https?://127\.0\.0\.1(:\d{1,5})?/|file:///)[^\s]*$')


def test_repo(environ, stat=os.stat):
    """(the test repository to use or '', why the variable was ignored or '')."""
    url = environ.get('EFA_EL10_TEST_REPO', '')
    if not url:
        return '', ''
    if not EL10_TEST_URL.match(url):
        return '', f'EFA_EL10_TEST_REPO ignored: only http(s)://127.0.0.1 or file:// is taken, not {url[:80]}'
    try:
        found = stat(EL10_TEST_MARKER)
    except OSError:
        return '', f'EFA_EL10_TEST_REPO ignored: {EL10_TEST_MARKER} is missing'
    if found.st_uid != 0 or found.st_mode & 0o7777 != 0o600:
        return '', f'EFA_EL10_TEST_REPO ignored: {EL10_TEST_MARKER} must belong to root with mode 0600'
    return url, ''


EL10_TEST_REPO, EL10_TEST_IGNORED = test_repo(os.environ)
# 6.0.0.6-alpha1: the pre-release goes to EL10 only from the testing channel, where it is the one version (not el10/ itself).
EL10_REPO = EL10_TEST_REPO or 'https://repo.efa-next.eu/el10/testing/'
EL10_PROBE = EL10_REPO + 'repodata/repomd.xml'
ELEVATE_RELEASE = 'https://repo.almalinux.org/elevate/elevate-release-latest-el9.noarch.rpm'
ELEVATE_PACKAGES = ('leapp-upgrade', 'leapp-data-almalinux')
# S22: the release package of ELevate only signed by the ELevate key, which ships with eFa-next and is pinned by its full
# fingerprint (from https://repo.almalinux.org/elevate/RPM-GPG-KEY-ELevate; the copy in elevate-release is the same file).
ELEVATE_KEY = '/usr/share/eFa/keys/RPM-GPG-KEY-ELevate'
ELEVATE_FINGERPRINT = '74E7F249EE698A4DACFB48C8429785E181B961A5'
# S23: the upgrade keeps the distribution. AlmaLinux 9 goes to AlmaLinux 10 with ELevate. RHEL 9 would go to RHEL 10 with the
# leapp of Red Hat (leapp-upgrade from the RHEL repositories, no leapp-data-almalinux) on a registered system; it stays blocked
# until a real RHEL run passed: then set RHEL_ENABLED = True. Every other distribution is not supported.
RHEL_ENABLED = False
RHEL_PACKAGES = ('leapp-upgrade',)


def os_id(os_release):
    """The ID of /etc/os-release (almalinux, rhel, rocky, centos, ...), or ''."""
    match = re.search(r'^ID="?([A-Za-z0-9._-]+)"?\s*$', os_release or '', re.M)
    return match.group(1).lower() if match else ''


def distribution_problem(source_id, registered=None):
    """None when this distribution may be upgraded in place to the same distribution 10, else the reason."""
    if source_id == 'almalinux':
        return None
    if source_id == 'rhel':
        if not RHEL_ENABLED:
            return 'RHEL 9 → 10: noch nicht getestet'
        if registered is not True:
            return 'RHEL 9 → 10 needs a registered system (subscription-manager status)'
        return None
    return f'{source_id or "unknown distribution"}: nicht unterstützt'


def upgrade_packages(source_id):
    """What preupgrade installs: ELevate (with its release package) for AlmaLinux, the leapp of Red Hat for RHEL. The target is
    always the same distribution: leapp-data-almalinux never on another one."""
    if source_id == 'almalinux':
        return ELEVATE_RELEASE, ELEVATE_PACKAGES
    if source_id == 'rhel':
        return None, RHEL_PACKAGES
    raise ValueError(f'no upgrade path for {source_id}')


def rpm_signature_problem(checksig, signature, key_id=ELEVATE_FINGERPRINT[-16:]):
    """None when rpm -K said the digests and signatures are OK and the signature is the one of key_id; else the reason.
    checksig: the output of rpm -K, signature: %{RSAHEADER:pgpsig} or %{SIGPGP:pgpsig} of the package."""
    if not re.search(r':\s*digests signatures OK\s*$', checksig or '', re.M):
        return 'the package is not signed by an imported key, or it was changed: ' + (checksig or 'no answer').strip()[-200:]
    if key_id.lower() not in (signature or '').lower():
        return f'the package is not signed by the ELevate key {key_id}: {(signature or "no signature").strip()[-120:]}'
    return None
# What the first EL10 boot removes again: the tool, its data and the repository package of ELevate.
CLEANUP_PACKAGES = ('leapp-upgrade-el9toel10', 'leapp-upgrade-el9toel10-deps', 'leapp-upgrade-el9toel10-fapolicyd', 'leapp-data-almalinux',
                    'leapp', 'python3-leapp', 'snactor', 'leapp-deps', 'leapp-deps-el10', 'leapp-repository-deps-el10', 'elevate-release')
# leapp puts its own packages on the exclude= line of dnf.conf; dnf remove then skips them and still ends with 0. Only these
# names come off the line again, the pins of eFa-next (efa-next-setup) stay.
DNF_CONF = '/etc/dnf/dnf.conf'
LEAPP_DNF_EXCLUDES = ('leapp', 'python3-leapp', 'leapp-upgrade-el9toel10', 'leapp-upgrade-el9toel10-fapolicyd', 'snactor')


def dnf_exclude_without_leapp(text):
    """dnf.conf without leapp's names on its exclude= line: (new text, the names taken off)."""
    taken = []

    def strip(found):
        names = [name.strip() for name in re.split(r'[,\s]+', found.group(2)) if name.strip()]
        taken.extend(name for name in names if name in LEAPP_DNF_EXCLUDES)
        return found.group(1) + ','.join(name for name in names if name not in LEAPP_DNF_EXCLUDES)
    return re.sub(r'^(exclude\s*=\s*)(.*)$', strip, text, flags=re.M), taken


KERNEL_PACKAGE = re.compile(r'^(kernel(?:-[a-z]+)*)-(\d[^-]*)-([^-]+)\.([a-z0-9_]+)$')


def old_kernels(packages, running):
    """The el9 kernel packages (name-version-release.arch) to remove after the upgrade: none while no el10 kernel is
    installed or while an el9 kernel runs, never the running one."""
    kernels = [(item, KERNEL_PACKAGE.match(item)) for item in packages]
    kernels = [(item, found) for item, found in kernels if found]
    el10 = [item for item, found in kernels if found.group(1) == 'kernel-core' and '.el10' in found.group(3)]
    if not el10 or '.el9' in (running or ''):
        return []
    return sorted(item for item, found in kernels if '.el9' in found.group(3) and f'{found.group(2)}-{found.group(3)}.{found.group(4)}' != running)


# What leapp leaves on disk once its packages are gone (its data, the upgrade container, its resume copy); its logs in
# /var/log/leapp stay. Removed after the checks passed.
LEAPP_LEFTOVERS = ('/etc/leapp/files', '/var/lib/leapp', '/root/tmp_leapp_py3')
LEAPP_ETC = '/etc/leapp'
# The drain waits only for mail on its way (active, incoming); deferred mail waits for its next try anyway and stays queued.
DRAIN_QUEUES = ('active', 'incoming')

# Files the setup of eFa-next writes itself: the package of EL10 brings its own version beside them (.rpmnew), or keeps the
# old one beside the new (.rpmsave). After the upgrade they move to RPMNEW_DIR/<time>/ for a later comparison by hand.
RPMNEW_MANAGED = ('/etc/postfix/main.cf', '/etc/postfix/master.cf', '/etc/postfix/transport', '/etc/chrony.conf', '/etc/unbound/unbound.conf',
                  '/etc/redis/redis.conf', '/etc/valkey/valkey.conf', '/etc/rspamd/rspamd.conf', '/etc/nginx/nginx.conf', '/etc/clamd.d/scan.conf',
                  '/etc/fail2ban/jail.conf', '/etc/dnf/automatic.conf')
RPMNEW_DIR = STATE_DIR + '/rpmnew'

# Perl packages that may come new with the upgrade, each with its reason (SBOM-2: none without one).
PERL_ALLOWED = {'perl-locale': 'EL10 split of perl-POSIX: perl-POSIX 2.20 requires it'}
# The units of the release upgrade itself are enabled for its own run, not settings of the host.
RU_OWN_UNITS = ('efa-release-upgrade-finish.service', 'efa-release-upgrade-recover.service')
# A settings file that is a file of its package without a change (rpm -V): the package may change, add or drop it.
PACKAGE_FILE = 'package'
# Files of the OS packages that change with the release, never written by eFa-next: when they were the package's own file before
# the upgrade (PACKAGE_FILE), a change or their removal is expected. Everything eFa-next writes must stay the same.
OS_CHANGED_FILES = ('/etc/postfix/access', '/etc/postfix/canonical', '/etc/postfix/generic', '/etc/postfix/relocated', '/etc/postfix/virtual',
                    '/etc/postfix/header_checks', '/etc/unbound/conf.d/example.com.conf', '/etc/unbound/conf.d/remote-control.conf')
# Files of packages leapp removes on its own (php-fpm is not in EL10 for eFa-next): their removal is expected in any state.
OS_REMOVED_FILES = ('/etc/nginx/conf.d/php-fpm.conf', '/etc/nginx/default.d/php.conf')
# The services eFa-next runs besides its own efa-* units: each one enabled must be active after the finish (F5).
MANAGED_SERVICES = ('postfix', 'rspamd', 'clamd@scan', 'clamav-freshclam', 'mariadb', 'valkey', 'redis', 'unbound', 'nginx', 'dovecot',
                    'fail2ban', 'chronyd', 'firewalld')
LEAPP_REPORT = '/var/log/leapp/leapp-report.json'
VENDORS_DIR = '/etc/leapp/files/vendors.d'
# The signing key of repo.efa-next.eu (fingerprint 1823 D6D3 BB7D 5AEA 286E 836D CFE7 E079 16CC 8046), as leapp lists key IDs.
KEY_ID = 'cfe7e07916cc8046'
# rspamd comes from its own repository (repo id rspamd on EL9); its key 3FA3 47D5 E599 BE45 95CA 2576 FFA2 32ED BF21 E25E and subkey.
RSPAMD_REPO = 'https://rspamd.com/rpm-stable/centos-10/$basearch'
RSPAMD_KEY_IDS = ('ffa232edbf21e25e', 'fe2a076b3ef4a6c1')
# Network drivers EL9 has and EL10 no longer maintains, as leapp reports them; leapp preupgrade names the full list.
EL10_DROPPED_DRIVERS = ('e1000',)
# Postfix of EL10 has no Berkeley DB: hash: and btree: maps become lmdb: after the upgrade.
BDB_TYPES = ('hash', 'btree')
ALIAS_PARAMETERS = ('alias_maps', 'alias_database')
MIN_VERSION = (6, 0, 0, 6)
MIN_ROOT = 5 * 1024 ** 3
# /boot: leapp checks the space it needs itself and its inhibitor decides; below 400 MB it cannot fit, below 600 MB it is tight.
MIN_BOOT = 400 * 1024 ** 2
WARN_BOOT = 600 * 1024 ** 2
# A preupgrade report older than this does not count for the start: the system may have changed since.
REPORT_HOURS = 24
# The word leapp uses for a package repository in its vendor maps: data, not a call of the package manager.
REPO_TYPE = 'rpm'
ACTIONS = ('status', 'preflight', 'preupgrade', 'start', 'abort')
# The states in which leapp upgrade runs or has run: from here on only a VM snapshot leads back.
POINT_OF_NO_RETURN = ('upgrading', 'rebooting', 'finishing')
# x86-64-v3 (AlmaLinux 10 default build): AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT (abm in /proc/cpuinfo), MOVBE, XSAVE.
V3_FLAGS = ('avx', 'avx2', 'bmi1', 'bmi2', 'f16c', 'fma', 'abm', 'movbe', 'xsave')
# Inhibitors start may resolve itself; every other one stops. Empty: none is known yet, each one is looked at by a person.
KNOWN_INHIBITORS = ()
# Units that must run after the upgrade; one entry with | is enough when one of them runs.
REQUIRED_UNITS = ('postfix', 'rspamd', 'clamd@scan|clamd@amavisd|clamd', 'mariadb', 'valkey|redis', 'unbound', 'nginx',
                  'efa-web', 'efactl-runner', 'efa-maillog', 'efa-milter-health', 'chronyd', 'firewalld')
GTUBE = 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
EICAR = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


def os_major(os_release):
    """The major version from the text of /etc/os-release, or None."""
    match = re.search(r'^VERSION_ID="?(\d+)', os_release or '', re.M)
    return int(match.group(1)) if match else None


def version_tuple(text):
    match = re.search(r'\d+(?:\.\d+){3,}', text or '')
    return tuple(int(part) for part in match.group().split('.')) if match else None


def cpu_v3(cpuinfo):
    """True when the first flags line of /proc/cpuinfo has every flag of x86-64-v3."""
    match = re.search(r'^flags\s*:\s*(.*)$', cpuinfo or '', re.M)
    flags = set(match.group(1).split()) if match else set()
    return all(flag in flags for flag in V3_FLAGS)


def ifcfg_files(names):
    """The legacy network scripts among the file names of the network-scripts folder; ifcfg-lo does not count."""
    return sorted(name for name in names if name.startswith('ifcfg-') and name != 'ifcfg-lo')


def dropped_drivers(drivers):
    """{interface: driver} of the network cards whose driver EL10 no longer maintains."""
    return {name: driver for name, driver in sorted((drivers or {}).items()) if driver in EL10_DROPPED_DRIVERS}


def bdb_maps(postconf_n):
    """{parameter: [type:path, ...]} of the hash: and btree: maps in the lines of postconf -n."""
    found = {}
    for line in (postconf_n or '').splitlines():
        name, sep, value = line.partition('=')
        maps = re.findall(r'\b(?:%s):[^\s,]+' % '|'.join(BDB_TYPES), value) if sep else []
        if maps:
            found[name.strip()] = maps
    return found


def lmdb_changes(postconf_n, postconf_p=''):
    """The parameters of main.cf (postconf -n) and the service options of master.cf (postconf -P, service/type/name = value)
    with lmdb: instead of hash:/btree:, the map files to rebuild with postmap and the alias files for postalias. Caches
    (btree: with a $ in the path) are only switched, Postfix fills them again."""
    result, maps, aliases = {'parameters': {}, 'service_parameters': {}}, set(), set()
    for key, text in (('parameters', postconf_n), ('service_parameters', postconf_p)):
        values = {line.partition('=')[0].strip(): line.partition('=')[2].strip() for line in (text or '').splitlines() if '=' in line}
        for name, found in bdb_maps(text).items():
            result[key][name] = re.sub(r'\b(?:%s):' % '|'.join(BDB_TYPES), 'lmdb:', values[name])
            for item in found:
                path = item.split(':', 1)[1]
                if '$' not in path and path.startswith('/'):
                    (aliases if name in ALIAS_PARAMETERS else maps).add(path)
    return {**result, 'postmap': sorted(maps - aliases), 'postalias': sorted(aliases)}


def check(name, ok, detail, required=True):
    return {'name': name, 'ok': bool(ok), 'required': required, 'detail': detail}


def preflight(facts):
    """The checks from the facts efactl collects. ready only when every required check passed."""
    v3 = cpu_v3(facts.get('cpuinfo', ''))
    installed = version_tuple(facts.get('efa_version', ''))
    role = facts.get('cluster_role') or 'none'
    dropped = dropped_drivers(facts.get('net_drivers'))
    bdb = bdb_maps(facts.get('postconf_n', ''))
    source = os_id(facts.get('os_release', ''))
    distribution = distribution_problem(source, facts.get('rhel_registered'))
    checks = [
        check('Enterprise Linux 9', os_major(facts.get('os_release', '')) == 9, f"VERSION_ID {os_major(facts.get('os_release', ''))}"),
        check('Distribution', distribution is None, f'{source} 9 to {source} 10' if distribution is None else distribution),
        check('eFa-next 6.0.0.6 or newer', bool(installed) and installed >= MIN_VERSION, facts.get('efa_version') or 'unknown'),
        check('eFa-next repository for EL10', facts.get('el10_repo') is True,
              'reachable' if facts.get('el10_repo') is True else f"not reachable: {facts.get('el10_repo') or 'no answer'}. "
                                                                   'The upgrade stays disabled until eFa-next publishes packages for EL10.'),
        check('CPU x86-64-v3', v3, 'yes' if v3 else 'no: only the x86_64_v2 variant of AlmaLinux 10 fits this CPU; '
                                                     'ELevate installs the default build, so the upgrade is not offered.'),
        check('5 GB free on /', facts.get('free_root', 0) >= MIN_ROOT, f"{facts.get('free_root', 0) // 1024 ** 2} MB free"),
        check('400 MB free on /boot', facts.get('free_boot', 0) >= MIN_BOOT, f"{facts.get('free_boot', 0) // 1024 ** 2} MB free"),
        check('600 MB free on /boot', facts.get('free_boot', 0) >= WARN_BOOT, f"{facts.get('free_boot', 0) // 1024 ** 2} MB free: "
              'tight, leapp preupgrade tells whether it is enough', required=False),
        check('No pending updates', facts.get('pending') == [],
              'none' if facts.get('pending') == [] else f"{len(facts.get('pending') or [])} pending: update the system first"
              if isinstance(facts.get('pending'), list) else f"dnf: {facts.get('pending')}"),
        check('NetworkManager keyfiles', not facts.get('ifcfg'),
              'keyfiles only' if not facts.get('ifcfg') else 'convert first (nmcli connection migrate): ' + ', '.join(facts['ifcfg'])),
        check('Time synchronised', facts.get('time_synced') is True, 'yes' if facts.get('time_synced') else 'no: chrony must be synchronised'),
        check('Mail queue', True, f"{facts.get('queue', 0)} mails; they wait in the queue during the upgrade", required=False),
        check('Cluster role', role in ('none', 'standalone', ''), f'{role}: upgrade one node at a time, the others keep the mail'
              if role not in ('none', 'standalone', '') else 'single host', required=False),
        check('Wazuh agent', True, 'not installed' if not facts.get('wazuh') else
              f"{facts['wazuh'].get('version')} ({facts['wazuh'].get('enabled')}, {facts['wazuh'].get('active')}): stays exactly as it is over "
              'the upgrade, no update; its ossec.conf, client.keys and state are compared after it', required=False),
        check('Packages from other repositories', not third_party_packages(facts.get('installed_from')), 'none' if not
              third_party_packages(facts.get('installed_from')) else 'leapp knows no target for them, they may stay as EL9 packages or go: ' +
              ', '.join(f'{name} ({repo})' for name, repo in third_party_packages(facts.get('installed_from'))), required=False),
        check('No network teaming', not facts.get('team'), 'none' if not facts.get('team') else
              'teaming (teamd) is not in EL10: ' + ', '.join(facts['team']) + '. Convert it to a bond before the upgrade '
              '(nmcli), or the host has no network after it.'),
        check('Network drivers maintained in EL10', not dropped, 'yes' if not dropped else 'no longer maintained in EL10: ' +
              ', '.join(f'{name} ({driver})' for name, driver in dropped.items()) + '. Switch the virtual NIC (for example to '
              'virtio or vmxnet3) before the upgrade, or the host may have no network after it.', required=False),
        check('Postfix maps without Berkeley DB', not bdb, 'none' if not bdb else 'hash:/btree: in ' + ', '.join(sorted(bdb)) +
              ': switched to lmdb: and rebuilt after the upgrade', required=False),
        check('Repository of eFa-next for EL10 is the real one', not EL10_TEST_REPO and not EL10_TEST_IGNORED,
              EL10_TEST_IGNORED or ('yes' if not EL10_TEST_REPO else
                                    f'TEST: unsigned test builds from {EL10_TEST_REPO} (EFA_EL10_TEST_REPO); never in production'),
              required=False),
    ]
    warnings =[f"{item['name']}: {item['detail']}" for item in checks if not item['required'] and not item['ok']]
    reasons = [f"{item['name']}: {item['detail']}" for item in checks if item['required'] and not item['ok']]
    return {'ready': not reasons, 'checks': checks, 'reasons': reasons, 'warnings': warnings}


def leapp_report(report):
    """The inhibitors and the high risks of leapp-report.json; unknown inhibitors stop the upgrade."""
    inhibitors, high = [], []
    for entry in (report or {}).get('entries', []):
        if not isinstance(entry, dict):
            continue
        groups = set(entry.get('groups') or []) | set(entry.get('flags') or [])
        item = {'title': str(entry.get('title', ''))[:300], 'summary': str(entry.get('summary', ''))[:1000],
                'severity': entry.get('severity', ''), 'key': entry.get('key', ''),
                'remediation': [str(hint.get('context', '')) for hint in (entry.get('detail') or {}).get('remediations', [])
                                if isinstance(hint, dict)][:5]}
        if 'inhibitor' in groups:
            inhibitors.append(item)
        elif entry.get('severity') == 'high':
            high.append(item)
    unknown = [item for item in inhibitors if not any(re.search(pattern, item['title']) for pattern in KNOWN_INHIBITORS)]
    return {'inhibitors': inhibitors, 'high_risk': high, 'unknown_inhibitors': unknown, 'ok': not unknown}


# Owner, 2026-11-12: the start may leave out the backup when a VM snapshot is the way back. Only with this sentence typed in
# (English or German), besides the snapshot box and the host name; the default stays the encrypted external backup.
SNAPSHOT_ONLY_PHRASES = ('without backup, snapshot only', 'ohne backup, nur snapshot')


def snapshot_only_choice(typed):
    """(True, None) for the typed sentence, (False, None) for an empty field, (False, why) for anything else."""
    text = ' '.join((typed or '').split()).lower()
    if not text:
        return False, None
    if text in SNAPSHOT_ONLY_PHRASES:
        return True, None
    return False, f'To start without a backup type exactly: {SNAPSHOT_ONLY_PHRASES[0]} (or: ohne Backup, nur Snapshot). Leave it empty for the backup.'


def start_problem(snapshot, typed_host, hostname, state, now):
    """None when start may run: a VM snapshot confirmed, the host name typed, and a fresh preupgrade without inhibitors."""
    if (snapshot or '').strip() != 'yes':
        return 'Confirm that a VM snapshot of this host exists: without one there is no way back.'
    if not hostname or (typed_host or '').strip().lower() != hostname.lower():
        return f'Type the host name {hostname} to confirm.'
    report = (state or {}).get('preupgrade') or {}
    if not report.get('ok'):
        return 'Run preupgrade first; it must finish without an unknown inhibitor.'
    if now - report.get('time', 0) > REPORT_HOURS * 3600:
        return f'The preupgrade report is older than {REPORT_HOURS} hours: run preupgrade again.'
    if (state or {}).get('state') in ('preupgrade', 'starting', *POINT_OF_NO_RETURN):
        return f"A step runs already: {state['state']}."
    return None


def abort_problem(state):
    """None when abort may stop: only before leapp upgrade starts."""
    if (state or {}).get('state') in POINT_OF_NO_RETURN:
        return 'leapp upgrade has started: abort is no longer possible. Only the VM snapshot leads back.'
    return None


# The format leapp-upgrade-el9toel10 0.24 takes for vendor maps (as the maps of leapp-data-almalinux): 1.3.0, data stream 4.2,
# and the distribution in every repository entry.
VENDOR_MAP_FORMAT = '1.3.0'
VENDOR_DATA_STREAM = '4.2'


def vendor_map(pesid, el9_repoid, el10_repoid, distro):
    """A leapp vendor map: the EL9 repository of a vendor to its EL10 one, for this distribution."""
    def entries(major, repoid):
        return [{'major_version': major, 'repoid': repoid, 'arch': 'x86_64', 'channel': 'ga', 'repo_type': REPO_TYPE, 'distro': distro}]
    return {'datetime': '202611100000Z', 'version_format': VENDOR_MAP_FORMAT, 'provided_data_streams': [VENDOR_DATA_STREAM],
            'mapping': [{'source_major_version': '9', 'target_major_version': '10',
                         'entries': [{'source': f'{pesid}-el9', 'target': [f'{pesid}-el10']}]}],
            'repositories': [{'pesid': f'{pesid}-el9', 'entries': entries('9', el9_repoid)},
                             {'pesid': f'{pesid}-el10', 'entries': entries('10', el10_repoid)}]}


# No package events: the packages keep their names from EL9 to EL10.
VENDOR_PES = {'legal_notice': '', 'packageinfo': [], 'provided_data_streams': [VENDOR_DATA_STREAM], 'timestamp': '202611100000Z'}


def vendor_files(distro='almalinux'):
    """The leapp vendor files for the eFa-next and rspamd repositories: the EL10 repository, its mapping from the EL9 one, no
    package events, the keys."""
    repo = ('[efa-next-el10]\nname=eFa-next EL10\nbaseurl=' + EL10_REPO + '\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n'
            'gpgkey=https://repo.efa-next.eu/RPM-GPG-KEY-efa-next\n')
    if EL10_TEST_REPO:
        repo = ('[efa-next-el10]\nname=eFa-next EL10 TEST BUILDS (unsigned, not for production)\nbaseurl=' + EL10_REPO +
                '\nenabled=1\ngpgcheck=0\nrepo_gpgcheck=0\n')
    rspamd_repo = ('[rspamd-el10]\nname=Rspamd stable repository EL10\nbaseurl=' + RSPAMD_REPO + '\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\n'
                   'gpgkey=https://rspamd.com/rpm/rspamd.asc\n'
                   # The same pin as the EL9 repository: rspamd 5 and newer stay out until eFa-next allows them.
                   'exclude=rspamd-[5-9]* rspamd-[1-9][0-9]*\n')
    pes = json.dumps(VENDOR_PES, indent=1) + '\n'
    return {'efa-next.repo': repo, 'efa-next_map.json': json.dumps(vendor_map('efa-next', 'efa-next', 'efa-next-el10', distro), indent=1) + '\n',
            'efa-next_pes.json': pes, 'efa-next.sigs': KEY_ID + '\n',
            'rspamd.repo': rspamd_repo, 'rspamd_map.json': json.dumps(vendor_map('rspamd', 'rspamd', 'rspamd-el10', distro), indent=1) + '\n',
            'rspamd_pes.json': pes, 'rspamd.sigs': ''.join(key + '\n' for key in RSPAMD_KEY_IDS)}


# The repository files of eFa-next and rspamd on the host: leapp uses the vendors.d copies only during the upgrade.
REPO_FILES = ('/etc/yum.repos.d/efa-next.repo', '/etc/yum.repos.d/rspamd.repo')
# The EL9 repository of eFa-next as docs/install.md writes it. leapp takes the vendor efa-next only while this repository is
# enabled on the host; without it leapp removes eFa-next ("Removing dependent packages"), as in the first rehearsal.
EL9_REPO = ('[efa-next]\nname=eFa-next EL9\nbaseurl=https://repo.efa-next.eu/el9/\nenabled=0\ngpgcheck=1\nrepo_gpgcheck=1\n'
            'gpgkey=https://repo.efa-next.eu/RPM-GPG-KEY-efa-next\n')


def repo_enabled(text, on):
    """The repository file with the section [efa-next] on (1) or off (0); the other sections as they are."""
    text = text or EL9_REPO
    head = re.search(r'^\[efa-next\][^\n]*\n', text, flags=re.M)
    if not head:
        text = text.rstrip('\n') + '\n\n' + EL9_REPO if text.strip() else EL9_REPO
        head = re.search(r'^\[efa-next\][^\n]*\n', text, flags=re.M)
    end = re.search(r'^\[', text[head.end():], flags=re.M)
    end = head.end() + end.start() if end else len(text)
    body = text[head.end():end]
    if re.search(r'^enabled\s*=', body, flags=re.M):
        body = re.sub(r'^enabled\s*=.*$', f'enabled={int(on)}', body, flags=re.M)
    else:
        body = f'enabled={int(on)}\n' + body
    return text[:head.end()] + body + text[end:]


# The package data of leapp-data-almalinux (pes-events.json) drops packages EL10 still has: nginx of the module stream 1.26
# (#17687, AlmaLinux 10 AppStream has it without a module), sendmail-milter (#14207, in EPEL 10; pymilter needs its
# libmilter) and python3-pytz (#17202, in EPEL 10; certbot 4.2 needs it). leapp's own customisation files keep them
# (to_keep takes names out of the removals) and take eFa-next and what it needs from the target repositories (to_install).
# efactl adds these lines for each leapp run and takes them out again after; the rest of the files stays as leapp ships it.
LEAPP_TRANSACTION_DIR = '/etc/leapp/transaction'
LEAPP_TO_INSTALL = ('eFa-next', 'eFa-next-base', 'python3-pymilter', 'certbot', 'python3-certbot-nginx')
LEAPP_TO_KEEP = ('nginx', 'sendmail-milter', 'python3-pytz', 'wazuh-agent')
LEAPP_FILES_MARK = '# eFa-next release upgrade (efactl), removed after the leapp run:'


def transaction_with(text, names):
    """A leapp transaction file (to_install, to_keep) with these names in a block of its own; again gives the same."""
    text = transaction_without(text)
    return (text.rstrip('\n') + '\n' if text.strip() else '') + LEAPP_FILES_MARK + '\n' + ''.join(name + '\n' for name in names)


def transaction_without(text):
    """The file without the block of efactl: as leapp shipped it."""
    head, _mark, _block = (text or '').partition(LEAPP_FILES_MARK + '\n')
    return head


# leapp's EPEL vendor repository (vendors.d/epel.repo) is the newest EPEL 10, which may be built for a newer minor release
# than the target (EPEL 10.3 pyOpenSSL needs the cryptography of RHEL 10.3; AlmaLinux 10.2 has an older one). Its metalink
# points at the EPEL of the target minor release for the leapp run: still the one EPEL source, with leapp's key.
LEAPP_EPEL_REPO = '/etc/leapp/files/vendors.d/epel.repo'
LEAPP_UPGRADE_PATHS = '/usr/share/leapp-repository/repositories/system_upgrade/common/files/upgrade_paths.json'


def leapp_target(paths, distro, version_id):
    """The release leapp upgrades to by default (the last path for this release, else for its major version), or ''."""
    default = ((paths or {}).get(distro) or {}).get('default') or {}
    targets = default.get(version_id) or default.get(version_id.split('.')[0]) or []
    return targets[-1] if targets else ''


def epel_pinned(text, target):
    """epel.repo of leapp with its metalink on EPEL of the target release (10.2), or back on the newest (target '')."""
    repo = f'epel-{target}' if re.fullmatch(r'\d+\.\d+', target or '') else 'epel-10'
    return re.sub(r'(metalink=\S*[?&]repo=)epel-10(\.\d+)?(?=&|$)', r'\g<1>' + repo, text, flags=re.M)


# The logs leapp writes per step; efactl reads the vendors it took and its dnf transaction check (before any change).
LEAPP_LOG = '/var/log/leapp/leapp-{}.log'
VENDOR_ACTIVE = 'Vendor efa-next found in active list'
# The packages eFa-next cannot do without (rpm/eFa*.spec): leapp must upgrade them, never remove them. On EL10 redis goes,
# valkey comes in its place.
# Packages of the operator that leapp leaves exactly as they are (no update, no reinstall): the Wazuh agent is one build for
# EL9 and EL10, and its package scripts stop and restart a running agent and delete /etc/systemd/system/wazuh-agent.service
# (a mask, as on a clone whose agent must never run). leapp may not touch them; to_keep keeps them out of the removals.
KEEP_AS_IS = ('wazuh-agent',)
# The repositories of the distribution, of eFa-next and of the vendors leapp takes; what comes from elsewhere is listed.
KNOWN_REPOS = re.compile(r'^(@?(anaconda|System|commandline)|almalinux.*|baseos|appstream|crb|extras|highavailability|nfv|rt|sap.*|'
                         r'resilientstorage|plus|epel.*|rspamd.*|efa-next.*|elevate|wazuh)$')


def third_party_packages(installed_from):
    """(name, repository) of the installed packages from a repository that is none of KNOWN_REPOS."""
    found = []
    for line in installed_from or []:
        name, _sep, repo = line.partition(' ')
        if repo and not KNOWN_REPOS.match(repo.strip()):
            found.append((name, repo.strip()))
    return found


KEEP_PACKAGES = ('eFa-next', 'eFa-next-base', 'postfix', 'mariadb-server', 'rspamd', 'nginx', 'clamd', 'unbound',
                 'python3-pymilter', 'certbot', 'python3-certbot-nginx', 'python3-flask', 'python3-waitress', 'python3-PyMySQL')
REPLACED_BY = {'redis': 'valkey'}
ARCHES = ('x86_64', 'noarch', 'i686', 'aarch64')
TRANSACTION_MARK = 'dnf_transaction_check: '


def leapp_transaction(log_text):
    """The last dnf transaction check of a leapp log: {section: [package names]} (Installing, Upgrading, Removing,
    Removing dependent packages, ...); {} when the log has none."""
    found, section, done = {}, None, False
    for line in (log_text or '').splitlines():
        if TRANSACTION_MARK not in line:
            continue
        text = line.split(TRANSACTION_MARK, 1)[1]
        if re.match(r'^(Installing|Upgrading|Removing|Downgrading|Reinstalling)[A-Za-z ]*:$', text):
            # A section after the summary of the last check starts the next check ("Downloading Packages:" is none).
            if done:
                found, done = {}, False
            section = text[:-1]
            found.setdefault(section, [])
        elif text.startswith('Transaction Summary'):
            section, done = None, True
        elif section and text.startswith(' ') and text.split() and text.split()[0] not in ARCHES:
            found[section].append(text.split()[0])
    return found


def removal_problems(log_text, report, test_builds=False):
    """Why leapp must not go on: the vendor efa-next not taken, eFa-next not in the upgrade, a package eFa-next needs
    removed, or the report saying it would remove eFa-next as a package of a third party. [] when none."""
    problems = []
    if VENDOR_ACTIVE not in (log_text or ''):
        problems.append('leapp did not take the eFa-next repository (vendor efa-next not active): it would remove eFa-next.')
    found = leapp_transaction(log_text)
    if not found:
        return problems + ['leapp wrote no dnf transaction check: what it would remove is unknown.']
    removed = set(found.get('Removing', [])) | set(found.get('Removing dependent packages', []))
    added = {name for section, names in found.items() if section.startswith(('Installing', 'Upgrading', 'Reinstalling')) for name in names}
    for name in sorted(removed):
        if name in KEEP_PACKAGES or (name in REPLACED_BY and REPLACED_BY[name] not in added):
            problems.append(f'leapp would remove {name}, which eFa-next needs.')
    for name in ('eFa-next', 'eFa-next-base'):
        if name not in added and name not in removed:
            problems.append(f'{name} is not in the upgrade of leapp.')
    for name in KEEP_AS_IS:
        touched = [section for section, names in found.items() if name in names]
        if touched:
            problems.append(f"leapp would change {name} ({', '.join(touched)}): it must stay as it is (its scripts would stop, "
                            'restart or unmask it).')
    # Test builds are unsigned: leapp always names them here, the transaction above decides for them.
    for entry in (report or {}).get('entries', []) if not test_builds else []:
        if isinstance(entry, dict) and 'not signed by the distribution vendor' in str(entry.get('title', '')) and \
                re.search(r'^\s*- eFa-next(-base)?\s*$', str(entry.get('summary', '')), flags=re.M):
            problems.append('leapp counts eFa-next as a package of a third party that may be removed.')
            break
    return problems


# The safety net of the start (outside the packages, which leapp may remove): at the first EL10 boot without efactl it puts
# eFa-next back from the EL10 repository and runs the checks; else maintenance stays on with a note on the console.
RECOVER_DIR = '/etc/efa-release-upgrade'
RECOVER_UNIT = 'efa-release-upgrade-recover.service'
RECOVER_UNIT_FILE = '/etc/systemd/system/' + RECOVER_UNIT
RECOVER_MOTD = '/etc/motd.d/efa-release-upgrade'


def recover_files(script, finish_mark, efactl='/usr/sbin/efactl'):
    """{path: text} of the safety net: the script (of the platform, release_recover_script), its EL10 repository and its unit."""
    unit = f'''[Unit]
Description=eFa-next release upgrade: install eFa-next again if the upgrade removed it
ConditionPathExists={finish_mark}
ConditionPathExists=!{efactl}
Wants=network-online.target
After=network-online.target
Before=efa-release-upgrade-finish.service

[Service]
Type=oneshot
ExecStart=/bin/sh {RECOVER_DIR}/recover.sh
TimeoutStartSec=1h

[Install]
WantedBy=multi-user.target
'''
    return {f'{RECOVER_DIR}/recover.sh': script, f'{RECOVER_DIR}/repos/efa-next-el10.repo': vendor_files()['efa-next.repo'],
            RECOVER_UNIT_FILE: unit}


def repo_el10(text):
    """A repository file of EL9 (efa-next.repo, rspamd.repo) for EL10: the folders and names of the release."""
    text = re.sub(r'(repo\.efa-next\.eu/)el9\b', r'\1el10', text)
    text = re.sub(r'(rspamd\.com/rpm(?:-stable)?/)centos-9\b', r'\1centos-10', text)
    return re.sub(r'^(name=.*)\bEL9\b', r'\1EL10', text, flags=re.M)


# The settings compared before and after (EL10-5): text files below these, by their SHA-256. main.cf and master.cf are
# compared as postconf -n/-P instead, the compiled tables not at all.
CONFIG_DIRS = ('/etc/rspamd/local.d', '/etc/rspamd/override.d', '/etc/nginx/conf.d', '/etc/unbound/conf.d', '/etc/fail2ban/jail.d',
               '/etc/clamd.d/scan.conf', '/etc/ssh/sshd_config.d/40-efa.conf', '/etc/ssh/sshd_config.d/00-efa-root.conf', '/etc/postfix',
               '/etc/efa-web', '/etc/eFa/wazuh.json', '/var/ossec/etc/ossec.conf')
CONFIG_SKIP = ('/etc/postfix/main.cf', '/etc/postfix/master.cf')
CONFIG_SKIP_ENDINGS = ('.db', '.lmdb', '.rpmnew', '.rpmsave', '.efactl')


def config_postconf(text):
    """postconf -n or -P as sorted lines, the table types as after the upgrade (hash/btree are lmdb there on purpose)."""
    lines = {re.sub(r'\b(?:%s):' % '|'.join(BDB_TYPES), 'lmdb:', line.strip()) for line in (text or '').splitlines() if '=' in line}
    return sorted(line for line in lines if not line.startswith('default_database_type'))


def config_diff(before, after):
    """What differs in the settings: changed postconf lines, files changed, added or removed, enabled units. Empty: the same."""
    found = []
    for key in ('postconf_n', 'postconf_p'):
        old, new = set(before.get(key, [])), set(after.get(key, []))
        found += [f'{key} before: {line}' for line in sorted(old - new)] + [f'{key} after: {line}' for line in sorted(new - old)]
    # A file of its package, unchanged before and after (or dropped, or new with it), is the package's; everything an admin
    # or eFa-next changed still counts, also when the package replaced it.
    old_files, new_files = before.get('files', {}), after.get('files', {})
    found += [f'changed: {path}' for path in sorted(set(old_files) & set(new_files)) if old_files[path] != new_files[path]
              and not (path in OS_CHANGED_FILES and old_files[path] == PACKAGE_FILE)]
    found += [f'removed: {path}' for path in sorted(set(old_files) - set(new_files)) if old_files[path] != PACKAGE_FILE
              and path not in OS_REMOVED_FILES]
    found += [f'added: {path}' for path in sorted(set(new_files) - set(old_files)) if new_files[path] != PACKAGE_FILE]
    old_units = set(before.get('units', [])) - set(RU_OWN_UNITS)
    new_units = set(after.get('units', [])) - set(RU_OWN_UNITS)
    found += [f'unit no longer enabled: {unit}' for unit in sorted(old_units - new_units)]
    found += [f'unit newly enabled: {unit}' for unit in sorted(new_units - old_units)]
    return found


def el9_leftovers(packages):
    """Installed package names (name-version-release) still built for EL9 after the upgrade; gpg-pubkey does not count."""
    return sorted(item for item in packages if '.el9' in item and not item.startswith('gpg-pubkey'))


def mail_recipients(domains, logged, listed):
    """F2: the recipients to try for the test mail, most likely valid first: recent recipients of clean mail in the mail log, the
    addresses of the plain relay recipient tables, then postmaster@ and abuse@ of each own domain. Only addresses of own domains."""
    domains = sorted({item.lower() for item in domains})
    found = []
    for item in list(logged) + list(listed) + [f'{local}@{domain}' for domain in domains for local in ('postmaster', 'abuse')]:
        for address in re.split(r'[\s,;<>]+', str(item or '').lower()):
            if re.fullmatch(r'[a-z0-9._%+=-]+@[a-z0-9.-]+', address) and address.rsplit('@', 1)[1] in domains and address not in found:
                found.append(address)
    return found[:20]


def table_addresses(text):
    """The full addresses in the first column of a Postfix lookup table source (relay_recipients)."""
    return [line.split()[0] for line in (text or '').splitlines() if line.strip() and not line.lstrip().startswith('#')
            and '@' in line.split()[0] and not line.split()[0].startswith('@')]


def leftover_plan(names, required_by, user_installed, new_since_baseline):
    """F4: (remove, kept) for leftover packages (EL9 builds, Perl that came new with the upgrade). A package goes only when no
    installed package needs it and it is no choice of the admin: user installed counts only for what was there before the upgrade
    (leapp installs as the user). kept: {name: why}, shown as a hint."""
    remove, kept = [], {}
    for name in sorted(set(names)):
        if required_by.get(name):
            kept[name] = 'needed by ' + ', '.join(sorted(required_by[name])[:5])
        elif name in user_installed and name not in new_since_baseline:
            kept[name] = 'installed by the admin'
        else:
            remove.append(name)
    return remove, kept


def service_problems(states):
    """F5: the enabled services of eFa-next that do not run; states: {unit: (type, active state)} of the enabled ones. A oneshot
    unit that ran and ended is fine, a failed one is not."""
    return sorted(unit for unit, (kind, active) in states.items()
                  if active != 'active' and not (kind == 'oneshot' and active == 'inactive'))


def unit_problems(active):
    """The required units of which none runs; active is the set of active unit names."""
    return [entry for entry in REQUIRED_UNITS if not any(name in active for name in entry.split('|'))]


def strip_counters(ruleset):
    """An nft ruleset without its counters, which change with every packet."""
    return re.sub(r'\s*counter packets \d+ bytes \d+', '', ruleset or '')


def compare(before, after):
    """The keys whose value changed between the baseline before leapp upgrade and the first EL10 boot."""
    return sorted(key for key in before if key in after and before[key] != after[key])


def post_checks(facts, before):
    """The checks after the first EL10 boot. ok only when every required one passed: then maintenance mode is lifted."""
    # F4: what the finish kept on purpose (needed by another package, installed by the admin) is a hint, not a failure.
    kept = facts.get('leftovers_kept') or {}
    every_left = el9_leftovers(facts.get('packages', []))
    left = [item for item in every_left if item.rsplit('-', 2)[0] not in kept]
    perl_extra = sorted(set(facts.get('perl_extra') or []) - set(PERL_ALLOWED) - set(kept))
    hints = [f'{name}: {why}' for name, why in sorted(kept.items())]
    down = service_problems(facts.get('service_states') or {})
    changed = compare({key: before.get(key) for key in ('addresses', 'routes', 'firewall', 'mail_block', 'counts', 'wazuh')},
                      {key: facts.get(key) for key in ('addresses', 'routes', 'firewall', 'mail_block', 'counts', 'wazuh')})
    units = unit_problems(set(facts.get('active', [])))
    mail = facts.get('mail', {})
    checks = [
        check('Enterprise Linux 10', os_major(facts.get('os_release', '')) == 10, f"VERSION_ID {os_major(facts.get('os_release', ''))}"),
        # S23: never a change of the distribution (leapp-data-almalinux on RHEL or Rocky would make them AlmaLinux).
        check('Same distribution', bool(before.get('os_id')) and os_id(facts.get('os_release', '')) == before.get('os_id'),
              f"{before.get('os_id') or 'unknown'} before, {os_id(facts.get('os_release', '')) or 'unknown'} now"),
        check('EL10 kernel', '.el10' in facts.get('kernel', ''), facts.get('kernel', '')),
        check('No EL9 packages left', not left, ', '.join(left[:20]) or 'none'),
        check('Leftover packages kept', not kept, '; '.join(hints[:20]) + ' (remove them by hand when nothing needs them any more)'
              if kept else 'none', required=False),
        check('dnf check', facts.get('dnf_check') == '', facts.get('dnf_check') or 'clean'),
        check('SELinux enforcing', facts.get('selinux') == 'Enforcing', facts.get('selinux', '')),
        check('No new SELinux denials', facts.get('avc', 0) == 0, f"{facts.get('avc', 0)} AVC since boot"),
        check('Time synchronised', facts.get('time_synced') is True, 'chrony'),
        check('Addresses and routes unchanged', 'addresses' not in changed and 'routes' not in changed, 'same' if not
              {'addresses', 'routes'} & set(changed) else 'changed'),
        check('Firewall zones and ports unchanged', 'firewall' not in changed, 'same' if 'firewall' not in changed else 'changed'),
        check('Wazuh agent unchanged', 'wazuh' not in changed, 'not installed' if not before.get('wazuh') else 'same: package, the program runs (-V), ossec.conf, '
              'client.keys, enabled and running state' if 'wazuh' not in changed else
              f"before {before.get('wazuh')}, now {facts.get('wazuh') or 'not installed'}"),
        check('Other nft tables unchanged (mail block)', 'mail_block' not in changed, 'same' if 'mail_block' not in changed else 'changed'),
        check('Services running', not units, 'all' if not units else 'not running: ' + ', '.join(units)),
        check('Every enabled eFa-next service active', 'service_states' in facts and not down,
              ('not active: ' + ', '.join(down[:20])) if down else 'all' if 'service_states' in facts else 'not checked'),
        check('Test mail accepted', mail.get('clean') == 'accepted', mail.get('clean', 'not run')),
        check('GTUBE rejected', mail.get('gtube') == 'rejected', mail.get('gtube', 'not run')),
        check('EICAR rejected', mail.get('eicar') == 'rejected', mail.get('eicar', 'not run')),
        check('DKIM keys unchanged', facts.get('dkim') == before.get('dkim'), f"{len(facts.get('dkim') or [])} keys"),
        check('Database check', facts.get('db_check') == '', facts.get('db_check') or 'ok'),
        check('Quarantine, domain and user counts unchanged', 'counts' not in changed, json.dumps(facts.get('counts'))),
        check('Backup works', facts.get('backup') is True, 'ok' if facts.get('backup') is True else str(facts.get('backup'))),
        check('Perl only as allowed', not perl_extra, ', '.join(perl_extra) or 'ok' + ''.join(
            f'; {name}: {PERL_ALLOWED[name]}' for name in sorted(set(facts.get('perl_extra') or []) & set(PERL_ALLOWED)))),
        check('Settings unchanged', 'config' in before and not facts.get('config_diff'),
              'same' if 'config' in before and not facts.get('config_diff') else
              '; '.join((facts.get('config_diff') or ['no settings export from before the upgrade'])[:20])),
        check('nginx configuration test', facts.get('nginx_test') == '', facts.get('nginx_test') or 'ok'),
    ]
    failed = [f"{item['name']}: {item['detail']}" for item in checks if item['required'] and not item['ok']]
    return {'ok': not failed, 'checks': checks, 'failed': failed}


def self_test():
    v3 = 'processor : 0\nflags : fpu avx avx2 bmi1 bmi2 f16c fma abm movbe xsave sse4_2\n'
    assert cpu_v3(v3) and not cpu_v3(v3.replace(' avx2', '')) and not cpu_v3('')
    assert os_major('NAME="AlmaLinux"\nVERSION_ID="9.8"\n') == 9 and os_major('VERSION_ID=10.1\n') == 10 and os_major('') is None
    assert ifcfg_files(['readme-ifcfg-rh.txt', 'ifcfg-lo', 'ifcfg-ens33']) == ['ifcfg-ens33']
    facts = {'os_release': 'ID="almalinux"\nVERSION_ID="9.8"\n', 'efa_version': '6.0.0.6', 'el10_repo': True, 'cpuinfo': v3, 'free_root': 6 * 1024 ** 3,
             'free_boot': 2 * 1024 ** 3, 'pending': [], 'ifcfg': [], 'time_synced': True, 'queue': 3, 'cluster_role': 'none'}
    assert preflight(facts)['ready']
    for key, bad in (('efa_version', '6.0.0.5.1'), ('el10_repo', 'HTTP 404'), ('free_boot', 399 * 1024 ** 2), ('pending', [{'package': 'x'}]),
                     ('ifcfg', ['ifcfg-ens33']), ('time_synced', False), ('os_release', 'VERSION_ID="10.0"\n'), ('cpuinfo', '')):
        found = preflight({**facts, key: bad})
        assert not found['ready'] and found['reasons'], key
    assert preflight({**facts, 'cluster_role': 'client', 'queue': 5000})['ready']
    teamed = preflight({**facts, 'team': ['team0', 'team0-port1']})
    assert not teamed['ready'] and 'team0, team0-port1' in teamed['reasons'][0] and 'bond' in teamed['reasons'][0]
    assert preflight({**facts, 'team': []})['ready']
    tight = preflight({**facts, 'free_boot': 555 * 1024 ** 2})
    assert tight['ready'] and tight['warnings'] and '/boot' in tight['warnings'][0]
    report = {'entries': [{'title': 'Missing required answers', 'groups': ['inhibitor'], 'severity': 'high', 'key': 'a',
                           'detail': {'remediations': [{'type': 'hint', 'context': 'leapp answer'}]}},
                          {'title': 'Old flag style', 'flags': ['inhibitor'], 'severity': 'high', 'key': 'b'},
                          {'title': 'Risky', 'groups': ['network'], 'severity': 'high', 'key': 'c'},
                          {'title': 'Info', 'groups': [], 'severity': 'info', 'key': 'd'}, 'junk']}
    parsed = leapp_report(report)
    assert [i['key'] for i in parsed['inhibitors']] == ['a', 'b'] and [i['key'] for i in parsed['high_risk']] == ['c']
    assert not parsed['ok'] and parsed['inhibitors'][0]['remediation'] == ['leapp answer'] and leapp_report({})['ok']
    ok_state = {'state': 'ready', 'preupgrade': {'ok': True, 'time': 1000}}
    assert start_problem('yes', 'MX.example', 'mx.example', ok_state, 2000) is None
    assert start_problem('', 'mx.example', 'mx.example', ok_state, 2000) and start_problem('yes', 'other', 'mx.example', ok_state, 2000)
    assert start_problem('yes', 'mx.example', 'mx.example', {'preupgrade': {'ok': False, 'time': 1000}}, 2000)
    assert snapshot_only_choice('') == (False, None) and snapshot_only_choice('  Without  Backup, snapshot ONLY ') == (True, None)
    assert snapshot_only_choice('ohne Backup, nur Snapshot') == (True, None) and snapshot_only_choice('yes')[1]
    assert start_problem('yes', 'mx.example', 'mx.example', ok_state, 1000 + REPORT_HOURS * 3600 + 1)
    assert start_problem('yes', 'mx.example', 'mx.example', {**ok_state, 'state': 'upgrading'}, 2000)
    assert start_problem('yes', 'mx.example', '', ok_state, 2000)
    assert abort_problem({'state': 'starting'}) is None and abort_problem({}) is None and abort_problem({'state': 'upgrading'})
    files = vendor_files()
    assert set(files) == {'efa-next.repo', 'efa-next_map.json', 'efa-next_pes.json', 'efa-next.sigs', 'rspamd.repo', 'rspamd_map.json',
                          'rspamd_pes.json', 'rspamd.sigs'}
    for name in ('efa-next_map.json', 'rspamd_map.json'):
        found = json.loads(files[name])
        assert found['version_format'] == '1.3.0' and found['provided_data_streams'] == ['4.2'], name
        assert all(entry['distro'] == 'almalinux' for repo in found['repositories'] for entry in repo['entries']), name
    assert json.loads(files['efa-next_pes.json'])['packageinfo'] == []
    assert json.loads(files['efa-next_map.json'])['mapping'] and json.loads(files['rspamd_map.json'])['repositories'][0]['entries'][0]['repoid'] == 'rspamd'
    el9_repo = ('[efa-next]\nname=eFa-next EL9\nbaseurl=https://repo.efa-next.eu/el9/\nenabled=0\n\n[rspamd]\nname=Rspamd stable repository\n'
                'baseurl=https://rspamd.com/rpm-stable/centos-9/$basearch\nexclude=rspamd-[5-9]*\n')
    switched = repo_el10(el9_repo)
    assert 'repo.efa-next.eu/el10/' in switched and 'centos-10/$basearch' in switched and 'name=eFa-next EL10' in switched
    assert 'el9' not in switched and 'centos-9' not in switched and 'exclude=rspamd-[5-9]*' in switched and repo_el10(switched) == switched
    assert dropped_drivers({'enp0s3': 'e1000', 'ens192': 'vmxnet3', 'eth1': 'e1000e'}) == {'enp0s3': 'e1000'}
    # The source repository on for leapp, off again after; a missing file is written as docs/install.md has it.
    on = repo_enabled(el9_repo, True)
    assert '[efa-next]\nname=eFa-next EL9\nbaseurl=https://repo.efa-next.eu/el9/\nenabled=1\n' in on and on.count('enabled=') == 1
    assert repo_enabled(on, False) == el9_repo and 'enabled=1\ngpgcheck=1' in repo_enabled('', True)
    assert repo_enabled('[rspamd]\nenabled=1\n', True).startswith('[rspamd]\nenabled=1\n\n[efa-next]')
    # The dnf transaction check of leapp: the first rehearsal (vendor not taken, eFa-next removed) and a good one.
    def log(lines):
        return ''.join(f'2026-11-10 09:40:42.4 DEBUG PID: 1 leapp.workflow.TargetTransactionCheck.{TRANSACTION_MARK}{line}\n' for line in lines)
    bad = ('Vendor efa-next not in active list, skipping\n' + log(['Installing:', ' postfix  x86_64  2:3.8.5-10.el10_2  baseos  1 M',
           'Removing:', ' redis    x86_64  6.2.24-1.el9_8   @System  1 M', ' nginx', '      x86_64  2:1.26.3-9  @System 1 M',
           'Removing dependent packages:', ' eFa-next  noarch  6.0.0.6-1.el9  @System  1 M', '', 'Transaction Summary']))
    assert leapp_transaction(bad)['Removing'] == ['redis', 'nginx'] and leapp_transaction('') == {}
    problems = removal_problems(bad, {})
    assert len(problems) == 5 and 'vendor efa-next not active' in problems[0] and 'remove eFa-next,' in ' '.join(problems), problems
    good = ('Vendor efa-next found in active list, processing file efa-next.sigs\n' + log(['Installing:', ' valkey  x86_64  8.0  appstream 1 M',
            'Upgrading:', ' eFa-next  noarch  6.0.0.6-1.el10  efa-next-el10  1 M', ' eFa-next-base  noarch  1:6.0.0.6-1.el10  efa-next-el10  1 M',
            'Removing:', ' redis  x86_64  6.2.24-1.el9_8  @System  1 M', 'Transaction Summary']))
    assert removal_problems(good, {}) == [], removal_problems(good, {})
    third = {'entries': [{'title': 'Packages not signed by the distribution vendor found on the system',
                          'summary': 'Third-party packages may be removed ...\n    - eFa-next\n    - eFa-next-base\n'}]}
    assert removal_problems(good, third) and removal_problems(good, third, test_builds=True) == []
    assert 'no dnf transaction check' in removal_problems(VENDOR_ACTIVE, {})[0]
    net = recover_files('#!/bin/sh\n', '/var/lib/eFa/release-upgrade/finish-pending')
    shipped = '# packages to install\n#pkg\n'
    added = transaction_with(shipped, LEAPP_TO_KEEP)
    assert added.startswith(shipped) and added.endswith('nginx\nsendmail-milter\npython3-pytz\nwazuh-agent\n') and transaction_with(added, LEAPP_TO_KEEP) == added
    # The Wazuh agent of the operator stays exactly as it is: any change of leapp to it stops the upgrade.
    assert third_party_packages(['bash baseos', 'wazuh-agent wazuh', 'acme-tool @acme-repo', 'eFa-next @commandline', 'rspamd rspamd',
                                 'x epel', 'y almalinux-appstream']) == [('acme-tool', '@acme-repo')]
    log = lambda lines: ''.join(f'x TargetTransactionCheck.{TRANSACTION_MARK}{line}\n' for line in lines)
    kept = VENDOR_ACTIVE + '\n' + log(['Upgrading:', ' eFa-next  noarch  6.0.0.6-1.el10  efa-next-el10  1 M',
                                      ' eFa-next-base  noarch  1:6.0.0.6-1.el10  efa-next-el10  1 M', 'Transaction Summary'])
    assert removal_problems(kept, {}) == []
    for section in ('Upgrading', 'Reinstalling', 'Downgrading', 'Removing', 'Removing dependent packages'):
        touched = VENDOR_ACTIVE + '\n' + log(['Upgrading:', ' eFa-next  noarch  6.0.0.6-1.el10  efa-next-el10  1 M',
                                             ' eFa-next-base  noarch  1:6.0.0.6-1.el10  efa-next-el10  1 M', f'{section}:',
                                             ' wazuh-agent  x86_64  4.14.10-1  wazuh  10 M', 'Transaction Summary'])
        assert any('leapp would change wazuh-agent' in item for item in removal_problems(touched, {})), section
    assert transaction_without(added) == shipped and transaction_with('', ('a',)) == LEAPP_FILES_MARK + '\na\n'
    paths = {'almalinux': {'default': {'9.8': ['10.0', '10.1', '10.2'], '9': ['10.0', '10.1', '10.2'], '9.7': ['10.0', '10.1']}}}
    assert leapp_target(paths, 'almalinux', '9.8') == '10.2' and leapp_target(paths, 'almalinux', '9.6') == '10.2'
    assert leapp_target(paths, 'almalinux', '9.7') == '10.1' and leapp_target(paths, 'rocky', '9.8') == '' and leapp_target({}, 'x', '9') == ''
    epel = '[el10-epel]\nmetalink=https://mirrors.fedoraproject.org/metalink?repo=epel-10&arch=$basearch&infra=$infra\ngpgcheck=1\n'
    pinned = epel_pinned(epel, '10.2')
    assert 'metalink?repo=epel-10.2&arch=$basearch' in pinned and epel_pinned(pinned, '10.2') == pinned and epel_pinned(pinned, '') == epel
    assert epel_pinned(epel, '') == epel and epel_pinned(epel, 'x; rm') == epel
    assert set(net) == {RECOVER_DIR + '/recover.sh', RECOVER_DIR + '/repos/efa-next-el10.repo', RECOVER_UNIT_FILE}
    assert 'ConditionPathExists=!/usr/sbin/efactl' in net[RECOVER_UNIT_FILE] and '[efa-next-el10]' in net[RECOVER_DIR + '/repos/efa-next-el10.repo']
    postconf_n = ('alias_maps = hash:/etc/aliases\nalias_database = hash:/etc/aliases\nrelay_domains = hash:/etc/postfix/transport\n'
                  'postscreen_cache_map = btree:$data_directory/postscreen_cache\n'
                  'smtpd_helo_restrictions = permit_mynetworks, check_helo_access hash:/etc/postfix/helo_access, reject_invalid_helo_hostname\n'
                  'mynetworks = 127.0.0.0/8\nhashed_thing = cidr:/etc/postfix/x.cidr\n')
    assert sorted(bdb_maps(postconf_n)) == ['alias_database', 'alias_maps', 'postscreen_cache_map', 'relay_domains', 'smtpd_helo_restrictions']
    change = lmdb_changes(postconf_n)
    assert change['parameters']['smtpd_helo_restrictions'] == 'permit_mynetworks, check_helo_access lmdb:/etc/postfix/helo_access, reject_invalid_helo_hostname'
    assert change['parameters']['postscreen_cache_map'] == 'lmdb:$data_directory/postscreen_cache' and 'mynetworks' not in change['parameters']
    assert change['postmap'] == ['/etc/postfix/helo_access', '/etc/postfix/transport'] and change['postalias'] == ['/etc/aliases']
    master = lmdb_changes('', 'submission/inet/smtpd_sender_restrictions = check_sender_access hash:/etc/postfix/sub_senders, reject\n'
                              'smtp/inet/smtpd_tls_security_level = may\n')
    assert master['service_parameters'] == {'submission/inet/smtpd_sender_restrictions': 'check_sender_access lmdb:/etc/postfix/sub_senders, reject'}
    assert master['postmap'] == ['/etc/postfix/sub_senders'] and not master['parameters']
    warned = preflight({**facts, 'net_drivers': {'enp0s3': 'e1000'}, 'postconf_n': postconf_n})
    assert warned['ready'] and len(warned['warnings']) == 2 and 'enp0s3 (e1000)' in warned['warnings'][0]
    assert files['efa-next.sigs'].strip() == KEY_ID and 'gpgcheck=1' in files['efa-next.repo']
    assert el9_leftovers(['bash-5.2-1.el10.x86_64', 'foo-1-1.el9.noarch', 'gpg-pubkey-1-2.el9']) == ['foo-1-1.el9.noarch']
    assert unit_problems({'postfix', 'rspamd', 'clamd@scan', 'mariadb', 'valkey', 'unbound', 'nginx', 'efa-web', 'efactl-runner',
                          'efa-maillog', 'efa-milter-health', 'chronyd', 'firewalld'}) == []
    assert unit_problems(set()) and 'valkey|redis' in unit_problems({'redis2'})
    assert strip_counters('tcp dport 25 counter packets 24 bytes 1440 reject') == 'tcp dport 25 reject'
    before = {'addresses': ['10.0.0.1/24'], 'routes': ['default via 10.0.0.254'], 'firewall': 'z', 'mail_block': 'm', 'counts': {'q': 1},
              'dkim': ['k'], 'os_id': 'almalinux'}
    # S22: only a package signed by the ELevate key counts.
    good = 'e.rpm: digests signatures OK\n'
    assert rpm_signature_problem(good, 'RSA/SHA256, Fri Oct 17 2025, Key ID 429785e181b961a5') is None
    # The test repository only with the root marker (0600) and on this host itself.
    class Stat:
        def __init__(self, uid=0, mode=0o100600):
            self.st_uid, self.st_mode = uid, mode
    def missing(path):
        raise FileNotFoundError(path)
    local = {'EFA_EL10_TEST_REPO': 'http://127.0.0.1:8099/el10/'}
    assert test_repo({}) == ('', '') and test_repo(local, lambda path: Stat()) == (local['EFA_EL10_TEST_REPO'], '')
    assert test_repo({'EFA_EL10_TEST_REPO': 'file:///root/el10-repo/'}, lambda path: Stat())[0] == 'file:///root/el10-repo/'
    assert 'missing' in test_repo(local, missing)[1] and 'root with mode 0600' in test_repo(local, lambda path: Stat(mode=0o100644))[1]
    assert 'root with mode 0600' in test_repo(local, lambda path: Stat(uid=1000))[1]
    for url in ('https://evil.example/el10/', 'http://127.0.0.1.evil.example/', 'http://10.0.0.1/el10/', 'ftp://127.0.0.1/'):
        assert test_repo({'EFA_EL10_TEST_REPO': url}, lambda path: Stat()) == ('', test_repo({'EFA_EL10_TEST_REPO': url}, lambda path: Stat())[1]), url
        assert 'ignored' in test_repo({'EFA_EL10_TEST_REPO': url}, lambda path: Stat())[1], url
    assert rpm_signature_problem('e.rpm: digests SIGNATURES NOT OK\n', 'Key ID 429785e181b961a5')
    assert rpm_signature_problem('e.rpm: digests OK\n', '(none)') and rpm_signature_problem(good, 'Key ID 21ea45ab2f86d6a1')
    assert rpm_signature_problem('', '') and len(ELEVATE_FINGERPRINT) == 40
    # S23: the distribution stays; only AlmaLinux goes ahead today.
    assert os_id('NAME="Rocky Linux"\nID="rocky"\nVERSION_ID="9.6"\n') == 'rocky' and os_id('ID=rhel\n') == 'rhel' and os_id('') == ''
    assert distribution_problem('almalinux') is None and 'nicht getestet' in distribution_problem('rhel', True)
    assert 'nicht unterstützt' in distribution_problem('rocky') and 'nicht unterstützt' in distribution_problem('centos')
    assert upgrade_packages('almalinux') == (ELEVATE_RELEASE, ELEVATE_PACKAGES) and 'leapp-data-almalinux' not in upgrade_packages('rhel')[1]
    for other in ('rhel', 'rocky', 'centos'):
        assert not preflight({**facts, 'os_release': f'ID="{other}"\nVERSION_ID="9.6"\n'})['ready'], other
    after = {**before, 'os_release': 'ID="almalinux"\nVERSION_ID="10.1"\n', 'kernel': '6.12.0-55.el10.x86_64', 'packages': [], 'dnf_check': '',
             'selinux': 'Enforcing', 'avc': 0, 'time_synced': True, 'active': ['postfix', 'rspamd', 'clamd@scan', 'mariadb', 'valkey', 'unbound',
                                                                               'nginx', 'efa-web', 'efactl-runner', 'efa-maillog',
                                                                               'efa-milter-health', 'chronyd', 'firewalld'],
             'mail': {'clean': 'accepted', 'gtube': 'rejected', 'eicar': 'rejected'}, 'db_check': '', 'backup': True, 'perl_extra': [],
             'service_states': {'postfix': ('forking', 'active'), 'efa-firstboot': ('oneshot', 'inactive')}}
    config = {'postconf_n': config_postconf('transport_maps = hash:/etc/postfix/transport\nmyhostname = mx.example\n'),
              'postconf_p': config_postconf('submission/inet/smtpd_tls_security_level = encrypt\n'),
              'files': {'/etc/rspamd/local.d/actions.conf': 'a' * 64}, 'units': ['efa-web.service']}
    config_after = {**config, 'postconf_n': config_postconf('default_database_type = lmdb\ntransport_maps = lmdb:/etc/postfix/transport\n'
                                                            'myhostname = mx.example\n')}
    assert config_diff(config, config_after) == []
    assert config_diff(config, {**config_after, 'files': {'/etc/rspamd/local.d/actions.conf': 'b' * 64}}) == ['changed: /etc/rspamd/local.d/actions.conf']
    assert config_diff(config, {**config_after, 'units': []}) == ['unit no longer enabled: efa-web.service']
    assert any('myhostname = other' in item for item in config_diff(config, {**config_after, 'postconf_n': config_postconf('myhostname = other\n')}))
    before['config'] = config
    after.update(config_diff=[], nginx_test='')
    # F5: an enabled service of eFa-next that does not run (dovecot on a host without IPv6) fails the finish.
    assert service_problems({'dovecot': ('notify', 'failed'), 'efa-x': ('oneshot', 'failed'), 'efa-y': ('oneshot', 'inactive')}) == ['dovecot', 'efa-x']
    assert not post_checks({**after, 'service_states': {'dovecot': ('notify', 'failed')}}, before)['ok']
    assert not post_checks({key: value for key, value in after.items() if key != 'service_states'}, before)['ok'], 'not checked is no pass'
    # F2: the test mail goes to a recipient this host takes, never to a foreign domain.
    assert mail_recipients(['Example.org'], ['a@example.org, b@other.example', None], ['c@example.org']) == [
        'a@example.org', 'c@example.org', 'postmaster@example.org', 'abuse@example.org']
    assert table_addresses('# x\nuser@example.org OK\n@example.org OK\nexample.org OK\n') == ['user@example.org']
    # F4: a leftover goes only when nothing needs it and the admin did not install it; what leapp brought counts as not chosen.
    plan = leftover_plan(['iprutils', 'unzoo', 'perl-Lexical-Var', 'perl-Sys-SigAction'], {'perl-Sys-SigAction': ['efa-x']},
                         {'iprutils', 'perl-Lexical-Var'}, {'perl-Lexical-Var'})
    assert plan == (['perl-Lexical-Var', 'unzoo'], {'iprutils': 'installed by the admin', 'perl-Sys-SigAction': 'needed by efa-x'}), plan
    kept_after = {**after, 'packages': ['iprutils-2.4.19-5.el9.x86_64'], 'leftovers_kept': {'iprutils': 'installed by the admin'}}
    found = post_checks(kept_after, before)
    assert found['ok'] and any(item['name'] == 'Leftover packages kept' and not item['ok'] and 'iprutils' in item['detail'] for item in found['checks'])
    assert not post_checks({**after, 'packages': ['unzoo-4.4-31.el9.x86_64']}, before)['ok'], 'a leftover not kept on purpose still fails'
    assert post_checks({**after, 'perl_extra': ['perl-Test2-Suite'], 'leftovers_kept': {'perl-Test2-Suite': 'needed by x'}}, before)['ok']
    # F3: package files of the OS that change with the release; the files of eFa-next stay the same.
    pkg = PACKAGE_FILE
    os_before = {'files': {'/etc/postfix/canonical': pkg, '/etc/unbound/conf.d/example.com.conf': pkg, '/etc/nginx/conf.d/php-fpm.conf': 'p' * 64,
                           '/etc/postfix/generic': 'g' * 64, '/etc/nginx/conf.d/efa.conf': 'e' * 64}}
    os_after = {'files': {'/etc/postfix/canonical': 'c' * 64, '/etc/unbound/conf.d/example.com.conf': 'x' * 64, '/etc/postfix/generic': 'h' * 64}}
    assert config_diff(os_before, os_after) == ['changed: /etc/postfix/generic', 'removed: /etc/nginx/conf.d/efa.conf'], config_diff(os_before, os_after)
    assert post_checks(after, before)['ok'], post_checks(after, before)['failed']
    assert not post_checks({**after, 'config_diff': ['changed: /etc/nginx/conf.d/efa.conf']}, before)['ok']
    assert not post_checks(after, {key: value for key, value in before.items() if key != 'config'})['ok']
    assert not post_checks({**after, 'mail_block': 'gone'}, before)['ok'] and not post_checks({**after, 'kernel': '5.14.0.el9'}, before)['ok']
    assert not post_checks({**after, 'mail': {'clean': 'accepted', 'gtube': 'accepted', 'eicar': 'rejected'}}, before)['ok']
    # Rehearsal 3: perl-locale with its reason, any other new Perl package stops.
    assert post_checks({**after, 'perl_extra': ['perl-locale']}, before)['ok']
    assert not post_checks({**after, 'perl_extra': ['perl-locale', 'perl-CGI']}, before)['ok']
    # The Wazuh agent: the same package, files and state after the upgrade, or the check fails (a clone's agent stays off).
    agent = {'version': '4.14.10-1', 'enabled': 'masked', 'active': 'inactive', 'ossec_conf': 'a' * 64, 'client_keys': 'b' * 64, 'runs': True}
    assert post_checks({**after, 'wazuh': agent}, {**before, 'wazuh': agent})['ok']
    # Its package has no el tag: it is no EL9 leftover.
    assert el9_leftovers(['wazuh-agent-4.14.10-1.x86_64', 'bash-5.2-1.el10.x86_64']) == []
    for key, value in (('active', 'active'), ('enabled', 'enabled'), ('ossec_conf', 'c' * 64), ('client_keys', ''), ('version', '4.14.11-1'),
                       ('runs', False)):
        assert not post_checks({**after, 'wazuh': {**agent, key: value}}, {**before, 'wazuh': agent})['ok'], key
    assert not post_checks({**after, 'wazuh': {}}, {**before, 'wazuh': agent})['ok'], 'removed by the upgrade'
    shown = preflight({**facts, 'wazuh': agent, 'installed_from': ['acme-tool @acme-repo']})
    assert shown['ready'] and any('masked, inactive' in text for text in shown['warnings'] + [c['detail'] for c in shown['checks']])
    assert any('acme-tool (@acme-repo)' in text for text in shown['warnings'])
    # Package files the package changed, dropped or added do not count; what an admin changed does.
    pkg = PACKAGE_FILE
    old = {'files': {'/etc/postfix/access': pkg, '/etc/unbound/conf.d/unbound-local-root.conf': pkg, '/etc/rspamd/local.d/a.conf': 'a' * 64,
                     '/etc/postfix/header_checks': 'h' * 64}, 'units': ['efa-web.service']}
    new = {'files': {'/etc/postfix/access': pkg, '/etc/postfix/dynamicmaps.cf.d/lmdb': pkg, '/etc/rspamd/local.d/a.conf': 'a' * 64,
                     '/etc/postfix/header_checks': pkg}, 'units': ['efa-web.service', 'efa-release-upgrade-finish.service']}
    assert config_diff(old, new) == ['changed: /etc/postfix/header_checks'], config_diff(old, new)
    assert config_diff({**old, 'files': {'/etc/x': pkg}}, {**new, 'files': {'/etc/x': 'b' * 64}}) == ['changed: /etc/x']
    assert config_diff({**old, 'files': {'/etc/x': 'a' * 64}}, {**new, 'files': {}}) == ['removed: /etc/x']
    assert config_diff({**old, 'files': {}}, {**new, 'files': {'/etc/x': 'a' * 64}}) == ['added: /etc/x']
    # A setting of main.cf an admin made, lost in the upgrade: the check fails.
    lost = {**config, 'postconf_n': config_postconf('transport_maps = hash:/etc/postfix/transport\nmyhostname = mx.example\n'
                                                     'message_size_limit = 52428800\n')}
    assert any('message_size_limit = 52428800' in item for item in config_diff(lost, config_after))
    assert not post_checks({**after, 'config_diff': config_diff(lost, config_after)}, {**before, 'config': lost})['ok']
    conf = '[main]\ngpgcheck=1\nexclude=clamd-[2-9]*,python3-leapp,leapp-upgrade-el9toel10,snactor,leapp,python3-pymilter-[2-9]*\n'
    stripped, taken = dnf_exclude_without_leapp(conf)
    assert stripped == '[main]\ngpgcheck=1\nexclude=clamd-[2-9]*,python3-pymilter-[2-9]*\n' and taken == ['python3-leapp', 'leapp-upgrade-el9toel10', 'snactor', 'leapp']
    assert dnf_exclude_without_leapp(stripped) == (stripped, [])
    packages = ['kernel-5.14.0-687.66.1.el9_8.x86_64', 'kernel-core-5.14.0-687.66.1.el9_8.x86_64', 'kernel-modules-core-5.14.0-687.66.1.el9_8.x86_64',
                'kernel-6.12.0-211.74.1.el10_2.x86_64', 'kernel-core-6.12.0-211.74.1.el10_2.x86_64', 'kernel-tools-libs-6.12.0-1.el10.x86_64', 'bash-5.2-1.el10.x86_64']
    assert old_kernels(packages, '6.12.0-211.74.1.el10_2.x86_64') == ['kernel-5.14.0-687.66.1.el9_8.x86_64', 'kernel-core-5.14.0-687.66.1.el9_8.x86_64',
                                                                       'kernel-modules-core-5.14.0-687.66.1.el9_8.x86_64']
    assert old_kernels(packages, '5.14.0-687.66.1.el9_8.x86_64') == [] and old_kernels(packages[:3], '6.12.0-211.74.1.el10_2.x86_64') == []
    return True


if __name__ == '__main__':
    import sys
    if '--self-test' in sys.argv:
        print('self-test ok' if self_test() else 'self-test failed')
