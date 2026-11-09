# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Shared helpers for the eFa-next configuration programs.

Paths in this module are absolute target paths such as /etc/eFa/eFa-Config.
They are mapped below env.root: "/" on a real host, a temporary folder in
the self-tests. Below a test root no command is ever executed; the tests
install a fake runner instead.

Nothing in here is specific to one operating system. Everything that is
lives in the platform layer (efa_platform and its implementations).
"""

import grp
import ipaddress
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time

SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
YES_NO = ("YES", "NO")


class StepError(Exception):
    """A configuration step failed. The message never holds a secret."""


class InputError(StepError):
    """A value given to a program is not valid."""


class Env:
    """Process-wide settings: target root, verbosity, command runner."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.root = "/"
        self.verbose = False
        self.runner = None          # tests: callable(argv, input_text)
        self.platform = None        # set lazily by platform()
        self.program = os.path.basename(sys.argv[0]) or "efa"
        self.log_file = "eFa-config.log"

    @property
    def live(self):
        return self.root == "/"


env = Env()


def platform():
    """Return the platform layer object for this host (cached)."""
    if env.platform is None:
        import efa_platform
        env.platform = efa_platform.detect()
    return env.platform


def P(name):
    """Shortcut: the platform path for a logical name, e.g. P('efa_config')."""
    return platform().path(name)


def rp(path):
    """Map an absolute target path below env.root."""
    if env.live:
        return path
    return os.path.join(env.root, path.lstrip("/"))


# ---------------------------------------------------------------- logging

def log(message, level="INFO"):
    """Append a line to the program log; print it when verbose or not INFO.

    Callers never pass secrets to this function.
    """
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = "%s %s %s: %s\n" % (stamp, env.program, level, message)
    try:
        try:
            log_dir = rp(P("log_dir"))
        except StepError:  # unknown platform: still keep a log
            log_dir = rp("/var/log/eFa")
        os.makedirs(log_dir, mode=0o750, exist_ok=True)
        fd = os.open(os.path.join(log_dir, env.log_file),
                     os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass
    if env.verbose or level != "INFO":
        sys.stderr.write("%s: %s\n" % (level, message))


def info(message):
    log(message, "INFO")


def warn(message):
    log(message, "WARNING")


def error(message):
    log(message, "ERROR")


# ---------------------------------------------------------------- commands

def _short(text, limit=400):
    text = (text or "").strip().replace("\n", " | ")
    return text[-limit:]


def run(cmd, input_text=None, check=True, secret=False):
    """Run a command without a shell and return a CompletedProcess.

    Secrets are only ever passed through input_text (stdin), never in cmd.
    With secret=True, the output of a failed command is not repeated in the
    error message, because some programs echo their input.
    """
    cmd = [str(part) for part in cmd]
    if env.verbose:
        log("run: " + " ".join(cmd))
    if env.runner is not None:
        result = env.runner(cmd, input_text)
    elif env.live:
        try:
            result = subprocess.run(
                cmd, input=input_text, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, universal_newlines=True, check=False,
                env={"PATH": SAFE_PATH, "LC_ALL": "C", "HOME": "/root"})
        except FileNotFoundError:
            raise StepError("program not found: %s" % cmd[0])
    else:
        raise StepError("commands are disabled below a test root")
    if check and result.returncode != 0:
        detail = "" if secret else _short(result.stderr or result.stdout)
        msg = "'%s' failed with exit code %d" % (" ".join(cmd), result.returncode)
        raise StepError(msg + (": " + detail if detail else ""))
    return result


def have(program):
    """True if a program is on the safe PATH (always True below a test root)."""
    if not env.live:
        return True
    return shutil.which(program, path=SAFE_PATH) is not None


def which(program):
    """Full path of a program, or the bare name below a test root."""
    if not env.live:
        return program
    found = shutil.which(program, path=SAFE_PATH)
    if not found:
        raise StepError("program not found: %s" % program)
    return found


# ---------------------------------------------------------------- files

def _ids(owner, group):
    if not env.live:
        return None, None
    try:
        uid = pwd.getpwnam(owner).pw_uid if owner else -1
        gid = grp.getgrnam(group).gr_gid if group else -1
    except KeyError:
        raise StepError("user or group missing: %s:%s" % (owner, group))
    return uid, gid


def set_owner_mode(path, mode, owner="root", group=None):
    """Set mode and owner of an existing file or folder."""
    target = rp(path)
    os.chmod(target, mode)
    uid, gid = _ids(owner, group or platform().root_group)
    if uid is not None:
        os.chown(target, uid, gid)


def ensure_dir(path, mode=0o755, owner="root", group=None):
    os.makedirs(rp(path), exist_ok=True)
    set_owner_mode(path, mode, owner, group)


def read_text(path, default=None):
    try:
        with open(rp(path), encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        if default is None:
            raise StepError("file missing: %s" % path)
        return default


def write_file(path, content, mode=0o644, owner="root", group=None,
               validate=None):
    """Write a file atomically. Return True if its content changed.

    The temporary file is created with mode 0600 and gets its final mode
    and owner before it is renamed, so secrets are never readable by others.
    validate(tmp_path) may raise StepError to keep the old file.
    """
    target = rp(path)
    data = content.encode("utf-8") if isinstance(content, str) else content
    try:
        with open(target, "rb") as fh:
            unchanged = fh.read() == data and not os.path.islink(target)
    except FileNotFoundError:
        unchanged = False
    if unchanged:
        set_owner_mode(path, mode, owner, group)
        return False
    folder = os.path.dirname(target)
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".efa-")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        uid, gid = _ids(owner, group or platform().root_group)
        if uid is not None:
            os.chown(tmp, uid, gid)
        if validate is not None:
            validate(tmp)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    platform().restore_context(path)
    return True


def ensure_file(path, content="", mode=0o644, owner="root", group=None):
    """Create a file with content if it does not exist. True if created."""
    if os.path.exists(rp(path)):
        set_owner_mode(path, mode, owner, group)
        return False
    return write_file(path, content, mode, owner, group)


def remove(path):
    """Remove a file or folder tree if it exists. True if removed."""
    target = rp(path)
    if os.path.isdir(target) and not os.path.islink(target):
        shutil.rmtree(target)
        return True
    try:
        os.unlink(target)
        return True
    except FileNotFoundError:
        return False


def touch(path, mode=0o644):
    return ensure_file(path, "", mode)


# ---------------------------------------------------------------- KEY:value

KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def read_kv(path):
    """Read a KEY:value file into a dict (missing file: empty dict)."""
    data = {}
    for line in read_text(path, "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data


def write_kv(path, data, mode, group=None):
    lines = []
    for key, value in data.items():
        value = str(value)
        if not KEY_RE.match(key) or any(ch in value for ch in "\r\n\0"):
            raise StepError("invalid settings entry for key %r" % key)
        lines.append("%s:%s\n" % (key, value))
    return write_file(path, "".join(lines), mode=mode, group=group)


# ---------------------------------------------------------------- text edits

def set_directives(text, settings, disable=()):
    """Set 'Key value' directives (clamd style) in a configuration text.

    The first active line of a key is replaced, later active duplicates are
    dropped, missing keys are appended. Keys in disable are commented out.
    """
    out, seen = [], set()
    for line in text.splitlines():
        stripped = line.strip()
        word = None
        if stripped and not stripped.startswith("#"):
            word = stripped.split(None, 1)[0]
        if word in settings:
            if word not in seen:
                out.append("%s %s" % (word, settings[word]))
                seen.add(word)
            continue
        if word in disable:
            out.append("#" + line)
            continue
        out.append(line)
    for key, value in settings.items():
        if key not in seen:
            out.append("%s %s" % (key, value))
    return "\n".join(out) + "\n"


def set_ini(text, section, values):
    """Set 'key = value' entries of one [section] in an INI text."""
    out, done = [], set()
    current, found = None, False

    def flush():
        for key, value in values.items():
            if key not in done:
                out.append("%s = %s" % (key, value))
                done.add(key)

    for line in text.splitlines():
        stripped = line.strip()
        match = re.match(r"^\[([^\]]+)\]$", stripped)
        if match:
            if current == section:
                flush()
            current = match.group(1).strip()
            found = found or current == section
            out.append(line)
            continue
        if (current == section and "=" in stripped
                and not stripped.startswith(("#", ";"))):
            key = stripped.split("=", 1)[0].strip()
            if key in values:
                if key not in done:
                    out.append("%s = %s" % (key, values[key]))
                    done.add(key)
                continue
        out.append(line)
    if current == section:
        flush()
    if not found:
        out.extend(["", "[%s]" % section])
        flush()
    return "\n".join(out) + "\n"


def replace_block(text, block_lines, name="eFa"):
    """Replace (or append) a marked block of lines in a text."""
    begin = "# BEGIN %s managed block" % name
    end = "# END %s managed block" % name
    out, inside = [], False
    for line in text.splitlines():
        if line.strip() == begin:
            inside = True
            continue
        if line.strip() == end:
            inside = False
            continue
        if not inside:
            out.append(line)
    while out and not out[-1].strip():
        out.pop()
    out.extend([begin] + list(block_lines) + [end])
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- checks

LABEL_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def valid_label(value):
    return bool(LABEL_RE.match(value or ""))


def valid_domain(value):
    parts = (value or "").split(".")
    return len(value or "") <= 253 and len(parts) >= 2 and all(
        valid_label(p) for p in parts)


def valid_fqdn(value):
    return valid_domain(value)


def ip_version(value):
    """4 or 6 for a valid IP address, else 0."""
    try:
        return ipaddress.ip_address(value).version
    except ValueError:
        return 0


def valid_email(value):
    if not value or CONTROL_RE.search(value) or value.count("@") != 1:
        return False
    local, domain = value.split("@")
    return bool(re.match(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$", local)) \
        and valid_domain(domain)


def netmask_prefix(value, version=4):
    """Return a prefix length from '24', '/24' or '255.255.255.0'."""
    value = (value or "").strip().lstrip("/")
    limit = 32 if version == 4 else 128
    if value.isdigit() and 0 <= int(value) <= limit:
        return int(value)
    if version == 4:
        try:
            return ipaddress.IPv4Network("0.0.0.0/" + value).prefixlen
        except ValueError:
            pass
    raise InputError("invalid netmask or prefix: %r" % value)


def current_fqdn():
    """The host name from the settings, else /etc/hostname, else a default."""
    cfg = read_kv(P("efa_config"))
    name = "%s.%s" % (cfg.get("HOSTNAME", ""), cfg.get("DOMAINNAME", ""))
    if valid_fqdn(name):
        return name
    name = read_text(P("hostname_file"), "").strip()
    return name if valid_fqdn(name) else "efa.localdomain"


# ---------------------------------------------------------------- steps

def run_steps(steps, names, stop_on_error=False):
    """Run named steps in order. Return the list of names that failed."""
    failed = []
    for name in names:
        info("step %s: start" % name)
        try:
            steps[name]()
        except Exception as exc:  # report every step, keep going
            error("step %s failed: %s" % (name, exc))
            failed.append(name)
            if stop_on_error:
                break
        else:
            info("step %s: ok" % name)
    return failed


def ensure_certificate(fqdn, force=False, ips=()):
    """Make the self-signed eFa-next certificate for fqdn (and the static ips) unless it already fits.

    With the IP addresses in the SAN the browser warns once at the new address, and the warning names it.

    Returns True if a new certificate was made.
    """
    crt, key = P("cert_file"), P("key_file")
    if not force and os.path.exists(rp(crt)) and os.path.exists(rp(key)):
        res = run(["openssl", "x509", "-noout", "-subject", "-nameopt",
                   "RFC2253", "-in", rp(crt)], check=False)
        san = run(["openssl", "x509", "-noout", "-ext", "subjectAltName", "-in", rp(crt)], check=False) if ips else None
        # openssl writes IPv6 addresses in full: compare the addresses, not the text.
        found = {ipaddress.ip_address(ip) for ip in re.findall(r"IP Address:([0-9A-Fa-f:.]+)", san.stdout)} if ips and san.returncode == 0 else None
        san_ok = not ips or (found is not None and all(ipaddress.ip_address(ip) in found for ip in ips))
        if res.returncode == 0 and res.stdout.strip() == "subject=CN=" + fqdn and san_ok:
            return False
    for path in (crt, key):
        os.makedirs(os.path.dirname(rp(path)), exist_ok=True)
    fd_k, tmp_key = tempfile.mkstemp(dir=os.path.dirname(rp(key)), prefix=".efa-")
    fd_c, tmp_crt = tempfile.mkstemp(dir=os.path.dirname(rp(crt)), prefix=".efa-")
    os.close(fd_k)
    os.close(fd_c)
    try:
        run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256",
             "-days", "3650", "-nodes", "-subj", "/CN=" + fqdn,
             "-addext", "subjectAltName=" + ",".join(["DNS:" + fqdn] + ["IP:" + ip for ip in ips]),
             "-keyout", tmp_key, "-out", tmp_crt])
        os.chmod(tmp_key, 0o600)
        os.chmod(tmp_crt, 0o644)
        os.replace(tmp_key, rp(key))
        os.replace(tmp_crt, rp(crt))
    finally:
        for tmp in (tmp_key, tmp_crt):
            if os.path.exists(tmp):
                os.unlink(tmp)
    platform().restore_context(key)
    platform().restore_context(crt)
    info("made a self-signed certificate for %s" % fqdn)
    return True
