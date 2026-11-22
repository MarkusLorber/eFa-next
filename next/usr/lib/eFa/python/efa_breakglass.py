# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The break-glass admin of a host (Hans 2026-11-18): a local user with a random name, ten one-time codes and no password,
TOTP or key. SSH only from the admin networks with a code (keyboard-interactive), the local console with a code, sudo with
a fresh code; every try raises an alarm. Never replicated in a cluster: its state is under /var/lib, not /etc.

The codes exist in clear only in the one request that makes them (and in its PDF); here only their scrypt hashes. A code
works once: it is removed under a lock when it is used."""
import base64
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import string
import time

STATE_DIR = '/var/lib/efa-breakglass'
CODES = 10
SCRYPT = {'n': 2 ** 15, 'r': 8, 'p': 1, 'maxmem': 64 * 1024 * 1024, 'dklen': 32}
# The same values in the PAM files and in the self check.
FAILLOCK = {'deny': 5, 'unlock_time': 900, 'fail_interval': 900}
SSHD_FILE = '/etc/ssh/sshd_config.d/45-efa-breakglass.conf'
CHECKER = '/usr/libexec/eFa/breakglass-code'
SHELL = '/usr/sbin/efa-breakglass-shell'
SUDOERS = '/etc/sudoers.d/efa-breakglass'
GUARD_MARK = '# efa-breakglass: the break-glass admin with a one-time code; every other user goes on below unchanged'
NAME_RE = re.compile(r'efa-bg-[a-z0-9]{8}')


def state_file(folder=STATE_DIR):
    return os.path.join(folder, 'state.json')


def new_name():
    return 'efa-bg-' + ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))


def new_code():
    """128 bits in base32 without padding, in groups of four for reading aloud."""
    text = base64.b32encode(secrets.token_bytes(16)).decode().rstrip('=')
    return '-'.join(text[i:i + 4] for i in range(0, len(text), 4))


def normal(code):
    return re.sub(r'[^A-Z2-7]', '', str(code).upper())


def hashed(code, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(normal(code).encode(), salt=salt, **SCRYPT)
    return {'salt': salt.hex(), 'hash': digest.hex()}


def read_state(folder=STATE_DIR):
    try:
        with open(state_file(folder)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def write_state(state, folder=STATE_DIR):
    """Written whole (a temp file renamed), root only: the folder 0700, the file 0600."""
    os.makedirs(folder, mode=0o700, exist_ok=True)
    os.chmod(folder, 0o700)
    path = state_file(folder)
    fd = os.open(path + '.new', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(state, f, sort_keys=True)
    os.chmod(path + '.new', 0o600)
    os.replace(path + '.new', path)


def issue(state, user, now=None):
    """New codes for user: the clear codes (for the PDF of this request only) and the state with their hashes; the codes of
    before count no more."""
    codes = [new_code() for _ in range(CODES)]
    new = {**state, 'user': user, 'codes': [hashed(code) for code in codes], 'issued': int(time.time() if now is None else now)}
    new.setdefault('created', new['issued'])
    return codes, new


def use_code(code, folder=STATE_DIR, now=None):
    """True when code is one of the codes left: it is removed at once, under a lock, so it never works twice."""
    if not normal(code):
        return False
    os.makedirs(folder, mode=0o700, exist_ok=True)
    with open(os.path.join(folder, 'state.lock'), 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = read_state(folder)
        for index, item in enumerate(state.get('codes', [])):
            digest = hashlib.scrypt(normal(code).encode(), salt=bytes.fromhex(item['salt']), **SCRYPT)
            if hmac.compare_digest(digest.hex(), item['hash']):
                del state['codes'][index]
                state['last_use'] = int(time.time() if now is None else now)
                write_state(state, folder)
                return True
    return False


def in_networks(address, networks):
    try:
        ip = ipaddress.ip_address(str(address).strip().strip('[]'))
    except ValueError:
        return False
    for net in networks:
        try:
            if ip in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False


def sshd_text(user, networks):
    """The Match blocks: with a code from the admin networks only; from anywhere else this user cannot log in at all (public
    key only, with no key file). Without admin networks only the second block. Nothing global changes."""
    if not NAME_RE.fullmatch(user):
        raise ValueError('not a break-glass user name')
    nets = [str(ipaddress.ip_network(net, strict=False)) for net in networks]
    lines = ['# eFa-next break-glass admin (efactl breakglass-issue): one-time codes, from the admin networks only.']
    if nets:
        lines += [f'Match User {user} Address {",".join(nets)}', '    AuthenticationMethods keyboard-interactive',
                  '    KbdInteractiveAuthentication yes', '    PasswordAuthentication no', '    PubkeyAuthentication no', '    MaxAuthTries 3',
                  '    AllowTcpForwarding no', '    AllowAgentForwarding no', '    AllowStreamLocalForwarding no', '    X11Forwarding no',
                  '    PermitTunnel no']
    lines += [f'Match User {user}', '    AuthenticationMethods publickey', '    PubkeyAuthentication yes', '    AuthorizedKeysFile none',
              '    KbdInteractiveAuthentication no', '    PasswordAuthentication no', 'Match all', '']
    return '\n'.join(lines)


def faillock_args(tty=False):
    extra = ' dir=/var/run/faillock-efa-bg-tty' if tty else ''
    return f"deny={FAILLOCK['deny']} unlock_time={FAILLOCK['unlock_time']} fail_interval={FAILLOCK['fail_interval']} even_deny_root{extra}"


def guard_lines(user, tty=False):
    """The auth lines of the break-glass user on top of a service: every other user jumps over all of them in one step
    (success=N, N counted here); this user: faillock, the code (on stdin only, expose_authtok, no log=), faillock again, and a
    right code ends the auth part (success=done). A "substack" cannot jump, so the lines stand in the file itself. The local
    console has a faillock counter of its own: a lock-out over SSH never closes the console."""
    if not NAME_RE.fullmatch(user):
        raise ValueError('not a break-glass user name')
    args = faillock_args(tty)
    own = [f'auth       requisite                    pam_faillock.so preauth {args}',
           f'auth       [success=1 default=ignore]   pam_exec.so quiet expose_authtok {CHECKER}',
           f'auth       [default=die]                pam_faillock.so authfail {args}',
           f'auth       [success=done default=die]   pam_faillock.so authsucc {args}']
    return [GUARD_MARK, f'auth       [success={len(own)} default=ignore] pam_succeed_if.so quiet user != {user}'] + own


GUARD_LEN = 6  # the mark, the jump and the four lines of the user


def with_guard(text, user, tty=False):
    """The PAM file of a service with the lines of the break-glass user on top of its auth part; old ones go first."""
    lines = without_guard(text).split('\n')
    at = next((i for i, line in enumerate(lines) if re.match(r'\s*-?auth\s', line)), len(lines))
    return '\n'.join(lines[:at] + guard_lines(user, tty) + lines[at:])


def without_guard(text):
    lines, out, skip = text.split('\n'), [], 0
    for line in lines:
        if skip:
            skip -= 1
            continue
        if line == GUARD_MARK:
            skip = GUARD_LEN - 1
            continue
        out.append(line)
    return '\n'.join(out)


def sudoers_text(user):
    if not NAME_RE.fullmatch(user):
        raise ValueError('not a break-glass user name')
    return (f'# eFa-next break-glass admin: sudo with a fresh one-time code each time (PAM), never without.\n'
            f'Defaults:{user} timestamp_timeout=0\n{user} ALL=(ALL) ALL\n')
