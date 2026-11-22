# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Hooks of the system update (6.0.0.6.7): programs of the admin that run before and after update-system (and so each step
of the staged rollout of a cluster), and an optional wrapper that runs the dnf transaction in its place.

    /etc/eFa/update-hooks.d/pre.d/*   before the backup; a hook that fails (exit code not 0, or its timeout) stops the update
    /etc/eFa/update-hooks.d/post.d/*  after the packages (before a reboot); a failure is reported, the update stays
    /etc/eFa/update-hooks.d/wrapper   runs the dnf transaction: it gets the whole dnf command line as its arguments

Nothing runs that a user other than root could have changed: the folder and every folder above it belong to root and are
not writable by group or others; a hook is a regular file (never a symlink: opened with O_NOFOLLOW, then checked on the open
file), owned by root:root, executable, not writable by group or others. It runs from that open file (/proc/self/fd), so it
cannot be swapped between the check and the start. A hook that fails the check is left out (the caller raises the alarm);
a wrapper that fails it refuses the whole update, it never falls back to plain dnf."""
import os
import stat
import subprocess

PHASES = ('pre', 'post')
TIMEOUT = 600


def _folder_problem(path):
    """Why this folder or one above it is not safe, or None."""
    path = os.path.abspath(path)
    parts = path.split(os.sep)
    for depth in range(1, len(parts) + 1):
        here = os.sep + os.path.join(*parts[1:depth]) if depth > 1 else os.sep
        try:
            info = os.lstat(here)
        except OSError as err:
            return f'{here}: {err.strerror}'
        if not stat.S_ISDIR(info.st_mode):
            return f'{here}: not a folder (a symlink?)'
        if info.st_uid != 0:
            return f'{here}: not owned by root'
        if info.st_mode & 0o022:
            return f'{here}: writable by group or others'
    return None


def open_checked(path):
    """(fd, None) for a program that is safe to run, else (None, why). The fd is open, the caller closes it."""
    problem = _folder_problem(os.path.dirname(os.path.abspath(path)))
    if problem:
        return None, problem
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as err:
        return None, f'{path}: {"a symlink" if err.errno == 40 else err.strerror}'
    info = os.fstat(fd)
    problem = (None if stat.S_ISREG(info.st_mode) else 'not a regular file') or \
              (None if (info.st_uid, info.st_gid) == (0, 0) else 'not owned by root:root') or \
              (None if not info.st_mode & 0o022 else 'writable by group or others') or \
              (None if info.st_mode & 0o100 else 'not executable')
    if problem:
        os.close(fd)
        return None, f'{path}: {problem}'
    return fd, None


def hooks(folder, phase):
    """[(name, fd or None, problem or None)] of a phase, in the order of their names; [] without the folder."""
    where = os.path.join(folder, f'{phase}.d')
    if not os.path.lexists(where):
        return []
    problem = _folder_problem(where)
    try:
        names = sorted(os.listdir(where))
    except OSError as err:
        return [(where, None, f'{where}: {err.strerror}')]
    if problem:
        return [(name, None, problem) for name in names] or [(where, None, problem)]
    found = []
    for name in names:
        if name.startswith('.') or name.endswith(('~', '.rpmnew', '.rpmsave', '.disabled')):
            continue
        fd, problem = open_checked(os.path.join(where, name))
        found.append((name, fd, problem))
    return found


def run_fd(fd, argv=(), timeout=TIMEOUT, env=None, run=subprocess.run):
    """The program behind an open fd: (exit code, last output). A timeout counts as a failure (124)."""
    try:
        done = run([f'/proc/self/fd/{fd}', *argv], pass_fds=(fd,), capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return 124, f'no end after {timeout} s'
    except OSError as err:
        return 126, str(err)
    return done.returncode, ((done.stderr or '') + (done.stdout or ''))[-300:]


def run_phase(folder, phase, env=None, timeout=TIMEOUT, run=subprocess.run):
    """Every hook of a phase: {'ok': no hook failed, 'ran': [names], 'failed': [(name, why)], 'refused': [(name, why)]}.
    A refused hook (it failed the check) is not run and not a failure of the update; the caller raises the alarm."""
    result = {'ok': True, 'ran': [], 'failed': [], 'refused': []}
    for name, fd, problem in hooks(folder, phase):
        if fd is None:
            result['refused'].append((name, problem))
            continue
        try:
            code, out = run_fd(fd, (phase,), timeout, env, run)
        finally:
            os.close(fd)
        result['ran'].append(name)
        if code != 0:
            result['ok'] = False
            result['failed'].append((name, f'exit {code}: {out.strip()[-200:]}'))
    return result


def wrapper(folder):
    """None without a wrapper, else (fd, None) or (None, why): a wrapper that fails the check refuses the update."""
    path = os.path.join(folder, 'wrapper')
    if not os.path.lexists(path):
        return None
    return open_checked(path)
