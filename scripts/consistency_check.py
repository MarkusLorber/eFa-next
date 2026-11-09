#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The registries of efactl agree: COMMANDS, COMMAND_PERMISSIONS, the forms of efa_nav and ARG_CHOICES. Pure logic, no root,
also on Windows (the Unix-only modules are stubbed), so a lost or misnamed entry shows before the push. Run from the repository
root: python3 scripts/consistency_check.py"""
import argparse, contextlib, importlib.machinery, importlib.util, io, os, subprocess, sys, tempfile, types

# No bytecode next to the sources: efactl has no .py ending, its cache would be a stray file.
sys.dont_write_bytecode = True
# The status commands below read an empty configuration, never the one of this host.
os.environ['EFA_ETC'] = tempfile.mkdtemp()
for name in ('grp', 'pwd', 'fcntl', 'syslog', 'termios', 'resource'):
    sys.modules.setdefault(name, types.ModuleType(name))
sys.modules['fcntl'].flock = lambda *a: None
sys.modules['fcntl'].LOCK_EX, sys.modules['fcntl'].LOCK_NB, sys.modules['fcntl'].LOCK_SH, sys.modules['fcntl'].LOCK_UN = 2, 4, 1, 8
sys.modules['syslog'].syslog = lambda *a: None
sys.path.insert(0, 'next/usr/lib/eFa/python')
loader = importlib.machinery.SourceFileLoader('efactl', 'next/usr/sbin/efactl')
spec = importlib.util.spec_from_loader('efactl', loader)
efactl = importlib.util.module_from_spec(spec)
loader.exec_module(efactl)
import efa_nav as nav

COMMANDS, problems = efactl.COMMANDS, []
perms = efactl.COMMAND_PERMISSIONS
problems += [f'permission without a command: {name}' for name in sorted(set(perms) - set(COMMANDS))]
problems += [f'unknown permission: {name} {perm}' for name, perm in perms.items() if perm is not None and perm not in efactl.PERMISSIONS]
for name, cmd in COMMANDS.items():
    fields = [arg['name'] for arg in cmd['args'] if not arg.get('secret') and arg.get('kind') != 'confirm' and arg['name'] != 'confirm']
    if not cmd['writes'] or not fields or name in nav.FORM_NEW or name in nav.FORM_KEYED:
        continue
    if name not in nav.FORM_SOURCE:
        problems.append(f'{name}: no FORM_SOURCE')
        continue
    status, keys = nav.FORM_SOURCE[name]
    if status not in COMMANDS or COMMANDS[status]['writes'] or [arg for arg in COMMANDS[status]['args'] if arg.get('required')]:
        problems.append(f'{name}: bad status command {status}')
    if set(fields) != set(keys):
        problems.append(f'{name}: fields and FORM_SOURCE keys differ: {sorted(set(fields) ^ set(keys))}')
problems += [f'FORM_NEW/FORM_KEYED and FORM_SOURCE: {name}' for name in sorted((nav.FORM_NEW | nav.FORM_KEYED) & set(nav.FORM_SOURCE))]
problems += [f'FORM_NEW/FORM_KEYED, no command: {name}' for name in sorted((nav.FORM_NEW | nav.FORM_KEYED) - set(COMMANDS))]
problems += [f'FORM_SOURCE, no command: {name}' for name in sorted(set(nav.FORM_SOURCE) - set(COMMANDS))]
for (name, arg), _choices in getattr(efactl, 'ARG_CHOICES', {}).items():
    if name not in COMMANDS or arg not in [item['name'] for item in COMMANDS[name]['args']]:
        problems.append(f'ARG_CHOICES without a command argument: {name} {arg}')
shown = set()
for value in vars(nav).values():
    if isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], list):
                shown |= {entry for entry in item[1] if isinstance(entry, str)}
problems += [f'card names an unknown command: {name}' for name in sorted(shown - set(COMMANDS))]
# 5q: the role matrix of the self-test, with its sets read from efactl (one place to change them).
source = open('next/usr/sbin/efactl', encoding='utf-8').read()
start = source.index('        system_only = {')
matrix = {}
exec('\n'.join(line[8:] for line in source[start:source.index('        for role in ROLES:', start)].split('\n')), {}, matrix)
built = {key: efactl._group_row({'id': number, 'name': spec['name'], 'builtin': key, 'description': '', 'permissions': '', 'scope': 'member',
                                 'scope_tenants': '', 'scope_domains': '', 'disabled': 0}) for number, (key, spec) in enumerate(efactl.BUILTIN_GROUPS.items(), 1)}
for role in efactl.ROLES:
    who = {'grants': efactl.grants_of([{'group': built[role], 'tenant_id': None, 'domain': None}], {1: ['a.example'], 2: ['b.example']})}
    allowed = {name for name, cmd in COMMANDS.items() if efactl.command_allowed(who, name, cmd['writes'])}
    counted = {name for name in allowed if efactl.COMMAND_PERMISSIONS.get(name, 'x') is not None}
    if role != 'super' and allowed & matrix['system_only']:
        problems.append(f'role {role} may run system commands: {sorted(allowed & matrix["system_only"])}')
    if role in ('readonly', 'auditor', 'user'):
        writes = {name for name in counted if COMMANDS[name]['writes']} - matrix['gated_inside']
        if not writes <= matrix['own_mailbox']:
            problems.append(f'role {role} may write outside the own mailbox: {sorted(writes - matrix["own_mailbox"])}')
    if role == 'user' and not counted <= matrix['own_mailbox']:
        problems.append(f'role user: more than the own mailbox: {sorted(counted - matrix["own_mailbox"])}')
# The value a form shows comes from its status command and must be one of its choices, not the text shown for it (an empty value
# is "nothing chosen yet"). Each status runs without programs (every call answers nothing); one that needs the host is skipped.
efactl.subprocess.run = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, '', '')
outputs, skipped = {}, 0
for name, (status, keys) in sorted(nav.FORM_SOURCE.items()):
    if status not in outputs:
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                outputs[status] = COMMANDS[status]['func'](argparse.Namespace())
        except Exception:  # noqa: BLE001 - needs the database or another part of a real host
            outputs[status], skipped = None, skipped + 1
    if outputs[status] is None:
        continue
    for arg in COMMANDS[name]['args']:
        key = keys.get(arg['name'])
        value = nav.form_value(outputs[status], key) if key else None
        options = [item['value'] for item in arg.get('choices', [])]
        if options and value not in (None, '') and value not in options:
            problems.append(f'{name} --{arg["name"]}: {status} gives {value!r}, none of {options}')
print('\n'.join(problems) or f'consistency: ok, {len(COMMANDS)} commands, form values of {len(outputs) - skipped} status commands '
                            f'({skipped} need a host)')
sys.exit(1 if problems else 0)
