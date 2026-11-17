# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The progress of an update, for the Update card (Hans 2026-11-15: one card, a progress bar, the step and the time left).

efactl writes one small file while an update runs (update-system and the install of an eFa-next release share it); the web
interface reads it through efactl update-progress. Here only the pure parts: the steps, the package counter of dnf, the
percentage and the time left. No system call."""

import re

# The steps in their order, with their label (translated in the web interface) and the time a step takes when no run on this
# host measured it yet (seconds).
STEPS = {
    'download': ('Download', 60),
    'backup': ('Backup', 120),
    'check': ('Check packages', 120),
    'efa': ('eFa-next', 120),
    'os': ('Operating system', 300),
    'health': ('Health check', 60),
    'reboot': ('Reboot', 240),
}
# The steps of each kind of update; reboot only when it was chosen, efa only when a newer release is known.
KINDS = {'system': ('backup', 'check', 'efa', 'os', 'health', 'reboot'), 'efa': ('download', 'backup', 'efa', 'health')}
ACTIVE = ('waiting', 'running', 'rebooting')
# A line of the dnf transaction: "  Upgrading        : openssl-libs-1:3.2.2-6.el9_5.1.x86_64        27/46". Verifying
# counts the same packages again at the end.
DNF_LINE = re.compile(r'^\s*(Upgrading|Upgraded|Installing|Reinstalling|Downgrading|Obsoleting|Erasing|Removing|Cleanup|Verifying)\s*:\s*(\S+)\s+(\d+)/(\d+)\s*$')


def all_texts():
    """The step labels, for scripts/i18n_extract.py (the web interface translates them by value)."""
    return [label for label, _seconds in STEPS.values()]


def steps_of(kind, efa_update=True, reboot=False):
    """The steps of one run."""
    return [step for step in KINDS[kind] if (step != 'efa' or efa_update or kind == 'efa') and (step != 'reboot' or reboot)]


def dnf_line(line):
    """(done, total, package, verifying) of a transaction line of dnf, else None."""
    found = DNF_LINE.match(line)
    if not found:
        return None
    done, total = int(found.group(3)), int(found.group(4))
    if not total or done > total:
        return None
    return done, total, found.group(2), found.group(1) == 'Verifying'


def dnf_fraction(done, total, verifying):
    """The share of the operating system step: the transaction is 90 %, the check of the packages after it the rest."""
    share = done / total if total else 0
    return round(0.9 + 0.1 * share, 3) if verifying else round(0.9 * share, 3)


def expected(step, durations):
    """Seconds a step takes: as on the last good run of this host, else the default."""
    took = (durations or {}).get(step)
    return max(int(took), 5) if isinstance(took, (int, float)) and took > 0 else STEPS[step][1]


def view(progress, durations, now):
    """What the Update card shows of a progress record: the state, the percentage, the step, the steps with their state and
    the seconds left (None when unknown). progress is the record efactl writes, durations the seconds of each step of the
    last good run, now the time (epoch seconds)."""
    progress = progress or {}
    steps = [step for step in progress.get('steps') or [] if step in STEPS]
    state = progress.get('state') or 'idle'
    current = progress.get('step') if progress.get('step') in steps else None
    index = steps.index(current) if current else (len(steps) if state in ('done', 'failed') else -1)
    finished = state in ('done', 'failed')
    fraction = 0.0
    left = None
    if current and state in ('running', 'rebooting'):
        started = progress.get('step_started')
        elapsed = max(0, now - (now if started is None else started))
        wanted = expected(current, durations)
        packages = progress.get('packages')
        if current == 'os' and packages and packages[1]:
            fraction = dnf_fraction(packages[0], packages[1], bool(progress.get('verifying')))
            # The rate of this run, once a part is done; before that the time of the last run.
            left_now = elapsed / fraction * (1 - fraction) if fraction >= 0.05 and elapsed else max(wanted - elapsed, 0)
        else:
            fraction = min(elapsed / wanted, 0.95)
            left_now = max(wanted - elapsed, 0)
        left = int(left_now + sum(expected(step, durations) for step in steps[index + 1:]))
    elif state == 'waiting':
        # Until the start; the card says when that is.
        left = int(max((progress.get('at') or now) - now, 0))
    weights = [expected(step, durations) for step in steps]
    total = sum(weights) or 1
    if finished:
        percent = 100 if state == 'done' else int(round(100 * sum(weights[:max(index, 0)]) / total))
    elif index >= 0:
        percent = int(round(100 * (sum(weights[:index]) + weights[index] * fraction) / total))
    else:
        percent = 0
    # A failed run: its last step is the one that failed.
    failed_step = progress.get('step') if state == 'failed' else None
    marks = []
    for number, step in enumerate(steps):
        if state == 'done' or (number < index and step != failed_step):
            mark = 'done'
        elif step == failed_step:
            mark = 'failed'
        elif number == index and not finished:
            mark = 'now'
        else:
            mark = 'todo'
        marks.append({'step': step, 'label': STEPS[step][0], 'state': mark})
    return {'state': state, 'kind': progress.get('kind'), 'percent': max(0, min(percent, 100)), 'step': current,
            'label': STEPS[current][0] if current else None, 'number': index + 1 if current else None, 'count': len(steps),
            'steps': marks, 'seconds_left': left, 'packages': progress.get('packages'), 'line': progress.get('line'),
            'from': progress.get('from'), 'to': progress.get('to'), 'started': progress.get('started_text'),
            'finished': progress.get('finished_text'), 'at': progress.get('at_text'), 'result': progress.get('result'),
            'backup': progress.get('backup'), 'dry_run': bool(progress.get('dry_run')), 'reboot': bool(progress.get('reboot')),
            'held': progress.get('held') or [],
            'took': int(progress['finished'] - progress['started']) if finished and progress.get('finished') is not None and progress.get('started') is not None else None}


def durations_after(progress):
    """The seconds of each step of a good run, kept for the time left of the next one. A dry run installs nothing: it measures
    no install step."""
    took = dict(progress.get('took') or {})
    if progress.get('dry_run'):
        took = {step: seconds for step, seconds in took.items() if step in ('backup', 'check', 'health')}
    return {step: int(seconds) for step, seconds in took.items() if step in STEPS and isinstance(seconds, (int, float)) and seconds >= 0}


def self_test():
    assert steps_of('system', efa_update=False) == ['backup', 'check', 'os', 'health']
    assert steps_of('system', efa_update=True, reboot=True) == ['backup', 'check', 'efa', 'os', 'health', 'reboot']
    assert steps_of('efa') == ['download', 'backup', 'efa', 'health']
    assert dnf_line('  Upgrading        : openssl-libs-1:3.2.2-6.el9_5.1.x86_64          27/46') == (27, 46, 'openssl-libs-1:3.2.2-6.el9_5.1.x86_64', False)
    assert dnf_line('  Verifying        : kernel-5.14.0-503.el9.x86_64   3/46')[3] is True
    assert dnf_line('Upgraded: openssl-libs') is None and dnf_line('  Running scriptlet: x 1/2 extra') is None and dnf_line('  Upgrading : x 9/4') is None
    assert dnf_fraction(23, 46, False) == 0.45 and dnf_fraction(46, 46, True) == 1.0
    # A run in the operating system step, half of the packages done after 100 s: the rate gives the rest of this step.
    record = {'state': 'running', 'kind': 'system', 'steps': ['backup', 'check', 'os', 'health'], 'step': 'os', 'step_started': 1000,
              'packages': [23, 46], 'line': 'Upgrading openssl', 'from': '6.0.0.6.3', 'to': '6.0.0.6.4'}
    shown = view(record, {'backup': 100, 'check': 100, 'os': 200, 'health': 100}, 1100)
    assert shown['number'] == 3 and shown['count'] == 4 and shown['label'] == 'Operating system'
    assert [mark['state'] for mark in shown['steps']] == ['done', 'done', 'now', 'todo']
    assert shown['percent'] == round(100 * (200 + 200 * 0.45) / 500), shown
    assert shown['seconds_left'] == int(100 / 0.45 * 0.55 + 100), shown
    # Without a measured run: the defaults; the time left never goes below what the steps after it take.
    shown = view({**record, 'step': 'check', 'packages': None, 'step_started': 0}, None, 10 ** 6)
    assert shown['seconds_left'] == STEPS['os'][1] + STEPS['health'][1] and shown['percent'] < 100
    waiting = view({'state': 'waiting', 'steps': ['backup', 'os'], 'at': 1300}, {}, 1000)
    assert waiting['seconds_left'] == 300 and waiting['percent'] == 0 and waiting['number'] is None
    done = view({**record, 'state': 'done', 'step': None, 'started': 1000, 'finished': 1720}, {}, 2000)
    assert done['percent'] == 100 and done['took'] == 720 and all(mark['state'] == 'done' for mark in done['steps'])
    failed = view({**record, 'state': 'failed', 'step': 'os'}, {}, 2000)
    assert [mark['state'] for mark in failed['steps']] == ['done', 'done', 'failed', 'todo'] and failed['percent'] < 100
    assert view(None, None, 0)['state'] == 'idle'
    assert durations_after({'took': {'backup': 90.4, 'os': 300, 'x': 3}}) == {'backup': 90, 'os': 300}
    assert durations_after({'dry_run': True, 'took': {'backup': 90, 'os': 3}}) == {'backup': 90}
    print('self-test ok')


if __name__ == '__main__':
    self_test()
