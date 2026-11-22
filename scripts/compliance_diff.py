#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The changes between the compliance files of two releases, as Markdown for the changelog and the release notes.

    compliance_diff.py OLD.compliance.json NEW.compliance.json
    compliance_diff.py - NEW.compliance.json        the first release with a compliance file
"""
import json
import sys

FIELDS = ('status', 'owner', 'scope', 'limits')


def controls(data):
    return {(standard['id'], control['id']): {**control, 'standard_title': standard['title']}
            for standard in data['standards'] for control in standard['controls']}


def diff(old, new):
    """(new, changed, removed): new and removed are (standard, control id, title); changed adds [(field, before, after)]."""
    before, after = controls(old) if old else {}, controls(new)
    added = [(key[0], key[1], after[key]['title']) for key in after if key not in before]
    removed = [(key[0], key[1], before[key]['title']) for key in before if key not in after]
    changed = []
    for key in after:
        if key in before:
            fields = [(field, before[key][field], after[key][field]) for field in FIELDS if before[key][field] != after[key][field]]
            if before[key]['evidence'] != after[key]['evidence']:
                fields.append(('evidence', len(before[key]['evidence']), len(after[key]['evidence'])))
            if fields:
                changed.append((key[0], key[1], after[key]['title'], fields))
    return added, changed, removed


def markdown(old, new):
    title = f"### Compliance file {new['version']}"
    if not old:
        return f"{title}\n\nFirst release with a compliance file: {sum(len(s['controls']) for s in new['standards'])} controls in " \
               f"{len(new['standards'])} standards (eFa-next-{new['version']}.compliance.json).\n"
    added, changed, removed = diff(old, new)
    lines = [title, '', f"Compared with {old['version']}."]
    if not (added or changed or removed):
        return '\n'.join(lines + ['', 'No control changed.']) + '\n'
    if added:
        lines += ['', 'New:'] + [f'- {std} {cid}: {text}' for std, cid, text in added]
    if changed:
        lines += ['', 'Changed:']
        for std, cid, text, fields in changed:
            lines.append(f'- {std} {cid}: {text}: ' + '; '.join(
                f'{field} {before} -> {after}' if field in ('status', 'owner', 'evidence') else f'{field} reworded' for field, before, after in fields))
    if removed:
        lines += ['', 'Removed:'] + [f'- {std} {cid}: {text}' for std, cid, text in removed]
    return '\n'.join(lines) + '\n'


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    old = None
    if argv[1] != '-':
        with open(argv[1], encoding='utf-8') as f:
            old = json.load(f)
    with open(argv[2], encoding='utf-8') as f:
        new = json.load(f)
    sys.stdout.write(markdown(old, new))
    return 0


def self_test():
    one = {'version': '1.0.0.1', 'standards': [{'id': 'x', 'title': 'X', 'controls': [
        {'id': 'a', 'title': 'A', 'status': 'partial', 'owner': 'shared', 'scope': 's', 'limits': '', 'evidence': []},
        {'id': 'b', 'title': 'B', 'status': 'covered', 'owner': 'efa-next', 'scope': 's', 'limits': '', 'evidence': []}]}]}
    two = json.loads(json.dumps(one))
    two['version'] = '1.0.0.2'
    two['standards'][0]['controls'][0].update(status='covered', evidence=[{'type': 'test', 'ref': 't'}])
    two['standards'][0]['controls'][1] = {'id': 'c', 'title': 'C', 'status': 'covered', 'owner': 'os', 'scope': 's', 'limits': '', 'evidence': []}
    text = markdown(one, two)
    assert '- x c: C' in text and '- x b: B' in text and 'status partial -> covered; evidence 0 -> 1' in text, text
    assert 'First release with a compliance file: 2 controls in 1 standards' in markdown(None, one)
    assert 'No control changed.' in markdown(one, one)
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
        sys.exit(0)
    sys.exit(main(sys.argv))
