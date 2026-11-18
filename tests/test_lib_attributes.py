# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski

"""6.0.0.6.6.1: every name the programs take from a library of eFa-next exists in that library.

6.0.0.6.6 shipped efa-cluster.py calling efa_cluster.release_of(), a function of a branch not in the release: every status
request of the master crashed on the node. The unit tests used fake libraries, so nothing ran the real call. This test reads
the sources (no import, no mocks): efa_x.<name> after "import efa_x", _lib('efa_x').<name>, a name bound to _lib('efa_x')
in a function, the first value of _cluster_parts() and "from efa_x import <name>"."""

import ast
import glob
import os
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
LIB_DIRS = [os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'python'), os.path.join(ROOT, 'src', 'eFa-base', 'root', 'usr', 'lib', 'eFa', 'python')]


def programs():
    """Every Python program and library of the tree (the libraries use each other too)."""
    found = []
    for pattern in ('next/usr/sbin/*', 'next/usr/local/sbin/*', 'next/usr/libexec/eFa/*', 'next/usr/lib/eFa/python/*.py',
                    'src/*/root/usr/sbin/*', 'src/*/root/usr/lib/eFa/python/*.py', 'migration/*'):
        for path in sorted(glob.glob(os.path.join(ROOT, *pattern.split('/')))):
            if os.path.isfile(path):
                with open(path, 'rb') as f:
                    head = f.read(200)
                if path.endswith('.py') or head.startswith(b'#!') and b'python' in head.splitlines()[0]:
                    found.append(os.path.relpath(path, ROOT).replace(os.sep, '/'))
    return found


def lib_path(name):
    for folder in LIB_DIRS:
        path = os.path.join(folder, name + '.py')
        if os.path.exists(path):
            return path
    return None


def defined_names(path):
    """The names a module defines at its top level (def, class, assignment, import), read from its source."""
    tree = ast.parse(open(path, encoding='utf-8').read())
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                for item in ast.walk(target):
                    if isinstance(item, ast.Name):
                        names.add(item.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            names |= {alias.asname or alias.name.split('.')[0] for alias in node.names}
        elif isinstance(node, (ast.If, ast.Try)):  # definitions under a top-level if or try
            for inner in ast.walk(node):
                if isinstance(inner, (ast.FunctionDef, ast.ClassDef)):
                    names.add(inner.name)
                elif isinstance(inner, ast.Assign):
                    names |= {item.id for target in inner.targets for item in ast.walk(target) if isinstance(item, ast.Name)}
    return names


def lib_call(node):
    """'efa_x' for the expression _lib('efa_x'), else None."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == '_lib' and node.args \
            and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value
    return None


def used_names(path):
    """[(module, name, line)] of the library names a program uses."""
    tree = ast.parse(open(path, encoding='utf-8').read())
    found = []
    modules = {}  # names bound to a library module for the whole file: import efa_x [as y]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith('efa'):
                    modules[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and (node.module or '').startswith('efa'):
            found += [(node.module, alias.name, node.lineno) for alias in node.names]
    scopes = [tree] + [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for scope in scopes:
        local, other = {}, set()
        for node in ast.walk(scope):
            if isinstance(node, ast.Assign):
                module = lib_call(node.value)
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        (local.__setitem__(target.id, module) if module else other.add(target.id))
                    elif isinstance(target, ast.Tuple) and isinstance(node.value, ast.Call) and getattr(node.value.func, 'id', '') == '_cluster_parts' \
                            and isinstance(target.elts[0], ast.Name):
                        local[target.elts[0].id] = 'efa_cluster'
                    else:
                        other |= {item.id for item in ast.walk(target) if isinstance(item, ast.Name)}
            elif isinstance(node, (ast.arg,)):
                other.add(node.arg)
        # A name also bound to something else in this scope (a fake of a self-test) is not checked here.
        names = {name: module for name, module in local.items() if name not in other}
        if scope is not tree:
            names = {**{name: module for name, module in modules.items() if name not in other and name not in local}, **names}
        else:
            names = {**modules, **names}
        for node in ast.walk(scope):
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                module = lib_call(node.value) or (names.get(node.value.id) if isinstance(node.value, ast.Name) else None)
                if module:
                    found.append((module, node.attr, node.lineno))
    return sorted(set(found))


class LibraryNames(unittest.TestCase):
    def test_every_used_name_exists(self):
        missing, checked = [], 0
        cache = {}
        for program in programs():
            for module, name, line in used_names(os.path.join(ROOT, *program.split('/'))):
                path = lib_path(module)
                if path is None:
                    continue  # a module of the standard library or of a package, not of eFa-next
                if module not in cache:
                    cache[module] = defined_names(path)
                checked += 1
                if name not in cache[module]:
                    missing.append(f'{program}:{line}: {module}.{name}')
        self.assertGreater(checked, 300, 'the reader found the uses')
        self.assertEqual(missing, [], 'names a program uses that its library does not have')

    def test_it_finds_the_bug_of_6_0_0_6_6(self):
        source = 'import efa_cluster\n\ndef node_status():\n    return efa_cluster.release_of()\n'
        path = os.path.join(ROOT, 'build', 'tmp-lib-attributes.py')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(source)
        try:
            used = used_names(path)
        finally:
            os.remove(path)
        self.assertIn(('efa_cluster', 'release_of', 4), used)
        self.assertNotIn('release_of', defined_names(lib_path('efa_cluster')) - {'release_of'})


if __name__ == '__main__':
    unittest.main()
