# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A4: one safe reader for ZIP files that come from outside (DMARC/TLS reports in efa-reports, disclaimer imports in efactl).

It unpacks flat, never to disk, and refuses what a report or a template never needs: too many members, too much unpacked data,
a ZIP bomb (compression ratio), path traversal, absolute paths, backslashes, drive letters, symlinks and encrypted members.
A member that is itself an archive is handed back as bytes; the caller decides whether to open it, with a depth limit."""
import io
import stat
import zipfile


class UnsafeZip(ValueError):
    """A ZIP that breaks a limit or carries an unsafe member. A subclass of ValueError, so existing handlers still catch it."""


def safe_unzip(data, max_files=50, max_total=5 * 1024 * 1024, max_ratio=100):
    """The members of a ZIP as {name: bytes}, or raises UnsafeZip. Directories are skipped. No recursion: a member that is
    another archive comes back as bytes."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        entries = archive.infolist()
    except (zipfile.BadZipFile, ValueError, EOFError, OSError) as err:
        raise UnsafeZip(f'no valid ZIP: {err}') from None
    members = [item for item in entries if not item.is_dir()]
    if len(members) > max_files:
        raise UnsafeZip(f'more than {max_files} files in the ZIP')
    if sum(item.file_size for item in members) > max_total:
        raise UnsafeZip(f'unpacks to more than {max_total // 1024 // 1024} MB')
    found = {}
    for item in members:
        name = item.filename
        if name.startswith(('/', '\\')) or '..' in name.split('/') or '\\' in name or ':' in name:
            raise UnsafeZip(f'{name}: an absolute path or ..')
        if stat.S_ISLNK(item.external_attr >> 16):
            raise UnsafeZip(f'{name}: a link')
        if item.flag_bits & 0x1:
            raise UnsafeZip(f'{name}: encrypted')
        if item.compress_size and item.file_size / item.compress_size > max_ratio and item.file_size > 1024 * 1024:
            raise UnsafeZip(f'{name}: packed too tightly (a ZIP bomb?)')
        with archive.open(item) as f:
            content = f.read(max_total + 1)
        if len(content) != item.file_size:
            raise UnsafeZip(f'{name}: the stored size does not match')
        found[name] = content
    return found


def self_test():
    def zipped(items, **kw):
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, body in items.items():
                archive.writestr(name, body)
            link = kw.get('link')
            if link:
                info = zipfile.ZipInfo(link)
                info.external_attr = 0o120777 << 16
                archive.writestr(info, 'target')
        return out.getvalue()

    assert safe_unzip(zipped({'a.txt': 'hello', 'b/c.xml': '<x/>'})) == {'a.txt': b'hello', 'b/c.xml': b'<x/>'}
    # A backslash or drive letter cannot be produced with zipfile (it writes '/' names), but the check still guards real input.
    for bad in (b'PK not a zip',
                zipped({'../x': 'a'}), zipped({'/abs': 'a'}), zipped({'c:x': 'a'}),
                zipped({'a.txt': 'x'}, link='l'),
                zipped({f'f{i}': 'x' for i in range(51)}),
                zipped({'big': b'0' * (6 * 1024 * 1024)})):
        try:
            safe_unzip(bad, max_total=5 * 1024 * 1024)
            raise AssertionError('a bad ZIP was accepted')
        except UnsafeZip:
            pass
    # A tight but small file is allowed; the bomb check only bites above 1 MB unpacked.
    assert safe_unzip(zipped({'small': b'0' * 1000})) == {'small': b'0' * 1000}
    # A ZIP bomb: many zeros, far over the ratio, above 1 MB.
    try:
        safe_unzip(zipped({'bomb': b'0' * (4 * 1024 * 1024)}), max_total=50 * 1024 * 1024)
        raise AssertionError('a ZIP bomb was accepted')
    except UnsafeZip:
        pass
    print('self-test ok')


if __name__ == '__main__':
    import sys
    if '--self-test' in sys.argv:
        self_test()
