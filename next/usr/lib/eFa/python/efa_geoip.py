# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""G7-6: a reader for the MaxMind DB format (MMDB), standard library only, for the local GeoIP files (DB-IP Lite Country and
ASN, CC BY 4.0). Every lookup happens on this server: no address is ever sent anywhere.

The file is mapped read-only; the search tree is walked bit by bit and the record decoded from the data section. Only what the
format needs: maps, arrays, strings, integers, floats and pointers; a bad file raises ValueError, never reads outside the file.
build() writes a small file of the same format, for the self tests."""
import ipaddress
import mmap
import struct

MARKER = b'\xab\xcd\xefMaxMind.com'
META_SEARCH = 128 * 1024
DEPTH_MAX = 32


class Reader:
    def __init__(self, path):
        with open(path, 'rb') as f:
            try:
                self.buf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            except ValueError:
                raise ValueError('empty file')
        size = len(self.buf)
        where = self.buf.rfind(MARKER, max(0, size - META_SEARCH))
        if where < 0:
            self.close()
            raise ValueError('no MMDB metadata')
        start = where + len(MARKER)
        try:
            self.meta, _end = self._decode(start, start, 0)
            if not isinstance(self.meta, dict):
                raise ValueError('metadata is no map')
            self.node_count, self.record_size = int(self.meta['node_count']), int(self.meta['record_size'])
            self.ip_version = int(self.meta['ip_version'])
        except (KeyError, TypeError, struct.error, IndexError) as err:
            self.close()
            raise ValueError(f'bad metadata: {err}')
        if self.record_size not in (24, 28, 32) or self.ip_version not in (4, 6) or self.node_count <= 0:
            self.close()
            raise ValueError('unknown tree layout')
        self.tree_size = self.node_count * self.record_size // 4
        if self.tree_size + 16 > where or self.buf[self.tree_size:self.tree_size + 16] != b'\0' * 16:
            self.close()
            raise ValueError('the search tree does not fit the file')
        self.data_start = self.tree_size + 16
        self.data_end = where
        self.v4_start = 0
        if self.ip_version == 6:
            node = 0
            for _ in range(96):
                if node >= self.node_count:
                    break
                node = self._record(node, 0)
            self.v4_start = node
        self.cache = {}

    def close(self):
        try:
            self.buf.close()
        except (AttributeError, ValueError):
            pass

    def _record(self, node, bit):
        size, buf = self.record_size, self.buf
        off = node * size // 4
        if size == 24:
            off += 3 * bit
            return int.from_bytes(buf[off:off + 3], 'big')
        if size == 28:
            middle = buf[off + 3]
            if bit:
                return ((middle & 0x0f) << 24) | int.from_bytes(buf[off + 4:off + 7], 'big')
            return ((middle >> 4) << 24) | int.from_bytes(buf[off:off + 3], 'big')
        off += 4 * bit
        return int.from_bytes(buf[off:off + 4], 'big')

    def _decode(self, offset, base, depth):
        """(value, next offset) at offset; pointers count from base (the data section, or the metadata for the metadata)."""
        if depth > DEPTH_MAX:
            raise ValueError('nested too deep')
        buf = self.buf
        if offset >= len(buf):
            raise ValueError('reads past the end')
        ctrl = buf[offset]
        offset += 1
        kind = ctrl >> 5
        if kind == 1:
            sizes = (ctrl >> 3) & 3
            low = ctrl & 7
            raw = buf[offset:offset + sizes + 1]
            offset += sizes + 1
            if sizes == 0:
                pointer = (low << 8) | raw[0]
            elif sizes == 1:
                pointer = ((low << 16) | int.from_bytes(raw, 'big')) + 2048
            elif sizes == 2:
                pointer = ((low << 24) | int.from_bytes(raw, 'big')) + 526336
            else:
                pointer = int.from_bytes(raw, 'big')
            value, _next = self._decode(base + pointer, base, depth + 1)
            return value, offset
        if kind == 0:
            kind = 7 + buf[offset]
            offset += 1
        size = ctrl & 0x1f
        if size >= 29:
            extra = size - 28
            raw = int.from_bytes(buf[offset:offset + extra], 'big')
            offset += extra
            size = (29, 285, 65821)[extra - 1] + raw
        if kind == 2:
            return buf[offset:offset + size].decode('utf-8', 'replace'), offset + size
        if kind == 3:
            return struct.unpack('>d', buf[offset:offset + 8])[0], offset + 8
        if kind == 4:
            return bytes(buf[offset:offset + size]), offset + size
        if kind in (5, 6, 9, 10):
            return int.from_bytes(buf[offset:offset + size], 'big'), offset + size
        if kind == 8:
            value = int.from_bytes(buf[offset:offset + size], 'big')
            return (value - (1 << 32) if size == 4 and value >= 1 << 31 else value), offset + size
        if kind == 7:
            found = {}
            for _ in range(size):
                key, offset = self._decode(offset, base, depth + 1)
                found[str(key)], offset = self._decode(offset, base, depth + 1)
            return found, offset
        if kind == 11:
            items = []
            for _ in range(size):
                item, offset = self._decode(offset, base, depth + 1)
                items.append(item)
            return items, offset
        if kind == 14:
            return bool(size), offset
        if kind == 15:
            return struct.unpack('>f', buf[offset:offset + 4])[0], offset + 4
        raise ValueError(f'unknown data type {kind}')

    def lookup(self, ip):
        """The record of an address, or None (not in the file, or not a public address)."""
        try:
            address = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return None
        if getattr(address, 'ipv4_mapped', None):
            address = address.ipv4_mapped
        if not address.is_global:
            return None
        if address.version == 6 and self.ip_version == 4:
            return None
        key = address.packed
        if key in self.cache:
            return self.cache[key]
        node, bits = (self.v4_start, 32) if address.version == 4 else (0, 128)
        for index in range(bits):
            if node >= self.node_count:
                break
            node = self._record(node, (key[index >> 3] >> (7 - (index & 7))) & 1)
        found = None
        if node > self.node_count:
            offset = self.data_start + node - self.node_count - 16
            if offset >= self.data_end:
                raise ValueError('a record points past the data')
            try:
                found, _next = self._decode(offset, self.data_start, 0)
            except (struct.error, IndexError, UnicodeError) as err:
                raise ValueError(f'a bad record: {err}')
        if len(self.cache) > 4096:
            self.cache.clear()
        self.cache[key] = found
        return found


def country_of(record):
    """(ISO code, English name) of a country record of DB-IP or MaxMind, or ('', '')."""
    country = (record or {}).get('country') or (record or {}).get('registered_country') or {}
    code = str(country.get('iso_code') or '')[:2].upper()
    names = country.get('names') or {}
    return (code, str(names.get('en') or code)) if len(code) == 2 and code.isalpha() else ('', '')


def asn_of(record):
    """(number, organisation) of an ASN record, or (None, '')."""
    number = (record or {}).get('autonomous_system_number')
    return (number, str((record or {}).get('autonomous_system_organization') or '')[:120]) if isinstance(number, int) else (None, '')


def flag(code):
    """The flag of a two-letter country code as regional indicator symbols; empty for anything else."""
    code = (code or '').upper()
    return ''.join(chr(0x1F1E6 + ord(char) - 65) for char in code) if len(code) == 2 and code.isascii() and code.isalpha() else ''


# ---------------------------------------------------------------- a small writer, for the self tests only
def _head(kind, size):
    if size < 29:
        first, extra = size, b''
    elif size < 285:
        first, extra = 29, bytes([size - 29])
    elif size < 65821:
        first, extra = 30, (size - 285).to_bytes(2, 'big')
    else:
        first, extra = 31, (size - 65821).to_bytes(3, 'big')
    return bytes([(kind << 5) | first]) + extra if kind < 8 else bytes([first, kind - 7]) + extra


def _pointer(where):
    if where < 2048:
        return bytes([0x20 | (where >> 8), where & 0xff])
    if where < 526336:
        where -= 2048
        return bytes([0x28 | (where >> 16)]) + (where & 0xffff).to_bytes(2, 'big')
    if where < 134744064:
        where -= 526336
        return bytes([0x30 | (where >> 24)]) + (where & 0xffffff).to_bytes(3, 'big')
    return bytes([0x38]) + where.to_bytes(4, 'big')


def _encode(value, out, seen):
    """Appends value to out; a string written before becomes a pointer to it (as the real files do), when seen is a dict."""
    if isinstance(value, bool):
        out += _head(14, int(value))
    elif isinstance(value, str):
        if seen is not None and value in seen:
            out += _pointer(seen[value])
            return
        if seen is not None:
            seen[value] = len(out)
        raw = value.encode()
        out += _head(2, len(raw)) + raw
    elif isinstance(value, float):
        out += _head(3, 8) + struct.pack('>d', value)
    elif isinstance(value, int):
        raw = value.to_bytes((value.bit_length() + 7) // 8, 'big')
        out += _head(6 if value < 1 << 32 else 9, len(raw)) + raw
    elif isinstance(value, dict):
        out += _head(7, len(value))
        for key, item in value.items():
            _encode(str(key), out, seen)
            _encode(item, out, seen)
    elif isinstance(value, list):
        out += _head(11, len(value))
        for item in value:
            _encode(item, out, seen)
    else:
        raise TypeError(type(value))


def build(networks, database_type, epoch=0):
    """An MMDB file (bytes, IPv6 tree, 24-bit records) for [(network, record)]; IPv4 networks under ::/96. No overlaps."""
    nodes = [[None, None]]
    data, offsets, seen = bytearray(), [], {}
    for _network, record in networks:
        offsets.append(len(data))
        _encode(record, data, seen)
    for number, (network, _record) in enumerate(networks):
        net = ipaddress.ip_network(network)
        value, length = int(net.network_address), (96 if net.version == 4 else 0) + net.prefixlen
        node = 0
        for index in range(length):
            # An IPv4 network as ::a.b.c.d: its 32 bits are the low bits of the 128.
            bit = (value >> (127 - index)) & 1
            if index == length - 1:
                nodes[node][bit] = ('data', number)
            else:
                if nodes[node][bit] is None:
                    nodes.append([None, None])
                    nodes[node][bit] = len(nodes) - 1
                node = nodes[node][bit]
    count = len(nodes)

    def record(item):
        if item is None:
            return count
        if isinstance(item, tuple):
            return count + 16 + offsets[item[1]]
        return item
    tree = b''.join(record(left).to_bytes(3, 'big') + record(right).to_bytes(3, 'big') for left, right in nodes)
    meta = bytearray()
    _encode({'binary_format_major_version': 2, 'binary_format_minor_version': 0, 'build_epoch': epoch, 'database_type': database_type,
             'description': {'en': 'eFa-next self test'}, 'ip_version': 6, 'languages': ['en'], 'node_count': count, 'record_size': 24}, meta, None)
    return tree + b'\0' * 16 + bytes(data) + MARKER + bytes(meta)
