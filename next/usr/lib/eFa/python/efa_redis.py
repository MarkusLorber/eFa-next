# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The local Redis (Valkey on EL10) in its own protocol (RESP2), for the send limits of efa-outbound and the cluster service:
several commands in one round trip, the answers as int, str, None or lists. Standard library only."""
import socket

MAX_LINE = 1 << 20
MAX_ITEMS = 100000


def call(commands, host='127.0.0.1', port=6379, timeout=2):
    """The answers of the commands, in order. OSError when Redis does not answer or answers with an error."""
    out = b''
    for command in commands:
        parts = [str(item).encode() for item in command]
        out += b'*%d\r\n' % len(parts) + b''.join(b'$%d\r\n%s\r\n' % (len(part), part) for part in parts)
    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.sendall(out)
        reader = conn.makefile('rb')
        return [read(reader) for _command in commands]


def read(reader, depth=0):
    line = reader.readline(MAX_LINE)
    if not line.endswith(b'\r\n'):
        raise OSError('redis: no answer')
    kind, value = line[:1], line[1:-2]
    try:
        if kind == b':':
            return int(value)
        if kind == b'+':
            return value.decode()
        if kind == b'$':
            size = int(value)
            if size < 0:
                return None
            if size > MAX_LINE:
                raise OSError('redis: answer too large')
            data = reader.read(size + 2)
            if len(data) != size + 2 or not data.endswith(b'\r\n'):
                raise OSError('redis: answer cut off')
            return data[:-2].decode('utf-8', 'replace')
        if kind == b'*' and depth < 2:
            size = int(value)
            if size < 0:
                return None
            if size > MAX_ITEMS:
                raise OSError('redis: answer too large')
            return [read(reader, depth + 1) for _ in range(size)]
    except ValueError:
        pass
    raise OSError(f'redis: {line[:40]!r}')


class Memory:
    """Redis in memory, for the self-tests and the unit tests: the commands the send limits and the cluster use, with Redis's
    answers (no expiry: the keys carry the hour)."""

    def __init__(self):
        self.data = {}

    def __call__(self, commands):
        return [self.one(command[0].upper(), str(command[1]), [str(item) for item in command[2:]]) for command in commands]

    def one(self, name, key, rest):
        data = self.data
        if name == 'INCRBY':
            data[key] = int(data.get(key, 0)) + int(rest[0])
            return data[key]
        if name == 'HINCRBY':
            table = data.setdefault(key, {})
            table[rest[0]] = int(table.get(rest[0], 0)) + int(rest[1])
            return table[rest[0]]
        if name == 'HGETALL':
            return [item for pair in sorted(data.get(key, {}).items()) for item in (pair[0], str(pair[1]))]
        if name == 'SADD':
            before = len(data.setdefault(key, set()))
            data[key] |= set(rest)
            return len(data[key]) - before
        if name == 'SMEMBERS':
            return sorted(data.get(key, set()))
        if name == 'SCARD':
            return len(data.get(key, set()))
        if name == 'SUNIONSTORE':
            union = set().union(*(data.get(item, set()) for item in rest))
            data.pop(key, None)
            if union:
                data[key] = union
            return len(union)
        if name == 'GET':
            return None if data.get(key) is None else str(data[key])
        if name == 'SET':
            if 'NX' in [item.upper() for item in rest[1:]] and key in data:
                return None
            data[key] = rest[0]
            return 'OK'
        if name == 'DEL':
            return sum(1 for item in [key] + rest if data.pop(item, None) is not None)
        if name == 'EXPIRE':
            return int(key in data)
        raise OSError(f'redis: unknown command {name}')


def self_test():
    import io
    answers = b':3\r\n+OK\r\n$-1\r\n$5\r\nhello\r\n*2\r\n$1\r\na\r\n$2\r\nbc\r\n*0\r\n'
    reader = io.BytesIO(answers)
    assert [read(reader) for _ in range(6)] == [3, 'OK', None, 'hello', ['a', 'bc'], []]
    for bad in (b'-ERR wrong\r\n', b'$5\r\nhel', b':x\r\n', b'*1\r\n*1\r\n*1\r\n:1\r\n', b''):
        try:
            read(io.BytesIO(bad))
            raise AssertionError(bad)
        except OSError:
            pass
    # The protocol itself, against a small server: what is sent and what comes back.
    import threading
    server = socket.socket()
    server.bind(('127.0.0.1', 0))
    server.listen(1)
    seen = []

    def answer():
        conn, _addr = server.accept()
        with conn:
            seen.append(conn.recv(4096))
            conn.sendall(b':3\r\n+OK\r\n$-1\r\n')
    threading.Thread(target=answer, daemon=True).start()
    assert call([('INCRBY', 'k', 3), ('SET', 'k2', 1), ('GET', 'k3')], port=server.getsockname()[1]) == [3, 'OK', None]
    assert seen[0].startswith(b'*3\r\n$6\r\nINCRBY\r\n$1\r\nk\r\n$1\r\n3\r\n*3\r\n$3\r\nSET\r\n'), seen
    server.close()
    memory = Memory()
    assert memory([('INCRBY', 'a', 2), ('HINCRBY', 'h', 'f', 3), ('SADD', 's', 'x', 'y'), ('SUNIONSTORE', 'u', 's', 'none'), ('GET', 'a'),
                   ('SET', 'n', 1, 'NX', 'EX', 9), ('SET', 'n', 1, 'NX'), ('HGETALL', 'h'), ('DEL', 's', 'u')]) == \
        [2, 3, 2, 2, '2', 'OK', None, ['f', '3'], 2]
    print('self-test ok')


if __name__ == '__main__':
    self_test()
