# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""QR codes as inline SVG, for the otpauth address of TOTP (5r). Byte mode, error correction level M, versions 1 to 10
(up to 213 bytes), after ISO/IEC 18004. Standard library only; the page shows the SVG, no script, no image from outside."""

# Error correction level M: (codewords for error correction per block, [(blocks, data codewords per block), ...]).
BLOCKS_M = {1: (10, [(1, 16)]), 2: (16, [(1, 28)]), 3: (26, [(1, 44)]), 4: (18, [(2, 32)]), 5: (24, [(2, 43)]), 6: (16, [(4, 27)]),
            7: (18, [(4, 31)]), 8: (22, [(2, 38), (2, 39)]), 9: (22, [(3, 36), (2, 37)]), 10: (26, [(4, 43), (1, 44)])}
ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]}
REMAINDER = {1: 0, 2: 7, 3: 7, 4: 7, 5: 7, 6: 7, 7: 0, 8: 0, 9: 0, 10: 0}

EXP, LOG = [0] * 512, [0] * 256
_value = 1
for _i in range(255):
    EXP[_i], LOG[_value] = _value, _i
    _value <<= 1
    if _value & 0x100:
        _value ^= 0x11d
for _i in range(255, 512):
    EXP[_i] = EXP[_i - 255]


def _mul(a, b):
    return 0 if a == 0 or b == 0 else EXP[LOG[a] + LOG[b]]


def rs_ecc(data, count):
    """The error correction codewords of one block (Reed-Solomon over GF(256), polynomial 0x11d)."""
    generator = [1]
    for i in range(count):
        generator = [a ^ _mul(b, EXP[i]) for a, b in zip(generator + [0], [0] + generator)]
    rest = list(data) + [0] * count
    for i in range(len(data)):
        factor = rest[i]
        if factor:
            for j, coefficient in enumerate(generator):
                rest[i + j] ^= _mul(coefficient, factor)
    return rest[len(data):]


def _bits(value, length):
    return [(value >> i) & 1 for i in range(length - 1, -1, -1)]


def codewords(data, version):
    """Data and error correction codewords, interleaved, of bytes in byte mode."""
    ec, groups = BLOCKS_M[version]
    capacity = sum(count * size for count, size in groups)
    bits = _bits(0b0100, 4) + _bits(len(data), 8 if version < 10 else 16)
    for byte in data:
        bits += _bits(byte, 8)
    if len(bits) > capacity * 8:
        raise ValueError('too long for this version')
    bits += [0] * min(4, capacity * 8 - len(bits))
    bits += [0] * (-len(bits) % 8)
    words = [int(''.join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = [0xEC, 0x11]
    while len(words) < capacity:
        words.append(pad[(len(words) - len(bits) // 8) % 2])
    blocks, start = [], 0
    for count, size in groups:
        for _ in range(count):
            blocks.append(words[start:start + size])
            start += size
    eccs = [rs_ecc(block, ec) for block in blocks]
    out = [block[i] for i in range(max(map(len, blocks))) for block in blocks if i < len(block)]
    return out + [item[i] for i in range(ec) for item in eccs]


def _format_bits(mask):
    value = (0b00 << 3) | mask  # level M is 00
    rest = value << 10
    for i in range(14, 9, -1):
        if rest & (1 << i):
            rest ^= 0x537 << (i - 10)
    return ((value << 10) | rest) ^ 0x5412


def _version_bits(version):
    rest = version << 12
    for i in range(17, 11, -1):
        if rest & (1 << i):
            rest ^= 0x1F25 << (i - 12)
    return (version << 12) | rest


def _base(version):
    size = 17 + 4 * version
    grid = [[None] * size for _ in range(size)]

    def finder(row, col):
        for r in range(-1, 8):
            for c in range(-1, 8):
                if 0 <= row + r < size and 0 <= col + c < size:
                    dark = 0 <= r <= 6 and 0 <= c <= 6 and (r in (0, 6) or c in (0, 6) or (2 <= r <= 4 and 2 <= c <= 4))
                    grid[row + r][col + c] = dark
    finder(0, 0)
    finder(0, size - 7)
    finder(size - 7, 0)
    for i in range(8, size - 8):
        grid[6][i] = grid[i][6] = i % 2 == 0
    last = len(ALIGN[version]) - 1
    for i, r in enumerate(ALIGN[version]):
        for j, c in enumerate(ALIGN[version]):
            # Not on the three finders; those on the timing lines are drawn over them.
            if (i, j) in ((0, 0), (0, last), (last, 0)):
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    grid[r + dr][c + dc] = max(abs(dr), abs(dc)) != 1
    grid[4 * version + 9][8] = True
    # Reserved for the format and the version information.
    for i in range(9):
        for row, col in ((8, i), (i, 8)):
            if grid[row][col] is None:
                grid[row][col] = False
    for i in range(8):
        for row, col in ((8, size - 1 - i), (size - 1 - i, 8)):
            if grid[row][col] is None:
                grid[row][col] = False
    if version >= 7:
        for i in range(6):
            for j in range(3):
                grid[i][size - 11 + j] = grid[size - 11 + j][i] = False
    return grid


MASKS = [lambda r, c: (r + c) % 2 == 0, lambda r, c: r % 2 == 0, lambda r, c: c % 3 == 0, lambda r, c: (r + c) % 3 == 0,
         lambda r, c: (r // 2 + c // 3) % 2 == 0, lambda r, c: (r * c) % 2 + (r * c) % 3 == 0, lambda r, c: ((r * c) % 2 + (r * c) % 3) % 2 == 0,
         lambda r, c: ((r + c) % 2 + (r * c) % 3) % 2 == 0]


def _place(version, words, mask):
    base = _base(version)
    size = len(base)
    grid = [row[:] for row in base]
    bits = [bit for word in words for bit in _bits(word, 8)] + [0] * REMAINDER[version]
    index, upward, col = 0, True, size - 1
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for c in (col, col - 1):
                if base[row][c] is None:
                    bit = bits[index] if index < len(bits) else 0
                    index += 1
                    grid[row][c] = bool(bit) ^ MASKS[mask](row, c)
        upward = not upward
        col -= 2
    form = _format_bits(mask)
    for i in range(15):
        bit = bool((form >> i) & 1)
        # Around the finder at the top left.
        if i < 6:
            grid[i][8] = bit
        elif i < 8:
            grid[i + 1][8] = bit
        else:
            grid[8][14 - i + (1 if i == 8 else 0) if i < 9 else 14 - i] = bit
        # The copy at the bottom left and the top right.
        if i < 8:
            grid[8][size - 1 - i] = bit
        else:
            grid[size - 15 + i][8] = bit
    if version >= 7:
        info = _version_bits(version)
        for i in range(18):
            bit = bool((info >> i) & 1)
            grid[i // 3][size - 11 + i % 3] = bit
            grid[size - 11 + i % 3][i // 3] = bit
    return grid


def _penalty(grid):
    size, score = len(grid), 0
    for lines in (grid, [list(col) for col in zip(*grid)]):
        for line in lines:
            run, last = 0, None
            for cell in line:
                run = run + 1 if cell == last else 1
                last = cell
                if run == 5:
                    score += 3
                elif run > 5:
                    score += 1
            text = ''.join('1' if cell else '0' for cell in line)
            score += 40 * (text.count('10111010000') + text.count('00001011101'))
    for r in range(size - 1):
        for c in range(size - 1):
            if grid[r][c] == grid[r + 1][c] == grid[r][c + 1] == grid[r + 1][c + 1]:
                score += 3
    dark = sum(cell for line in grid for cell in line) * 100 // (size * size)
    return score + abs(dark - 50) // 5 * 10


def matrix(text):
    """The modules of the QR code of text (True is dark), with the mask of the lowest penalty."""
    data = text.encode('utf-8')
    version = next((v for v in BLOCKS_M if 4 + (8 if v < 10 else 16) + 8 * len(data) <= 8 * sum(c * s for c, s in BLOCKS_M[v][1])), None)
    if version is None:
        raise ValueError('text too long for a QR code of version 10')
    words = codewords(data, version)
    return min((_place(version, words, mask) for mask in range(8)), key=_penalty)


def svg(text, module=4):
    """The QR code as SVG with the quiet zone of four modules."""
    grid = matrix(text)
    size = len(grid) + 8
    path = ''.join(f'M{c + 4} {r + 4}h1v1h-1z' for r, line in enumerate(grid) for c, cell in enumerate(line) if cell)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" width="{size * module}" height="{size * module}" '
            f'role="img" aria-label="QR code"><rect width="{size}" height="{size}" fill="#fff"/><path d="{path}" fill="#000"/></svg>')


def self_test():
    # The example of the standard texts: HELLO WORLD as 1-M (alphanumeric mode); the error correction of its data codewords.
    data = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17]
    assert rs_ecc(data, 10) == [196, 35, 39, 119, 235, 215, 231, 226, 93, 23], rs_ecc(data, 10)
    assert _format_bits(0) == 0b101010000010010 and _version_bits(7) == 0b000111110010010100
    for text, size in (('a', 21), ('otpauth://totp/eFa-next:anna%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=eFa-next', 37), ('x' * 213, 57)):
        grid = matrix(text)
        assert len(grid) == size and all(len(line) == size and all(isinstance(cell, bool) for cell in line) for line in grid), text
    assert codewords(b'a', 1)[:2] == [0x40, 0x16]
    try:
        matrix('x' * 214)
        raise AssertionError('too long')
    except ValueError:
        pass
    assert svg('a').startswith('<svg ') and 'script' not in svg('a')
    print('self-test ok')


if __name__ == '__main__':
    self_test()
