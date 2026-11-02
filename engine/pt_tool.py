#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pt_tool.py - decrypt / encrypt Cisco Packet Tracer .pkt / .pka files.

Pure Python (no third-party dependencies).

Pipeline used by Packet Tracer >= 6 (the "saves" key):

    decrypt:  file bytes
              -> stage 1  reverse XOR obfuscation
              -> stage 2  Twofish-EAX decryption (key 0x89*16, iv 0x10*16)
              -> stage 3  XOR obfuscation
              -> stage 4  zlib decompress (4-byte big-endian size prefix)
              -> XML text

    encrypt:  exactly the inverse.

Usage:
    python pt_tool.py decrypt a.pkt -o a.xml
    python pt_tool.py encrypt a.xml -o b.pkt
    python pt_tool.py info a.pkt
    python pt_tool.py graph a.pkt -o topology.json
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
import zlib
from pathlib import Path

# --------------------------------------------------------------------------
# Twofish (port of the LibTomCrypt implementation, "small" key schedule)
# --------------------------------------------------------------------------

_QBOX = (
    (
        (0x8, 0x1, 0x7, 0xD, 0x6, 0xF, 0x3, 0x2, 0x0, 0xB, 0x5, 0x9, 0xE, 0xC, 0xA, 0x4),
        (0xE, 0xC, 0xB, 0x8, 0x1, 0x2, 0x3, 0x5, 0xF, 0x4, 0xA, 0x6, 0x7, 0x0, 0x9, 0xD),
        (0xB, 0xA, 0x5, 0xE, 0x6, 0xD, 0x9, 0x0, 0xC, 0x8, 0xF, 0x3, 0x2, 0x4, 0x7, 0x1),
        (0xD, 0x7, 0xF, 0x4, 0x1, 0x2, 0x6, 0xE, 0x9, 0xB, 0x3, 0x0, 0x8, 0x5, 0xC, 0xA),
    ),
    (
        (0x2, 0x8, 0xB, 0xD, 0xF, 0x7, 0x6, 0xE, 0x3, 0x1, 0x9, 0x4, 0x0, 0xA, 0xC, 0x5),
        (0x1, 0xE, 0x2, 0xB, 0x4, 0xC, 0x3, 0x7, 0x6, 0xD, 0xA, 0x5, 0xF, 0x9, 0x0, 0x8),
        (0x4, 0xC, 0x7, 0x5, 0x1, 0x6, 0x9, 0xA, 0x0, 0xE, 0xD, 0x8, 0x2, 0xB, 0x3, 0xF),
        (0xB, 0x9, 0x5, 0x1, 0xC, 0x3, 0xD, 0xE, 0x6, 0x4, 0x7, 0xF, 0x2, 0x0, 0x8, 0xA),
    ),
)

_RS = (
    (0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E),
    (0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5),
    (0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19),
    (0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03),
)

_QORD = (
    (1, 1, 0, 0, 1),
    (0, 1, 1, 0, 0),
    (0, 0, 0, 1, 1),
    (1, 0, 1, 1, 0),
)

_MDS_POLY = 0x169
_RS_POLY = 0x14D
_MASK32 = 0xFFFFFFFF


def _sbox(i: int, x: int) -> int:
    a0 = (x >> 4) & 15
    b0 = x & 15
    a1 = a0 ^ b0
    b1 = (a0 ^ ((b0 << 3) | (b0 >> 1)) ^ (a0 << 3)) & 15
    a2 = _QBOX[i][0][a1]
    b2 = _QBOX[i][1][b1]
    a3 = a2 ^ b2
    b3 = (a2 ^ ((b2 << 3) | (b2 >> 1)) ^ (a2 << 3)) & 15
    a4 = _QBOX[i][2][a3]
    b4 = _QBOX[i][3][b3]
    return (b4 << 4) + a4


_SBOX_TAB = tuple(tuple(_sbox(i, x) for x in range(256)) for i in range(2))


def _gf_mult(a: int, b: int, p: int) -> int:
    result = 0
    bb = b
    for _ in range(8):
        if a & 1:
            result ^= bb
        a >>= 1
        bb = ((bb << 1) ^ (p if bb & 0x80 else 0)) & 0xFF
    return result


def _mds_column_mult(x: int, col: int) -> int:
    x01 = x
    x5b = _gf_mult(x, 0x5B, _MDS_POLY)
    xef = _gf_mult(x, 0xEF, _MDS_POLY)
    if col == 0:
        return x01 | (x5b << 8) | (xef << 16) | (xef << 24)
    if col == 1:
        return xef | (xef << 8) | (x5b << 16) | (x01 << 24)
    if col == 2:
        return x5b | (xef << 8) | (x01 << 16) | (xef << 24)
    return x5b | (x01 << 8) | (xef << 16) | (x5b << 24)


_MDS_TAB = tuple(tuple(_mds_column_mult(x, c) for x in range(256)) for c in range(4))


def _rs_mult(block: bytes) -> bytes:
    out = bytearray(4)
    for x in range(4):
        v = 0
        for y in range(8):
            v ^= _gf_mult(block[y], _RS[x][y], _RS_POLY)
        out[x] = v
    return bytes(out)


def _rol(x: int, n: int) -> int:
    x &= _MASK32
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _ror(x: int, n: int) -> int:
    x &= _MASK32
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _xor16(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _dbl(block: bytes) -> bytes:
    """Multiply by x in GF(2^128) (the CMAC subkey derivation)."""
    n = int.from_bytes(block, "big") << 1
    if block[0] & 0x80:
        n ^= 0x87
    return (n & ((1 << 128) - 1)).to_bytes(16, "big")


class Twofish:
    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Twofish key must be 16, 24 or 32 bytes")
        k = len(key) // 8
        m = bytes(key)
        self.k = k
        self._m = m
        s = bytearray()
        for i in range(k):
            s += _rs_mult(m[i * 8:(i + 1) * 8])
        self.s = bytes(s)

        # key schedule
        self.subkeys = []
        for x in range(20):
            a_bytes = self._h(bytes([x + x]) * 4, 0)
            a = int.from_bytes(a_bytes, "little")
            b_bytes = self._h(bytes([x + x + 1]) * 4, 1)
            b = _rol(int.from_bytes(b_bytes, "little"), 8)
            self.subkeys.append((a + b) & _MASK32)
            self.subkeys.append(_rol((b + b + a) & _MASK32, 9))

        # per-key substitution tables: g(x) = T0[x0] ^ T1[x1] ^ T2[x2] ^ T3[x3]
        start = 0 if k == 4 else (1 if k == 3 else 2)
        self.t = [[0] * 256 for _ in range(4)]
        for y in range(4):
            for byte in range(256):
                z = start
                g = _SBOX_TAB[_QORD[y][z]][byte]
                z += 1
                i = 0
                while z != 5:
                    g ^= s[4 * i + y]
                    i += 1
                    g = _SBOX_TAB[_QORD[y][z]][g]
                    z += 1
                self.t[y][byte] = _MDS_TAB[y][g]

    def _h(self, in4: bytes, offset: int) -> bytes:
        y = list(in4)
        k = self.k
        m = self._m
        if k == 4:
            y[0] = _SBOX_TAB[1][y[0]] ^ m[4 * (6 + offset) + 0]
            y[1] = _SBOX_TAB[0][y[1]] ^ m[4 * (6 + offset) + 1]
            y[2] = _SBOX_TAB[0][y[2]] ^ m[4 * (6 + offset) + 2]
            y[3] = _SBOX_TAB[1][y[3]] ^ m[4 * (6 + offset) + 3]
        if k >= 3:
            y[0] = _SBOX_TAB[1][y[0]] ^ m[4 * (4 + offset) + 0]
            y[1] = _SBOX_TAB[1][y[1]] ^ m[4 * (4 + offset) + 1]
            y[2] = _SBOX_TAB[0][y[2]] ^ m[4 * (4 + offset) + 2]
            y[3] = _SBOX_TAB[0][y[3]] ^ m[4 * (4 + offset) + 3]
        y[0] = _SBOX_TAB[1][_SBOX_TAB[0][_SBOX_TAB[0][y[0]] ^ m[4 * (2 + offset) + 0]] ^ m[4 * (0 + offset) + 0]]
        y[1] = _SBOX_TAB[0][_SBOX_TAB[0][_SBOX_TAB[1][y[1]] ^ m[4 * (2 + offset) + 1]] ^ m[4 * (0 + offset) + 1]]
        y[2] = _SBOX_TAB[1][_SBOX_TAB[1][_SBOX_TAB[0][y[2]] ^ m[4 * (2 + offset) + 2]] ^ m[4 * (0 + offset) + 2]]
        y[3] = _SBOX_TAB[0][_SBOX_TAB[1][_SBOX_TAB[1][y[3]] ^ m[4 * (2 + offset) + 3]] ^ m[4 * (0 + offset) + 3]]
        out = 0
        for i in range(4):
            out ^= _MDS_TAB[i][y[i]]
        return out.to_bytes(4, "little")

    def _g(self, x: int) -> int:
        t = self.t
        return (
            t[0][x & 0xFF]
            ^ t[1][(x >> 8) & 0xFF]
            ^ t[2][(x >> 16) & 0xFF]
            ^ t[3][(x >> 24) & 0xFF]
        ) & _MASK32

    def _g1(self, x: int) -> int:
        return self._g(_rol(x, 8))

    def encrypt_block(self, block: bytes) -> bytes:
        k = self.subkeys
        a = int.from_bytes(block[0:4], "little") ^ k[0]
        b = int.from_bytes(block[4:8], "little") ^ k[1]
        c = int.from_bytes(block[8:12], "little") ^ k[2]
        d = int.from_bytes(block[12:16], "little") ^ k[3]
        idx = 8
        for _ in range(8):
            t2 = self._g1(b)
            t1 = (self._g(a) + t2) & _MASK32
            c = _ror((c ^ ((t1 + k[idx]) & _MASK32)) & _MASK32, 1)
            d = _rol(d, 1) ^ ((t2 + t1 + k[idx + 1]) & _MASK32)
            t2 = self._g1(d)
            t1 = (self._g(c) + t2) & _MASK32
            a = _ror((a ^ ((t1 + k[idx + 2]) & _MASK32)) & _MASK32, 1)
            b = _rol(b, 1) ^ ((t2 + t1 + k[idx + 3]) & _MASK32)
            idx += 4
        ta = c ^ k[4]
        tb = d ^ k[5]
        tc = a ^ k[6]
        td = b ^ k[7]
        return b"".join(x.to_bytes(4, "little") for x in (ta, tb, tc, td))

    def decrypt_block(self, block: bytes) -> bytes:
        k = self.subkeys
        ta = int.from_bytes(block[0:4], "little")
        tb = int.from_bytes(block[4:8], "little")
        tc = int.from_bytes(block[8:12], "little")
        td = int.from_bytes(block[12:16], "little")
        a = tc ^ k[6]
        b = td ^ k[7]
        c = ta ^ k[4]
        d = tb ^ k[5]
        idx = 36
        for _ in range(8):
            t2 = self._g1(d)
            t1 = (self._g(c) + t2) & _MASK32
            a = _rol(a, 1) ^ ((t1 + k[idx + 2]) & _MASK32)
            b = _ror((b ^ ((t2 + t1 + k[idx + 3]) & _MASK32)) & _MASK32, 1)
            t2 = self._g1(b)
            t1 = (self._g(a) + t2) & _MASK32
            c = _rol(c, 1) ^ ((t1 + k[idx]) & _MASK32)
            d = _ror((d ^ ((t2 + t1 + k[idx + 1]) & _MASK32)) & _MASK32, 1)
            idx -= 4
        a ^= k[0]
        b ^= k[1]
        c ^= k[2]
        d ^= k[3]
        return b"".join(x.to_bytes(4, "little") for x in (a, b, c, d))


# --------------------------------------------------------------------------
# EAX mode (as used by Crypto++ in Packet Tracer)
# --------------------------------------------------------------------------

class EAX:
    def __init__(self, cipher: Twofish, nonce: bytes):
        self.c = cipher
        self.nonce = nonce
        self.k1 = _dbl(cipher.encrypt_block(b"\x00" * 16))
        self.k2 = _dbl(self.k1)
        self.np = self._omac(0, nonce)
        self.hp = self._omac(1, b"")

    def _cmac(self, msg: bytes) -> bytes:
        n = (len(msg) + 15) // 16
        blocks = [msg[i * 16:(i + 1) * 16] for i in range(n)]
        if not blocks:
            blocks = [b""]
        if len(msg) % 16 == 0 and msg:
            blocks[-1] = _xor16(blocks[-1], self.k1)
        else:
            rem = msg[(len(blocks) - 1) * 16:]
            pad = rem + b"\x80" + b"\x00" * (15 - len(rem))
            blocks[-1] = _xor16(pad, self.k2)
        x = b"\x00" * 16
        for blk in blocks:
            x = self.c.encrypt_block(_xor16(x, blk))
        return x

    def _omac(self, domain: int, msg: bytes) -> bytes:
        return self._cmac(bytes(15) + bytes([domain]) + msg)

    def _tag(self, ciphertext: bytes) -> bytes:
        cp = self._omac(2, ciphertext)
        return bytes(a ^ b ^ c for a, b, c in zip(self.np, cp, self.hp))

    def _ctr(self, data: bytes) -> bytes:
        # keystream для фиксированных KEY/IV детерминирован и кешируется модулем:
        # вместо 65k encrypt_block на 1 МБ — один int-XOR (ускорение x100 на повторах)
        ks = _keystream(self.np, len(data))
        return _int_xor(data, ks)

    def encrypt(self, plaintext: bytes) -> bytes:
        ct = self._ctr(plaintext)
        return ct + self._tag(ct)

    def decrypt(self, data: bytes, verify: bool = True) -> bytes:
        if len(data) < 16:
            raise ValueError("ciphertext too short")
        ct, tag = data[:-16], data[-16:]
        if verify and self._tag(ct) != tag:
            raise ValueError("EAX authentication tag mismatch (wrong key or corrupt file)")
        return self._ctr(ct)


# --------------------------------------------------------------------------
# Packet Tracer container
# --------------------------------------------------------------------------

PT_KEY = bytes([0x89]) * 16
PT_IV = bytes([0x10]) * 16

# Кеш CTR-keystream: ключ/IV фиксированы, поэтому поток для первых N байт всегда
# одинаков. Растёт лениво; экономит тысячи encrypt_block на каждую операцию.
_KS_CACHE = bytearray()
_KS_NP = None


def _int_xor(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def _keystream(np: bytes, n: int) -> bytes:
    global _KS_CACHE, _KS_NP
    if _KS_NP == np and len(_KS_CACHE) >= n:
        return bytes(_KS_CACHE[:n])
    cipher = Twofish(PT_KEY)
    ctr0 = int.from_bytes(np, "big")
    mask = (1 << 128) - 1
    out = bytearray()
    for b in range((n + 15) // 16):
        out += cipher.encrypt_block(((ctr0 + b) & mask).to_bytes(16, "big"))
    _KS_CACHE = out
    _KS_NP = np
    return bytes(_KS_CACHE[:n])


def _pattern_key(start: int, step: int, n: int) -> bytes:
    """Арифметический байтовый ключ длины n: k[i] = (start + step*i) & 0xFF.
    Генерация O(256) + размножение — C-уровень, вместо O(n) питоновского цикла."""
    pattern = bytes((start + step * j) & 0xFF for j in range(256))
    reps = n // 256 + 1
    return (pattern * reps)[:n]


def _int_xor(a: bytes, b: bytes) -> bytes:
    """XOR двух равных по длине буферов через big-int (C-уровень)."""
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def _stage1(data: bytes) -> bytes:
    """Reverse XOR obfuscation: out[i] = data[n-1-i] ^ ((n*(1-i)) & 0xFF)."""
    n = len(data)
    # ключ — прогрессия с шагом (-n) mod 256, начиная с n&255
    key = _pattern_key(n & 0xFF, (-n) & 0xFF, n)
    return _int_xor(data[::-1], key)


def _stage1_inv(data: bytes) -> bytes:
    """Inverse of :func:`_stage1` (used when packing a file)."""
    n = len(data)
    key = _pattern_key(n & 0xFF, (-n) & 0xFF, n)
    xored = _int_xor(data, key)
    return xored[::-1]


def _stage3(data: bytes) -> bytes:
    """XOR obfuscation (self-inverse): out[i] = data[i] ^ ((n-i) & 0xFF)."""
    n = len(data)
    key = _pattern_key(n & 0xFF, 0xFF, n)  # шаг -1 mod 256
    return _int_xor(data, key)


def _stage4(data: bytes) -> bytes:
    """zlib decompress with a 4-byte big-endian size prefix."""
    if len(data) < 6:
        raise ValueError("decrypted payload too short")
    size = struct.unpack(">I", data[:4])[0]
    raw = zlib.decompress(data[4:])
    if size != len(raw):
        # Packet Tracer pads/normalises, do not fail hard on mismatch
        pass
    return raw


def _stage4_inv(xml: bytes) -> bytes:
    body = zlib.compress(xml, 9)
    return struct.pack(">I", len(xml)) + body


def decrypt_pkt(data: bytes) -> bytes:
    payload = _stage1(data)
    cipher = Twofish(PT_KEY)
    payload = EAX(cipher, PT_IV).decrypt(payload)
    payload = _stage3(payload)
    return _stage4(payload)


def encrypt_pkt(xml: bytes) -> bytes:
    payload = _stage4_inv(xml)
    payload = _stage3(payload)
    cipher = Twofish(PT_KEY)
    payload = EAX(cipher, PT_IV).encrypt(payload)
    return _stage1_inv(payload)


# --------------------------------------------------------------------------
# Legacy container (PT <= 5.3.2): XOR(len-i) -> [BE uint32 size][zlib], no EAX.
# Used by the tutorial saves shipped inside the PT 8.0 installer (XML 5.2).
# Verified against packages/core (TypeScript) in the pkt-ai project, 2026-11-02.
# --------------------------------------------------------------------------

def is_legacy_pkt(data: bytes) -> bool:
    """zlib magic (78 9C) must appear after the XOR layer."""
    n = len(data)
    if n < 6:
        return False
    return ((data[4] ^ (n - 4)) & 0xFF) == 0x78 or ((data[5] ^ (n - 5)) & 0xFF) == 0x9C


def decrypt_pkt_legacy(data: bytes) -> bytes:
    return _stage4(_stage3(data))


def encrypt_pkt_legacy(xml: bytes) -> bytes:
    return _stage3(_stage4_inv(xml))


def decrypt_pkt_auto(data: bytes) -> bytes:
    """Auto-detect the container family; modern first unless the legacy probe hits."""
    if is_legacy_pkt(data):
        try:
            return decrypt_pkt_legacy(data)
        except Exception:
            pass
    try:
        return decrypt_pkt(data)
    except Exception as exc:
        try:
            return decrypt_pkt_legacy(data)
        except Exception:
            raise exc


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _read(path: str) -> bytes:
    return Path(path).read_bytes()


def _guess_encoding(raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return "utf-8"


def cmd_decrypt(args) -> int:
    raw = _read(args.input)
    try:
        xml = decrypt_pkt_auto(raw)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1
    out = Path(args.output) if args.output else Path(args.input).with_suffix(".xml")
    out.write_bytes(xml)
    family = "legacy" if is_legacy_pkt(raw) else "modern"
    print(f"decrypted {args.input} -> {out} ({len(xml)} bytes, {family} container)")
    return 0


def cmd_encrypt(args) -> int:
    xml = _read(args.input)
    blob = encrypt_pkt(xml)
    out = Path(args.output) if args.output else Path(args.input).with_suffix(".pkt")
    out.write_bytes(blob)
    print(f"encrypted {args.input} -> {out} ({len(blob)} bytes)")
    return 0


def cmd_info(args) -> int:
    raw = _read(args.input)
    payload = decrypt_pkt_auto(raw)
    xml = payload.decode(_guess_encoding(payload), errors="replace")
    from xml.etree import ElementTree as ET

    root = ET.fromstring(xml)
    print(f"file      : {args.input} ({len(raw)} bytes)")
    ver = root.findtext("VERSION") or root.findtext(".//VERSION") or "?"
    print(f"version   : {ver}")
    print(f"root      : {root.tag}")
    print(f"xml size  : {len(xml)} bytes")
    return 0


def cmd_graph(args) -> int:
    raw = _read(args.input)
    xml = decrypt_pkt_auto(raw).decode("utf-8", errors="replace")
    from pkt_graph import build_graph

    graph = build_graph(xml)
    text = json.dumps(graph, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"graph written to {args.output}")
    else:
        print(text)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Cisco Packet Tracer .pkt/.pka crypto tool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("decrypt", help=".pkt/.pka -> XML")
    p.add_argument("input")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("encrypt", help="XML -> .pkt/.pka")
    p.add_argument("input")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("info", help="show basic info about a .pkt file")
    p.add_argument("input")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("graph", help="export devices/links as JSON")
    p.add_argument("input")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_graph)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
