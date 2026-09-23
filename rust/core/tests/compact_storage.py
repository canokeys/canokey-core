# SPDX-License-Identifier: Apache-2.0
"""Check actual persisted sizes and grow/shrink/reload behavior through APDUs."""

import sys

from card_test import Card, connection, tlv
from openpgp_normal import Card as OpenPgp, ATTR
from piv_normal import Piv

with connection(sys.argv[1]) as wire:

    def size(record):
        return int.from_bytes(wire.command(f"SIZE {record}"), "big")

    assert [size(i) for i in (1, 2, 3, 4, 5, 6, 7, 14)] == [
        10,
        10,
        4,
        70,
        10,
        12,
        4,
        21,
    ]
    c = Card(wire)
    c.cmd("admin", 0xA4, 4, data=bytes.fromhex("f000000000"))
    c.cmd("pin", 0x20, data=b"123456", le=None)
    c.cmd("static", 0x44, 1, data=b"\x02\x03abc\x00", le=None)
    assert size(0) == 11
    c.cmd("clear", 0x13, le=None)
    assert size(0) == 8

    c.cmd("oath", 0xA4, 4, data=bytes.fromhex("a0000005272101"))
    for name in (b"a", b"b" * 64):
        c.cmd(
            "put", 1, data=tlv(0x71, name) + tlv(0x73, b"\x21\x06" + b"k" * 20), le=None
        )
    assert size(3) == 4 + 39 + 102
    c.cmd("rename", 5, data=tlv(0x71, b"a") + tlv(0x71, b"c" * 64), le=None)
    assert size(3) == 208
    wire.command("RESET")
    c.cmd("oath", 0xA4, 4, data=bytes.fromhex("a0000005272101"))
    assert len(c.cmd("list", 0xA1)) == 134
    for name in (b"c" * 64, b"b" * 64):
        c.cmd("delete", 2, data=tlv(0x71, name), le=None)
    assert size(3) == 4

    pgp = OpenPgp(wire)
    pgp.select()
    pgp.verify()
    values = [
        (0x5B, b"N" * 39),
        (0x5E, b"L" * 63),
        (0x5F2D, b"enfrdeit"),
        (0x5F35, b"2"),
        (0x5F50, b"U" * 255),
    ]
    for tag, value in values:
        pgp.put(tag, value)
    assert size(4) == 435
    wire.command("RESET")
    pgp.select()
    pgp.verify()
    for tag, value in values:
        assert pgp.get(tag) == value
        pgp.put(tag, value[:1])
    assert size(4) == 74
    for a, width in [(5, 128), (6, 192), (7, 256)]:
        pgp.put(0xC1, ATTR[a])
        pgp.cmd("generate", 0x47, 0x80, data=tlv(0xB6, b""))
        assert size(8) == 31 + 4 + 5 * width

    piv = Piv(wire)
    piv.select()
    piv.auth()
    for a, width in [(5, 128), (6, 192), (7, 256)]:
        key = piv.generate(a)
        assert size(17) == 6 + 4 + 5 * width
        for name in ("x" * 39, "y", ""):
            name = name.encode("utf-16le")
            piv.cmd("name", 0xF5, 1, 0x9A, name, le=None)
            assert size(17) == 6 + 4 + 5 * width + len(name)
            assert piv.cmd("name_read", 0xF5, 0, 0x9A) == name
            assert piv.public(a).public_numbers() == key.public_numbers()
    print("Compact storage: sizes, growth, shrinkage and reload passed")
