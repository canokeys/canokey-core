#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Cross-applet reset regression for the combined host profile."""

import argparse

from card_test import connection
from openpgp_normal import Card as OpenPgp
from piv_normal import Piv, tlv

ADMIN = bytes.fromhex("f000000000")
OATH = bytes.fromhex("a0000005272101")


def admin(card):
    card.cmd("select_admin", 0xA4, 4, data=ADMIN)
    card.cmd("admin_verify", 0x20, data=b"123456", le=None)


def seed_piv(card):
    card.select()
    card.auth()
    card.generate(0)
    card.put(0x5FC105, tlv(0x53, b"throwaway certificate"))


def check_piv_reset(card):
    card.select()
    card.cmd("reset_erased_key", 0xF7, 0, 0x9A, status=0x6A88)
    card.get(0x5FC105, status=0x6A82)
    card.verify()
    card.auth()


def run(wire):
    card = Piv(wire)
    pgp = OpenPgp(wire)
    admin(card)
    default_pass = card.cmd("default_pass", 0x43)
    card.cmd("seed_pass", 0x44, 1, data=bytes([2, 3]) + b"abc" + b"\0", le=None)
    card.cmd("select_oath", 0xA4, 4, data=OATH)
    card.cmd("seed_oath", 0x01, data=tlv(0x71, b"reset-test") + tlv(0x73, b"\x21\x06secret"))
    pgp.select()
    default_name = pgp.get(0x5B)
    pgp.verify()
    pgp.put(0x5B, b"Reset<<Regression")
    seed_piv(card)

    # ADMIN's per-applet reset needs authorization and must leave peers intact.
    card.cmd("select_admin", 0xA4, 4, data=ADMIN)
    card.cmd("unauthorized_piv_reset", 0x04, le=None, status=0x6982)
    admin(card)
    card.cmd("admin_piv_reset", 0x04, le=None)
    check_piv_reset(card)
    pgp.select()
    assert pgp.get(0x5B) == b"Reset<<Regression"
    seed_piv(card)

    # Factory recovery clears every enabled applet, not only ADMIN/PASS.
    card.cmd("select_admin", 0xA4, 4, data=ADMIN)
    for status in (0x63C2, 0x63C1, 0x6983):
        card.cmd("block_admin", 0x20, data=b"000000", le=None, status=status)
    card.cmd("factory_reset", 0x50, data=b"RESET", le=None)
    check_piv_reset(card)
    pgp.select()
    assert pgp.get(0x5B) == default_name
    pgp.verify()
    card.cmd("select_oath", 0xA4, 4, data=OATH)
    assert card.cmd("oath_empty", 0xA1) == b""
    admin(card)
    assert card.cmd("pass_empty", 0x43) == default_pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    args = parser.parse_args()
    with connection(args.host) as wire:
        run(wire)
