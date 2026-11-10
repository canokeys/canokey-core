#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Recover uncertain storage through the real IFD library, without a daemon."""
import hashlib
import os
import sys
import tempfile

from fido2 import cbor
from fido2.ctap2.base import AuthenticatorData

from card_test import Card
from pcsc_normal import Driver

NFC_FIDO_AID = bytes.fromhex("A0000006472F0001")
REBOOT_COOKIE = bytes.fromhex("1256ABF0")  # Host-only recovery, before applet dispatch.
CTAP_MAKE_CREDENTIAL = 0x01
CTAP_GET_ASSERTION = 0x02
CTAP_SUCCESS = 0x00
CTAP_OTHER = 0x7F
SELECT_BY_NAME = 0x04
SW_NO_APPLET = 0x6A82
POWER_UP = 500  # PC/SC IFD_POWER_UP action, not an APDU value.


def run(library):
    with tempfile.TemporaryDirectory(prefix="rust-pcsc-recovery-") as directory:
        os.environ.update(CANOKEY_VIRT_LFS_ROOT=directory + "/image",
                          CANOKEY_VIRT_RESET_STORAGE="1", CANOKEY_TEST_NFC="1")
        driver = Driver(library)
        assert driver.lib.IFDHCreateChannel(driver.lun, 0) == 0
        try:
            assert driver.power(POWER_UP)[0] == 0
            card = Card(driver)

            def select(status=0x9000):
                card.cmd("select NFC FIDO", 0xA4, SELECT_BY_NAME,
                         data=NFC_FIDO_AID, status=status)

            def ctap(command, parameters, expected=CTAP_SUCCESS):
                payload = bytes([command]) + cbor.encode(parameters)
                # Short case 4 APDU: CLA/INS/P1/P2/Lc, CTAP bytes, Le=256.
                assert len(payload) <= 255
                response = card.cmd("CTAP", 0x10, 0x80, cla=0x80, data=payload)
                assert response[0] == expected, response.hex()
                return cbor.decode(response[1:]) if len(response) > 1 else None

            select()
            challenge = hashlib.sha256(b"IFD lost acknowledgement").digest()
            rp = "pcsc-recovery.example"
            made = ctap(CTAP_MAKE_CREDENTIAL, {
                1: challenge, 2: {"id": rp}, 3: {"id": b"recovery"},
                4: [{"type": "public-key", "alg": -7}], 7: {"rk": True},
            })
            key = AuthenticatorData(made[2]).credential_data.public_key
            request = {1: rp, 2: challenge, 5: {"up": False}}
            before = ctap(CTAP_GET_ASSERTION, request)
            counter = AuthenticatorData(before[2]).counter
            key.verify(before[2] + challenge, before[3])

            # Record 4f owns the signature counter. Operation 02 loses the
            # acknowledgement after durable commit and marks storage uncertain.
            card.cmd("inject lost acknowledgement", 0xEF, 0x02, data=b"4f")
            ctap(CTAP_GET_ASSERTION, request, CTAP_OTHER)
            select(SW_NO_APPLET)
            card.cmd("recover before selection", 0xEE, data=REBOOT_COOKIE)
            select()
            recovered = ctap(CTAP_GET_ASSERTION, request)
            key.verify(recovered[2] + challenge, recovered[3])
            assert AuthenticatorData(recovered[2]).counter == counter + 2
        finally:
            assert driver.lib.IFDHCloseChannel(driver.lun) == 0
    print("Rust PC/SC recovery: uncertain SELECT rejected; reboot, durable counter and signature passed")


if __name__ == "__main__":
    run(sys.argv[1])
