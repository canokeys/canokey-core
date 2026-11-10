#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the patched, pinned test client without a physical reader."""
import ast
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fido2.ctap import CtapError
from fido2.hid import CAPABILITY, CTAPHID
from fido2.pcsc import CtapPcscDevice
from smartcard.Exceptions import CardConnectionException
from smartcard.scard import SCARD_LEAVE_CARD, SCARD_UNPOWER_CARD


SELECT_HEADER = bytes.fromhex("00A40400")  # ISO SELECT by AID.
FIDO_SELECT = bytes.fromhex("00A4040008F043414E4F464944")  # Select the private USB FIDO AID.
GET_INFO = bytes.fromhex("80100000010400")  # CTAP authenticatorGetInfo.
SW_SUCCESS = (0x90, 0x00)
SW_NO_APPLET = (0x6A, 0x82)
GET_INFO_RESPONSE = bytes.fromhex("00A0")  # CTAP success followed by an empty CBOR map.
REBOOT = bytes.fromhex("00EE0000041256ABF0")  # Host-only recovery cookie, intercepted before applet dispatch.


class Connection:
    def __init__(self, card):
        self.card = card
        self.disposition = SCARD_UNPOWER_CARD
        self.fail_next = False
        self.sent = []

    def connect(self, disposition=SCARD_UNPOWER_CARD):
        self.disposition = disposition
        self.card.selected = False

    def disconnect(self):
        if self.disposition != SCARD_LEAVE_CARD:
            self.card.selected = False

    def transmit(self, apdu, protocol=None):
        apdu = bytes(apdu)
        self.sent.append(apdu)
        if self.fail_next:
            self.fail_next = False
            raise CardConnectionException("injected connection loss")
        if apdu == REBOOT:
            self.card.uncertain = False
            self.card.selected = False
            return [], *SW_SUCCESS
        if apdu[:4] == SELECT_HEADER:
            if self.card.uncertain:
                return [], *SW_NO_APPLET
            expected = bytes.fromhex("00A4040008A0000006472F0001") if self.card.nfc else FIDO_SELECT
            if apdu != expected:
                self.card.selected = False
                return [], *SW_NO_APPLET
            self.card.selected = True
            return list(b"U2F_V2"), *SW_SUCCESS
        if not self.card.selected:
            return [], *SW_NO_APPLET
        # CTAP success and an empty CBOR map suffice for the capability probe.
        return list(GET_INFO_RESPONSE), *SW_SUCCESS


class SelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = Path(sys.argv[1]).read_text()
        tree = ast.parse(source)
        client = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "MoreRobustPcscDevice")
        device = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "TestDevice")
        reboot = next(n for n in device.body if isinstance(n, ast.FunctionDef) and n.name == "send_nfc_reboot")
        namespace = dict(CtapPcscDevice=CtapPcscDevice, CtapError=CtapError,
                         CAPABILITY=CAPABILITY, CTAPHID=CTAPHID, sys=sys)
        exec(compile(ast.Module(body=[client, reboot], type_ignores=[]), sys.argv[1], "exec"), namespace)
        cls.client_type = namespace["MoreRobustPcscDevice"]
        cls.reboot = staticmethod(namespace["send_nfc_reboot"])

    def setUp(self):
        environment = patch.dict("os.environ", {"CANOKEY_TEST_NFC": "0"})
        environment.start()
        self.addCleanup(environment.stop)
        self.card = SimpleNamespace(selected=False, nfc=False, uncertain=False)
        self.old = Connection(self.card)
        self.client_type(self.old, "old reader")
        self.connection = Connection(self.card)
        self.client = self.client_type(self.connection, "active reader")

    def test_nfc_uses_standard_aid_and_usb_rejects_it(self):
        standard = bytes.fromhex("00A4040008A0000006472F0001")
        self.assertEqual(self.connection.transmit(standard)[1:], SW_NO_APPLET)
        with patch.dict("os.environ", {"CANOKEY_TEST_NFC": "1"}):
            self.card.nfc = True
            connection = Connection(self.card)
            client = self.client_type(connection, "NFC reader")
            self.assertEqual(connection.sent[0], standard)
            connection.fail_next = True
            self.assertEqual(client.apdu_exchange(GET_INFO)[1:], SW_SUCCESS)
            self.assertIn(standard, connection.sent[1:])

    def test_late_old_connection_cleanup_preserves_selection(self):
        self.old.disconnect()
        self.assertEqual(self.client.apdu_exchange(GET_INFO)[1:], SW_SUCCESS)

    def test_reconnect_selects_before_retrying_payload(self):
        self.connection.sent.clear()
        self.connection.fail_next = True
        self.assertEqual(self.client.apdu_exchange(GET_INFO)[1:], SW_SUCCESS)
        self.assertEqual(self.connection.sent[1][:4], SELECT_HEADER)
        self.assertEqual(self.connection.sent[-1], GET_INFO)
        self.assertEqual(self.connection.disposition, SCARD_LEAVE_CARD)

    def test_interrupted_select_retries_without_recursion(self):
        self.connection.sent.clear()
        self.connection.fail_next = True
        self.assertEqual(self.client.apdu_exchange(FIDO_SELECT)[1:], SW_SUCCESS)
        self.assertEqual(self.connection.sent, [FIDO_SELECT, FIDO_SELECT])

    def test_reboot_hook_recovers_without_applet_selection(self):
        self.card.selected = False
        with patch.object(sys, "argv", ["test", "canokeys"]):
            self.assertTrue(self.reboot(SimpleNamespace(dev=self.client)))

    def test_reboot_precedes_selection_after_lost_commit_acknowledgement(self):
        self.card.uncertain = True
        self.connection.sent.clear()
        with patch.object(sys, "argv", ["test", "canokeys"]):
            self.assertTrue(self.reboot(SimpleNamespace(dev=self.client)))
        self.assertEqual(self.connection.sent, [REBOOT])
        self.assertFalse(self.card.uncertain)
        self.client._select()
        self.assertTrue(self.card.selected)

    def test_reboot_reconnect_does_not_select_uncertain_storage(self):
        self.card.uncertain = True
        self.connection.sent.clear()
        self.connection.fail_next = True
        with patch.object(sys, "argv", ["test", "canokeys"]):
            self.assertTrue(self.reboot(SimpleNamespace(dev=self.client)))
        self.assertEqual(self.connection.sent, [REBOOT, REBOOT])
        self.assertFalse(self.card.uncertain)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
