#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate E65 disabled-applet SELECT contracts from pinned C routing rules."""
import argparse
import json
from pathlib import Path

from c312_select_vectors import (Wire, select, USB_AID, NFC_AID, ADMIN_SELECT,
                                ADMIN_VERIFY, ADMIN_QUERY, VERSION, GET_RESPONSE,
                                SUCCESS, NOT_FOUND, WRONG_P2, NO_RESPONSE, FIDO_VERSION)

# Admin configuration selectors: feature mask P1=06, NDEF enable P1=04.
FEATURE_MASK = 0x3f
FEATURE_OPENPGP_USB = 0x02
FEATURE_OPENPGP_NFC = 0x04
FEATURE_PIV_USB = 0x08
FEATURE_PIV_NFC = 0x10
FEATURE_FIDO = 0x20
NDEF_AID = bytes.fromhex('d2760000850101')
OPENPGP_AID = bytes.fromhex('d27600012401')
PIV_AID = bytes.fromhex('a000000308000010000100')
# READ_CONFIG: LED on, reserved zero, NDEF writable/enabled, WebUSB on, all features.
DEFAULT_CONFIG = bytes.fromhex('01000001013f') + SUCCESS
# Empty Admin VERIFY without a grant reports the unchanged three PIN retries.
UNVERIFIED_PIN = bytes.fromhex('63c3')


def configure_features(mask):
    return bytes([0, 0x40, 0x06, mask, 0])


def configure_ndef(enabled):
    return bytes([0, 0x40, 0x04, int(enabled), 0])


def probe(aid, p2, form):
    extended = form.startswith('extended')
    frame = select(aid, p2, extended)
    return frame + ((b'\0\0' if extended else b'\0') if form.endswith('4') else b'')


def generate():
    cases = []
    for transport in ['ccid', 'webusb', 'nfc']:
        nfc = transport == 'nfc'
        fido = NFC_AID if nfc else USB_AID
        pgp_bit = FEATURE_OPENPGP_NFC if nfc else FEATURE_OPENPGP_USB
        piv_bit = FEATURE_PIV_NFC if nfc else FEATURE_PIV_USB
        targets = [('ndef', NDEF_AID, 0), ('openpgp', OPENPGP_AID, pgp_bit),
                   ('piv-rid', PIV_AID[:5], piv_bit), ('piv-nine', PIV_AID[:9], piv_bit),
                   ('piv-full', PIV_AID, piv_bit), ('fido', fido, FEATURE_FIDO)]
        forms = ['short3', 'short4'] + ([] if transport == 'ccid' else ['extended3', 'extended4'])
        for target, aid, bit in targets:
            # Also disable OpenPGP to establish a genuine unselected context via
            # C's disabled_applet_response, without fixture policy injection.
            flags = FEATURE_MASK & ~pgp_bit & ~bit
            for prior in ['none', 'admin-pin'] + ([] if target == 'fido' else ['fido']):
                for form in forms:
                    for p2 in [0, 0xff]:
                        wire = Wire(transport)
                        wire.apdu(ADMIN_SELECT, SUCCESS)
                        wire.apdu(ADMIN_VERIFY, SUCCESS)
                        wire.apdu(configure_features(flags), SUCCESS)
                        if target == 'ndef':
                            wire.apdu(configure_ndef(False), SUCCESS)
                        wire.apdu(bytes.fromhex('0042000000'),
                                  bytes([1, 0, 0, int(target != 'ndef'), 1, flags]) + SUCCESS)
                        if prior == 'none':
                            wire.apdu(select(OPENPGP_AID), NOT_FOUND)
                            wire.apdu(VERSION, NOT_FOUND)
                        elif prior == 'fido':
                            wire.apdu(select(fido), FIDO_VERSION)
                            wire.apdu(VERSION, FIDO_VERSION)
                        else:
                            wire.apdu(ADMIN_QUERY, SUCCESS)
                        wire.apdu(probe(aid, p2, form), WRONG_P2 if p2 else NOT_FOUND)
                        # Wrong P2 precedes disabled-target handling. Disabled
                        # NDEF uses a separate rejection path; other disabled
                        # targets clear selection on every transport.
                        kept_admin = prior == 'admin-pin' and (p2 != 0 or target == 'ndef')
                        kept_fido = prior == 'fido' and nfc and (p2 != 0 or target == 'ndef')
                        wire.apdu(ADMIN_QUERY if kept_admin else VERSION,
                                  SUCCESS if kept_admin else FIDO_VERSION if kept_fido else NOT_FOUND)
                        wire.apdu(GET_RESPONSE, NO_RESPONSE)
                        wire.apdu(ADMIN_SELECT, SUCCESS)
                        wire.apdu(ADMIN_QUERY, SUCCESS if kept_admin else UNVERIFIED_PIN)
                        wire.apdu(ADMIN_VERIFY, SUCCESS)
                        wire.apdu(configure_features(FEATURE_MASK), SUCCESS)
                        wire.apdu(configure_ndef(True), SUCCESS)
                        wire.apdu(bytes.fromhex('0042000000'), DEFAULT_CONFIG)
                        wire.apdu(select(fido), FIDO_VERSION)
                        wire.apdu(VERSION, FIDO_VERSION)
                        cases.append(dict(id=f'E65-{transport}-{target}-{prior}-{form}-p2-{p2:02x}',
                                          transport=transport, oracle_rows=['E21', 'E23', 'E64', 'E65'],
                                          preconditions='Fresh authenticator; disable target through authenticated Admin APDUs, verify exact config, establish prior context through real SELECT. No direct policy-state injection; no physical timing claim.',
                                          steps=wire.steps))
    return dict(schema=1, scope='Disabled NDEF/FIDO/OpenPGP/PIV SELECT, P2 precedence, short/extended Case3/4, context/grant retention, response cleanup and configuration recovery.', cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(generate(), indent=2) + '\n')
