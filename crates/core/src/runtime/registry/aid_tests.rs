// SPDX-License-Identifier: Apache-2.0
use super::Selected;
use canokey_protocol::apdu::Transport;

#[test]
fn literal_selectors_reject_other_prefixes_suffixes_and_byte_changes() {
    // Wire literals deliberately do not use the production AID table.
    let cases: &[(&[u8], bool, bool)] = &[
        (
            b"\xd2\x76\x00\x00\x85\x01\x01",
            cfg!(feature = "ndef"),
            false,
        ),
        (
            b"\xa0\x00\x00\x06\x47\x2f\x00\x01",
            cfg!(feature = "ctap"),
            false,
        ),
        (b"\xf0\x00\x00\x00\x00", cfg!(feature = "admin"), false),
        (
            b"\xa0\x00\x00\x05\x27\x21\x01",
            cfg!(feature = "oath"),
            false,
        ),
        (
            b"\xd2\x76\x00\x01\x24\x01",
            cfg!(feature = "openpgp"),
            false,
        ),
        (
            b"\xa0\x00\x00\x03\x08\x00\x00\x10\x00\x01\x00",
            cfg!(feature = "piv"),
            true,
        ),
    ];
    for &(aid, enabled, piv) in cases {
        for len in 0..=aid.len() {
            let prefix = &aid[..len];
            let accepted = enabled && (len == aid.len() || (piv && matches!(len, 5 | 9)));
            assert_eq!(
                Selected::from_aid(prefix, Transport::Nfc).is_some(),
                accepted,
                "{prefix:02x?}"
            );
            if accepted {
                assert!(
                    Selected::from_aid(prefix, Transport::Nfc)
                        == Selected::from_aid(aid, Transport::Nfc)
                );
            }
            for at in 0..len {
                let mut changed = [0; 16];
                changed[..len].copy_from_slice(prefix);
                for byte in 0..=u8::MAX {
                    if byte != prefix[at] {
                        changed[at] = byte;
                        assert!(Selected::from_aid(&changed[..len], Transport::Nfc).is_none());
                    }
                }
            }
        }
        let mut suffixed = [0; 16];
        suffixed[..aid.len()].copy_from_slice(aid);
        for byte in 0..=u8::MAX {
            suffixed[aid.len()] = byte;
            assert!(Selected::from_aid(&suffixed[..aid.len() + 1], Transport::Nfc).is_none());
        }
    }
    #[cfg(feature = "ndef")]
    assert!(matches!(
        Selected::from_aid(cases[0].0, Transport::Nfc),
        Some(Selected::Ndef)
    ));
    #[cfg(feature = "ctap")]
    assert!(matches!(
        Selected::from_aid(cases[1].0, Transport::Nfc),
        Some(Selected::Ctap)
    ));
    #[cfg(feature = "admin")]
    assert!(matches!(
        Selected::from_aid(cases[2].0, Transport::Nfc),
        Some(Selected::Admin)
    ));
    #[cfg(feature = "oath")]
    assert!(matches!(
        Selected::from_aid(cases[3].0, Transport::Nfc),
        Some(Selected::Oath)
    ));
    #[cfg(feature = "openpgp")]
    assert!(matches!(
        Selected::from_aid(cases[4].0, Transport::Nfc),
        Some(Selected::OpenPgp)
    ));
    #[cfg(feature = "piv")]
    assert!(matches!(
        Selected::from_aid(cases[5].0, Transport::Nfc),
        Some(Selected::Piv)
    ));
}

#[test]
fn fido_aid_is_exact_and_bound_to_transport() {
    let usb = b"\xf0\x43\x41\x4e\x4f\x46\x49\x44";
    let nfc = b"\xa0\x00\x00\x06\x47\x2f\x00\x01";
    for (transport, allowed, denied) in [(Transport::Usb, usb, nfc), (Transport::Nfc, nfc, usb)] {
        assert_eq!(
            Selected::from_aid(allowed, transport).is_some(),
            cfg!(feature = "ctap")
        );
        assert!(Selected::from_aid(denied, transport).is_none());
        for length in 0..allowed.len() {
            assert!(Selected::from_aid(&allowed[..length], transport).is_none());
        }
        for index in 0..allowed.len() {
            for value in 0..=u8::MAX {
                if value == allowed[index] {
                    continue;
                }
                let mut changed = *allowed;
                changed[index] = value;
                assert!(Selected::from_aid(&changed, transport).is_none());
            }
        }
        let mut suffix = [0; 9];
        suffix[..8].copy_from_slice(allowed);
        assert!(Selected::from_aid(&suffix, transport).is_none());
    }
}
