// SPDX-License-Identifier: Apache-2.0
use super::{AppletState, Registry, Router, Selected, Sw};
use canokey_protocol::apdu::{Header, Transport};

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

#[cfg_attr(not(has_applet), allow(dead_code))]
fn check_limits(state: AppletState, aid: &[u8], cases: &[(u8, u8, u8, u8, Result<u32, Sw>)]) {
    let mut registry = Registry::new();
    assert!(Selected::from_aid(aid, Transport::Nfc) == Some(state.selected()));
    registry.applet = state;
    for &(cla, ins, p1, p2, expected) in cases {
        assert_eq!(
            registry.command_limit(Header { cla, ins, p1, p2 }),
            expected
        );
    }
}

#[test]
fn selected_applets_keep_their_command_limits() {
    #[cfg(feature = "ndef")]
    check_limits(
        AppletState::Ndef(crate::applets::ndef::Applet::new()),
        b"\xd2\x76\x00\x00\x85\x01\x01",
        &[(0xff, 0xd6, 0, 0, Ok(1024))],
    );
    #[cfg(feature = "admin")]
    check_limits(
        AppletState::Admin,
        b"\xf0\x00\x00\x00\x00",
        &[
            (
                0x00,
                0x02,
                0,
                0,
                Ok(if cfg!(feature = "ctap") { 1152 } else { 256 }),
            ),
            (
                0x10,
                0x02,
                0,
                0,
                if cfg!(feature = "ctap") {
                    Ok(1152)
                } else {
                    Err(Sw::CLA_NOT_SUPPORTED)
                },
            ),
            (0x10, 0x45, 0, 0, Ok(256)),
            (0x10, 0x20, 0, 0, Err(Sw::CLA_NOT_SUPPORTED)),
        ],
    );
    #[cfg(feature = "ctap")]
    check_limits(
        AppletState::Ctap,
        b"\xa0\x00\x00\x06\x47\x2f\x00\x01",
        &[
            (0x90, 0x10, 0, 0, Ok(1296)),
            (0x10, 0x10, 0, 0, Err(Sw::CLA_NOT_SUPPORTED)),
        ],
    );
    #[cfg(feature = "oath")]
    check_limits(
        AppletState::Oath(crate::applets::oath::protocol::Oath::new()),
        b"\xa0\x00\x00\x05\x27\x21\x01",
        &[(0x10, 0xa2, 0, 0, Ok(288))],
    );
    #[cfg(feature = "openpgp")]
    check_limits(
        AppletState::OpenPgp(crate::applets::openpgp::protocol::OpenPgp::new()),
        b"\xd2\x76\x00\x01\x24\x01",
        &[
            (0x00, 0x20, 0, 0, Ok(513)),
            (0x10, 0x20, 0, 0, Err(Sw::CLA_NOT_SUPPORTED)),
            (0x10, 0xda, 0x7f, 0x21, Ok(1152)),
            (0x10, 0xdb, 0, 0, Ok(1400)),
        ],
    );
    #[cfg(feature = "piv")]
    for aid in [
        b"\xa0\x00\x00\x03\x08\x00\x00\x10\x00\x01\x00".as_slice(),
        b"\xa0\x00\x00\x03\x08\x00\x00\x10\x00",
        b"\xa0\x00\x00\x03\x08",
    ] {
        check_limits(
            AppletState::Piv(crate::applets::piv::Piv::new()),
            aid,
            &[
                (0x00, 0x20, 0, 0, Ok(513)),
                (0x10, 0x20, 0, 0, Err(Sw::CLA_NOT_SUPPORTED)),
                (0x10, 0x87, 0, 0, Ok(65535)),
                (0x10, 0xdb, 0, 0, Ok(6573)),
                (0x10, 0xfe, 0, 0, Ok(1400)),
            ],
        );
    }
}
