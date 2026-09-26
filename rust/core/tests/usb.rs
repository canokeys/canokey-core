// SPDX-License-Identifier: Apache-2.0
use canokey_protocol::usb::Setup;
use canokey_rust_core::runtime::usb::{ControlIn, Device, Reply, descriptors::Interfaces};
fn request(kind: u8, request: u8, value: u16, index: u16, length: u16) -> Setup {
    Setup {
        kind,
        request,
        value,
        index,
        length,
    }
}
#[test]
fn setup_literal_little_endian_and_exact_length() {
    assert_eq!(
        Setup::decode(&[0x81, 6, 0, 0x22, 2, 0, 0xff, 1]),
        Some(request(0x81, 6, 0x2200, 2, 511))
    );
    for n in 0..16 {
        if n != 8 {
            assert!(Setup::decode(&[0; 16][..n]).is_none());
        }
    }
}
#[test]
fn descriptors_match_interfaces_and_endpoint_directions() {
    for hid in [false, true] {
        for keyboard in [false, true] {
            let interfaces = Interfaces { hid, keyboard };
            let mut out = [0; 160];
            let n = interfaces.configuration(&mut out);
            assert_eq!(n, 86 + 32 * (hid as usize + keyboard as usize));
            assert_eq!(u16::from_le_bytes([out[2], out[3]]) as usize, n);
            assert_eq!(out[4], interfaces.count());
            let mut offset = 0;
            let mut next_interface = 0;
            let mut eps = 0u8;
            while offset < n {
                let d = &out[offset..offset + out[offset] as usize];
                if d[1] == 4 {
                    assert_eq!(d[2], next_interface);
                    next_interface += 1;
                }
                if d[1] == 5 {
                    assert!(interfaces.endpoint(d[2] as u16));
                    let bit = 1 << ((d[2] & 3) * 2 + (d[2] >> 7));
                    assert_eq!(eps & bit, 0);
                    eps |= bit;
                    assert_eq!(d[4], if d[2] & 3 == 1 { 8 } else { 64 });
                }
                offset += d.len();
            }
            assert_eq!(offset, n);
            assert_eq!(next_interface, interfaces.count());
            assert_eq!(
                eps,
                0xc0 | if hid { 0x30 } else { 0 } | if keyboard { 0x0c } else { 0 }
            );
            for invalid in [4, 0x10, 0x84, 0x100, 0x180, 0xffff] {
                assert!(!interfaces.endpoint(invalid));
            }
        }
    }
}
#[test]
fn standard_request_validation_and_state() {
    let mut d = Device::new(Interfaces {
        hid: true,
        keyboard: true,
    });
    let mut b = [0; 160];
    assert_eq!(d.setup(request(0, 9, 1, 0, 0), false, &mut b), Reply::Stall);
    assert_eq!(
        d.setup(request(0, 5, 7, 0, 0), false, &mut b),
        Reply::Address(7)
    );
    assert_eq!(d.address, 0); // only the status acknowledgement commits address
    d.address = 7;
    assert_eq!(
        d.setup(request(0, 9, 1, 0, 0), false, &mut b),
        Reply::Configure(true)
    );
    d.configured = true;
    for s in [
        request(0, 5, 8, 0, 0),
        request(0x80, 9, 1, 0, 0),
        request(0, 9, 2, 0, 0),
        request(0, 9, 1, 1, 0),
        request(0, 9, 1, 0, 1),
        request(2, 3, 0, 0, 0),
        request(2, 3, 0, 0x183, 0),
        request(0, 3, 1, 0, 0),
        request(0x81, 10, 0, 3, 1),
        request(1, 11, 1, 0, 0),
    ] {
        assert_eq!(d.setup(s, false, &mut b), Reply::Stall, "{s:?}");
    }
    assert_eq!(
        d.setup(request(0x82, 0, 0, 0x83, 2), true, &mut b),
        Reply::Data(2)
    );
    assert_eq!(&b[..2], &[1, 0]);
    assert_eq!(
        d.setup(request(2, 1, 0, 0x83, 0), true, &mut b),
        Reply::Halt(0x83, false)
    );
    assert_eq!(
        d.setup(request(0x80, 8, 0, 0, 1), false, &mut b),
        Reply::Data(1)
    );
    assert_eq!(b[0], 1);
    d.reset();
    assert!(!d.configured);
    assert_eq!(d.address, 0);
}
#[test]
fn hid_reports_idle_leds_and_rejected_class_requests() {
    let mut d = Device::new(Interfaces {
        hid: true,
        keyboard: true,
    });
    d.address = 1;
    d.configured = true;
    let mut b = [0; 160];
    assert_eq!(
        d.setup(request(0x81, 6, 0x2200, 0, 255), false, &mut b),
        Reply::Data(34)
    );
    assert_eq!(
        d.setup(request(0x81, 6, 0x2200, 2, 255), false, &mut b),
        Reply::Data(87)
    );
    assert_eq!(
        d.setup(request(0x21, 10, 0x0701, 2, 0), false, &mut b),
        Reply::Status
    );
    assert_eq!(
        d.setup(request(0xa1, 2, 1, 2, 1), false, &mut b),
        Reply::Data(1)
    );
    assert_eq!(b[0], 7);
    assert_eq!(
        d.setup(request(0x21, 9, 0x0201, 2, 2), false, &mut b),
        Reply::ReceiveLed
    );
    for s in [
        request(0x21, 9, 0x0201, 0, 2),
        request(0x81, 6, 0x2201, 0, 255),
        request(0xa1, 10, 0, 0, 0),
        request(0x21, 10, 1, 0, 0),
        request(0xa1, 2, 0, 1, 1),
        request(0x21, 11, 0, 2, 0),
    ] {
        assert_eq!(d.setup(s, false, &mut b), Reply::Stall);
    }
}
#[test]
fn control_in_every_length_and_short_termination() {
    for available in 0..=160 {
        for requested in [0, 1, 8, 15, 16, 17, 31, 32, 64, 128, 255, 65535] {
            let mut input = ControlIn::new();
            input.begin(available, requested);
            let n = available.min(requested as usize);
            let mut actual = 0;
            let mut zeros = 0;
            while let Some((offset, len)) = input.next_packet() {
                assert_eq!(offset, actual);
                assert!(len <= 16);
                actual += len;
                if len == 0 {
                    zeros += 1;
                }
            }
            assert_eq!(actual, n);
            assert_eq!(zeros, usize::from(n < requested as usize && n % 16 == 0));
        }
    }
}
#[test]
fn configurations_match_legacy_wire_fixtures() {
    // Captured from the previous production C descriptor callbacks, separately
    // compiled for each HID/keyboard combination before removing that source.
    let fixtures = [
        include_str!("vectors/usb-config-00.hex"),
        include_str!("vectors/usb-config-01.hex"),
        include_str!("vectors/usb-config-10.hex"),
        include_str!("vectors/usb-config-11.hex"),
    ];
    for (i, hex) in fixtures.iter().enumerate() {
        let interfaces = Interfaces {
            hid: i & 2 != 0,
            keyboard: i & 1 != 0,
        };
        let mut out = [0; 160];
        let n = interfaces.configuration(&mut out);
        let expected: Vec<u8> = hex
            .trim()
            .as_bytes()
            .chunks(2)
            .map(|x| u8::from_str_radix(core::str::from_utf8(x).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(&out[..n], &expected);
    }
}
