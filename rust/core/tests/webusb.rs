// SPDX-License-Identifier: Apache-2.0
use canokey_protocol::usb::Setup;
use canokey_rust_core::runtime::{
    usb::webusb::Descriptor,
    webusb::{Request, Transport},
};
fn setup(kind: u8, request: u8, value: u16, index: u16, length: u16) -> Setup {
    Setup {
        kind,
        request,
        value,
        index,
        length,
    }
}
#[test]
fn discovery_matches_native_bytes_for_every_packet_boundary() {
    let fixtures = [
        (Descriptor::Bos, include_str!("vectors/webusb-bos.hex")),
        (Descriptor::Url, include_str!("vectors/webusb-url.hex")),
        (
            Descriptor::Microsoft { interface: 1 },
            include_str!("vectors/webusb-ms_os_20.hex"),
        ),
    ];
    for (descriptor, fixture) in fixtures {
        let bytes: Vec<u8> = fixture
            .trim()
            .as_bytes()
            .chunks(2)
            .map(|v| u8::from_str_radix(core::str::from_utf8(v).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(descriptor.len(), bytes.len());
        for width in 1..=64 {
            let mut actual = Vec::new();
            loop {
                let mut packet = [0xaa; 64];
                let n = descriptor.read(actual.len(), &mut packet[..width]);
                assert!(packet[n..].iter().all(|&v| v == 0xaa));
                if n == 0 {
                    break;
                }
                actual.extend_from_slice(&packet[..n]);
            }
            assert_eq!(actual, bytes);
        }
    }
    for interface in 0..4 {
        let descriptor = Descriptor::Microsoft { interface };
        for offset in 0..=23 {
            let mut packet = [0; 32];
            let n = descriptor.read(offset, &mut packet);
            if offset <= 22 && offset + n > 22 {
                assert_eq!(packet[22 - offset], interface);
            }
        }
    }
}
#[test]
fn vendor_requests_validate_direction_recipient_and_index() {
    assert_eq!(
        Descriptor::request(setup(0xc0, 1, 1, 2, 255), 1),
        Some(Descriptor::Url)
    );
    assert_eq!(
        Descriptor::request(setup(0xc0, 2, 0, 7, 178), 0),
        Some(Descriptor::Microsoft { interface: 0 })
    );
    assert_eq!(
        Descriptor::request(setup(0x80, 6, 0x0f00, 0, 5), 1),
        Some(Descriptor::Bos)
    );
    for s in [
        setup(0x40, 1, 1, 2, 23),
        setup(0xc1, 1, 1, 2, 23),
        setup(0xc0, 1, 0, 2, 23),
        setup(0xc0, 2, 0, 8, 178),
    ] {
        assert_eq!(Descriptor::request(s, 1), None);
    }
    for interface in 0..4 {
        assert_eq!(
            Request::decode(setup(0x41, 0, 0, interface, 261), interface as u8),
            Some(Request::Command(261))
        );
        assert_eq!(
            Request::decode(setup(0xc1, 1, 0, interface, 65535), interface as u8),
            Some(Request::Response(65535))
        );
        assert_eq!(
            Request::decode(setup(0xc1, 2, 0, interface, 1), interface as u8),
            Some(Request::Status)
        );
        for s in [
            setup(0xc1, 0, 0, interface, 10),
            setup(0x41, 0, 0, interface, 262),
            setup(0x41, 0, 1, interface, 10),
            setup(0x41, 0, 0, interface + 1, 10),
            setup(0xc1, 2, 0, interface, 2),
        ] {
            assert_eq!(Request::decode(s, interface as u8), None);
        }
    }
}
#[test]
fn all_short_apdu_lengths_and_response_completion_hold_session() {
    for length in 0..=261 {
        let mut t = Transport::new();
        assert_eq!(t.status(), 255);
        assert!(!t.command(length, 0, false));
        assert!(t.command(length, 0, true));
        let mut received = 0;
        while received < length {
            let n = (length - received).min(16);
            assert_eq!(t.receive(n, 1), Some(received));
            received += n;
        }
        assert_eq!(t.status(), 1);
        assert_eq!(t.execute(), Some(length));
        assert_eq!(t.execute(), None);
        assert!(!t.command(5, 2, true));
        assert!(t.finish(258, 3));
        assert_eq!(t.status(), 0);
        assert_eq!(t.response(17, 4), Some(17));
        assert_eq!(t.status(), 2);
        assert!(!t.expired(10000));
        assert_eq!(t.response(17, 5), None);
        t.completed(u32::MAX - 1000);
        assert_eq!(t.status(), 4);
        assert!(!t.expired(998));
        assert!(t.expired(999));
        t.keepalive(1000);
        assert!(!t.expired(2999));
        assert!(t.expired(3000));
        assert!(t.command(5, 3000, true));
    }
}
#[test]
fn reset_during_execution_does_not_reassign_live_workspace() {
    let mut t = Transport::new();
    assert!(t.command(5, 0, true));
    assert_eq!(t.receive(5, 1), Some(0));
    assert_eq!(t.execute(), Some(5));
    for _ in 0..2 {
        t.reset();
    }
    assert!(t.busy());
    assert!(!t.command(5, 2, true));
    assert!(!t.finish(2, 3));
    assert!(!t.busy());
    assert_eq!(t.response(2, 4), None);
    assert!(t.command(5, 5, true));
}
#[test]
fn incomplete_and_malformed_packets_never_queue_execution() {
    for n in [0, 1, 15, 17, 32] {
        let mut t = Transport::new();
        assert!(t.command(32, 0, true));
        assert_eq!(t.receive(n, 1), None);
        assert_eq!(t.execute(), None);
        assert!(!t.expired(3000));
        t.reset();
        assert!(!t.busy());
    }
    let mut t = Transport::new();
    assert!(t.command(17, 0, true));
    assert_eq!(t.receive(16, 1), Some(0));
    assert_eq!(t.receive(2, 2), None);
    assert_eq!(t.receive(1, 3), Some(16));
    assert_eq!(t.execute(), Some(17));
    assert!(!t.finish(259, 4));
    assert!(!t.busy());
}

#[test]
fn webusb_composition_preserves_native_interface_order() {
    use canokey_rust_core::runtime::usb::{Device, Reply, descriptors::Interfaces};
    for hid in [false, true] {
        for keyboard in [false, true] {
            let interfaces = Interfaces {
                hid,
                keyboard,
                webusb: true,
            };
            let mut bytes = [0; 160];
            let length = interfaces.configuration(&mut bytes);
            assert_eq!(length, 95 + 32 * (hid as usize + keyboard as usize));
            let mut seen = 0;
            let mut offset = 9;
            while offset < length {
                if bytes[offset + 1] == 4 {
                    assert_eq!(bytes[offset + 2], seen);
                    if seen == interfaces.webusb() {
                        assert_eq!(
                            &bytes[offset..offset + 9],
                            &[9, 4, seen, 0, 0, 255, 255, 255, 0x12]
                        );
                    }
                    seen += 1;
                }
                offset += bytes[offset] as usize;
            }
            assert_eq!(seen, interfaces.count());
            assert_eq!(interfaces.ccid(), interfaces.webusb() + 1);
            let mut d = Device::new(interfaces);
            assert_eq!(
                d.setup(setup(0x80, 6, 0x100, 0, 18), false, &mut bytes),
                Reply::Data(18)
            );
            assert_eq!(&bytes[2..4], &[0x10, 2]);
            assert_eq!(
                d.setup(setup(0x80, 6, 0x312, 0x409, 255), false, &mut bytes),
                Reply::Data(14)
            );
        }
    }
}
