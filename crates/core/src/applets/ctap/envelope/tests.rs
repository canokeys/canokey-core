// SPDX-License-Identifier: Apache-2.0
extern crate std;
use super::*;
use std::{vec, vec::Vec};

fn request(map: Option<&[u8]>, protocol: u8, full: bool) -> Vec<u8> {
    // Unknown fields before and after the parameter map must not be authenticated.
    let mut wire = vec![if map.is_some() { 0xa6 } else { 0xa5 }, 0, 0x78, 70];
    wire.extend_from_slice(&[b'x'; 70]);
    wire.extend_from_slice(&[1, 3]);
    if let Some(map) = map {
        wire.push(2);
        wire.extend_from_slice(map);
    }
    wire.extend_from_slice(&[3, protocol, 4]);
    let auth_len = if protocol == 1 {
        wire.push(0x50);
        16
    } else {
        wire.extend_from_slice(&[0x58, 32]);
        32
    };
    wire.extend_from_slice(&[0x5a; 32][..auth_len]);
    wire.push(5);
    if full {
        let len = super::super::MAX_REQUEST - 1 - wire.len() - 3;
        wire.push(0x59);
        wire.extend_from_slice(&(len as u16).to_be_bytes());
        wire.resize(super::super::MAX_REQUEST - 1, 0xa5);
    } else {
        wire.push(0x80);
    }
    wire
}

#[test]
fn in_place_authentication_preserves_exact_map_and_erases_the_source() {
    let maps: [Option<&[u8]>; 3] = [
        None,
        Some(b"\xa0"),
        Some(b"\xa3\x01\x08\x02\x81\x63\xe4\xbe\x8b\x03\xf4"),
    ];
    for command in [super::super::CONFIG, 0x0a, 0x41] {
        for map in maps {
            for protocol in [1, 2] {
                for full in [false, true] {
                    let wire = request(map, protocol, full);
                    for split in 0..=wire.len() {
                        let mut parser = Parser::new(command);
                        parser.consume(&wire[..split]);
                        parser.consume(&[]);
                        parser.consume(&wire[split..]);
                        let params = match parser.finish().unwrap() {
                            Command::Config(p) | Command::Management(p) => p,
                            _ => unreachable!(),
                        };
                        let mut expected = vec![0xff; 32];
                        expected.extend_from_slice(&[super::super::CONFIG, 3]);
                        expected.extend_from_slice(map.unwrap_or_default());
                        assert_eq!(&params.message[params.start..params.len], expected);
                        assert_eq!(
                            &params.auth[..params.auth_len],
                            &[0x5a; 32][..if protocol == 1 { 16 } else { 32 }]
                        );
                        assert!(parser.fields.params.message.iter().all(|&b| b == 0));
                        assert_eq!(parser.fields.params.auth, [0; 32]);
                        assert!(matches!(parser.finish(), Err(Status::MissingParameter)));
                        if map.is_some() {
                            // No relocation: the large leading unknown field is
                            // reflected in the authenticated map's stored offset.
                            assert!(params.start > 70);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn failed_and_oversized_envelopes_keep_first_error_and_can_be_wiped() {
    for command in [super::super::CONFIG, 0x0a, 0x41] {
        let mut parser = Parser::new(command);
        parser.consume(b"\xa2\x01\x03");
        parser.consume(b"\x04\x41x"); // Invalid auth length.
        parser.consume(&[0xff; super::super::MAX_REQUEST]);
        assert!(matches!(parser.finish(), Err(Status::InvalidParameter)));
        parser.clear(&canokey_ports::default_memory());
        assert!(parser.fields.params.message.iter().all(|&b| b == 0));
        assert_eq!(parser.fields.params.auth, [0; 32]);

        let mut wire = request(Some(b"\xa0"), 2, true);
        wire.push(0);
        for split in [0, 1, wire.len() - 1, wire.len()] {
            let mut parser = Parser::new(command);
            parser.consume(&wire[..split]);
            parser.consume(&wire[split..]);
            // Config preserves its legacy bare-command status when the first
            // fragment is rejected before any bytes are accepted.
            let expected = if command == super::super::CONFIG && (split == 0 || split == wire.len())
            {
                Status::UnhandledRequest
            } else {
                Status::InvalidCbor
            };
            assert!(matches!(parser.finish(), Err(error) if error == expected));
        }
    }
}
