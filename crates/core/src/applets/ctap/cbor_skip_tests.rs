// SPDX-License-Identifier: Apache-2.0
extern crate std;
use super::*;
use canokey_protocol::cbor::{Encoder, Event};
use std::vec::Vec;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/c312-cbor-skip/vectors.rs"
));

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/c312-parser/vectors.rs"
));

// Unknown positive integer and short text labels precede/follow recognized
// fields so skipping must resume the enclosing schema at its original depth.
const UNKNOWN_LABEL: u8 = 127;
const UNKNOWN_MEMBER: &str = "?";

fn encoded(write: impl FnOnce(&mut Encoder<&mut [u8]>)) -> Vec<u8> {
    let mut buffer = [0; MAX_REQUEST];
    let mut e = Encoder::new(&mut buffer[..]);
    write(&mut e);
    e.finish().unwrap();
    let n = MAX_REQUEST - e.writer().len();
    buffer[..n].to_vec()
}

fn credential(value: &[u8], location: u8, make: bool) -> Vec<u8> {
    encoded(|e| {
        e.u8(if make { MAKE_CREDENTIAL } else { GET_ASSERTION });
        if !make {
            e.map(3)
                .u8(1)
                .str("example.com")
                .u8(2)
                .bytes(&[0x42; 32])
                .u8(UNKNOWN_LABEL)
                .encoded(value);
            return;
        }
        e.map(if matches!(location, 0 | 4..=8) { 5 } else { 4 });
        e.u8(1).bytes(&[0x42; 32]);
        e.u8(2).map(if location == 1 { 2 } else { 1 });
        if location == 1 {
            e.str(UNKNOWN_MEMBER).encoded(value);
        }
        e.str("id").str("example.com");
        e.u8(3).map(if location == 2 { 2 } else { 1 });
        if location == 2 {
            e.str(UNKNOWN_MEMBER).encoded(value);
        }
        e.str("id").bytes(&[0x24]);
        e.u8(4).array(1).map(if location == 3 { 3 } else { 2 });
        if location == 3 {
            e.str(UNKNOWN_MEMBER).encoded(value);
        }
        e.str("alg").i32(-7).str("type").str("public-key");
        match location {
            0 => {
                e.u8(UNKNOWN_LABEL).encoded(value);
            }
            4 => {
                e.u8(5)
                    .array(1)
                    .map(3)
                    .str(UNKNOWN_MEMBER)
                    .encoded(value)
                    .str("id")
                    .bytes(&[0x24; credential::ID_BYTES])
                    .str("type")
                    .str("public-key");
            }
            5 => {
                e.u8(6).map(1).str(UNKNOWN_MEMBER).encoded(value);
            }
            6 => {
                e.u8(7)
                    .map(2)
                    .str(UNKNOWN_MEMBER)
                    .encoded(value)
                    .str("rk")
                    .bool(false);
            }
            7 | 8 => {
                e.u8(6)
                    .map(2)
                    .str("hmac-secret")
                    .bool(true)
                    .str("hmac-secret-mc")
                    .encoded(&hmac(value, location == 8));
            }
            _ => (),
        }
    })
}

fn envelope(value: &[u8], command: u8, location: u8) -> Vec<u8> {
    encoded(|e| {
        e.encoded(&[command]).map(2).u8(1).u8(3);
        if location == 0 {
            e.u8(UNKNOWN_LABEL).encoded(value);
        } else {
            e.u8(2).map(1);
            match location {
                1 => {
                    e.u8(UNKNOWN_LABEL).encoded(value);
                }
                2 => {
                    e.u8(2)
                        .map(3)
                        .str(UNKNOWN_MEMBER)
                        .encoded(value)
                        .str("id")
                        .bytes(&[0x24; credential::ID_BYTES])
                        .str("type")
                        .str("public-key");
                }
                3 => {
                    e.u8(3)
                        .map(2)
                        .str(UNKNOWN_MEMBER)
                        .encoded(value)
                        .str("id")
                        .bytes(&[0x24]);
                }
                _ => unreachable!(),
            }
        }
    })
}

fn finish(request: &mut Request) -> Result<(), Status> {
    match request.finish()? {
        Command::Management(p) => p.management.fields(&p.message).map(|_| ()),
        _ => Ok(()),
    }
}

#[test]
fn request_status_matches_executed_c_parsers_at_every_fragment_boundary() {
    for &(id, wire, expected) in C312_PARSER_VECTORS {
        for split in 0..=wire.len() {
            let mut request = Request::new();
            request.consume(&wire[..split]);
            request.consume(&[]);
            request.consume(&wire[split..]);
            let actual = finish(&mut request).err().map_or(0, |status| status as u8);
            assert_eq!(actual, expected, "{id} split={split}");
        }
        let mut request = Request::new();
        for byte in wire {
            request.consume(core::slice::from_ref(byte));
        }
        let actual = finish(&mut request).err().map_or(0, |status| status as u8);
        assert_eq!(actual, expected, "{id} byte-by-byte");
    }
}

fn check(wire: &[u8], accepted: bool) {
    check_result(
        wire,
        if accepted {
            Ok(())
        } else {
            Err(Status::InvalidCbor)
        },
    );
}

fn check_result(wire: &[u8], expected: Result<(), Status>) {
    for split in 0..=wire.len() {
        let mut request = Request::new();
        request.consume(&wire[..split]);
        request.consume(&[]);
        request.consume(&wire[split..]);
        assert_eq!(
            finish(&mut request),
            expected,
            "command={} split={split} wire={wire:?}",
            wire[0],
        );
    }
    let mut request = Request::new();
    for byte in wire {
        request.consume(core::slice::from_ref(byte));
    }
    assert_eq!(finish(&mut request), expected);
}

#[test]
fn unknown_skip_matches_pinned_c_at_every_fragment_boundary() {
    for &(value, accepted) in C312_UNKNOWN_VALUES {
        for command in [CLIENT_PIN, LARGE_BLOBS] {
            let wire = encoded(|e| {
                e.u8(command);
                if command == CLIENT_PIN {
                    e.map(2).u8(2).u8(wire::pin_protocol::GET_RETRIES);
                } else {
                    e.map(3).u8(1).u8(1).u8(3).u8(0);
                }
                e.u8(UNKNOWN_LABEL).encoded(value);
            });
            check(&wire, accepted);
        }
        check(&credential(value, 0, false), accepted);
        for location in 0..=8 {
            let wire = credential(value, location, true);
            if location == 6 || (location == 1 && value[0] >> 5 != 3) {
                // RP/options impose value types before unknown-value skipping.
                check_result(&wire, Err(Status::UnexpectedType));
            } else {
                check(&wire, accepted);
            }
        }
        for command in [CONFIG, CREDENTIAL_MANAGEMENT, LEGACY_CREDENTIAL_MANAGEMENT] {
            for location in 0..=if command == CONFIG { 1 } else { 3 } {
                check(&envelope(value, command, location), accepted);
            }
        }
    }
}

fn hmac(value: &[u8], in_agreement: bool) -> Vec<u8> {
    encoded(|e| {
        e.map(if in_agreement { 4 } else { 5 })
            .u8(1)
            .map(if in_agreement { 6 } else { 5 });
        e.u8(1).u8(2).u8(3).i32(-25);
        if in_agreement {
            e.u8(UNKNOWN_LABEL).encoded(value);
        }
        e.i32(-1)
            .u8(1)
            .i32(-2)
            .bytes(&[0x42; 32])
            .i32(-3)
            .bytes(&[0x24; 32]);
        e.u8(2)
            .bytes(&[0x42; 32])
            .u8(3)
            .bytes(&[0x24; 16])
            .u8(4)
            .u8(1);
        if !in_agreement {
            e.u8(UNKNOWN_LABEL).encoded(value);
        }
    })
}

#[test]
fn nested_agreement_and_hmac_skip_have_independent_budgets() {
    for &(value, accepted) in C312_UNKNOWN_VALUES {
        for in_agreement in [false, true] {
            let wire = hmac(value, in_agreement);
            for split in 0..=wire.len() {
                let mut decoder = request_decoder::RequestDecoder::new();
                let mut parser = hmac_secret::Parser::new();
                let mut started = false;
                let mut complete = false;
                let mut events = |event: &Event<'_>, _| {
                    if !started {
                        assert!(matches!(event, Event::Map(_)));
                        started = true;
                    } else {
                        complete = parser.event(event)?;
                    }
                    Ok(())
                };
                decoder.consume(&wire[..split], &mut events);
                decoder.consume(&wire[split..], &mut events);
                assert_eq!(decoder.finish().is_ok() && complete, accepted);
            }
        }
    }
}

#[test]
fn abandoned_unknown_values_cannot_contaminate_the_next_request() {
    // A map/array value containing a long UTF-8 string is provisional until
    // finish; abandonment must discard its skip state and owned credentials.
    let value = encoded(|e| {
        e.array(1)
            .map(1)
            .str("x")
            .str("界界界界界界界界界界界界界界界界界界界界界界界界");
    });
    let wire = credential(&value, 1, true);
    for split in 1..wire.len() {
        let mut request = Request::new();
        request.consume(&wire[..split]);
        request.clear(&canokey_ports::default_memory());
        request.consume(&[GET_INFO]);
        assert!(matches!(request.finish(), Ok(Command::GetInfo)));
    }
}

#[test]
fn truncated_unknown_payloads_preserve_the_first_cbor_error() {
    let value = encoded(|e| {
        e.array(1).bytes(&[0x24; 256]);
    });
    for wire in [
        credential(&value, 0, true),
        envelope(&value, CONFIG, 1),
        envelope(&value, CREDENTIAL_MANAGEMENT, 2),
    ] {
        check(&wire[..wire.len() - 1], false);
    }
    // A missing body retains the legacy CONFIG result. A malformed nonempty
    // body has a CBOR error even when rejected in the first consume call.
    let mut request = Request::new();
    request.consume(&[CONFIG]);
    assert_eq!(finish(&mut request), Err(Status::UnhandledRequest));
    check(&[CONFIG, 0xff], false);
}
