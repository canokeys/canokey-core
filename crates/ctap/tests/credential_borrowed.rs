// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::{
    extensions,
    request::{
        borrowed::Reader,
        credential::{self, borrowed},
    },
    status::Status,
};
struct Profile;
impl<'a> borrowed::Profile<'a> for Profile {
    type Reader = Reader<'a, Status, 2047>;
    type Extensions = extensions::borrowed::Input<'a>;
    type Algorithm = i32;
    fn extensions(reader: &mut Self::Reader, make: bool) -> Result<Self::Extensions, Status> {
        Self::Extensions::read(reader, make)
    }
    fn algorithm(kind: &str, algorithm: i64, _: bool) -> Option<i32> {
        (kind == "public-key" && matches!(algorithm, -7 | -8)).then_some(algorithm as i32)
    }
}
mod labels {
    include!("fixtures/credential_labels.rs");
}
mod options {
    include!("fixtures/credential_options.rs");
}
mod cbor {
    include!("fixtures/credential_cbor.rs");
}
fn streamed(bytes: &[u8], make: bool) -> Result<(), Status> {
    let mut parser = credential::Parser::<Status, 102, 2047>::new(make);
    parser.consume(bytes);
    parser.finish_with(&canokey_ports::default_memory(), |_| ())
}
fn borrowed(bytes: &[u8], make: bool) -> Result<(), Status> {
    borrowed::Request::<Profile>::decode(bytes, make).map(|_| ())
}
fn cases() -> impl Iterator<Item = (bool, Vec<u8>, Option<u8>)> {
    labels::cases()
        .into_iter()
        .chain(options::cases())
        .chain(cbor::cases())
}
#[test]
fn actual_shared_consumers_follow_the_same_cases() {
    for (make, bytes, expected) in cases() {
        for (consumer, result) in [
            ("streamed", streamed(&bytes, make)),
            ("borrowed", borrowed(&bytes, make)),
        ] {
            assert_eq!(
                result.err().map(|status| status as u8),
                expected,
                "{consumer} make={make} bytes={bytes:02x?}"
            );
        }
    }
}
#[test]
fn truncated_requests_preserve_the_first_canokey_error() {
    for (make, bytes, _) in cases() {
        for length in 0..bytes.len() {
            assert_eq!(
                borrowed(&bytes[..length], make),
                streamed(&bytes[..length], make),
                "make={make} length={length} bytes={bytes:02x?}"
            );
        }
    }
}
#[test]
fn mutations_follow_the_current_canokey_consumer() {
    let mut compared = 0;
    for (make, bytes, expected) in cases() {
        if expected.is_some() {
            continue;
        }
        let mut mutated = bytes.clone();
        for offset in 0..bytes.len() {
            for value in [
                0x00, 0x01, 0x17, 0x18, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xf4, 0xf5, 0xf6, 0xff,
            ] {
                mutated[offset] = value;
                assert_eq!(
                    borrowed(&mutated, make),
                    streamed(&mutated, make),
                    "make={make} offset={offset} bytes={mutated:02x?}"
                );
                compared += 1;
            }
            mutated[offset] = bytes[offset];
        }
    }
    assert!(
        compared > 10_000,
        "only {compared} schema mutations exercised"
    );
    println!("Current CanoKey schema oracle: {compared} mutations");
}
#[test]
fn shared_framing_and_unknown_skip_have_separate_container_budgets() {
    for depth in 0..=9 {
        let mut bytes = vec![0x81; depth];
        bytes.push(0x00);
        assert_eq!(Reader::<Status>::validate(&bytes).is_ok(), depth <= 8);
        let mut reader = Reader::<Status>::new(&bytes);
        assert_eq!(reader.skip_unknown().is_ok(), depth <= 4);
    }
    let bytes = b"\x82\xa2\x02\x00\x01\x00\xf5";
    let mut reader = Reader::<Status>::new(bytes);
    assert_eq!(reader.array().unwrap(), 2);
    assert_eq!(reader.item().unwrap(), &bytes[1..6]);
    assert!(reader.boolean().unwrap());
    assert!(reader.done());
    assert_eq!(
        Reader::<Status>::validate(&bytes[1..]),
        Err(Status::InvalidCbor)
    );
}
