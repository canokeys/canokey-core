// SPDX-License-Identifier: Apache-2.0
//! Product capacities and direct Command publication for the shared parser.
use super::{Command, Status};
pub(super) use canokey_ctap::request::credential::MAX_LIST;
pub type Parameters = canokey_ctap::request::credential::Parameters<{ super::MAX_REQUEST / 20 }>;
pub struct Parser(
    canokey_ctap::request::credential::Parser<
        Status,
        { super::MAX_REQUEST / 20 },
        { (super::MAX_REQUEST - 1) as u16 },
    >,
);
impl Parser {
    pub const fn new(make: bool) -> Self {
        Self(canokey_ctap::request::credential::Parser::new(make))
    }
    pub fn consume(&mut self, bytes: &[u8]) {
        self.0.consume(bytes);
    }
    pub(crate) fn clear(&mut self, memory: &(impl crate::ports::Memory + ?Sized)) {
        self.0.clear(memory);
    }
    #[inline(never)]
    pub fn finish(&mut self) -> Result<Command, Status> {
        self.0
            .finish_with(&canokey_ports::default_memory(), Command::Credential)
    }
}

#[cfg(test)]
mod option_tests {
    use super::*;
    mod cases {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../ctap/tests/fixtures/credential_options.rs"
        ));
    }
    #[test]
    fn command_options_match_shared_cases_at_every_fragment_boundary() {
        for (make, bytes, expected) in cases::cases() {
            for split in 0..=bytes.len() {
                let mut parser = Parser::new(make);
                parser.consume(&bytes[..split]);
                parser.consume(&bytes[split..]);
                assert_eq!(
                    parser.finish().err().map(|status| status as u8),
                    expected,
                    "make={make} split={split} bytes={bytes:?}"
                );
            }
        }
    }

    mod label_cases {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../ctap/tests/fixtures/credential_labels.rs"
        ));
    }
    #[test]
    fn integer_labels_and_entity_fields_match_shared_cases_at_every_split() {
        for (make, bytes, expected) in label_cases::cases() {
            for split in 0..=bytes.len() {
                let mut parser = Parser::new(make);
                parser.consume(&bytes[..split]);
                parser.consume(&bytes[split..]);
                assert_eq!(
                    parser.finish().err().map(|status| status as u8),
                    expected,
                    "make={make} split={split} bytes={bytes:02x?}"
                );
            }
        }
    }
    mod cbor_cases {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../ctap/tests/fixtures/credential_cbor.rs"
        ));
    }
    #[test]
    fn cbor_order_and_unknown_values_match_shared_cases_at_every_split() {
        for (make, bytes, expected) in cbor_cases::cases() {
            for split in 0..=bytes.len() {
                let mut parser = Parser::new(make);
                parser.consume(&bytes[..split]);
                parser.consume(&bytes[split..]);
                assert_eq!(
                    parser.finish().err().map(|status| status as u8),
                    expected,
                    "make={make} split={split} bytes={bytes:02x?}"
                );
            }
        }
    }
}
