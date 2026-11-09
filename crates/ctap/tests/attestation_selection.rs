// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::provision::{self, PRIVATE_KEY_BYTES, Selection, SelectionSource};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Error {
    Missing,
    Io,
    Malformed,
}
struct Source {
    certificate: Result<usize, Error>,
    key: Result<(), Error>,
    events: Vec<&'static str>,
}
impl SelectionSource for Source {
    type Error = Error;
    fn certificate_length(&mut self) -> Result<usize, Error> {
        self.events.push("certificate");
        self.certificate
    }
    fn key(&mut self, output: &mut [u8; PRIVATE_KEY_BYTES]) -> Result<(), Error> {
        self.events.push("key");
        // A partially supplied key must remain visible to the caller's wipe
        // even when the read fails or self attestation is selected afterward.
        output.fill(0x37);
        self.key
    }
    fn missing(error: &Error) -> bool {
        *error == Error::Missing
    }
    fn invalid() -> Error {
        Error::Malformed
    }
}
#[test]
fn missing_either_checks_both_materials_before_fallback_or_error() {
    for (certificate, key, expected) in [
        (Ok(1), Ok(()), Ok(1)),
        (Ok(1024), Ok(()), Ok(1024)),
        (Ok(0), Ok(()), Err(Error::Malformed)),
        (Ok(1025), Ok(()), Err(Error::Malformed)),
        (Ok(usize::MAX), Ok(()), Err(Error::Malformed)),
        (Err(Error::Missing), Ok(()), Ok(0)),
        (Ok(1), Err(Error::Missing), Ok(0)),
        (Ok(0), Err(Error::Missing), Ok(0)),
        (Ok(usize::MAX), Err(Error::Missing), Ok(0)),
        (Err(Error::Missing), Err(Error::Missing), Ok(0)),
        (Err(Error::Io), Ok(()), Err(Error::Malformed)),
        (Ok(1), Err(Error::Io), Err(Error::Malformed)),
        (Err(Error::Io), Err(Error::Missing), Err(Error::Malformed)),
        (Err(Error::Missing), Err(Error::Io), Err(Error::Malformed)),
        (
            Err(Error::Missing),
            Err(Error::Malformed),
            Err(Error::Malformed),
        ),
    ] {
        let mut source = Source {
            certificate,
            key,
            events: vec![],
        };
        let mut guarded = [0xa5; PRIVATE_KEY_BYTES + 2];
        assert_eq!(
            provision::select(
                &mut source,
                (&mut guarded[1..1 + PRIVATE_KEY_BYTES]).try_into().unwrap(),
                1024,
                Selection::MissingEither
            ),
            expected
        );
        assert_eq!(source.events, ["certificate", "key"]);
        assert_eq!(guarded[0], 0xa5);
        assert_eq!(guarded[PRIVATE_KEY_BYTES + 1], 0xa5);
        assert_eq!(
            &guarded[1..1 + PRIVATE_KEY_BYTES],
            &[0x37; PRIVATE_KEY_BYTES]
        );
    }
}
#[test]
fn optional_zero_and_invalid_certificates_do_not_read_private_key() {
    for certificate in [
        Ok(0),
        Ok(1025),
        Ok(usize::MAX),
        Err(Error::Missing),
        Err(Error::Io),
    ] {
        let mut source = Source {
            certificate,
            key: Err(Error::Io),
            events: vec![],
        };
        let mut output = [0xa5; PRIVATE_KEY_BYTES];
        let expected = match certificate {
            Ok(0) => Ok(0),
            Ok(_) => Err(Error::Malformed),
            Err(error) => Err(error),
        };
        assert_eq!(
            provision::select(
                &mut source,
                &mut output,
                1024,
                Selection::OptionalCertificate
            ),
            expected
        );
        assert_eq!(source.events, ["certificate"]);
        assert_eq!(output, [0xa5; PRIVATE_KEY_BYTES]);
    }
}
#[test]
fn optional_provisioned_material_propagates_key_errors_without_fallback() {
    for length in [1, 1023, 1024] {
        for key in [
            Ok(()),
            Err(Error::Missing),
            Err(Error::Io),
            Err(Error::Malformed),
        ] {
            let mut source = Source {
                certificate: Ok(length),
                key,
                events: vec![],
            };
            let mut output = [0xa5; PRIVATE_KEY_BYTES];
            assert_eq!(
                provision::select(
                    &mut source,
                    &mut output,
                    1024,
                    Selection::OptionalCertificate
                ),
                key.map(|()| length)
            );
            assert_eq!(source.events, ["certificate", "key"]);
            assert_eq!(output, [0x37; PRIVATE_KEY_BYTES]);
        }
    }
}
