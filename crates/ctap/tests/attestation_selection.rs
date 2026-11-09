// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::provision::{self, PRIVATE_KEY_BYTES, SelectionSource};

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
fn certificate_admission_precedes_key_access_and_never_masks_corrupt_material() {
    let mut compared = 0;
    for maximum in [0, 1024, 1152] {
        for certificate in [
            Ok(0),
            Ok(1),
            Ok(maximum),
            Ok(maximum + 1),
            Ok(usize::MAX),
            Err(Error::Missing),
            Err(Error::Io),
            Err(Error::Malformed),
        ] {
            for key in [
                Ok(()),
                Err(Error::Missing),
                Err(Error::Io),
                Err(Error::Malformed),
            ] {
                let mut source = Source {
                    certificate,
                    key,
                    events: vec![],
                };
                let mut guarded = [0xa5; PRIVATE_KEY_BYTES + 2];
                let (expected, reads_key) = match certificate {
                    Ok(0) | Err(Error::Missing) => (Ok(0), false),
                    Ok(length) if length <= maximum => (key.map(|()| length), true),
                    Ok(_) => (Err(Error::Malformed), false),
                    Err(error) => (Err(error), false),
                };
                assert_eq!(
                    provision::select(
                        &mut source,
                        (&mut guarded[1..1 + PRIVATE_KEY_BYTES]).try_into().unwrap(),
                        maximum
                    ),
                    expected
                );
                assert_eq!(
                    source.events,
                    if reads_key {
                        vec!["certificate", "key"]
                    } else {
                        vec!["certificate"]
                    }
                );
                assert_eq!(guarded[0], 0xa5);
                assert_eq!(guarded[PRIVATE_KEY_BYTES + 1], 0xa5);
                assert_eq!(
                    &guarded[1..1 + PRIVATE_KEY_BYTES],
                    &[if reads_key { 0x37 } else { 0xa5 }; PRIVATE_KEY_BYTES]
                );
                compared += 1;
            }
        }
    }
    assert_eq!(compared, 96);
}
