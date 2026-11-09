// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::signing::{self, Algorithm, Backend};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Error {
    Digest,
    Sign,
    Encode,
    Length,
}
struct Fixture<'a> {
    events: &'a mut Vec<&'static str>,
    failure: Option<Error>,
    length: usize,
}
impl signing::Primitive for Fixture<'_> {
    type Error = Error;
    type Signature = usize;
    fn digest(&mut self, algorithm: Algorithm, output: &mut [u8; 32]) -> Result<(), Error> {
        self.events.push(match algorithm {
            Algorithm::Es256 => "sha256",
            Algorithm::Sm2 => "sm2-za-digest",
            Algorithm::Ed25519 => panic!("Ed25519 must sign the original message"),
        });
        if self.failure == Some(Error::Digest) {
            return Err(Error::Digest);
        }
        output.fill(0xa5);
        Ok(())
    }
    fn sign(&mut self, digest: Option<&[u8; 32]>) -> Result<usize, Error> {
        match digest {
            Some(digest) => {
                assert_eq!(digest, &[0xa5; 32]);
                self.events.push("sign-digest");
            }
            None => self.events.push("sign-message"),
        }
        if self.failure == Some(Error::Sign) {
            return Err(Error::Sign);
        }
        Ok(self.length)
    }
    fn length(&self, signature: &usize) -> usize {
        *signature
    }
    fn invalid_signature() -> Error {
        Error::Length
    }
}
impl Backend for Fixture<'_> {
    fn der(&mut self, _: usize) -> Result<usize, Error> {
        self.events.push("der");
        if self.failure == Some(Error::Encode) {
            return Err(Error::Encode);
        }
        Ok(72)
    }
    fn raw(&mut self, signature: usize) -> Result<usize, Error> {
        self.events.push("raw");
        if self.failure == Some(Error::Encode) {
            return Err(Error::Encode);
        }
        Ok(signature)
    }
}
#[test]
fn standard_algorithms_choose_transcript_and_wire_encoding() {
    for (algorithm, expected, length) in [
        (Algorithm::Es256, vec!["sha256", "sign-digest", "der"], 72),
        (Algorithm::Ed25519, vec!["sign-message", "raw"], 64),
        (
            Algorithm::Sm2,
            vec!["sm2-za-digest", "sign-digest", "raw"],
            64,
        ),
    ] {
        let mut events = vec![];
        assert_eq!(
            signing::sign(
                algorithm,
                Fixture {
                    events: &mut events,
                    failure: None,
                    length: 64
                }
            ),
            Ok(length)
        );
        assert_eq!(events, expected);
    }
}
#[test]
fn errors_stop_before_later_crypto_or_encoding() {
    for algorithm in [Algorithm::Es256, Algorithm::Ed25519, Algorithm::Sm2] {
        for failure in [Error::Digest, Error::Sign, Error::Encode] {
            if algorithm == Algorithm::Ed25519 && failure == Error::Digest {
                continue;
            }
            let mut events = vec![];
            assert_eq!(
                signing::sign(
                    algorithm,
                    Fixture {
                        events: &mut events,
                        failure: Some(failure),
                        length: 64
                    }
                ),
                Err(failure)
            );
            let expected = match failure {
                Error::Digest => 1,
                Error::Sign => {
                    if algorithm == Algorithm::Ed25519 {
                        1
                    } else {
                        2
                    }
                }
                Error::Encode => {
                    if algorithm == Algorithm::Ed25519 {
                        2
                    } else {
                        3
                    }
                }
                Error::Length => unreachable!(),
            };
            assert_eq!(events.len(), expected);
        }
    }
}
#[test]
fn malformed_native_lengths_never_reach_wire_encoding() {
    for algorithm in [Algorithm::Es256, Algorithm::Ed25519, Algorithm::Sm2] {
        for length in [0, 1, 32, 63, 65, 72, usize::MAX] {
            let mut events = vec![];
            assert_eq!(
                signing::sign(
                    algorithm,
                    Fixture {
                        events: &mut events,
                        failure: None,
                        length
                    }
                ),
                Err(Error::Length)
            );
            assert!(!events.contains(&"der") && !events.contains(&"raw"));
        }
    }
}

#[test]
fn native_result_can_be_used_without_forcing_an_output_buffer_or_wire_conversion() {
    for algorithm in [Algorithm::Es256, Algorithm::Ed25519, Algorithm::Sm2] {
        let mut events = vec![];
        assert_eq!(
            signing::prepare(
                algorithm,
                &mut Fixture {
                    events: &mut events,
                    failure: None,
                    length: 64,
                }
            ),
            Ok(64)
        );
        assert!(!events.contains(&"der") && !events.contains(&"raw"));
        assert_eq!(
            events.last(),
            Some(&if algorithm == Algorithm::Ed25519 {
                "sign-message"
            } else {
                "sign-digest"
            })
        );
    }
}
