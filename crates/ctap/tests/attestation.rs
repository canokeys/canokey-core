// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::attestation::{self, Backend, Statement, Unprovisioned};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Error {
    Material,
    Sign,
    Output,
}
#[derive(Debug, PartialEq, Eq)]
enum Event {
    Select,
    Sign(Statement),
    Respond(Statement),
    Wipe,
}
// The product owns key cleanup even when shared execution exits before respond.
// The signature is a loan into existing backing, never a by-value secret copy.
struct Fixture<'a> {
    events: &'a mut Vec<Event>,
    key: &'a mut [u8; 32],
    signature: &'a [u8; 64],
    certificate: Result<usize, Error>,
    failure: Option<Error>,
}
impl Drop for Fixture<'_> {
    fn drop(&mut self) {
        self.key.fill(0x00);
        self.events.push(Event::Wipe);
    }
}
impl<'a> Backend for Fixture<'a> {
    type Error = Error;
    type Signature = &'a [u8; 64];
    type Output = usize;
    fn select(&mut self) -> Result<usize, Error> {
        self.events.push(Event::Select);
        self.key.fill(0x19);
        self.certificate
    }
    fn sign(&mut self, statement: Statement) -> Result<Self::Signature, Error> {
        self.events.push(Event::Sign(statement));
        if self.failure == Some(Error::Sign) {
            return Err(Error::Sign);
        }
        Ok(self.signature)
    }
    fn respond(self, statement: Statement, signature: Self::Signature) -> Result<usize, Error> {
        self.events.push(Event::Respond(statement));
        assert!(core::ptr::eq(signature, self.signature));
        if self.failure == Some(Error::Output) {
            return Err(Error::Output);
        }
        Ok(signature.len() + statement.certificate_length())
    }
}
#[test]
fn profiles_choose_existing_fallback_owners_and_assertions_never_select_material() {
    for fallback in [Unprovisioned::SignCredential, Unprovisioned::Return] {
        for make in [false, true] {
            for certificate in [0, 1, 4096] {
                let mut events = vec![];
                let mut key = [0x44; 32];
                let signature = [0x55; 64];
                let result = attestation::execute(
                    make,
                    fallback,
                    Fixture {
                        events: &mut events,
                        key: &mut key,
                        signature: &signature,
                        certificate: Ok(certificate),
                        failure: None,
                    },
                );
                let mut expected = vec![];
                if make {
                    expected.push(Event::Select);
                }
                if make && certificate == 0 && matches!(fallback, Unprovisioned::Return) {
                    assert_eq!(result, Ok(None));
                } else {
                    let statement = if !make {
                        Statement::Assertion
                    } else if certificate == 0 {
                        Statement::SelfAttestation
                    } else {
                        Statement::Provisioned { certificate }
                    };
                    assert_eq!(statement.provisioned(), make && certificate != 0);
                    expected.push(Event::Sign(statement));
                    expected.push(Event::Respond(statement));
                    assert_eq!(result, Ok(Some(64 + if make { certificate } else { 0 })));
                }
                expected.push(Event::Wipe);
                assert_eq!(events, expected);
                assert_eq!(key, [0x00; 32]);
            }
        }
    }
}
#[test]
fn selection_and_signing_errors_never_enter_response_and_all_owners_are_released() {
    for fallback in [Unprovisioned::SignCredential, Unprovisioned::Return] {
        for failure in [Error::Material, Error::Sign, Error::Output] {
            let mut events = vec![];
            let mut key = [0x44; 32];
            let signature = [0x55; 64];
            let result = attestation::execute(
                true,
                fallback,
                Fixture {
                    events: &mut events,
                    key: &mut key,
                    signature: &signature,
                    certificate: if failure == Error::Material {
                        Err(failure)
                    } else {
                        Ok(100)
                    },
                    failure: Some(failure),
                },
            );
            assert_eq!(result, Err(failure));
            let mut expected = vec![Event::Select];
            let statement = Statement::Provisioned { certificate: 100 };
            if failure != Error::Material {
                expected.push(Event::Sign(statement));
            }
            if failure == Error::Output {
                expected.push(Event::Respond(statement));
            }
            expected.push(Event::Wipe);
            assert_eq!(events, expected);
            assert_eq!(key, [0x00; 32]);
        }
    }
}
#[test]
fn assertion_bypasses_material_errors_in_both_profiles() {
    for fallback in [Unprovisioned::SignCredential, Unprovisioned::Return] {
        let mut events = vec![];
        let mut key = [0x44; 32];
        let signature = [0x55; 64];
        assert_eq!(
            attestation::execute(
                false,
                fallback,
                Fixture {
                    events: &mut events,
                    key: &mut key,
                    signature: &signature,
                    certificate: Err(Error::Material),
                    failure: None,
                }
            ),
            Ok(Some(64))
        );
        assert_eq!(
            events,
            [
                Event::Sign(Statement::Assertion),
                Event::Respond(Statement::Assertion),
                Event::Wipe
            ]
        );
        assert_eq!(key, [0x00; 32]);
    }
}
