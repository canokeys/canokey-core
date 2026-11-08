// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::client_pin::{Derivation, Protocol, agreement};
use std::cell::RefCell;

struct Generation {
    cached: bool,
    rejected: usize,
    fail_at: usize,
    calls: usize,
    commit_error: bool,
    events: Vec<&'static str>,
}
impl agreement::Generation for Generation {
    type Error = u8;
    type Output = u8;
    fn ready(&self) -> bool {
        self.cached
    }
    fn generate(&mut self) -> Result<bool, u8> {
        self.events.push("generate");
        self.calls += 1;
        if self.calls == self.fail_at {
            Err(0xee)
        } else {
            Ok(self.calls > self.rejected)
        }
    }
    fn commit(&mut self) -> Result<u8, u8> {
        self.events.push("commit");
        if self.commit_error {
            Err(0xef)
        } else {
            self.cached = true;
            Ok(0x51)
        }
    }
    fn restore(&mut self) -> Result<u8, u8> {
        self.events.push("restore");
        Ok(0x52)
    }
}
#[test]
fn eager_generation_redraws_but_cached_keys_restore_without_generation_or_export() {
    for rejected in 0..=3 {
        for fail_at in 0..=rejected + 1 {
            for commit_error in [false, true] {
                let mut backend = Generation {
                    cached: false,
                    rejected,
                    fail_at,
                    calls: 0,
                    commit_error,
                    events: Vec::new(),
                };
                let result = agreement::establish(&mut backend);
                let generated = if fail_at == 0 { rejected + 1 } else { fail_at };
                let mut expected = vec!["generate"; generated];
                if fail_at == 0 {
                    expected.push("commit");
                }
                assert_eq!(backend.events, expected);
                assert_eq!(
                    result,
                    if fail_at != 0 {
                        Err(0xee)
                    } else if commit_error {
                        Err(0xef)
                    } else {
                        Ok(0x51)
                    }
                );
                assert_eq!(backend.cached, result.is_ok());
                // Only the owner can mark a failed operation ready or erase it.
                backend.cached = true;
                backend.events.clear();
                assert_eq!(agreement::establish(&mut backend), Ok(0x52));
                assert_eq!(backend.events, ["restore"]);
                assert_eq!(backend.calls, generated);
            }
        }
    }
}

struct Exchange<'a> {
    events: &'a RefCell<Vec<&'static str>>,
    calls: usize,
    fail_at: usize,
    wipes: usize,
}
impl Exchange<'_> {
    fn step(&mut self) -> Result<(), u8> {
        self.calls += 1;
        if self.calls == self.fail_at {
            Err(self.calls as u8)
        } else {
            Ok(())
        }
    }
}
impl Derivation for Exchange<'_> {
    type Error = u8;
    fn sha256(&mut self, input: &[u8], out: &mut [u8; 32]) -> Result<(), u8> {
        self.events.borrow_mut().push("sha");
        assert_eq!(input, [0x41; 32]);
        out.fill(0x51);
        self.step()
    }
    fn hmac_sha256(&mut self, _: &[u8; 32], _: &[u8], out: &mut [u8; 32]) -> Result<(), u8> {
        self.events.borrow_mut().push("hmac");
        out.fill(0x52);
        self.step()
    }
    fn wipe(&mut self, bytes: &mut [u8]) {
        self.events.borrow_mut().push("wipe");
        bytes.fill(0x00);
        self.wipes += 1;
    }
}
impl agreement::Exchange for Exchange<'_> {
    fn agree(&mut self, peer: &[u8; 64], output: &mut [u8]) -> Result<(), u8> {
        self.events.borrow_mut().push("agree");
        assert_eq!(peer, &[0x61; 64]);
        output[..32].fill(0x41);
        self.step()
    }
}
#[test]
fn exchange_keeps_ecdh_before_protocol_and_kdf_with_existing_output_loans() {
    for protocol in [Protocol::One, Protocol::Two] {
        for valid_protocol in [false, true] {
            for fail_at in 0..=4 {
                let events = RefCell::new(Vec::new());
                let mut backend = Exchange {
                    events: &events,
                    calls: 0,
                    fail_at,
                    wipes: 0,
                };
                let mut scratch = [0xaa; 64];
                let mut mac_key = [0xbb; 32];
                let mut aes_key = [0xcc; 32];
                let result = agreement::decapsulate(
                    || {
                        events.borrow_mut().push("protocol");
                        if valid_protocol {
                            Ok(protocol)
                        } else {
                            Err(0xee)
                        }
                    },
                    &[0x61; 64],
                    &mut scratch,
                    &mut mac_key,
                    &mut aes_key,
                    &mut backend,
                );
                let mut expected = vec!["agree"];
                let mut expected_error = None;
                if fail_at == 1 {
                    expected_error = Some(1);
                } else {
                    expected.push("protocol");
                    if !valid_protocol {
                        expected_error = Some(0xee);
                    } else {
                        let steps = if protocol == Protocol::One { 1 } else { 3 };
                        for index in 0..steps {
                            expected.push(if protocol == Protocol::One {
                                "sha"
                            } else {
                                "hmac"
                            });
                            if fail_at == index + 2 {
                                expected_error = Some(fail_at as u8);
                                break;
                            }
                        }
                        if protocol == Protocol::Two {
                            expected.push("wipe");
                        }
                    }
                }
                assert_eq!(events.borrow().as_slice(), expected);
                assert_eq!(result.err(), expected_error);
                assert_eq!(&scratch[..32], &[0x41; 32]);
                assert_eq!(&scratch[32..], &[0xaa; 32]);
                assert_eq!(
                    backend.wipes,
                    usize::from(fail_at != 1 && valid_protocol && protocol == Protocol::Two)
                );
            }
        }
    }
}
