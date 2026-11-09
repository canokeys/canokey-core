// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::authorization::{
    self, Backend, Error, Policy, Profile, Request, RuleError, SecretOrder,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Read,
    Cancel,
    Timeout,
    Proof,
}
struct Product {
    calls: Vec<&'static str>,
    pin_set: bool,
    always_uv: bool,
    fault: Option<Fault>,
}
impl Backend for Product {
    type Error = Fault;
    // Stand-in for a product's captured deadline: the engine must return the
    // exact value supplied after proof admission, without issuing another grant.
    type Authorization = (u32, u32);
    fn policy(&mut self) -> Result<Policy, Fault> {
        self.calls.push("read");
        if self.fault == Some(Fault::Read) {
            return Err(Fault::Read);
        }
        Ok(Policy {
            pin_set: self.pin_set,
            always_uv: self.always_uv,
        })
    }
    fn presence(&mut self) -> Result<(), Fault> {
        self.calls.push("presence");
        match self.fault {
            Some(Fault::Cancel | Fault::Timeout) => Err(self.fault.unwrap()),
            _ => Ok(()),
        }
    }
    fn verify(&mut self) -> Result<(u32, u32), Fault> {
        self.calls.push("verify");
        if self.fault == Some(Fault::Proof) {
            return Err(Fault::Proof);
        }
        Ok((u32::MAX - 10, 600_000))
    }
}
fn request() -> Request {
    Request {
        make: true,
        up: true,
        uv: false,
        resident: false,
        auth_length: None,
        secret: false,
        large_blob_key: false,
    }
}
fn profile(streamed: bool) -> Profile {
    Profile {
        secret_order: if streamed {
            SecretOrder::AfterEmptyAuthentication
        } else {
            SecretOrder::BeforePolicy
        },
        reject_assertion_resident: !streamed,
    }
}
fn product(pin_set: bool) -> Product {
    Product {
        calls: Vec::new(),
        pin_set,
        always_uv: false,
        fault: None,
    }
}
#[test]
fn ordinary_up_only_and_token_authorized_paths_never_collect_the_probe_gesture() {
    for streamed in [false, true] {
        for make in [false, true] {
            for pin_set in [false, true] {
                for length in [None, Some(16), Some(32)] {
                    let mut request = request();
                    request.make = make;
                    request.auth_length = length;
                    let mut backend = product(pin_set);
                    let actual =
                        authorization::authorize(&request, profile(streamed), &mut backend);
                    match (length, pin_set) {
                        (None, _) => {
                            assert_eq!(actual, Ok(None));
                            assert_eq!(backend.calls, ["read"]);
                        }
                        (Some(_), false) => {
                            assert_eq!(actual, Err(Error::Rule(RuleError::PinNotSet)));
                            assert_eq!(backend.calls, ["read"]);
                        }
                        (Some(_), true) => {
                            assert_eq!(actual, Ok(Some((u32::MAX - 10, 600_000))));
                            assert_eq!(backend.calls, ["read", "verify"]);
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn explicit_policy_and_option_rejections_precede_any_token_admission() {
    for streamed in [false, true] {
        for (case, expected) in [
            (0, RuleError::PuatRequired),
            (1, RuleError::InvalidOption),
            (2, RuleError::InvalidOption),
            (3, RuleError::InvalidOption),
            (4, RuleError::PuatRequired),
        ] {
            let mut request = request();
            let mut backend = product(true);
            match case {
                0 => request.resident = true,
                1 => request.uv = true,
                2 => request.up = false,
                3 => request.large_blob_key = true,
                4 => {
                    request.make = false;
                    backend.always_uv = true;
                }
                _ => unreachable!(),
            }
            assert_eq!(
                authorization::authorize(&request, profile(streamed), &mut backend),
                Err(Error::Rule(expected))
            );
            assert_eq!(backend.calls, ["read"]);
        }
        let mut request = request();
        request.make = false;
        request.resident = true;
        let mut backend = product(false);
        let expected = if streamed {
            Ok(None)
        } else {
            Err(Error::Rule(RuleError::InvalidOption))
        };
        // Streamed schemas reject rk before this engine; borrowed schemas do so here.
        assert_eq!(
            authorization::authorize(&request, profile(streamed), &mut backend),
            expected
        );
        assert_eq!(backend.calls, ["read"]);
    }
}
#[test]
fn empty_authentication_probes_presence_before_options_but_preserves_secret_precedence() {
    for streamed in [false, true] {
        for pin_set in [false, true] {
            let mut request = request();
            request.auth_length = Some(0);
            request.uv = true;
            request.up = false;
            let mut backend = product(pin_set);
            let expected = if pin_set {
                RuleError::PinInvalid
            } else {
                RuleError::PinNotSet
            };
            assert_eq!(
                authorization::authorize(&request, profile(streamed), &mut backend),
                Err(Error::Rule(expected))
            );
            assert_eq!(backend.calls, ["read", "presence"]);
            request.make = false;
            request.secret = true;
            backend.calls.clear();
            let actual = authorization::authorize(&request, profile(streamed), &mut backend);
            if streamed {
                assert_eq!(actual, Err(Error::Rule(expected)));
                assert_eq!(backend.calls, ["read", "presence"]);
            } else {
                assert_eq!(actual, Err(Error::Rule(RuleError::UnsupportedOption)));
                assert!(backend.calls.is_empty());
            }
        }
    }
}
#[test]
fn read_probe_and_proof_errors_are_unchanged_and_no_later_capability_runs() {
    for streamed in [false, true] {
        for fault in [Fault::Read, Fault::Cancel, Fault::Timeout, Fault::Proof] {
            let mut request = request();
            request.auth_length = if fault == Fault::Proof {
                Some(16)
            } else {
                Some(0)
            };
            let mut backend = product(true);
            backend.fault = Some(fault);
            assert_eq!(
                authorization::authorize(&request, profile(streamed), &mut backend),
                Err(Error::Backend(fault))
            );
            assert_eq!(
                backend.calls,
                match fault {
                    Fault::Read => vec!["read"],
                    Fault::Proof => vec!["read", "verify"],
                    _ => vec!["read", "presence"],
                }
            );
        }
        let mut request = request();
        request.make = false;
        request.up = false;
        request.secret = true;
        let mut backend = product(true);
        backend.fault = Some(Fault::Read);
        let expected = if streamed {
            Err(Error::Backend(Fault::Read))
        } else {
            Err(Error::Rule(RuleError::UnsupportedOption))
        };
        assert_eq!(
            authorization::authorize(&request, profile(streamed), &mut backend),
            expected
        );
        assert_eq!(backend.calls, if streamed { vec!["read"] } else { vec![] });
    }
}
