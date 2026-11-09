// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::authorization::{self, Backend, Error, Policy, Request, RuleError};

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
fn product(pin_set: bool) -> Product {
    Product {
        calls: Vec::new(),
        pin_set,
        always_uv: false,
        fault: None,
    }
}
#[test]
fn ordinary_up_only_and_token_paths_preserve_the_authorization_value_without_probe() {
    for make in [false, true] {
        for pin_set in [false, true] {
            for length in [None, Some(16), Some(32)] {
                let mut request = request();
                request.make = make;
                request.auth_length = length;
                let mut backend = product(pin_set);
                let actual = authorization::authorize(&request, &mut backend);
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
#[test]
fn invalid_options_and_silent_secret_precede_policy_probe_and_token_faults() {
    for pin_set in [false, true] {
        for auth_length in [None, Some(0), Some(16), Some(32)] {
            for fault in [
                None,
                Some(Fault::Read),
                Some(Fault::Cancel),
                Some(Fault::Proof),
            ] {
                for (case, expected) in [
                    (0, RuleError::UnsupportedOption),
                    (1, RuleError::UnsupportedOption),
                    (2, RuleError::InvalidOption),
                    (3, RuleError::InvalidOption),
                ] {
                    let mut request = request();
                    request.auth_length = auth_length;
                    match case {
                        0 => {
                            request.make = false;
                            request.up = false;
                            request.secret = true;
                        }
                        1 => {
                            request.make = false;
                            request.resident = true;
                        }
                        2 => request.up = false,
                        3 => request.large_blob_key = true,
                        _ => unreachable!(),
                    }
                    let mut backend = product(pin_set);
                    backend.fault = fault;
                    assert_eq!(
                        authorization::authorize(&request, &mut backend),
                        Err(Error::Rule(expected))
                    );
                    assert!(backend.calls.is_empty());
                }
            }
        }
    }
    let mut request = request();
    request.uv = true;
    let mut backend = product(true);
    assert_eq!(
        authorization::authorize(&request, &mut backend),
        Err(Error::Rule(RuleError::InvalidOption))
    );
    assert!(backend.calls.is_empty());
}
#[test]
fn valid_empty_authentication_probes_presence_once_and_never_verifies_token() {
    for make in [false, true] {
        for pin_set in [false, true] {
            for uv in [false, true] {
                let mut request = request();
                request.make = make;
                request.uv = uv;
                request.auth_length = Some(0);
                let mut backend = product(pin_set);
                assert_eq!(
                    authorization::authorize(&request, &mut backend),
                    Err(Error::Rule(if pin_set {
                        RuleError::PinInvalid
                    } else {
                        RuleError::PinNotSet
                    }))
                );
                assert_eq!(backend.calls, ["read", "presence"]);
            }
        }
    }
}
#[test]
fn policy_uv_requirements_precede_credential_selection_without_consuming_presence() {
    for resident in [false, true] {
        let mut request = request();
        request.resident = resident;
        let mut backend = product(true);
        backend.always_uv = !resident;
        assert_eq!(
            authorization::authorize(&request, &mut backend),
            Err(Error::Rule(RuleError::PuatRequired))
        );
        assert_eq!(backend.calls, ["read"]);
    }
}
#[test]
fn admitted_request_preserves_read_probe_and_proof_errors_without_later_calls() {
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
            authorization::authorize(&request, &mut backend),
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
}
