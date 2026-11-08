// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::client_pin::{authentication, retry};
use std::cell::RefCell;

#[test]
fn authenticator_compares_only_selected_prefix_and_erases_full_scratch_on_failure() {
    for scratch_bytes in [31, 32, 64] {
        for auth_bytes in [0, 16, 32, 33, 64] {
            for auth_length in 0..=65 {
                for fail in [false, true] {
                    for matches in [false, true] {
                        let mut scratch = [0x00; 64];
                        let auth = [if matches { 0x42 } else { 0x43 }; 65];
                        let events = RefCell::new(Vec::new());
                        let result = authentication::verify(
                            &auth[..auth_length],
                            auth_bytes,
                            &mut scratch[..scratch_bytes],
                            |output| {
                                events.borrow_mut().push("compute");
                                output.fill(0x42);
                                if fail { Err(0xee) } else { Ok(()) }
                            },
                            |expected, computed| {
                                events.borrow_mut().push("compare");
                                assert_eq!(computed.len(), auth_bytes);
                                expected == computed
                            },
                            |output| {
                                events.borrow_mut().push("wipe");
                                assert_eq!(output, &vec![0x42; scratch_bytes]);
                                output.fill(0x00);
                            },
                        );
                        let compared = scratch_bytes >= 32 && auth_bytes <= 32;
                        let expected_events: &[&str] = if compared {
                            &["compute", "compare", "wipe"]
                        } else {
                            &["compute", "wipe"]
                        };
                        assert_eq!(events.borrow().as_slice(), expected_events);
                        assert_eq!(scratch, [0x00; 64]);
                        assert_eq!(
                            result,
                            if fail {
                                Err(0xee)
                            } else {
                                Ok(compared
                                    && auth_length == auth_bytes
                                    && (matches || auth_length == 0))
                            }
                        );
                    }
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Failure {
    Blocked,
    Store,
    Compare,
    Wrong(retry::Rejection),
}
struct Backend {
    remaining: u8,
    durable: u8,
    attempts: u8,
    charge_failure: u8,
    comparison: Result<bool, ()>,
    events: Vec<&'static str>,
}
impl retry::Verification for Backend {
    type Error = Failure;
    fn remaining(&self) -> u8 {
        self.remaining
    }
    fn blocked(&self) -> Failure {
        Failure::Blocked
    }
    fn charge(&mut self, remaining: u8) -> Result<(), Failure> {
        self.events.push("charge");
        self.remaining = remaining;
        if self.charge_failure != 1 {
            self.durable = remaining;
        }
        if self.charge_failure != 0 {
            Err(Failure::Store)
        } else {
            Ok(())
        }
    }
    fn compare(&mut self) -> Result<bool, Failure> {
        self.events.push("compare");
        self.comparison.map_err(|_| Failure::Compare)
    }
    fn rejected(&mut self) -> Failure {
        self.events.push("reject");
        self.attempts -= 1;
        Failure::Wrong(retry::rejection(self.remaining, self.attempts))
    }
}

#[test]
fn verification_never_compares_after_uncertain_charge_or_refunds_before_owner_commit() {
    for remaining in 0..=8 {
        for attempts in 1..=3 {
            // 1 fails before the durable write; 2 reports failure after it.
            for charge_failure in 0..=2 {
                for comparison in [Ok(true), Ok(false), Err(())] {
                    let mut backend = Backend {
                        remaining,
                        durable: remaining,
                        attempts,
                        charge_failure,
                        comparison,
                        events: Vec::new(),
                    };
                    let result = retry::verify(&mut backend);
                    if remaining == 0 {
                        assert_eq!(result, Err(Failure::Blocked));
                        assert!(backend.events.is_empty());
                        assert_eq!(backend.attempts, attempts);
                        continue;
                    }
                    assert_eq!(backend.remaining, remaining - 1);
                    assert_eq!(
                        backend.durable,
                        if charge_failure == 1 {
                            remaining
                        } else {
                            remaining - 1
                        }
                    );
                    if charge_failure != 0 {
                        assert_eq!(result, Err(Failure::Store));
                        assert_eq!(backend.events, ["charge"]);
                        assert_eq!(backend.attempts, attempts);
                    } else if comparison == Ok(false) {
                        let expected = if remaining == 1 {
                            retry::Rejection::Blocked
                        } else if attempts == 1 {
                            retry::Rejection::PowerCycleBlocked
                        } else {
                            retry::Rejection::Invalid
                        };
                        assert_eq!(result, Err(Failure::Wrong(expected)));
                        assert_eq!(backend.events, ["charge", "compare", "reject"]);
                        assert_eq!(backend.attempts, attempts - 1);
                    } else {
                        assert_eq!(result, comparison.map(|_| ()).map_err(|_| Failure::Compare));
                        assert_eq!(backend.events, ["charge", "compare"]);
                        assert_eq!(backend.attempts, attempts);
                    }
                }
            }
        }
    }
}
