// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::credential::{self, Creation, Id, Opening, Scheme};
use std::cell::RefCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Random,
    Tag,
    Seed,
    Compare,
    ClearTag,
    Reject,
    Accept,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Error {
    Random,
    Derive,
}
struct Create {
    trace: Vec<Event>,
    attempts: u8,
    reject_attempts: u8,
    fail_random: bool,
    fail_tag: bool,
}
impl Creation for Create {
    type Error = Error;
    type Credential = Id;
    fn random_nonce(&mut self, nonce: &mut [u8]) -> Result<(), Error> {
        self.trace.push(Event::Random);
        assert_eq!(nonce.len(), 16);
        if self.fail_random {
            return Err(Error::Random);
        }
        self.attempts += 1;
        nonce.fill(self.attempts);
        Ok(())
    }
    fn prepare(&mut self, id: &Id) -> Result<[u8; 32], Error> {
        self.trace.push(Event::Tag);
        assert!(id[2..18].iter().all(|&byte| byte == self.attempts));
        if self.fail_tag {
            Err(Error::Derive)
        } else {
            Ok([self.attempts; 32])
        }
    }
    fn clear_tag(&mut self, tag: &mut [u8; 32]) {
        self.trace.push(Event::ClearTag);
        assert_eq!(*tag, [self.attempts; 32]);
        tag.fill(0x00);
    }
    fn accept(&mut self, id: &Id) -> Option<Id> {
        self.trace.push(Event::Accept);
        assert!(id[18..].iter().all(|&byte| byte == self.attempts));
        (self.attempts > self.reject_attempts).then_some(*id)
    }
}
fn creator() -> Create {
    Create {
        trace: Vec::new(),
        attempts: 0,
        reject_attempts: 2,
        fail_random: false,
        fail_tag: false,
    }
}
#[test]
fn rejection_redraws_exact_nonce_and_preserves_scheme_and_all_policy_bits() {
    for scheme in [
        Scheme::P256,
        Scheme::Ed25519,
        Scheme::Sm2,
        Scheme::MlDsa65,
        Scheme::MlDsa44,
    ] {
        for flags in 0x00..=0xff {
            let mut backend = creator();
            let id = credential::create(scheme, flags, &mut backend).unwrap();
            assert_eq!(id[0], scheme as u8);
            assert_eq!(id[1], flags);
            assert_eq!(&id[2..18], &[0x03; 16]);
            assert_eq!(&id[18..], &[0x03; 16]);
            assert_eq!(
                backend.trace,
                [Event::Random, Event::Tag, Event::ClearTag, Event::Accept].repeat(3)
            );
        }
    }
}
#[test]
fn random_or_derivation_errors_stop_without_acceptance_or_automatic_retry() {
    for random in [false, true] {
        let mut backend = creator();
        backend.fail_random = random;
        backend.fail_tag = !random;
        assert_eq!(
            credential::create(Scheme::P256, 0x07, &mut backend),
            Err(if random { Error::Random } else { Error::Derive })
        );
        assert_eq!(
            backend.trace,
            if random {
                vec![Event::Random]
            } else {
                vec![Event::Random, Event::Tag]
            }
        );
    }
}
struct Open {
    trace: RefCell<Vec<Event>>,
    valid: bool,
    fail_tag: bool,
    fail_seed: bool,
    reject_seed: bool,
}
impl Opening for Open {
    type Error = Error;
    type Credential = Id;
    fn tag(&mut self, _: &Id) -> Result<[u8; 32], Error> {
        self.trace.borrow_mut().push(Event::Tag);
        if self.fail_tag {
            Err(Error::Derive)
        } else {
            Ok([0x7a; 32])
        }
    }
    fn equal(&self, expected: &[u8], computed: &[u8]) -> bool {
        self.trace.borrow_mut().push(Event::Compare);
        assert_eq!(expected, &[0x7a; 16]);
        assert_eq!(computed, &[0x7a; 16]);
        self.valid
    }
    fn clear_tag(&mut self, tag: &mut [u8; 32]) {
        self.trace.borrow_mut().push(Event::ClearTag);
        assert_eq!(*tag, [0x7a; 32]);
        tag.fill(0x00);
    }
    fn reject(&mut self) {
        self.trace.borrow_mut().push(Event::Reject);
    }
    fn accept(&mut self, id: &Id) -> Result<Option<Id>, Error> {
        self.trace.borrow_mut().push(Event::Seed);
        if self.fail_seed {
            return Err(Error::Derive);
        }
        self.trace.borrow_mut().push(Event::Accept);
        Ok((!self.reject_seed).then_some(*id))
    }
}
#[test]
fn opening_authenticates_before_seed_and_never_retries_failed_or_invalid_seeds() {
    let id = [0x7a; 34];
    for fail_tag in [false, true] {
        for valid in [false, true] {
            for fail_seed in [false, true] {
                for reject_seed in [false, true] {
                    let mut backend = Open {
                        trace: RefCell::new(Vec::new()),
                        valid,
                        fail_tag,
                        fail_seed,
                        reject_seed,
                    };
                    let expected = if fail_tag || (valid && fail_seed) {
                        Err(Error::Derive)
                    } else {
                        Ok((valid && !reject_seed).then_some(id))
                    };
                    assert_eq!(credential::open(&id, &mut backend), expected);
                    let mut trace = vec![Event::Tag];
                    if !fail_tag {
                        trace.extend([Event::Compare, Event::ClearTag]);
                        if valid {
                            trace.push(Event::Seed);
                            if !fail_seed {
                                trace.push(Event::Accept);
                            }
                        } else {
                            trace.push(Event::Reject);
                        }
                    }
                    assert_eq!(*backend.trace.borrow(), trace);
                }
            }
        }
    }
}
#[test]
fn scalar_boundaries_preserve_p256_and_sm2_rejection_without_reduction() {
    // Fixed SEC 2 P-256 order and SM2 order from the pre-extraction products.
    let orders = [
        (
            Scheme::P256,
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        ),
        (
            Scheme::Sm2,
            "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123",
        ),
    ];
    for scheme in [Scheme::Ed25519, Scheme::MlDsa65, Scheme::MlDsa44] {
        assert!(credential::valid_signing_seed(scheme, &[0x00; 32]));
        assert!(credential::valid_signing_seed(scheme, &[0xff; 32]));
    }
    for (scheme, hex) in orders {
        let order: [u8; 32] =
            core::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap());
        let mut one = [0x00; 32];
        one[31] = 0x01;
        let mut last = order;
        last[31] -= if scheme == Scheme::Sm2 { 2 } else { 1 };
        let mut limit = last;
        limit[31] += 1;
        for (seed, expected) in [
            ([0x00; 32], false),
            (one, true),
            (last, true),
            (limit, false),
            (order, false),
            ([0xff; 32], false),
        ] {
            assert_eq!(credential::valid_signing_seed(scheme, &seed), expected);
        }
        // Vary every byte at the admission boundary; fixed old comparison is
        // lexicographic big-endian 0 < d < limit, with no modular reduction.
        for offset in 0..32 {
            for byte in 0x00..=0xff {
                let mut seed = limit;
                seed[offset] = byte;
                let old = seed.iter().any(|&b| b != 0x00) && seed.as_slice() < limit.as_slice();
                assert_eq!(credential::valid_signing_seed(scheme, &seed), old);
                for scheme in [Scheme::Ed25519, Scheme::MlDsa65, Scheme::MlDsa44] {
                    assert!(credential::valid_signing_seed(scheme, &seed));
                }
            }
        }
    }
}
