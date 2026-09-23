// SPDX-License-Identifier: Apache-2.0
//! Private components go directly into the shared key workspace, never a wire buffer.
use super::repository as repo;
use super::wire::key_tag;
use crate::ports::alg;
use crate::ports::key_layout;
use canokey_protocol::{
    response::StatusWord as Sw,
    tlv::length::{Feed, LengthState},
};
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Tag,
    Length,
    Value,
    PolicyTag,
    PolicyLength,
    PolicyValue,
    // Compatibility path for non-ML-KEM imports after all key components.
    // Once entered, trailing bytes are ignored rather than parsed as policies.
    IgnoredTail,
}
pub struct Import {
    phase: Phase,
    component: usize,
    length: LengthState,
    n: usize,
    offset: usize,
    tag: u8,
    pub meta: [u8; repo::META],
    pub slot: usize,
}
impl Import {
    pub const fn new() -> Self {
        Self {
            phase: Phase::Tag,
            component: 0,
            length: LengthState::Initial,
            n: 0,
            offset: 0,
            tag: 0,
            meta: [0; repo::META],
            slot: 0,
        }
    }
    pub fn feed(
        &mut self,
        b: &[u8],
        key: &mut [u8; crate::ports::key_layout::SIZE],
    ) -> Result<(), Sw> {
        let a = self.meta[repo::ALGORITHM];
        for &v in b {
            match self.phase {
                Phase::Tag => {
                    let expected = if repo::rsa(a) {
                        self.component as u8 + key_tag::IMPORT_RSA_P
                    } else {
                        match a {
                            alg::MLDSA65 => key_tag::IMPORT_MLDSA,
                            alg::MLKEM768 => key_tag::IMPORT_MLKEM,
                            _ => key_tag::IMPORT_EC,
                        }
                    };
                    if v != expected
                        && !(a == alg::ED25519 && v == key_tag::IMPORT_ED25519)
                        && !(a == alg::X25519 && v == key_tag::IMPORT_X25519)
                    {
                        return Err(Sw::WRONG_DATA);
                    }
                    self.length = LengthState::Initial;
                    self.phase = Phase::Length;
                }
                Phase::Length => match self.length.feed(v) {
                    Feed::More => (),
                    Feed::Invalid => return Err(Sw::WRONG_DATA),
                    Feed::Complete(n) => {
                        self.n = n as usize;
                        self.offset = 0;
                        if self.n == 0
                            || self.n > repo::width(a)
                            || (!repo::rsa(a) && self.n != repo::width(a))
                        {
                            return Err(Sw::WRONG_LENGTH);
                        }
                        self.phase = Phase::Value;
                    }
                },
                Phase::Value => {
                    // Right-align a short big-endian integer within its active
                    // component width; the caller has zeroed the workspace.
                    let base = if repo::rsa(a) {
                        key_layout::P + self.component * key_layout::RSA_LIMB_BYTES + repo::width(a)
                            - self.n
                    } else {
                        0
                    };
                    key[base + self.offset] = v;
                    self.offset += 1;
                    if self.offset == self.n {
                        self.component += 1;
                        self.phase = if repo::rsa(a) && self.component < key_layout::RSA_LIMBS {
                            Phase::Tag
                        } else {
                            Phase::PolicyTag
                        };
                    }
                }
                Phase::PolicyTag => {
                    if !matches!(v, key_tag::PIN_POLICY | key_tag::TOUCH_POLICY) {
                        if a == alg::MLKEM768 {
                            return Err(Sw::WRONG_DATA);
                        }
                        self.phase = Phase::IgnoredTail;
                    } else {
                        self.tag = v;
                        self.phase = Phase::PolicyLength;
                    }
                }
                Phase::PolicyLength => {
                    if v != 1 {
                        return Err(Sw::WRONG_LENGTH);
                    }
                    self.phase = Phase::PolicyValue;
                }
                Phase::PolicyValue => {
                    repo::policy(&mut self.meta, self.tag, v)?;
                    self.phase = Phase::PolicyTag;
                }
                Phase::IgnoredTail => (),
            }
        }
        Ok(())
    }
    pub fn finish(&self, key: &mut [u8; crate::ports::key_layout::SIZE]) -> Result<(), Sw> {
        if !matches!(self.phase, Phase::PolicyTag | Phase::IgnoredTail) {
            return Err(Sw::WRONG_LENGTH);
        }
        if repo::rsa(self.meta[repo::ALGORITHM]) {
            key[..key_layout::EXPONENT_BYTES].copy_from_slice(&key_layout::RSA_PUBLIC_EXPONENT);
            // Lower-bound check on each prime, intended to keep the product at the
            // requested modulus width: approximately sqrt(2) * 2^(prime_bits-1).
            // 0xB504F334 is the leading 32-bit approximation from the C parser;
            // this is not a primality test or a substitute for CRT validation.
            if key[key_layout::P..key_layout::P + 4] < [0xb5, 0x04, 0xf3, 0x34][..]
                || key[key_layout::Q..key_layout::Q + 4] < [0xb5, 0x04, 0xf3, 0x34][..]
            {
                return Err(Sw::WRONG_DATA);
            }
        }
        if self.meta[repo::ALGORITHM] == alg::X25519 {
            // Card import byte order differs from the native X25519 scalar view.
            key[..32].reverse()
        }
        Ok(())
    }
}
