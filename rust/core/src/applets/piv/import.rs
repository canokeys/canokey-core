// SPDX-License-Identifier: Apache-2.0
//! Private components go directly into the shared key workspace, never a wire buffer.
use super::repository as repo;
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
    pub fn feed(&mut self, b: &[u8], key: &mut [u8; 1284]) -> Result<(), Sw> {
        let a = self.meta[repo::ALGORITHM];
        for &v in b {
            match self.phase {
                Phase::Tag => {
                    let expected = if repo::rsa(a) {
                        self.component as u8 + 1
                    } else {
                        match a {
                            11 => 9,
                            10 => 10,
                            _ => 6,
                        }
                    };
                    if v != expected && !(a == 3 && v == 7) && !(a == 4 && v == 8) {
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
                    let base = if repo::rsa(a) {
                        4 + self.component * 256 + repo::width(a) - self.n
                    } else {
                        0
                    };
                    key[base + self.offset] = v;
                    self.offset += 1;
                    if self.offset == self.n {
                        self.component += 1;
                        self.phase = if repo::rsa(a) && self.component < 5 {
                            Phase::Tag
                        } else {
                            Phase::PolicyTag
                        };
                    }
                }
                Phase::PolicyTag => {
                    if !matches!(v, 0xaa | 0xab) {
                        if a == 10 {
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
    pub fn finish(&self, key: &mut [u8; 1284]) -> Result<(), Sw> {
        if !matches!(self.phase, Phase::PolicyTag | Phase::IgnoredTail) {
            return Err(Sw::WRONG_LENGTH);
        }
        if repo::rsa(self.meta[repo::ALGORITHM]) {
            key[..4].copy_from_slice(&[0, 1, 0, 1]);
            if key[4..8] < [0xb5, 4, 0xf3, 0x34][..] || key[260..264] < [0xb5, 4, 0xf3, 0x34][..] {
                return Err(Sw::WRONG_DATA);
            }
        }
        if self.meta[repo::ALGORITHM] == 4 {
            key[..32].reverse()
        }
        Ok(())
    }
}
