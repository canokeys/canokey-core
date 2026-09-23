// SPDX-License-Identifier: Apache-2.0
//! The import envelope is bounded; component values stream directly into the
//! session key. No encoded-key buffer and no flash writes before validation.
use super::{
    domain::{Algorithm, role},
    repository,
};
use crate::Platform;
use canokey_protocol::{
    response::StatusWord as Sw,
    tlv::length::{Feed, LengthState},
};
fn length(b: &[u8], at: &mut usize) -> Result<Option<usize>, Sw> {
    let mut state = LengthState::Initial;
    while *at < b.len() {
        let v = b[*at];
        *at += 1;
        match state.feed(v) {
            Feed::More => (),
            Feed::Complete(n) => return Ok(Some(n as usize)),
            Feed::Invalid => return Err(Sw::WRONG_DATA),
        }
    }
    Ok(None)
}
/// Parse a complete BER object, returning its tag and value without allocation.
pub fn object(b: &[u8]) -> Result<(u16, &[u8]), Sw> {
    if b.is_empty() {
        return Err(Sw::WRONG_DATA);
    }
    let mut at = 1;
    let mut tag = b[0] as u16;
    if tag & 31 == 31 {
        tag = (tag << 8) | *b.get(at).ok_or(Sw::WRONG_DATA)? as u16;
        at += 1;
    }
    let n = length(b, &mut at)?.ok_or(Sw::WRONG_LENGTH)?;
    if at + n != b.len() {
        return Err(Sw::WRONG_LENGTH);
    }
    Ok((tag, &b[at..]))
}
pub struct Import {
    prefix: [u8; 48],
    used: usize,
    total: usize,
    received: usize,
    lengths: [usize; 6],
    component: usize,
    offset: usize,
    pub role: usize,
    pub algorithm: Algorithm,
    ready: bool,
}
impl Import {
    pub const fn new() -> Self {
        Self {
            prefix: [0; 48],
            used: 0,
            total: 0,
            received: 0,
            lengths: [0; 6],
            component: 0,
            offset: 0,
            role: 0,
            algorithm: Algorithm(5),
            ready: false,
        }
    }
    fn header(&mut self, p: &mut Platform<'_>) -> Result<bool, Sw> {
        let b = &self.prefix[..self.used];
        if b[0] != 0x4d {
            return Err(Sw::WRONG_DATA);
        }
        let mut at = 1;
        let Some(n) = length(b, &mut at)? else {
            return Ok(false);
        };
        self.total = at + n;
        if self.total > 1400 {
            return Err(Sw::WRONG_LENGTH);
        }
        let Some(&r) = b.get(at) else {
            return Ok(false);
        };
        self.role = role(r).ok_or(Sw::WRONG_DATA)?;
        at += 1;
        let Some(&crt) = b.get(at) else {
            return Ok(false);
        };
        at += 1;
        if !matches!(crt, 0 | 3) {
            return Err(Sw::WRONG_DATA);
        }
        if b.len() < at + crt as usize {
            return Ok(false);
        }
        if crt == 3 && b[at..at + 3] != [0x84, 1, 1] {
            return Err(Sw::WRONG_DATA);
        }
        at += crt as usize;
        if b.len() < at + 2 {
            return Ok(false);
        }
        if b[at..at + 2] != [0x7f, 0x48] {
            return Err(Sw::WRONG_DATA);
        }
        at += 2;
        let Some(n) = length(b, &mut at)? else {
            return Ok(false);
        };
        if n > 24 {
            return Err(Sw::WRONG_DATA);
        }
        if b.len() < at + n {
            return Ok(false);
        }
        let end = at + n;
        let mut count = 0;
        let mut tags = [0; 6];
        self.lengths.fill(0);
        while at < end {
            if count == 6 {
                return Err(Sw::WRONG_DATA);
            }
            tags[count] = b[at];
            at += 1;
            self.lengths[count] = length(&b[..end], &mut at)?.ok_or(Sw::WRONG_DATA)?;
            count += 1;
        }
        if b.len() < at + 2 {
            return Ok(false);
        }
        if b[at..at + 2] != [0x5f, 0x48] {
            return Err(Sw::WRONG_DATA);
        }
        at += 2;
        let Some(n) = length(b, &mut at)? else {
            return Ok(false);
        };
        if at + n != self.total || self.lengths.iter().sum::<usize>() != n {
            return Err(Sw::WRONG_LENGTH);
        }
        self.algorithm = Algorithm(repository::meta(p, self.role)?[1]);
        let a = self.algorithm;
        let width = a.scalar();
        if a.rsa() {
            if count != 6
                || tags != [0x91, 0x92, 0x93, 0x94, 0x95, 0x96]
                || self.lengths[0] != 4
                || self.lengths[1] != width
                || self.lengths[2] != width
                || self.lengths[3..].iter().any(|n| *n == 0 || *n > width)
            {
                return Err(Sw::WRONG_DATA);
            }
        } else if !(count == 1 || count == 2)
            || tags[0] != 0x92
            || (count == 2 && tags[1] != 0x99)
            || self.lengths[0] == 0
            || self.lengths[0] > width
            || self.lengths[1] > a.public() + 1
        {
            return Err(Sw::WRONG_DATA);
        }
        Ok(true)
    }
    pub fn feed(
        &mut self,
        bytes: &[u8],
        key: &mut [u8; 1284],
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        for &byte in bytes {
            self.received += 1;
            if !self.ready {
                if self.used == self.prefix.len() {
                    return Err(Sw::WRONG_DATA);
                }
                self.prefix[self.used] = byte;
                self.used += 1;
                self.ready = self.header(p)?;
                continue;
            }
            while self.component < 6 && self.offset == self.lengths[self.component] {
                self.component += 1;
                self.offset = 0;
            }
            if self.received > self.total || self.component == 6 {
                return Err(Sw::WRONG_LENGTH);
            }
            let a = self.algorithm;
            let i = self.component;
            let target = if a.rsa() {
                // Wire e,p,q,qinv,dp,dq -> explicit e,p,q,dp,dq,qinv.
                let bases = [0, 4, 260, 1028, 516, 772];
                let width = if i == 0 { 4 } else { a.scalar() };
                Some(bases[i] + width - self.lengths[i] + self.offset)
            } else if i == 0 {
                Some(a.scalar() - self.lengths[0] + self.offset)
            } else {
                None
            };
            if let Some(at) = target {
                key[at] = byte;
            }
            self.offset += 1;
        }
        Ok(())
    }
    pub fn finish(&self, key: &mut [u8; 1284]) -> Result<(), Sw> {
        if !self.ready || self.received != self.total {
            return Err(Sw::WRONG_LENGTH);
        }
        if self.algorithm.0 == 4 {
            key[..32].reverse();
        }
        Ok(())
    }
}
