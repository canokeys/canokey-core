// SPDX-License-Identifier: Apache-2.0
//! The import envelope is bounded; component values stream directly into the
//! session key. No encoded-key buffer and no flash writes before validation.
use super::repository::key_meta;
use super::wire::{key_tag, limits};
use super::{
    domain::{Algorithm, role},
    repository,
};
use crate::Platform;
use crate::ports::alg;
use crate::ports::key_layout;
use canokey_protocol::{
    response::StatusWord as Sw,
    tlv::length::{Feed, LengthState},
};
fn length(b: &[u8], at: &mut usize) -> Result<Option<usize>, Sw> {
    // This parser is intentionally local: import headers arrive incrementally
    // and must report "incomplete" separately from malformed BER. The shared
    // protocol helpers parse complete TLVs and cannot provide that distinction.
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
// Complete headers need no event callback or streaming decoder state. Match
// the streaming decoder's tag grammar and retain incomplete vs invalid errors.
fn object_header(b: &[u8]) -> Result<(u16, usize, usize), Sw> {
    let mut at = 0;
    loop {
        let byte = *b.get(at).ok_or(Sw::WRONG_LENGTH)?;
        if at == 3 || (at == 1 && byte & 0x7f == 0) {
            return Err(Sw::WRONG_DATA);
        }
        let last = if at == 0 {
            byte & 0x1f != 0x1f
        } else {
            byte & 0x80 == 0
        };
        at += 1;
        if last {
            break;
        }
    }
    let tag_end = at;
    let size = length(b, &mut at)?.ok_or(Sw::WRONG_LENGTH)?;
    // The streaming parser rejects wide tags when their complete header is
    // emitted, not before: a truncated three-byte-tag header is WRONG_LENGTH.
    if tag_end > 2 {
        return Err(Sw::WRONG_DATA);
    }
    let tag = if tag_end == 1 {
        u16::from(b[0])
    } else {
        u16::from_be_bytes([b[0], b[1]])
    };
    Ok((tag, at, size))
}

/// Parse exactly one complete BER object, borrowing its value without copying.
pub fn object(b: &[u8]) -> Result<(u16, &[u8]), Sw> {
    if b.is_empty() {
        return Err(Sw::WRONG_DATA);
    }
    let (tag, at, size) = object_header(b)?;
    let (value, tail) = b[at..].split_at_checked(size).ok_or(Sw::WRONG_LENGTH)?;
    if !tail.is_empty() {
        // A complete sibling header is forbidden; an incomplete trailing
        // header must still report WRONG_LENGTH, just like Decoder::finish.
        object_header(tail)?;
        return Err(Sw::WRONG_DATA);
    }
    Ok((tag, value))
}

pub struct Import {
    // Only the 4D envelope, control reference and 7F48/5F48 descriptors
    // are buffered. Private component bytes bypass this prefix buffer.
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
            algorithm: Algorithm(alg::RSA2048),
            ready: false,
        }
    }
    // Reparse the bounded prefix after each byte: false means incomplete,
    // not invalid. No private component has been consumed when this returns true.
    fn header(&mut self, p: &mut Platform<'_>) -> Result<bool, Sw> {
        let b = &self.prefix[..self.used];
        if b[0] != key_tag::IMPORT {
            return Err(Sw::WRONG_DATA);
        }
        let mut at = 1;
        let Some(n) = length(b, &mut at)? else {
            return Ok(false);
        };
        self.total = at + n;
        if self.total > usize::from(limits::KEY_IMPORT_BYTES) {
            return Err(Sw::WRONG_LENGTH);
        }
        let Some(&r) = b.get(at) else {
            return Ok(false);
        };
        self.role = role(r).ok_or(Sw::WRONG_DATA)?;
        at += 1;
        let Some(&control_reference_len) = b.get(at) else {
            return Ok(false);
        };
        at += 1;
        if !matches!(control_reference_len, 0 | 3) {
            return Err(Sw::WRONG_DATA);
        }
        if b.len() < at + control_reference_len as usize {
            return Ok(false);
        }
        if control_reference_len == 3 && b[at..at + 3] != key_tag::KEY_REFERENCE {
            return Err(Sw::WRONG_DATA);
        }
        at += control_reference_len as usize;
        if b.len() < at + 2 {
            return Ok(false);
        }
        if b[at..at + 2] != key_tag::COMPONENT_LENGTHS {
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
        if b[at..at + 2] != key_tag::COMPONENT_VALUES {
            return Err(Sw::WRONG_DATA);
        }
        at += 2;
        let Some(n) = length(b, &mut at)? else {
            return Ok(false);
        };
        if at + n != self.total || self.lengths.iter().sum::<usize>() != n {
            return Err(Sw::WRONG_LENGTH);
        }
        self.algorithm = Algorithm(repository::meta(p, self.role)?[key_meta::ALGORITHM]);
        let a = self.algorithm;
        let width = a.private_component_bytes();
        if a.rsa() {
            if count != 6
                || tags != key_tag::RSA_COMPONENTS
                || self.lengths[0] != 4
                || self.lengths[1] != width
                || self.lengths[2] != width
                || self.lengths[3..].iter().any(|n| *n == 0 || *n > width)
            {
                return Err(Sw::WRONG_DATA);
            }
        } else if !(count == 1 || count == 2)
            || tags[0] != key_tag::PRIVATE
            || (count == 2 && tags[1] != key_tag::PUBLIC)
            || self.lengths[0] == 0
            || self.lengths[0] > width
            || self.lengths[1] > a.public_value_bytes() + 1
        {
            return Err(Sw::WRONG_DATA);
        }
        Ok(true)
    }
    pub fn feed(
        &mut self,
        bytes: &[u8],
        key: &mut [u8; crate::ports::key_layout::SIZE],
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
                let bases = [
                    key_layout::EXPONENT,
                    key_layout::P,
                    key_layout::Q,
                    key_layout::QINV,
                    key_layout::DP,
                    key_layout::DQ,
                ];
                let width = if i == 0 {
                    key_layout::EXPONENT_BYTES
                } else {
                    a.private_component_bytes()
                };
                Some(bases[i] + width - self.lengths[i] + self.offset)
            } else if i == 0 {
                Some(a.private_component_bytes() - self.lengths[0] + self.offset)
            } else {
                // An optional supplied EC public key is length-checked but not
                // trusted: the crypto adapter derives it from the private key.
                None
            };
            if let Some(at) = target {
                key[at] = byte;
            }
            self.offset += 1;
        }
        Ok(())
    }
    pub fn finish(&self, key: &mut [u8; crate::ports::key_layout::SIZE]) -> Result<(), Sw> {
        if !self.ready || self.received != self.total {
            return Err(Sw::WRONG_LENGTH);
        }
        if self.algorithm.0 == alg::X25519 {
            key[..32].reverse();
        }
        Ok(())
    }
}

#[cfg(test)]
mod object_tests {
    use super::*;
    use canokey_protocol::tlv::{Decoder, Error as TlvError, Event};

    fn compare(bytes: &[u8]) {
        let actual = object(bytes);
        let expected = reference_object(bytes);
        assert_eq!(actual, expected, "input: {bytes:02x?}");
        if let Ok((_, value)) = actual {
            // A successful value is a borrow of the original object's suffix.
            assert_eq!(value.as_ptr(), bytes[bytes.len() - value.len()..].as_ptr());
        }
    }

    #[test]
    fn complete_objects_match_streaming_grammar_and_trailing_errors() {
        compare(&[]);
        for first in 0..=u8::MAX {
            compare(&[first]);
            for second in 0..=u8::MAX {
                compare(&[first, second]);
                for third in [0, 1, 0x1f, 0x7f, 0x80, 0x81, 0x82, 0xff] {
                    compare(&[first, second, third]);
                    compare(&[0x30, 0, first, second, third]);
                }
            }
        }
        for bytes in [
            &b"\x7f\x81\x01\x00"[..],
            &b"\x7f\x81\x81\x01\x00"[..],
            &b"\x7f\x81\x01\x82\x00"[..],
            &b"\x30\x00\x7f\x81\x01\x00"[..],
        ] {
            for n in 0..=bytes.len() {
                compare(&bytes[..n]);
            }
        }
    }

    #[test]
    fn complete_objects_accept_ber_lengths_and_reject_each_truncation() {
        let mut bytes = [0x5a; 65540];
        for tag in [&b"\x30"[..], &b"\x5f\x2d"[..]] {
            for size in [0u16, 1, 127, 128, 255, 256, 513, u16::MAX] {
                for form in 0..=2 {
                    if (form == 0 && size >= 128) || (form == 1 && size >= 256) {
                        continue;
                    }
                    bytes[..tag.len()].copy_from_slice(tag);
                    let [hi, lo] = size.to_be_bytes();
                    let encoded = match form {
                        0 => [lo, 0, 0],
                        1 => [0x81, lo, 0],
                        _ => [0x82, hi, lo],
                    };
                    let at = tag.len() + form + 1;
                    bytes[tag.len()..at].copy_from_slice(&encoded[..form + 1]);
                    let end = at + usize::from(size);
                    for n in 0..=end {
                        compare(&bytes[..n]);
                    }
                    assert_eq!(object(&bytes[..end]).unwrap().1.len(), usize::from(size));
                }
            }
        }
    }

    /// Parse a complete BER object, returning its tag and value without allocation.
    fn reference_object(b: &[u8]) -> Result<(u16, &[u8]), Sw> {
        if b.is_empty() {
            return Err(Sw::WRONG_DATA);
        }
        let mut decoder = Decoder::default();
        let mut tag = None;
        let mut value_seen = false;
        decoder
            .feed(b, &mut |event| {
                match event {
                    Event::Start {
                        tag: encoded,
                        length,
                    } => {
                        if tag.is_some() || encoded.bytes().len() > 2 {
                            return Err(TlvError::Invalid);
                        }
                        let bytes = encoded.bytes();
                        let number = bytes
                            .iter()
                            .fold(0u16, |n, byte| (n << 8) | u16::from(*byte));
                        tag = Some((number, usize::from(length)));
                    }
                    Event::Value(bytes) => {
                        if value_seen || bytes.is_empty() {
                            return Err(TlvError::Invalid);
                        }
                        value_seen = true;
                    }
                    Event::End => (),
                }
                Ok(())
            })
            .map_err(|error| match error {
                TlvError::Truncated => Sw::WRONG_LENGTH,
                _ => Sw::WRONG_DATA,
            })?;
        decoder.finish().map_err(|error| match error {
            TlvError::Truncated => Sw::WRONG_LENGTH,
            _ => Sw::WRONG_DATA,
        })?;
        let (tag, length) = tag.ok_or(Sw::WRONG_DATA)?;
        if length > b.len() || (length != 0 && !value_seen) {
            return Err(Sw::WRONG_LENGTH);
        }
        let value = &b[b.len() - length..];
        Ok((tag, value))
    }
}
