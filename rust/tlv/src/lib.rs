// SPDX-License-Identifier: Apache-2.0
#![no_std]
#![forbid(unsafe_code)]

/// The layout of `tlv_len_stream_t` in common.h. All bit patterns are valid.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct LengthState {
    pub value: u16,
    pub count: u8,
    pub seen: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Feed {
    More,
    Complete(u16),
    Invalid,
}

impl LengthState {
    pub fn feed(&mut self, byte: u8) -> Feed {
        if self.count == 0 {
            if byte & 0x80 == 0 {
                return Feed::Complete(byte.into());
            }
            self.count = byte & 0x7f;
            if self.count == 0 || self.count > 2 {
                return Feed::Invalid;
            }
            self.seen = 0;
            self.value = 0;
            return Feed::More;
        }
        // Preserve the C unsigned-field behavior, including states resumed
        // after an error. Callers normally reset/discard an invalid stream.
        self.value = self.value.wrapping_shl(8) | u16::from(byte);
        self.seen = self.seen.wrapping_add(1);
        if self.seen != self.count {
            return Feed::More;
        }
        let length = self.value;
        *self = Self::default();
        Feed::Complete(length)
    }
}

/// Decode a length header without materializing its payload. `available` is the
/// total encoded length+payload capacity; only the prefix (at most 3 bytes) is read.
/// A complete header is returned even if its payload is truncated.
pub fn decode_length(prefix: &[u8], available: usize) -> (u16, Option<usize>, bool) {
    let (value, width) = match prefix {
        [first, ..] if *first < 0x80 => (u16::from(*first), 1),
        [0x81, byte, ..] => (u16::from(*byte), 2),
        [0x82, hi, lo, ..] => (u16::from_be_bytes([*hi, *lo]), 3),
        _ => return (0, None, false),
    };
    let valid = width <= available && usize::from(value) <= available - width;
    (value, Some(width), valid)
}
