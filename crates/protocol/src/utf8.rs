// SPDX-License-Identifier: Apache-2.0
//! Compact RFC 3629 UTF-8 validation for short protocol strings.
//!
//! `core::str::from_utf8` and `chars().count()` are unrolled for throughput
//! and cost about 600 bytes on Thumb-1. CTAP and CBOR strings are at most a few
//! hundred bytes, so one byte-at-a-time state machine serves every caller.
//! Validation matches `core::str::from_utf8` exactly: it rejects overlong
//! forms, UTF-16 surrogates (U+D800..U+DFFF) and scalars above U+10FFFF.

/// Incremental validator that carries at most one partial scalar between calls.
#[derive(Clone, Copy)]
pub struct Validator {
    /// Continuation bytes still required by the current scalar.
    need: u8,
    /// Inclusive bounds for the next continuation byte. Only the first
    /// continuation byte after E0, ED, F0 and F4 is narrower than 80..=BF.
    low: u8,
    high: u8,
}

const CONTINUATION_LOW: u8 = 0x80;
const CONTINUATION_HIGH: u8 = 0xbf;

impl Validator {
    pub const fn new() -> Self {
        Self {
            need: 0,
            low: CONTINUATION_LOW,
            high: CONTINUATION_HIGH,
        }
    }

    /// Accept one byte. False means no continuation can make the input valid.
    pub fn push(&mut self, byte: u8) -> bool {
        if self.need != 0 {
            if byte < self.low || byte > self.high {
                return false;
            }
            self.need -= 1;
            self.low = CONTINUATION_LOW;
            self.high = CONTINUATION_HIGH;
            return true;
        }
        // RFC 3629 section 4: lead byte, continuation count and the range of
        // the first continuation byte.
        let (need, low, high) = match byte {
            0x00..=0x7f => return true,
            0xc2..=0xdf => (1, CONTINUATION_LOW, CONTINUATION_HIGH),
            0xe0 => (2, 0xa0, CONTINUATION_HIGH),
            0xed => (2, CONTINUATION_LOW, 0x9f),
            0xe1..=0xef => (2, CONTINUATION_LOW, CONTINUATION_HIGH),
            0xf0 => (3, 0x90, CONTINUATION_HIGH),
            0xf1..=0xf3 => (3, CONTINUATION_LOW, CONTINUATION_HIGH),
            0xf4 => (3, CONTINUATION_LOW, 0x8f),
            _ => return false,
        };
        *self = Self { need, low, high };
        true
    }

    /// True when no scalar is partially consumed.
    pub fn complete(&self) -> bool {
        self.need == 0
    }
}

impl Default for Validator {
    fn default() -> Self {
        Self::new()
    }
}

/// Bytes preceding the first invalid or truncated scalar; equal to
/// `core::str::Utf8Error::valid_up_to` for invalid input.
pub fn valid_up_to(bytes: &[u8]) -> usize {
    let mut validator = Validator::new();
    let mut end = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        if !validator.push(byte) {
            break;
        }
        if validator.complete() {
            end = index + 1;
        }
    }
    end
}

/// Borrow valid UTF-8 as text.
#[allow(unsafe_code)]
pub fn str(bytes: &[u8]) -> Option<&str> {
    if valid_up_to(bytes) != bytes.len() {
        return None;
    }
    // SAFETY: valid_up_to accepted every byte as part of a complete RFC 3629
    // scalar; the tests compare it with core::str::from_utf8 exhaustively for
    // every sequence of up to three bytes and every four-byte lead/continuation
    // boundary.
    Some(unsafe { core::str::from_utf8_unchecked(bytes) })
}

/// Unicode scalar values in text: every byte except continuation bytes.
pub fn chars(text: &str) -> usize {
    text.bytes()
        .filter(|byte| !(CONTINUATION_LOW..=CONTINUATION_HIGH).contains(byte))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(bytes: &[u8]) {
        let expected = core::str::from_utf8(bytes);
        assert_eq!(str(bytes), expected.ok(), "{bytes:02x?}");
        match expected {
            Ok(text) => {
                assert_eq!(valid_up_to(bytes), bytes.len());
                assert_eq!(chars(text), text.chars().count());
            }
            Err(error) => assert_eq!(valid_up_to(bytes), error.valid_up_to(), "{bytes:02x?}"),
        }
        // Streaming: an invalid byte is reported where the standard library
        // finds an error with a length; truncation is not invalid.
        let mut validator = Validator::new();
        let accepted = bytes.iter().all(|&byte| validator.push(byte));
        match expected {
            Ok(_) => assert!(accepted && validator.complete()),
            Err(error) if error.error_len().is_none() => {
                assert!(accepted && !validator.complete(), "{bytes:02x?}")
            }
            Err(_) => assert!(!accepted, "{bytes:02x?}"),
        }
    }

    #[test]
    fn every_sequence_of_up_to_three_bytes_matches_core() {
        check(&[]);
        for a in 0..=0xff_u8 {
            check(&[a]);
            for b in 0..=0xff_u8 {
                check(&[a, b]);
                for c in 0..=0xff_u8 {
                    check(&[a, b, c]);
                }
            }
        }
    }

    #[test]
    fn four_byte_boundaries_match_core() {
        // Boundary values around every range used by the state machine.
        let edges = [
            0x00, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xc1, 0xc2, 0xdf, 0xe0, 0xe1,
            0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf3, 0xf4, 0xf5, 0xff,
        ];
        for a in 0..=0xff_u8 {
            for &b in &edges {
                for &c in &edges {
                    for &d in &edges {
                        check(&[a, b, c, d]);
                        check(&[0x41, a, b, c, d]);
                    }
                }
            }
        }
    }

    #[test]
    fn mixed_text_counts_scalars() {
        let text = "a\u{7f}\u{80}\u{7ff}\u{800}\u{d7ff}\u{e000}\u{ffff}\u{10000}\u{10ffff}";
        check(text.as_bytes());
        assert_eq!(chars(text), 10);
    }
}
