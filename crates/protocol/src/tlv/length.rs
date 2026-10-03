// SPDX-License-Identifier: Apache-2.0
//! Incremental definite BER length, independent of any C state layout.
//! Accepts short form and one/two-byte long forms, including non-minimal BER
//! encodings. Indefinite lengths and lengths wider than u16 are rejected.
//! Writers may produce canonical lengths without requiring DER-only input.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LengthState {
    #[default]
    Initial,
    Long {
        remaining: u8,
        value: u16,
    },
    Failed,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Feed {
    More,
    Complete(u16),
    Invalid,
}
/// Decode a borrowed length prefix. None means incomplete input; Err means an
/// invalid BER length. Return the value and bytes consumed, leaving any body
/// bytes to the caller. Non-minimal definite encodings remain valid.
pub fn read_prefix(bytes: &[u8]) -> Result<Option<(u16, usize)>, super::Error> {
    let mut state = LengthState::Initial;
    for (i, &byte) in bytes.iter().enumerate() {
        match state.feed(byte) {
            Feed::More => (),
            Feed::Complete(n) => return Ok(Some((n, i + 1))),
            Feed::Invalid => return Err(super::Error::Invalid),
        }
    }
    Ok(None)
}
impl LengthState {
    pub fn feed(&mut self, byte: u8) -> Feed {
        match *self {
            Self::Initial if byte < 128 => Feed::Complete(u16::from(byte)),
            Self::Initial if matches!(byte, 0x81 | 0x82) => {
                *self = Self::Long {
                    remaining: byte & 0x7f,
                    value: 0,
                };
                Feed::More
            }
            Self::Long { remaining, value } => {
                let value = (value << 8) | u16::from(byte);
                if remaining == 1 {
                    *self = Self::Initial;
                    Feed::Complete(value)
                } else {
                    *self = Self::Long {
                        remaining: remaining - 1,
                        value,
                    };
                    Feed::More
                }
            }
            _ => {
                *self = Self::Failed;
                Feed::Invalid
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Feed, LengthState, read_prefix};

    fn compare_prefix(bytes: &[u8]) {
        let mut state = LengthState::Initial;
        let mut expected = Ok(None);
        for (i, &byte) in bytes.iter().enumerate() {
            match state.feed(byte) {
                Feed::More => (),
                Feed::Complete(n) => {
                    expected = Ok(Some((n, i + 1)));
                    break;
                }
                Feed::Invalid => {
                    expected = Err(super::super::Error::Invalid);
                    break;
                }
            }
        }
        assert_eq!(read_prefix(bytes), expected, "{bytes:?}");
    }

    #[test]
    fn accepts_short_and_long_lengths() {
        let mut state = LengthState::default();
        assert_eq!(state.feed(0x7f), Feed::Complete(127));
        assert_eq!(state.feed(0x81), Feed::More);
        assert_eq!(state.feed(0x80), Feed::Complete(128));
        assert_eq!(state.feed(0x82), Feed::More);
        assert_eq!(state.feed(0x01), Feed::More);
        assert_eq!(state.feed(0x02), Feed::Complete(258));
        assert_eq!(state.feed(0x20), Feed::Complete(32));
        // The borrowed reader must preserve the streaming grammar, including
        // non-minimal forms, partial prefixes and bytes after the length.
        compare_prefix(&[]);
        for n in 0..=u16::MAX {
            let [hi, lo] = n.to_be_bytes();
            compare_prefix(&[0x82, hi, lo, 0xff]);
            if hi == 0 {
                compare_prefix(&[0x81, lo, 0xff]);
                compare_prefix(&[0x82, lo]);
                if lo < 128 {
                    compare_prefix(&[lo, 0xff]);
                }
            }
        }
        compare_prefix(&[0x81]);
        compare_prefix(&[0x82]);
    }

    #[test]
    fn rejects_indefinite_and_overlong_lengths() {
        let mut state = LengthState::default();
        assert_eq!(state.feed(0x80), Feed::Invalid);
        let mut state = LengthState::default();
        assert_eq!(state.feed(0x83), Feed::Invalid);
        for first in (0x80..=0xff).filter(|first| !matches!(first, 0x81 | 0x82)) {
            compare_prefix(&[first]);
            compare_prefix(&[first, 0, 0]);
        }
    }
}
