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
    use super::{Feed, LengthState};

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
    }

    #[test]
    fn rejects_indefinite_and_overlong_lengths() {
        let mut state = LengthState::default();
        assert_eq!(state.feed(0x80), Feed::Invalid);
        let mut state = LengthState::default();
        assert_eq!(state.feed(0x83), Feed::Invalid);
    }
}
