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
