// SPDX-License-Identifier: Apache-2.0
// Fixed Core dcf88037 SM2 codec; product load/save omitted, portable import adjusted.
#[derive(Clone, Copy)]
pub(crate) struct Sm2 {
    pub curve: i32,
    pub algorithm: i32,
}
impl Sm2 {
    pub const DEFAULT: Self = Self {
        curve: 9,       // CanoKey private COSE curve identifier for SM2.
        algorithm: -54, // CanoKey private COSE algorithm identifier for SM2.
    };
    pub fn encode(self) -> [u8; 8] {
        let mut wire = [0; 8];
        wire[..4].copy_from_slice(&self.curve.to_be_bytes());
        wire[4..].copy_from_slice(&self.algorithm.to_be_bytes());
        wire
    }
    pub(super) fn decode(wire: &[u8]) -> Option<Self> {
        if wire.len() != 8 {
            return None;
        }
        let value = Self {
            curve: i32::from_be_bytes(wire[..4].try_into().ok()?),
            algorithm: i32::from_be_bytes(wire[4..].try_into().ok()?),
        };
        // Same reserved COSE identifiers as the C profile.
        if matches!(value.curve, 0..=8 | 256..=259)
            || matches!(value.algorithm, -7 | -8)
            || canokey_ports::mldsa::from_cose(value.algorithm).is_some()
        {
            return None;
        }
        Some(value)
    }
}
