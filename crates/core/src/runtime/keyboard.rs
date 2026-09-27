// SPDX-License-Identifier: Apache-2.0
//! US keyboard encoding and completion-driven press/release sequencing.
#![forbid(unsafe_code)]

pub struct Keyboard {
    release_id: u8,
}
impl Default for Keyboard {
    fn default() -> Self {
        Self::new()
    }
}
impl Keyboard {
    pub const fn new() -> Self {
        Self { release_id: 0 }
    }
    pub fn ready(&self, endpoint_idle: bool) -> bool {
        endpoint_idle && self.release_id == 0
    }
    /// The caller retains the report unchanged until endpoint completion.
    /// Call accepted only after a successful submission; a failed submission
    /// must retry the same bytes without consuming another character.
    pub fn prepare(&self, character: Option<u8>, report: &mut [u8; 8]) -> Option<usize> {
        self.prepare_usage(character.and_then(ascii), report)
    }
    pub fn prepare_usage(&self, usage: Option<(u8, u8)>, report: &mut [u8; 8]) -> Option<usize> {
        report.fill(0);
        if self.release_id != 0 {
            report[0] = self.release_id;
            return Some(if self.release_id == 2 { 2 } else { 8 });
        }
        let (modifier, usage) = usage?;
        report[0] = 1;
        report[1] = modifier;
        report[3] = usage;
        Some(8)
    }
    pub fn prepare_eject(&self, report: &mut [u8; 8]) -> Option<usize> {
        if self.release_id != 0 {
            return self.prepare_usage(None, report);
        }
        report.fill(0);
        report[0] = 2;
        report[1] = 0xb8;
        Some(2)
    }
    pub fn accepted(&mut self, report_id: u8) {
        self.release_id = if self.release_id == 0 { report_id } else { 0 };
    }
}
/// Preserve the legacy QWERTY layout and CR-only Enter convention.
pub fn ascii(ch: u8) -> Option<(u8, u8)> {
    // One packed byte per ASCII value: bit 7 selects left Shift; zero skips.
    let key = *US_ASCII.get(usize::from(ch))?;
    (key != 0).then_some((if key & 0x80 != 0 { 2 } else { 0 }, key & 0x7f))
}
const US_ASCII: [u8; 128] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00,
    0x00, // ASCII 00..0f
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // ASCII 10..1f
    0x2c, 0x9e, 0xb4, 0xa0, 0xa1, 0xa2, 0xa4, 0x34, 0xa6, 0xa7, 0xa5, 0xae, 0x36, 0x2d, 0x37,
    0x38, // ASCII 20..2f
    0x27, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0xb3, 0x33, 0xb6, 0x2e, 0xb7,
    0xb8, // ASCII 30..3f
    0x9f, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91,
    0x92, // ASCII 40..4f
    0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x2f, 0x31, 0x30, 0xa3,
    0xad, // ASCII 50..5f
    0x35, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
    0x12, // ASCII 60..6f
    0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0xaf, 0xb1, 0xb0, 0xb5,
    0x00, // ASCII 70..7f
];

#[cfg(test)]
fn legacy_ascii(ch: u8) -> Option<(u8, u8)> {
    let key = match ch {
        b'a'..=b'z' => 4 + ch - b'a',
        b'A'..=b'Z' => (4 + ch - b'A') | 0x80,
        b'1'..=b'9' => 30 + ch - b'1',
        b'0' => 39,
        b'\r' => 0x28,
        b' ' => 0x2c,
        b'!' => 0x1e | 0x80,
        b'"' => 0x34 | 0x80,
        b'#' => 0x20 | 0x80,
        b'$' => 0x21 | 0x80,
        b'%' => 0x22 | 0x80,
        b'&' => 0x24 | 0x80,
        b'\'' => 0x34,
        b'(' => 0x26 | 0x80,
        b')' => 0x27 | 0x80,
        b'*' => 0x25 | 0x80,
        b'+' => 0x2e | 0x80,
        b',' => 0x36,
        b'-' => 0x2d,
        b'.' => 0x37,
        b'/' => 0x38,
        b':' => 0x33 | 0x80,
        b';' => 0x33,
        b'<' => 0x36 | 0x80,
        b'=' => 0x2e,
        b'>' => 0x37 | 0x80,
        b'?' => 0x38 | 0x80,
        b'@' => 0x1f | 0x80,
        b'[' => 0x2f,
        b'\\' => 0x31,
        b']' => 0x30,
        b'^' => 0x23 | 0x80,
        b'_' => 0x2d | 0x80,
        b'`' => 0x35,
        b'{' => 0x2f | 0x80,
        b'|' => 0x31 | 0x80,
        b'}' => 0x30 | 0x80,
        b'~' => 0x35 | 0x80,
        _ => return None,
    };
    Some((if key & 0x80 != 0 { 2 } else { 0 }, key & 0x7f))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packed_table_matches_legacy_mapping_for_every_byte() {
        for ch in 0..=255 {
            assert_eq!(ascii(ch), legacy_ascii(ch), "{ch}");
        }
    }
    #[test]
    fn all_printable_ascii_has_a_report() {
        for ch in 32..=126 {
            assert!(ascii(ch).is_some(), "{ch}");
        }
        for ch in [0, 9, 10, 127, 128, 255] {
            assert_eq!(ascii(ch), None);
        }
        assert_eq!(ascii(b'\r'), Some((0, 40)));
        assert_eq!(ascii(b'A'), Some((2, 4)));
        assert_eq!(ascii(b'z'), Some((0, 29)));
        assert_eq!(ascii(b'0'), Some((0, 39)));
        assert_eq!(ascii(b'@'), Some((2, 31)));
        assert_eq!(ascii(b'\\'), Some((0, 49)));
    }
    #[test]
    fn eject_uses_consumer_report_and_matching_release() {
        let mut keyboard = Keyboard::new();
        let mut report = [0xff; 8];
        assert_eq!(keyboard.prepare_eject(&mut report), Some(2));
        assert_eq!(report, [2, 0xb8, 0, 0, 0, 0, 0, 0]);
        keyboard.accepted(report[0]);
        assert!(!keyboard.ready(true));
        assert_eq!(keyboard.prepare(None, &mut report), Some(2));
        assert_eq!(report, [2, 0, 0, 0, 0, 0, 0, 0]);
        keyboard.accepted(report[0]);
        assert!(keyboard.ready(true));
    }
    #[test]
    fn press_then_release_before_next_character() {
        let mut keyboard = Keyboard::new();
        let mut report = [0xff; 8];
        assert!(!keyboard.ready(false));
        assert!(keyboard.ready(true));
        assert_eq!(keyboard.prepare(Some(b'A'), &mut report), Some(8));
        assert_eq!(report, [1, 2, 0, 4, 0, 0, 0, 0]);
        // Preparation alone must not advance the sequence on a failed send.
        assert!(keyboard.ready(true));
        keyboard.accepted(report[0]);
        assert!(!keyboard.ready(true));
        assert_eq!(keyboard.prepare(None, &mut report), Some(8));
        assert_eq!(report, [1, 0, 0, 0, 0, 0, 0, 0]);
        keyboard.accepted(report[0]);
        assert!(!keyboard.ready(false));
        assert!(keyboard.ready(true));
    }
}
