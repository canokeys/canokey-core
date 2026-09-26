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
