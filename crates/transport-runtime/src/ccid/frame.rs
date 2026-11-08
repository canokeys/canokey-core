// SPDX-License-Identifier: Apache-2.0
//! CCID envelope accounting; payload length never includes the ten-byte header.
use canokey_protocol::ccid::{HEADER, payload_length};

pub(super) enum Fragment<'a> {
    Header(&'a [u8; HEADER]),
    Body { offset: usize, bytes: &'a [u8] },
}
pub(super) struct Frame {
    pub header: [u8; HEADER],
    header_bytes: u8,
    remaining: u32,
}
impl Frame {
    pub const fn new() -> Self {
        Self {
            header: [0x00; HEADER],
            header_bytes: 0,
            remaining: 0,
        }
    }
    pub fn complete(&self) -> bool {
        usize::from(self.header_bytes) == HEADER && self.remaining == 0
    }
    pub fn started(&self) -> bool {
        self.header_bytes != 0
    }
    pub fn has_header(&self) -> bool {
        usize::from(self.header_bytes) == HEADER
    }
    pub fn length(&self) -> u32 {
        payload_length(&self.header)
    }
    /// Deliver only declared bytes. Header and body callbacks borrow disjoint
    /// product input state synchronously and cannot retain a reference to Frame.
    /// Return the trailing byte count for the product's final-packet policy.
    pub fn feed(&mut self, mut bytes: &[u8], mut consume: impl FnMut(Fragment<'_>)) -> usize {
        while !bytes.is_empty() && !self.complete() {
            if !self.has_header() {
                let offset = usize::from(self.header_bytes);
                let length = bytes.len().min(HEADER - offset);
                self.header[offset..offset + length].copy_from_slice(&bytes[..length]);
                self.header_bytes += length as u8;
                bytes = &bytes[length..];
                if self.has_header() {
                    self.remaining = self.length();
                    consume(Fragment::Header(&self.header));
                }
            } else {
                let length = bytes.len().min(self.remaining as usize);
                let offset = (self.length() - self.remaining) as usize;
                consume(Fragment::Body {
                    offset,
                    bytes: &bytes[..length],
                });
                self.remaining -= length as u32;
                bytes = &bytes[length..];
            }
        }
        bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maximum_payload_is_not_truncated_by_header_addition() {
        let mut frame = Frame::new();
        assert_eq!(
            frame.feed(
                &[0x6f, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00],
                |_| {}
            ),
            0
        );
        assert_eq!(frame.remaining, u32::MAX);
        frame.feed(&[0x5a; 64], |_| {});
        assert_eq!(frame.remaining, u32::MAX - 64);
        assert!(!frame.complete());
        // Simulate the already-drained prefix to inspect the exact last-byte
        // transition without allocating or replaying a four-gigabyte fixture.
        frame.remaining = 10;
        let mut offset = 0;
        frame.feed(&[0x5a; 9], |fragment| {
            if let Fragment::Body {
                offset: body_offset,
                ..
            } = fragment
            {
                offset = body_offset;
            }
        });
        assert_eq!(offset, (u32::MAX - 10) as usize);
        assert!(!frame.complete());
        frame.feed(&[0x5a], |_| {});
        assert!(frame.complete());
    }
}
