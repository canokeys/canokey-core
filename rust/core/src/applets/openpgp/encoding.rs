// SPDX-License-Identifier: Apache-2.0
//! Bounded BER response encoding for metadata and semantic crypto output.
use canokey_protocol::response::StatusWord as Sw;

pub(super) struct BufferRange {
    start: usize,
    end: usize,
}
impl BufferRange {
    pub(super) fn new(start: usize, length: usize) -> Option<Self> {
        Some(Self {
            start,
            end: start.checked_add(length)?,
        })
    }
    pub(super) fn tail(total: usize, length: usize) -> Option<Self> {
        let start = total.checked_sub(length)?;
        Self::new(start, length)
    }
    pub(super) fn range(self) -> core::ops::Range<usize> {
        self.start..self.end
    }
}

pub(super) struct Writer<'a> {
    out: &'a mut [u8],
    pub(super) len: usize,
}
impl<'a> Writer<'a> {
    pub(super) fn new(out: &'a mut [u8]) -> Self {
        Self { out, len: 0 }
    }
    pub(super) fn bytes(&mut self, b: &[u8]) -> Result<(), Sw> {
        let end = self.len + b.len();
        self.out
            .get_mut(self.len..end)
            .ok_or(Sw::UNABLE_TO_PROCESS)?
            .copy_from_slice(b);
        self.len = end;
        Ok(())
    }
    pub(super) fn tag(&mut self, tag: u16) -> Result<(), Sw> {
        if tag > 255 {
            self.bytes(&tag.to_be_bytes())
        } else {
            self.bytes(&[tag as u8])
        }
    }
    pub(super) fn header(&mut self, tag: u16, n: usize) -> Result<(), Sw> {
        self.tag(tag)?;
        if n < 128 {
            self.bytes(&[n as u8])
        } else if n < 256 {
            self.bytes(&[0x81, n as u8])
        } else {
            self.bytes(&[0x82, (n >> 8) as u8, n as u8])
        }
    }
    // Reserve the longest supported BER length (82 hi lo). The returned
    // token is the value start; close() shrinks this prefix after encoding.
    pub(super) fn open(&mut self, tag: u16) -> Result<usize, Sw> {
        self.tag(tag)?;
        self.bytes(&[0x82, 0x00, 0x00])?;
        Ok(self.len)
    }
    pub(super) fn close(&mut self, start: usize) -> Result<(), Sw> {
        let n = self.len - start;
        // Canonical short/long BER lengths, shrinking the bounded metadata result.
        if n < 128 {
            self.out[start - 3] = n as u8;
            self.out.copy_within(start..self.len, start - 2);
            self.len -= 2;
        } else if n < 256 {
            self.out[start - 3] = 0x81;
            self.out[start - 2] = n as u8;
            self.out.copy_within(start..self.len, start - 1);
            self.len -= 1;
        } else {
            self.out[start - 2..start].copy_from_slice(&(n as u16).to_be_bytes());
        }
        Ok(())
    }
}
