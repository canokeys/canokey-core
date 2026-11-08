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
        let end = self.len.checked_add(b.len()).ok_or(Sw::UNABLE_TO_PROCESS)?;
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
        let n = u16::try_from(n).map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        self.tag(tag)?;
        self.len += canokey_protocol::tlv::write_length(n, &mut self.out[self.len..])
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        Ok(())
    }
    // Reserve the longest supported BER length (82 hi lo). The returned
    // token is the value start; close() shrinks this prefix after encoding.
    pub(super) fn open(&mut self, tag: u16) -> Result<usize, Sw> {
        self.tag(tag)?;
        self.bytes(&[0x82, 0x00, 0x00])?;
        Ok(self.len)
    }
    pub(super) fn close(&mut self, start: usize) -> Result<(), Sw> {
        let n = self.len.checked_sub(start).ok_or(Sw::UNABLE_TO_PROCESS)?;
        let n16 = u16::try_from(n).map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        if start < 3 {
            return Err(Sw::UNABLE_TO_PROCESS);
        }
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
            self.out[start - 2..start].copy_from_slice(&n16.to_be_bytes());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_ber_length_is_not_truncated() {
        let mut out = [0xa5; 8];
        let mut writer = Writer::new(&mut out);
        assert_eq!(writer.header(0x7f49, 65536), Err(Sw::UNABLE_TO_PROCESS));
        assert_eq!(writer.len, 0);
        assert_eq!(out, [0xa5; 8]);
    }

    #[test]
    fn incomplete_container_and_exhausted_output_fail_without_panicking() {
        let mut out = [0; 8];
        let mut writer = Writer::new(&mut out);
        assert_eq!(writer.close(0), Err(Sw::UNABLE_TO_PROCESS));
        let start = writer.open(0x7f49).unwrap();
        assert_eq!(writer.close(start + 1), Err(Sw::UNABLE_TO_PROCESS));
        writer.bytes(&[1; 3]).unwrap();
        assert_eq!(writer.bytes(&[2]), Err(Sw::UNABLE_TO_PROCESS));
        writer.close(start).unwrap();
        assert_eq!(writer.len, 6);
        assert_eq!(&out[..6], &[0x7f, 0x49, 3, 1, 1, 1]);
    }
}
