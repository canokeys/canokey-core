// SPDX-License-Identifier: Apache-2.0
//! CTAPHID report layout. USB SETUP has different (little-endian) wire fields.
pub const REPORT_SIZE: usize = 64;
pub const MAX_MESSAGE: usize = 57 + 128 * 59;
pub const BROADCAST: u32 = u32::MAX;
pub const PING: u8 = 0x81;
pub const INIT: u8 = 0x86;
pub const CBOR: u8 = 0x90;
pub const CANCEL: u8 = 0x91;
pub const ERROR: u8 = 0xbf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Error {
    Command = 1,
    Length = 3,
    Sequence = 4,
    Timeout = 5,
    Busy = 6,
    Channel = 0x0b,
    Other = 0x7f,
}

pub struct Report<'a> {
    pub cid: u32,
    pub tag: u8,
    pub length: Option<usize>,
    pub data: &'a [u8],
}
impl<'a> Report<'a> {
    pub fn decode(bytes: &'a [u8; REPORT_SIZE]) -> Self {
        let initial = bytes[4] & 0x80 != 0;
        Self {
            cid: u32::from_be_bytes(bytes[..4].try_into().unwrap()),
            tag: bytes[4],
            length: initial.then(|| u16::from_be_bytes([bytes[5], bytes[6]]) as usize),
            data: &bytes[if initial { 7 } else { 5 }..],
        }
    }
}

/// The caller retains the finished report until the endpoint completes it.
pub fn header(out: &mut [u8; REPORT_SIZE], cid: u32, tag: u8, length: usize) -> &mut [u8] {
    out.fill(0);
    out[..4].copy_from_slice(&cid.to_be_bytes());
    out[4] = tag;
    if tag & 0x80 != 0 {
        out[5..7].copy_from_slice(&(length as u16).to_be_bytes());
        &mut out[7..]
    } else {
        &mut out[5..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn literal_wire_order() {
        let mut bytes = [0; 64];
        bytes[..8].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x81, 0x01, 0x23, 0xab]);
        let report = Report::decode(&bytes);
        assert_eq!(
            (report.cid, report.tag, report.length),
            (0x12345678, PING, Some(291))
        );
        assert_eq!(report.data[0], 0xab);
        header(&mut bytes, 0x12345678, PING, 291)[0] = 0xab;
        assert_eq!(
            &bytes[..8],
            &[0x12, 0x34, 0x56, 0x78, 0x81, 0x01, 0x23, 0xab]
        );
        header(&mut bytes, 0x12345678, 0x7f, 0)[0] = 0xcd;
        assert_eq!(&bytes[..6], &[0x12, 0x34, 0x56, 0x78, 0x7f, 0xcd]);
    }
}
