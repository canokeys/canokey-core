// SPDX-License-Identifier: Apache-2.0
//! Key command policy and crypto-port calls; semantic buffers belong to runtime.
use super::{domain::role, encoding::Writer, import::object, protocol::OpenPgp};
use crate::{Platform, runtime::workspace::Workspace};
use canokey_protocol::{apdu::Header, response::StatusWord as Sw};
impl OpenPgp {
    #[inline(never)]
    pub(super) fn generate_key(
        &mut self,
        h: Header,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        let b = &w.input[..self.used];

        if h.p2 != 0 || !matches!(h.p1, 0x80 | 0x81) {
            return Err(Sw::WRONG_P1P2);
        }
        let r = crt(b)?;
        let (a, n) = self.session.public_key(r, h.p1 == 0x80, w, p)?;
        let mut prefix = [0; 12];
        let mut v = Writer::new(&mut prefix);
        let inner = if a.rsa() {
            n + 10
        } else {
            n + if a.0 == 3 || a.0 == 4 {
                2
            } else {
                if n + 1 < 128 { 3 } else { 4 }
            }
        };
        v.header(0x7f49, inner)?;
        if a.rsa() {
            v.header(0x81, n)?;
        } else {
            v.header(0x86, n + usize::from(a.0 != 3 && a.0 != 4))?;
            if a.0 != 3 && a.0 != 4 {
                v.bytes(&[4])?;
            }
        }
        let start = v.len;
        w.output.copy_within(..n, start);
        w.output[..start].copy_from_slice(&prefix[..start]);
        let mut end = start + n;
        if a.rsa() {
            w.output[end..end + 2].copy_from_slice(&[0x82, 4]);
            w.output[end + 2..end + 6].copy_from_slice(&w.key.bytes[..4]);
            end += 6;
        }
        Ok(end as u32)
    }
    #[inline(never)]
    pub(super) fn use_key(
        &mut self,
        h: Header,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        let b = &w.input[..self.used];
        let tag = u16::from_be_bytes([h.p1, h.p2]);

        let r = match (h.ins, tag) {
            (0x88, 0) => 2,
            (0x2a, 0x9e9a) => 0,
            (0x2a, 0x8086) => 1,
            _ => return Err(Sw::WRONG_P1P2),
        };
        let a = self.session.prepare(r, &mut w.key.bytes, p)?;
        let input = if r == 1 && a.rsa() {
            if b.len() != a.public() + 1 || b[0] != 0 {
                return Err(Sw::WRONG_LENGTH);
            }
            &b[1..]
        } else if r == 1 {
            let (t, b) = object(b)?;
            if t != 0xa6 {
                return Err(Sw::WRONG_DATA);
            }
            let (t, b) = object(b)?;
            if t != 0x7f49 {
                return Err(Sw::WRONG_DATA);
            }
            let (t, b) = object(b)?;
            if t != 0x86 {
                return Err(Sw::WRONG_DATA);
            }
            if a.0 == 4 {
                if b.len() != 32 {
                    return Err(Sw::WRONG_LENGTH);
                }
                b
            } else {
                if b.len() != a.public() + 1 || b[0] != 4 {
                    return Err(Sw::WRONG_DATA);
                }
                &b[1..]
            }
        } else {
            if b.is_empty()
                || a.rsa() && b.len() > a.public() * 2 / 5
                || !a.rsa() && a.0 != 3 && b.len() > a.scalar()
            {
                return Err(Sw::WRONG_LENGTH);
            }
            b
        };
        // Each checked envelope contains exactly one trailing value.
        let offset = self.used - input.len();
        let length = input.len();
        self.session
            .execute(r, a, offset..offset + length, w, p)
            .map(|n| n as u32)
            .map_err(Into::into)
    }
}
fn crt(b: &[u8]) -> Result<usize, Sw> {
    if b.len() != 2 && b.len() != 5 {
        return Err(Sw::WRONG_LENGTH);
    }
    if b[1] as usize + 2 != b.len() || (b.len() == 5 && b[2..] != [0x84, 1, 1]) {
        return Err(Sw::WRONG_DATA);
    }
    role(b[0]).ok_or(Sw::WRONG_DATA)
}
