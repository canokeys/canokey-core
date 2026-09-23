// SPDX-License-Identifier: Apache-2.0
//! OpenPGP data-object schema; persistence remains in the repository.
use super::{
    domain::Algorithm,
    encoding::Writer,
    pin,
    protocol::{AID, OpenPgp},
    repository::{self as repo, KEYS, io},
};
use crate::{Platform, ports::Record};
use canokey_protocol::response::StatusWord as Sw;
const HISTORY: &[u8] = &[0, 0x31, 0xc5, 0x73, 0xc0, 1, 0x80, 5, 0x90, 0];
const CAPS: &[u8] = &[0x74, 0, 1, 0, 4, 0x80, 0, 0xff, 0, 0];
impl OpenPgp {
    #[inline(never)]
    pub(super) fn get(&self, tag: u16, out: &mut [u8], p: &mut Platform<'_>) -> Result<usize, Sw> {
        let mut s = [0; repo::STATE_LEN];
        repo::state(p, &mut s)?;
        let mut v = Writer::new(out);
        if matches!(tag, 0x65 | 0x6e | 0x73 | 0x7a | 0xfa) {
            let start = v.open(tag)?;
            self.emit(tag, &mut v, &s, p)?;
            v.close(start)?;
        } else {
            self.emit(tag, &mut v, &s, p)?;
        }
        Ok(v.len)
    }
    fn emit(
        &self,
        tag: u16,
        v: &mut Writer<'_>,
        s: &[u8; repo::STATE_LEN],
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        if let Some((off, _)) = repo::field(tag) {
            return v.bytes(&s[off + 1..off + 1 + s[off] as usize]);
        }
        match tag {
            0x4f => {
                let mut serial = [0; 4];
                p.device.serial(&mut serial);
                v.bytes(AID)?;
                v.bytes(&[3, 4, 0xf1, 0xd0])?;
                v.bytes(&serial)?;
                v.bytes(&[0, 0])
            }
            0x5f52 => v.bytes(HISTORY),
            0x7f74 => v.bytes(&[0x81, 1, 0x20]),
            0xc0 => v.bytes(CAPS),
            0x65 | 0x6e | 0x73 => {
                let tags: &[u16] = match tag {
                    0x65 => &[0x5b, 0x5f2d, 0x5f35],
                    0x6e => &[0x4f, 0x5f52, 0x7f74, 0x73],
                    _ => &[
                        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xcd, 0xde, 0xd6, 0xd7, 0xd8,
                    ],
                };
                for &t in tags {
                    let at = v.open(t)?;
                    self.emit(t, v, s, p)?;
                    v.close(at)?;
                }
                Ok(())
            }
            0xc1..=0xc3 => {
                let r = (tag - 0xc1) as usize;
                let a = Algorithm(repo::meta(p, r)?[1]);
                let mut b = [0; 12];
                let n = a.attrs(r, &mut b);
                v.bytes(&b[..n])
            }
            0xc4 => {
                let pw1 = pin::info(Record::PgpPw1, p)?.1;
                let rc = pin::info(Record::PgpRc, p)?.1;
                let pw3 = pin::info(Record::PgpPw3, p)?.1;
                v.bytes(&[s[2], 64, 64, 64, pw1, rc, pw3])
            }
            0xc5 => {
                for r in 0..3 {
                    v.bytes(&repo::meta(p, r)?[4..24])?;
                }
                Ok(())
            }
            0xc6 => v.bytes(&s[8..68]),
            0xc7..=0xc9 => v.bytes(&repo::meta(p, (tag - 0xc7) as usize)?[4..24]),
            0xca..=0xcc => {
                let at = 8 + (tag - 0xca) as usize * 20;
                v.bytes(&s[at..at + 20])
            }
            0xcd => {
                for r in 0..3 {
                    v.bytes(&repo::meta(p, r)?[24..28])?;
                }
                Ok(())
            }
            0xce..=0xd0 => v.bytes(&repo::meta(p, (tag - 0xce) as usize)?[24..28]),
            0xd6..=0xd8 => v.bytes(&[repo::meta(p, (tag - 0xd6) as usize)?[3], 0x20]),
            0xde => {
                for r in 0..3 {
                    v.bytes(&[r as u8 + 1, repo::meta(p, r)?[2]])?;
                }
                Ok(())
            }
            0x7a => {
                v.header(0x93, 3)?;
                v.bytes(&repo::meta(p, 0)?[28..31])
            }
            0x0102 => v.bytes(&s[3..4]),
            0xfa => {
                for r in 0..3 {
                    for a in (0..9).map(Algorithm).filter(|a| a.allowed(r)) {
                        let mut b = [0; 12];
                        let n = a.attrs(r, &mut b);
                        v.header(0xc1 + r as u16, n)?;
                        v.bytes(&b[..n])?;
                    }
                }
                Ok(())
            }
            _ => Err(Sw(0x6a88)),
        }
    }
    #[inline(never)]
    pub(super) fn put(&mut self, tag: u16, b: &[u8], p: &mut Platform<'_>) -> Result<(), Sw> {
        if (0xc1..=0xc3).contains(&tag) {
            let r = (tag - 0xc1) as usize;
            let a = Algorithm::parse(b, r).ok_or(Sw::WRONG_DATA)?;
            let mut m = repo::meta(p, r)?;
            if m[1] != a.0 {
                m[1] = a.0;
                m[2] = 0;
                p.storage.replace(KEYS[r], &m).map_err(io)?;
            }
            return Ok(());
        }
        if (0xc7..=0xc9).contains(&tag)
            || (0xce..=0xd0).contains(&tag)
            || (0xd6..=0xd8).contains(&tag)
        {
            let (r, off, n) = if tag <= 0xc9 {
                ((tag - 0xc7) as usize, 4, 20)
            } else if tag <= 0xd0 {
                ((tag - 0xce) as usize, 24, 4)
            } else {
                ((tag - 0xd6) as usize, 3, 2)
            };
            if b.len() != n {
                return Err(Sw::WRONG_LENGTH);
            }
            let mut m = repo::meta(p, r)?;
            if off == 3 {
                if m[3] == 2 {
                    return Err(Sw::CONDITIONS_NOT_SATISFIED);
                }
                if b[0] > 2 || b[1] != 0x20 {
                    return Err(Sw::WRONG_DATA);
                }
                m[3] = b[0];
                self.session.clear_touch();
            } else {
                m[off..off + n].copy_from_slice(b);
            }
            return repo::put_meta(p, r, &m).map_err(Into::into);
        }
        if tag == 0xd3 {
            if b.is_empty() {
                let limit = pin::info(Record::PgpRc, p)?.2;
                return pin::create(Record::PgpRc, b, limit, p).map_err(Into::into);
            }
            return pin::change(Record::PgpRc, b, p).map_err(Into::into);
        }
        let mut s = [0; repo::STATE_LEN];
        repo::state(p, &mut s)?;
        if let Some((off, max)) = repo::field(tag) {
            if b.len() > max {
                return Err(Sw::WRONG_LENGTH);
            }
            s[off] = b.len() as u8;
            s[off + 1..off + 1 + max].fill(0);
            s[off + 1..off + 1 + b.len()].copy_from_slice(b);
        } else {
            match tag {
                0xc4 => {
                    if b.len() != 1 {
                        return Err(Sw::WRONG_LENGTH);
                    }
                    if b[0] > 1 {
                        return Err(Sw::WRONG_DATA);
                    }
                    s[2] = b[0];
                }
                0x0102 => {
                    if b.len() != 1 {
                        return Err(Sw::WRONG_LENGTH);
                    }
                    s[3] = b[0];
                    self.session.clear_touch();
                }
                0xca..=0xcc => {
                    if b.len() != 20 {
                        return Err(Sw::WRONG_LENGTH);
                    }
                    let at = 8 + (tag - 0xca) as usize * 20;
                    s[at..at + 20].copy_from_slice(b);
                }
                _ => return Err(Sw(0x6a88)),
            }
        }
        repo::save_state(p, &s).map_err(Into::into)
    }
}
