// SPDX-License-Identifier: Apache-2.0
//! Source-backed X.509 certificates. Only DER headers and small extensions are
//! retained; issuer/validity stay in storage and PQ public keys are regenerated.
use super::{codec, repository as repo};
use crate::ports::{DigestOperation, StreamOperation};
use crate::{
    Platform,
    ports::{CryptoScratch, HashState, KeyMaterial, KeyOperation},
};
use canokey_protocol::response::StatusWord as Sw;
const SIGNATURE: &[u8] = b"\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02";
pub struct Attestation {
    // Scalar backing keeps initialization in place on Thumb-1 (no aggregate stack copies).
    segments: [usize; 54],
    count: usize,
    encoded: [u8; 256],
    used: usize,
    pub total: usize,
    public: CryptoScratch,
    algorithm: usize,
}
impl Attestation {
    pub const fn new() -> Self {
        Self {
            segments: [0; 54],
            count: 0,
            encoded: [0; 256],
            used: 0,
            total: 0,
            public: CryptoScratch::new(),
            algorithm: 0,
        }
    }
    fn segment(&mut self, source: usize, offset: usize, len: usize) -> Result<(), Sw> {
        if self.count == 18 {
            return Err(Sw::UNABLE_TO_PROCESS);
        }
        self.segments[self.count * 3..self.count * 3 + 3].copy_from_slice(&[source, offset, len]);
        self.count += 1;
        self.total += len;
        Ok(())
    }
    fn bytes(&mut self, b: &[u8]) -> Result<(), Sw> {
        if self.used + b.len() > self.encoded.len() {
            return Err(Sw::UNABLE_TO_PROCESS);
        }
        let at = self.used;
        self.encoded[at..at + b.len()].copy_from_slice(b);
        self.used += b.len();
        if self.count > 0 {
            let last = &mut self.segments[(self.count - 1) * 3..self.count * 3];
            if last[0] == 0 && last[1] + last[2] == at {
                last[2] += b.len();
                self.total += b.len();
                return Ok(());
            }
        }
        self.segment(0, at, b.len())
    }
    fn header(&mut self, tag: u8, n: usize) -> Result<(), Sw> {
        let mut b = [0; 4];
        let n = codec::header(&mut b, &[tag], n)?;
        self.bytes(&b[..n])
    }
    fn wrap(&mut self, index: usize, start: usize, tag: u8) -> Result<(), Sw> {
        let mut b = [0; 4];
        let n = codec::header(&mut b, &[tag], self.total - start)?;
        if self.count == 18 || self.used + n > 256 {
            return Err(Sw::UNABLE_TO_PROCESS);
        }
        self.segments
            .copy_within(index * 3..self.count * 3, (index + 1) * 3);
        self.segments[index * 3..index * 3 + 3].copy_from_slice(&[0, self.used, n]);
        self.count += 1;
        self.encoded[self.used..self.used + n].copy_from_slice(&b[..n]);
        self.used += n;
        self.total += n;
        Ok(())
    }
    fn boundary(&mut self, b: &[u8]) -> Result<(), Sw> {
        let at = self.used;
        if at + b.len() > 256 {
            return Err(Sw::UNABLE_TO_PROCESS);
        }
        self.encoded[at..at + b.len()].copy_from_slice(b);
        self.used += b.len();
        self.segment(0, at, b.len())
    }
    fn oid(&mut self, oid: &[u8]) -> Result<(), Sw> {
        self.header(6, oid.len())?;
        self.bytes(oid)
    }
    fn spki(&mut self, a: u8, n: usize) -> Result<(), Sw> {
        let index = self.count;
        let start = self.total;
        if repo::rsa(a) {
            self.boundary(b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00")?;
            let bi = self.count;
            let bs = self.total;
            self.boundary(&[0])?;
            let ri = self.count;
            let rs = self.total;
            for (offset, length) in [(0, n - 4), (n - 4, 4)] {
                let data = &self.public.bytes[offset..offset + length];
                let skip = data.iter().position(|v| *v != 0).unwrap_or(length - 1);
                let pad = usize::from(data[skip] & 128 != 0);
                let mut h = [0; 4];
                let hl = codec::header(&mut h, &[2], length - skip + pad)?;
                self.boundary(&h[..hl])?;
                if pad != 0 {
                    self.bytes(&[0])?
                }
                self.segment(2, offset + skip, length - skip)?;
            }
            self.wrap(ri, rs, 0x30)?;
            self.wrap(bi, bs, 3)?;
        } else {
            let oid: &[u8] = match a {
                0 => b"\x2a\x86\x48\xce\x3d\x03\x01\x07",
                1 => b"\x2b\x81\x04\x00\x0a",
                2 => b"\x2b\x81\x04\x00\x22",
                8 => b"\x2b\x81\x04\x00\x23",
                9 => b"\x2a\x81\x1c\xcf\x55\x01\x82\x2d",
                3 => b"\x2b\x65\x70",
                4 => b"\x2b\x65\x6e",
                11 => b"\x60\x86\x48\x01\x65\x03\x04\x03\x12",
                _ => return Err(Sw::WRONG_DATA),
            };
            let ec = matches!(a, 0 | 1 | 2 | 8 | 9);
            let ai = self.count;
            let ast = self.total;
            self.boundary(&[])?;
            if ec {
                self.oid(b"\x2a\x86\x48\xce\x3d\x02\x01")?
            }
            self.oid(oid)?;
            self.wrap(ai, ast, 0x30)?;
            self.header(3, n + 1 + usize::from(ec))?;
            self.bytes(if ec { &[0, 4] } else { &[0] })?;
            self.segment(2, 0, n)?;
        }
        self.wrap(index, start, 0x30)
    }
    #[inline(never)]
    pub fn prepare(&mut self, id: usize, p: &mut Platform<'_>) -> Result<(), Sw> {
        let (issuer, validity) = parse_cert(p)?;
        let m = repo::meta(id, p)?;
        if m[repo::ORIGIN] != 1 {
            return Err(Sw(0x6a88));
        }
        if m[repo::ALGORITHM] == 10 {
            return Err(Sw::WRONG_DATA);
        }
        let signer = repo::meta(24, p)?;
        if signer[2] == 0 || signer[1] != 0 {
            return Err(Sw(0x6a88));
        }
        self.algorithm = m[repo::ALGORITHM] as usize;
        let n = if m[repo::ALGORITHM] == 11 {
            self.pq_public(id, p)?
        } else {
            self.classic_public(id, &m, p)?
        };
        (|| {
            self.bytes(b"\xa0\x03\x02\x01\x02")?;
            let mut serial = [0; 16];
            p.crypto
                .random(&mut serial)
                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            if serial.iter().all(|b| *b == 0) {
                serial[15] = 1
            }
            let pad = usize::from(serial[0] & 128 != 0);
            self.header(2, 16 + pad)?;
            if pad != 0 {
                self.bytes(&[0])?
            }
            self.bytes(&serial)?;
            self.bytes(SIGNATURE)?;
            self.segment(1, issuer.0, issuer.1)?;
            self.segment(1, validity.0, validity.1)?;
            self.bytes(
                b"\x30\x25\x31\x23\x30\x21\x06\x03\x55\x04\x03\x0c\x1aCanoKey PIV Attestation ",
            )?;
            let hex = b"0123456789abcdef";
            let slot = repo::SLOTS[id];
            self.bytes(&[hex[(slot >> 4) as usize], hex[(slot & 15) as usize]])?;
            self.spki(m[repo::ALGORITHM], n)?;
            self.bytes(
                b"\xa3\x28\x30\x26\x30\x12\x06\x0a\x2b\x06\x01\x04\x01\x84\x88\x2a\x01\x01\x04\x04",
            )?;
            let mut serial = [0; 4];
            p.device.serial(&mut serial);
            self.bytes(&serial)?;
            self.bytes(b"\x30\x10\x06\x0a\x2b\x06\x01\x04\x01\x84\x88\x2a\x01\x02\x04\x02")?;
            self.bytes(&m[repo::PIN_POLICY..5])?;
            self.wrap(0, 0, 0x30)?;
            let mut digest = [0; 32];
            self.hash(&mut digest, p)?;
            let mut sig = [0; 72];
            let signed = sign(&signer, &digest, &mut sig, p);
            p.memory.wipe(&mut digest);
            let n = signed?;
            // Complete the F9 primitive before starting the response source.
            if m[repo::ALGORITHM] == 11 {
                let _ =
                    p.crypto
                        .piv_stream(StreamOperation::Abort, 11, &mut self.public, &[], &mut []);
                self.pq_public(id, p)?;
            }
            self.bytes(SIGNATURE)?;
            self.header(3, n + 1)?;
            self.bytes(&[0])?;
            self.bytes(&sig[..n])?;
            self.wrap(0, 0, 0x30)
        })()
    }
    #[inline(never)]
    fn pq_public(&mut self, id: usize, p: &mut Platform<'_>) -> Result<usize, Sw> {
        let mut seed = [0; 32];
        let result = (|| {
            p.storage
                .read_at(repo::KEYS[id], repo::HEADER as u32, &mut seed)
                .map_err(repo::io)?;
            p.crypto
                .piv_stream(
                    StreamOperation::PublicInit,
                    11,
                    &mut self.public,
                    &seed,
                    &mut [],
                )
                .map_err(|_| Sw::UNABLE_TO_PROCESS)
        })();
        p.memory.wipe(&mut seed);
        result
    }
    #[inline(never)]
    fn classic_public(
        &mut self,
        id: usize,
        m: &[u8; repo::META],
        p: &mut Platform<'_>,
    ) -> Result<usize, Sw> {
        let mut key = KeyMaterial::new();
        let result = (|| {
            repo::load(id, m, &mut key.bytes, p)?;
            let n = p
                .crypto
                .key_operation(
                    KeyOperation::Public,
                    m[repo::ALGORITHM],
                    &mut key,
                    &[],
                    &mut self.public.bytes[..528],
                )
                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            if n > 512 {
                return Err(Sw::UNABLE_TO_PROCESS);
            }
            if repo::rsa(m[repo::ALGORITHM]) {
                self.public.bytes[n..n + 4].copy_from_slice(&key.bytes[..4]);
                Ok(n + 4)
            } else {
                Ok(n)
            }
        })();
        p.memory.wipe(&mut key.bytes);
        result
    }
    #[inline(never)]
    fn hash(&mut self, digest: &mut [u8; 32], p: &mut Platform<'_>) -> Result<(), Sw> {
        let mut state = HashState { bytes: [0; 256] };
        let result = (|| {
            p.crypto
                .digest(DigestOperation::Init, &mut state, &[], &mut [])
                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            let mut chunk = [0; 64];
            let mut off = 0;
            while off < self.total {
                let n = (self.total - off).min(64);
                self.read(off, &mut chunk[..n], p)?;
                p.crypto
                    .digest(DigestOperation::Update, &mut state, &chunk[..n], &mut [])
                    .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                off += n;
            }
            p.crypto
                .digest(DigestOperation::Final, &mut state, &[], digest)
                .map_err(|_| Sw::UNABLE_TO_PROCESS)
        })();
        let _ = p
            .crypto
            .digest(DigestOperation::Abort, &mut state, &[], &mut []);
        result
    }
    pub fn read(
        &mut self,
        offset: usize,
        out: &mut [u8],
        p: &mut Platform<'_>,
    ) -> Result<usize, Sw> {
        if offset.checked_add(out.len()).is_none_or(|n| n > self.total) {
            return Err(Sw::UNABLE_TO_PROCESS);
        }
        let mut pos = 0;
        let end = offset + out.len();
        for s in self.segments[..self.count * 3].as_chunks::<3>().0 {
            let lo = offset.max(pos);
            let hi = end.min(pos + s[2]);
            if lo < hi {
                let at = s[1] + lo - pos;
                let dst = &mut out[lo - offset..hi - offset];
                match s[0] {
                    0 => dst.copy_from_slice(&self.encoded[at..at + dst.len()]),
                    1 => {
                        p.storage
                            .read_at(repo::OBJECTS[24], at as u32, dst)
                            .map_err(repo::io)?;
                    }
                    _ => {
                        if self.algorithm == 11 {
                            let n = p
                                .crypto
                                .piv_stream(StreamOperation::Read, 11, &mut self.public, &[], dst)
                                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                            if n != dst.len() {
                                return Err(Sw::UNABLE_TO_PROCESS);
                            }
                        } else {
                            dst.copy_from_slice(&self.public.bytes[at..at + dst.len()])
                        }
                    }
                }
            }
            pos += s[2];
        }
        Ok(out.len())
    }
    pub fn close(&mut self, p: &mut Platform<'_>) {
        if self.algorithm == 11 {
            let _ = p
                .crypto
                .piv_stream(StreamOperation::Abort, 11, &mut self.public, &[], &mut []);
        }
        p.memory.wipe(&mut self.public.bytes);
        self.count = 0;
        self.used = 0;
        self.total = 0;
    }
}
#[inline(never)]
fn sign(
    m: &[u8; repo::META],
    digest: &[u8; 32],
    signature: &mut [u8; 72],
    p: &mut Platform<'_>,
) -> Result<usize, Sw> {
    let mut key = KeyMaterial::new();
    let mut out = [0; 528];
    let result = (|| {
        repo::load(24, m, &mut key.bytes, p)?;
        let n = p
            .crypto
            .key_operation(KeyOperation::EcSign, 0, &mut key, digest, &mut out)
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        if n != 64 {
            return Err(Sw::UNABLE_TO_PROCESS);
        }
        let n = super::protocol::der_signature(&mut out, n)?;
        signature[..n].copy_from_slice(&out[..n]);
        Ok(n)
    })();
    p.memory.wipe(&mut key.bytes);
    p.memory.wipe(&mut out);
    result
}
struct Tlv {
    tag: u8,
    value: usize,
    len: usize,
    total: usize,
}
fn tlv(off: usize, end: usize, p: &mut Platform<'_>) -> Result<Tlv, Sw> {
    let error = Sw(0x6a88);
    if off + 2 > end {
        return Err(error);
    }
    let mut b = [0; 4];
    p.storage
        .read_at(repo::OBJECTS[24], off as u32, &mut b[..2])
        .map_err(|_| error)?;
    let mut h = 2;
    let mut len = b[1] as usize;
    if len & 128 != 0 {
        let count = len & 127;
        if count == 0 || count > 2 || off + 2 + count > end {
            return Err(error);
        }
        p.storage
            .read_at(repo::OBJECTS[24], (off + 2) as u32, &mut b[2..2 + count])
            .map_err(|_| error)?;
        h += count;
        len = 0;
        for v in &b[2..h] {
            len = len * 256 + *v as usize
        }
        if len < 128 {
            return Err(error);
        }
    }
    if off + h + len > end {
        return Err(error);
    }
    Ok(Tlv {
        tag: b[0],
        value: off + h,
        len,
        total: h + len,
    })
}
type FileSpan = (usize, usize);
fn parse_cert(p: &mut Platform<'_>) -> Result<(FileSpan, FileSpan), Sw> {
    let e = Sw(0x6a88);
    let size = p.storage.size(repo::OBJECTS[24]).map_err(|_| e)? as usize;
    let object = tlv(0, size, p)?;
    if object.tag != 0x53 {
        return Err(e);
    }
    let mut off = object.value;
    let end = off + object.len;
    let cert = loop {
        if off >= end {
            return Err(e);
        }
        let f = tlv(off, end, p)?;
        if f.tag == 0x70 {
            break f;
        }
        off += f.total;
    };
    let outer = tlv(cert.value, cert.value + cert.len, p)?;
    if outer.tag != 0x30 || outer.total != cert.len {
        return Err(e);
    }
    let tbs = tlv(outer.value, outer.value + outer.len, p)?;
    if tbs.tag != 0x30 {
        return Err(e);
    }
    let end = tbs.value + tbs.len;
    off = tbs.value;
    let v = tlv(off, end, p)?;
    if v.tag == 0xa0 {
        off += v.total
    }
    for tag in [2, 0x30, 0x30] {
        let f = tlv(off, end, p)?;
        if f.tag != tag {
            return Err(e);
        }
        off += f.total;
    }
    let validity = tlv(off, end, p)?;
    if validity.tag != 0x30 {
        return Err(e);
    }
    let vp = (off, validity.total);
    off += validity.total;
    let issuer = tlv(off, end, p)?;
    if issuer.tag != 0x30 {
        return Err(e);
    }
    Ok(((off, issuer.total), vp))
}
