// SPDX-License-Identifier: Apache-2.0
//! Source-backed X.509 certificates. Only DER headers and small extensions are
//! retained; issuer/validity stay in storage and PQ public keys are regenerated.
use super::wire::object_tlv;
use super::{codec, repository as repo};
use crate::ports::{
    DigestOperation, EC_POINT_UNCOMPRESSED, HASH_STATE_BYTES, RSA_OUTPUT_BYTES, StreamOperation,
    alg, key_layout,
};
use crate::runtime::workspace::OUTPUT_BYTES;
use crate::{
    Platform,
    ports::{CryptoScratch, HashState, KeyMaterial, KeyOperation},
};
use canokey_protocol::response::StatusWord as Sw;
const DER_INTEGER: u8 = 0x02;
const DER_BIT_STRING: u8 = 0x03;
const DER_OID: u8 = 0x06;
const DER_SEQUENCE: u8 = 0x30;
const DER_VERSION_EXPLICIT: u8 = 0xa0;
const DER_SIGN_BIT: u8 = 0x80;
const DER_LONG_LENGTH: usize = 0x80;
const CERTIFICATE_SERIAL_BYTES: usize = 16;
// A certificate is emitted as a scatter/gather plan. Each three-word entry is
// [source selector, byte offset within that source, byte length]. Sources are
// small encoded bytes, the stored issuer certificate, or regenerated public key.
const MAX_SEGMENTS: usize = 18;
const SEGMENT_WORDS: usize = 3;
const SOURCE: usize = 0;
const OFFSET: usize = 1;
const LENGTH: usize = 2;
const SOURCE_ENCODED: usize = 0;
const SOURCE_ISSUER: usize = 1;
const SOURCE_PUBLIC: usize = 2;
const ENCODED_CAPACITY: usize = 256;
const SHA256_BYTES: usize = 32;
const P256_SIGNATURE_BYTES: usize = 64;
const P256_DER_SIGNATURE_MAX: usize = 72;
const HASH_CHUNK_BYTES: usize = 64;
// DER AlgorithmIdentifier for ecdsa-with-SHA256 (OID 1.2.840.10045.4.3.2).
const SIGNATURE_ALGORITHM: &[u8] = b"\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02";
pub struct Attestation {
    // Scalar backing keeps initialization in place on Thumb-1 (no aggregate stack copies).
    segments: [usize; MAX_SEGMENTS * SEGMENT_WORDS],
    count: usize,
    encoded: [u8; ENCODED_CAPACITY],
    used: usize,
    pub total: usize,
    public: Public,
    algorithm: usize,
}
// These states are mutually exclusive views of the existing public workspace.
// A classic subject retains only its public bytes while the key area is reused
// for the F9 signer. PQ generation is restarted after signing as before.
enum Public {
    Classic {
        key: KeyMaterial,
        bytes: [u8; OUTPUT_BYTES],
    },
    Pq(CryptoScratch),
}
impl Public {
    const fn new() -> Self {
        Self::Classic {
            key: KeyMaterial::new(),
            bytes: [0; OUTPUT_BYTES],
        }
    }
    fn clear(&mut self, memory: &crate::ports::MemoryPort<'_>) {
        match self {
            Self::Classic { key, bytes } => {
                memory.wipe(&mut key.bytes);
                key.bits = 0;
                key.reserved = 0;
                memory.wipe(bytes);
            }
            Self::Pq(s) => memory.wipe(&mut s.bytes),
        }
    }
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Classic { bytes, .. } => bytes,
            Self::Pq(_) => unreachable!(),
        }
    }
    #[inline(never)]
    fn classic(&mut self, memory: &crate::ports::MemoryPort<'_>) -> &mut KeyMaterial {
        if !matches!(self, Self::Classic { .. }) {
            self.clear(memory);
            // No const template: the enum-sized rodata copy costs more Flash
            // than in-place construction costs instructions.
            *self = Self::new();
        }
        let Self::Classic { key, .. } = self else {
            unreachable!()
        };
        key
    }
}
impl Attestation {
    pub const fn new() -> Self {
        Self {
            segments: [0; MAX_SEGMENTS * SEGMENT_WORDS],
            count: 0,
            encoded: [0; ENCODED_CAPACITY],
            used: 0,
            total: 0,
            public: Public::new(),
            algorithm: 0,
        }
    }
    pub(crate) fn clear(&mut self, memory: &crate::ports::MemoryPort<'_>) {
        memory.wipe(&mut self.encoded);
        self.public.clear(memory);
        self.segments.fill(0);
        self.count = 0;
        self.used = 0;
        self.total = 0;
        self.algorithm = 0;
    }
    fn segment(&mut self, source: usize, offset: usize, len: usize) -> Result<(), Sw> {
        if self.count == MAX_SEGMENTS {
            return Err(Sw::UNABLE_TO_PROCESS);
        }
        self.segments[self.count * SEGMENT_WORDS..self.count * SEGMENT_WORDS + SEGMENT_WORDS]
            .copy_from_slice(&[source, offset, len]);
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
            let last =
                &mut self.segments[(self.count - 1) * SEGMENT_WORDS..self.count * SEGMENT_WORDS];
            if last[SOURCE] == SOURCE_ENCODED && last[OFFSET] + last[LENGTH] == at {
                last[LENGTH] += b.len();
                self.total += b.len();
                return Ok(());
            }
        }
        self.segment(SOURCE_ENCODED, at, b.len())
    }
    fn certificate_serial(
        &mut self,
        serial: &mut [u8; CERTIFICATE_SERIAL_BYTES],
    ) -> Result<(), Sw> {
        // RFC 5280 requires a positive serial; DER INTEGER must be minimal.
        if serial.iter().all(|byte| *byte == 0) {
            serial[CERTIFICATE_SERIAL_BYTES - 1] = 1;
        }
        let first = serial.iter().position(|byte| *byte != 0).unwrap();
        let value = &serial[first..];
        let pad = usize::from(value[0] & DER_SIGN_BIT != 0);
        self.header(DER_INTEGER, value.len() + pad)?;
        if pad != 0 {
            self.bytes(&[0x00])?;
        }
        self.bytes(value)
    }
    fn header(&mut self, tag: u8, n: usize) -> Result<(), Sw> {
        let mut b = [0; 4];
        let n = codec::header(&mut b, &[tag], n)?;
        self.bytes(&b[..n])
    }
    fn wrap(&mut self, index: usize, start: usize, tag: u8) -> Result<(), Sw> {
        let mut b = [0; 4];
        let n = codec::header(&mut b, &[tag], self.total - start)?;
        if self.count == MAX_SEGMENTS || self.used + n > ENCODED_CAPACITY {
            return Err(Sw::UNABLE_TO_PROCESS);
        }
        self.segments.copy_within(
            index * SEGMENT_WORDS..self.count * SEGMENT_WORDS,
            (index + 1) * SEGMENT_WORDS,
        );
        self.segments[index * SEGMENT_WORDS..index * SEGMENT_WORDS + SEGMENT_WORDS]
            .copy_from_slice(&[SOURCE_ENCODED, self.used, n]);
        self.count += 1;
        self.encoded[self.used..self.used + n].copy_from_slice(&b[..n]);
        self.used += n;
        self.total += n;
        Ok(())
    }
    fn boundary(&mut self, b: &[u8]) -> Result<(), Sw> {
        let at = self.used;
        if at + b.len() > ENCODED_CAPACITY {
            return Err(Sw::UNABLE_TO_PROCESS);
        }
        self.encoded[at..at + b.len()].copy_from_slice(b);
        self.used += b.len();
        self.segment(SOURCE_ENCODED, at, b.len())
    }
    fn oid(&mut self, oid: &[u8]) -> Result<(), Sw> {
        self.header(DER_OID, oid.len())?;
        self.bytes(oid)
    }
    fn spki(&mut self, a: u8, n: usize) -> Result<(), Sw> {
        let index = self.count;
        let start = self.total;
        if repo::rsa(a) {
            self.boundary(b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00")?;
            let bi = self.count;
            let bs = self.total;
            self.boundary(&[0x00])?;
            let ri = self.count;
            let rs = self.total;
            for (offset, length) in [
                (0, n - key_layout::EXPONENT_BYTES),
                (n - key_layout::EXPONENT_BYTES, key_layout::EXPONENT_BYTES),
            ] {
                let data = &self.public.bytes()[offset..offset + length];
                let skip = data.iter().position(|v| *v != 0).unwrap_or(length - 1);
                let pad = usize::from(data[skip] & DER_SIGN_BIT != 0);
                let mut h = [0; 4];
                let hl = codec::header(&mut h, &[DER_INTEGER], length - skip + pad)?;
                self.boundary(&h[..hl])?;
                if pad != 0 {
                    self.bytes(&[0x00])?
                }
                self.segment(SOURCE_PUBLIC, offset + skip, length - skip)?;
            }
            self.wrap(ri, rs, DER_SEQUENCE)?;
            self.wrap(bi, bs, DER_BIT_STRING)?;
        } else {
            let oid: &[u8] = match a {
                alg::P256 => b"\x2a\x86\x48\xce\x3d\x03\x01\x07",
                alg::SECP256K1 => b"\x2b\x81\x04\x00\x0a",
                alg::P384 => b"\x2b\x81\x04\x00\x22",
                alg::P521 => b"\x2b\x81\x04\x00\x23",
                alg::SM2 => b"\x2a\x81\x1c\xcf\x55\x01\x82\x2d",
                alg::ED25519 => b"\x2b\x65\x70",
                alg::X25519 => b"\x2b\x65\x6e",
                alg::MLDSA65 => b"\x60\x86\x48\x01\x65\x03\x04\x03\x12",
                _ => return Err(Sw::WRONG_DATA),
            };
            let ec = matches!(
                a,
                alg::P256 | alg::SECP256K1 | alg::P384 | alg::P521 | alg::SM2
            );
            let ai = self.count;
            let ast = self.total;
            self.boundary(&[])?;
            if ec {
                self.oid(b"\x2a\x86\x48\xce\x3d\x02\x01")?
            }
            self.oid(oid)?;
            self.wrap(ai, ast, DER_SEQUENCE)?;
            self.header(DER_BIT_STRING, n + 1 + usize::from(ec))?;
            self.bytes(if ec {
                &[0x00, EC_POINT_UNCOMPRESSED]
            } else {
                &[0x00]
            })?;
            self.segment(SOURCE_PUBLIC, 0, n)?;
        }
        self.wrap(index, start, DER_SEQUENCE)
    }
    #[inline(never)]
    pub fn prepare(&mut self, id: usize, p: &mut Platform<'_>) -> Result<(), Sw> {
        let (issuer, validity) = parse_cert(p)?;
        let mut m = [0; repo::META];
        repo::read_meta(id, p, &mut m)?;
        if m[repo::ORIGIN] != 1 {
            return Err(Sw::REFERENCE_NOT_FOUND);
        }
        if m[repo::ALGORITHM] == alg::MLKEM768 {
            return Err(Sw::WRONG_DATA);
        }
        let mut signer = [0; repo::META];
        repo::read_meta(repo::ATTESTATION_KEY, p, &mut signer)?;
        if signer[repo::ORIGIN] == 0 || signer[repo::ALGORITHM] != alg::P256 {
            return Err(Sw::REFERENCE_NOT_FOUND);
        }
        self.algorithm = m[repo::ALGORITHM] as usize;
        let n = if m[repo::ALGORITHM] == alg::MLDSA65 {
            self.pq_public(id, p)?
        } else {
            self.classic_public(id, &m, p)?
        };
        (|| {
            self.bytes(b"\xa0\x03\x02\x01\x02")?;
            let mut serial = [0; CERTIFICATE_SERIAL_BYTES];
            p.crypto
                .random(&mut serial)
                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            self.certificate_serial(&mut serial)?;
            self.bytes(SIGNATURE_ALGORITHM)?;
            self.segment(SOURCE_ISSUER, issuer.0, issuer.1)?;
            self.segment(SOURCE_ISSUER, validity.0, validity.1)?;
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
            self.bytes(&m[repo::PIN_POLICY..repo::TOUCH_POLICY + 1])?;
            self.wrap(0, 0, DER_SEQUENCE)?;
            let mut digest = [0; SHA256_BYTES];
            self.hash(&mut digest, p)?;
            let mut sig = [0; P256_DER_SIGNATURE_MAX];
            if m[repo::ALGORITHM] == alg::MLDSA65 {
                self.abort_pq(p);
            }
            let key = self.public.classic(p.memory);
            let signed = sign(key, &signer, &digest, &mut sig, p);
            p.memory.wipe(&mut digest);
            let n = signed?;
            // Complete the F9 primitive before starting the response source.
            if m[repo::ALGORITHM] == alg::MLDSA65 {
                self.pq_public(id, p)?;
            }
            self.bytes(SIGNATURE_ALGORITHM)?;
            self.header(DER_BIT_STRING, n + 1)?;
            self.bytes(&[0x00])?;
            self.bytes(&sig[..n])?;
            self.wrap(0, 0, DER_SEQUENCE)
        })()
    }
    #[inline(never)]
    fn pq_public(&mut self, id: usize, p: &mut Platform<'_>) -> Result<usize, Sw> {
        self.public.clear(p.memory);
        // In-place init: a const CryptoScratch template would duplicate its
        // 2,400 zero bytes into rodata for a single copy.
        self.public = Public::Pq(CryptoScratch::new());
        let Public::Pq(s) = &mut self.public else {
            unreachable!()
        };
        super::protocol::init_public_stream(id, alg::MLDSA65, s, p)
    }
    fn abort_pq(&mut self, p: &mut Platform<'_>) {
        if let Public::Pq(s) = &mut self.public {
            let _ = p
                .crypto
                .stream(StreamOperation::Abort, alg::MLDSA65, s, &[], &mut []);
        }
    }
    #[inline(never)]
    fn classic_public(
        &mut self,
        id: usize,
        m: &[u8; repo::META],
        p: &mut Platform<'_>,
    ) -> Result<usize, Sw> {
        self.public.classic(p.memory);
        let Public::Classic { key, bytes } = &mut self.public else {
            unreachable!()
        };
        let result = (|| {
            repo::load(id, m, &mut key.bytes, p)?;
            let n = p
                .crypto
                .key_operation(KeyOperation::Public, m[repo::ALGORITHM], key, &[], bytes)
                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            if n > RSA_OUTPUT_BYTES {
                return Err(Sw::UNABLE_TO_PROCESS);
            }
            if repo::rsa(m[repo::ALGORITHM]) {
                bytes[n..n + key_layout::EXPONENT_BYTES]
                    .copy_from_slice(&key.bytes[..key_layout::EXPONENT_BYTES]);
                Ok(n + key_layout::EXPONENT_BYTES)
            } else {
                Ok(n)
            }
        })();
        p.memory.wipe(&mut key.bytes);
        result
    }
    #[inline(never)]
    fn hash(&mut self, digest: &mut [u8; SHA256_BYTES], p: &mut Platform<'_>) -> Result<(), Sw> {
        let mut state = HashState {
            bytes: [0; HASH_STATE_BYTES],
        };
        let result = (|| {
            p.crypto
                .digest(DigestOperation::Init, &mut state, &[], &mut [])
                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            let mut chunk = [0; HASH_CHUNK_BYTES];
            let mut off = 0;
            while off < self.total {
                let n = (self.total - off).min(HASH_CHUNK_BYTES);
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
        let count = out.len();
        let mut window = canokey_protocol::response::ReadWindow::new(offset, out);
        for s in self.segments[..self.count * SEGMENT_WORDS]
            .as_chunks::<SEGMENT_WORDS>()
            .0
        {
            let (start, dst) = window.take(s[LENGTH]);
            if !dst.is_empty() {
                let at = s[OFFSET] + start;
                match s[SOURCE] {
                    SOURCE_ENCODED => dst.copy_from_slice(&self.encoded[at..at + dst.len()]),
                    SOURCE_ISSUER => {
                        p.storage
                            .read_at(repo::OBJECTS[repo::ATTESTATION_KEY], at as u32, dst)
                            .map_err(repo::io)?;
                    }
                    _ => {
                        if self.algorithm == alg::MLDSA65 as usize {
                            let Public::Pq(scratch) = &mut self.public else {
                                return Err(Sw::UNABLE_TO_PROCESS);
                            };
                            let n = p
                                .crypto
                                .stream(StreamOperation::Read, alg::MLDSA65, scratch, &[], dst)
                                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                            if n != dst.len() {
                                return Err(Sw::UNABLE_TO_PROCESS);
                            }
                        } else {
                            dst.copy_from_slice(&self.public.bytes()[at..at + dst.len()])
                        }
                    }
                }
            }
        }
        Ok(count)
    }
    pub fn close(&mut self, p: &mut Platform<'_>) {
        if self.algorithm == alg::MLDSA65 as usize {
            self.abort_pq(p);
        }
        self.public.clear(p.memory);
        self.count = 0;
        self.used = 0;
        self.total = 0;
    }
}
#[inline(never)]
fn sign(
    key: &mut KeyMaterial,
    m: &[u8; repo::META],
    digest: &[u8; SHA256_BYTES],
    signature: &mut [u8; P256_DER_SIGNATURE_MAX],
    p: &mut Platform<'_>,
) -> Result<usize, Sw> {
    let mut out = [0; OUTPUT_BYTES];
    let result = (|| {
        repo::load(repo::ATTESTATION_KEY, m, &mut key.bytes, p)?;
        let n = p
            .crypto
            .key_operation(KeyOperation::EcSign, alg::P256, key, digest, &mut out)
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        if n != P256_SIGNATURE_BYTES {
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
    let error = Sw::REFERENCE_NOT_FOUND;
    if off + 2 > end {
        return Err(error);
    }
    let mut b = [0; 4];
    p.storage
        .read_at(
            repo::OBJECTS[repo::ATTESTATION_KEY],
            off as u32,
            &mut b[..2],
        )
        .map_err(|_| error)?;
    let mut h = 2;
    let mut len = b[1] as usize;
    if len & DER_LONG_LENGTH != 0 {
        let count = len & 127;
        if count == 0 || count > 2 || off + 2 + count > end {
            return Err(error);
        }
        p.storage
            .read_at(
                repo::OBJECTS[repo::ATTESTATION_KEY],
                (off + 2) as u32,
                &mut b[2..2 + count],
            )
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
    let e = Sw::REFERENCE_NOT_FOUND;
    let size = p
        .storage
        .size(repo::OBJECTS[repo::ATTESTATION_KEY])
        .map_err(|_| e)? as usize;
    let object = tlv(0, size, p)?;
    if object.tag != object_tlv::DATA {
        return Err(e);
    }
    let mut off = object.value;
    let end = off + object.len;
    let cert = loop {
        if off >= end {
            return Err(e);
        }
        let f = tlv(off, end, p)?;
        if f.tag == object_tlv::CERTIFICATE {
            break f;
        }
        off += f.total;
    };
    let outer = tlv(cert.value, cert.value + cert.len, p)?;
    if outer.tag != DER_SEQUENCE || outer.total != cert.len {
        return Err(e);
    }
    let tbs = tlv(outer.value, outer.value + outer.len, p)?;
    if tbs.tag != DER_SEQUENCE {
        return Err(e);
    }
    let end = tbs.value + tbs.len;
    off = tbs.value;
    let v = tlv(off, end, p)?;
    if v.tag == DER_VERSION_EXPLICIT {
        off += v.total
    }
    for tag in [DER_INTEGER, DER_SEQUENCE, DER_SEQUENCE] {
        let f = tlv(off, end, p)?;
        if f.tag != tag {
            return Err(e);
        }
        off += f.total;
    }
    let validity = tlv(off, end, p)?;
    if validity.tag != DER_SEQUENCE {
        return Err(e);
    }
    let vp = (off, validity.total);
    off += validity.total;
    let issuer = tlv(off, end, p)?;
    if issuer.tag != DER_SEQUENCE {
        return Err(e);
    }
    Ok(((off, issuer.total), vp))
}

#[cfg(test)]
mod serial_tests {
    use super::*;

    #[test]
    fn certificate_serial_is_a_minimal_positive_der_integer() {
        for (tail, expected) in [
            (&[0x00][..], &[DER_INTEGER, 0x01, 0x01][..]),
            (&[0x01][..], &[DER_INTEGER, 0x01, 0x01][..]),
            (&[0x7f][..], &[DER_INTEGER, 0x01, 0x7f][..]),
            (&[0x80][..], &[DER_INTEGER, 0x02, 0x00, 0x80][..]),
            (&[0x01, 0x00][..], &[DER_INTEGER, 0x02, 0x01, 0x00][..]),
        ] {
            let mut serial = [0; CERTIFICATE_SERIAL_BYTES];
            serial[CERTIFICATE_SERIAL_BYTES - tail.len()..].copy_from_slice(tail);
            let mut writer = Attestation::new();
            writer.certificate_serial(&mut serial).unwrap();
            assert_eq!(&writer.encoded[..writer.used], expected);
        }
        let mut serial = [0xff; CERTIFICATE_SERIAL_BYTES];
        let mut writer = Attestation::new();
        writer.certificate_serial(&mut serial).unwrap();
        assert_eq!(&writer.encoded[..3], &[DER_INTEGER, 0x11, 0x00]);
        assert_eq!(&writer.encoded[3..writer.used], &serial);
    }
}
