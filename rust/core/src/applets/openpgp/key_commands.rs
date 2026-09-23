// SPDX-License-Identifier: Apache-2.0
//! Key command policy and crypto-port calls; semantic buffers belong to runtime.
use super::domain::key_role;
use super::wire::{BufferRange, ins::*, key_tag};
use super::{domain::role, encoding::Writer, import::object, protocol::OpenPgp};
use crate::ports::EC_POINT_UNCOMPRESSED;
use crate::ports::alg;
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

        // GENERATE ASYMMETRIC KEY PAIR: P1=80 generates/replaces the key;
        // P1=81 only reads its public value. P2 is reserved (00); the body
        // control-reference template selects the signature/decipher/auth key.
        if h.p2 != 0x00 || !matches!(h.p1, 0x80 | 0x81) {
            return Err(Sw::WRONG_P1P2);
        }
        let r = parse_key_role(b)?;
        let (a, n) = self.session.public_key(r, h.p1 == 0x80, w, p)?;
        let mut prefix = [0; 12];
        let mut v = Writer::new(&mut prefix);
        // Outer 7F49 value length: RSA adds the modulus TLV header (4 bytes)
        // and exponent TLV (6 bytes). EC adds a point TLV header and, only for
        // Weierstrass curves, the SEC1 04 prefix; P-521 needs a long BER length.
        let inner = if a.rsa() {
            n + 10
        } else {
            n + if a.0 == alg::ED25519 || a.0 == alg::X25519 {
                2
            } else {
                if n + 1 < 128 { 3 } else { 4 }
            }
        };
        v.header(key_tag::PUBLIC_TEMPLATE, inner)?;
        if a.rsa() {
            v.header(key_tag::MODULUS, n)?;
        } else {
            v.header(
                key_tag::POINT,
                n + usize::from(a.0 != alg::ED25519 && a.0 != alg::X25519),
            )?;
            if a.0 != alg::ED25519 && a.0 != alg::X25519 {
                v.bytes(&[EC_POINT_UNCOMPRESSED])?;
            }
        }
        let start = v.len;
        w.output.copy_within(..n, start);
        w.output[..start].copy_from_slice(&prefix[..start]);
        let mut end = start + n;
        if a.rsa() {
            // RSA public output ends with 82 04 and the four-byte exponent.
            w.output[end..end + 2].copy_from_slice(&[key_tag::EXPONENT, 0x04]);
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
            (INS_INTERNAL_AUTHENTICATE, 0x0000) => key_role::AUTHENTICATION,
            (INS_PERFORM_SECURITY_OPERATION, key_tag::PSO_SIGNATURE) => key_role::SIGNATURE,
            (INS_PERFORM_SECURITY_OPERATION, key_tag::PSO_DECIPHER) => key_role::DECIPHER,
            _ => return Err(Sw::WRONG_P1P2),
        };
        let a = self.session.prepare(r, &mut w.key.bytes, p)?;
        let input = if r == key_role::DECIPHER && a.rsa() {
            if b.len() != a.public_value_bytes() + 1 || b[0] != 0 {
                return Err(Sw::WRONG_LENGTH);
            }
            &b[1..]
        } else if r == key_role::DECIPHER {
            let (t, b) = object(b)?;
            if t != key_tag::AGREEMENT_TEMPLATE {
                return Err(Sw::WRONG_DATA);
            }
            let (t, b) = object(b)?;
            if t != key_tag::PUBLIC_TEMPLATE {
                return Err(Sw::WRONG_DATA);
            }
            let (t, b) = object(b)?;
            if t != key_tag::POINT {
                return Err(Sw::WRONG_DATA);
            }
            if a.0 == alg::X25519 {
                if b.len() != 32 {
                    return Err(Sw::WRONG_LENGTH);
                }
                b
            } else {
                if b.len() != a.public_value_bytes() + 1 || b[0] != EC_POINT_UNCOMPRESSED {
                    return Err(Sw::WRONG_DATA);
                }
                &b[1..]
            }
        } else {
            // Preserve the C OpenPGP signature-input policy: RSA accepts at
            // most 2/5 of its modulus byte length; non-Ed EC accepts one scalar
            // width. This is an applet limit, not the PKCS#1 padding capacity.
            if b.is_empty()
                || a.rsa() && b.len() > a.public_value_bytes() * 2 / 5
                || !a.rsa() && a.0 != alg::ED25519 && b.len() > a.private_component_bytes()
            {
                return Err(Sw::WRONG_LENGTH);
            }
            b
        };
        // Each checked envelope contains exactly one trailing value.
        let input_range = BufferRange::tail(self.used, input.len()).ok_or(Sw::WRONG_LENGTH)?;
        self.session
            .execute(r, a, input_range.range(), w, p)
            .map(|n| n as u32)
            .map_err(Into::into)
    }
}
// Decode a Control Reference Template (CRT), not RSA CRT arithmetic.
// Accepted forms are [role, 00] or [role, 03, 84, 01, 01].
fn parse_key_role(b: &[u8]) -> Result<usize, Sw> {
    if b.len() != 2 && b.len() != 5 {
        return Err(Sw::WRONG_LENGTH);
    }
    if b[1] as usize + 2 != b.len() || (b.len() == 5 && b[2..] != key_tag::KEY_REFERENCE) {
        return Err(Sw::WRONG_DATA);
    }
    role(b[0]).ok_or(Sw::WRONG_DATA)
}
