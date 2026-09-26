// SPDX-License-Identifier: Apache-2.0
//! Key generation, public-key encoding and private operations.
use super::*;
use crate::ports::EC_POINT_UNCOMPRESSED;
use crate::ports::alg;
use crate::ports::sm2_packet;
use crate::runtime::workspace::agreement_layout as agreement;

fn parse_sm2_packet(
    exp: &mut &[u8],
    own: Option<&[u8]>,
) -> Result<([u8; sm2_packet::SIZE], usize), Sw> {
    let mut packet = [0; sm2_packet::SIZE];
    for (tag, at) in [
        (ga_tag::PEER_STATIC, sm2_packet::PEER_STATIC),
        (ga_tag::PEER_EPHEMERAL, sm2_packet::PEER_EPHEMERAL),
    ] {
        let (t, v) = codec::take(exp)?;
        if t != tag || v.len() != 65 || v[0] != EC_POINT_UNCOMPRESSED {
            return Err(Sw::WRONG_DATA);
        }
        packet[at..at + 64].copy_from_slice(&v[1..]);
    }
    let default = b"1234567812345678";
    packet[sm2_packet::PEER_ID] = 16;
    packet[sm2_packet::PEER_ID + 1..sm2_packet::PEER_ID + 1 + default.len()]
        .copy_from_slice(default);
    if exp.first() == Some(&ga_tag::PEER_ID) {
        let (_, v) = codec::take(exp)?;
        if v.is_empty() || v.len() > 32 {
            return Err(Sw::WRONG_DATA);
        }
        packet[sm2_packet::PEER_ID] = v.len() as u8;
        packet[sm2_packet::PEER_ID + 1..sm2_packet::PEER_ID + 1 + v.len()].copy_from_slice(v);
    }
    packet[sm2_packet::OWN_ID] = 16;
    packet[sm2_packet::OWN_ID + 1..sm2_packet::OWN_ID + 1 + default.len()].copy_from_slice(default);
    if let Some(v) = own {
        if v.len() > 32 {
            return Err(Sw::WRONG_DATA);
        }
        packet[sm2_packet::OWN_ID] = v.len() as u8;
        packet[sm2_packet::OWN_ID + 1..sm2_packet::OWN_ID + 1 + v.len()].copy_from_slice(v);
    }
    let mut klen = 16;
    if !exp.is_empty() {
        let (t, v) = codec::take(exp)?;
        if t != ga_tag::OUTPUT_LENGTH || v.len() != 2 {
            return Err(Sw::WRONG_DATA);
        }
        klen = u16::from_be_bytes(v.try_into().unwrap()) as usize;
    }
    if !exp.is_empty() || klen == 0 || klen > 128 {
        return Err(Sw::WRONG_DATA);
    }
    Ok((packet, klen))
}

impl Piv {
    #[inline(never)]
    pub(super) fn public(
        &mut self,
        id: usize,
        m: &[u8; repo::META],
        metadata: bool,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        if m[repo::ORIGIN] == 0 {
            return Err(Sw::REFERENCE_NOT_FOUND);
        }
        let a = m[repo::ALGORITHM];
        if a >= alg::MLKEM768 {
            self.pending_public = Some(PendingPublicKey {
                slot_index: id,
                include_metadata: metadata,
                generated_algorithm: None,
            });
            return Ok((if a == alg::MLKEM768 {
                crate::ports::mlkem768::PUBLIC_BYTES
            } else {
                crate::ports::mldsa65::PUBLIC_BYTES
            }) as u32);
        }
        repo::load(id, m, &mut w.key.bytes, p)?;
        let n = p
            .crypto
            .key_operation(KeyOperation::Public, a, &mut w.key, &[], &mut w.output)
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        self.memory(n);
        let mut at = 0;
        if metadata {
            at = self.metadata_header(a, m);
        }
        if repo::rsa(a) {
            // RSA body: modulus TLV (4-byte header for 2048..4096 bits),
            // then exponent TLV (2-byte header plus the 4-byte exponent).
            const MODULUS_HEADER_BYTES: usize = 4;
            const EXPONENT_TLV_BYTES: usize = 6;
            let inner = n + MODULUS_HEADER_BYTES + EXPONENT_TLV_BYTES;
            at += codec::header(
                &mut self.header[at..],
                if metadata {
                    &[metadata_tag::PUBLIC_KEY]
                } else {
                    &key_tag::PUBLIC_TEMPLATE
                },
                inner,
            )?;
            at += codec::header(&mut self.header[at..], &[key_tag::MODULUS], n)?;
            self.suffix[..2].copy_from_slice(&[key_tag::EXPONENT, 0x04]);
            self.suffix[2..].copy_from_slice(&w.key.bytes[..4]);
            self.suffix_len = 6;
        } else {
            let point = usize::from(a != alg::ED25519 && a != alg::X25519);
            let inner = n + point + if n + point < 128 { 2 } else { 3 };
            at += codec::header(
                &mut self.header[at..],
                if metadata {
                    &[metadata_tag::PUBLIC_KEY]
                } else {
                    &key_tag::PUBLIC_TEMPLATE
                },
                inner,
            )?;
            at += codec::header(&mut self.header[at..], &[key_tag::PUBLIC_POINT], n + point)?;
            if point != 0 {
                self.header[at] = EC_POINT_UNCOMPRESSED;
                at += 1;
            }
        }
        self.header_len = at;
        Ok((at + n + self.suffix_len) as u32)
    }
    #[inline(never)]
    pub(super) fn generate(
        &mut self,
        h: Header,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        self.authorized()?;
        if self.used < 5 {
            return Err(Sw::WRONG_LENGTH);
        }
        // GENERATE KEY: P1 is reserved (00), P2 selects the destination slot.
        // Algorithm and policies are carried in the AC data template.
        if h.p1 != 0x00 {
            return Err(Sw::WRONG_P1P2);
        }
        let id = repo::slot(h.p2)?;
        let mut b = codec::object(&w.input[..self.used], key_tag::GENERATION_TEMPLATE)?;
        let (t, v) = codec::take(&mut b)?;
        if t != key_tag::ALGORITHM || v.len() != 1 {
            return Err(Sw::WRONG_DATA);
        }
        let a = repo::algorithm(v[0], &self.config)?;
        if id == repo::ATTESTATION_KEY && a != alg::P256 {
            return Err(Sw::WRONG_DATA);
        }
        let mut m = [0; repo::META];
        repo::read_meta(id, p, &mut m)?;
        m[repo::ALGORITHM] = a;
        m[repo::ORIGIN] = 1;
        m[repo::NAME_LENGTH..].fill(0);
        repo::policies(&mut m, b)?;
        if a >= alg::MLKEM768 {
            p.crypto
                .random(&mut w.key.bytes[..repo::material(a)])
                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        } else {
            p.crypto
                .key_operation(KeyOperation::Generate, a, &mut w.key, &[], &mut w.output)
                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        }
        if a >= alg::MLKEM768 {
            // Keep the previous slot untouched until the final public chunk.
            // Only the compact metadata/seed record is staged, never the public key.
            self.pending_commit = Some(id as u8);
            p.storage.stage_begin().map_err(repo::io)?;
            p.storage
                .stage_append(&m[..repo::HEADER])
                .map_err(repo::io)?;
            p.storage
                .stage_append(&w.key.bytes[..repo::material(a)])
                .map_err(repo::io)?;
            self.pending_public = Some(PendingPublicKey {
                slot_index: id,
                include_metadata: false,
                generated_algorithm: Some(a),
            });
            Ok(0) // finish_public supplies the encoded streaming response length.
        } else {
            repo::save(id, &m, &w.key.bytes, p)?;
            self.public(id, &m, false, w, p)
        }
    }
    #[inline(never)]
    pub(super) fn general_authenticate(
        &mut self,
        h: Header,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        let mut fields: [Option<&[u8]>; 6] = [None; 6];
        for (i, field) in fields.iter_mut().enumerate() {
            *field = self.ga.field(i, &w.input);
        }
        if h.p2 == reference::MANAGEMENT {
            return self.management_auth(h, &fields, w.output.as_mut_slice(), p);
        }
        let id = repo::slot(h.p2)?;
        let mut m = [0; repo::META];
        repo::read_meta(id, p, &mut m)?;
        if m[repo::ORIGIN] == 0 {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        let a = repo::algorithm(h.p1, &self.config).map_err(|_| Sw::WRONG_P1P2)?;
        if a != m[repo::ALGORITHM] {
            return Err(Sw::WRONG_P1P2);
        }
        if fields[ga_field::WITNESS].is_some() || fields[ga_field::RESPONSE] != Some(&[][..]) {
            return Err(Sw::WRONG_DATA);
        }
        self.auth_clear(p);
        // GA operation selection is in the nested tags: 81 carries signing/
        // RSA input, 85 carries agreement input, and empty 82 requests output.
        // SM2 without 81 enters its dedicated multi-step agreement protocol.
        if a == alg::SM2 && fields[ga_field::CHALLENGE].is_none() {
            return self.sm2_agree(id, &m, w, p);
        }
        let (op, data) = if let Some(input) = fields[ga_field::CHALLENGE] {
            if fields[ga_field::EXPONENTIATION].is_some() || input.is_empty() {
                return Err(Sw::WRONG_DATA);
            }
            if repo::rsa(a) {
                if input.len() != repo::width(a) * 2 {
                    return Err(Sw::WRONG_LENGTH);
                }
                (KeyOperation::RsaRaw, input)
            } else if a == alg::X25519 {
                return Err(Sw::WRONG_DATA);
            } else {
                if a != alg::ED25519
                    && (input.len() > repo::width(a) || (a == alg::SM2 && input.len() != 32))
                {
                    return Err(Sw::WRONG_LENGTH);
                }
                (KeyOperation::EcSign, input)
            }
        } else if let Some(peer) = fields[ga_field::EXPONENTIATION] {
            // F9 is signing-only; Ed25519/RSA do not implement this ECDH
            // form. SM2 must use its identity-bound key-exchange protocol,
            // never plain ECDH with the same static key.
            if id == repo::ATTESTATION_KEY || a == alg::ED25519 || a == alg::SM2 || repo::rsa(a) {
                return Err(Sw::WRONG_DATA);
            }
            if a == alg::X25519 {
                if peer.len() != 32 {
                    return Err(Sw::WRONG_DATA);
                }
                (KeyOperation::Agree, peer)
            } else {
                if peer.len() != repo::width(a) * 2 + 1 || peer[0] != EC_POINT_UNCOMPRESSED {
                    return Err(Sw::WRONG_DATA);
                }
                (KeyOperation::Agree, &peer[1..])
            }
        } else {
            return Err(Sw::WRONG_DATA);
        };
        // Validate the operation shape completely before consuming a touch.
        self.touch(m[repo::TOUCH_POLICY], p)?;
        self.authorize_private(m[repo::PIN_POLICY])?;
        repo::load(id, &m, &mut w.key.bytes, p)?;
        // C PIV left-pads digest integers to the curve width. The native
        // primitive requires that exact width (including P-521's leading byte).
        const P521_BYTES: usize = 66;
        let mut padded = [0; P521_BYTES];
        let data = if matches!(op, KeyOperation::EcSign) && a != alg::ED25519 {
            let width = repo::width(a);
            padded[width - data.len()..width].copy_from_slice(data);
            &padded[..width]
        } else {
            data
        };
        let mut n = p
            .crypto
            .key_operation(op, a, &mut w.key, data, &mut w.output)
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        if matches!(op, KeyOperation::EcSign) && a != alg::ED25519 && a != alg::SM2 {
            n = der_signature(&mut w.output, n)?;
        }
        self.wrapped(n)
    }
    fn sm2_step2(
        &mut self,
        packet: &mut [u8; sm2_packet::SIZE],
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        p.crypto
            .key_operation(
                KeyOperation::Public,
                alg::SM2,
                &mut w.key,
                &[],
                &mut w.output,
            )
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        if !codec::equal(
            &w.output[..64],
            &w.agreement[agreement::STATIC_PUBLIC..agreement::ID_LENGTH],
        ) {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        packet[..32].copy_from_slice(&w.agreement[agreement::SCALAR..agreement::EPHEMERAL_PUBLIC]);
        let n = w.agreement[agreement::ID_LENGTH] as usize;
        if n > 0 {
            packet[sm2_packet::OWN_ID] = n as u8;
            packet[sm2_packet::OWN_ID + 1..sm2_packet::OWN_ID + 1 + n]
                .copy_from_slice(&w.agreement[agreement::ID..agreement::ID + n]);
        }
        w.key.bytes[..32].copy_from_slice(&packet[..32]);
        p.crypto
            .key_operation(
                KeyOperation::Public,
                alg::SM2,
                &mut w.key,
                &[],
                &mut w.output,
            )
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        if !codec::equal(
            &w.output[..64],
            &w.agreement[agreement::EPHEMERAL_PUBLIC..agreement::STATIC_PUBLIC],
        ) {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        self.clear_agreement(w, p);
        Ok(())
    }

    fn sm2_responder(
        packet: &mut [u8; sm2_packet::SIZE],
        own: Option<&[u8]>,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<[u8; 65], Sw> {
        if let Some(v) = own {
            packet[sm2_packet::OWN_ID] = v.len() as u8;
            packet[sm2_packet::OWN_ID + 1..sm2_packet::OWN_ID + 1 + v.len()].copy_from_slice(v);
        }
        p.crypto
            .key_operation(
                KeyOperation::Generate,
                alg::SM2,
                &mut w.key,
                &[],
                &mut w.output,
            )
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        packet[..32].copy_from_slice(&w.key.bytes[..32]);
        p.crypto
            .key_operation(
                KeyOperation::Public,
                alg::SM2,
                &mut w.key,
                &[],
                &mut w.output,
            )
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        let mut ephemeral = [0; 65];
        ephemeral[0] = EC_POINT_UNCOMPRESSED;
        ephemeral[1..].copy_from_slice(&w.output[..64]);
        Ok(ephemeral)
    }

    #[inline(never)]
    pub(super) fn sm2_agree(
        &mut self,
        id: usize,
        m: &[u8; repo::META],
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        let result = (|| {
            let field = |i: usize| self.ga.field(i, &w.input);
            if field(ga_field::RESPONSE) != Some(&[][..]) {
                return Err(Sw::WRONG_DATA);
            }
            let own = field(ga_field::WITNESS);
            if own.is_some_and(|v| v.is_empty() || v.len() > 32) {
                return Err(Sw::WRONG_DATA);
            }
            let exp = field(ga_field::EXPONENTIATION);
            self.authorize_private(m[repo::PIN_POLICY])?;
            repo::load(id, m, &mut w.key.bytes, p)?;
            // No peer template (85): initiator step 1 generates an ephemeral
            // key and retains it for a later request on this same key slot.
            if exp.is_none() {
                let mut identity = [0; 32];
                let identity_len = own.map_or(0, |v| {
                    identity[..v.len()].copy_from_slice(v);
                    v.len()
                });
                self.touch(m[repo::TOUCH_POLICY], p)?;
                return self.sm2_start(id, Some(&identity[..identity_len]), w, p);
            }
            let mut exp = exp.unwrap();
            // A bare 04||X||Y would be plain ECDH. SM2 expects a nested
            // template with both static and ephemeral peer points instead.
            if exp.first() == Some(&EC_POINT_UNCOMPRESSED) {
                return Err(Sw::WRONG_DATA);
            }
            let (mut packet, klen) = parse_sm2_packet(&mut exp, own)?;
            let own_copy = own.map(|value| {
                let mut copy = [0; 32];
                copy[..value.len()].copy_from_slice(value);
                (copy, value.len())
            });
            // Same-slot retained state means initiator step 2; otherwise this
            // is the responder path. Step 2 must reuse its original own ID,
            // so a new witness/identity field is forbidden.
            let step2 = self.agreement == Some(id);
            let mut ephemeral = [0; 65];
            if step2 && own.is_some() {
                return Err(Sw::WRONG_DATA);
            }
            self.touch(m[repo::TOUCH_POLICY], p)?;
            if step2 {
                self.sm2_step2(&mut packet, w, p)?;
            } else {
                ephemeral = Self::sm2_responder(
                    &mut packet,
                    own_copy.as_ref().map(|(copy, n)| &copy[..*n]),
                    w,
                    p,
                )?;
            }
            repo::load(id, m, &mut w.key.bytes, p)?;
            packet[sm2_packet::ROLE] = u8::from(!step2);
            packet[sm2_packet::OUTPUT_LENGTH] = klen as u8;
            let result = p
                .crypto
                .key_operation(
                    KeyOperation::Sm2Exchange,
                    alg::SM2,
                    &mut w.key,
                    &packet,
                    &mut w.output,
                )
                .map_err(|_| Sw::WRONG_DATA);
            p.memory.wipe(&mut packet);
            let n = result?;
            if n != klen {
                return Err(Sw::UNABLE_TO_PROCESS);
            }
            if step2 {
                return self.wrapped(n);
            }
            let mut h = [0; 4];
            let hl = codec::header(&mut h, &[ga_tag::EXPONENTIATION], n)?;
            w.output.copy_within(0..n, 67 + hl);
            // Responder reply carries a 65-byte SEC1 ephemeral point in 82,
            // followed by the derived key in 85; 7C wraps both fields.
            w.output[..2].copy_from_slice(&[ga_tag::RESPONSE, 0x41]);
            w.output[2..67].copy_from_slice(&ephemeral);
            w.output[67..67 + hl].copy_from_slice(&h[..hl]);
            self.memory(67 + hl + n);
            self.header_len = codec::header(&mut self.header, &[ga_tag::TEMPLATE], self.body_len)?;
            Ok((self.header_len + self.body_len) as u32)
        })();
        if result.is_err() {
            self.clear_agreement(w, p);
        }
        result
    }

    fn sm2_start(
        &mut self,
        id: usize,
        own: Option<&[u8]>,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        if self.agreement.is_some() {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        p.crypto
            .key_operation(
                KeyOperation::Public,
                alg::SM2,
                &mut w.key,
                &[],
                &mut w.output,
            )
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        w.agreement[agreement::STATIC_PUBLIC..agreement::ID_LENGTH]
            .copy_from_slice(&w.output[..64]);
        p.crypto
            .key_operation(
                KeyOperation::Generate,
                alg::SM2,
                &mut w.key,
                &[],
                &mut w.output,
            )
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        w.agreement[agreement::SCALAR..agreement::EPHEMERAL_PUBLIC]
            .copy_from_slice(&w.key.bytes[..32]);
        p.crypto
            .key_operation(
                KeyOperation::Public,
                alg::SM2,
                &mut w.key,
                &[],
                &mut w.output,
            )
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        w.agreement[agreement::EPHEMERAL_PUBLIC..agreement::STATIC_PUBLIC]
            .copy_from_slice(&w.output[..64]);
        w.agreement[agreement::ID_LENGTH] = own.map_or(0, |v| v.len() as u8);
        if let Some(v) = own {
            w.agreement[agreement::ID..agreement::ID + v.len()].copy_from_slice(v);
        }
        w.output.copy_within(0..64, 1);
        w.output[0] = EC_POINT_UNCOMPRESSED;
        self.agreement = Some(id);
        self.wrapped(65)
    }
}
