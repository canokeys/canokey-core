// SPDX-License-Identifier: Apache-2.0
//! Key generation, public-key encoding and private operations.
use super::*;

impl Piv {
    pub(super) fn public(
        &mut self,
        id: usize,
        m: &[u8; repo::META],
        metadata: bool,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        if m[repo::ORIGIN] == 0 {
            return Err(Sw(0x6a88));
        }
        let a = m[repo::ALGORITHM];
        if a >= 10 {
            self.pending_public = Some((id, metadata));
            return Ok(if a == 10 { 1184 } else { 1952 });
        }
        repo::load(id, m, &mut w.key.bytes, p)?;
        let n = p
            .crypto
            .key_operation(KeyOperation::Public, a, &mut w.key, &[], &mut w.output)
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        self.memory(n);
        let mut at = 0;
        if metadata {
            self.header[..10].copy_from_slice(&[
                1,
                1,
                repo::algorithm_id(a, &self.config),
                2,
                2,
                m[repo::PIN_POLICY],
                m[repo::TOUCH_POLICY],
                3,
                1,
                m[repo::ORIGIN],
            ]);
            at = 10;
        }
        if repo::rsa(a) {
            let inner = n + 4 + 6;
            at += codec::header(
                &mut self.header[at..],
                if metadata { &[4] } else { &[0x7f, 0x49] },
                inner,
            )?;
            at += codec::header(&mut self.header[at..], &[0x81], n)?;
            self.suffix[..2].copy_from_slice(&[0x82, 4]);
            self.suffix[2..].copy_from_slice(&w.key.bytes[..4]);
            self.suffix_len = 6;
        } else {
            let point = usize::from(a != 3 && a != 4);
            let inner = n + point + if n + point < 128 { 2 } else { 3 };
            at += codec::header(
                &mut self.header[at..],
                if metadata { &[4] } else { &[0x7f, 0x49] },
                inner,
            )?;
            at += codec::header(&mut self.header[at..], &[0x86], n + point)?;
            if point != 0 {
                self.header[at] = 4;
                at += 1;
            }
        }
        self.header_len = at;
        Ok((at + n + self.suffix_len) as u32)
    }
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
        if h.p1 != 0 {
            return Err(Sw::WRONG_DATA);
        }
        let id = repo::slot(h.p2)?;
        let mut b = codec::object(&w.input[..self.used], 0xac)?;
        let (t, v) = codec::take(&mut b)?;
        if t != 0x80 || v.len() != 1 {
            return Err(Sw::WRONG_DATA);
        }
        let a = repo::algorithm(v[0], &self.config)?;
        if id == 24 && a != 0 {
            return Err(Sw::WRONG_DATA);
        }
        let mut m = repo::meta(id, p)?;
        m[repo::ALGORITHM] = a;
        m[repo::ORIGIN] = 1;
        m[repo::NAME_LENGTH..].fill(0);
        repo::policies(&mut m, b)?;
        if a >= 10 {
            p.crypto
                .random(&mut w.key.bytes[..repo::material(a)])
                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        } else {
            p.crypto
                .key_operation(KeyOperation::Generate, a, &mut w.key, &[], &mut w.output)
                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        }
        repo::save(id, &m, &w.key.bytes, p)?;
        self.public(id, &m, false, w, p)
    }
    #[inline(never)]
    pub(super) fn general_authenticate(
        &mut self,
        h: Header,
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        let mut fields: [Option<&[u8]>; 6] = [None; 6];
        for (i, entry) in self.ga.fields.iter().enumerate() {
            if let Some((offset, n)) = entry {
                fields[i] = Some(&w.input[*offset..*offset + *n]);
            }
        }
        if h.p2 == 0x9b {
            return self.management_auth(h, &fields, w.output.as_mut_slice(), p);
        }
        let id = repo::slot(h.p2)?;
        let m = repo::meta(id, p)?;
        if m[repo::ORIGIN] == 0 {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        let a = repo::algorithm(h.p1, &self.config).map_err(|_| Sw::WRONG_P1P2)?;
        if a != m[repo::ALGORITHM] {
            return Err(Sw::WRONG_P1P2);
        }
        self.auth_clear(p);
        self.touch(m[repo::TOUCH_POLICY], p)?;
        if a == 9 && fields[1].is_none() {
            return self.sm2_agree(h.p2, id, &m, w, p);
        }
        if fields[0].is_some() || fields[2] != Some(&[][..]) {
            return Err(Sw::WRONG_DATA);
        }
        self.authorize_private(m[repo::PIN_POLICY])?;
        repo::load(id, &m, &mut w.key.bytes, p)?;
        let (op, data) = if let Some(input) = fields[1] {
            if fields[5].is_some() || input.is_empty() {
                return Err(Sw::WRONG_DATA);
            }
            if repo::rsa(a) {
                if input.len() != repo::width(a) * 2 {
                    return Err(Sw::WRONG_LENGTH);
                }
                (KeyOperation::RsaRaw, input)
            } else if a == 4 {
                return Err(Sw::WRONG_DATA);
            } else {
                if a != 3 && (input.len() > repo::width(a) || (a == 9 && input.len() != 32)) {
                    return Err(Sw::WRONG_LENGTH);
                }
                (KeyOperation::EcSign, input)
            }
        } else if let Some(peer) = fields[5] {
            if id == 24 || a == 3 || a == 9 || repo::rsa(a) {
                return Err(Sw::WRONG_DATA);
            }
            if a == 4 {
                if peer.len() != 32 {
                    return Err(Sw::WRONG_DATA);
                }
                (KeyOperation::Agree, peer)
            } else {
                if peer.len() != repo::width(a) * 2 + 1 || peer[0] != 4 {
                    return Err(Sw::WRONG_DATA);
                }
                (KeyOperation::Agree, &peer[1..])
            }
        } else {
            return Err(Sw::WRONG_DATA);
        };
        // C PIV left-pads digest integers to the curve width. The native
        // primitive requires that exact width (including P-521's leading byte).
        let mut padded = [0; 66];
        let data = if matches!(op, KeyOperation::EcSign) && a != 3 {
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
        if matches!(op, KeyOperation::EcSign) && a != 3 && a != 9 {
            n = der_signature(&mut w.output, n)?;
        }
        self.wrapped(n)
    }
    #[inline(never)]
    pub(super) fn sm2_agree(
        &mut self,
        slot: u8,
        id: usize,
        m: &[u8; repo::META],
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        let result = (|| {
            let field = |i: usize| self.ga.fields[i].map(|(o, n)| &w.input[o..o + n]);
            if field(2) != Some(&[][..]) {
                return Err(Sw::WRONG_DATA);
            }
            let own = field(0);
            if own.is_some_and(|v| v.is_empty() || v.len() > 32) {
                return Err(Sw::WRONG_DATA);
            }
            let exp = field(5);
            self.authorize_private(m[repo::PIN_POLICY])?;
            repo::load(id, m, &mut w.key.bytes, p)?;
            if exp.is_none() {
                if self.agreement.is_some() {
                    return Err(Sw::CONDITIONS_NOT_SATISFIED);
                }
                p.crypto
                    .key_operation(KeyOperation::Public, 9, &mut w.key, &[], &mut w.output)
                    .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                w.agreement[96..160].copy_from_slice(&w.output[..64]);
                p.crypto
                    .key_operation(KeyOperation::Generate, 9, &mut w.key, &[], &mut w.output)
                    .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                w.agreement[..32].copy_from_slice(&w.key.bytes[..32]);
                p.crypto
                    .key_operation(KeyOperation::Public, 9, &mut w.key, &[], &mut w.output)
                    .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                w.agreement[32..96].copy_from_slice(&w.output[..64]);
                w.agreement[160] = own.map_or(0, |v| v.len() as u8);
                if let Some(v) = own {
                    w.agreement[161..161 + v.len()].copy_from_slice(v)
                }
                w.output.copy_within(0..64, 1);
                w.output[0] = 4;
                self.agreement = Some(id);
                return self.wrapped(65);
            }
            let mut exp = exp.unwrap();
            if exp.first() == Some(&4) {
                return Err(Sw::WRONG_DATA);
            }
            let mut packet = [0; 228];
            for (tag, at) in [(0x86, 32), (0x87, 96)] {
                let (t, v) = codec::take(&mut exp)?;
                if t != tag || v.len() != 65 || v[0] != 4 {
                    return Err(Sw::WRONG_DATA);
                }
                packet[at..at + 64].copy_from_slice(&v[1..]);
            }
            let default = b"1234567812345678";
            packet[193] = 16;
            packet[194..210].copy_from_slice(default);
            if exp.first() == Some(&0x88) {
                let (_, v) = codec::take(&mut exp)?;
                if v.is_empty() || v.len() > 32 {
                    return Err(Sw::WRONG_DATA);
                }
                packet[193] = v.len() as u8;
                packet[194..194 + v.len()].copy_from_slice(v);
            }
            let mut klen = 16;
            if !exp.is_empty() {
                let (t, v) = codec::take(&mut exp)?;
                if t != 0x89 || v.len() != 2 {
                    return Err(Sw::WRONG_DATA);
                }
                klen = u16::from_be_bytes(v.try_into().unwrap()) as usize;
            }
            if !exp.is_empty() || klen == 0 || klen > 128 {
                return Err(Sw::WRONG_DATA);
            }
            let step2 = self.agreement == Some(id);
            if step2 && own.is_some() {
                return Err(Sw::WRONG_DATA);
            }
            packet[160] = 16;
            packet[161..177].copy_from_slice(default);
            if step2 {
                p.crypto
                    .key_operation(KeyOperation::Public, 9, &mut w.key, &[], &mut w.output)
                    .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                if !codec::equal(&w.output[..64], &w.agreement[96..160]) {
                    return Err(Sw::CONDITIONS_NOT_SATISFIED);
                }
                packet[..32].copy_from_slice(&w.agreement[..32]);
                let n = w.agreement[160] as usize;
                if n > 0 {
                    packet[160] = n as u8;
                    packet[161..161 + n].copy_from_slice(&w.agreement[161..161 + n]);
                }
                w.key.bytes[..32].copy_from_slice(&packet[..32]);
                p.crypto
                    .key_operation(KeyOperation::Public, 9, &mut w.key, &[], &mut w.output)
                    .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                if !codec::equal(&w.output[..64], &w.agreement[32..96]) {
                    return Err(Sw::CONDITIONS_NOT_SATISFIED);
                }
                self.agreement = None;
                p.memory.wipe(&mut w.agreement);
            } else {
                if let Some(v) = own {
                    packet[160] = v.len() as u8;
                    packet[161..161 + v.len()].copy_from_slice(v)
                }
                p.crypto
                    .key_operation(KeyOperation::Generate, 9, &mut w.key, &[], &mut w.output)
                    .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                packet[..32].copy_from_slice(&w.key.bytes[..32]);
                p.crypto
                    .key_operation(KeyOperation::Public, 9, &mut w.key, &[], &mut w.output)
                    .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            }
            let mut ephemeral = [0; 65];
            ephemeral[0] = 4;
            ephemeral[1..].copy_from_slice(&w.output[..64]);
            repo::load(id, m, &mut w.key.bytes, p)?;
            packet[226] = u8::from(!step2);
            packet[227] = klen as u8;
            let result = p
                .crypto
                .key_operation(
                    KeyOperation::Sm2Exchange,
                    9,
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
            let hl = codec::header(&mut h, &[0x85], n)?;
            w.output.copy_within(0..n, 67 + hl);
            w.output[..2].copy_from_slice(&[0x82, 65]);
            w.output[2..67].copy_from_slice(&ephemeral);
            w.output[67..67 + hl].copy_from_slice(&h[..hl]);
            self.memory(67 + hl + n);
            self.header_len = codec::header(&mut self.header, &[0x7c], self.body_len)?;
            Ok((self.header_len + self.body_len) as u32)
        })();
        if result.is_err() {
            self.agreement = None;
            p.memory.wipe(&mut w.agreement);
        }
        let _ = slot;
        result
    }
}
