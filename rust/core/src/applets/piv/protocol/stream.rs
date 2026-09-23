// SPDX-License-Identifier: Apache-2.0
//! Streaming crypto and shared-workspace transitions.
use super::*;
use crate::ports::StreamOperation;
use crate::ports::alg;
use crate::runtime::workspace::SessionWorkspace;
impl Piv {
    pub fn select(&mut self, w: &mut SessionWorkspace, p: &mut Platform<'_>) -> Result<u32, Sw> {
        self.select_classic(w.classic(), p)
    }
    pub fn reset(&mut self, w: &mut SessionWorkspace, p: &mut Platform<'_>) {
        self.close(w, p);
        self.reset_classic(w.classic(), p);
    }
    pub fn cancel(&mut self, w: &mut SessionWorkspace, p: &mut Platform<'_>) {
        if matches!(self.request, Request::None) {
            return;
        }
        if let Request::Stream(a) = self.request {
            if let SessionWorkspace::Stream(s) = w {
                let _ = p
                    .crypto
                    .piv_stream(StreamOperation::Abort, a, s, &[], &mut []);
                p.memory.wipe(&mut s.bytes);
            }
            self.request = Request::None;
            self.auth_clear(p);
        }
        self.cancel_classic(w.classic(), p);
    }
    pub fn begin(
        &mut self,
        h: Header,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        if h.ins == INS_GENERAL_AUTHENTICATE && h.p2 != reference::MANAGEMENT {
            let a = if h.p1 == wire_alg::ED25519_STREAM && self.config[0] != 0 {
                alg::ED25519
            } else {
                repo::algorithm(h.p1, &self.config).map_err(|_| Sw::WRONG_P1P2)?
            };
            if a >= alg::MLKEM768
                || h.p1 == wire_alg::ED25519_STREAM
                || (a == alg::SM2 && h.chained())
            {
                self.agreement = None;
                self.stream_phase = StreamPhase::Identity;
                self.sm2_id_used = 0;
                self.sm2_id.fill(0);
                let id = repo::slot(h.p2)?;
                let m = repo::meta(id, p)?;
                if m[repo::ORIGIN] == 0 {
                    return Err(Sw::CONDITIONS_NOT_SATISFIED);
                }
                if m[repo::ALGORITHM] != a {
                    return Err(Sw::WRONG_P1P2);
                }
                self.authorize_private(m[repo::PIN_POLICY])?;
                self.touch(m[repo::TOUCH_POLICY], p)?;
                self.auth_clear(p);
                let mut seed = [0; 64];
                p.storage
                    .read_at(
                        repo::KEYS[id],
                        repo::HEADER as u32,
                        &mut seed[..repo::material(a)],
                    )
                    .map_err(repo::io)?;
                // Changing the workspace variant destroys classic key/input
                // backing. Retain only the bounded seed across this transition.
                let s = w.stream();
                let r = p
                    .crypto
                    .piv_stream(
                        if a == alg::MLKEM768 {
                            StreamOperation::DecapsulateInit
                        } else {
                            StreamOperation::SignInit
                        },
                        a,
                        s,
                        &seed[..repo::material(a)],
                        &mut [],
                    )
                    .map_err(|_| Sw::UNABLE_TO_PROCESS);
                p.memory.wipe(&mut seed);
                if r.is_err() {
                    let _ = p
                        .crypto
                        .piv_stream(StreamOperation::Abort, a, s, &[], &mut []);
                    p.memory.wipe(&mut s.bytes);
                }
                r?;
                self.ga = Ga::new();
                self.request = Request::Stream(a);
                self.memory(0);
                return Ok(());
            }
        }
        self.begin_classic(h, w.classic(), p)
    }
    pub fn consume(
        &mut self,
        b: &[u8],
        w: &mut SessionWorkspace,
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        if let Request::Stream(a) = self.request {
            let SessionWorkspace::Stream(s) = w else {
                return Err(Sw::UNABLE_TO_PROCESS);
            };
            // Long message/ciphertext chunks go straight to the primitive;
            // only the optional SM2 identity is retained in applet state.
            self.ga.events(b, &mut |tag, length, bytes| {
                if let Some(n) = length {
                    match tag {
                        ga_tag::WITNESS
                            if a == alg::SM2
                                && self.stream_phase == StreamPhase::Identity
                                && n > 0
                                && n <= 32 => {}
                        ga_tag::RESPONSE
                            if self.stream_phase == StreamPhase::Identity && n == 0 =>
                        {
                            self.stream_phase = StreamPhase::ResponseTag;
                        }
                        ga_tag::CHALLENGE
                            if self.stream_phase == StreamPhase::ResponseTag
                                && (a != alg::MLKEM768
                                    || n == crate::ports::mlkem768::CIPHERTEXT_BYTES) =>
                        {
                            if a == alg::SM2 {
                                p.crypto
                                    .piv_stream(
                                        StreamOperation::Sm2Identity,
                                        a,
                                        s,
                                        &self.sm2_id[..self.sm2_id_used],
                                        &mut [],
                                    )
                                    .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                            }
                            self.stream_phase = StreamPhase::Payload;
                        }
                        _ => return Err(Sw::WRONG_DATA),
                    }
                } else if tag == ga_tag::WITNESS {
                    let end = self.sm2_id_used + bytes.len();
                    if end > 32 {
                        return Err(Sw::WRONG_DATA);
                    }
                    self.sm2_id[self.sm2_id_used..end].copy_from_slice(bytes);
                    self.sm2_id_used = end;
                } else if tag == ga_tag::CHALLENGE {
                    p.crypto
                        .piv_stream(
                            if a == alg::MLKEM768 {
                                StreamOperation::DecapsulateUpdate
                            } else {
                                StreamOperation::SignUpdate
                            },
                            a,
                            s,
                            bytes,
                            &mut [],
                        )
                        .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                }
                Ok(())
            })
        } else {
            self.consume_classic(b, w.classic(), p)
        }
    }
    pub fn finish(
        &mut self,
        h: Header,
        le: u32,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_>,
    ) -> Result<(u32, Sw), Sw> {
        // ATTEST F9 uses P1 as the subject key slot, unlike GA which uses P2.
        // P2 is reserved (00); the signer is always the attestation identity.
        if h.ins == INS_ATTEST {
            self.request = Request::None;
            if h.p2 != 0x00 {
                return Err(Sw::WRONG_P1P2);
            }
            if self.used != 0 {
                return Err(Sw::WRONG_LENGTH);
            }
            let id = repo::slot(h.p1)?;
            let a = w.attestation();
            if let Err(e) = a.prepare(id, p) {
                a.close(p);
                return Err(e);
            }
            return Ok((a.total as u32, Sw::SUCCESS));
        }
        if let Request::Stream(a) = self.request {
            self.ga.finish()?;
            if self.ga.field_len(ga_field::RESPONSE).is_none_or(|n| n != 0)
                || self.ga.field_len(ga_field::CHALLENGE).is_none()
            {
                return Err(Sw::WRONG_DATA);
            }
            let SessionWorkspace::Stream(s) = w else {
                return Err(Sw::UNABLE_TO_PROCESS);
            };
            if a == alg::MLKEM768 {
                let mut secret = [0; 32];
                let r = p
                    .crypto
                    .piv_stream(StreamOperation::DecapsulateFinal, a, s, &[], &mut secret)
                    .map_err(|_| Sw::UNABLE_TO_PROCESS);
                let _ = p
                    .crypto
                    .piv_stream(StreamOperation::Abort, a, s, &[], &mut []);
                p.memory.wipe(&mut s.bytes);
                self.request = Request::None;
                let n = r?;
                if n != 32 {
                    p.memory.wipe(&mut secret);
                    return Err(Sw::UNABLE_TO_PROCESS);
                }
                w.classic().output[..n].copy_from_slice(&secret[..n]);
                p.memory.wipe(&mut secret);
                return self.wrapped(n).map(|n| (n, Sw::SUCCESS));
            }
            let n = p
                .crypto
                .piv_stream(StreamOperation::SignFinal, a, s, &[], &mut [])
                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            self.request = Request::None;
            let total = self.wrapped(n)?;
            self.response = Response::Crypto(a);
            return Ok((total, Sw::SUCCESS));
        }
        let result = self.finish_classic(h, le, w.classic(), p);
        if result.is_ok()
            && let Some(PendingPublicKey {
                slot_index: id,
                include_metadata: metadata,
            }) = self.pending_public.take()
        {
            let m = repo::meta(id, p)?;
            let a = m[repo::ALGORITHM];
            let mut seed = [0; 64];
            p.storage
                .read_at(
                    repo::KEYS[id],
                    repo::HEADER as u32,
                    &mut seed[..repo::material(a)],
                )
                .map_err(repo::io)?;
            let s = w.stream();
            let r = p
                .crypto
                .piv_stream(
                    StreamOperation::PublicInit,
                    a,
                    s,
                    &seed[..repo::material(a)],
                    &mut [],
                )
                .map_err(|_| Sw::UNABLE_TO_PROCESS);
            p.memory.wipe(&mut seed);
            let n = r?;
            self.memory(n);
            self.response = Response::Crypto(a);
            let mut at = 0;
            if metadata {
                at = self.metadata_header(a, &m);
            }
            at += codec::header(
                &mut self.header[at..],
                if metadata {
                    &[metadata_tag::PUBLIC_KEY]
                } else {
                    &key_tag::PUBLIC_TEMPLATE
                },
                n + 4,
            )?;
            at += codec::header(&mut self.header[at..], &[key_tag::PUBLIC_POINT], n)?;
            self.header_len = at;
            return Ok(((at + n) as u32, Sw::SUCCESS));
        }
        result
    }
    pub fn read(
        &mut self,
        offset: usize,
        out: &mut [u8],
        w: &mut SessionWorkspace,
        p: &mut Platform<'_>,
    ) -> Result<usize, Sw> {
        if let SessionWorkspace::Attestation(a) = w {
            return a.read(offset, out, p);
        }
        if let Response::Crypto(a) = self.response {
            let SessionWorkspace::Stream(s) = w else {
                return Err(Sw::UNABLE_TO_PROCESS);
            };
            if offset
                .checked_add(out.len())
                .is_none_or(|n| n > self.header_len + self.body_len)
            {
                return Err(Sw::UNABLE_TO_PROCESS);
            }
            let head = self.header_len.saturating_sub(offset).min(out.len());
            out[..head].copy_from_slice(
                &self.header[offset.min(self.header_len)..offset.min(self.header_len) + head],
            );
            if head < out.len() {
                let n = p
                    .crypto
                    .piv_stream(StreamOperation::Read, a, s, &[], &mut out[head..])
                    .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                if n != out.len() - head {
                    return Err(Sw::UNABLE_TO_PROCESS);
                }
            }
            Ok(out.len())
        } else {
            self.read_classic(offset, out, w.classic(), p)
        }
    }
    pub fn close(&mut self, w: &mut SessionWorkspace, p: &mut Platform<'_>) {
        if let SessionWorkspace::Attestation(a) = w {
            a.close(p);
            self.memory(0);
            return;
        }
        if let SessionWorkspace::Stream(s) = w {
            let a = match self.response {
                Response::Crypto(a) => a,
                _ => 0,
            };
            let _ = p
                .crypto
                .piv_stream(StreamOperation::Abort, a, s, &[], &mut []);
            p.memory.wipe(&mut s.bytes);
            self.memory(0);
        } else {
            self.close_classic(w.classic(), p)
        }
    }
}
