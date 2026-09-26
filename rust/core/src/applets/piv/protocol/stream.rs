// SPDX-License-Identifier: Apache-2.0
//! Streaming crypto and shared-workspace transitions.
use super::*;
use crate::ports::StreamOperation;
use crate::ports::alg;
use crate::runtime::workspace::SessionWorkspace;

fn abort_stream(a: u8, s: &mut crate::ports::CryptoScratch, p: &mut Platform<'_>) {
    let _ = p.crypto.stream(StreamOperation::Abort, a, s, &[], &mut []);
    p.memory.wipe(&mut s.bytes);
}

impl Piv {
    pub fn select(&mut self, w: &mut SessionWorkspace, p: &mut Platform<'_>) -> Result<u32, Sw> {
        self.select_classic(w.classic_with(p.memory), p)
    }
    pub fn reset(&mut self, w: &mut SessionWorkspace, p: &mut Platform<'_>) {
        self.close(w, p);
        self.reset_classic(w.classic_with(p.memory), p);
    }
    pub fn cancel(&mut self, w: &mut SessionWorkspace, p: &mut Platform<'_>) {
        if matches!(self.request, Request::None) {
            return;
        }
        if let Request::Stream(a) = self.request {
            if let SessionWorkspace::Stream(s) = w {
                abort_stream(a, s, p);
            }
            self.request = Request::None;
            self.auth_clear(p);
        }
        self.cancel_classic(w.classic_with(p.memory), p);
    }
    // Share input handling without expanding it into the runtime dispatcher.
    #[inline(never)]
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
                let mut m = [0; repo::META];
                repo::read_meta(id, p, &mut m)?;
                if m[repo::ORIGIN] == 0 {
                    return Err(Sw::CONDITIONS_NOT_SATISFIED);
                }
                if m[repo::ALGORITHM] != a {
                    return Err(Sw::WRONG_P1P2);
                }
                // Reject unauthorized input before initializing private crypto.
                // A gesture belongs only to a complete, validated request.
                self.check_private(m[repo::PIN_POLICY])?;
                self.stream_pin_policy = m[repo::PIN_POLICY];
                self.stream_touch_policy = m[repo::TOUCH_POLICY];
                self.auth_clear(p);
                // Changing the workspace variant destroys classic key/input
                // backing; initialize the stream only after the transition.
                w.wipe_active(p.memory);
                let s = w.stream_with(p.memory);
                let operation = if a == alg::MLKEM768 {
                    StreamOperation::DecapsulateInit
                } else {
                    StreamOperation::SignInit
                };
                let r = super::init_stream(id, a, operation, s, p);
                if r.is_err() {
                    abort_stream(a, s, p);
                }
                r?;
                self.ga = Ga::new();
                self.request = Request::Stream(a);
                self.memory(0);
                return Ok(());
            }
        }
        self.begin_classic(h, w.classic_with(p.memory), p)
    }
    #[inline(never)]
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
                                    .stream(
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
                        .stream(
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
            self.consume_classic(b, w.classic_with(p.memory), p)
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
            w.wipe_active(p.memory);
            let a = w.attestation_with(p.memory);
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
            self.check_private(self.stream_pin_policy)?;
            self.touch(self.stream_touch_policy, p)?;
            self.authorize_private(self.stream_pin_policy)?;
            let SessionWorkspace::Stream(s) = w else {
                return Err(Sw::UNABLE_TO_PROCESS);
            };
            if a == alg::MLKEM768 {
                let mut secret = [0; 32];
                let r = p
                    .crypto
                    .stream(StreamOperation::DecapsulateFinal, a, s, &[], &mut secret)
                    .map_err(|_| Sw::UNABLE_TO_PROCESS);
                abort_stream(a, s, p);
                self.request = Request::None;
                let n = r?;
                if n != 32 {
                    p.memory.wipe(&mut secret);
                    return Err(Sw::UNABLE_TO_PROCESS);
                }
                w.classic_with(p.memory).output[..n].copy_from_slice(&secret[..n]);
                p.memory.wipe(&mut secret);
                return self.wrapped(n).map(|n| (n, Sw::SUCCESS));
            }
            let n = p
                .crypto
                .stream(StreamOperation::SignFinal, a, s, &[], &mut [])
                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            self.request = Request::None;
            let total = self.wrapped(n)?;
            self.response = ResponseBacking::Crypto(a);
            return Ok((total, Sw::SUCCESS));
        }
        let result = self.finish_classic(h, le, w.classic_with(p.memory), p);
        if result.is_ok()
            && let Some(PendingPublicKey {
                slot_index: id,
                include_metadata: metadata,
                generated_algorithm,
            }) = self.pending_public.take()
        {
            let result = self.finish_public(id, metadata, generated_algorithm, w, p);
            if result.is_err() {
                self.close(w, p);
            }
            return result;
        }
        result
    }
    // Encoding a prepared public stream is disjoint from private operations.
    #[inline(never)]
    fn finish_public(
        &mut self,
        id: usize,
        metadata: bool,
        generated_algorithm: Option<u8>,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_>,
    ) -> Result<(u32, Sw), Sw> {
        let mut m = [0; repo::META];
        let (a, n) = if let Some(a) = generated_algorithm {
            // The seed crosses the workspace variant transition only on this
            // bounded stack frame. Persistent staging owns the eventual commit.
            let mut seed = [0; 64];
            let length = repo::material(a);
            seed[..length].copy_from_slice(&w.classic_with(p.memory).key.bytes[..length]);
            let s = w.stream_with(p.memory);
            let result = p
                .crypto
                .stream(StreamOperation::PublicInit, a, s, &seed[..length], &mut [])
                .map_err(|_| Sw::UNABLE_TO_PROCESS);
            p.memory.wipe(&mut seed);
            (a, result?)
        } else {
            repo::read_meta(id, p, &mut m)?;
            let a = m[repo::ALGORITHM];
            let s = w.stream_with(p.memory);
            (a, super::init_public_stream(id, a, s, p)?)
        };
        self.memory(n);
        self.response = ResponseBacking::Crypto(a);
        let mut at = 0;
        if metadata {
            at = self.metadata_header(a, &m);
        }
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
        at += codec::header(&mut self.header[at..], &[key_tag::PUBLIC_POINT], n)?;
        self.header_len = at;
        Ok(((at + n) as u32, Sw::SUCCESS))
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
        if let ResponseBacking::Crypto(a) = self.response {
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
                    .stream(StreamOperation::Read, a, s, &[], &mut out[head..])
                    .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
                if n != out.len() - head {
                    return Err(Sw::UNABLE_TO_PROCESS);
                }
            }
            if offset + out.len() == self.header_len + self.body_len
                && let Some(id) = self.pending_commit.take()
            {
                if let Err(error) = p.storage.stage_commit(repo::KEYS[id as usize]) {
                    p.storage.stage_abort();
                    return Err(repo::io(error));
                }
            }
            Ok(out.len())
        } else {
            self.read_classic(offset, out, w.classic_with(p.memory), p)
        }
    }
    pub fn close(&mut self, w: &mut SessionWorkspace, p: &mut Platform<'_>) {
        self.abort_generation(p);
        if let SessionWorkspace::Attestation(a) = w {
            a.close(p);
            self.memory(0);
            return;
        }
        if let SessionWorkspace::Stream(s) = w {
            let a = match self.response {
                ResponseBacking::Crypto(a) => a,
                _ => match self.request {
                    Request::Stream(a) => a,
                    // No primitive is live when close has no stream request;
                    // P256 is the harmless ABI value accepted by Abort.
                    _ => alg::P256,
                },
            };
            abort_stream(a, s, p);
            self.memory(0);
        } else {
            self.close_classic(w.classic_with(p.memory), p)
        }
    }
}
