// SPDX-License-Identifier: Apache-2.0
//! CanoKey input ownership and parsing over the shared CTAPHID session.
use canokey_ports::RequestLimits;
use canokey_protocol::ctaphid::{self as wire, Error, REPORT_SIZE};
use canokey_transport_runtime::ctaphid::{Backend, Completion, Profile, Response, Session};

// Three HID packet windows stay inline; larger requests use PKE staging.
const INLINE: usize = 192;
pub fn preserves_context(command: u8, length: usize) -> bool {
    length <= INLINE
        && (matches!(command, wire::PING | wire::WINK)
            || (command == wire::CBOR && length == 0)
            || (command == wire::MSG && length < canokey_protocol::apdu::EXTENDED_HEADER_BYTES))
}
/// One exclusive applet session, acquired before touching request scratch.
/// begin must reject other active transports and retain yielded card context.
/// close releases request storage, not the transport transaction. The caller
/// must exclude all other core/crypto entrypoints while Transport::active().
pub trait Scratch {
    type Limits: RequestLimits;
    fn webauthn_enabled(&mut self) -> bool {
        true
    }
    /// Available staging bytes; the wire message limit applies independently.
    fn capacity(&self) -> usize;
    /// Main-loop query only; a retained native response may still own PKE.
    fn continuation_pending(&mut self) -> bool {
        false
    }
    /// Inline controls and envelopes rejected before parsing preserve applet scratch.
    fn begin(&mut self, use_pke: bool, preserve_context: bool) -> Result<(), Error>;
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error>;
    fn read(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), Error>;
    fn close(&mut self);
    /// Parser storage aliases the core's existing session workspace.
    fn begin_request(&mut self, message_length: Option<usize>);
    fn consume_request(&mut self, bytes: &[u8]);
    /// Source is closed before execution; response reads never reexecute crypto.
    fn finish_request(&mut self, cid: u32) -> usize;
    /// Trigger the indication without parsing a command over retained output.
    fn wink(&mut self, cid: u32);
    fn read_response(&mut self, offset: usize, out: &mut [u8]) -> Result<(), Error>;
    fn close_response(&mut self);
    /// Successful packet completion may retain an APDU response continuation.
    fn complete_response(&mut self) {
        self.close_response();
    }
    fn discard_continuation(&mut self) {}
    /// Header-only GET RESPONSE must not overwrite shared response backing.
    fn continue_message(&mut self, _bytes: &[u8]) -> Option<usize> {
        None
    }
}

pub struct CanoKey;
impl Profile for CanoKey {
    const DEVICE_VERSION: [u8; 3] = crate::release::CTAPHID_DEVICE;
    const CAPABILITIES: u8 = 0x05; // WINK/CBOR; NMSG clear.
    const REGISTERED_CHANNELS: bool = false;
    const WRAP_CHANNELS: bool = true;
    const INCLUSIVE_TIMEOUT: bool = false;
    const CANCEL_DURING_RECEIVE: bool = false;
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Storage {
    Released,
    Inline,
    Pke,
}
struct Input {
    storage: Storage,
    inline: [u8; INLINE],
    response: bool,
    continuation_cid: u32,
}
impl Input {
    const fn new() -> Self {
        Self {
            storage: Storage::Released,
            inline: [0x00; INLINE],
            response: false,
            continuation_cid: 0,
        }
    }
    #[inline(never)]
    fn close_request(&mut self, scratch: &mut impl Scratch) {
        if self.storage != Storage::Released {
            scratch.close();
            self.storage = Storage::Released;
        }
    }
}
pub struct Transport {
    session: Session<CanoKey>,
    input: Input,
}
impl Default for Transport {
    fn default() -> Self {
        Self::new()
    }
}
impl Transport {
    pub const fn new() -> Self {
        Self {
            session: Session::new(),
            input: Input::new(),
        }
    }
    pub fn active(&self) -> bool {
        self.session.active()
    }
    pub fn reset(&mut self, scratch: &mut impl Scratch) {
        self.session.reset(&mut Adapter {
            input: &mut self.input,
            scratch,
        });
    }
    pub fn completed(&mut self, scratch: &mut impl Scratch) {
        self.session.completed(&mut Adapter {
            input: &mut self.input,
            scratch,
        });
    }
    pub fn receive(
        &mut self,
        bytes: &[u8; REPORT_SIZE],
        tick: u32,
        output: &mut [u8; REPORT_SIZE],
        scratch: &mut impl Scratch,
    ) -> bool {
        self.session.receive(
            bytes,
            tick,
            output,
            &mut Adapter {
                input: &mut self.input,
                scratch,
            },
        )
    }
    pub fn timeout(
        &mut self,
        now: u32,
        output: &mut [u8; REPORT_SIZE],
        scratch: &mut impl Scratch,
    ) -> bool {
        self.session.timeout(
            now,
            output,
            &mut Adapter {
                input: &mut self.input,
                scratch,
            },
        )
    }
    pub fn transmit(&mut self, output: &mut [u8; REPORT_SIZE], scratch: &mut impl Scratch) -> bool {
        self.session.transmit(
            output,
            &mut Adapter {
                input: &mut self.input,
                scratch,
            },
        )
    }
}
struct Adapter<'a, S> {
    input: &'a mut Input,
    scratch: &'a mut S,
}
impl<S: Scratch> Backend for Adapter<'_, S> {
    fn reset(&mut self) {
        self.input.close_request(self.scratch);
        if self.input.response {
            self.scratch.close_response();
            self.input.response = false;
        }
        self.scratch.discard_continuation();
        self.input.continuation_cid = 0;
        self.input.inline.fill(0x00);
    }

    fn begin(&mut self, command: u8, length: usize, _cid: u32) -> Result<(), Error> {
        let limit = if command == wire::MSG {
            S::Limits::NATIVE_MSG_MAX_BYTES
        } else {
            S::Limits::CTAP_REQUEST_MAX_BYTES
        };
        if length > limit || (length > INLINE && length > self.scratch.capacity()) {
            return Err(Error::Length);
        }
        if !matches!(
            command,
            wire::PING | wire::CBOR | wire::MSG | wire::WINK | wire::CANCEL
        ) {
            return Err(Error::Command);
        }
        let pke = length > INLINE;
        if pke && self.scratch.continuation_pending() {
            return Err(Error::Busy);
        }
        self.scratch
            .begin(pke, preserves_context(command, length))?;
        self.input.storage = if pke { Storage::Pke } else { Storage::Inline };
        Ok(())
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        if self.input.storage == Storage::Pke {
            self.scratch.write(offset, bytes)
        } else {
            self.input.inline[offset..offset + bytes.len()].copy_from_slice(bytes);
            Ok(())
        }
    }

    #[inline(never)]
    fn finish(&mut self, command: u8, mut total: usize, cid: u32) -> Result<usize, Error> {
        let scratch = &mut *self.scratch;
        if command == wire::CANCEL {
            // Idle/late CANCEL payloads have no reply and never enter Core.
            self.input.close_request(scratch);
            self.input.inline.fill(0x00);
            return Ok(0);
        }
        if command == wire::WINK {
            // WINK consumes and ignores its admitted payload.
            self.input.close_request(scratch);
            self.input.inline.fill(0x00);
            scratch.wink(cid);
            total = 0;
        }
        if command == wire::CBOR || command == wire::MSG {
            if !scratch.webauthn_enabled() {
                return Err(Error::Command);
            }
            if command == wire::CBOR {
                if total == 0 {
                    return Err(Error::Length);
                }
                if scratch.continuation_pending() {
                    return Err(Error::Busy);
                }
            }
            if command == wire::MSG {
                if total < canokey_protocol::apdu::EXTENDED_HEADER_BYTES {
                    return Err(Error::Length);
                }
                let mut header = [0x00; canokey_protocol::apdu::EXTENDED_HEADER_BYTES];
                if self.input.storage == Storage::Pke {
                    scratch.read(0, &mut header)?;
                } else {
                    header.copy_from_slice(
                        &self.input.inline[..canokey_protocol::apdu::EXTENDED_HEADER_BYTES],
                    );
                }
                wire::message_body_length(&header, total)?;
                // Refused CBOR and control traffic may change the current RX
                // CID. Only the CID that created the retained source may read
                // or replace it; last-received CID is not response ownership.
                if scratch.continuation_pending() && cid != self.input.continuation_cid {
                    return Err(Error::Busy);
                }
            }
            // The shared parser also needs cleanup when a staged read fails.
            self.input.response = true;
            let continued = if command == wire::MSG && self.input.storage == Storage::Inline {
                scratch.continue_message(&self.input.inline[..total])
            } else {
                None
            };
            if let Some(length) = continued {
                self.input.close_request(scratch);
                self.input.inline.fill(0x00);
                total = length;
            } else {
                scratch.begin_request((command == wire::MSG).then_some(total));
                if self.input.storage == Storage::Pke {
                    for offset in (0..total).step_by(INLINE) {
                        let n = INLINE.min(total - offset);
                        scratch.read(offset, &mut self.input.inline[..n])?;
                        scratch.consume_request(&self.input.inline[..n]);
                    }
                } else {
                    scratch.consume_request(&self.input.inline[..total]);
                }
                self.input.close_request(scratch);
                self.input.inline.fill(0x00);
                total = scratch.finish_request(cid);
            }
            self.input.response = true;
        }
        Ok(total)
    }
}

impl<S: Scratch> Response for Adapter<'_, S> {
    fn read(&mut self, offset: usize, output: &mut [u8]) -> Result<(), Error> {
        if self.input.response {
            self.scratch.read_response(offset, output)
        } else if self.input.storage == Storage::Pke {
            self.scratch.read(offset, output)
        } else {
            output.copy_from_slice(&self.input.inline[offset..offset + output.len()]);
            Ok(())
        }
    }
    fn abort(&mut self, receiving: bool) {
        if receiving && !self.input.response {
            self.input.close_request(self.scratch);
            self.input.inline.fill(0x00);
        } else {
            self.reset();
        }
    }
}
impl<S: Scratch> Completion for Adapter<'_, S> {
    fn complete(&mut self, cid: u32) {
        self.input.close_request(self.scratch);
        if self.input.response {
            self.scratch.complete_response();
            self.input.continuation_cid = if self.scratch.continuation_pending() {
                cid
            } else {
                0
            };
            self.input.response = false;
        }
        self.input.inline.fill(0x00);
    }
}
