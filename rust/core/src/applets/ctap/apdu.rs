// SPDX-License-Identifier: Apache-2.0
//! FIDO SELECT, APDU command envelope and response backing. CTAP parsing and
//! execution are shared with native HID in the parent module.
use super::{Request, Response, Session};
use crate::{ports::Platform, runtime::workspace::SessionWorkspace};
use canokey_protocol::{apdu::Header, response::StatusWord as Sw};

pub const AID: &[u8] = &[0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01];
const VERSION: &[u8] = b"FIDO_2_0";
const INS_MSG: u8 = 0x10;

fn valid_message_parameters(header: Header) -> bool {
    // P1 bit 7 allows NFCCTAP_GETRESPONSE keepalive polling. Like the legacy
    // synchronous engine, we may finish the command directly with 9000; the
    // hint must not make standards-compliant NFC clients fail discovery.
    header.p1 & 0x7f == 0 && header.p2 == 0
}

pub fn allows_extended(header: Header) -> bool {
    (header.cla == 0 && matches!(header.ins, 1 | 2 | 3 | 0xa4 | 0x10))
        || (header.cla == 0x80 && header.ins == INS_MSG && valid_message_parameters(header))
}

pub struct Applet {
    response: Response,
    session: Session,
    message_status: Option<Sw>,
    message_offset: usize,
    message_length: usize,
}
impl Applet {
    pub const fn new() -> Self {
        Self {
            response: Response::Constant(&[]),
            session: Session::new(),
            message_status: None,
            message_offset: 0,
            message_length: 0,
        }
    }
    #[cfg(feature = "pass")]
    pub(crate) fn take_presence(&mut self) -> bool {
        self.session.presence.take()
    }
    #[cfg(feature = "admin")]
    pub(crate) fn erase(
        &mut self,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        self.close(w, p);
        self.session.erase(p).map_err(|_| Sw::UNABLE_TO_PROCESS)
    }
    pub fn install(&mut self, p: &mut Platform<'_>) -> Result<(), Sw> {
        self.session.install(p).map_err(|_| Sw::UNABLE_TO_PROCESS)
    }
    pub fn response_preemptable(&self) -> bool {
        // CTAP's encoded-response threshold excluded the 32-byte command
        // overhead. U2F registration always published a certificate source.
        self.response.len() > 256
            || matches!(
                self.response,
                Response::Authentication {
                    certificate: Some(_),
                    ..
                }
            )
    }
    pub fn reset(&mut self, w: &mut SessionWorkspace, p: &mut Platform<'_>) {
        self.session.abort_blob(p);
        self.session.reset(p.memory);
        self.close(w, p);
    }
    pub fn cancel_command(&mut self, w: &mut SessionWorkspace) {
        // GET RESPONSE abandons input chaining while retaining response backing.
        w.cancel_ctap_request();
    }
    pub fn select(&mut self, w: &mut SessionWorkspace, p: &mut Platform<'_>) -> u32 {
        self.close(w, p);
        self.response = Response::Constant(VERSION);
        VERSION.len() as u32
    }
    // Share input handling without expanding it into the runtime dispatcher.
    #[inline(never)]
    pub fn begin(
        &mut self,
        header: Header,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        self.close(w, p);
        if header.cla == 0 {
            w.wipe_active(p.memory);
            *w = SessionWorkspace::U2fRequest(super::u2f::Request::new(header));
            return Ok(());
        }
        w.wipe_active(p.memory);
        *w.ctap_request_with(p.memory) = Request::new();
        if header.ins != INS_MSG {
            return Err(Sw::INS_NOT_SUPPORTED);
        }
        if !valid_message_parameters(header) {
            return Err(Sw::WRONG_P1P2);
        }
        Ok(())
    }
    #[inline(never)]
    pub fn consume(&mut self, bytes: &[u8], w: &mut SessionWorkspace) -> Result<(), Sw> {
        if let SessionWorkspace::U2fRequest(request) = w {
            request.consume(bytes);
        } else {
            w.ctap_request().consume(bytes);
        }
        Ok(())
    }
    pub fn finish(&mut self, w: &mut SessionWorkspace, p: &mut Platform<'_>) -> Result<u32, Sw> {
        if let SessionWorkspace::U2fRequest(request) = w {
            let request = core::mem::replace(request, super::u2f::Request::new(request.header));
            self.response = self.session.u2f(&request, w.classic_with(p.memory), p)?;
            return Ok(self.response.len() as u32);
        }
        let mut command = w.ctap_request_with(p.memory).finish();
        Ok(self.execute(&mut command, w, p) as u32)
    }
    pub fn execute(
        &mut self,
        command: &mut Result<super::Command, super::Status>,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_>,
    ) -> usize {
        self.response = self.session.execute(command, w.classic_with(p.memory), p);
        self.prepare(w, p);
        self.response.len()
    }
    pub fn execute_message(
        &mut self,
        command: &mut Message,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_>,
    ) -> usize {
        let limit = match command {
            Message::Ctap(_, limit) | Message::U2f(_, limit) => *limit,
            Message::Error(_) => u32::MAX,
        };
        let result = match command {
            Message::Ctap(command, _) => {
                Ok(self.session.execute(command, w.classic_with(p.memory), p))
            }
            Message::U2f(request, _) => self.session.u2f(request, w.classic_with(p.memory), p),
            Message::Error(error) => Err(*error),
        };
        let (response, sw) = match result {
            Ok(response) => (response, Sw::SUCCESS),
            Err(sw) => (Response::Constant(&[]), sw),
        };
        self.response = response;
        self.prepare(w, p);
        self.message_offset = 0;
        self.message_window(limit, sw)
    }
    pub fn read(
        &mut self,
        offset: usize,
        output: &mut [u8],
        w: &mut SessionWorkspace,
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        if let Some(sw) = self.message_status {
            let length = self.message_length;
            if offset
                .checked_add(output.len())
                .is_none_or(|end| end > length + 2)
            {
                return Err(Sw::WRONG_LENGTH);
            }
            let n = output.len().min(length.saturating_sub(offset));
            if n != 0 {
                self.read_payload(self.message_offset + offset, &mut output[..n], w, p)?;
            }
            if n < output.len() {
                let start = offset + n - length;
                let end = start + output.len() - n;
                output[n..].copy_from_slice(&sw.bytes()[start..end]);
            }
            Ok(())
        } else {
            self.read_payload(offset, output, w, p)
        }
    }
    fn read_payload(
        &mut self,
        offset: usize,
        output: &mut [u8],
        w: &mut SessionWorkspace,
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        if matches!(self.response, Response::Stream(_)) {
            let SessionWorkspace::CtapStream(stream) = w else {
                return Err(Sw::UNABLE_TO_PROCESS);
            };
            stream.read(offset, output, p)
        } else {
            self.response
                .read(w.classic_with(p.memory), offset, output, p.storage)
        }
    }
    fn prepare(&mut self, w: &mut SessionWorkspace, p: &mut Platform<'_>) {
        if let Response::Pending(plan) = self.response {
            self.response = match super::pq::Stream::prepare(plan, w, p) {
                Ok(n) => Response::Stream(n),
                Err(error) => {
                    self.session.reset(p.memory);
                    Response::Error(error)
                }
            };
        }
    }
    fn message_window(&mut self, limit: u32, final_sw: Sw) -> usize {
        let plan = canokey_protocol::response::ResponsePlan::new(
            self.response.len() as u32,
            self.message_offset as u32,
            limit,
            final_sw,
        )
        .expect("MSG offset remains within response");
        self.message_length = plan.length as usize;
        self.message_status = Some(plan.sw);
        self.message_length + 2
    }
    pub fn pending_message(&self) -> bool {
        self.message_status.is_some()
            && self.message_length == 0
            && self.message_offset < self.response.len()
    }
    /// Advance only after the last HID IN report is acknowledged. The backing
    /// remains in the shared workspace until GET RESPONSE or explicit abort.
    pub fn complete_message(&mut self) -> bool {
        if self.message_status.is_some() {
            self.message_offset += self.message_length;
            self.message_length = 0;
            return self.pending_message();
        }
        false
    }
    pub fn continue_message(
        &mut self,
        bytes: &[u8],
        w: &mut SessionWorkspace,
        p: &mut Platform<'_>,
    ) -> Option<usize> {
        if bytes.len() < 2 || !matches!(bytes[0], 0 | 0x80) || bytes[1] != 0xc0 {
            return None;
        }
        // GET RESPONSE has no body. Decode only its bounded header shapes,
        // including the legacy nine-byte empty-Lc form, without constructing
        // the shared request parser over live response bytes.
        let result = match bytes {
            [_, _, 0, 0] => Ok(256),
            [_, _, 0, 0, le] => Ok(if *le == 0 { 256 } else { u32::from(*le) }),
            [_, _, 0, 0, 0, hi, lo] | [_, _, 0, 0, 0, 0, 0, hi, lo] => {
                let le = u16::from_be_bytes([*hi, *lo]);
                Ok(if le == 0 { 65536 } else { u32::from(le) })
            }
            [_, _, p1, p2, ..] if *p1 != 0 || *p2 != 0 => Err(Sw::WRONG_P1P2),
            _ => Err(Sw::WRONG_LENGTH),
        }
        .and_then(|limit| {
            if self.pending_message() {
                Ok(limit)
            } else {
                Err(Sw::COMMAND_NOT_ALLOWED)
            }
        });
        Some(match result {
            Ok(limit) => self.message_window(limit, Sw::SUCCESS),
            Err(sw) => {
                self.close(w, p);
                self.message_window(0, sw)
            }
        })
    }
    pub fn close(&mut self, w: &mut SessionWorkspace, p: &mut Platform<'_>) {
        if let SessionWorkspace::CtapStream(stream) = w {
            stream.close(p);
        }

        self.response = Response::Constant(&[]);
        self.message_status = None;
        self.message_offset = 0;
        self.message_length = 0;
    }
}

impl Default for Applet {
    fn default() -> Self {
        Self::new()
    }
}

/// Parsed HID MSG envelope. It owns semantic input, never source/PKE offsets.
pub enum Message {
    Ctap(Result<super::Command, super::Status>, u32),
    U2f(super::u2f::Request, u32),
    Error(Sw),
}

pub struct MessageParser {
    decoder: Option<canokey_protocol::apdu::FrameDecoder>,
    request: MessageInput,
}
enum MessageInput {
    Empty,
    Ctap(Request),
    U2f(super::u2f::Request),
    Error(Sw),
}
impl MessageParser {
    pub fn new(length: usize) -> Self {
        Self {
            decoder: canokey_protocol::apdu::FrameDecoder::new(length).ok(),
            request: MessageInput::Empty,
        }
    }
    #[inline(never)]
    pub fn consume(&mut self, bytes: &[u8]) {
        use canokey_protocol::apdu::FrameEvent;
        let Some(decoder) = &mut self.decoder else {
            return;
        };
        let result = decoder.feed_events(bytes, &mut |event| {
            match event {
                FrameEvent::Start(info) => {
                    let h = info.header;
                    self.request = if h.cla == 0 {
                        MessageInput::U2f(super::u2f::Request::new(h))
                    } else if h.cla != 0x80 {
                        MessageInput::Error(Sw::CLA_NOT_SUPPORTED)
                    } else if h.ins != INS_MSG {
                        MessageInput::Error(Sw::INS_NOT_SUPPORTED)
                    } else if !valid_message_parameters(h) {
                        MessageInput::Error(Sw::WRONG_P1P2)
                    } else {
                        MessageInput::Ctap(Request::new())
                    };
                }
                FrameEvent::Data(bytes) => match &mut self.request {
                    MessageInput::Ctap(request) => request.consume(bytes),
                    MessageInput::U2f(request) => request.consume(bytes),
                    _ => (),
                },
            }
            Ok(())
        });
        if result.is_err() {
            self.decoder = None;
        }
    }
    pub(crate) fn clear(&mut self, memory: &crate::ports::MemoryPort<'_>) {
        match &mut self.request {
            MessageInput::Ctap(r) => r.clear(memory),
            MessageInput::U2f(r) => r.clear(memory),
            _ => (),
        }
        self.request = MessageInput::Empty;
        self.decoder = None;
    }
    pub fn finish(&mut self) -> Message {
        let Some(Ok(info)) = self.decoder.take().map(|decoder| decoder.finish()) else {
            return Message::Error(Sw::WRONG_LENGTH);
        };
        let limit = info.le.unwrap_or(u32::MAX);
        match &mut self.request {
            MessageInput::Ctap(request) => Message::Ctap(request.finish(), limit),
            MessageInput::U2f(request) => Message::U2f(
                core::mem::replace(request, super::u2f::Request::new(request.header)),
                limit,
            ),
            MessageInput::Error(error) => Message::Error(*error),
            MessageInput::Empty => Message::Error(Sw::WRONG_LENGTH),
        }
    }
}

#[cfg(test)]
mod message_parameters_tests {
    use super::*;
    #[test]
    fn nfc_keepalive_hint_is_accepted_for_extended_and_hid_messages() {
        for p1 in [0, 0x80, 1, 0x7f, 0xff] {
            for p2 in [0, 1] {
                let valid = matches!(p1, 0 | 0x80) && p2 == 0;
                let header = Header {
                    cla: 0x80,
                    ins: INS_MSG,
                    p1,
                    p2,
                };
                assert_eq!(allows_extended(header), valid);
                let short = [0x80, 0x10, p1, p2, 1, 4];
                let extended = [0x80, 0x10, p1, p2, 0, 0, 1, 4];
                for frame in [short.as_slice(), extended.as_slice()] {
                    let mut parser = MessageParser::new(frame.len());
                    for chunk in frame.chunks(2) {
                        parser.consume(chunk);
                    }
                    let reply = parser.finish();
                    if valid {
                        assert!(matches!(
                            reply,
                            Message::Ctap(Ok(super::super::Command::GetInfo), _)
                        ));
                    } else {
                        assert!(matches!(reply, Message::Error(Sw::WRONG_P1P2)));
                    }
                }
            }
        }
    }
}
