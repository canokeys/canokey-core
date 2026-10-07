// SPDX-License-Identifier: Apache-2.0
//! HID MSG APDU-envelope decoding and continuation over shared response backing.
use super::{
    Applet, Request, Response,
    apdu::{INS_MSG, valid_message_parameters},
};
use crate::{ports::Platform, runtime::workspace::SessionWorkspace};
use canokey_protocol::response::StatusWord as Sw;

impl Applet {
    pub fn execute_message(
        &mut self,
        command: &mut Message,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_>,
    ) -> usize {
        let message = self.dispatch_message(command, w, p);
        self.complete(w, p, Some(message))
    }
    pub(super) fn dispatch_message(
        &mut self,
        command: &mut Message,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_>,
    ) -> (u32, Sw) {
        let limit = match command {
            Message::Ctap(_, limit) | Message::U2f(_, limit) => *limit,
            Message::Error(_) => u32::MAX,
        };
        let result = match command {
            Message::Ctap(command, _) => {
                Ok(self
                    .session
                    .execute(command, &mut w.classic_with(p.memory), p))
            }
            Message::U2f(request, _) => self.session.u2f(request, &mut w.classic_with(p.memory), p),
            Message::Error(error) => Err(*error),
        };
        let (response, sw) = match result {
            Ok(response) => (response, Sw::SUCCESS),
            Err(sw) => (Response::Constant(&[]), sw),
        };
        self.response = response;
        (limit, sw)
    }
    pub(super) fn message_window(&mut self, limit: u32, final_sw: Sw) -> usize {
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
    use super::super::apdu::allows_extended;
    use super::*;
    use canokey_protocol::apdu::Header;
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
