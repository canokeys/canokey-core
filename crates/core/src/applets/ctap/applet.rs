// SPDX-License-Identifier: Apache-2.0
//! Shared CTAP/U2F session, execution and response backing for all transports.
use super::{Response, Session};
use crate::{ports::Platform, runtime::workspace::SessionWorkspace};
use canokey_protocol::response::StatusWord as Sw;

pub struct Applet {
    pub(super) response: Response,
    pub(super) session: Session,
    pub(super) message_status: Option<Sw>,
    pub(super) message_offset: usize,
    pub(super) message_length: usize,
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
    pub(crate) fn take_presence_attempt(&mut self) -> bool {
        self.session.presence.take_attempt()
    }
    #[cfg(feature = "admin")]
    pub(crate) fn reset_persistent(
        &mut self,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), super::Status> {
        self.close(w, p);
        self.session.reset_persistent(p)
    }
    pub fn install(&mut self, p: &mut Platform<'_, impl crate::ports::Backends>) -> Result<(), Sw> {
        self.session.install(p).map_err(|_| Sw::UNABLE_TO_PROCESS)
    }
    pub fn response_preemptable(&self) -> bool {
        // Responses longer than 256 bytes and U2F registration responses
        // backed by a certificate source may be preempted between APDU chunks.
        self.response.len() > 256
            || matches!(
                self.response,
                Response::Authentication {
                    certificate: Some(_),
                    ..
                }
            )
    }
    pub fn reset(
        &mut self,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) {
        self.session.abort_blob(p);
        self.session.reset(p.memory);
        self.close(w, p);
    }
    pub fn cancel_command(&mut self, w: &mut SessionWorkspace) {
        // GET RESPONSE abandons input chaining while retaining response backing.
        w.cancel_ctap_request();
    }
    pub(crate) fn finish_hid(
        &mut self,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> usize {
        let message = self.finish_hid_command(w, p);
        self.complete(w, p, message)
    }
    #[inline(never)]
    fn finish_hid_command(
        &mut self,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Option<(u32, Sw)> {
        if let SessionWorkspace::CtapMessage(request) = w {
            let mut command = request.finish();
            Some(self.dispatch_message(&mut command, w, p))
        } else {
            let mut command = w.ctap_request_with(p.memory).finish();
            self.dispatch(&mut command, w, p);
            None
        }
    }
    pub(super) fn dispatch(
        &mut self,
        command: &mut Result<super::Command, super::Status>,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) {
        self.response = self
            .session
            .execute(command, &mut w.classic_with(p.memory), p);
    }
    pub fn execute(
        &mut self,
        command: &mut Result<super::Command, super::Status>,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> usize {
        self.dispatch(command, w, p);
        self.complete(w, p, None)
    }
    pub(super) fn complete(
        &mut self,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
        message: Option<(u32, Sw)>,
    ) -> usize {
        self.prepare(w, p);
        if let Some((limit, sw)) = message {
            self.message_offset = 0;
            self.message_window(limit, sw)
        } else {
            self.response.len()
        }
    }
    pub fn read(
        &mut self,
        offset: usize,
        output: &mut [u8],
        w: &mut SessionWorkspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Sw> {
        if let Some(sw) = self.message_status {
            let length = self.message_length;
            if !canokey_protocol::response::checked_window(offset, output.len(), length + 2) {
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
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Sw> {
        if matches!(self.response, Response::Stream(_)) {
            let Some(mut stream) = w.ctap_stream() else {
                return Err(Sw::UNABLE_TO_PROCESS);
            };
            stream.read(offset, output, p)
        } else {
            self.response
                .read(&mut w.classic_with(p.memory), offset, output, p.storage)
        }
    }
    fn prepare(
        &mut self,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) {
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
    pub fn close(
        &mut self,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) {
        if let Some(mut stream) = w.ctap_stream() {
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
