// SPDX-License-Identifier: Apache-2.0
//! FIDO SELECT and APDU command envelope over the shared CTAP applet.
use super::{Applet, Request, Response};
use crate::{ports::Platform, runtime::workspace::SessionWorkspace};
use canokey_protocol::{apdu::Header, response::StatusWord as Sw};

// FIDO Alliance RID A000000647, FIDO application suffix 2F0001.
pub const AID: &[u8] = &canokey_protocol::apdu::FIDO_AID;
// Preserve the legacy six-byte SELECT reply; CTAP2 capabilities use GetInfo.
const VERSION: &[u8] = b"U2F_V2";
pub(super) const INS_MSG: u8 = 0x10;

pub(super) fn valid_message_parameters(header: Header) -> bool {
    // P1 bit 7 allows NFCCTAP_GETRESPONSE keepalive polling. Like the legacy
    // synchronous engine, we may finish the command directly with 9000; the
    // hint must not make standards-compliant NFC clients fail discovery.
    header.p1 & 0x7f == 0 && header.p2 == 0
}

pub fn allows_extended(header: Header) -> bool {
    // Let U2F classify unknown instructions after valid extended framing, just
    // as for short APDUs. Runtime ownership and command-size limits still apply.
    header.cla == 0
        || (header.cla == 0x80 && header.ins == INS_MSG && valid_message_parameters(header))
}

impl Applet {
    pub fn select(
        &mut self,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> u32 {
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
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Sw> {
        self.close(w, p);
        if header.cla == 0 {
            w.wipe_active(p.memory);
            *w = SessionWorkspace::U2fRequest(super::u2f::Request::new(header));
            return Ok(());
        }
        w.wipe_active(p.memory);
        *w = SessionWorkspace::CtapRequest(Request::new());
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
    pub fn finish(
        &mut self,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<u32, Sw> {
        self.finish_apdu_command(w, p)?;
        Ok(self.complete(w, p, None) as u32)
    }
    // Command objects must leave the stack before PQ response initialization.
    #[inline(never)]
    fn finish_apdu_command(
        &mut self,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Sw> {
        if let SessionWorkspace::U2fRequest(request) = w {
            let request = core::mem::replace(request, super::u2f::Request::new(request.header));
            self.response = self
                .session
                .u2f(&request, &mut w.classic_with(p.memory), p)?;
        } else {
            let mut command = w.ctap_request_with(p.memory).finish();
            self.dispatch(&mut command, w, p);
        }
        Ok(())
    }
}
