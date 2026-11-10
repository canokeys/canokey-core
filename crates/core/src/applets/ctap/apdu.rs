// SPDX-License-Identifier: Apache-2.0
//! FIDO SELECT and APDU command envelope over the shared CTAP applet.
use super::{Applet, Request, Response};
use crate::{ports::Platform, runtime::workspace::SessionWorkspace};
use canokey_protocol::{
    apdu::{Header, fido},
    response::StatusWord as Sw,
};

// Preserve the legacy six-byte SELECT reply; CTAP2 capabilities use GetInfo.
const VERSION: &[u8] = b"U2F_V2";
pub(super) use canokey_protocol::apdu::{FIDO_CBOR_INS as INS_MSG, fido::valid_message_parameters};

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
        fido::begin_message(header)
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
        header: Header,
        w: &mut SessionWorkspace,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<u32, Sw> {
        if header.cla != 0x00 {
            fido::finish_message(header)?;
        }
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
            let request = w.ctap_request_with(p.memory);
            // The APDU envelope rejects an empty CBOR message with6700.
            // Native HID keeps the CTAP InvalidLength status from finish().
            if request.command.is_none() {
                return Err(Sw::WRONG_LENGTH);
            }
            let mut command = request.finish();
            self.dispatch(&mut command, w, p);
        }
        Ok(())
    }
}
