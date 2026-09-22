// SPDX-License-Identifier: Apache-2.0
//! Explicit composition root for the ADMIN + PASS profile.
#![forbid(unsafe_code)]
use crate::{
    Platform,
    admin::{self, Admin, Grants},
    pass::Pass,
};
use canokey_protocol::{apdu::Header, response::StatusWord as Sw};
#[derive(Clone, Copy, PartialEq, Eq)]
enum Selected {
    None,
    Admin,
    #[cfg(feature = "oath")]
    Oath,
}
pub struct Registry {
    selected: Selected,
    #[cfg(feature = "oath")]
    oath: crate::oath_protocol::Oath,
    admin: Admin,
    pass: Pass,
}
impl Registry {
    pub const fn new() -> Self {
        Self {
            selected: Selected::None,
            #[cfg(feature = "oath")]
            oath: crate::oath_protocol::Oath::new(),
            admin: Admin::new(),
            pass: Pass::new(),
        }
    }
    pub fn reset(&mut self, p: &mut dyn Platform) {
        self.selected = Selected::None;
        self.admin.cancel_command(p);
        #[cfg(feature = "oath")]
        self.oath.reset(p);
    }
    pub fn select(
        &mut self,
        aid: &[u8],
        grants: &mut Grants,
        p: &mut dyn Platform,
    ) -> Result<u32, Sw> {
        // Resolve first: an unsuccessful SELECT must not discard the current applet.
        let next = if aid == admin::AID {
            Selected::Admin
        } else {
            #[cfg(feature = "oath")]
            if aid == crate::oath_protocol::AID {
                return self.select_oath(grants, p);
            }
            return Err(Sw::FILE_NOT_FOUND);
        };
        if self.selected != next {
            self.reset(p);
            grants.admin = false;
        }
        self.selected = next;
        Ok(0)
    }
    #[cfg(feature = "oath")]
    fn select_oath(&mut self, grants: &mut Grants, p: &mut dyn Platform) -> Result<u32, Sw> {
        if self.selected != Selected::Oath {
            self.reset(p);
            grants.admin = false;
        }
        let n = self.oath.select(p)?;
        self.selected = Selected::Oath;
        Ok(n)
    }
    pub fn accepts_cla(&self, header: Header) -> bool {
        match self.selected {
            Selected::Admin => header.cla == 0,
            #[cfg(feature = "oath")]
            Selected::Oath => header.unchained().cla == 0,
            Selected::None => header.cla == 0,
        }
    }
    pub fn command_capacity(&self) -> u32 {
        match self.selected {
            #[cfg(feature = "oath")]
            Selected::Oath => crate::oath_protocol::CAPACITY as u32,
            _ => admin::COMMAND_CAPACITY as u32,
        }
    }
    pub fn install(&mut self, p: &mut dyn Platform) -> Result<(), Sw> {
        self.admin.install(p)?;
        self.pass.install(p).map_err(admin::pass_error)?;
        #[cfg(feature = "oath")]
        self.oath.install(p)?;
        Ok(())
    }
    pub fn cancel_command(&mut self, p: &mut dyn Platform) {
        self.admin.cancel_command(p);
        #[cfg(feature = "oath")]
        self.oath.cancel_command(p);
    }
    pub fn consume(&mut self, bytes: &[u8]) -> Result<(), Sw> {
        #[cfg(feature = "oath")]
        if matches!(self.selected, Selected::Oath) {
            return self.oath.consume(bytes);
        }
        self.admin.consume(bytes)
    }
    pub fn finish(
        &mut self,
        header: Header,
        le: u32,
        grants: &mut Grants,
        p: &mut dyn Platform,
    ) -> Result<(u32, Sw), Sw> {
        #[cfg(feature = "oath")]
        if matches!(self.selected, Selected::Oath) {
            return self.oath.finish(header, le, &mut self.pass, p);
        }
        #[cfg(feature = "oath")]
        if header.ins == 0x05 {
            if !grants.admin {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            let shape = self.admin.check_empty(header);
            self.admin.cancel_command(p);
            shape?;
            self.oath.clear(&mut self.pass, p)?;
            return Ok((0, Sw::SUCCESS));
        }
        if header.ins == 0x50 {
            let check = self.admin.check_factory_reset(header, p);
            self.admin.cancel_command(p);
            check?;
            if !crate::presence::strong(p) {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            grants.admin = false;
            // PIN is reset last: failed partial reset remains locked and retryable.
            self.pass.clear(p).map_err(admin::pass_error)?;
            #[cfg(feature = "oath")]
            self.oath.clear(&mut self.pass, p)?;
            crate::auth::factory_reset(p).map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            return Ok((0, Sw::SUCCESS));
        }
        let _ = le;
        self.admin
            .finish(header, grants, &mut self.pass, p)
            .map(|n| (n, Sw::SUCCESS))
    }
    pub fn read_response(&self, offset: usize, out: &mut [u8]) -> Result<(), Sw> {
        #[cfg(feature = "oath")]
        if matches!(self.selected, Selected::Oath) {
            return self.oath.read_response(offset, out);
        }
        self.admin.read_response(offset, out)
    }
    pub fn take_presence(&mut self) -> bool {
        #[cfg(feature = "oath")]
        {
            core::mem::take(&mut self.oath.consumed_presence)
        }
        #[cfg(not(feature = "oath"))]
        {
            false
        }
    }
    pub fn touch(&self, index: u8, out: &mut [u8], p: &mut dyn Platform) -> Result<usize, Sw> {
        #[cfg(feature = "oath")]
        if let canokey_pass::domain::Slot::Oath { id, enter, .. } =
            self.pass.slot(index).map_err(admin::pass_error)?
        {
            use canokey_oath::service;
            let shared = core::cell::RefCell::new(p);
            let mut store = crate::oath_backend::Store(&shared);
            let mut mac = crate::oath_backend::Mac(&shared);
            // The physical gesture authorizes this output, independently of the OATH session.
            let mut result = service::calculate(
                &mut store,
                &mut mac,
                service::CredentialId(id),
                &[],
                service::Presence::Confirmed,
            )
            .map_err(crate::oath_protocol::status)?;
            let digits = usize::from(result.digits());
            let length = digits + usize::from(enter != 0);
            if out.len() < length {
                result.clear(&mut mac);
                return Err(Sw::WRONG_LENGTH);
            }
            let mut value = result.truncated();
            for byte in out[..digits].iter_mut().rev() {
                *byte = b'0' + (value % 10) as u8;
                value /= 10;
            }
            if enter != 0 {
                out[digits] = b'\r';
            }
            result.clear(&mut mac);
            return Ok(length);
        }
        let _ = p;
        self.pass.touch(index, out).map_err(admin::pass_error)
    }
    pub fn challenge(
        &self,
        index: u8,
        input: &[u8],
        out: &mut [u8; 20],
        p: &mut dyn Platform,
    ) -> Result<(), Sw> {
        self.pass
            .challenge(index, input, out, p)
            .map_err(admin::pass_error)
    }
}
