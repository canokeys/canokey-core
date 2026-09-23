// SPDX-License-Identifier: Apache-2.0
//! ADMIN protocol adapter. PASS remains a typed service without APDU knowledge.
#![forbid(unsafe_code)]
use crate::applets::pass::{codec::Layout, domain};
use crate::{
    Platform,
    applets::{
        admin::{pass_config as pass_protocol, pin as auth},
        pass::service::Pass,
    },
};
use canokey_protocol::{apdu::Header, response::StatusWord as Sw};
pub const AID: &[u8] = &[0xf0, 0, 0, 0, 0];
pub const COMMAND_CAPACITY: usize = 64;
#[derive(Default)]
pub struct Grants {
    pub admin: bool,
}
pub(crate) fn auth_error(error: auth::Error) -> Sw {
    match error {
        auth::Error::Persistence => Sw::UNABLE_TO_PROCESS,
        auth::Error::Length => Sw::WRONG_LENGTH,
        auth::Error::Blocked => Sw::AUTHENTICATION_BLOCKED,
        auth::Error::Retries(n) => Sw(0x63c0 | u16::from(n)),
    }
}
pub fn pass_error(error: domain::Error) -> Sw {
    match error {
        domain::Error::Persistence => Sw::UNABLE_TO_PROCESS,
        _ => Sw::WRONG_DATA,
    }
}
pub enum Action {
    Response(u32),
    FactoryReset,
    #[cfg(feature = "oath")]
    ResetOath,
    #[cfg(feature = "openpgp")]
    ResetOpenPgp,
}
pub struct Admin {
    command: [u8; COMMAND_CAPACITY],
    used: usize,
    response: [u8; pass_protocol::MAX_DESCRIPTION_LENGTH],
    response_len: usize,
}
impl Admin {
    pub const fn new() -> Self {
        Self {
            command: [0; COMMAND_CAPACITY],
            used: 0,
            response: [0; pass_protocol::MAX_DESCRIPTION_LENGTH],
            response_len: 0,
        }
    }
    pub fn install(&mut self, p: &mut Platform<'_>) -> Result<(), Sw> {
        auth::install(p).map_err(auth_error)
    }
    pub fn cancel_command(&mut self, p: &mut Platform<'_>) {
        p.memory.wipe(&mut self.command);
        self.used = 0;
    }
    pub fn consume(&mut self, data: &[u8]) -> Result<(), Sw> {
        let end = self
            .used
            .checked_add(data.len())
            .filter(|n| *n <= COMMAND_CAPACITY)
            .ok_or(Sw::WRONG_LENGTH)?;
        self.command[self.used..end].copy_from_slice(data);
        self.used = end;
        Ok(())
    }
    pub fn finish(
        &mut self,
        h: Header,
        grants: &mut Grants,
        pass: Option<&mut Pass>,
        p: &mut Platform<'_>,
    ) -> Result<Action, Sw> {
        self.response_len = 0;
        let result = if h.ins == 0x50 {
            self.check_factory_reset(h, p)
                .map(|()| Action::FactoryReset)
        } else {
            self.dispatch(h, grants, pass, p)
        };
        self.cancel_command(p);
        result
    }
    fn dispatch(
        &mut self,
        h: Header,
        grants: &mut Grants,
        pass: Option<&mut Pass>,
        p: &mut Platform<'_>,
    ) -> Result<Action, Sw> {
        #[cfg(feature = "openpgp")]
        if h.ins == 0x03 {
            if !grants.admin {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            if h.p1 != 0 || h.p2 != 0 {
                return Err(Sw::WRONG_P1P2);
            }
            self.check_empty(h)?;
            return Ok(Action::ResetOpenPgp);
        }
        #[cfg(feature = "oath")]
        if h.ins == 0x05 {
            if !grants.admin {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            self.check_empty(h)?;
            return Ok(Action::ResetOath);
        }
        self.execute(h, grants, pass, p).map(Action::Response)
    }
    fn execute(
        &mut self,
        h: Header,
        grants: &mut Grants,
        pass: Option<&mut Pass>,
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        // The published ADMIN protocol specifies 6D00 for unknown instructions.
        if !matches!(h.ins, 0x20 | 0x21 | 0x43 | 0x44 | 0x13) {
            return Err(Sw::INS_NOT_SUPPORTED);
        }
        if h.p2 != 0 {
            return Err(Sw::WRONG_P1P2);
        }
        if h.ins == 0x20 {
            if h.p1 != 0 {
                return Err(Sw::WRONG_P1P2);
            }
            if self.used == 0 {
                return if grants.admin {
                    Ok(0)
                } else {
                    Err(Sw(0x63c0 | u16::from(auth::retries(p).map_err(auth_error)?)))
                };
            }
            grants.admin = false;
            auth::verify(&self.command[..self.used], p).map_err(auth_error)?;
            grants.admin = true;
            return Ok(0);
        }
        if !grants.admin {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        match h.ins {
            0x21 => {
                if h.p1 != 0 {
                    return Err(Sw::WRONG_P1P2);
                }
                if !(6..=64).contains(&self.used) {
                    return Err(Sw::WRONG_LENGTH);
                }
                grants.admin = false;
                auth::change(&self.command[..self.used], p).map_err(auth_error)?;
            }
            0x44 => {
                let pass = pass.ok_or(Sw::INS_NOT_SUPPORTED)?;
                let (index, slot) = pass_protocol::decode_config(h.p1, &self.command[..self.used])?;
                pass.configure(index, slot, p.storage, p.memory)
                    .map_err(pass_error)?;
            }
            0x43 | 0x13 => {
                let pass = pass.ok_or(Sw::INS_NOT_SUPPORTED)?;
                if h.p1 != 0 {
                    return Err(Sw::WRONG_P1P2);
                }
                if self.used != 0 {
                    return Err(Sw::WRONG_LENGTH);
                }
                if h.ins == 0x13 {
                    pass.clear(p.storage, p.memory).map_err(pass_error)?;
                } else {
                    let records = pass.records().map_err(pass_error)?;
                    self.response_len =
                        pass_protocol::read_config_part(records, Layout, 0, &mut [])
                            .map_err(pass_error)?;
                    pass_protocol::read_config_part(
                        records,
                        Layout,
                        0,
                        &mut self.response[..self.response_len],
                    )
                    .map_err(pass_error)?;
                }
            }
            _ => return Err(Sw::INS_NOT_SUPPORTED),
        }
        Ok(self.response_len as u32)
    }
    #[cfg(any(feature = "oath", feature = "openpgp"))]
    pub fn check_empty(&self, h: Header) -> Result<(), Sw> {
        if h.p1 != 0 || h.p2 != 0 {
            return Err(Sw::WRONG_P1P2);
        }
        if self.used != 0 {
            return Err(Sw::WRONG_LENGTH);
        }
        Ok(())
    }
    pub fn check_factory_reset(&self, h: Header, p: &mut Platform<'_>) -> Result<(), Sw> {
        if h.p1 != 0 || h.p2 != 0 {
            return Err(Sw::WRONG_P1P2);
        }
        if self.used != 5 {
            return Err(Sw::WRONG_LENGTH);
        }
        if &self.command[..5] != b"RESET" {
            return Err(Sw::WRONG_DATA);
        }
        if auth::retries(p).map_err(auth_error)? != 0 {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        Ok(())
    }
    pub fn close_response(&mut self, p: &mut Platform<'_>) {
        p.memory.wipe(&mut self.response);
        self.response_len = 0;
    }
    pub fn read_response(&self, offset: usize, out: &mut [u8]) -> Result<(), Sw> {
        let end = offset.checked_add(out.len()).ok_or(Sw::WRONG_LENGTH)?;
        out.copy_from_slice(
            self.response[..self.response_len]
                .get(offset..end)
                .ok_or(Sw::WRONG_LENGTH)?,
        );
        Ok(())
    }
}
