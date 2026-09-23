// SPDX-License-Identifier: Apache-2.0
//! ADMIN protocol adapter. PASS remains a typed service without APDU knowledge.
#![forbid(unsafe_code)]
// Applet instruction bytes; P1/P2 and TLV tags have separate meanings.
const INS_FACTORY_RESET: u8 = 0x50;
#[cfg(feature = "openpgp")]
const INS_RESET_OPENPGP: u8 = 0x03;
#[cfg(feature = "piv")]
const INS_RESET_PIV: u8 = 0x04;
#[cfg(feature = "oath")]
const INS_RESET_OATH: u8 = 0x05;
const INS_VERIFY: u8 = 0x20;
const INS_CHANGE_PIN: u8 = 0x21;
const INS_GET_PASS_CONFIG: u8 = 0x43;
const INS_SET_PASS_CONFIG: u8 = 0x44;
const INS_RESET_PASS: u8 = 0x13;

use crate::applets::pass::codec::Layout;
use crate::{
    Platform,
    applets::{
        admin::{pass_config as pass_protocol, pin as auth},
        pass::service::Pass,
    },
};
use canokey_protocol::{apdu::Header, response::StatusWord as Sw};
pub const AID: &[u8] = &[0xf0, 0x00, 0x00, 0x00, 0x00];
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
        auth::Error::Retries(n) => Sw::retries(n),
    }
}

pub enum Action {
    Response(u32),
    FactoryReset,
    #[cfg(feature = "piv")]
    ResetPiv,
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
        let result = if h.ins == INS_FACTORY_RESET {
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
        if h.ins == INS_RESET_OPENPGP {
            if !grants.admin {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            if h.p1 != 0x00 || h.p2 != 0x00 {
                return Err(Sw::WRONG_P1P2);
            }
            self.check_empty(h)?;
            return Ok(Action::ResetOpenPgp);
        }
        #[cfg(feature = "piv")]
        if h.ins == INS_RESET_PIV {
            if !grants.admin {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            self.check_empty(h)?;
            return Ok(Action::ResetPiv);
        }
        #[cfg(feature = "oath")]
        if h.ins == INS_RESET_OATH {
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
        if !matches!(
            h.ins,
            INS_VERIFY
                | INS_CHANGE_PIN
                | INS_GET_PASS_CONFIG
                | INS_SET_PASS_CONFIG
                | INS_RESET_PASS
        ) {
            return Err(Sw::INS_NOT_SUPPORTED);
        }
        // ADMIN credential/PASS commands reserve P2=00. P1 is also 00
        // except SET PASS CONFIG, where 1/2 selects the keyboard slot.
        if h.p2 != 0x00 {
            return Err(Sw::WRONG_P1P2);
        }
        if h.ins == INS_VERIFY {
            if h.p1 != 0x00 {
                return Err(Sw::WRONG_P1P2);
            }
            if self.used == 0 {
                return if grants.admin {
                    Ok(0)
                } else {
                    Err(Sw::retries(auth::retries(p).map_err(auth_error)?))
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
            INS_CHANGE_PIN => {
                if h.p1 != 0x00 {
                    return Err(Sw::WRONG_P1P2);
                }
                if !(auth::MIN_LENGTH..=auth::MAX_LENGTH).contains(&self.used) {
                    return Err(Sw::WRONG_LENGTH);
                }
                grants.admin = false;
                auth::change(&self.command[..self.used], p).map_err(auth_error)?;
            }
            INS_SET_PASS_CONFIG => {
                let pass = pass.ok_or(Sw::INS_NOT_SUPPORTED)?;
                let (index, slot) = pass_protocol::decode_config(h.p1, &self.command[..self.used])?;
                pass.configure(index, slot, p.storage, p.memory)
                    .map_err(crate::applets::pass::status)?;
            }
            INS_GET_PASS_CONFIG | INS_RESET_PASS => {
                let pass = pass.ok_or(Sw::INS_NOT_SUPPORTED)?;
                if h.p1 != 0x00 {
                    return Err(Sw::WRONG_P1P2);
                }
                if self.used != 0 {
                    return Err(Sw::WRONG_LENGTH);
                }
                if h.ins == INS_RESET_PASS {
                    pass.clear(p.storage, p.memory)
                        .map_err(crate::applets::pass::status)?;
                } else {
                    let records = pass.records().map_err(crate::applets::pass::status)?;
                    self.response_len =
                        pass_protocol::read_config_part(records, Layout, 0, &mut [])
                            .map_err(crate::applets::pass::status)?;
                    pass_protocol::read_config_part(
                        records,
                        Layout,
                        0,
                        &mut self.response[..self.response_len],
                    )
                    .map_err(crate::applets::pass::status)?;
                }
            }
            _ => return Err(Sw::INS_NOT_SUPPORTED),
        }
        Ok(self.response_len as u32)
    }
    #[cfg(any(feature = "oath", feature = "openpgp", feature = "piv"))]
    // Per-applet reset commands carry no options: P1/P2=00 and no data.
    // The caller checks ADMIN authorization; this helper checks wire shape only.
    pub fn check_empty(&self, h: Header) -> Result<(), Sw> {
        if h.p1 != 0x00 || h.p2 != 0x00 {
            return Err(Sw::WRONG_P1P2);
        }
        if self.used != 0 {
            return Err(Sw::WRONG_LENGTH);
        }
        Ok(())
    }
    // Factory reset is the blocked-ADMIN recovery path: 50 00 00 plus literal
    // RESET, with no retries left. The runtime separately requires five touches
    // before executing the returned reset action; this check alone never erases.
    pub fn check_factory_reset(&self, h: Header, p: &mut Platform<'_>) -> Result<(), Sw> {
        if h.p1 != 0x00 || h.p2 != 0x00 {
            return Err(Sw::WRONG_P1P2);
        }
        if self.used != b"RESET".len() {
            return Err(Sw::WRONG_LENGTH);
        }
        if &self.command[..b"RESET".len()] != b"RESET" {
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
