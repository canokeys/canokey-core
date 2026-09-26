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
#[cfg(feature = "ctap")]
pub(crate) const INS_PROVISION_ATTESTATION: u8 = 0x02;
#[cfg(feature = "ctap")]
const INS_CTAP_INSTALL: u8 = 0x01;
#[cfg(feature = "ctap")]
const INS_CTAP_CERTIFICATE: u8 = 0x09;
#[cfg(feature = "ctap")]
const INS_CTAP_BEGIN: u8 = 0x11;
#[cfg(feature = "ctap")]
const INS_CTAP_END: u8 = 0x12;

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
    #[cfg(feature = "ctap")]
    InstallFidoKey([u8; 32]),
    #[cfg(feature = "ctap")]
    ResetCtap,
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
    #[cfg(feature = "ctap")]
    certificate: bool,
}
impl Admin {
    pub const fn new() -> Self {
        Self {
            command: [0; COMMAND_CAPACITY],
            used: 0,
            response: [0; pass_protocol::MAX_DESCRIPTION_LENGTH],
            response_len: 0,
            #[cfg(feature = "ctap")]
            certificate: false,
        }
    }
    pub fn install(&mut self, p: &mut Platform<'_>) -> Result<(), Sw> {
        auth::install(p).map_err(auth_error)
    }
    pub fn begin(&mut self, h: Header, grants: &Grants, p: &mut Platform<'_>) -> Result<(), Sw> {
        let _ = (&h, &grants, &p);
        #[cfg(feature = "ctap")]
        if h.ins == INS_PROVISION_ATTESTATION {
            if !grants.admin {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            if h.p1 != 0 || h.p2 != 0 {
                return Err(Sw::WRONG_P1P2);
            }
            p.storage.stage_begin().map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            self.certificate = true;
        }
        Ok(())
    }
    pub fn cancel_command(&mut self, p: &mut Platform<'_>) {
        #[cfg(feature = "ctap")]
        if self.certificate {
            p.storage.stage_abort();
            self.certificate = false;
        }
        p.memory.wipe(&mut self.command);
        self.used = 0;
    }
    pub fn consume(&mut self, data: &[u8], p: &mut Platform<'_>) -> Result<(), Sw> {
        let _ = &p;
        #[cfg(feature = "ctap")]
        if self.certificate {
            self.used = self
                .used
                .checked_add(data.len())
                .filter(|n| *n <= crate::applets::ctap::provision::CERT_LIMIT)
                .ok_or(Sw::WRONG_LENGTH)?;
            return p
                .storage
                .stage_append(data)
                .map_err(|_| Sw::UNABLE_TO_PROCESS);
        }
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
        le: u32,
        grants: &mut Grants,
        pass: Option<&mut Pass>,
        p: &mut Platform<'_>,
    ) -> Result<Action, Sw> {
        self.response_len = 0;
        let result = if h.ins == 0x42 && h.p1 == 0 && h.p2 == 0 && le < 6 {
            Err(Sw::WRONG_LENGTH)
        } else if h.ins == INS_FACTORY_RESET {
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
        #[cfg(feature = "ctap")]
        if matches!(
            h.ins,
            INS_CTAP_INSTALL | INS_PROVISION_ATTESTATION | INS_CTAP_CERTIFICATE
        ) {
            if !grants.admin {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            if h.p1 != 0 || h.p2 != 0 {
                return Err(Sw::WRONG_P1P2);
            }
            if h.ins == INS_CTAP_INSTALL {
                let key = self.command[..self.used]
                    .try_into()
                    .map_err(|_| Sw::WRONG_LENGTH)?;
                return Ok(Action::InstallFidoKey(key));
            }
            if h.ins == INS_CTAP_CERTIFICATE {
                if self.used != 0 {
                    return Err(Sw::WRONG_LENGTH);
                }
                return Ok(Action::ResetCtap);
            }
            if !self.certificate {
                return Err(Sw::CONDITIONS_NOT_SATISFIED);
            }
            p.storage
                .stage_commit(crate::ports::Record::CtapCertificate)
                .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            self.certificate = false;
            return Ok(Action::Response(0));
        }
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
        #[cfg(feature = "ndef")]
        if matches!(h.ins, 0x07 | 0x08) {
            if !grants.admin {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            // ADMIN selection has already dropped the NDEF session. This
            // temporary policy object shares storage and needs no file buffer.
            let mut ndef = crate::applets::ndef::Ndef::new();
            if h.ins == 0x07 {
                ndef.install(true, p.storage)?;
            } else {
                ndef.set_read_only(h.p1, p.storage)?;
            }
            return Ok(Action::Response(0));
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
        if matches!(h.ins, 0x14 | 0x40 | 0x42) {
            return self.device_config(h, grants, p);
        }
        #[cfg(feature = "ctap")]
        if matches!(h.ins, INS_CTAP_BEGIN | INS_CTAP_END) {
            if h.p1 != 0 || h.p2 != 0 {
                return Err(Sw::WRONG_P1P2);
            }
            if !grants.admin {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            use crate::applets::ctap::settings::Sm2;
            if h.ins == INS_CTAP_END {
                Sm2::save(&self.command[..self.used], p)?;
                return Ok(0);
            }
            if self.used != 0 {
                return Err(Sw::WRONG_LENGTH);
            }
            let config = Sm2::load(p).map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            self.response[..8].copy_from_slice(&config.encode());
            self.response_len = 8;
            return Ok(8);
        }
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
                        pass_protocol::read_config(records, Layout, &mut self.response)
                            .map_err(crate::applets::pass::status)?;
                }
            }
            _ => return Err(Sw::INS_NOT_SUPPORTED),
        }
        Ok(self.response_len as u32)
    }
    #[cfg(classic_presence)]
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
    fn device_config(
        &mut self,
        h: Header,
        grants: &Grants,
        p: &mut Platform<'_>,
    ) -> Result<u32, Sw> {
        use crate::runtime::config;
        let io = |_| Sw::UNABLE_TO_PROCESS;
        if h.ins == 0x14 {
            if h.p1 > 1 || h.p2 > 1 {
                return Err(Sw::WRONG_P1P2);
            }
            if self.used != 0 {
                return Err(Sw::WRONG_LENGTH);
            }
            if h.p1 == 0 {
                self.response[0] =
                    u8::from(config::flags(p.storage).map_err(io)? & config::NFC != 0);
                self.response_len = 1;
                return Ok(1);
            }
            if !grants.admin {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            config::update(
                p.storage,
                config::NFC,
                if h.p2 == 0 { 0 } else { config::NFC },
            )
            .map_err(io)?;
            return Ok(0);
        }
        if h.ins == 0x42 {
            if h.p1 != 0 || h.p2 != 0 {
                return Err(Sw::WRONG_P1P2);
            }
            let flags = config::flags(p.storage).map_err(io)?;
            self.response[..6].copy_from_slice(&[
                u8::from(flags & config::LED != 0),
                0,
                0,
                u8::from(flags & config::NDEF != 0),
                u8::from(flags & config::WEBUSB != 0),
                ((flags & config::FEATURES) >> 7) as u8,
            ]);
            #[cfg(feature = "ndef")]
            {
                self.response[2] = u8::from(crate::applets::ndef::Ndef::new().read_only(p.storage));
            }
            self.response_len = 6;
            return Ok(6);
        }
        if !grants.admin {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        let mask = match h.p1 {
            1 => config::LED,
            4 => config::NDEF,
            5 => config::WEBUSB,
            6 => {
                if self.used != 0 {
                    return Err(Sw::WRONG_LENGTH);
                }
                if h.p2 & !0x3f != 0 {
                    return Err(Sw::WRONG_P1P2);
                }
                config::FEATURES
            }
            _ => return Err(Sw::WRONG_P1P2),
        };
        let value = if h.p1 == 6 {
            u32::from(h.p2) << 7
        } else if h.p2 & 1 != 0 {
            mask
        } else {
            0
        };
        config::update(p.storage, mask, value).map_err(io)?;
        Ok(0)
    }
    // Factory reset is the blocked-ADMIN recovery path: 50 00 00 plus literal
    // RESET, with no retries left. The runtime separately requires five touches
    // before executing the returned reset action; this check alone never erases.
    pub fn check_factory_reset(&self, h: Header, p: &mut Platform<'_>) -> Result<(), Sw> {
        if p.device.contactless() {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
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
        crate::applets::close_response(p.memory, &mut self.response, &mut self.response_len);
    }
    pub fn read_response(&self, offset: usize, out: &mut [u8]) -> Result<(), Sw> {
        crate::applets::read_response_chunk(&self.response, self.response_len, offset, out)
    }
}
