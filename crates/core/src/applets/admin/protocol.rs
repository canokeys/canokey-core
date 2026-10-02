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
const INS_WRITE_SERIAL: u8 = 0x30;
const INS_READ_VERSION: u8 = 0x31;
const INS_READ_SERIAL: u8 = 0x32;
const INS_NFC_ENABLE: u8 = 0x14;
const INS_CONFIG: u8 = 0x40;
const INS_READ_CONFIG: u8 = 0x42;
#[cfg(feature = "ndef")]
const INS_RESET_NDEF: u8 = 0x07;
#[cfg(feature = "ndef")]
const INS_NDEF_READ_ONLY: u8 = 0x08;
const INS_VENDOR: u8 = 0xff;
const P1_CORE_COMMIT: u8 = 0x02;
const INFORMATION_CHIP_ID: u8 = 0x03;
const P1_CONFIG_LED: u8 = 0x01;
const P1_CONFIG_NDEF: u8 = 0x04;
const P1_CONFIG_WEBUSB: u8 = 0x05;
const P1_CONFIG_FEATURES: u8 = 0x06;
const CONFIG_RESPONSE_BYTES: usize = 6;
// CIU vendor recovery payload, checked in addition to ADMIN authorization.
// This literal is a command discriminator, not a secret authentication factor.
const RECOVERY_PAYLOAD: &[u8] = b"D3549Fa2dcb$23n";
const INS_STORAGE_USAGE: u8 = 0x41;
const INS_GET_PASS_CONFIG: u8 = 0x43;
const INS_SET_PASS_CONFIG: u8 = 0x44;
pub(crate) const INS_SET_KEYMAP: u8 = 0x45;
const INS_GET_KEYMAP: u8 = 0x46;
const INS_RESET_KEYMAP: u8 = 0x47;
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
pub const COMMAND_CAPACITY: usize = 256;
use crate::runtime::workspace::Workspace;
const _: () =
    assert!(crate::runtime::workspace::OUTPUT_BYTES >= pass_protocol::MAX_DESCRIPTION_LENGTH);
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
    used: usize,
    response_len: usize,
    #[cfg(feature = "ctap")]
    certificate: bool,
}
impl Admin {
    pub const fn new() -> Self {
        Self {
            used: 0,
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
    pub fn cancel_command(&mut self, w: &mut Workspace, p: &mut Platform<'_>) {
        self.abort_transaction(p);
        p.memory.wipe(w.input);
    }
    /// End external resources; the registry wipes its active workspace once.
    pub(crate) fn abort_transaction(&mut self, p: &mut Platform<'_>) {
        let _ = &p;
        #[cfg(feature = "ctap")]
        if self.certificate {
            p.storage.stage_abort();
            self.certificate = false;
        }
        self.used = 0;
    }
    pub fn consume(
        &mut self,
        data: &[u8],
        w: &mut Workspace,
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
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
        w.input[self.used..end].copy_from_slice(data);
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
        w: &mut Workspace,
    ) -> Result<Action, Sw> {
        self.response_len = 0;
        if h.ins == INS_GET_KEYMAP
            && h.p1 == 0
            && h.p2 <= 1
            && le
                < if h.p2 == 0 {
                    1
                } else {
                    crate::runtime::config::KEYMAP_BYTES as u32
                }
        {
            self.cancel_command(w, p);
            return Err(Sw::WRONG_LENGTH);
        }

        // Information queries truncate at Le, without GET RESPONSE chaining.
        if h.ins == INS_READ_VERSION || (h.ins == INS_READ_SERIAL && h.p1 != 0) {
            let result = if h.p2 != 0
                || (h.ins == INS_READ_VERSION && h.p1 > P1_CORE_COMMIT)
                || (h.ins == INS_READ_SERIAL && h.p1 != 1)
            {
                Err(Sw::WRONG_P1P2)
            } else if self.used != 0 {
                Err(Sw::WRONG_LENGTH)
            } else {
                let capacity = (le as usize).min(w.output.len());
                self.response_len = p.device.information(
                    if h.ins == INS_READ_SERIAL {
                        INFORMATION_CHIP_ID
                    } else {
                        h.p1
                    },
                    &mut w.output[..capacity],
                );
                if self.response_len > capacity {
                    self.response_len = 0;
                    Err(Sw::UNABLE_TO_PROCESS)
                } else {
                    Ok(Action::Response(self.response_len as u32))
                }
            };
            self.cancel_command(w, p);
            return result;
        }
        if h.ins == INS_STORAGE_USAGE {
            let result = if h.p1 > 1 || h.p2 != 0 {
                Err(Sw::WRONG_P1P2)
            } else if le
                < if h.p1 == 0 {
                    super::usage::SUMMARY_BYTES as u32
                } else {
                    super::usage::APPLET_BYTES as u32
                }
            {
                Err(Sw::WRONG_LENGTH)
            } else {
                super::usage::read(p.storage, h.p1 == 1, w.output).map(|n| {
                    self.response_len = n;
                    Action::Response(n as u32)
                })
            };
            self.cancel_command(w, p);
            return result;
        }
        let result = if h.p1 == 0
            && h.p2 == 0
            && ((h.ins == INS_READ_CONFIG && le < CONFIG_RESPONSE_BYTES as u32)
                || (h.ins == INS_READ_SERIAL && le < crate::runtime::config::SERIAL_BYTES as u32))
        {
            Err(Sw::WRONG_LENGTH)
        } else if h.ins == INS_FACTORY_RESET {
            self.check_factory_reset(h, w, p)
                .map(|()| Action::FactoryReset)
        } else {
            self.dispatch(h, grants, pass, p, w)
        };
        self.cancel_command(w, p);
        result
    }
    // Keep provisioning/reset decoding out of the registry's reset orchestration.
    // This boundary reduces the complete CIU images with the pinned optimizer.
    #[inline(never)]
    fn dispatch(
        &mut self,
        h: Header,
        grants: &mut Grants,
        pass: Option<&mut Pass>,
        p: &mut Platform<'_>,
        w: &mut Workspace,
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
                let key = w.input[..self.used]
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
        if matches!(h.ins, INS_RESET_NDEF | INS_NDEF_READ_ONLY) {
            if !grants.admin {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            // ADMIN selection has already dropped the NDEF session. This
            // temporary policy object shares storage and needs no file buffer.
            let mut ndef = crate::applets::ndef::Ndef::new();
            if h.ins == INS_RESET_NDEF {
                ndef.install(true, p.storage)?;
            } else {
                ndef.set_read_only(h.p1, p.storage)?;
            }
            return Ok(Action::Response(0));
        }
        self.execute(h, grants, pass, p, w).map(Action::Response)
    }
    // Keep command execution outside the reset/provisioning dispatcher: this
    // boundary reduces both complete CIU images with the pinned size optimizer.
    #[inline(never)]
    fn execute(
        &mut self,
        h: Header,
        grants: &mut Grants,
        pass: Option<&mut Pass>,
        p: &mut Platform<'_>,
        w: &mut Workspace,
    ) -> Result<u32, Sw> {
        if h.ins == INS_VENDOR {
            if !grants.admin {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            if h.p1 != 0xff || h.p2 > 1 || &w.input[..self.used] != RECOVERY_PAYLOAD {
                return Err(Sw::WRONG_P1P2);
            }
            let word = p.device.recovery_word().ok_or(Sw::UNABLE_TO_PROCESS)?;
            let result = crate::runtime::config::recovery(p.storage, word, h.p2 == 1);
            crate::runtime::config::notify(p);
            result.map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            return Ok(0);
        }
        if matches!(h.ins, INS_SET_KEYMAP..=INS_RESET_KEYMAP) {
            if !grants.admin {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            if h.p1 != 0
                || (h.ins == INS_GET_KEYMAP && h.p2 > 1)
                || (h.ins == INS_RESET_KEYMAP && h.p2 != 0)
            {
                return Err(Sw::WRONG_P1P2);
            }
            if self.used
                != if h.ins == INS_SET_KEYMAP {
                    crate::runtime::config::KEYMAP_BYTES
                } else {
                    0
                }
            {
                return Err(Sw::WRONG_LENGTH);
            }
            use crate::runtime::config;
            if h.ins == INS_GET_KEYMAP {
                let layout = config::read_keymap(
                    p.storage,
                    (&mut w.output[..crate::runtime::config::KEYMAP_BYTES])
                        .try_into()
                        .unwrap(),
                )
                .map_err(|_| Sw::REFERENCE_NOT_FOUND)?;
                self.response_len = if h.p2 == 0 {
                    w.output[0] = layout;
                    1
                } else {
                    crate::runtime::config::KEYMAP_BYTES
                };
                return Ok(self.response_len as u32);
            }
            let table = if h.ins == INS_SET_KEYMAP {
                Some(
                    (&w.input[..crate::runtime::config::KEYMAP_BYTES])
                        .try_into()
                        .unwrap(),
                )
            } else {
                None
            };
            config::write_keymap(p.storage, h.p2, table).map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            return Ok(0);
        }
        if h.ins == INS_WRITE_SERIAL || (h.ins == INS_READ_SERIAL && h.p1 == 0) {
            if h.p1 != 0 || h.p2 != 0 {
                return Err(Sw::WRONG_P1P2);
            }
            if h.ins == INS_WRITE_SERIAL {
                if !grants.admin {
                    return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
                }
                let serial = w.input[..self.used]
                    .try_into()
                    .map_err(|_| Sw::WRONG_LENGTH)?;
                crate::runtime::config::write_serial(p.storage, serial)
                    .map_err(|_| Sw::CONDITIONS_NOT_SATISFIED)?;
                return Ok(0);
            }
            if self.used != 0 {
                return Err(Sw::WRONG_LENGTH);
            }
            w.output[..4].copy_from_slice(&crate::runtime::config::serial(p.storage));
            self.response_len = 4;
            return Ok(4);
        }
        if matches!(h.ins, INS_NFC_ENABLE | INS_CONFIG | INS_READ_CONFIG) {
            return self.device_config(h, grants, p, w);
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
                Sm2::save(&w.input[..self.used], p)?;
                return Ok(0);
            }
            if self.used != 0 {
                return Err(Sw::WRONG_LENGTH);
            }
            let config = Sm2::load(p).map_err(|_| Sw::UNABLE_TO_PROCESS)?;
            w.output[..8].copy_from_slice(&config.encode());
            self.response_len = 8;
            return Ok(8);
        }
        // Preserve legacy authentication precedence for unknown instructions.
        if !matches!(
            h.ins,
            INS_VERIFY
                | INS_CHANGE_PIN
                | INS_GET_PASS_CONFIG
                | INS_SET_PASS_CONFIG
                | INS_RESET_PASS
        ) {
            return Err(if grants.admin {
                Sw::INS_NOT_SUPPORTED
            } else {
                Sw::SECURITY_STATUS_NOT_SATISFIED
            });
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
            auth::verify(&w.input[..self.used], p).map_err(auth_error)?;
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
                auth::change(&w.input[..self.used], p).map_err(auth_error)?;
            }
            INS_SET_PASS_CONFIG => {
                let pass = pass.ok_or(Sw::INS_NOT_SUPPORTED)?;
                let (index, slot) = pass_protocol::decode_config(h.p1, &w.input[..self.used])?;
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
                    self.response_len = pass_protocol::read_config(records, Layout, w.output)
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
        w: &mut Workspace,
    ) -> Result<u32, Sw> {
        use crate::runtime::config;
        let io = |_| Sw::UNABLE_TO_PROCESS;
        if h.ins == INS_NFC_ENABLE {
            if h.p1 > 1 || h.p2 > 1 {
                return Err(Sw::WRONG_P1P2);
            }
            if self.used != 0 {
                return Err(Sw::WRONG_LENGTH);
            }
            if h.p1 == 0 {
                w.output[0] = u8::from(config::flags(p.storage).map_err(io)? & config::NFC != 0);
                self.response_len = 1;
                return Ok(1);
            }
            if !grants.admin {
                return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
            }
            let result = config::update(
                p.storage,
                config::NFC,
                if h.p2 == 0 { 0 } else { config::NFC },
            );
            config::notify(p);
            result.map_err(io)?;
            return Ok(0);
        }
        if h.ins == INS_READ_CONFIG {
            if h.p1 != 0 || h.p2 != 0 {
                return Err(Sw::WRONG_P1P2);
            }
            let flags = config::flags(p.storage).map_err(io)?;
            // LED, reserved, NDEF read-only, NDEF enabled, WebUSB landing,
            // then the six applet feature bits packed from config FEATURE_SHIFT.
            w.output[..CONFIG_RESPONSE_BYTES].copy_from_slice(&[
                u8::from(flags & config::LED != 0),
                0,
                0,
                u8::from(flags & config::NDEF != 0),
                u8::from(flags & config::WEBUSB != 0),
                ((flags & config::FEATURES) >> config::FEATURE_SHIFT) as u8,
            ]);
            #[cfg(feature = "ndef")]
            {
                w.output[2] = u8::from(crate::applets::ndef::Ndef::new().read_only(p.storage));
            }
            self.response_len = CONFIG_RESPONSE_BYTES;
            return Ok(CONFIG_RESPONSE_BYTES as u32);
        }
        if !grants.admin {
            return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
        }
        let mask = match h.p1 {
            P1_CONFIG_LED => config::LED,
            P1_CONFIG_NDEF => config::NDEF,
            P1_CONFIG_WEBUSB => config::WEBUSB,
            P1_CONFIG_FEATURES => {
                if self.used != 0 {
                    return Err(Sw::WRONG_LENGTH);
                }
                if h.p2 & !config::FEATURE_MASK != 0 {
                    return Err(Sw::WRONG_P1P2);
                }
                config::FEATURES
            }
            _ => return Err(Sw::WRONG_P1P2),
        };
        let value = if h.p1 == P1_CONFIG_FEATURES {
            u32::from(h.p2) << config::FEATURE_SHIFT
        } else if h.p2 & 1 != 0 {
            mask
        } else {
            0
        };
        let result = config::update(p.storage, mask, value);
        config::notify(p);
        result.map_err(io)?;
        Ok(0)
    }
    // Factory reset is the blocked-ADMIN recovery path: 50 00 00 plus literal
    // RESET, with no retries left. The runtime separately requires five touches
    // before executing the returned reset action; this check alone never erases.
    pub fn check_factory_reset(
        &self,
        h: Header,
        w: &Workspace,
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        if p.device.contactless() {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        if h.p1 != 0x00 || h.p2 != 0x00 {
            return Err(Sw::WRONG_P1P2);
        }
        if self.used != b"RESET".len() {
            return Err(Sw::WRONG_LENGTH);
        }
        if &w.input[..b"RESET".len()] != b"RESET" {
            return Err(Sw::WRONG_DATA);
        }
        if auth::retries(p).map_err(auth_error)? != 0 {
            return Err(Sw::CONDITIONS_NOT_SATISFIED);
        }
        Ok(())
    }
    pub fn close_response(&mut self, w: &mut Workspace, p: &mut Platform<'_>) {
        crate::applets::close_response(p.memory, w.output, &mut self.response_len);
    }
    pub fn read_response(&self, offset: usize, out: &mut [u8], w: &Workspace) -> Result<(), Sw> {
        crate::applets::read_response_chunk(w.output, self.response_len, offset, out)
    }
}
