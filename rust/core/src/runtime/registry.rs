// SPDX-License-Identifier: Apache-2.0
//! Static composition root. Disabled services have no state or install side effects.
use super::engine::Router;
use crate::Platform;
#[cfg(feature = "admin")]
use crate::applets::admin::protocol as admin;
#[cfg(feature = "ctap")]
use crate::applets::ctap;
#[cfg(feature = "pass")]
use crate::applets::pass::service::Pass;
#[cfg(feature = "piv")]
use crate::applets::piv::Piv;
use canokey_protocol::{apdu::Header, response::StatusWord as Sw};

#[cfg(any(feature = "admin", feature = "oath", feature = "openpgp"))]
macro_rules! pass_arg {
    ($this:expr) => {{
        #[cfg(feature = "pass")]
        {
            Some(&mut $this.pass)
        }
        #[cfg(not(feature = "pass"))]
        {
            None
        }
    }};
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Selected {
    None,
    #[cfg(feature = "ndef")]
    Ndef,
    #[cfg(feature = "admin")]
    Admin,
    #[cfg(feature = "ctap")]
    Ctap,
    #[cfg(feature = "oath")]
    Oath,
    #[cfg(feature = "openpgp")]
    OpenPgp,
    #[cfg(feature = "piv")]
    Piv,
}

/// One discriminant owns both CCID selection and its live applet state.
/// CTAP state stays outside this enum because native HID does not use AID selection.
/// ADMIN/PASS services likewise remain available to cross-applet flows.
enum AppletState {
    None,
    #[cfg(feature = "ndef")]
    Ndef(crate::applets::ndef::Applet),
    #[cfg(feature = "admin")]
    Admin,
    #[cfg(feature = "ctap")]
    Ctap,
    #[cfg(feature = "oath")]
    Oath(crate::applets::oath::protocol::Oath),
    #[cfg(feature = "openpgp")]
    OpenPgp(crate::applets::openpgp::protocol::OpenPgp),
    #[cfg(feature = "piv")]
    Piv(Piv),
}
impl AppletState {
    fn selected(&self) -> Selected {
        match self {
            Self::None => Selected::None,
            #[cfg(feature = "ndef")]
            Self::Ndef(_) => Selected::Ndef,
            #[cfg(feature = "admin")]
            Self::Admin => Selected::Admin,
            #[cfg(feature = "ctap")]
            Self::Ctap => Selected::Ctap,
            #[cfg(feature = "oath")]
            Self::Oath(_) => Selected::Oath,
            #[cfg(feature = "openpgp")]
            Self::OpenPgp(_) => Selected::OpenPgp,
            #[cfg(feature = "piv")]
            Self::Piv(_) => Selected::Piv,
        }
    }
    #[cfg(all(feature = "pass", classic_presence))]
    fn take_presence(&mut self) -> bool {
        match self {
            #[cfg(feature = "oath")]
            Self::Oath(s) => s.take_presence(),
            #[cfg(feature = "openpgp")]
            Self::OpenPgp(s) => s.take_presence(),
            #[cfg(feature = "piv")]
            Self::Piv(s) => s.take_presence(),
            _ => false,
        }
    }
}

impl Selected {
    fn enabled(self, p: &mut Platform<'_>) -> bool {
        use super::config;
        let mask = match self {
            #[cfg(feature = "ndef")]
            Self::Ndef => config::NDEF,
            #[cfg(feature = "openpgp")]
            Self::OpenPgp => {
                if p.device.contactless() {
                    config::OPENPGP_NFC
                } else {
                    config::OPENPGP_USB
                }
            }
            #[cfg(feature = "piv")]
            Self::Piv => {
                if p.device.contactless() {
                    config::PIV_NFC
                } else {
                    config::PIV_USB
                }
            }
            #[cfg(feature = "ctap")]
            Self::Ctap => config::WEBAUTHN,
            _ => 0,
        };
        mask == 0 || config::enabled(p.storage, mask)
    }
    fn from_aid(aid: &[u8]) -> Option<Self> {
        match aid {
            #[cfg(feature = "ndef")]
            crate::applets::ndef::AID => Some(Self::Ndef),
            #[cfg(feature = "ctap")]
            ctap::apdu::AID => Some(Self::Ctap),
            #[cfg(feature = "admin")]
            admin::AID => Some(Self::Admin),
            #[cfg(feature = "oath")]
            crate::applets::oath::protocol::AID => Some(Self::Oath),
            #[cfg(feature = "openpgp")]
            crate::applets::openpgp::protocol::AID => Some(Self::OpenPgp),
            #[cfg(feature = "piv")]
            // Match the full AID, the standardized nine-byte prefix, or the
            // legacy RID-only selector; other partial versions are not AIDs.
            aid if matches!(aid.len(), 5 | 9 | 11) && crate::applets::piv::AID.starts_with(aid) => {
                Some(Self::Piv)
            }
            _ => None,
        }
    }
}

impl AppletState {
    fn command_limit(&self, h: Header) -> (u8, u32) {
        match self {
            #[cfg(feature = "admin")]
            Self::Admin => {
                #[cfg(feature = "ctap")]
                if h.ins == crate::applets::admin::protocol::INS_PROVISION_ATTESTATION {
                    return (h.unchained().cla, ctap::provision::CERT_LIMIT as u32);
                }
                (
                    if h.ins == 0x45 {
                        h.unchained().cla
                    } else {
                        h.cla
                    },
                    admin::COMMAND_CAPACITY as u32,
                )
            }
            #[cfg(feature = "ctap")]
            Self::Ctap => (h.unchained().cla & !0x80, ctap::MAX_REQUEST as u32),
            #[cfg(feature = "oath")]
            Self::Oath(_) => (
                h.unchained().cla,
                crate::applets::oath::protocol::CAPACITY as u32,
            ),
            #[cfg(feature = "openpgp")]
            Self::OpenPgp(_) => (
                h.unchained().cla,
                crate::applets::openpgp::protocol::OpenPgp::limit(h),
            ),
            #[cfg(feature = "piv")]
            Self::Piv(_) => (
                if h.chained() && !crate::applets::piv::Piv::supports_chaining(h.ins) {
                    h.cla
                } else {
                    h.unchained().cla
                },
                Piv::limit(h),
            ),
            #[cfg(feature = "ndef")]
            Self::Ndef(_) => (
                if h.ins == 0xd6 {
                    h.unchained().cla
                } else {
                    h.cla
                },
                1024,
            ),
            Self::None => (h.cla, 0),
        }
    }
}

pub struct Registry {
    applet: AppletState,
    #[cfg(feature = "admin")]
    admin: admin::Admin,
    #[cfg(feature = "ctap")]
    ctap: ctap::apdu::Applet,
    #[cfg(feature = "admin")]
    grants: admin::Grants,
    #[cfg(feature = "pass")]
    pass: Pass,
    #[cfg(feature = "pass")]
    output: crate::applets::pass::output::Output,
    #[cfg(any(
        feature = "admin",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap"
    ))]
    workspace: super::workspace::SessionWorkspace,
}
impl Registry {
    pub const fn new() -> Self {
        Self {
            applet: AppletState::None,
            #[cfg(feature = "admin")]
            admin: admin::Admin::new(),
            #[cfg(feature = "ctap")]
            ctap: ctap::apdu::Applet::new(),
            #[cfg(feature = "admin")]
            grants: admin::Grants { admin: false },
            #[cfg(feature = "pass")]
            pass: Pass::new(),
            #[cfg(feature = "pass")]
            output: crate::applets::pass::output::Output::new(),
            #[cfg(any(
                feature = "admin",
                feature = "openpgp",
                feature = "piv",
                feature = "ctap"
            ))]
            workspace: super::workspace::SessionWorkspace::new(),
        }
    }
    #[allow(unused_variables)]
    fn reset_sessions(&mut self, platform: &mut Platform<'_>) {
        #[cfg(any(
            feature = "admin",
            feature = "openpgp",
            feature = "piv",
            feature = "ctap"
        ))]
        self.workspace.wipe_active(platform.memory);
        #[cfg(feature = "admin")]
        {
            self.grants.admin = false;
            self.admin
                .cancel_command(self.workspace.classic_with(platform.memory), platform);
        }
        #[cfg(feature = "ctap")]
        self.ctap.reset(&mut self.workspace, platform);
        // Wipe the live classic state before vacating it. ADMIN selection survives
        // its factory-reset command; CTAP state was reset separately above.
        #[cfg(classic_presence)]
        match &mut self.applet {
            #[cfg(feature = "oath")]
            AppletState::Oath(s) => {
                s.reset(platform);
                self.applet = AppletState::None;
            }
            #[cfg(feature = "openpgp")]
            AppletState::OpenPgp(s) => {
                s.reset(self.workspace.classic_with(platform.memory), platform);
                self.applet = AppletState::None;
            }
            #[cfg(feature = "piv")]
            AppletState::Piv(s) => {
                s.reset(&mut self.workspace, platform);
                self.applet = AppletState::None;
            }
            _ => (),
        }
    }

    #[cfg(feature = "ctap")]
    pub fn begin_hid_request(&mut self, message_length: Option<usize>, p: &mut Platform<'_>) {
        use super::workspace::SessionWorkspace;
        self.workspace.wipe_active(p.memory);
        if let Some(length) = message_length {
            self.workspace = SessionWorkspace::CtapMessage(ctap::apdu::MessageParser::new(length));
        } else {
            self.workspace = SessionWorkspace::CtapRequest(ctap::Request::new());
        }
    }
    #[cfg(feature = "ctap")]
    pub fn consume_hid_request(&mut self, bytes: &[u8]) {
        use super::workspace::SessionWorkspace;
        match &mut self.workspace {
            SessionWorkspace::CtapRequest(request) => request.consume(bytes),
            SessionWorkspace::CtapMessage(request) => request.consume(bytes),
            _ => unreachable!(),
        }
    }
    #[cfg(feature = "ctap")]
    #[inline(never)]
    pub fn finish_hid_request(&mut self, p: &mut Platform<'_>) -> usize {
        if let super::workspace::SessionWorkspace::CtapMessage(request) = &mut self.workspace {
            let mut command = request.finish();
            self.ctap
                .execute_message(&mut command, &mut self.workspace, p)
        } else {
            let mut command = self.workspace.ctap_request_with(p.memory).finish();
            self.ctap.execute(&mut command, &mut self.workspace, p)
        }
    }
    #[cfg(feature = "ctap")]
    pub fn execute_ctap(
        &mut self,
        command: Result<ctap::Command, ctap::Status>,
        p: &mut Platform<'_>,
    ) -> usize {
        let mut command = command;
        self.ctap.execute(&mut command, &mut self.workspace, p)
    }
    #[cfg(feature = "ctap")]
    pub fn execute_ctap_message(
        &mut self,
        command: ctap::apdu::Message,
        p: &mut Platform<'_>,
    ) -> usize {
        self.ctap
            .execute_message(&mut { command }, &mut self.workspace, p)
    }
    #[cfg(feature = "ctap")]
    pub fn read_ctap(
        &mut self,
        offset: usize,
        out: &mut [u8],
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        self.ctap.read(offset, out, &mut self.workspace, p)
    }
    #[cfg(feature = "ctap")]
    pub fn close_ctap(&mut self, p: &mut Platform<'_>) {
        self.ctap.close(&mut self.workspace, p);
        self.workspace.classic_with(p.memory).clear(p.memory);
    }
    #[cfg(feature = "pass")]
    pub fn touch(&self, index: u8, out: &mut [u8], p: &mut Platform<'_>) -> Result<usize, Sw> {
        if !super::config::enabled(p.storage, super::config::PASS) {
            return Ok(0);
        }
        // HOTP touch is a flow operation and uses flow_status; challenge is
        // a PASS service primitive and maps its domain status directly below.
        crate::flows::hotp_output::touch(&self.pass, index, out, p).map_err(flow_status)
    }
    #[cfg(feature = "pass")]
    pub fn challenge(
        &self,
        index: u8,
        input: &[u8],
        out: &mut [u8; 20],
        p: &mut Platform<'_>,
    ) -> Result<(), Sw> {
        self.pass
            .challenge(index, input, out, p)
            .map_err(crate::applets::pass::status)
    }
    #[cfg(feature = "admin")]
    #[cfg_attr(feature = "openpgp", inline(never))]
    fn finish_admin(&mut self, h: Header, le: u32, p: &mut Platform<'_>) -> Result<(u32, Sw), Sw> {
        let pass = pass_arg!(self);
        match self.admin.finish(
            h,
            le,
            &mut self.grants,
            pass,
            p,
            self.workspace.classic_with(p.memory),
        )? {
            admin::Action::Response(n) => return Ok((n, Sw::SUCCESS)),
            #[cfg(feature = "ctap")]
            admin::Action::InstallFidoKey(mut key) => {
                ctap::provision::install_key(&mut key, self.workspace.classic_with(p.memory), p)?
            }
            #[cfg(feature = "ctap")]
            admin::Action::ResetCtap => self.ctap.erase(&mut self.workspace, p)?,
            #[cfg(feature = "openpgp")]
            admin::Action::ResetOpenPgp => {
                // No live CCID state can exist under ADMIN selection; the fresh
                // instance only runs the persistent-storage clear.
                crate::applets::openpgp::protocol::OpenPgp::new()
                    .clear(self.workspace.classic_with(p.memory), p)?
            }
            #[cfg(feature = "oath")]
            admin::Action::ResetOath => {
                // Same reasoning: OATH RAM state cannot be live here.
                let pass = pass_arg!(self);
                crate::flows::factory_reset::oath(pass, p).map_err(flow_status)?;
            }
            #[cfg(feature = "piv")]
            admin::Action::ResetPiv => {
                let mut piv = Piv::new();
                piv.reset(&mut self.workspace, p);
                piv.reset_persistent(p)?;
            }
            admin::Action::FactoryReset => {
                #[cfg(feature = "pass")]
                self.output.inhibit(true, p.memory);
                if !super::presence::strong(p.device) {
                    return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
                }
                self.reset_sessions(p);
                #[cfg(feature = "ndef")]
                crate::applets::ndef::Applet::install(true, p)?;
                #[cfg(feature = "ctap")]
                self.ctap.erase(&mut self.workspace, p)?;
                let pass = pass_arg!(self);
                #[cfg(feature = "piv")]
                let mut piv = Piv::new();
                crate::flows::factory_reset::run(
                    pass,
                    #[cfg(feature = "piv")]
                    &mut piv,
                    p,
                )
                .map_err(flow_status)?;
            }
        }
        Ok((0, Sw::SUCCESS))
    }
}
/// Unambiguous FIDO commands accepted after card/slot reset, before SELECT.
/// Never steal an APDU from an explicitly selected applet.
#[cfg(feature = "ctap")]
fn implicit_fido(h: Header) -> bool {
    (h.cla & !0x10 == 0x80 && h.ins == 0x10)
        || (h.cla == 0 && (matches!(h.ins, 1..=3) || (h.ins == 0xa4 && h.p1 != 4)))
}
impl Router for Registry {
    #[allow(unused_variables)]
    fn install(&mut self, platform: &mut Platform<'_>) -> Result<(), Sw> {
        #[cfg(feature = "admin")]
        self.admin.install(platform)?;
        #[cfg(feature = "ndef")]
        crate::applets::ndef::Applet::install(false, platform)?;
        #[cfg(feature = "pass")]
        self.pass
            .install(platform.storage, platform.memory)
            .map_err(crate::applets::pass::status)?;
        #[cfg(feature = "oath")]
        crate::applets::oath::protocol::Oath::new().install(platform)?;
        #[cfg(feature = "openpgp")]
        crate::applets::openpgp::protocol::OpenPgp::new().install(platform)?;
        #[cfg(feature = "piv")]
        Piv::new().install(platform)?;
        Ok(())
    }
    fn reset(&mut self, p: &mut Platform<'_>) {
        #[cfg(feature = "pass")]
        self.output.inhibit(true, p.memory);
        self.reset_sessions(p);
        self.applet = AppletState::None;
    }
    fn implicit_select(&mut self, header: Header, p: &mut Platform<'_>) -> Result<(), Sw> {
        let _ = (&header, &p);
        #[cfg(feature = "ctap")]
        if matches!(self.applet, AppletState::None) && implicit_fido(header) {
            if !Selected::Ctap.enabled(p) {
                return Err(Sw::FILE_NOT_FOUND);
            }
            self.applet = AppletState::Ctap;
        }
        Ok(())
    }
    fn selected(&self) -> bool {
        !matches!(self.applet, AppletState::None)
    }
    #[inline(never)]
    fn select(&mut self, aid: &[u8], p: &mut Platform<'_>) -> Result<u32, Sw> {
        let next = Selected::from_aid(aid).ok_or(Sw::FILE_NOT_FOUND)?;
        if !next.enabled(p) {
            self.reset_sessions(p);
            self.applet = AppletState::None;
            return Err(Sw::FILE_NOT_FOUND);
        }
        if self.applet.selected() != next {
            self.reset_sessions(p);
            match next {
                Selected::None => self.applet = AppletState::None,
                #[cfg(feature = "ndef")]
                Selected::Ndef => {
                    self.applet = AppletState::Ndef(crate::applets::ndef::Applet::new())
                }
                #[cfg(feature = "admin")]
                Selected::Admin => self.applet = AppletState::Admin,
                #[cfg(feature = "ctap")]
                Selected::Ctap => self.applet = AppletState::Ctap,
                #[cfg(feature = "oath")]
                Selected::Oath => {
                    self.applet = AppletState::Oath(crate::applets::oath::protocol::Oath::new())
                }
                #[cfg(feature = "openpgp")]
                Selected::OpenPgp => {
                    self.applet =
                        AppletState::OpenPgp(crate::applets::openpgp::protocol::OpenPgp::new())
                }
                #[cfg(feature = "piv")]
                Selected::Piv => self.applet = AppletState::Piv(Piv::new()),
            };
            // Boot validates a temporary instance. Reload durable PIN/config
            // only on a real switch, preserving grants on same-AID SELECT.
            #[cfg(feature = "piv")]
            if let AppletState::Piv(piv) = &mut self.applet
                && let Err(error) = piv.install(p)
            {
                self.applet = AppletState::None;
                return Err(error);
            }
        }
        match &mut self.applet {
            #[cfg(feature = "ctap")]
            AppletState::Ctap => Ok(self.ctap.select(&mut self.workspace, p)),
            #[cfg(feature = "oath")]
            AppletState::Oath(s) => s.select(p),
            #[cfg(feature = "openpgp")]
            AppletState::OpenPgp(s) => s.select(p),
            #[cfg(feature = "piv")]
            AppletState::Piv(s) => s.select(&mut self.workspace, p),
            _ => Ok(0),
        }
    }
    fn allows_extended(&self, header: Header) -> bool {
        let _ = header;
        #[cfg(feature = "openpgp")]
        if matches!(self.applet, AppletState::OpenPgp(_)) {
            return true;
        }
        #[cfg(feature = "ndef")]
        if matches!(self.applet, AppletState::Ndef(_)) && header.ins == 0xb0 {
            return true;
        }
        #[cfg(feature = "ctap")]
        if matches!(self.applet, AppletState::Ctap)
            || (matches!(self.applet, AppletState::None) && implicit_fido(header))
        {
            return ctap::apdu::allows_extended(header);
        }
        false
    }
    fn command_limit(&self, h: Header) -> Result<u32, Sw> {
        // CTAP uses base CLA=80; other applets require CLA=00. Strip the chain bit only where
        // chaining is supported; leaving it set deliberately makes the final
        // CLA check reject chained ADMIN or unsupported chained PIV commands.
        #[cfg(feature = "ctap")]
        if matches!(self.applet, AppletState::None) && implicit_fido(h) {
            // Admission is read-only; start performs the configuration check
            // before consuming staged input or executing any applet operation.
            return Ok(ctap::MAX_REQUEST as u32);
        }
        let (cla, limit) = self.applet.command_limit(h);
        if !self.selected() {
            return Err(Sw::FILE_NOT_FOUND);
        }
        if cla != 0 {
            Err(Sw::CLA_NOT_SUPPORTED)
        } else {
            Ok(limit)
        }
    }
    #[allow(unused_variables)]
    fn abort_command(&mut self, platform: &mut Platform<'_>) {
        match &mut self.applet {
            #[cfg(feature = "ndef")]
            AppletState::Ndef(s) => s.cancel(),
            #[cfg(feature = "admin")]
            AppletState::Admin => self
                .admin
                .cancel_command(self.workspace.classic_with(platform.memory), platform),
            #[cfg(feature = "ctap")]
            AppletState::Ctap => self.ctap.cancel_command(&mut self.workspace),
            #[cfg(feature = "oath")]
            AppletState::Oath(s) => s.cancel_command(platform),
            #[cfg(feature = "openpgp")]
            AppletState::OpenPgp(s) => {
                s.abort(self.workspace.classic_with(platform.memory), platform)
            }
            #[cfg(feature = "piv")]
            AppletState::Piv(s) => s.cancel(&mut self.workspace, platform),
            AppletState::None => (),
        }
    }
    #[allow(unused_variables)]
    fn begin_command(&mut self, header: Header, platform: &mut Platform<'_>) -> Result<(), Sw> {
        if !self.applet.selected().enabled(platform) {
            self.reset_sessions(platform);
            self.applet = AppletState::None;
            return Err(Sw::FILE_NOT_FOUND);
        }
        match &mut self.applet {
            #[cfg(feature = "ndef")]
            AppletState::Ndef(s) => s.begin(header),
            #[cfg(feature = "admin")]
            AppletState::Admin => self.admin.begin(header, &self.grants, platform),
            #[cfg(feature = "ctap")]
            AppletState::Ctap => self.ctap.begin(header, &mut self.workspace, platform),
            #[cfg(feature = "openpgp")]
            AppletState::OpenPgp(s) => s.begin(
                header,
                self.workspace.classic_with(platform.memory),
                platform,
            ),
            #[cfg(feature = "piv")]
            AppletState::Piv(s) => s.begin(header, &mut self.workspace, platform),
            _ => Ok(()),
        }
    }
    #[allow(unused_variables)]
    fn consume(&mut self, bytes: &[u8], platform: &mut Platform<'_>) -> Result<(), Sw> {
        match &mut self.applet {
            #[cfg(feature = "ndef")]
            AppletState::Ndef(s) => s.consume(bytes),
            #[cfg(feature = "admin")]
            AppletState::Admin => self.admin.consume(
                bytes,
                self.workspace.classic_with(platform.memory),
                platform,
            ),
            #[cfg(feature = "ctap")]
            AppletState::Ctap => self.ctap.consume(bytes, &mut self.workspace),
            #[cfg(feature = "oath")]
            AppletState::Oath(s) => s.consume(bytes),
            #[cfg(feature = "openpgp")]
            AppletState::OpenPgp(s) => s.consume(
                bytes,
                self.workspace.classic_with(platform.memory),
                platform,
            ),
            #[cfg(feature = "piv")]
            AppletState::Piv(s) => s.consume(bytes, &mut self.workspace, platform),
            AppletState::None => Err(Sw::FILE_NOT_FOUND),
        }
    }
    #[allow(unused_variables)]
    fn end_frame(&mut self, last: bool, platform: &mut Platform<'_>) -> Result<(), Sw> {
        #[cfg(feature = "ndef")]
        if let AppletState::Ndef(s) = &mut self.applet {
            return s.end_frame(last, platform);
        }
        Ok(())
    }
    #[allow(unused_variables)]
    // Share final dispatch without expanding it into frame/response handling.
    #[inline(never)]
    fn finish(
        &mut self,
        header: Header,
        le: u32,
        platform: &mut Platform<'_>,
    ) -> Result<(u32, Sw), Sw> {
        match &mut self.applet {
            #[cfg(feature = "ndef")]
            AppletState::Ndef(s) => s.finish(le, platform),
            #[cfg(feature = "admin")]
            AppletState::Admin => self.finish_admin(header, le, platform),
            #[cfg(feature = "ctap")]
            AppletState::Ctap => self
                .ctap
                .finish(&mut self.workspace, platform)
                .map(|n| (n, Sw::SUCCESS)),
            #[cfg(feature = "oath")]
            AppletState::Oath(s) => {
                let pass = pass_arg!(self);
                s.finish(header, le, pass, platform)
            }
            #[cfg(feature = "openpgp")]
            AppletState::OpenPgp(s) => s.finish(
                header,
                le,
                self.workspace.classic_with(platform.memory),
                platform,
            ),
            #[cfg(feature = "piv")]
            AppletState::Piv(s) => s.finish(header, le, &mut self.workspace, platform),
            AppletState::None => Err(Sw::FILE_NOT_FOUND),
        }
    }
    #[allow(unused_variables)]
    fn read_response(
        &mut self,
        offset: u32,
        out: &mut [u8],
        platform: &mut Platform<'_>,
    ) -> Result<usize, Sw> {
        match &mut self.applet {
            #[cfg(feature = "ndef")]
            AppletState::Ndef(s) => s.read(offset as usize, out, platform),
            #[cfg(feature = "admin")]
            AppletState::Admin => self
                .admin
                .read_response(
                    offset as usize,
                    out,
                    self.workspace.classic_with(platform.memory),
                )
                .map(|()| out.len()),
            #[cfg(feature = "ctap")]
            AppletState::Ctap => self
                .ctap
                .read(offset as usize, out, &mut self.workspace, platform)
                .map(|()| out.len()),
            #[cfg(feature = "oath")]
            AppletState::Oath(s) => s.read_response(offset as usize, out).map(|()| out.len()),
            #[cfg(feature = "openpgp")]
            AppletState::OpenPgp(s) => s.read(
                offset as usize,
                out,
                self.workspace.classic_with(platform.memory),
                platform,
            ),
            #[cfg(feature = "piv")]
            AppletState::Piv(s) => s.read(offset as usize, out, &mut self.workspace, platform),
            AppletState::None => Err(Sw::COMMAND_NOT_ALLOWED),
        }
    }
    fn response_preemptable(&self, total: u32) -> bool {
        // Legacy ordinary replies used 256 bytes plus 32 bytes of APDU
        // overhead; larger results used explicitly closeable response sources.
        // The limits describe compatibility, not new runtime allocations.
        let _ = total;
        match &self.applet {
            #[cfg(feature = "ndef")]
            AppletState::Ndef(_) => total > 288,
            #[cfg(feature = "openpgp")]
            AppletState::OpenPgp(s) => s.response_preemptable(total),
            #[cfg(feature = "piv")]
            AppletState::Piv(s) => s.response_preemptable(total, &self.workspace),
            #[cfg(feature = "ctap")]
            AppletState::Ctap => self.ctap.response_preemptable(),
            _ => false,
        }
    }
    #[allow(unused_variables)]
    fn close_response(&mut self, platform: &mut Platform<'_>) {
        match &mut self.applet {
            #[cfg(feature = "ndef")]
            AppletState::Ndef(s) => s.close(),
            #[cfg(feature = "admin")]
            AppletState::Admin => self
                .admin
                .close_response(self.workspace.classic_with(platform.memory), platform),
            #[cfg(feature = "ctap")]
            AppletState::Ctap => self.ctap.close(&mut self.workspace, platform),
            #[cfg(feature = "oath")]
            AppletState::Oath(s) => s.close_response(platform),
            #[cfg(feature = "openpgp")]
            AppletState::OpenPgp(s) => {
                s.close(self.workspace.classic_with(platform.memory), platform)
            }
            #[cfg(feature = "piv")]
            AppletState::Piv(s) => s.close(&mut self.workspace, platform),
            AppletState::None => (),
        }
    }
    #[cfg(feature = "pass")]
    fn is_eject(&self, h: Header, p: &mut Platform<'_>) -> bool {
        h.cla == 0xff
            && h.ins == 0xee
            && h.p1 == 0xff
            && h.p2 == 0xee
            && super::config::enabled(p.storage, super::config::PASS)
    }
    #[cfg(feature = "pass")]
    fn eject(&mut self, p: &mut Platform<'_>) -> Result<(), Sw> {
        self.output.eject(p.memory);
        Ok(())
    }
    #[cfg(feature = "pass")]
    fn output_busy(&self) -> bool {
        // PASS owns the shared output queue; the registry only arbitrates
        // applet presence and forwards sampling at this composition boundary.
        self.output.busy()
    }
    #[cfg(feature = "pass")]
    fn sample_output(
        &mut self,
        pressed: bool,
        now: u32,
        ready: bool,
        inhibit: bool,
        p: &mut Platform<'_>,
    ) -> Option<u8> {
        #[allow(unused_mut)]
        let mut presence = false;
        #[cfg(classic_presence)]
        {
            presence |= self.applet.take_presence();
        }
        #[cfg(feature = "ctap")]
        {
            presence |= self.ctap.take_presence();
        }
        if presence || inhibit {
            self.output.inhibit(pressed, p.memory);
            return None;
        }
        self.output
            .sample(pressed, now, ready, p.memory, |index, out| {
                if super::config::enabled(p.storage, super::config::PASS) {
                    crate::flows::hotp_output::touch(&self.pass, index, out, p).unwrap_or(0)
                } else {
                    0
                }
            })
    }
}
impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(any(feature = "admin", feature = "pass"))]
fn flow_status(error: crate::flows::Error) -> Sw {
    use crate::flows::Error;
    match error {
        #[cfg(all(feature = "admin", feature = "piv"))]
        Error::Piv => Sw::UNABLE_TO_PROCESS,
        Error::Pass(e) => crate::applets::pass::status(e),
        #[cfg(feature = "oath")]
        Error::Oath(e) => crate::applets::oath::protocol::status(e),
        #[cfg(all(feature = "admin", feature = "openpgp"))]
        Error::OpenPgp(e) => e.into(),
        #[cfg(feature = "admin")]
        Error::Admin(e) => admin::auth_error(e),
        #[cfg(all(feature = "pass", feature = "oath"))]
        Error::Output => Sw::WRONG_LENGTH,
    }
}

#[cfg(all(
    test,
    feature = "admin",
    feature = "openpgp",
    feature = "piv",
    feature = "ndef",
    not(feature = "static-backend")
))]
#[path = "registry_config_tests.rs"]
mod config_tests;
