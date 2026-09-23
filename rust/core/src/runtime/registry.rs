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
#[derive(Clone, Copy, PartialEq, Eq)]
enum Selected {
    None,
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

impl Selected {
    fn from_aid(aid: &[u8]) -> Option<Self> {
        match aid {
            #[cfg(feature = "ctap")]
            ctap::apdu::AID => Some(Self::Ctap),
            #[cfg(feature = "admin")]
            admin::AID => Some(Self::Admin),
            #[cfg(feature = "oath")]
            crate::applets::oath::protocol::AID => Some(Self::Oath),
            #[cfg(feature = "openpgp")]
            crate::applets::openpgp::protocol::AID => Some(Self::OpenPgp),
            #[cfg(feature = "piv")]
            aid if aid.len() >= 5 && crate::applets::piv::AID.starts_with(aid) => Some(Self::Piv),
            _ => None,
        }
    }

    fn command_limit(self, h: Header) -> (u8, u32) {
        match self {
            #[cfg(feature = "admin")]
            Self::Admin => (h.cla, admin::COMMAND_CAPACITY as u32),
            #[cfg(feature = "ctap")]
            Self::Ctap => (h.unchained().cla ^ 0x80, ctap::MAX_REQUEST as u32),
            #[cfg(feature = "oath")]
            Self::Oath => (
                h.unchained().cla,
                crate::applets::oath::protocol::CAPACITY as u32,
            ),
            #[cfg(feature = "openpgp")]
            Self::OpenPgp => (
                h.unchained().cla,
                crate::applets::openpgp::protocol::OpenPgp::limit(h),
            ),
            #[cfg(feature = "piv")]
            Self::Piv => (
                if h.chained() && !crate::applets::piv::Piv::supports_chaining(h.ins) {
                    h.cla
                } else {
                    h.unchained().cla
                },
                Piv::limit(h),
            ),
            Self::None => (h.cla, 0),
        }
    }
}

pub struct Registry {
    selected: Selected,
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
    #[cfg(feature = "oath")]
    oath: crate::applets::oath::protocol::Oath,
    #[cfg(feature = "openpgp")]
    pgp: crate::applets::openpgp::protocol::OpenPgp,
    #[cfg(any(feature = "openpgp", feature = "piv"))]
    workspace: super::workspace::SessionWorkspace,
    #[cfg(feature = "piv")]
    piv: Piv,
}
impl Registry {
    pub const fn new() -> Self {
        Self {
            selected: Selected::None,
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
            #[cfg(feature = "oath")]
            oath: crate::applets::oath::protocol::Oath::new(),
            #[cfg(feature = "openpgp")]
            pgp: crate::applets::openpgp::protocol::OpenPgp::new(),
            #[cfg(any(feature = "openpgp", feature = "piv"))]
            workspace: super::workspace::SessionWorkspace::new(),
            #[cfg(feature = "piv")]
            piv: Piv::new(),
        }
    }
    fn reset_sessions(&mut self, platform: &mut Platform<'_>) {
        // Parameters may be unused when their applet features are disabled.
        let _ = (&platform,);
        #[cfg(feature = "admin")]
        {
            self.grants.admin = false;
            self.admin.cancel_command(platform);
        }
        #[cfg(feature = "ctap")]
        self.ctap.reset();
        #[cfg(feature = "oath")]
        self.oath.reset(platform);
        #[cfg(feature = "piv")]
        self.piv.reset(&mut self.workspace, platform);
        #[cfg(feature = "openpgp")]
        self.pgp.reset(self.workspace.classic(), platform);
    }
    #[cfg(feature = "pass")]
    pub fn touch(&self, index: u8, out: &mut [u8], p: &mut Platform<'_>) -> Result<usize, Sw> {
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
    fn finish_admin(&mut self, h: Header, p: &mut Platform<'_>) -> Result<(u32, Sw), Sw> {
        #[cfg(not(feature = "pass"))]
        let pass = None;
        #[cfg(feature = "pass")]
        let pass = Some(&mut self.pass);
        match self.admin.finish(h, &mut self.grants, pass, p)? {
            admin::Action::Response(n) => return Ok((n, Sw::SUCCESS)),
            #[cfg(feature = "openpgp")]
            admin::Action::ResetOpenPgp => self.pgp.clear(self.workspace.classic(), p)?,
            #[cfg(feature = "oath")]
            admin::Action::ResetOath => {
                self.oath.reset(p);
                #[cfg(not(feature = "pass"))]
                let pass = None;
                #[cfg(feature = "pass")]
                let pass = Some(&mut self.pass);
                crate::flows::factory_reset::oath(pass, p).map_err(flow_status)?;
            }
            #[cfg(feature = "piv")]
            admin::Action::ResetPiv => {
                self.piv.reset(&mut self.workspace, p);
                self.piv.reset_persistent(p)?;
            }
            admin::Action::FactoryReset => {
                #[cfg(feature = "pass")]
                self.output.inhibit(true, p.memory);
                if !super::presence::strong(p.device) {
                    return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
                }
                self.reset_sessions(p);
                #[cfg(not(feature = "pass"))]
                let pass = None;
                #[cfg(feature = "pass")]
                let pass = Some(&mut self.pass);
                crate::flows::factory_reset::run(
                    pass,
                    #[cfg(feature = "piv")]
                    &mut self.piv,
                    p,
                )
                .map_err(flow_status)?;
            }
        }
        Ok((0, Sw::SUCCESS))
    }
}
impl Router for Registry {
    fn install(&mut self, platform: &mut Platform<'_>) -> Result<(), Sw> {
        // Parameters may be unused when their applet features are disabled.
        let _ = (&platform,);
        #[cfg(feature = "admin")]
        self.admin.install(platform)?;
        #[cfg(feature = "pass")]
        self.pass
            .install(platform.storage, platform.memory)
            .map_err(crate::applets::pass::status)?;
        #[cfg(feature = "oath")]
        self.oath.install(platform)?;
        #[cfg(feature = "openpgp")]
        self.pgp.install(platform)?;
        #[cfg(feature = "piv")]
        self.piv.install(platform)?;
        Ok(())
    }
    fn reset(&mut self, p: &mut Platform<'_>) {
        #[cfg(feature = "pass")]
        self.output.inhibit(true, p.memory);
        self.reset_sessions(p);
        self.selected = Selected::None;
    }
    fn selected(&self) -> bool {
        self.selected != Selected::None
    }
    fn select(&mut self, aid: &[u8], p: &mut Platform<'_>) -> Result<u32, Sw> {
        let next = Selected::from_aid(aid).ok_or(Sw::FILE_NOT_FOUND)?;
        if self.selected != next {
            self.reset_sessions(p);
        }
        self.selected = next;
        match next {
            #[cfg(feature = "ctap")]
            Selected::Ctap => Ok(self.ctap.select()),
            #[cfg(feature = "oath")]
            Selected::Oath => self.oath.select(p),
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => self.pgp.select(p),
            #[cfg(feature = "piv")]
            Selected::Piv => self.piv.select(&mut self.workspace, p),
            _ => Ok(0),
        }
    }
    fn allows_extended(&self, header: Header) -> bool {
        let _ = header;
        #[cfg(feature = "ctap")]
        if self.selected == Selected::Ctap {
            return ctap::apdu::allows_extended(header);
        }
        false
    }
    fn command_limit(&self, h: Header) -> Result<u32, Sw> {
        // CTAP uses base CLA=80; other applets require CLA=00. Strip the chain bit only where
        // chaining is supported; leaving it set deliberately makes the final
        // CLA check reject chained ADMIN or unsupported chained PIV commands.
        let (cla, limit) = self.selected.command_limit(h);
        if !self.selected() {
            return Err(Sw::FILE_NOT_FOUND);
        }
        if cla != 0 {
            Err(Sw::CLA_NOT_SUPPORTED)
        } else {
            Ok(limit)
        }
    }
    fn abort_command(&mut self, platform: &mut Platform<'_>) {
        // Parameters may be unused when their applet features are disabled.
        let _ = (&platform,);
        match self.selected {
            #[cfg(feature = "admin")]
            Selected::Admin => self.admin.cancel_command(platform),
            #[cfg(feature = "ctap")]
            Selected::Ctap => self.ctap.cancel_command(),
            #[cfg(feature = "oath")]
            Selected::Oath => self.oath.cancel_command(platform),
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => self.pgp.abort(self.workspace.classic(), platform),
            #[cfg(feature = "piv")]
            Selected::Piv => self.piv.cancel(&mut self.workspace, platform),
            Selected::None => (),
        }
    }
    fn begin_command(&mut self, header: Header, platform: &mut Platform<'_>) -> Result<(), Sw> {
        // Parameters may be unused when their applet features are disabled.
        let _ = (&platform, &header);
        #[cfg(feature = "ctap")]
        if self.selected == Selected::Ctap {
            return self.ctap.begin(header);
        }
        #[cfg(feature = "openpgp")]
        if self.selected == Selected::OpenPgp {
            return self.pgp.begin(header, self.workspace.classic(), platform);
        }
        #[cfg(feature = "piv")]
        if self.selected == Selected::Piv {
            return self.piv.begin(header, &mut self.workspace, platform);
        }
        Ok(())
    }
    fn consume(&mut self, bytes: &[u8], platform: &mut Platform<'_>) -> Result<(), Sw> {
        // Parameters may be unused when their applet features are disabled.
        let _ = (&platform, &bytes);
        match self.selected {
            #[cfg(feature = "admin")]
            Selected::Admin => self.admin.consume(bytes),
            #[cfg(feature = "ctap")]
            Selected::Ctap => self.ctap.consume(bytes),
            #[cfg(feature = "oath")]
            Selected::Oath => self.oath.consume(bytes),
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => self.pgp.consume(bytes, self.workspace.classic(), platform),
            #[cfg(feature = "piv")]
            Selected::Piv => self.piv.consume(bytes, &mut self.workspace, platform),
            Selected::None => Err(Sw::FILE_NOT_FOUND),
        }
    }
    fn finish(
        &mut self,
        header: Header,
        le: u32,
        platform: &mut Platform<'_>,
    ) -> Result<(u32, Sw), Sw> {
        // Parameters may be unused when their applet features are disabled.
        let _ = (&platform, &header, &le);
        match self.selected {
            #[cfg(feature = "admin")]
            Selected::Admin => self.finish_admin(header, platform),
            #[cfg(feature = "ctap")]
            Selected::Ctap => self.ctap.finish().map(|n| (n, Sw::SUCCESS)),
            #[cfg(feature = "oath")]
            Selected::Oath => {
                #[cfg(not(feature = "pass"))]
                let pass = None;
                #[cfg(feature = "pass")]
                let pass = Some(&mut self.pass);
                self.oath.finish(header, le, pass, platform)
            }
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => self
                .pgp
                .finish(header, le, self.workspace.classic(), platform),
            #[cfg(feature = "piv")]
            Selected::Piv => self.piv.finish(header, le, &mut self.workspace, platform),
            Selected::None => Err(Sw::FILE_NOT_FOUND),
        }
    }
    fn read_response(
        &mut self,
        offset: u32,
        out: &mut [u8],
        platform: &mut Platform<'_>,
    ) -> Result<usize, Sw> {
        // Parameters may be unused when their applet features are disabled.
        let _ = (&platform, &offset, &out);
        match self.selected {
            #[cfg(feature = "admin")]
            Selected::Admin => self
                .admin
                .read_response(offset as usize, out)
                .map(|()| out.len()),
            #[cfg(feature = "ctap")]
            Selected::Ctap => self.ctap.read(offset as usize, out).map(|()| out.len()),
            #[cfg(feature = "oath")]
            Selected::Oath => self
                .oath
                .read_response(offset as usize, out)
                .map(|()| out.len()),
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => {
                self.pgp
                    .read(offset as usize, out, self.workspace.classic(), platform)
            }
            #[cfg(feature = "piv")]
            Selected::Piv => self
                .piv
                .read(offset as usize, out, &mut self.workspace, platform),
            Selected::None => Err(Sw::COMMAND_NOT_ALLOWED),
        }
    }
    fn close_response(&mut self, platform: &mut Platform<'_>) {
        // Parameters may be unused when their applet features are disabled.
        let _ = (&platform,);
        match self.selected {
            #[cfg(feature = "admin")]
            Selected::Admin => self.admin.close_response(platform),
            #[cfg(feature = "ctap")]
            Selected::Ctap => self.ctap.close(),
            #[cfg(feature = "oath")]
            Selected::Oath => self.oath.close_response(platform),
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => self.pgp.close(self.workspace.classic(), platform),
            #[cfg(feature = "piv")]
            Selected::Piv => self.piv.close(&mut self.workspace, platform),
            Selected::None => (),
        }
    }
    #[cfg(feature = "pass")]
    fn output_busy(&self) -> bool {
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
        let presence = false;
        #[cfg(feature = "oath")]
        let presence = self.oath.take_presence() | presence;
        #[cfg(feature = "openpgp")]
        let presence = self.pgp.take_presence() | presence;
        #[cfg(feature = "piv")]
        let presence = self.piv.presence.take() | presence;
        if presence || inhibit {
            self.output.inhibit(pressed, p.memory);
            return None;
        }
        self.output
            .sample(pressed, now, ready, p.memory, |index, out| {
                crate::flows::hotp_output::touch(&self.pass, index, out, p).unwrap_or(0)
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
