// SPDX-License-Identifier: Apache-2.0
//! Static composition root. Disabled services have no state or install side effects.
use super::engine::Router;
use crate::Platform;
#[cfg(feature = "admin")]
use crate::applets::admin::protocol as admin;
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
    #[cfg(feature = "oath")]
    Oath,
    #[cfg(feature = "openpgp")]
    OpenPgp,
    #[cfg(feature = "piv")]
    Piv,
}
pub struct Registry {
    selected: Selected,
    #[cfg(feature = "admin")]
    admin: admin::Admin,
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
    fn reset_sessions(&mut self, _p: &mut Platform<'_>) {
        #[cfg(feature = "admin")]
        {
            self.grants.admin = false;
            self.admin.cancel_command(_p);
        }
        #[cfg(feature = "oath")]
        self.oath.reset(_p);
        #[cfg(feature = "piv")]
        self.piv.reset(&mut self.workspace, _p);
        #[cfg(feature = "openpgp")]
        self.pgp.reset(self.workspace.classic(), _p);
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
            .map_err(pass_error)
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
    fn install(&mut self, _p: &mut Platform<'_>) -> Result<(), Sw> {
        #[cfg(feature = "admin")]
        self.admin.install(_p)?;
        #[cfg(feature = "pass")]
        self.pass
            .install(_p.storage, _p.memory)
            .map_err(pass_error)?;
        #[cfg(feature = "oath")]
        self.oath.install(_p)?;
        #[cfg(feature = "openpgp")]
        self.pgp.install(_p)?;
        #[cfg(feature = "piv")]
        self.piv.install(_p)?;
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
    fn select(&mut self, _aid: &[u8], p: &mut Platform<'_>) -> Result<u32, Sw> {
        let next = match _aid {
            #[cfg(feature = "admin")]
            admin::AID => Some(Selected::Admin),
            #[cfg(feature = "oath")]
            crate::applets::oath::protocol::AID => Some(Selected::Oath),
            #[cfg(feature = "openpgp")]
            crate::applets::openpgp::protocol::AID => Some(Selected::OpenPgp),
            #[cfg(feature = "piv")]
            aid if aid.len() >= 5 && crate::applets::piv::AID.starts_with(aid) => {
                Some(Selected::Piv)
            }
            _ => None,
        }
        .ok_or(Sw::FILE_NOT_FOUND)?;
        if self.selected != next {
            self.reset_sessions(p);
        }
        self.selected = next;
        match next {
            #[cfg(feature = "oath")]
            Selected::Oath => self.oath.select(p),
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => self.pgp.select(p),
            #[cfg(feature = "piv")]
            Selected::Piv => self.piv.select(&mut self.workspace, p),
            _ => Ok(0),
        }
    }
    fn command_limit(&self, h: Header) -> Result<u32, Sw> {
        let (cla, limit) = match self.selected {
            #[cfg(feature = "admin")]
            Selected::Admin => (h.cla, admin::COMMAND_CAPACITY as u32),
            #[cfg(feature = "oath")]
            Selected::Oath => (
                h.unchained().cla,
                crate::applets::oath::protocol::CAPACITY as u32,
            ),
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => (
                h.unchained().cla,
                crate::applets::openpgp::protocol::OpenPgp::limit(h),
            ),
            #[cfg(feature = "piv")]
            Selected::Piv => (
                if h.chained() && !matches!(h.ins, 0x87 | 0xdb | 0xfe) {
                    h.cla
                } else {
                    h.unchained().cla
                },
                Piv::limit(h),
            ),
            Selected::None => (h.cla, 0),
        };
        if !self.selected() {
            return Err(Sw::FILE_NOT_FOUND);
        }
        if cla != 0 {
            Err(Sw::CLA_NOT_SUPPORTED)
        } else {
            Ok(limit)
        }
    }
    fn abort_command(&mut self, _p: &mut Platform<'_>) {
        match self.selected {
            #[cfg(feature = "admin")]
            Selected::Admin => self.admin.cancel_command(_p),
            #[cfg(feature = "oath")]
            Selected::Oath => self.oath.cancel_command(_p),
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => self.pgp.abort(self.workspace.classic(), _p),
            #[cfg(feature = "piv")]
            Selected::Piv => self.piv.cancel(&mut self.workspace, _p),
            Selected::None => (),
        }
    }
    fn begin_command(&mut self, _h: Header, _p: &mut Platform<'_>) -> Result<(), Sw> {
        #[cfg(feature = "openpgp")]
        if self.selected == Selected::OpenPgp {
            return self.pgp.begin(_h, self.workspace.classic(), _p);
        }
        #[cfg(feature = "piv")]
        if self.selected == Selected::Piv {
            return self.piv.begin(_h, &mut self.workspace, _p);
        }
        Ok(())
    }
    fn consume(&mut self, _bytes: &[u8], _p: &mut Platform<'_>) -> Result<(), Sw> {
        match self.selected {
            #[cfg(feature = "admin")]
            Selected::Admin => self.admin.consume(_bytes),
            #[cfg(feature = "oath")]
            Selected::Oath => self.oath.consume(_bytes),
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => self.pgp.consume(_bytes, self.workspace.classic(), _p),
            #[cfg(feature = "piv")]
            Selected::Piv => self.piv.consume(_bytes, &mut self.workspace, _p),
            Selected::None => Err(Sw::FILE_NOT_FOUND),
        }
    }
    fn finish(&mut self, _h: Header, _le: u32, _p: &mut Platform<'_>) -> Result<(u32, Sw), Sw> {
        match self.selected {
            #[cfg(feature = "admin")]
            Selected::Admin => self.finish_admin(_h, _p),
            #[cfg(feature = "oath")]
            Selected::Oath => {
                #[cfg(not(feature = "pass"))]
                let pass = None;
                #[cfg(feature = "pass")]
                let pass = Some(&mut self.pass);
                self.oath.finish(_h, _le, pass, _p)
            }
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => self.pgp.finish(_h, _le, self.workspace.classic(), _p),
            #[cfg(feature = "piv")]
            Selected::Piv => self.piv.finish(_h, _le, &mut self.workspace, _p),
            Selected::None => Err(Sw::FILE_NOT_FOUND),
        }
    }
    fn read_response(
        &mut self,
        _offset: u32,
        _out: &mut [u8],
        _p: &mut Platform<'_>,
    ) -> Result<usize, Sw> {
        match self.selected {
            #[cfg(feature = "admin")]
            Selected::Admin => self
                .admin
                .read_response(_offset as usize, _out)
                .map(|()| _out.len()),
            #[cfg(feature = "oath")]
            Selected::Oath => self
                .oath
                .read_response(_offset as usize, _out)
                .map(|()| _out.len()),
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => {
                self.pgp
                    .read(_offset as usize, _out, self.workspace.classic(), _p)
            }
            #[cfg(feature = "piv")]
            Selected::Piv => self
                .piv
                .read(_offset as usize, _out, &mut self.workspace, _p),
            Selected::None => Err(Sw::COMMAND_NOT_ALLOWED),
        }
    }
    fn close_response(&mut self, _p: &mut Platform<'_>) {
        match self.selected {
            #[cfg(feature = "admin")]
            Selected::Admin => self.admin.close_response(_p),
            #[cfg(feature = "oath")]
            Selected::Oath => self.oath.close_response(_p),
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => self.pgp.close(self.workspace.classic(), _p),
            #[cfg(feature = "piv")]
            Selected::Piv => self.piv.close(&mut self.workspace, _p),
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
        Error::Pass(e) => pass_error(e),
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

#[cfg(any(feature = "admin", feature = "pass"))]
fn pass_error(error: crate::applets::pass::domain::Error) -> Sw {
    match error {
        crate::applets::pass::domain::Error::Persistence => Sw::UNABLE_TO_PROCESS,
        _ => Sw::WRONG_DATA,
    }
}
