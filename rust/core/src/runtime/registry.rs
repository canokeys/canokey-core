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

/// CCID-selected applet states are mutually exclusive: `Selected` is the
/// discriminant, switching or any session reset wipes the live variant, and
/// only one variant's bytes exist at a time. CTAP keeps separate state because
/// HID frames do not pass through AID selection and may interleave with a
/// selected CCID applet. Boot install and ADMIN resets use fresh instances.
#[cfg(classic_presence)]
enum ClassicState {
    None,
    #[cfg(feature = "oath")]
    Oath(crate::applets::oath::protocol::Oath),
    #[cfg(feature = "openpgp")]
    OpenPgp(crate::applets::openpgp::protocol::OpenPgp),
    #[cfg(feature = "piv")]
    Piv(Piv),
}
#[cfg(classic_presence)]
impl ClassicState {
    /// Lean accessors rely on the registry invariant: `select` creates the
    /// matching variant and every reset returns to `None` first. The trap is
    /// shared so the impossible path does not expand at every call site.
    #[cold]
    #[inline(never)]
    fn bad_variant() -> ! {
        unreachable!()
    }
    #[cfg(feature = "oath")]
    fn oath(&mut self) -> &mut crate::applets::oath::protocol::Oath {
        match self {
            Self::Oath(s) => s,
            _ => Self::bad_variant(),
        }
    }
    #[cfg(feature = "openpgp")]
    fn pgp(&mut self) -> &mut crate::applets::openpgp::protocol::OpenPgp {
        match self {
            Self::OpenPgp(s) => s,
            _ => Self::bad_variant(),
        }
    }
    #[cfg(feature = "piv")]
    fn piv(&mut self) -> &mut Piv {
        match self {
            Self::Piv(s) => s,
            _ => Self::bad_variant(),
        }
    }
    #[cfg(feature = "pass")]
    fn take_presence(&mut self) -> bool {
        match self {
            #[cfg(feature = "oath")]
            Self::Oath(s) => s.take_presence(),
            #[cfg(feature = "openpgp")]
            Self::OpenPgp(s) => s.take_presence(),
            #[cfg(feature = "piv")]
            Self::Piv(s) => s.take_presence(),
            Self::None => false,
        }
    }
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
            Self::Admin => {
                #[cfg(feature = "ctap")]
                if h.ins == crate::applets::admin::protocol::INS_PROVISION_ATTESTATION {
                    return (h.unchained().cla, ctap::provision::CERT_LIMIT as u32);
                }
                (h.cla, admin::COMMAND_CAPACITY as u32)
            }
            #[cfg(feature = "ctap")]
            Self::Ctap => (h.unchained().cla & !0x80, ctap::MAX_REQUEST as u32),
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
    #[cfg(classic_presence)]
    classic: ClassicState,
    #[cfg(any(feature = "openpgp", feature = "piv", feature = "ctap"))]
    workspace: super::workspace::SessionWorkspace,
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
            #[cfg(classic_presence)]
            classic: ClassicState::None,
            #[cfg(any(feature = "openpgp", feature = "piv", feature = "ctap"))]
            workspace: super::workspace::SessionWorkspace::new(),
        }
    }
    #[allow(unused_variables)]
    fn reset_sessions(&mut self, platform: &mut Platform<'_>) {
        #[cfg(any(feature = "openpgp", feature = "piv", feature = "ctap"))]
        self.workspace.wipe_active(platform.memory);
        #[cfg(feature = "admin")]
        {
            self.grants.admin = false;
            self.admin.cancel_command(platform);
        }
        #[cfg(feature = "ctap")]
        self.ctap.reset(&mut self.workspace, platform);
        // Only the live CCID applet variant holds state; wipe it through its
        // own reset path, then vacate the union. Workspace side effects match
        // the previous per-field resets because the workspace was already wiped.
        #[cfg(classic_presence)]
        {
            match &mut self.classic {
                #[cfg(feature = "oath")]
                ClassicState::Oath(s) => s.reset(platform),
                #[cfg(feature = "openpgp")]
                ClassicState::OpenPgp(s) => {
                    s.reset(self.workspace.classic_with(platform.memory), platform)
                }
                #[cfg(feature = "piv")]
                ClassicState::Piv(s) => s.reset(&mut self.workspace, platform),
                ClassicState::None => (),
            }
            self.classic = ClassicState::None;
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
    fn finish_admin(&mut self, h: Header, p: &mut Platform<'_>) -> Result<(u32, Sw), Sw> {
        let pass = pass_arg!(self);
        match self.admin.finish(h, &mut self.grants, pass, p)? {
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
impl Router for Registry {
    #[allow(unused_variables)]
    fn install(&mut self, platform: &mut Platform<'_>) -> Result<(), Sw> {
        #[cfg(feature = "admin")]
        self.admin.install(platform)?;
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
        self.selected = Selected::None;
    }
    fn selected(&self) -> bool {
        self.selected != Selected::None
    }
    #[inline(never)]
    fn select(&mut self, aid: &[u8], p: &mut Platform<'_>) -> Result<u32, Sw> {
        let next = Selected::from_aid(aid).ok_or(Sw::FILE_NOT_FOUND)?;
        if self.selected != next {
            self.reset_sessions(p);
        }
        self.selected = next;
        match next {
            #[cfg(feature = "ctap")]
            Selected::Ctap => Ok(self.ctap.select(&mut self.workspace, p)),
            #[cfg(feature = "oath")]
            Selected::Oath => {
                if !matches!(self.classic, ClassicState::Oath(_)) {
                    self.classic = ClassicState::Oath(crate::applets::oath::protocol::Oath::new());
                }
                self.classic.oath().select(p)
            }
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => {
                if !matches!(self.classic, ClassicState::OpenPgp(_)) {
                    self.classic =
                        ClassicState::OpenPgp(crate::applets::openpgp::protocol::OpenPgp::new());
                }
                self.classic.pgp().select(p)
            }
            #[cfg(feature = "piv")]
            Selected::Piv => {
                if !matches!(self.classic, ClassicState::Piv(_)) {
                    self.classic = ClassicState::Piv(Piv::new());
                    // Installation at boot validates durable state in a temporary
                    // instance. Reload the PIN/config cache when reentering PIV.
                    if let Err(error) = self.classic.piv().install(p) {
                        self.classic = ClassicState::None;
                        self.selected = Selected::None;
                        return Err(error);
                    }
                }
                self.classic.piv().select(&mut self.workspace, p)
            }
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
    #[allow(unused_variables)]
    fn abort_command(&mut self, platform: &mut Platform<'_>) {
        match self.selected {
            #[cfg(feature = "admin")]
            Selected::Admin => self.admin.cancel_command(platform),
            #[cfg(feature = "ctap")]
            Selected::Ctap => self.ctap.cancel_command(&mut self.workspace),
            #[cfg(feature = "oath")]
            Selected::Oath => self.classic.oath().cancel_command(platform),
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => self
                .classic
                .pgp()
                .abort(self.workspace.classic_with(platform.memory), platform),
            #[cfg(feature = "piv")]
            Selected::Piv => self.classic.piv().cancel(&mut self.workspace, platform),
            Selected::None => (),
        }
    }
    fn begin_command(&mut self, header: Header, platform: &mut Platform<'_>) -> Result<(), Sw> {
        #[cfg(not(has_applet))]
        let _ = (header, &platform);
        #[cfg(feature = "admin")]
        if self.selected == Selected::Admin {
            return self.admin.begin(header, &self.grants, platform);
        }
        #[cfg(feature = "ctap")]
        if self.selected == Selected::Ctap {
            return self.ctap.begin(header, &mut self.workspace, platform);
        }
        #[cfg(feature = "openpgp")]
        if self.selected == Selected::OpenPgp {
            return self.classic.pgp().begin(
                header,
                self.workspace.classic_with(platform.memory),
                platform,
            );
        }
        #[cfg(feature = "piv")]
        if self.selected == Selected::Piv {
            return self
                .classic
                .piv()
                .begin(header, &mut self.workspace, platform);
        }
        Ok(())
    }
    #[allow(unused_variables)]
    fn consume(&mut self, bytes: &[u8], platform: &mut Platform<'_>) -> Result<(), Sw> {
        match self.selected {
            #[cfg(feature = "admin")]
            Selected::Admin => self.admin.consume(bytes, platform),
            #[cfg(feature = "ctap")]
            Selected::Ctap => self.ctap.consume(bytes, &mut self.workspace),
            #[cfg(feature = "oath")]
            Selected::Oath => self.classic.oath().consume(bytes),
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => self.classic.pgp().consume(
                bytes,
                self.workspace.classic_with(platform.memory),
                platform,
            ),
            #[cfg(feature = "piv")]
            Selected::Piv => self
                .classic
                .piv()
                .consume(bytes, &mut self.workspace, platform),
            Selected::None => Err(Sw::FILE_NOT_FOUND),
        }
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
        match self.selected {
            #[cfg(feature = "admin")]
            Selected::Admin => self.finish_admin(header, platform),
            #[cfg(feature = "ctap")]
            Selected::Ctap => self
                .ctap
                .finish(&mut self.workspace, platform)
                .map(|n| (n, Sw::SUCCESS)),
            #[cfg(feature = "oath")]
            Selected::Oath => {
                let pass = pass_arg!(self);
                self.classic.oath().finish(header, le, pass, platform)
            }
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => self.classic.pgp().finish(
                header,
                le,
                self.workspace.classic_with(platform.memory),
                platform,
            ),
            #[cfg(feature = "piv")]
            Selected::Piv => self
                .classic
                .piv()
                .finish(header, le, &mut self.workspace, platform),
            Selected::None => Err(Sw::FILE_NOT_FOUND),
        }
    }
    #[allow(unused_variables)]
    fn read_response(
        &mut self,
        offset: u32,
        out: &mut [u8],
        platform: &mut Platform<'_>,
    ) -> Result<usize, Sw> {
        match self.selected {
            #[cfg(feature = "admin")]
            Selected::Admin => self
                .admin
                .read_response(offset as usize, out)
                .map(|()| out.len()),
            #[cfg(feature = "ctap")]
            Selected::Ctap => self
                .ctap
                .read(offset as usize, out, &mut self.workspace, platform)
                .map(|()| out.len()),
            #[cfg(feature = "oath")]
            Selected::Oath => self
                .classic
                .oath()
                .read_response(offset as usize, out)
                .map(|()| out.len()),
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => self.classic.pgp().read(
                offset as usize,
                out,
                self.workspace.classic_with(platform.memory),
                platform,
            ),
            #[cfg(feature = "piv")]
            Selected::Piv => {
                self.classic
                    .piv()
                    .read(offset as usize, out, &mut self.workspace, platform)
            }
            Selected::None => Err(Sw::COMMAND_NOT_ALLOWED),
        }
    }
    #[allow(unused_variables)]
    fn close_response(&mut self, platform: &mut Platform<'_>) {
        match self.selected {
            #[cfg(feature = "admin")]
            Selected::Admin => self.admin.close_response(platform),
            #[cfg(feature = "ctap")]
            Selected::Ctap => self.ctap.close(&mut self.workspace, platform),
            #[cfg(feature = "oath")]
            Selected::Oath => self.classic.oath().close_response(platform),
            #[cfg(feature = "openpgp")]
            Selected::OpenPgp => self
                .classic
                .pgp()
                .close(self.workspace.classic_with(platform.memory), platform),
            #[cfg(feature = "piv")]
            Selected::Piv => self.classic.piv().close(&mut self.workspace, platform),
            Selected::None => (),
        }
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
            presence |= self.classic.take_presence();
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
