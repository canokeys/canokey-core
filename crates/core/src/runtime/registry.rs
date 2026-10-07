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

#[cfg(any(feature = "admin", feature = "oath"))]
macro_rules! pass_arg {
    ($this:expr) => {{
        #[cfg(feature = "pass")]
        {
            Some(&mut *$this.pass)
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
// Keep the tag at the front of this internal RAM union. A trailing tag makes
// every Thumb-1 dispatch rebuild a large offset before inspecting the applet.
#[repr(u8)]
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
    fn take_presence_attempt(&mut self) -> bool {
        match self {
            #[cfg(feature = "oath")]
            Self::Oath(s) => s.take_presence_attempt(),
            #[cfg(feature = "openpgp")]
            Self::OpenPgp(s) => s.take_presence_attempt(),
            #[cfg(feature = "piv")]
            Self::Piv(s) => s.take_presence_attempt(),
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
        // Iterate borrowed AIDs so size-optimized targets share one comparison
        // instead of expanding constant slice patterns into bytewise branches.
        const AIDS: &[(&[u8], Selected)] = &[
            #[cfg(feature = "ndef")]
            (crate::applets::ndef::AID, Selected::Ndef),
            #[cfg(feature = "ctap")]
            (ctap::apdu::AID, Selected::Ctap),
            #[cfg(feature = "admin")]
            (admin::AID, Selected::Admin),
            #[cfg(feature = "oath")]
            (crate::applets::oath::protocol::AID, Selected::Oath),
            #[cfg(feature = "openpgp")]
            (crate::applets::openpgp::protocol::AID, Selected::OpenPgp),
            #[cfg(feature = "piv")]
            (crate::applets::piv::AID, Selected::Piv),
            // Only the standardized nine-byte and legacy RID-only selectors
            // are accepted in addition to the full PIV AID.
            #[cfg(feature = "piv")]
            (crate::applets::piv::AID.split_at(9).0, Selected::Piv),
            #[cfg(feature = "piv")]
            (crate::applets::piv::AID.split_at(5).0, Selected::Piv),
        ];
        for &(candidate, selected) in AIDS {
            if aid == candidate {
                return Some(selected);
            }
        }
        None
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
                    if h.ins == admin::INS_SET_KEYMAP {
                        h.unchained().cla
                    } else {
                        h.cla
                    },
                    admin::COMMAND_CAPACITY as u32,
                )
            }
            #[cfg(feature = "ctap")]
            Self::Ctap => (
                h.unchained().cla & !canokey_protocol::apdu::CLA_FIDO,
                ctap::MAX_REQUEST as u32,
            ),
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
                if h.ins == crate::applets::ndef::INS_UPDATE_BINARY {
                    h.unchained().cla
                } else {
                    h.cla
                },
                crate::applets::ndef::FILE_LIMIT as u32,
            ),
            Self::None => (h.cla, 0),
        }
    }
}

// Put frequently accessed session controls before the large workspace.
// The stable internal order avoids expensive large-offset Thumb-1 accesses.
#[repr(C)]
pub struct Registry {
    #[cfg(feature = "admin")]
    admin: admin::Admin,
    #[cfg(feature = "ctap")]
    ctap: ctap::Applet,
    #[cfg(feature = "admin")]
    grants: admin::Grants,
    #[cfg(feature = "pass")]
    pass: Pass,
    #[cfg(feature = "pass")]
    output: crate::applets::pass::output::Output,
    applet: AppletState,
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
            ctap: ctap::Applet::new(),
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

    #[cfg(feature = "ctap")]
    // Drop parser-construction temporaries before the HID caller runs crypto.
    #[inline(never)]
    pub fn begin_hid_request(&mut self, message_length: Option<usize>, p: &mut Platform<'_>) {
        use super::workspace::SessionWorkspace;
        self.ctap.close(&mut self.workspace, p);
        self.workspace.wipe_active(p.memory);
        if let Some(length) = message_length {
            self.workspace =
                SessionWorkspace::CtapMessage(ctap::message::MessageParser::new(length));
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
        self.ctap.finish_hid(&mut self.workspace, p)
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
        command: ctap::message::Message,
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
    pub fn resume_ctap(&mut self, p: &mut Platform<'_>) {
        if !self.ctap.pending_message() {
            self.close_ctap(p);
        }
    }
    #[cfg(feature = "ctap")]
    pub fn complete_ctap(&mut self, p: &mut Platform<'_>) {
        if !self.ctap.complete_message() {
            self.close_ctap(p);
        }
    }
    #[cfg(feature = "ctap")]
    pub fn continue_ctap_message(&mut self, bytes: &[u8], p: &mut Platform<'_>) -> Option<usize> {
        self.ctap.continue_message(bytes, &mut self.workspace, p)
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
        crate::flows::credential_output::touch(&self.pass, index, out, p).map_err(flow_status)
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
}
/// Unambiguous FIDO commands accepted after card/slot reset, before SELECT.
/// Never steal an APDU from an explicitly selected applet.
#[cfg(feature = "ctap")]
fn implicit_fido(h: Header) -> bool {
    // Strip APDU chaining from FIDO CLA 80; accept CBOR INS 10 or U2F
    // REGISTER/AUTHENTICATE/VERSION. SELECT-by-name (P1=04) remains explicit.
    (h.cla & !canokey_protocol::apdu::CLA_CHAINING == canokey_protocol::apdu::CLA_FIDO
        && h.ins == canokey_protocol::apdu::FIDO_CBOR_INS)
        || (h.cla == 0
            && (matches!(
                h.ins,
                canokey_protocol::apdu::U2F_REGISTER..=canokey_protocol::apdu::U2F_VERSION
            ) || (h.ins == canokey_protocol::apdu::INS_SELECT
                && h.p1 != canokey_protocol::apdu::SELECT_BY_NAME)))
}
impl Router for Registry {
    #[allow(unused_variables)]
    fn install(&mut self, platform: &mut Platform<'_>) -> Result<(), Sw> {
        self.view().install(platform)
    }
    fn reset(&mut self, p: &mut Platform<'_>) {
        self.view().reset(p)
    }
    fn slot_power(&mut self, p: &mut Platform<'_>) -> bool {
        self.view().slot_power(p)
    }
    fn implicit_select(&mut self, header: Header, p: &mut Platform<'_>) -> Result<(), Sw> {
        self.view().implicit_select(header, p)
    }
    fn selected(&self) -> bool {
        !matches!(self.applet, AppletState::None)
    }
    fn select(&mut self, aid: &[u8], p: &mut Platform<'_>) -> Result<u32, Sw> {
        self.view().select(aid, p)
    }
    fn allows_extended(&self, header: Header) -> bool {
        let _ = header;
        #[cfg(feature = "openpgp")]
        if matches!(self.applet, AppletState::OpenPgp(_)) {
            return true;
        }
        #[cfg(feature = "ndef")]
        if matches!(self.applet, AppletState::Ndef(_))
            && header.ins == crate::applets::ndef::INS_READ_BINARY
        {
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
        self.view().abort_command(platform)
    }
    fn chain_header(&self, header: Header) -> Header {
        // NDEF UPDATE continues at the first fragment's offset; subsequent
        // P1/P2 values do not restart that applet's write cursor.
        #[cfg(feature = "ndef")]
        if matches!(self.applet, AppletState::Ndef(_))
            && header.ins == crate::applets::ndef::INS_UPDATE_BINARY
        {
            return Header {
                p1: 0,
                p2: 0,
                ..header
            };
        }
        header
    }
    #[allow(unused_variables)]
    fn begin_command(&mut self, header: Header, platform: &mut Platform<'_>) -> Result<(), Sw> {
        self.view().begin_command(header, platform)
    }
    #[allow(unused_variables)]
    fn consume(&mut self, bytes: &[u8], platform: &mut Platform<'_>) -> Result<(), Sw> {
        self.view().consume(bytes, platform)
    }
    #[allow(unused_variables)]
    fn end_frame(&mut self, last: bool, platform: &mut Platform<'_>) -> Result<(), Sw> {
        self.view().end_frame(last, platform)
    }
    #[allow(unused_variables)]
    // Share final dispatch without expanding it into frame/response handling.
    fn finish(
        &mut self,
        header: Header,
        requested: Option<u32>,
        platform: &mut Platform<'_>,
    ) -> Result<(u32, Sw), Sw> {
        self.view().finish(header, requested, platform)
    }
    #[allow(unused_variables)]
    // Keep applet workspace addressing out of the response cursor and its
    // error/close paths; this boundary reduces the complete Thumb-1 image.
    fn read_response(
        &mut self,
        offset: u32,
        out: &mut [u8],
        platform: &mut Platform<'_>,
    ) -> Result<usize, Sw> {
        self.view().read_response(offset, out, platform)
    }
    fn response_preemptable(&self, total: u32) -> bool {
        // Legacy ordinary replies used 256 bytes plus 32 bytes of APDU
        // overhead; larger results used explicitly closeable response sources.
        // The limits describe compatibility, not new runtime allocations.
        let _ = total;
        match &self.applet {
            #[cfg(feature = "ndef")]
            AppletState::Ndef(_) => total > canokey_protocol::apdu::RESPONSE_PREEMPT_BYTES as u32,
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
        self.view().close_response(platform)
    }
    #[cfg(feature = "pass")]
    fn is_eject(&self, h: Header, p: &mut Platform<'_>) -> bool {
        // PASS eject pseudo-APDU: FF EE FF EE, gated by the PASS feature.
        h.cla == 0xff
            && h.ins == 0xee
            && h.p1 == 0xff
            && h.p2 == 0xee
            && super::config::enabled(p.storage, super::config::PASS)
    }
    #[cfg(feature = "pass")]
    fn eject(&mut self, p: &mut Platform<'_>) -> Result<(), Sw> {
        self.view().eject(p)
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
        self.view().sample_output(pressed, now, ready, inhibit, p)
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
        #[cfg(all(feature = "admin", feature = "ctap"))]
        Error::Ctap => Sw::UNABLE_TO_PROCESS,
        #[cfg(all(feature = "admin", feature = "ndef"))]
        Error::Ndef => Sw::UNABLE_TO_PROCESS,
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

// A call-scoped set of disjoint borrows, never retained in Registry or a
// transport. Shared construction materializes deep field addresses once; the
// outlined routing methods load nearby pointers instead of rebuilding them.
// Registry continues to own every field and the only session workspace.
struct RegistryView<'a> {
    #[cfg(feature = "admin")]
    admin: &'a mut admin::Admin,
    #[cfg(feature = "ctap")]
    ctap: &'a mut ctap::Applet,
    #[cfg(feature = "admin")]
    grants: &'a mut admin::Grants,
    #[cfg(feature = "pass")]
    pass: &'a mut Pass,
    #[cfg(feature = "pass")]
    output: &'a mut crate::applets::pass::output::Output,
    applet: &'a mut AppletState,
    #[cfg(any(
        feature = "admin",
        feature = "openpgp",
        feature = "piv",
        feature = "ctap"
    ))]
    workspace: &'a mut super::workspace::SessionWorkspace,
}
impl Registry {
    // Keep construction shared: inlining this into each adapter grows both
    // complete Thumb-1 images even when the view methods remain outlined.
    #[inline(never)]
    fn view(&mut self) -> RegistryView<'_> {
        RegistryView {
            #[cfg(feature = "admin")]
            admin: &mut self.admin,
            #[cfg(feature = "ctap")]
            ctap: &mut self.ctap,
            #[cfg(feature = "admin")]
            grants: &mut self.grants,
            #[cfg(feature = "pass")]
            pass: &mut self.pass,
            #[cfg(feature = "pass")]
            output: &mut self.output,
            applet: &mut self.applet,
            #[cfg(any(
                feature = "admin",
                feature = "openpgp",
                feature = "piv",
                feature = "ctap"
            ))]
            workspace: &mut self.workspace,
        }
    }
}
impl RegistryView<'_> {
    #[allow(unused_variables)]
    #[inline(never)]
    fn reset_sessions(&mut self, platform: &mut Platform<'_>) {
        #[cfg(feature = "admin")]
        {
            self.grants.admin = false;
            self.admin.abort_transaction(platform);
        }
        #[cfg(feature = "ctap")]
        self.ctap.reset(&mut self.workspace, platform);
        // Release native handles before erasing backing bytes. The selected
        // applet is discarded, so it need not rebuild an empty classic view.
        #[cfg(classic_presence)]
        match &mut self.applet {
            #[cfg(feature = "oath")]
            AppletState::Oath(s) => {
                s.reset(platform);
                *self.applet = AppletState::None;
            }
            #[cfg(feature = "openpgp")]
            AppletState::OpenPgp(s) => {
                s.abort_transaction(platform);
                *self.applet = AppletState::None;
            }
            #[cfg(feature = "piv")]
            AppletState::Piv(s) => {
                s.deselect(&mut self.workspace, platform);
                *self.applet = AppletState::None;
            }
            _ => (),
        }
        #[cfg(any(
            feature = "admin",
            feature = "openpgp",
            feature = "piv",
            feature = "ctap"
        ))]
        self.workspace.wipe_active(platform.memory);
    }

    #[cfg(feature = "admin")]
    #[inline(never)]
    fn finish_admin(&mut self, h: Header, le: u32, p: &mut Platform<'_>) -> Result<(u32, Sw), Sw> {
        let pass = pass_arg!(self);
        match self.admin.finish(
            h,
            le,
            &mut self.grants,
            pass,
            p,
            &mut self.workspace.classic_with(p.memory),
        )? {
            admin::Action::Response(n) => return Ok((n, Sw::SUCCESS)),
            #[cfg(feature = "ctap")]
            admin::Action::InstallFidoKey(mut key) => ctap::provision::install_key(
                &mut key,
                &mut self.workspace.classic_with(p.memory),
                p,
            )
            .map_err(admin::provision_error)?,
            #[cfg(feature = "ctap")]
            admin::Action::ResetCtap => {
                crate::flows::factory_reset::ctap(self.ctap, self.workspace, p)
                    .map_err(flow_status)?
            }
            #[cfg(feature = "ndef")]
            admin::Action::ResetNdef => {
                crate::flows::factory_reset::ndef(p).map_err(flow_status)?
            }
            #[cfg(feature = "openpgp")]
            admin::Action::ResetOpenPgp => {
                // ADMIN selection already revoked the OpenPGP session. Keep
                // the clear operation's workspace wipe without constructing
                // a temporary applet whose session state is never observed.
                crate::flows::factory_reset::openpgp(self.workspace, p).map_err(flow_status)?;
            }
            #[cfg(feature = "oath")]
            admin::Action::ResetOath => {
                // Same reasoning: OATH RAM state cannot be live here.
                let pass = pass_arg!(self);
                crate::flows::factory_reset::oath(pass, p).map_err(flow_status)?;
            }
            #[cfg(feature = "piv")]
            admin::Action::ResetPiv => {
                crate::flows::factory_reset::piv(self.workspace, p).map_err(flow_status)?;
            }
            admin::Action::FactoryReset => {
                #[cfg(feature = "pass")]
                self.output.inhibit(true, p.memory);
                if !super::presence::strong(p.device) {
                    return Err(Sw::SECURITY_STATUS_NOT_SATISFIED);
                }
                self.reset_sessions(p);
                let pass = pass_arg!(self);
                crate::flows::factory_reset::run(
                    pass,
                    #[cfg(feature = "ctap")]
                    self.ctap,
                    self.workspace,
                    p,
                )
                .map_err(flow_status)?;
            }
        }
        Ok((0, Sw::SUCCESS))
    }

    #[allow(unused_variables)]
    #[inline(never)]
    fn install(&mut self, platform: &mut Platform<'_>) -> Result<(), Sw> {
        #[cfg(feature = "admin")]
        self.admin.install(platform)?;
        #[cfg(feature = "ctap")]
        self.ctap.install(platform)?;
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

    #[inline(never)]
    fn reset(&mut self, p: &mut Platform<'_>) {
        #[cfg(feature = "pass")]
        self.output.inhibit(true, p.memory);
        self.reset_sessions(p);
        *self.applet = AppletState::None;
    }

    #[inline(never)]
    fn slot_power(&mut self, p: &mut Platform<'_>) -> bool {
        #[cfg(feature = "ctap")]
        if matches!(self.applet, AppletState::Ctap) {
            self.ctap.close(&mut self.workspace, p);
            self.workspace.wipe_active(p.memory);
            return true;
        }
        self.reset(p);
        false
    }

    #[inline(never)]
    fn implicit_select(&mut self, header: Header, p: &mut Platform<'_>) -> Result<(), Sw> {
        let _ = (&header, &p);
        #[cfg(feature = "ctap")]
        if matches!(self.applet, AppletState::None) && implicit_fido(header) {
            if !Selected::Ctap.enabled(p) {
                return Err(Sw::FILE_NOT_FOUND);
            }
            *self.applet = AppletState::Ctap;
        }
        Ok(())
    }

    #[inline(never)]
    fn select(&mut self, aid: &[u8], p: &mut Platform<'_>) -> Result<u32, Sw> {
        let next = Selected::from_aid(aid).ok_or(Sw::FILE_NOT_FOUND)?;
        if !next.enabled(p) {
            self.reset_sessions(p);
            *self.applet = AppletState::None;
            return Err(Sw::FILE_NOT_FOUND);
        }
        if self.applet.selected() != next {
            self.reset_sessions(p);
            match next {
                Selected::None => *self.applet = AppletState::None,
                #[cfg(feature = "ndef")]
                Selected::Ndef => {
                    *self.applet = AppletState::Ndef(crate::applets::ndef::Applet::new())
                }
                #[cfg(feature = "admin")]
                Selected::Admin => *self.applet = AppletState::Admin,
                #[cfg(feature = "ctap")]
                Selected::Ctap => *self.applet = AppletState::Ctap,
                #[cfg(feature = "oath")]
                Selected::Oath => {
                    *self.applet = AppletState::Oath(crate::applets::oath::protocol::Oath::new())
                }
                #[cfg(feature = "openpgp")]
                Selected::OpenPgp => {
                    *self.applet =
                        AppletState::OpenPgp(crate::applets::openpgp::protocol::OpenPgp::new())
                }
                #[cfg(feature = "piv")]
                Selected::Piv => *self.applet = AppletState::Piv(Piv::new()),
            };
            // Boot validates a temporary instance. Reload durable PIN/config
            // only on a real switch, preserving grants on same-AID SELECT.
            #[cfg(feature = "piv")]
            if let AppletState::Piv(piv) = &mut self.applet
                && let Err(error) = piv.install(p)
            {
                *self.applet = AppletState::None;
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

    #[allow(unused_variables)]
    #[inline(never)]
    fn abort_command(&mut self, platform: &mut Platform<'_>) {
        match &mut self.applet {
            #[cfg(feature = "ndef")]
            AppletState::Ndef(s) => s.cancel(),
            #[cfg(feature = "admin")]
            AppletState::Admin => self
                .admin
                .cancel_command(&mut self.workspace.classic_with(platform.memory), platform),
            #[cfg(feature = "ctap")]
            AppletState::Ctap => self.ctap.cancel_command(&mut self.workspace),
            #[cfg(feature = "oath")]
            AppletState::Oath(s) => s.cancel_command(platform),
            #[cfg(feature = "openpgp")]
            AppletState::OpenPgp(s) => {
                s.abort(&mut self.workspace.classic_with(platform.memory), platform)
            }
            #[cfg(feature = "piv")]
            AppletState::Piv(s) => s.cancel(&mut self.workspace, platform),
            AppletState::None => (),
        }
    }

    #[allow(unused_variables)]
    #[inline(never)]
    fn begin_command(&mut self, header: Header, platform: &mut Platform<'_>) -> Result<(), Sw> {
        if !self.applet.selected().enabled(platform) {
            self.reset_sessions(platform);
            *self.applet = AppletState::None;
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
                &mut self.workspace.classic_with(platform.memory),
                platform,
            ),
            #[cfg(feature = "piv")]
            AppletState::Piv(s) => s.begin(header, &mut self.workspace, platform),
            _ => Ok(()),
        }
    }

    #[allow(unused_variables)]
    #[inline(never)]
    fn consume(&mut self, bytes: &[u8], platform: &mut Platform<'_>) -> Result<(), Sw> {
        match &mut self.applet {
            #[cfg(feature = "ndef")]
            AppletState::Ndef(s) => s.consume(bytes),
            #[cfg(feature = "admin")]
            AppletState::Admin => self.admin.consume(
                bytes,
                &mut self.workspace.classic_with(platform.memory),
                platform,
            ),
            #[cfg(feature = "ctap")]
            AppletState::Ctap => self.ctap.consume(bytes, &mut self.workspace),
            #[cfg(feature = "oath")]
            AppletState::Oath(s) => s.consume(bytes),
            #[cfg(feature = "openpgp")]
            AppletState::OpenPgp(s) => s.consume(
                bytes,
                &mut self.workspace.classic_with(platform.memory),
                platform,
            ),
            #[cfg(feature = "piv")]
            AppletState::Piv(s) => s.consume(bytes, &mut self.workspace, platform),
            AppletState::None => Err(Sw::FILE_NOT_FOUND),
        }
    }

    #[allow(unused_variables)]
    #[inline(never)]
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
        requested: Option<u32>,
        platform: &mut Platform<'_>,
    ) -> Result<(u32, Sw), Sw> {
        let le = requested.unwrap_or(super::engine::DEFAULT_APDU_LE);
        match &mut self.applet {
            #[cfg(feature = "ndef")]
            // READ BINARY without Le is a zero-byte read; encoded 00 is 256.
            AppletState::Ndef(s) => s.finish(requested.unwrap_or(0), platform),
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
                &mut self.workspace.classic_with(platform.memory),
                platform,
            ),
            #[cfg(feature = "piv")]
            AppletState::Piv(s) => s.finish(header, le, &mut self.workspace, platform),
            AppletState::None => Err(Sw::FILE_NOT_FOUND),
        }
    }

    #[allow(unused_variables)]
    // Keep applet workspace addressing out of the response cursor and its
    // error/close paths; this boundary reduces the complete Thumb-1 image.
    #[inline(never)]
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
                    &mut self.workspace.classic_with(platform.memory),
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
                &mut self.workspace.classic_with(platform.memory),
                platform,
            ),
            #[cfg(feature = "piv")]
            AppletState::Piv(s) => s.read(offset as usize, out, &mut self.workspace, platform),
            AppletState::None => Err(Sw::COMMAND_NOT_ALLOWED),
        }
    }

    #[allow(unused_variables)]
    #[inline(never)]
    fn close_response(&mut self, platform: &mut Platform<'_>) {
        match &mut self.applet {
            #[cfg(feature = "ndef")]
            AppletState::Ndef(s) => s.close(),
            #[cfg(feature = "admin")]
            AppletState::Admin => self
                .admin
                .close_response(&mut self.workspace.classic_with(platform.memory), platform),
            #[cfg(feature = "ctap")]
            AppletState::Ctap => self.ctap.close(&mut self.workspace, platform),
            #[cfg(feature = "oath")]
            AppletState::Oath(s) => s.close_response(platform),
            #[cfg(feature = "openpgp")]
            AppletState::OpenPgp(s) => {
                s.close(&mut self.workspace.classic_with(platform.memory), platform)
            }
            #[cfg(feature = "piv")]
            AppletState::Piv(s) => s.close(&mut self.workspace, platform),
            AppletState::None => (),
        }
    }

    #[cfg(feature = "pass")]
    #[inline(never)]
    fn eject(&mut self, p: &mut Platform<'_>) -> Result<(), Sw> {
        self.output.eject(p.memory);
        Ok(())
    }

    #[cfg(feature = "pass")]
    #[inline(never)]
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
            presence |= self.applet.take_presence_attempt();
        }
        #[cfg(feature = "ctap")]
        {
            presence |= self.ctap.take_presence_attempt();
        }
        if presence || inhibit {
            self.output.inhibit(pressed, p.memory);
            return None;
        }
        self.output
            .sample(pressed, now, ready, p.memory, |index, out| {
                if super::config::enabled(p.storage, super::config::PASS) {
                    crate::flows::credential_output::touch(&self.pass, index, out, p).unwrap_or(0)
                } else {
                    0
                }
            })
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

#[cfg(test)]
#[path = "registry_aid_tests.rs"]
mod aid_tests;
