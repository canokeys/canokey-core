// SPDX-License-Identifier: Apache-2.0
//! Cross-applet ADMIN actions and their status-word mapping.
#[cfg(feature = "admin")]
use super::RegistryView;
use super::Sw;

#[cfg(all(feature = "admin", feature = "ctap"))]
use super::ctap;
#[cfg(feature = "admin")]
use super::{Header, Platform, admin};

#[cfg(feature = "admin")]
impl RegistryView<'_> {
    #[inline(never)]
    pub(super) fn finish_admin(
        &mut self,
        h: Header,
        le: u32,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(u32, Sw), Sw> {
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
                if !crate::runtime::presence::strong(p.device) {
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
}

#[cfg(any(feature = "admin", feature = "pass"))]
pub(super) fn flow_status(error: crate::flows::Error) -> Sw {
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
