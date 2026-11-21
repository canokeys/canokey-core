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
#[cfg(any(feature = "openpgp", feature = "piv"))]
use canokey_ports::Device as _;
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
#[cfg(any(feature = "admin", feature = "pass"))]
mod actions;

// Emit entire matches so every dispatch arm uses the same feature gate.
macro_rules! dispatch_applet {
    ($value:expr, $fallback:pat => $default:expr; $(#[$gate:meta] $pat:pat => $action:expr,)*) => {
        match $value {
            $(#[$gate] $pat => $action,)*
            $fallback => $default,
        }
    };
}

// APDU entries are ordered by AID precedence and selected-state discriminant.
// Owned state is emitted in two groups to preserve the Thumb-1 field layout.
macro_rules! applets {
    (
        $this:ident, $io:ident, $platform:ident, $config:ident, $h:ident,
        $header:ident, $transport:ident, $bytes:ident, $last:ident,
        $le:ident, $offset:ident, $out:ident;
        #[$workspace_gate:meta];
        $(
            #[$gate:meta] $variant:ident {
                $(apdu: $selected:ident $(($ignore:tt => $state:ty = $make:expr))?,
                  aids: [$($aid:expr),* $(,)?],
                  limit: $limit:expr,)?
                $(transport_aid: $transport_aid:expr,)?
                $(mask: $mask:expr,)?
                $(primary: [$($primary:ident: $primary_ty:ty = $primary_init:expr),+ $(,)?],)?
                $(secondary: [$($secondary:ident: $secondary_ty:ty = $secondary_init:expr),+ $(,)?],)?
                $(install_first: $install_first:expr,)?
                $(install: $install:expr,)?
                $(reset_owned: $reset_owned:expr,)?
                $(reset_selected($reset_binding:ident): $reset_selected:expr,)?
                $(presence($presence_binding:ident): $presence:expr,)?
                $(can_yield($yield_binding:ident): $can_yield:expr,)?
                $(keep_selection_when_disabled: $keep_selection:expr,)?
                $(zero_le: $zero_le:expr,)?
                $(retain_nfc_input: $retain_nfc_input:expr,)?
                $(allows_extended: $allows_extended:expr,)?
                $(chain_header: $chain_header:expr,)?
                $(owned_presence: $owned_presence:expr,)?
                $(enter($enter_binding:ident): $enter:expr,)?
                $(end_frame($frame_binding:ident): $end_frame:expr,)?
                $(abort_command$(($abort_binding:ident))?: $abort_command:expr,)?
                $(begin_command$(($begin_binding:ident))?: $begin_command:expr,)?
                $(consume$(($consume_binding:ident))?: $consume:expr,)?
                $(finish$(($finish_binding:ident))?: $finish:expr,)?
                $(read_response$(($read_binding:ident))?: $read_response:expr,)?
                $(close_response$(($close_binding:ident))?: $close_response:expr,)?
                $(select$(($select_binding:ident))?: $select:expr,)?
            }
        )*
    ) => {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Selected {
            None,
            $($(#[$gate] $selected,)?)*
        }

        /// The discriminant owns both selection and live APDU applet state.
        // Keep the tag first to avoid large-offset loads on Thumb-1.
        // CTAP and ADMIN retain externally owned state for other entrypoints.
        #[repr(u8)]
        enum AppletState {
            None,
            $($(#[$gate] $selected $(($state))?,)?)*
        }

        impl AppletState {
            fn selected(&self) -> Selected {
                match self {
                    Self::None => Selected::None,
                    $($(#[$gate] Self::$selected $(($ignore))? => Selected::$selected,)?)*
                }
            }

            fn command_limit(&self, $h: Header) -> (u8, u32) {
                match self {
                    $($(#[$gate] Self::$selected $(($ignore))? => $limit,)?)*
                    Self::None => ($h.cla, 0),
                }
            }
        }

        impl Selected {
            fn enabled(self, $io: &mut Platform<'_, impl crate::ports::Backends>) -> bool {
                use super::config as $config;
                let mask = match self {
                    $($(#[$gate] Self::$variant => $mask,)?)*
                    _ => 0,
                };
                mask == 0 || $config::enabled($io.storage, mask)
            }

            fn from_aid(aid: &[u8], $transport: canokey_protocol::apdu::Transport) -> Option<Self> {
                // A transport-selected FIDO AID takes precedence.
                $($(
                    #[$gate]
                    if aid == $transport_aid {
                        return Some(Self::$variant);
                    }
                )?)*
                let _ = $transport;

                // Borrowed AIDs share one comparison on size-optimized targets.
                const AIDS: &[(&[u8], Selected)] = &[
                    $($($(#[$gate] ($aid, Selected::$selected),)*)?)*
                ];
                for &(candidate, selected) in AIDS {
                    if aid == candidate {
                        return Some(selected);
                    }
                }
                None
            }

            fn keep_selection_when_disabled($this) -> bool {
                dispatch_applet!(
                    $this, _ => false;
                    $($(#[$gate] Selected::$variant => $keep_selection,)?)*
                )
            }
        }

        #[cfg(all(feature = "pass", classic_presence))]
        impl AppletState {
            fn take_presence_attempt(&mut $this) -> bool {
                dispatch_applet!(
                    $this, _ => false;
                    $($(#[$gate] AppletState::$variant($presence_binding) => $presence,)?)*
                )
            }
        }

        // Frequently accessed session controls precede the shared workspace.
        #[repr(C)]
        pub struct Registry {
            $($($(#[$gate] $primary: $primary_ty,)*)?)*
            $($($(#[$gate] $secondary: $secondary_ty,)*)?)*
            applet: AppletState,
            #[$workspace_gate]
            workspace: super::workspace::SessionWorkspace,
        }

        // A call-scoped set of disjoint borrows. Materialize deep field addresses
        // once before the outlined routing methods load them.
        struct RegistryView<'a> {
            $($($(#[$gate] $primary: &'a mut $primary_ty,)*)?)*
            $($($(#[$gate] $secondary: &'a mut $secondary_ty,)*)?)*
            applet: &'a mut AppletState,
            #[$workspace_gate]
            workspace: &'a mut super::workspace::SessionWorkspace,
        }

        impl Registry {
            pub const fn new() -> Self {
                Self {
                    applet: AppletState::None,
                    $($($(#[$gate] $primary: $primary_init,)*)?)*
                    $($($(#[$gate] $secondary: $secondary_init,)*)?)*
                    #[$workspace_gate]
                    workspace: super::workspace::SessionWorkspace::new(),
                }
            }

            // Sharing construction avoids duplicating deep field addresses.
            #[inline(never)]
            fn view(&mut $this) -> RegistryView<'_> {
                RegistryView {
                    $($($(#[$gate] $primary: &mut $this.$primary,)*)?)*
                    $($($(#[$gate] $secondary: &mut $this.$secondary,)*)?)*
                    applet: &mut $this.applet,
                    #[$workspace_gate]
                    workspace: &mut $this.workspace,
                }
            }
        }

        impl Router for Registry {
            fn can_yield(&$this) -> bool {
                dispatch_applet!(
                    &$this.applet, _ => true;
                    $($(#[$gate] AppletState::$variant($yield_binding) => $can_yield,)?)*
                )
            }
            fn absent_le(&$this, info: canokey_protocol::apdu::CommandInfo) -> u32 {
                if info.lc == 0 {
                    dispatch_applet!(
                        $this.applet.selected(), _ => ();
                        $($(#[$gate] Selected::$variant => return $zero_le,)?)*
                    )
                }
                if info.extended {
                    65536
                } else {
                    super::engine::DEFAULT_APDU_LE
                }
            }
            #[cfg(feature = "ctap")]
            fn native_pending(&$this) -> bool {
                $this.ctap.pending_message()
            }
            fn selected(&$this) -> bool {
                !matches!($this.applet, AppletState::None)
            }
            fn retain_nfc_input(&$this) -> bool {
                dispatch_applet!(
                    $this.applet.selected(), _ => true;
                    $($(#[$gate] Selected::$variant => $retain_nfc_input,)?)*
                )
            }
            fn allows_extended(&$this, $header: Header) -> bool {
                // Transport admission is independent of command validity.
                match $this.applet.selected() {
                    Selected::None => $header.is_get_response(),
                    $($(#[$gate] Selected::$variant => $allows_extended,)?)*
                    #[allow(unreachable_patterns)]
                    _ => true,
                }
            }
            fn command_limit(&$this, $h: Header) -> Result<u32, Sw> {
                // Applets supply their accepted base CLA and logical command bound.
                // Strip the chain bit only for supported commands. NDEF deliberately
                // has no CLA filter, matching its INS-only dispatcher.
                let (cla, limit) = $this.applet.command_limit($h);
                if !$this.selected() {
                    return Err(Sw::FILE_NOT_FOUND);
                }
                if cla != 0 {
                    Err(Sw::CLA_NOT_SUPPORTED)
                } else {
                    Ok(limit)
                }
            }
            fn chain_header(&$this, $header: Header) -> Header {
                dispatch_applet!(
                    $this.applet.selected(), _ => $header;
                    $($(#[$gate] Selected::$variant => $chain_header,)?)*
                )
            }
            #[cfg(feature = "pass")]
            fn output_busy(&$this) -> bool {
                // PASS owns the shared output queue; the registry only arbitrates
                // applet presence and forwards sampling at this composition boundary.
                $this.output.busy()
            }
        }

        impl RegistryView<'_> {
            #[cfg_attr(not(has_applet), allow(unused_variables))]
            #[inline(never)]
            fn reset_sessions(&mut $this, $platform: &mut Platform<'_, impl crate::ports::Backends>) {
                $($(#[$gate] { $reset_owned; })?)*
                // Release native handles before erasing backing bytes.
                #[cfg(classic_presence)]
                dispatch_applet!(
                    &mut $this.applet, _ => ();
                    $($(#[$gate] AppletState::$variant($reset_binding) => {
                        $reset_selected;
                        *$this.applet = AppletState::None;
                    },)?)*
                );
                #[$workspace_gate]
                $this.workspace.wipe_active($platform.memory);
            }

            #[cfg_attr(not(any(has_applet, feature = "pass")), allow(unused_variables))]
            #[inline(never)]
            fn install(
                &mut $this,
                $platform: &mut Platform<'_, impl crate::ports::Backends>,
            ) -> Result<(), Sw> {
                $($(#[$gate] $install_first?;)?)*
                $($(#[$gate] $install?;)?)*
                Ok(())
            }

            #[inline(never)]
            fn reset(&mut $this, $io: &mut Platform<'_, impl crate::ports::Backends>) {
                #[cfg(feature = "pass")]
                $this.output.inhibit(true, $io.memory);
                $this.reset_sessions($io);
                *$this.applet = AppletState::None;
            }

            #[inline(never)]
            fn select(
                &mut $this,
                aid: &[u8],
                $transport: canokey_protocol::apdu::Transport,
                $io: &mut Platform<'_, impl crate::ports::Backends>,
            ) -> Result<u32, Sw> {
                let next = Selected::from_aid(aid, $transport).ok_or(Sw::FILE_NOT_FOUND)?;
                if !next.enabled($io) {
                    // Disabled NDEF follows the unknown-AID rejection path.
                    if next.keep_selection_when_disabled() {
                        return Err(Sw::FILE_NOT_FOUND);
                    }
                    $this.reset_sessions($io);
                    *$this.applet = AppletState::None;
                    return Err(Sw::FILE_NOT_FOUND);
                }
                if $this.applet.selected() != next {
                    $this.reset_sessions($io);
                    match next {
                        Selected::None => *$this.applet = AppletState::None,
                        $($(
                            #[$gate]
                            Selected::$selected => *$this.applet = AppletState::$selected $(($make))?,
                        )?)*
                    }
                    // Reload durable state only on an actual switch.
                    let entered = dispatch_applet!(
                        &mut $this.applet, _ => Ok(());
                        $($(#[$gate] AppletState::$variant($enter_binding) => $enter,)?)*
                    );
                    if let Err(error) = entered {
                        *$this.applet = AppletState::None;
                        return Err(error);
                    }
                }
                dispatch_applet!(
                    &mut $this.applet, _ => Ok(0);
                    $($(#[$gate] AppletState::$variant $(($select_binding))? => $select,)?)*
                )
            }

            #[cfg_attr(
                not(any(classic_presence, feature = "admin", feature = "ndef")),
                allow(unused_variables)
            )]
            #[inline(never)]
            fn abort_command(&mut $this, $platform: &mut Platform<'_, impl crate::ports::Backends>) {
                dispatch_applet!(
                    &mut $this.applet, AppletState::None => ();
                    $($(#[$gate] AppletState::$variant $(($abort_binding))? => $abort_command,)?)*
                )
            }

            #[inline(never)]
            fn begin_command(
                &mut $this,
                #[cfg_attr(
                    not(any(crypto_applet, feature = "ndef", feature = "admin")),
                    allow(unused_variables)
                )]
                $header: Header,
                $platform: &mut Platform<'_, impl crate::ports::Backends>,
            ) -> Result<(), Sw> {
                if !$this.applet.selected().enabled($platform) {
                    $this.reset_sessions($platform);
                    *$this.applet = AppletState::None;
                    return Err(Sw::FILE_NOT_FOUND);
                }
                dispatch_applet!(
                    &mut $this.applet, _ => Ok(());
                    $($(#[$gate] AppletState::$variant $(($begin_binding))? => $begin_command,)?)*
                )
            }

            #[inline(never)]
            fn consume(
                &mut $this,
                #[cfg_attr(not(has_applet), allow(unused_variables))] $bytes: &[u8],
                #[cfg_attr(
                    not(any(
                        feature = "ndef",
                        feature = "admin",
                        feature = "openpgp",
                        feature = "piv"
                    )),
                    allow(unused_variables)
                )]
                $platform: &mut Platform<'_, impl crate::ports::Backends>,
            ) -> Result<(), Sw> {
                dispatch_applet!(
                    &mut $this.applet, AppletState::None => Err(Sw::FILE_NOT_FOUND);
                    $($(#[$gate] AppletState::$variant $(($consume_binding))? => $consume,)?)*
                )
            }

            #[cfg_attr(not(feature = "ndef"), allow(unused_variables))]
            #[inline(never)]
            fn end_frame(
                &mut $this,
                $last: bool,
                $platform: &mut Platform<'_, impl crate::ports::Backends>,
            ) -> Result<(), Sw> {
                dispatch_applet!(
                    &mut $this.applet, _ => Ok(());
                    $($(#[$gate] AppletState::$variant($frame_binding) => $end_frame,)?)*
                )
            }

            // Share final dispatch without expanding it into frame/response handling.
            #[inline(never)]
            fn finish(
                &mut $this,
                #[cfg_attr(
                    not(any(crypto_applet, feature = "admin", feature = "oath")),
                    allow(unused_variables)
                )]
                $header: Header,
                #[cfg_attr(
                    not(any(classic_presence, feature = "admin", feature = "ndef")),
                    allow(unused_variables)
                )]
                $le: u32,
                #[cfg_attr(not(has_applet), allow(unused_variables))] $platform: &mut Platform<
                    '_,
                    impl crate::ports::Backends,
                >,
            ) -> Result<(u32, Sw), Sw> {
                dispatch_applet!(
                    &mut $this.applet, AppletState::None => Err(Sw::FILE_NOT_FOUND);
                    $($(#[$gate] AppletState::$variant $(($finish_binding))? => $finish,)?)*
                )
            }

            // Keep applet workspace addressing out of the response cursor and its
            // error/close paths; this boundary reduces the complete Thumb-1 image.
            #[inline(never)]
            fn read_response(
                &mut $this,
                #[cfg_attr(not(has_applet), allow(unused_variables))] $offset: u32,
                #[cfg_attr(not(has_applet), allow(unused_variables))] $out: &mut [u8],
                #[cfg_attr(
                    not(any(crypto_applet, feature = "admin", feature = "ndef")),
                    allow(unused_variables)
                )]
                $platform: &mut Platform<'_, impl crate::ports::Backends>,
            ) -> Result<usize, Sw> {
                dispatch_applet!(
                    &mut $this.applet, AppletState::None => Err(Sw::COMMAND_NOT_ALLOWED);
                    $($(#[$gate] AppletState::$variant $(($read_binding))? => $read_response,)?)*
                )
            }

            #[cfg_attr(
                not(any(crypto_applet, feature = "admin", feature = "oath")),
                allow(unused_variables)
            )]
            #[inline(never)]
            fn close_response(&mut $this, $platform: &mut Platform<'_, impl crate::ports::Backends>) {
                dispatch_applet!(
                    &mut $this.applet, AppletState::None => ();
                    $($(#[$gate] AppletState::$variant $(($close_binding))? => $close_response,)?)*
                )
            }

            #[cfg(feature = "pass")]
            #[inline(never)]
            fn eject(&mut $this, $io: &mut Platform<'_, impl crate::ports::Backends>) -> Result<(), Sw> {
                $this.output.eject($io.memory);
                Ok(())
            }

            #[cfg(feature = "pass")]
            #[inline(never)]
            fn sample_output(
                &mut $this,
                pressed: bool,
                now: u32,
                ready: bool,
                inhibit: bool,
                $io: &mut Platform<'_, impl crate::ports::Backends>,
            ) -> Option<u8> {
                #[cfg_attr(not(presence_applet), allow(unused_mut))]
                let mut presence = false;
                #[cfg(classic_presence)]
                {
                    presence |= $this.applet.take_presence_attempt();
                }
                $($(#[$gate] { presence |= $owned_presence; })?)*
                if presence || inhibit {
                    $this.output.inhibit(pressed, $io.memory);
                    return None;
                }
                $this.output
                    .sample(pressed, now, ready, $io.memory, |index, $out| {
                        if super::config::enabled($io.storage, super::config::PASS) {
                            crate::flows::credential_output::touch(&$this.pass, index, $out, $io).unwrap_or(0)
                        } else {
                            0
                        }
                    })
            }
        }
    };
}

applets! {
    self, p, platform, config, h, header, transport, bytes, last, le, offset, out;
    #[cfg(any(crypto_applet, feature = "admin", feature = "ndef"))];
    #[cfg(feature = "ndef")]
    Ndef {
        apdu: Ndef(_ => crate::applets::ndef::Applet = crate::applets::ndef::Applet::new()),
        aids: [crate::applets::ndef::AID],
        // The C NDEF handler dispatches by INS without restricting CLA.
        limit: (0, crate::applets::ndef::FILE_LIMIT as u32),
        mask: config::NDEF,
        install: crate::applets::ndef::Applet::install(false, platform),
        keep_selection_when_disabled: true,
        zero_le: 0,
        chain_header: {
            // NDEF SELECT/READ are complete commands even with CLA bit 4.
            if header.ins != crate::applets::ndef::INS_UPDATE_BINARY {
                header.unchained()
            } else {
                // UPDATE continues at the first fragment's offset.
                Header {
                    cla: header.cla & canokey_protocol::apdu::CLA_CHAINING,
                    p1: 0,
                    p2: 0,
                    ..header
                }
            }
        },
        end_frame(s): s.end_frame(
            last,
            &mut self.workspace.classic_with(platform.memory),
            platform,
        ),
        abort_command(s): s.cancel(
            &mut self.workspace.classic_with(platform.memory),
            platform.memory,
        ),
        begin_command(s): s.begin(
            header,
            &mut self.workspace.classic_with(platform.memory),
            platform.memory,
        ),
        consume(s): {
            s.consume(bytes, &mut self.workspace.classic_with(platform.memory))
        },
        // READ BINARY without Le is a zero-byte read; encoded 00 is 256.
        finish(s): s.finish(
            le,
            &mut self.workspace.classic_with(platform.memory),
            platform,
        ),
        read_response(s): s.read(offset as usize, out, platform),
        close_response(s): s.close(),
    }
    #[cfg(feature = "admin")]
    Admin {
        apdu: Admin,
        aids: [admin::AID],
        limit: {
            #[cfg(feature = "ctap")]
            if h.ins == admin::INS_PROVISION_ATTESTATION {
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
        },
        primary: [admin: admin::Admin = admin::Admin::new()],
        secondary: [grants: admin::Grants = admin::Grants { admin: false }],
        install_first: self.admin.install(platform),
        reset_owned: {
            self.grants.admin = false;
            self.admin.abort_transaction(platform);
        },
        abort_command: self
            .admin
            .cancel_command(&mut self.workspace.classic_with(platform.memory), platform),
        begin_command: self.admin.begin(header, &self.grants, platform),
        consume: self.admin.consume(
            bytes,
            &mut self.workspace.classic_with(platform.memory),
            platform,
        ),
        finish: self.finish_admin(header, le, platform),
        read_response: self
            .admin
            .read_response(
                offset as usize,
                out,
                &mut self.workspace.classic_with(platform.memory),
            )
            .map(|()| out.len()),
        close_response: self
            .admin
            .close_response(&mut self.workspace.classic_with(platform.memory), platform),
    }
    #[cfg(feature = "ctap")]
    Ctap {
        apdu: Ctap,
        aids: [],
        limit: (
            if h.cla == 0 { 0 } else { h.unchained().cla ^ canokey_protocol::apdu::CLA_FIDO },
            ctap::MAX_REQUEST as u32,
        ),
        transport_aid: transport.fido_aid(),
        mask: config::WEBAUTHN,
        primary: [ctap: ctap::Applet = ctap::Applet::new()],
        install_first: self.ctap.install(platform),
        reset_owned: self.ctap.reset(&mut self.workspace, platform),
        zero_le: 0,
        retain_nfc_input: false,
        owned_presence: self.ctap.take_presence_attempt(),
        abort_command: self.ctap.cancel_command(&mut self.workspace),
        begin_command: self.ctap.begin(header, &mut self.workspace, platform),
        consume: self.ctap.consume(bytes, &mut self.workspace),
        finish: self
            .ctap
            .finish(header, &mut self.workspace, platform)
            .map(|n| (n, Sw::SUCCESS)),
        read_response: {
            self.ctap
                .read_apdu(offset as usize, out, &mut self.workspace, platform)
        },
        close_response: {
            // Release the primitive before erasing its backing. Response
            // completion ends this workspace lease, not the FIDO session.
            self.ctap.close(&mut self.workspace, platform);
            self.workspace.wipe_active(platform.memory);
        },
        select: Ok(self.ctap.select(&mut self.workspace, p)),
    }
    #[cfg(feature = "pass")]
    Pass {
        secondary: [
            pass: Pass = Pass::new(),
            output: crate::applets::pass::output::Output = crate::applets::pass::output::Output::new(),
        ],
        install: self.pass.install(platform.storage, platform.memory).map_err(crate::applets::pass::status),
    }
    #[cfg(feature = "oath")]
    Oath {
        apdu: Oath(_ => crate::applets::oath::protocol::Oath = crate::applets::oath::protocol::Oath::new()),
        aids: [crate::applets::oath::protocol::AID],
        limit: (h.unchained().cla, crate::applets::oath::protocol::CAPACITY as u32),
        install: crate::applets::oath::protocol::Oath::new().install(platform),
        reset_selected(s): s.reset(platform),
        presence(s): s.take_presence_attempt(),
        abort_command(s): s.cancel_command(platform),
        consume(s): s.consume(bytes),
        finish(s): {
            let pass = pass_arg!(self);
            s.finish(header, le, pass, platform)
        },
        read_response(s): s.read_response(offset as usize, out).map(|()| out.len()),
        close_response(s): s.close_response(platform),
        select(s): s.select(p),
    }
    #[cfg(feature = "openpgp")]
    OpenPgp {
        apdu: OpenPgp(_ => crate::applets::openpgp::protocol::OpenPgp = crate::applets::openpgp::protocol::OpenPgp::new()),
        aids: [crate::applets::openpgp::protocol::AID],
        limit: (
            if h.chained() && !crate::applets::openpgp::protocol::OpenPgp::supports_chaining(h) {
                h.cla
            } else {
                h.unchained().cla
            },
            crate::applets::openpgp::protocol::OpenPgp::limit(h),
        ),
        mask: if p.device.contactless() { config::OPENPGP_NFC } else { config::OPENPGP_USB },
        install: crate::applets::openpgp::protocol::OpenPgp::new().install(platform),
        reset_selected(s): s.abort_transaction(platform),
        presence(s): s.take_presence_attempt(),
        zero_le: 0,
        abort_command(s): {
            s.abort(&mut self.workspace.classic_with(platform.memory), platform)
        },
        begin_command(s): s.begin(
            header,
            &mut self.workspace.classic_with(platform.memory),
            platform,
        ),
        consume(s): s.consume(
            bytes,
            &mut self.workspace.classic_with(platform.memory),
            platform,
        ),
        finish(s): s.finish(
            header,
            le,
            &mut self.workspace.classic_with(platform.memory),
            platform,
        ),
        read_response(s): s.read(
            offset as usize,
            out,
            &mut self.workspace.classic_with(platform.memory),
            platform,
        ),
        close_response(s): {
            s.close(&mut self.workspace.classic_with(platform.memory), platform)
        },
        select(s): s.select(p),
    }
    #[cfg(feature = "piv")]
    Piv {
        apdu: Piv(_ => Piv = Piv::new()),
        // Full AID, standardized nine-byte selector, then legacy RID selector.
        aids: [
            crate::applets::piv::AID,
            crate::applets::piv::AID.split_at(9).0,
            crate::applets::piv::AID.split_at(5).0,
        ],
        limit: (
            if h.chained() && !Piv::supports_chaining(h.ins) { h.cla } else { h.unchained().cla },
            Piv::limit(h),
        ),
        mask: if p.device.contactless() { config::PIV_NFC } else { config::PIV_USB },
        install: Piv::new().install(platform),
        reset_selected(s): s.deselect(&mut self.workspace, platform),
        presence(s): s.take_presence_attempt(),
        can_yield(s): s.can_yield(),
        zero_le: 0,
        allows_extended: false,
        enter(s): s.install(p),
        abort_command(s): s.cancel(&mut self.workspace, platform),
        begin_command(s): s.begin(header, &mut self.workspace, platform),
        consume(s): s.consume(bytes, &mut self.workspace, platform),
        finish(s): s.finish(header, le, &mut self.workspace, platform),
        read_response(s): s.read(offset as usize, out, &mut self.workspace, platform),
        close_response(s): s.close(&mut self.workspace, platform),
        select(s): s.select(&mut self.workspace, p),
    }
}

#[cfg(feature = "ctap")]
impl Registry {
    // Drop parser-construction temporaries before the HID caller runs crypto.
    #[inline(never)]
    pub fn begin_hid_request(
        &mut self,
        message_length: Option<usize>,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) {
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
    pub fn consume_hid_request(&mut self, bytes: &[u8]) {
        use super::workspace::SessionWorkspace;
        match &mut self.workspace {
            SessionWorkspace::CtapRequest(request) => request.consume(bytes),
            SessionWorkspace::CtapMessage(request) => request.consume(bytes),
            _ => unreachable!(),
        }
    }
    #[inline(never)]
    pub fn finish_hid_request(
        &mut self,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> usize {
        self.ctap.finish_hid(&mut self.workspace, p)
    }
    pub fn execute_ctap(
        &mut self,
        command: Result<ctap::Command, ctap::Status>,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> usize {
        let mut command = command;
        self.ctap.execute(&mut command, &mut self.workspace, p)
    }
    pub fn execute_ctap_message(
        &mut self,
        command: ctap::message::Message,
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> usize {
        self.ctap
            .execute_message(&mut { command }, &mut self.workspace, p)
    }
    pub fn read_ctap(
        &mut self,
        offset: usize,
        out: &mut [u8],
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Sw> {
        self.ctap.read(offset, out, &mut self.workspace, p)
    }
    pub fn resume_ctap(&mut self, p: &mut Platform<'_, impl crate::ports::Backends>) {
        if !self.ctap.pending_message() {
            self.close_ctap(p);
        }
    }
    pub fn complete_ctap(&mut self, p: &mut Platform<'_, impl crate::ports::Backends>) {
        if !self.ctap.complete_message() {
            self.close_ctap(p);
        }
    }
    pub fn continue_ctap_message(
        &mut self,
        bytes: &[u8],
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Option<usize> {
        self.ctap.continue_message(bytes, &mut self.workspace, p)
    }
    pub fn close_ctap(&mut self, p: &mut Platform<'_, impl crate::ports::Backends>) {
        self.ctap.close(&mut self.workspace, p);
        self.workspace.classic_with(p.memory).clear(p.memory);
    }
}

#[cfg(feature = "pass")]
impl Registry {
    pub fn touch(
        &self,
        index: u8,
        out: &mut [u8],
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<usize, Sw> {
        if !super::config::enabled(p.storage, super::config::PASS) {
            return Ok(0);
        }
        // HOTP touch is a flow operation and uses flow_status; challenge is
        // a PASS service primitive and maps its domain status directly below.
        crate::flows::credential_output::touch(&self.pass, index, out, p)
            .map_err(actions::flow_status)
    }
    pub fn challenge(
        &self,
        index: u8,
        input: &[u8],
        out: &mut [u8; 20],
        p: &mut Platform<'_, impl crate::ports::Backends>,
    ) -> Result<(), Sw> {
        self.pass
            .challenge(index, input, out, p)
            .map_err(crate::applets::pass::status)
    }
}

impl<B: crate::ports::Backends> canokey_transport_runtime::engine::Dispatch<Platform<'_, B>>
    for Registry
{
    #[cfg(feature = "ctap")]
    fn yield_native(&mut self, p: &mut Platform<'_, B>) {
        self.close_ctap(p);
    }
    fn install(&mut self, platform: &mut Platform<'_, B>) -> Result<(), Sw> {
        self.view().install(platform)
    }
    fn reset(&mut self, p: &mut Platform<'_, B>) {
        self.view().reset(p)
    }
    fn select(
        &mut self,
        aid: &[u8],
        transport: canokey_protocol::apdu::Transport,
        p: &mut Platform<'_, B>,
    ) -> Result<u32, Sw> {
        self.view().select(aid, transport, p)
    }
    fn reject_select(
        &mut self,
        transport: canokey_protocol::apdu::Transport,
        p: &mut Platform<'_, B>,
    ) {
        #[cfg(feature = "ctap")]
        if transport == canokey_protocol::apdu::Transport::Usb
            && matches!(self.applet, AppletState::Ctap)
        {
            self.view().reset(p);
        }
        let _ = (transport, p);
    }
    fn fido_selected(&self, p: &mut Platform<'_, B>) -> bool {
        #[cfg(feature = "ctap")]
        {
            matches!(self.applet, AppletState::Ctap) && Selected::Ctap.enabled(p)
        }
        #[cfg(not(feature = "ctap"))]
        {
            let _ = p;
            false
        }
    }
    fn abort_command(&mut self, platform: &mut Platform<'_, B>) {
        self.view().abort_command(platform)
    }
    fn begin_command(&mut self, header: Header, platform: &mut Platform<'_, B>) -> Result<(), Sw> {
        self.view().begin_command(header, platform)
    }
    fn consume(&mut self, bytes: &[u8], platform: &mut Platform<'_, B>) -> Result<(), Sw> {
        self.view().consume(bytes, platform)
    }
    fn end_frame(&mut self, last: bool, platform: &mut Platform<'_, B>) -> Result<(), Sw> {
        self.view().end_frame(last, platform)
    }
    // Share final dispatch without expanding it into frame/response handling.
    fn finish(
        &mut self,
        header: Header,
        le: u32,
        platform: &mut Platform<'_, B>,
    ) -> Result<(u32, Sw), Sw> {
        self.view().finish(header, le, platform)
    }
    // Keep applet workspace addressing out of the response cursor and its
    // error/close paths; this boundary reduces the complete Thumb-1 image.
    fn read_response(
        &mut self,
        offset: u32,
        out: &mut [u8],
        platform: &mut Platform<'_, B>,
    ) -> Result<usize, Sw> {
        self.view().read_response(offset, out, platform)
    }
    fn close_response(&mut self, platform: &mut Platform<'_, B>) {
        self.view().close_response(platform)
    }
    #[cfg(feature = "pass")]
    fn is_eject(&self, h: Header, p: &mut Platform<'_, B>) -> bool {
        // PASS eject pseudo-APDU: FF EE FF EE, gated by the PASS feature.
        h.cla == 0xff
            && h.ins == 0xee
            && h.p1 == 0xff
            && h.p2 == 0xee
            && super::config::enabled(p.storage, super::config::PASS)
    }
    #[cfg(feature = "pass")]
    fn eject(&mut self, p: &mut Platform<'_, B>) -> Result<(), Sw> {
        self.view().eject(p)
    }
    #[cfg(feature = "pass")]
    fn sample_output(
        &mut self,
        pressed: bool,
        now: u32,
        ready: bool,
        inhibit: bool,
        p: &mut Platform<'_, B>,
    ) -> Option<u8> {
        self.view().sample_output(pressed, now, ready, inhibit, p)
    }
    fn wipe(&mut self, bytes: &mut [u8], p: &mut Platform<'_, B>) {
        canokey_ports::Memory::wipe(p.memory, bytes);
    }

    fn installed(&mut self, p: &mut Platform<'_, B>) {
        super::config::notify(p);
    }
}
impl Default for Registry {
    fn default() -> Self {
        Self::new()
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
mod config_tests;

#[cfg(test)]
mod aid_tests;

#[cfg(all(test, feature = "ctap"))]
mod ctap_lifetime_tests;
