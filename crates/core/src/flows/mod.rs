// SPDX-License-Identifier: Apache-2.0
#[cfg(feature = "pass")]
pub(crate) mod credential_output;
#[cfg(feature = "admin")]
pub(crate) mod factory_reset;
#[cfg(feature = "oath")]
pub(crate) mod oath_pass;
/// Cross-applet errors carry no wire status.
#[cfg(any(feature = "admin", feature = "pass"))]
pub enum Error {
    #[cfg(all(feature = "admin", feature = "ctap"))]
    Ctap,
    #[cfg(all(feature = "admin", feature = "ndef"))]
    Ndef,
    #[cfg(all(feature = "admin", feature = "piv"))]
    Piv,
    Pass(crate::applets::pass::domain::Error),
    #[cfg(feature = "oath")]
    Oath(crate::applets::oath::Error),
    #[cfg(all(feature = "admin", feature = "openpgp"))]
    OpenPgp(crate::applets::openpgp::domain::Error),
    #[cfg(feature = "admin")]
    Admin(crate::applets::admin::pin::Error),
    #[cfg(all(feature = "pass", feature = "oath"))]
    Output,
}
