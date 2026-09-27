// SPDX-License-Identifier: Apache-2.0
#[cfg(feature = "admin")]
pub(crate) mod factory_reset;
#[cfg(feature = "pass")]
pub(crate) mod hotp_output;
/// Cross-applet errors carry no wire status.
pub enum Error {
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
