// SPDX-License-Identifier: Apache-2.0
pub mod engine;
#[cfg(any(
    feature = "admin",
    feature = "oath",
    feature = "openpgp",
    feature = "piv"
))]
pub(crate) mod presence;
pub mod registry;

#[cfg(any(feature = "openpgp", feature = "piv"))]
pub(crate) mod workspace;

#[cfg(feature = "ctap")]
pub mod ctaphid;
