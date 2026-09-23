// SPDX-License-Identifier: Apache-2.0
pub(crate) mod pin;

#[cfg(any(feature = "openpgp", feature = "piv"))]
pub(crate) mod key_storage;
