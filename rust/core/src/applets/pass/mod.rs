// SPDX-License-Identifier: Apache-2.0
#![forbid(unsafe_code)]
pub mod codec;
pub mod domain;
#[cfg(feature = "pass")]
pub(crate) mod output;
pub mod service;

/// APDU-facing mapping shared by ADMIN, OATH and runtime orchestration.
/// Keep protocol status outside domain/service code, which returns typed errors.
pub(crate) fn status(error: domain::Error) -> canokey_protocol::response::StatusWord {
    use canokey_protocol::response::StatusWord as Sw;
    match error {
        domain::Error::Persistence => Sw::UNABLE_TO_PROCESS,
        _ => Sw::WRONG_DATA,
    }
}
