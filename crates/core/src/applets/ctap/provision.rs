// SPDX-License-Identifier: Apache-2.0
//! Attestation material is provisioned by ADMIN, never synthesized at runtime.
#[cfg(feature = "admin")]
use crate::{
    ports::{KeyOperation, Platform, Record, alg},
    runtime::workspace::Workspace,
};
#[cfg(feature = "admin")]
use canokey_protocol::response::StatusWord as Sw;

pub(crate) const CERT_LIMIT: usize = 1152;
pub(super) const AAGUID: [u8; 16] = [
    0x24, 0x4e, 0xb2, 0x9e, 0xe0, 0x90, 0x4e, 0x49, 0x81, 0xfe, 0x1f, 0x20, 0xf8, 0xd3, 0xb8, 0xf4,
];
#[cfg(feature = "admin")]
pub(crate) fn install_key(
    key: &mut [u8; 32],
    w: &mut Workspace,
    p: &mut Platform<'_>,
) -> Result<(), Sw> {
    w.clear(p.memory);
    w.key.bytes[..32].copy_from_slice(key);
    p.memory.wipe(key);
    let result = (|| {
        p.crypto
            .key_operation(
                KeyOperation::Validate,
                alg::P256,
                &mut w.key,
                &[],
                &mut w.output,
            )
            .map_err(|_| Sw::WRONG_DATA)?;
        p.storage
            .replace(Record::CtapAttestationKey, &w.key.bytes[..32])
            .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
        super::settings::Sm2::save(&super::settings::Sm2::DEFAULT.encode(), p)
    })();
    w.clear(p.memory);
    result
}
