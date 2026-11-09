// SPDX-License-Identifier: Apache-2.0
//! Bounded framing plans; generated public keys remain owned by the stream.
use super::{Mode, Pending};
use crate::{
    credential, resident,
    response::encoding::{self, EncodeError, Encoder},
};

/// Encode from the borrowed resident record before its input storage is reused
/// for the stream seed. The returned length excludes the generated public key;
/// callers stage the seed and publish the plan only after successful encoding.
#[inline(always)]
pub fn public(
    entry: &resident::Entry<'_>,
    algorithm: u8,
    id: &credential::Id,
    total: Option<u8>,
    blob_key: Option<&[u8; credential::KEY_BYTES]>,
    output: &mut [u8],
) -> Result<(Pending, usize), EncodeError> {
    let capacity = output.len();
    let (status, body) = output.split_first_mut().ok_or(EncodeError)?;
    *status = 0x00;
    let mut encoder = Encoder::new(body);
    encoding::management_header(&mut encoder, entry, total.is_some(), blob_key.is_some())?;
    encoder.u8(encoding::management::PUBLIC_KEY).finish()?;
    encoding::mldsa_public_header(&mut encoder, algorithm)?;
    let public_at = capacity - encoder.writer().len();
    encoding::management_tail(&mut encoder, id, total, blob_key.map(|key| &key[..]))?;
    let length = capacity - encoder.writer().len();
    Ok((
        Pending {
            algorithm,
            mode: Mode::Public,
            prefix: public_at,
            auth: 0,
            public_at,
            signature_at: 0,
            certificate: None,
            output: length,
            hash_prefix: (0, 0),
            hash_suffix: (0, 0),
        },
        length,
    ))
}
