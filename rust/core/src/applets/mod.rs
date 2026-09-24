// SPDX-License-Identifier: Apache-2.0
#[cfg(feature = "admin")]
pub mod admin;
#[cfg(feature = "ctap")]
pub mod ctap;
#[cfg(feature = "oath")]
pub mod oath;
#[cfg(feature = "openpgp")]
pub mod openpgp;
#[cfg(any(feature = "admin", feature = "pass", feature = "oath"))]
pub mod pass;
#[cfg(feature = "piv")]
pub mod piv;

/// Copy one bounded response chunk for applets that expose GET RESPONSE data.
/// Keeping the checked slice operation here prevents each applet from growing
/// a subtly different offset/length implementation.
#[cfg(any(feature = "admin", feature = "oath"))]
pub(crate) fn read_response_chunk(
    response: &[u8],
    length: usize,
    offset: usize,
    out: &mut [u8],
) -> Result<(), canokey_protocol::response::StatusWord> {
    let end = offset
        .checked_add(out.len())
        .ok_or(canokey_protocol::response::StatusWord::WRONG_LENGTH)?;
    out.copy_from_slice(
        response[..length]
            .get(offset..end)
            .ok_or(canokey_protocol::response::StatusWord::WRONG_LENGTH)?,
    );
    Ok(())
}

#[cfg(any(feature = "admin", feature = "oath"))]
pub(crate) fn close_response(
    memory: &dyn crate::ports::Memory,
    response: &mut [u8],
    length: &mut usize,
) {
    memory.wipe(response);
    *length = 0;
}
