// SPDX-License-Identifier: Apache-2.0
// Shared bound for an OATH credential name and its PASS reference.
#[cfg(any(feature = "admin", feature = "oath", feature = "pass"))]
pub(crate) const OATH_NAME_BYTES: usize = 64;
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
#[cfg(has_applet)]
#[cfg_attr(
    not(any(feature = "admin", feature = "oath", feature = "ctap")),
    expect(dead_code)
)]
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

#[cfg(any(
    feature = "admin",
    feature = "oath",
    feature = "ndef",
    feature = "piv",
    feature = "openpgp"
))]
pub(crate) fn append_bounded(
    used: &mut usize,
    buf: &mut [u8],
    cap: usize,
    bytes: &[u8],
) -> Option<()> {
    let end = used.checked_add(bytes.len()).filter(|&end| end <= cap)?;
    buf.get_mut(*used..end)?.copy_from_slice(bytes);
    *used = end;
    Some(())
}

#[cfg(any(feature = "piv", feature = "openpgp"))]
pub(crate) fn get_challenge(
    le: u32,
    out: &mut [u8],
    crypto: &mut crate::ports::CryptoPort<'_>,
) -> Result<u32, canokey_protocol::response::StatusWord> {
    use canokey_protocol::{apdu::SHORT_DATA_BYTES, response::StatusWord as Sw};
    if le == 0 || le > SHORT_DATA_BYTES as u32 {
        return Err(Sw::WRONG_LENGTH);
    }
    crypto
        .random(&mut out[..le as usize])
        .map_err(|_| Sw::UNABLE_TO_PROCESS)?;
    Ok(le)
}

#[cfg(any(feature = "admin", feature = "oath", feature = "piv"))]
pub(crate) fn write_serial(out: &mut [u8], serial: impl FnOnce(&mut [u8; 4])) -> usize {
    const SERIAL_BYTES: usize = 4;
    serial((&mut out[..SERIAL_BYTES]).try_into().unwrap());
    SERIAL_BYTES
}

#[cfg(any(feature = "admin", feature = "oath"))]
pub(crate) fn close_response(
    memory: &crate::ports::MemoryPort<'_>,
    response: &mut [u8],
    length: &mut usize,
) {
    memory.wipe(response);
    *length = 0;
}

#[cfg(feature = "ndef")]
pub mod ndef;
