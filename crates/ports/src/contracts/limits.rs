// SPDX-License-Identifier: Apache-2.0
//! Static product request budgets, independent of wire format and backing size.

pub trait RequestLimits {
    /// CTAP command byte plus CBOR bytes; advertised by GetInfo maxMsgSize.
    const CTAP_REQUEST_MAX_BYTES: usize;
    /// Complete native HID MSG envelope, including its header and trailer.
    /// This does not authorize ISO extended APDUs on CCID.
    const NATIVE_MSG_MAX_BYTES: usize;
}
