// SPDX-License-Identifier: Apache-2.0
//! CanoKey product request policy; shared protocol code has no product budget.
use canokey_ports::RequestLimits;

#[derive(Default)]
pub struct CanoKeyLimits;
impl RequestLimits for CanoKeyLimits {
    const CTAP_REQUEST_MAX_BYTES: usize = 1296;
    const NATIVE_MSG_MAX_BYTES: usize = 1296;
}

pub const CTAP_MAX_REQUEST: usize = CanoKeyLimits::CTAP_REQUEST_MAX_BYTES;
