// SPDX-License-Identifier: Apache-2.0
//! CanoKey short-only CCID validation and card identity.
use canokey_protocol::ccid::{ATR, HEADER};
pub use canokey_transport_runtime::ccid::Backend;
pub use canokey_transport_runtime::ccid::ShortApdu as CanoKey;
pub const FRAME: usize = canokey_protocol::apdu::SHORT_FRAME_BYTES;
pub const REPLY: usize = canokey_protocol::apdu::SHORT_REPLY_BYTES;
pub const CONTROL_REPLY: usize = HEADER + ATR.len();
pub use canokey_transport_runtime::ccid::EXTENSION_INTERVAL;
pub type Transport = canokey_transport_runtime::ccid::Transport<CanoKey>;
