// SPDX-License-Identifier: Apache-2.0
//! Synchronous NFC IRQ runtime without product polling state.
pub use canokey_transport_runtime::nfc_io::{Chip, NoPolling};
pub type Io = canokey_transport_runtime::nfc_io::Io<NoPolling>;
