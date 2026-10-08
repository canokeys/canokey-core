// SPDX-License-Identifier: Apache-2.0
//! Outer backend selection for the serialized shared runtime.
use canokey_ports::{Backends, Platform};
pub mod core;

/// Capabilities constructed by the firmware, host or test owner.
///
/// Construction must not borrow transport state across Core execution: device
/// progress may service disjoint IRQ mailboxes while these capabilities are live.
pub trait Provider {
    type Backends: Backends;
    fn with_platform<T>(run: impl FnOnce(&mut Platform<'_, Self::Backends>) -> T) -> T;
}
