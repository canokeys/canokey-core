// SPDX-License-Identifier: Apache-2.0
//! Serialized test composition shared by APDU fixtures, replay and fuzzing.
use canokey_ports::{Device, MemoryBackend, Platform};
use canokey_rust_core::Core;
pub mod storage;
#[cfg(feature = "transport-hid")]
pub mod transport;
pub const CCID_OWNER: u8 = 1;
pub struct Clock {
    ticks: u32,
    #[cfg(feature = "ctap")]
    polling: canokey_ports::Polling,
}
impl Clock {
    fn pressed(&self) -> bool {
        (20..60).contains(&(self.ticks % 100))
    }
    #[cfg(feature = "ctap")]
    pub fn sample(&mut self) {
        self.polling.sample(self.pressed(), self.ticks);
    }
}
impl Device for Clock {
    fn information(&mut self, kind: u8, output: &mut [u8]) -> usize {
        use canokey_ports::board_info_kind;
        let bytes: &[u8] = match kind {
            board_info_kind::FIRMWARE => b"0.0.0",
            board_info_kind::PRODUCT => b"CanoKey Rust Virtual Card",
            board_info_kind::CORE => b"unknown",
            _ => &[0; canokey_ports::CHIP_ID_BYTES],
        };
        let n = bytes.len().min(output.len());
        output[..n].copy_from_slice(&bytes[..n]);
        n
    }
    fn serial(&mut self, out: &mut [u8; 4]) {
        out.fill(0);
    }
    fn now(&mut self) -> u32 {
        self.ticks
    }
    fn touched(&mut self) -> bool {
        #[cfg(feature = "ctap")]
        self.polling.clear();
        self.pressed()
    }
    fn progress(&mut self) -> bool {
        self.ticks = self.ticks.wrapping_add(1);
        true
    }
    fn led(&mut self, _: bool) {}
    #[cfg(feature = "ctap")]
    fn poll_presence(&mut self) -> bool {
        self.polling.take(self.ticks)
    }
    #[cfg(feature = "ctap")]
    fn wink(&mut self) {
        self.polling.wink(self.ticks);
    }
}
pub type Backend = canokey_ports::BackendTypes<
    storage::Records,
    canokey_native_crypto::CryptoBackend,
    Clock,
    MemoryBackend,
>;
pub struct Card {
    core: Core,
    pub records: storage::Records,
    pub clock: Clock,
    crypto: canokey_native_crypto::CryptoBackend,
    memory: MemoryBackend,
}
impl Card {
    /// # Safety
    /// All native crypto use must be serialized for the lifetime of this card.
    pub unsafe fn new() -> Self {
        Self {
            core: Core::new(),
            records: storage::Records::new(),
            clock: Clock {
                ticks: 0,
                #[cfg(feature = "ctap")]
                polling: canokey_ports::Polling::new(),
            },
            crypto: unsafe { canokey_native_crypto::CryptoBackend::new() },
            memory: MemoryBackend,
        }
    }
    pub fn run<T>(&mut self, action: impl FnOnce(&mut Core, &mut Platform<'_, Backend>) -> T) -> T {
        action(
            &mut self.core,
            &mut Platform::new(
                &mut self.records,
                &mut self.crypto,
                &mut self.clock,
                &self.memory,
            ),
        )
    }
    pub fn install(&mut self) -> bool {
        self.run(|core, p| core.install(p).is_ok())
    }
    pub fn reset(&mut self) {
        self.run(|core, p| core.reset(p));
    }
    pub fn slot_power(&mut self) {
        self.run(|core, p| core.slot_power(p));
    }
    pub fn exchange(&mut self, input: &[u8], output: &mut [u8]) -> Option<usize> {
        self.exchange_owner(CCID_OWNER, input, output)
    }
    pub fn exchange_owner(&mut self, owner: u8, input: &[u8], output: &mut [u8]) -> Option<usize> {
        self.run(|core, p| {
            let reply = core.receive(owner, input, p);
            core.transmit(reply, output, p).ok()
        })
    }
    #[cfg(feature = "pass")]
    pub fn touch(&mut self, index: u8, output: &mut [u8]) -> Option<usize> {
        self.run(|core, p| core.touch(index, output, p).ok())
    }
}
