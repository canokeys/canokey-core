// SPDX-License-Identifier: Apache-2.0
pub trait Device {
    fn serial(&mut self, output: &mut [u8; 4]);
    fn now(&mut self) -> u32;
    fn touched(&mut self) -> bool;
    fn wink(&mut self) {}
    /// Consume a completed, unexpired gesture for CTAP1 polling.
    fn poll_presence(&mut self) -> bool {
        false
    }
    /// Transport-only progress; false means reset/disconnect/cancel.
    fn progress(&mut self) -> bool;
    /// Transport-only status: true while waiting for user presence, false while processing.
    fn keepalive(&mut self, _waiting: bool) {}
    fn led(&mut self, on: bool);
}
