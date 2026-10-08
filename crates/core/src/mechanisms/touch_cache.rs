// SPDX-License-Identifier: Apache-2.0
pub fn wait(
    last: &mut Option<u32>,
    duration_ms: u32,
    presence: &mut crate::runtime::presence::Request,
    device: &mut (impl crate::ports::Device + ?Sized),
) -> bool {
    let now = device.now();
    if duration_ms != 0 && last.is_some_and(|last| now.wrapping_sub(last) < duration_ms) {
        return true;
    }
    if !presence.wait(device) {
        return false;
    }
    *last = Some(device.now());
    true
}
