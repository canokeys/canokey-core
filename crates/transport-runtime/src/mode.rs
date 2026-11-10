// SPDX-License-Identifier: Apache-2.0
//! Continuous D+ observation before enabling the USB pull-up.

const OBSERVATION_MS: u32 = 10;

/// Select contactless mode only after a full window with no low pin sample.
///
/// The caller supplies a running millisecond clock and the raw mode pin.
/// Sampling must precede USB pull-up and NFC bus preparation. Do not sleep
/// between samples: a brief host pull-down must select USB immediately.
pub fn detect_contactless(
    mut now: impl FnMut() -> u32,
    mut pin_high: impl FnMut() -> bool,
) -> bool {
    let start = now();
    loop {
        if !pin_high() {
            return false;
        }
        if now().wrapping_sub(start) >= OBSERVATION_MS {
            return true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_low_selects_usb_without_waiting() {
        let mut ticks = [100].into_iter();
        assert!(!detect_contactless(|| ticks.next().unwrap(), || false));
    }

    #[test]
    fn initial_high_does_not_hide_a_later_host_pull_down() {
        let mut ticks = [100, 100, 101].into_iter();
        let mut pins = [true, true, false].into_iter();
        assert!(!detect_contactless(
            || ticks.next().unwrap(),
            || pins.next().unwrap(),
        ));
    }

    #[test]
    fn continuous_high_requires_the_full_window() {
        let mut ticks = [100, 100, 109, 110].into_iter();
        let mut samples = 0;
        assert!(detect_contactless(
            || ticks.next().unwrap(),
            || {
                samples += 1;
                true
            },
        ));
        assert_eq!(samples, 3);
    }

    #[test]
    fn tick_wrap_preserves_the_window() {
        let mut ticks = [u32::MAX - 4, u32::MAX, 4, 5].into_iter();
        assert!(detect_contactless(|| ticks.next().unwrap(), || true));
    }
}
