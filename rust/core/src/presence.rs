// SPDX-License-Identifier: Apache-2.0
//! Main-loop presence operation; no C callback may reenter the core.
#![forbid(unsafe_code)]
use crate::Platform;
#[cfg(feature = "oath")]
pub fn wait(p: &mut dyn Platform) -> bool {
    let start = p.now();
    // A contact predating this request must be released before a fresh gesture.
    let mut armed = !p.touched();
    let mut pressed = false;
    loop {
        if !p.progress() || p.now().wrapping_sub(start) >= 30_000 {
            return false;
        }
        let touch = p.touched();
        if !armed {
            armed = !touch;
            continue;
        }
        if touch {
            pressed = true;
        }
        if pressed && !touch {
            return true;
        }
    }
}

/// Five fresh short touches, each prompted within a two-second blink window.
/// Delay after each release separates prompts; only raw transport progress runs.
pub fn strong(p: &mut dyn Platform) -> bool {
    let accepted = (|| {
        for round in 0..5 {
            let start = p.now();
            let mut armed = !p.touched();
            let mut pressed = None;
            loop {
                let elapsed = p.now().wrapping_sub(start);
                if elapsed >= 2000 || !p.progress() {
                    return false;
                }
                p.led((elapsed / if round % 2 == 0 { 50 } else { 200 }).is_multiple_of(2));
                let touch = p.touched();
                if !armed {
                    armed = !touch;
                    continue;
                }
                if touch && pressed.is_none() {
                    pressed = Some(p.now());
                }
                if !touch && let Some(since) = pressed {
                    if p.now().wrapping_sub(since) >= 500 {
                        return false;
                    }
                    break;
                }
            }
            p.led(false);
            let released = p.now();
            while p.now().wrapping_sub(released) < 2000 {
                if !p.progress() {
                    return false;
                }
            }
        }
        true
    })();
    p.led(false);
    accepted
}
