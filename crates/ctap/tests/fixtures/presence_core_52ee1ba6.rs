// SPDX-License-Identifier: Apache-2.0
// Fixed executed Core presence reference, 52ee1ba6; test-only.
const PRESENCE_TIMEOUT_MS: u32 = 30_000;
pub fn wait(device: &mut (impl canokey_ports::Device + ?Sized), minimum_ms: u32) -> Result<(), Error> {
    if device.contactless() {
        return if device.progress() {
            Ok(())
        } else {
            Err(Error::Cancelled)
        };
    }
    let start = device.now();
    // A contact predating this request must be released before a fresh gesture.
    let mut armed = !device.touched();
    let mut pressed = None;
    let result = (|| loop {
        if !device.progress() {
            return Err(Error::Cancelled);
        }
        if device.now().wrapping_sub(start) >= PRESENCE_TIMEOUT_MS {
            return Err(Error::Timeout);
        }
        let blink = (device.now().wrapping_sub(start) / 100).is_multiple_of(2);
        device.led(blink);
        let touch = device.touched();
        if !armed {
            armed = !touch;
            continue;
        }
        if touch {
            pressed.get_or_insert_with(|| device.now());
        } else if let Some(since) = pressed.take() {
            if device.now().wrapping_sub(since) >= minimum_ms {
                return Ok(());
            }
        }
    })();
    device.led_idle();
    result
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Cancelled,
    Timeout,
}
