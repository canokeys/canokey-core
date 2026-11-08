// SPDX-License-Identifier: Apache-2.0
//! Main-loop presence mechanisms over synchronous transport-only Device access.
//! No request payload, storage capability or callback into an application is held.
use crate::ports::Presence;

const LONG_TOUCH_MS: u32 = 500;
pub const TIMEOUT_MS: u32 = 30_000;
fn wait(device: &mut (impl Presence + ?Sized), minimum_ms: u32) -> Result<(), Error> {
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
        if device.now().wrapping_sub(start) >= TIMEOUT_MS {
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
/// An attempted request owns its gesture even when it times out or is cancelled.
pub struct Request {
    attempted: bool,
}
impl Request {
    pub const fn new() -> Self {
        Self { attempted: false }
    }
    pub fn wait(&mut self, device: &mut (impl Presence + ?Sized)) -> bool {
        self.wait_result(device).is_ok()
    }
    pub fn poll(&mut self, device: &mut (impl Presence + ?Sized)) -> bool {
        self.attempted = true;
        if device.contactless() {
            device.progress()
        } else {
            device.poll_presence()
        }
    }
    pub fn wait_result(&mut self, device: &mut (impl Presence + ?Sized)) -> Result<(), Error> {
        self.attempted = true;
        wait(device, 0)
    }
    pub fn wait_long(&mut self, device: &mut (impl Presence + ?Sized)) -> Result<(), Error> {
        self.attempted = true;
        wait(device, LONG_TOUCH_MS)
    }
    /// PASS suppresses output after any presence attempt, including failure.
    pub fn take_attempt(&mut self) -> bool {
        core::mem::take(&mut self.attempted)
    }
}

// vLEI accepts a continuous fresh press after a debounced release. CanoKey
// waits for a release to complete its gesture; the two contracts stay distinct.
pub const DEBOUNCE_MS: u32 = 30;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sample {
    Waiting,
    Accepted,
    TimedOut,
}
#[derive(Clone, Copy)]
enum Phase {
    Release(Option<u32>),
    Press,
    Hold(u32),
    Done(Sample),
}
pub struct DebouncedRequest {
    started: u32,
    hold: u32,
    phase: Phase,
}
impl DebouncedRequest {
    pub fn new(now: u32, hold_ms: u32) -> Self {
        Self {
            started: now,
            hold: hold_ms.max(DEBOUNCE_MS),
            phase: Phase::Release(None),
        }
    }
    pub fn sample(&mut self, now: u32, touched: bool) -> Sample {
        if let Phase::Done(result) = self.phase {
            return result;
        }
        if now.wrapping_sub(self.started) >= TIMEOUT_MS {
            self.phase = Phase::Done(Sample::TimedOut);
            return Sample::TimedOut;
        }
        self.phase = match self.phase {
            // Even an already-held touch must first be released after arrival.
            Phase::Release(_) if touched => Phase::Release(None),
            Phase::Release(None) => Phase::Release(Some(now)),
            Phase::Release(Some(start)) if now.wrapping_sub(start) >= DEBOUNCE_MS => Phase::Press,
            Phase::Release(start) => Phase::Release(start),
            Phase::Press if touched => Phase::Hold(now),
            Phase::Press => Phase::Press,
            Phase::Hold(_) if !touched => Phase::Press,
            Phase::Hold(start) if now.wrapping_sub(start) >= self.hold => {
                Phase::Done(Sample::Accepted)
            }
            Phase::Hold(start) => Phase::Hold(start),
            Phase::Done(_) => unreachable!(),
        };
        if let Phase::Done(result) = self.phase {
            result
        } else {
            Sample::Waiting
        }
    }
}
