// SPDX-License-Identifier: Apache-2.0
// Fixed executed vLEI gesture reference, 44b5257; test-only.
pub const TIMEOUT_MS: u32 = 30_000;
pub const DEBOUNCE_MS: u32 = 30;
pub const RESET_HOLD_MS: u32 = 5_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Result {
    Waiting,
    Accepted,
    TimedOut,
}
#[derive(Clone, Copy)]
enum Phase {
    Release(Option<u32>),
    Press,
    Hold(u32),
    Done(Result),
}
pub struct Request {
    started: u32,
    hold: u32,
    phase: Phase,
}
impl Request {
    pub fn new(now: u32, hold_ms: u32) -> Self {
        Self {
            started: now,
            hold: hold_ms.max(DEBOUNCE_MS),
            phase: Phase::Release(None),
        }
    }
    pub fn sample(&mut self, now: u32, touched: bool) -> Result {
        if let Phase::Done(result) = self.phase {
            return result;
        }
        if now.wrapping_sub(self.started) >= TIMEOUT_MS {
            self.phase = Phase::Done(Result::TimedOut);
            return Result::TimedOut;
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
                Phase::Done(Result::Accepted)
            }
            Phase::Hold(start) => Phase::Hold(start),
            Phase::Done(_) => unreachable!(),
        };
        if let Phase::Done(result) = self.phase {
            result
        } else {
            Result::Waiting
        }
    }
}
