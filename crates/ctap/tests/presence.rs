// SPDX-License-Identifier: Apache-2.0
// These traces link only the shared crate/ports, not either product runtime.
use canokey_ctap::presence::{DebouncedRequest, Error, Request, Sample};
use canokey_ports::Device;
mod before_core {
    include!("fixtures/presence_core_52ee1ba6.rs");
}
mod before_vlei {
    include!("fixtures/presence_vlei_44b5257.rs");
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    Now(u32),
    Touch(bool),
    Progress(bool),
    Led(bool),
    Idle,
    Contactless(bool),
    Poll,
}
#[derive(Clone)]
struct Trace {
    now: u32,
    step: u32,
    touch_bits: u8,
    samples: usize,
    progress: usize,
    cancel_at: usize,
    nfc: bool,
    calls: Vec<Call>,
}
impl Device for Trace {
    fn serial(&mut self, _: &mut [u8; 4]) {
        panic!("presence must not read identity")
    }
    fn now(&mut self) -> u32 {
        self.calls.push(Call::Now(self.now));
        self.now
    }
    fn touched(&mut self) -> bool {
        let touched = self.touch_bits & (1 << (self.samples.min(7))) != 0;
        self.samples += 1;
        self.calls.push(Call::Touch(touched));
        touched
    }
    fn progress(&mut self) -> bool {
        let live = self.progress != self.cancel_at;
        self.progress += 1;
        self.now = self.now.wrapping_add(self.step);
        self.calls.push(Call::Progress(live));
        live
    }
    fn contactless(&mut self) -> bool {
        self.calls.push(Call::Contactless(self.nfc));
        self.nfc
    }
    fn led(&mut self, value: bool) {
        self.calls.push(Call::Led(value));
    }
    fn led_idle(&mut self) {
        self.calls.push(Call::Idle);
    }
    fn poll_presence(&mut self) -> bool {
        self.calls.push(Call::Poll);
        true
    }
}

#[test]
fn blocking_wait_preserves_all_device_calls_cancellation_and_wraparound() {
    let mut cases = 0;
    for nfc in [false, true] {
        for started in [0, u32::MAX - 100] {
            for step in [100, 500, 30_000] {
                for touch_bits in 0x00..=0xff {
                    for cancel_at in [0, 1, 3, usize::MAX] {
                        for long in [false, true] {
                            let mut before = Trace {
                                now: started,
                                step,
                                touch_bits,
                                samples: 0,
                                progress: 0,
                                cancel_at,
                                nfc,
                                calls: Vec::new(),
                            };
                            let mut after = before.clone();
                            let expected =
                                before_core::wait(&mut before, if long { 500 } else { 0 }).map_err(
                                    |error| match error {
                                        before_core::Error::Cancelled => Error::Cancelled,
                                        before_core::Error::Timeout => Error::Timeout,
                                    },
                                );
                            let mut request = Request::new();
                            let actual = if long {
                                request.wait_long(&mut after)
                            } else {
                                request.wait_result(&mut after)
                            };
                            assert_eq!(actual, expected);
                            assert_eq!(after.calls, before.calls);
                            assert!(request.take_attempt());
                            assert!(!request.take_attempt());
                            cases += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 24576);
}

#[test]
fn polling_attempt_is_consumed_even_after_contactless_cancellation() {
    for nfc in [false, true] {
        for cancel_at in [0, usize::MAX] {
            let mut trace = Trace {
                now: 0,
                step: 1,
                touch_bits: 0x00,
                samples: 0,
                progress: 0,
                cancel_at,
                nfc,
                calls: Vec::new(),
            };
            let mut request = Request::new();
            assert_eq!(request.poll(&mut trace), !nfc || cancel_at != 0);
            assert!(request.take_attempt());
            assert!(!request.take_attempt());
            assert_eq!(
                trace.calls,
                if nfc {
                    vec![Call::Contactless(true), Call::Progress(cancel_at != 0)]
                } else {
                    vec![Call::Contactless(false), Call::Poll]
                }
            );
        }
    }
}

#[test]
fn debounced_gesture_matches_fixed_product_reference_at_all_boundaries() {
    let mut samples = 0;
    // Enumerate every eight-sample gesture with boundary, bounce, timeout and
    // wrapping clocks. Also sample terminal states after the sequence ends.
    for started in [0, u32::MAX - 20] {
        for hold_ms in [0, 29, 30, 31, 500, before_vlei::RESET_HOLD_MS, u32::MAX] {
            for step in [0, 1, 29, 30, 31, 500, 4999, 5000, 29999, 30000] {
                for touch_bits in 0x00u8..=0xff {
                    let mut before = before_vlei::Request::new(started, hold_ms);
                    let mut after = DebouncedRequest::new(started, hold_ms);
                    for index in 0..10 {
                        let now = started.wrapping_add(step * index);
                        let touched = touch_bits & (1 << index.min(7)) != 0;
                        let expected = match before.sample(now, touched) {
                            before_vlei::Result::Waiting => Sample::Waiting,
                            before_vlei::Result::Accepted => Sample::Accepted,
                            before_vlei::Result::TimedOut => Sample::TimedOut,
                        };
                        assert_eq!(after.sample(now, touched), expected);
                        samples += 1;
                    }
                }
            }
        }
    }
    assert_eq!(samples, 358400);
}

#[test]
fn capability_only_device_needs_no_product_or_backing() {
    struct Disconnected;
    impl canokey_ctap::ports::Presence for Disconnected {
        fn now(&mut self) -> u32 {
            panic!("contactless path must not read time")
        }
        fn touched(&mut self) -> bool {
            panic!("contactless path must not read touch")
        }
        fn contactless(&mut self) -> bool {
            true
        }
        fn progress(&mut self) -> bool {
            false
        }
        fn led(&mut self, _: bool) {
            panic!("contactless path must not prompt")
        }
        fn led_idle(&mut self) {
            panic!("contactless path has no LED lease")
        }
        fn poll_presence(&mut self) -> bool {
            panic!("contactless path must not poll touch")
        }
    }
    let mut request = Request::new();
    assert_eq!(
        request.wait_result(&mut Disconnected),
        Err(Error::Cancelled)
    );
    assert!(request.take_attempt());
    assert_eq!(
        core::mem::size_of::<Request>(),
        core::mem::size_of::<bool>()
    );
    assert_eq!(
        core::mem::size_of::<DebouncedRequest>(),
        core::mem::size_of::<before_vlei::Request>()
    );
    assert_eq!(
        core::mem::align_of::<DebouncedRequest>(),
        core::mem::align_of::<before_vlei::Request>()
    );
}
