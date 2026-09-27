// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "ctap")]
use canokey_rust_core::{Core, applets::ctap::Request, ports::*};
#[allow(dead_code)]
#[path = "support/ctap.rs"]
mod support;

struct DeviceState {
    time: u32,
    tick_step: u32,
    step: usize,
    touches: &'static [bool],
    connected: bool,
    contactless: bool,
    led: bool,
    waiting: bool,
}
impl DeviceState {
    fn new(touches: &'static [bool]) -> Self {
        Self {
            time: 0,
            tick_step: 1000,
            step: 0,
            touches,
            connected: true,
            contactless: false,
            led: false,
            waiting: false,
        }
    }
}
impl Device for DeviceState {
    fn now(&mut self) -> u32 {
        self.time
    }
    fn serial(&mut self, _: &mut [u8; 4]) {
        unreachable!()
    }
    fn contactless(&mut self) -> bool {
        self.contactless
    }
    fn touched(&mut self) -> bool {
        assert!(!self.contactless, "NFC must not poll the touch sensor");
        self.touches.get(self.step).copied().unwrap_or(false)
    }
    fn progress(&mut self) -> bool {
        self.step += 1;
        self.time = self.time.wrapping_add(self.tick_step);
        self.connected
    }
    fn led(&mut self, on: bool) {
        self.led = on;
    }
    fn keepalive(&mut self, waiting: bool) {
        self.waiting = waiting;
    }
}
#[derive(Default)]
struct Store {
    removed: bool,
    long_reset: bool,
    fail: bool,
}
impl Storage for Store {
    fn load(&mut self, _: Record, out: &mut [u8]) -> Result<usize, StorageError> {
        if !self.long_reset {
            return Err(StorageError::Missing);
        }
        out[..20].fill(0);
        out[16] = 8;
        out[18] = 4;
        out[19] = 4;
        Ok(20)
    }
    fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
        unreachable!()
    }
    fn remove(&mut self, id: Record) -> Result<(), StorageError> {
        assert!((77..181).contains(&id.id()));
        if self.fail {
            return Err(StorageError::Unavailable);
        }
        self.removed = true;
        Ok(())
    }
}
fn run(core: &mut Core, request: &[u8], device: &mut DeviceState, storage: &mut Store) -> u8 {
    let mut parser = Request::new();
    parser.consume(request);
    let mut crypto = support::Backend::default();
    let mut p = Platform {
        device,
        storage,
        crypto: &mut crypto,
        memory: &support::Backend::default(),
    };
    assert_eq!(core.execute_ctap(parser.finish(), &mut p), 1);
    let mut status = [0];
    core.read_ctap(0, &mut status, &mut p).unwrap();
    assert!(!device.led && !device.waiting);
    status[0]
}
#[test]
fn selection_requires_fresh_touch_and_cleans_up_on_cancel_or_timeout() {
    let mut core = Core::new();
    let mut store = Store::default();
    let mut device = DeviceState::new(&[true, false, true, false]);
    assert_eq!(run(&mut core, &[0x0b], &mut device, &mut store), 0);
    assert_eq!(device.step, 3); // releasing a predating touch alone cannot authorize
    let mut device = DeviceState::new(&[]);
    device.time = u32::MAX - 5000;
    assert_eq!(run(&mut core, &[0x0b], &mut device, &mut store), 0x2f);
    let mut device = DeviceState::new(&[]);
    device.connected = false;
    assert_eq!(run(&mut core, &[0x0b], &mut device, &mut store), 0x2d);
    assert_eq!(run(&mut core, &[0x0b, 0], &mut device, &mut store), 3);
    assert!(!store.removed);
}
#[test]
fn reset_is_power_on_gated_and_never_erases_before_presence() {
    let mut core = Core::new();
    let mut store = Store::default();
    let mut device = DeviceState::new(&[false, true, false]);
    device.time = 10_001;
    assert_eq!(run(&mut core, &[7], &mut device, &mut store), 0x30);
    assert_eq!(device.step, 0);
    core.reset(&mut Platform {
        storage: &mut store,
        device: &mut device,
        crypto: &mut support::Backend::default(),
        memory: &support::Backend::default(),
    });
    assert_eq!(run(&mut core, &[7], &mut device, &mut store), 0x30);
    let mut device = DeviceState::new(&[]);
    device.connected = false;
    assert_eq!(run(&mut core, &[7], &mut device, &mut store), 0x2d);
    assert!(!store.removed);
    let mut device = DeviceState::new(&[false, true, false]);
    store.fail = true;
    assert_eq!(run(&mut core, &[7], &mut device, &mut store), 0x7f);
    assert!(!store.removed);
    store.fail = false;
    let mut device = DeviceState::new(&[false, true, false]);
    assert_eq!(run(&mut core, &[7], &mut device, &mut store), 0);
    assert!(store.removed);

    // NFC authorizes presence through the live field, including long-reset mode.
    for long_reset in [false, true] {
        let mut store = Store {
            long_reset,
            ..Store::default()
        };
        let mut device = DeviceState::new(&[]);
        device.contactless = true;
        device.time = 10_001;
        assert_eq!(run(&mut core, &[7], &mut device, &mut store), 0x30);
        assert_eq!(device.step, 0);
        assert!(!store.removed);
        device.time = 0;
        device.connected = false;
        assert_eq!(run(&mut core, &[7], &mut device, &mut store), 0x2d);
        assert!(!store.removed);
        device.connected = true;
        let before = device.step;
        assert_eq!(run(&mut core, &[7], &mut device, &mut store), 0);
        assert_eq!(device.step, before + 1);
        assert!(store.removed);
    }
}

#[test]
fn long_reset_ignores_short_touch_and_requires_release_after_half_second() {
    let mut core = Core::new();
    let mut store = Store {
        long_reset: true,
        ..Store::default()
    };
    let mut device = DeviceState::new(&[
        false, true, false, true, true, true, true, true, true, false,
    ]);
    device.tick_step = 100;
    assert_eq!(run(&mut core, &[7], &mut device, &mut store), 0);
    assert_eq!(device.step, 9);
    assert!(store.removed);
    let mut store = Store {
        long_reset: true,
        ..Store::default()
    };
    let mut device = DeviceState::new(&[false, true, false]);
    device.tick_step = 100;
    assert_eq!(run(&mut core, &[7], &mut device, &mut store), 0x2f);
    assert!(!store.removed);
}

#[test]
fn credential_scan_errors_do_not_publish_or_cache_capacity() {
    struct ScanStore(Result<usize, StorageError>);
    impl Storage for ScanStore {
        fn load(&mut self, id: Record, out: &mut [u8]) -> Result<usize, StorageError> {
            if Some(id) == Record::ctap_credential(0) {
                out[0] = 0xff;
                self.0
            } else {
                Err(StorageError::Missing)
            }
        }
        fn replace(&mut self, _: Record, _: &[u8]) -> Result<(), StorageError> {
            panic!("capacity queries must not rewrite records");
        }
    }
    let mut core = Core::new();
    let mut baseline = Vec::new();
    for result in [
        Err(StorageError::Missing),
        Err(StorageError::Unavailable),
        Err(StorageError::Uncertain),
        Ok(1), // corrupt resident record, not an empty slot
        Err(StorageError::Missing),
    ] {
        let mut p = Platform {
            storage: &mut ScanStore(result),
            crypto: &mut support::Backend::default(),
            device: &mut support::Backend::default(),
            memory: &support::Backend::default(),
        };
        core.begin_ctap(&mut p);
        let n = core.execute_ctap(
            Ok(canokey_rust_core::applets::ctap::Command::GetInfo),
            &mut p,
        );
        let mut response = vec![0; n];
        core.read_ctap(0, &mut response, &mut p).unwrap();
        if matches!(result, Err(StorageError::Missing)) {
            assert!(n > 256 && response[0] == 0);
            if baseline.is_empty() {
                baseline = response;
            } else {
                assert_eq!(response, baseline);
            }
        } else {
            assert_eq!(response, [0x7f]);
        }
        core.close_ctap(&mut p);
    }
}
