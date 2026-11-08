// SPDX-License-Identifier: Apache-2.0
//! Literal FM11NT FIFO replay through the production IRQ/facade and real Core.
//! Only register IO and the existing test-card platform capabilities are faked.
use super::*;
use canokey_protocol::nfc as wire;
use canokey_rust_ffi::composition::nfc;
use std::io::{self, BufRead};
#[path = "nfc_execution.rs"]
mod execution;

struct Registers {
    irq: [u8; wire::FM_IRQ_BYTES],
    rf_status: u8,
    rx: Vec<u8>,
    tx: Vec<u8>,
    sends: usize,
}
thread_local! {
    static REGISTERS: RefCell<Registers> = const { RefCell::new(Registers {
        irq: [0; wire::FM_IRQ_BYTES], rf_status: 0, rx: Vec::new(), tx: Vec::new(), sends: 0,
    }) };
}
fn registers<T>(run: impl FnOnce(&mut Registers) -> T) -> T {
    REGISTERS.with(|r| run(&mut r.borrow_mut()))
}
#[unsafe(no_mangle)]
extern "C" fn ck_nfc_io_lock() -> u32 {
    hw(|h| {
        let prior = h.masked;
        h.masked = 1;
        prior
    })
}
#[unsafe(no_mangle)]
extern "C" fn ck_nfc_io_unlock(prior: u32) {
    hw(|h| h.masked = prior);
    execution::unlocked(prior);
}
#[unsafe(no_mangle)]
extern "C" fn ck_nfc_io_now() -> u32 {
    now()
}
#[unsafe(no_mangle)]
extern "C" fn ck_nfc_io_select(_active: u8) {}
#[unsafe(no_mangle)]
extern "C" fn ck_nfc_io_delay(milliseconds: u16) {
    advance(u32::from(milliseconds));
}
#[unsafe(no_mangle)]
extern "C" fn ck_nfc_io_schedule(callback: Option<unsafe extern "C" fn()>, milliseconds: u16) {
    execution::schedule(callback, milliseconds);
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ck_nfc_io_read(address: u16, out: *mut u8, length: u8) -> i32 {
    assert_ne!(hw(|h| h.masked), 0);
    let out = unsafe { std::slice::from_raw_parts_mut(out, usize::from(length)) };
    registers(|r| match address {
        wire::FM_REG_MAIN_IRQ => {
            out.copy_from_slice(&r.irq);
            r.irq.fill(0);
        }
        wire::FM_REG_FIFO_WORDCNT => out.copy_from_slice(&[r.rx.len() as u8]),
        wire::FM_REG_FIFO_ACCESS => out.copy_from_slice(&r.rx),
        wire::FM_REG_RF_STATUS => out.copy_from_slice(&[r.rf_status]),
        _ => panic!("unexpected NFC read {address:#x}"),
    });
    0
}
#[unsafe(no_mangle)]
unsafe extern "C" fn ck_nfc_io_write(address: u16, bytes: *const u8, length: u8) -> i32 {
    assert_ne!(hw(|h| h.masked), 0);
    let bytes = unsafe { std::slice::from_raw_parts(bytes, usize::from(length)) };
    registers(|r| match address {
        wire::FM_REG_FIFO_ACCESS => {
            assert!(bytes.len() <= wire::FRAME_LIMIT - 2);
            r.tx = bytes.to_vec();
        }
        wire::FM_REG_RF_TXEN => {
            assert_eq!(bytes, &[wire::FM_RF_TX_ENABLE]);
            r.sends += 1;
            execution::transmitted(&r.tx);
        }
        wire::FM_REG_RESET_SILENCE | wire::FM_REG_MAIN_IRQ_MASK => {}
        _ => panic!("unexpected NFC write {address:#x}"),
    });
    0
}
pub(super) fn run() {
    // Product main-loop execution runs with CPU IRQs enabled. A pending IRQ
    // may fire after a critical section restores that unmasked state.
    hw(|h| h.masked = 0);
    unsafe { nfc::init::<Fake>() };
    transport::records(|records| records.set_read_hook(execution::storage_read));
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        if execution::control(&line) {
            continue;
        }
        if transport::records(|records| records.response_fault_control(&line)) {
            continue;
        }
        let (service, line) = match line.strip_prefix("DEFER ") {
            Some(line) => (false, line),
            None => (true, line.as_str()),
        };
        let (operation, value) = line.split_once(' ').unwrap();
        registers(|r| {
            r.tx.clear();
            r.sends = 0;
        });
        match operation {
            "NFC" | "IRQ" => {
                assert!(value.len() % 2 == 0);
                let mut frame: Vec<u8> = (0..value.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
                    .collect();
                registers(|r| {
                    if operation == "IRQ" {
                        // Three latched IRQ bytes and live RF_STATUS precede FIFO bytes.
                        assert!(frame.len() >= wire::FM_IRQ_BYTES + 1);
                        r.irq.copy_from_slice(&frame[..wire::FM_IRQ_BYTES]);
                        r.rf_status = frame[wire::FM_IRQ_BYTES];
                        frame.drain(..wire::FM_IRQ_BYTES + 1);
                    } else {
                        r.irq[0] = wire::FM_MAIN_RX_DONE;
                    }
                    assert!(frame.len() <= wire::FRAME_LIMIT);
                    r.rx = frame;
                });
                unsafe { nfc::interrupt() };
            }
            "HALT" => {
                assert_eq!(value, "0");
                registers(|r| r.irq[2] = wire::FM_AUX_HALT);
                unsafe { nfc::interrupt() };
            }
            "TICK" => advance(value.parse().unwrap()),
            "POLL" => assert_eq!(value, "0"),
            _ => panic!("unknown NFC operation"),
        }
        // Receive/execute and response publication are separate main-loop turns.
        if service {
            unsafe {
                nfc::poll::<Fake>();
                nfc::poll::<Fake>();
                if operation == "IRQ" {
                    // Activation cleanup, command execution and response publication
                    // are separate serialized turns; the queued new RX must survive.
                    nfc::poll::<Fake>();
                }
            }
        }
        registers(|r| {
            assert!(r.sends <= 1 || execution::active());
            print!("WIRE ");
            if r.sends != 0 {
                for byte in &r.tx {
                    print!("{byte:02x}");
                }
            }
            println!();
        });
    }
}

// Shared virtual hardware for source-fault tests; these callbacks only touch
// IRQ-local state and never enter Core or choose a Provider.
pub(super) fn waiting_turn() {
    execution::wait();
}
pub(super) fn input(frame: &[u8]) {
    registers(|r| {
        r.tx.clear();
        r.sends = 0;
        r.rx = frame.to_vec();
        r.irq[0] = wire::FM_MAIN_RX_DONE;
    });
    unsafe { nfc::interrupt() };
}
pub(super) fn halt() {
    registers(|r| r.irq[2] = wire::FM_AUX_HALT);
    unsafe { nfc::interrupt() };
}
pub(super) fn response() -> Vec<u8> {
    registers(|r| {
        assert!(r.sends <= 1);
        if r.sends == 0 {
            Vec::new()
        } else {
            r.tx.clone()
        }
    })
}
