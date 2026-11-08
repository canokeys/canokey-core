// SPDX-License-Identifier: Apache-2.0
//! Host-only execution clock and reader IRQ schedule; Core/file bytes are real.
use super::*;
use std::cell::RefCell;

struct Schedule {
    timer: Option<unsafe extern "C" fn()>,
    active: bool,
    remaining: usize,
    fired: usize,
    elapsed: u32,
    reply: Vec<u8>,
    pending: bool,
    before: bool,
}
thread_local! {
    static STATE: RefCell<Schedule> = const { RefCell::new(Schedule {
        timer: None, active: false, remaining: 0, fired: 0,
        elapsed: 0, reply: Vec::new(), pending: false, before: false,
    }) };
}
pub(super) fn schedule(callback: Option<unsafe extern "C" fn()>, milliseconds: u16) {
    assert!(callback.is_none() || milliseconds == wire::WTX_INTERVAL_MS);
    STATE.with(|s| s.borrow_mut().timer = callback);
}
pub(super) fn active() -> bool {
    STATE.with(|s| s.borrow().active)
}
pub(super) fn control(line: &str) -> bool {
    let Some(command) = line.strip_prefix("EXEC ") else {
        return false;
    };
    if command == "DISARM" {
        STATE.with(|s| s.borrow_mut().remaining = 0);
        println!("EXEC DISARMED");
    } else if command == "STATUS" {
        STATE.with(|s| {
            let s = s.borrow();
            println!(
                "EXEC {} {} {}",
                s.remaining,
                s.fired,
                usize::from(s.timer.is_some())
            );
        });
    } else {
        let fields: Vec<_> = command.split_whitespace().collect();
        assert_eq!(fields.len(), 4);
        assert!(matches!(fields[0], "ARM" | "BEFORE"));
        let elapsed: u32 = fields[1].parse().unwrap();
        assert!(elapsed >= u32::from(wire::WTX_INTERVAL_MS));
        let count: usize = fields[2].parse().unwrap();
        assert!((1..=4).contains(&count));
        let reply: Vec<_> = (0..fields[3].len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&fields[3][i..i + 2], 16).unwrap())
            .collect();
        assert!((3..=wire::FRAME_LIMIT).contains(&reply.len()));
        STATE.with(|s| {
            let mut s = s.borrow_mut();
            s.active = true;
            s.remaining = count;
            s.fired = 0;
            s.elapsed = elapsed;
            s.reply = reply;
            s.pending = false;
            s.before = fields[0] == "BEFORE";
        });
        println!("EXEC ARMED");
    }
    true
}
pub(super) fn storage_read() {
    assert_eq!(hw(|h| h.masked), 0);
    let event = STATE.with(|s| {
        let mut s = s.borrow_mut();
        if !s.active || s.remaining == 0 {
            return None;
        }
        let callback = s.timer.take()?;
        s.remaining -= 1;
        s.fired += 1;
        Some((callback, s.elapsed, s.before.then(|| s.reply.clone())))
    });
    if let Some((callback, elapsed, before)) = event {
        if let Some(before) = before {
            input(&before);
        }
        // Only the timer's subsequent IO unlock may deliver the WTX reply;
        // the early frame's unlock precedes WTX transmission.
        STATE.with(|s| s.borrow_mut().pending = true);
        advance(elapsed);
        unsafe { callback() };
    }
}
pub(super) fn transmitted(bytes: &[u8]) {
    if active() {
        print!("RF ");
        for byte in bytes {
            print!("{byte:02x}");
        }
        println!();
    }
}
pub(super) fn unlocked(prior: u32) {
    if prior != 0 {
        return;
    }
    let reply = STATE.with(|s| {
        let mut s = s.borrow_mut();
        if s.pending {
            s.pending = false;
            Some(if s.before {
                vec![wire::PCB_WTX, 1, 0, 0]
            } else {
                s.reply.clone()
            })
        } else {
            None
        }
    });
    if let Some(reply) = reply {
        // GPIO IRQ is delivered after the global IO borrow is released. This
        // models pending hardware, never recursive access to borrowed Io/Core.
        input(&reply);
    }
}
pub(super) fn wait() {
    let callback = STATE.with(|s| s.borrow_mut().timer.take()).unwrap();
    advance(u32::from(wire::WTX_INTERVAL_MS));
    unsafe { callback() };
}
