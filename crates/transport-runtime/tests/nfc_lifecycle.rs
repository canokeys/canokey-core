// SPDX-License-Identifier: Apache-2.0
use canokey_transport_runtime::nfc::Execution;

#[test]
fn waiting_echo_wraparound_and_field_cancellation() {
    let mut e = Execution::new();
    assert!(!e.live());
    e.begin(u32::MAX - 99);
    assert!(!e.due(49));
    assert!(e.due(50));
    e.sent(50);
    assert!(!e.due(1000));
    assert!(!e.can_reply());
    assert_eq!(e.finish(), None);
    assert!(!e.echo(2));
    assert!(e.echo(1));
    assert!(e.can_reply());
    assert!(e.due(200));
    e.cancel();
    assert!(!e.live());
    assert!(!e.echo(1));
    assert_eq!(e.finish(), Some(false));
    e.begin(300);
    assert_eq!(e.finish(), Some(true));
    assert!(!e.live());
}

#[test]
fn recovery_preserves_clean_activation_and_does_not_timeout_crypto() {
    use canokey_transport_runtime::nfc::{HardwareAction, Recovery};
    let mut r = Recovery::new(0);
    let config = r.poll(0, false, false).unwrap();
    assert_eq!(config.operation, HardwareAction::ConfigureInterrupts);
    assert!(r.completed(config, false, 0));
    assert_eq!(r.poll(1, false, false), Some(config));
    assert!(r.completed(config, true, 1));
    assert_eq!(r.poll(200, false, false), None);
    assert_eq!(r.generation(), 0);
    assert_eq!(r.poll(1000, true, true), None);
    assert!(!r.drain_only());
    r.activity(1000);
    assert_eq!(r.poll(1199, true, false), None);
    let silence = r.poll(1200, true, false).unwrap();
    assert_eq!(silence.operation, HardwareAction::Silence);
    assert_eq!(r.generation(), 1);
    assert!(r.drain_only());
}
#[test]
fn forced_recovery_retries_and_cannot_be_cancelled_by_field_irqs() {
    use canokey_transport_runtime::nfc::{HardwareAction, Recovery};
    let mut r = Recovery::new(0);
    r.fault();
    let silence = r.poll(1, false, false).unwrap();
    assert!(r.completed(silence, false, 2));
    assert!(!r.activated(3));
    r.activity(4);
    assert_eq!(r.poll(5, false, false), Some(silence));
    r.fault();
    assert_eq!(r.generation(), 1);
    assert!(r.completed(silence, true, u32::MAX - 99));
    assert_eq!(r.poll(99, false, false), None);
    assert!(!r.activated(99));
    let unsilence = r.poll(100, false, false).unwrap();
    assert_eq!(unsilence.operation, HardwareAction::Unsilence);
    assert!(r.completed(unsilence, false, 101));
    assert!(r.drain_only());
    assert_eq!(r.poll(102, false, false), Some(unsilence));
    assert!(r.completed(unsilence, true, 103));
    assert!(!r.drain_only());
    let config = r.poll(104, false, false).unwrap();
    assert_eq!(config.operation, HardwareAction::ConfigureInterrupts);
    assert!(r.activated(105));
    assert!(!r.completed(config, true, 106));
    assert!(r.poll(106, false, false).is_some());
}
#[test]
fn irq_error_priority_matches_native_register_contract() {
    use canokey_transport_runtime::nfc::{Irq, irq};
    assert_eq!(
        irq([0x50, 0x00, 0x00]),
        Irq::Activity {
            activated: true,
            received: true
        }
    );
    assert_eq!(irq([0x50, 0x00, 0x04]), Irq::Halt);
    assert_eq!(irq([0x50, 0x04, 0x04]), Irq::Fault);
    for error in [0x08, 0x10, 0x20, 0x40] {
        assert_eq!(irq([0x50, 0x00, error | 0x04]), Irq::Fault);
    }
}
