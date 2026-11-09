// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::session::{Boundary, IdleWindow};

#[test]
fn core_exact_boundary_and_wrapping_clock_match_pre_extraction_admission() {
    // Core c3a61818 authentication.rs admitted getNextAssertion when remaining
    // was nonzero and now.wrapping_sub(started) <= 30_000. Refresh belongs to
    // signing, never to this check; repeated probes must not extend its window.
    for start in [0, 1, 30_000, u32::MAX - 30_000, u32::MAX] {
        let mut window = IdleWindow::new(());
        window.refresh((), start);
        for elapsed in (0..=60_001).chain([u32::MAX / 2, u32::MAX]) {
            let now = start.wrapping_add(elapsed);
            let old_admission = now.wrapping_sub(start) <= 30_000;
            assert_eq!(
                window.accepts(&(), now, Boundary::AfterLimit),
                old_admission
            );
        }
    }
    assert_eq!(
        core::mem::size_of::<IdleWindow<()>>(),
        core::mem::size_of::<u32>()
    );
    assert_eq!(
        core::mem::align_of::<IdleWindow<()>>(),
        core::mem::align_of::<u32>()
    );
}

#[test]
fn connection_binding_and_exact_expiry_are_explicit() {
    let mut window = IdleWindow::new((0x01020304u32, 7u32));
    window.refresh((0x01020304, 7), 100);
    assert!(window.accepts(&(0x01020304, 7), 30_099, Boundary::AtLimit));
    assert!(!window.accepts(&(0x01020304, 7), 30_100, Boundary::AtLimit));
    assert!(window.accepts(&(0x01020304, 7), 30_100, Boundary::AfterLimit));
    assert!(!window.accepts(&(0x01020304, 8), 101, Boundary::AtLimit));
    assert!(!window.accepts(&(0x01020305, 7), 101, Boundary::AtLimit));
    window.refresh((0x01020305, 8), 200);
    assert!(window.accepts(&(0x01020305, 8), 201, Boundary::AtLimit));
    assert!(!window.accepts(&(0x01020304, 7), 201, Boundary::AtLimit));
}

#[test]
fn standard_error_disposition_preserves_rejected_auth_but_revokes_uncertain_state() {
    for status in 0x00..=0xff {
        assert_eq!(
            canokey_ctap::session::reset_on_error(status),
            status == 0x7f
        );
    }
}
