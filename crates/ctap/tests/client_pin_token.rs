// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::client_pin::token::{self, Error, MissingRp, Scope};
use std::cell::Cell;

#[test]
fn admission_checks_all_permissions_and_rp_before_one_mac() {
    let bound = [0x51; 32];
    let other = [0x52; 32];
    for granted in 0..=0x07 {
        for required in 0..=0x07 {
            for rp in [None, Some(&bound), Some(&other)] {
                for allow_missing in [false, true] {
                    for mac_ok in [false, true] {
                        let calls = Cell::new((0, 0));
                        let result = token::authorize(
                            Scope {
                                granted,
                                required,
                                bound_rp: Some(&bound),
                                requested_rp: rp,
                                missing_rp: if allow_missing {
                                    MissingRp::Allow
                                } else {
                                    MissingRp::Deny
                                },
                            },
                            || {
                                let (mac, compare) = calls.get();
                                calls.set((mac + 1, compare));
                                if mac_ok { Ok(()) } else { Err(0xee) }
                            },
                            |left, right| {
                                let (mac, compare) = calls.get();
                                assert_eq!(mac, 0, "scope must precede MAC");
                                calls.set((mac, compare + 1));
                                left == right
                            },
                        );
                        let permission_ok = required != 0x00 && granted & required == required;
                        let rp_ok = rp.map_or(allow_missing, |rp| rp == &bound);
                        let expected = if !permission_ok || !rp_ok {
                            Err(Error::Scope)
                        } else if !mac_ok {
                            Err(Error::Mac(0xee))
                        } else {
                            Ok(())
                        };
                        assert_eq!(result, expected);
                        assert_eq!(
                            calls.get(),
                            (
                                usize::from(permission_ok && rp_ok),
                                usize::from(permission_ok && rp.is_some()),
                            )
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn permission_masks_and_presence_retention_do_not_grant_new_authority() {
    for granted in 0..=0x07ff {
        for required in [0x00, 0x01, 0x02, 0x03, 0x04, 0x0100, 0x0700, 0x8000] {
            let allowed = required != 0x00 && granted & required == required;
            let calls = Cell::new(0);
            let result = token::authorize(
                Scope {
                    granted,
                    required,
                    bound_rp: None,
                    requested_rp: None,
                    missing_rp: MissingRp::Deny,
                },
                || {
                    calls.set(calls.get() + 1);
                    Ok::<(), ()>(())
                },
                |_, _| panic!("unbound token must not compare RP"),
            );
            assert_eq!(result.is_ok(), allowed);
            assert_eq!(calls.get(), usize::from(allowed));
        }
        for retained in [0x00, 0x10, !0x07, 0xffff] {
            let after = token::after_presence(granted, retained);
            assert_eq!(after, granted & retained);
            assert_eq!(after & !granted, 0x00);
        }
    }
}

#[test]
fn lifetime_windows_preserve_exact_boundary_and_wrapping_origins() {
    for origin in [0, 1000, u32::MAX - 1000] {
        for limit in [0u32, 19_800, 30_000, 600_000] {
            for elapsed in [0, limit.saturating_sub(1), limit, limit + 1, u32::MAX] {
                let expected = if elapsed < limit {
                    Some(limit - elapsed)
                } else {
                    None
                };
                assert_eq!(
                    token::remaining_ms(origin.wrapping_add(elapsed), origin, limit),
                    expected
                );
            }
        }
    }
}
