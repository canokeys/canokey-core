// SPDX-License-Identifier: Apache-2.0
use canokey_ctap::client_pin::token::{self, Error, MissingRp, Order, PermissionMatch, Scope};
use std::cell::Cell;

#[test]
fn admission_preserves_scope_mac_and_comparator_call_order() {
    let bound = [0x51; 32];
    let other = [0x52; 32];
    for order in [
        Order::ScopeThenMac,
        Order::MacThenScope,
        Order::PermissionThenMacThenRp,
    ] {
        for permission_ok in [false, true] {
            for rp in [None, Some(&bound), Some(&other)] {
                for allow_missing in [false, true] {
                    for mac_ok in [false, true] {
                        let calls = Cell::new((0, 0));
                        let result = token::authorize(
                            Scope {
                                granted: if permission_ok { 0x01 } else { 0x02 },
                                required: 0x01,
                                permission_match: PermissionMatch::All,
                                bound_rp: Some(&bound),
                                requested_rp: rp,
                                missing_rp: if allow_missing {
                                    MissingRp::Allow
                                } else {
                                    MissingRp::Deny
                                },
                            },
                            order,
                            || {
                                let (mac, compare) = calls.get();
                                calls.set((mac + 1, compare));
                                if mac_ok { Ok(()) } else { Err(0xee) }
                            },
                            |left, right| {
                                let (mac, compare) = calls.get();
                                calls.set((mac, compare + 1));
                                left == right
                            },
                        );
                        let rp_ok = rp.map_or(allow_missing, |rp| rp == &bound);
                        let (verify_called, compare_called, expected) = match order {
                            Order::ScopeThenMac => (
                                permission_ok && rp_ok,
                                permission_ok && rp.is_some(),
                                if !permission_ok || !rp_ok {
                                    Err(Error::Scope)
                                } else if !mac_ok {
                                    Err(Error::Mac(0xee))
                                } else {
                                    Ok(())
                                },
                            ),
                            Order::MacThenScope => (
                                true,
                                mac_ok && permission_ok && rp.is_some(),
                                if !mac_ok {
                                    Err(Error::Mac(0xee))
                                } else if !permission_ok || !rp_ok {
                                    Err(Error::Scope)
                                } else {
                                    Ok(())
                                },
                            ),
                            Order::PermissionThenMacThenRp => (
                                permission_ok,
                                permission_ok && mac_ok && rp.is_some(),
                                if !permission_ok {
                                    Err(Error::Scope)
                                } else if !mac_ok {
                                    Err(Error::Mac(0xee))
                                } else if !rp_ok {
                                    Err(Error::Scope)
                                } else {
                                    Ok(())
                                },
                            ),
                        };
                        assert_eq!(result, expected);
                        assert_eq!(
                            calls.get(),
                            (usize::from(verify_called), usize::from(compare_called))
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
            for permission_match in [PermissionMatch::All, PermissionMatch::Any] {
                let allowed = match permission_match {
                    PermissionMatch::All => granted & required == required,
                    PermissionMatch::Any => granted & required != 0x00,
                };
                let result = token::authorize(
                    Scope {
                        granted,
                        required,
                        permission_match,
                        bound_rp: None,
                        requested_rp: None,
                        missing_rp: MissingRp::Deny,
                    },
                    Order::ScopeThenMac,
                    || Ok::<(), ()>(()),
                    |_, _| panic!("unbound token must not compare RP"),
                );
                assert_eq!(result.is_ok(), allowed);
            }
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
